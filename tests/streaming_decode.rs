//! Streaming decode must see exactly what the borrowing decoder sees, must
//! reject everything the borrowing decoder rejects, and must not hold payloads
//! in memory to do either.

#![cfg(unix)]

use std::io::{self, Read};

use nix_archive::nar::{
    decode_events, decode_events_reader, encode_regular, encode_tree, Error, Event, NamedNode,
    Node, ReadEvent,
};

mod common;

use common::{allocation_calls, baseline, peak_growth, reset_allocation_calls, serialized};

/// A NAR of one small tree with a directory, an executable, a symlink and a
/// name that is not valid UTF-8.
fn sample_nar() -> Vec<u8> {
    let bin = [NamedNode {
        name: b"tool",
        node: Node::Regular {
            executable: true,
            contents: b"#!/bin/sh\necho tool\n",
        },
    }];
    let root = [
        NamedNode {
            name: b"bin",
            node: Node::Directory(&bin),
        },
        NamedNode {
            name: b"data",
            node: Node::Regular {
                executable: false,
                contents: b"contents of data\n",
            },
        },
        NamedNode {
            name: b"link",
            node: Node::Symlink {
                target: b"bin/tool",
            },
        },
        NamedNode {
            name: b"raw\xff",
            node: Node::Regular {
                executable: false,
                contents: b"byte safe\n",
            },
        },
    ];
    let mut nar = Vec::new();
    encode_tree(&mut nar, &Node::Directory(&root)).expect("encode");
    nar
}

/// Both decoders described as comparable text, so a mismatch reads as a diff
/// rather than as two unrelated failures.
fn borrowed_events(nar: &[u8]) -> Vec<String> {
    let mut seen = Vec::new();
    decode_events(nar, |event| {
        seen.push(match event {
            Event::DirectoryStart { name } => format!("dir-start {name:?}"),
            Event::DirectoryEnd { name } => format!("dir-end {name:?}"),
            Event::Regular {
                name,
                executable,
                contents,
            } => format!("regular {name:?} exec={executable} {contents:?}"),
            Event::Symlink { name, target } => format!("symlink {name:?} -> {target:?}"),
        });
        Ok(())
    })
    .expect("decode_events");
    seen
}

fn streamed_events(nar: &[u8]) -> Vec<String> {
    let mut seen = Vec::new();
    let mut reader = io::Cursor::new(nar);
    decode_events_reader(&mut reader, |event| {
        seen.push(match event {
            ReadEvent::DirectoryStart { name } => format!("dir-start {name:?}"),
            ReadEvent::DirectoryEnd { name } => format!("dir-end {name:?}"),
            ReadEvent::Regular {
                name,
                executable,
                mut contents,
            } => {
                let size = contents.size();
                let mut bytes = Vec::new();
                contents.read_to_end(&mut bytes)?;
                assert_eq!(bytes.len() as u64, size, "declared size matches contents");
                format!("regular {name:?} exec={executable} {bytes:?}")
            }
            ReadEvent::Symlink { name, target } => format!("symlink {name:?} -> {target:?}"),
        });
        Ok(())
    })
    .expect("decode_events_reader");
    seen
}

/// A reader allowed to fail on an empty buffer, so payload readers cannot
/// accidentally probe it after reaching their declared end.
struct RejectEmptyReads<R>(R);

impl<R: Read> Read for RejectEmptyReads<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Err(io::Error::other("empty read"));
        }
        self.0.read(buf)
    }
}

/// Decode `nar`, draining every payload, and return whatever went wrong.
fn streamed_error(nar: &[u8]) -> Error {
    let mut reader = io::Cursor::new(nar);
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular { mut contents, .. } = event {
            io::copy(&mut contents, &mut io::sink())?;
        }
        Ok(())
    })
    .expect_err("expected a rejection")
}

fn borrowed_error(nar: &[u8]) -> Error {
    decode_events(nar, |_| Ok(())).expect_err("expected a rejection")
}

// Hand-built archives, for shapes the encoder is not willing to produce.

fn token(nar: &mut Vec<u8>, bytes: &[u8]) {
    nar.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    nar.extend_from_slice(bytes);
    nar.resize(nar.len() + (8 - bytes.len() % 8) % 8, 0);
}

fn append(nar: &mut Vec<u8>, parts: &[&[u8]]) {
    for part in parts {
        token(nar, part);
    }
}

/// A directory whose entries are `names` in exactly the order given, each an
/// empty regular file.
fn directory_of(names: &[&[u8]]) -> Vec<u8> {
    let mut nar = Vec::new();
    append(&mut nar, &[b"nix-archive-1", b"(", b"type", b"directory"]);
    for name in names {
        append(&mut nar, &[b"entry", b"(", b"name", name, b"node"]);
        append(
            &mut nar,
            &[b"(", b"type", b"regular", b"contents", b"", b")"],
        );
        append(&mut nar, &[b")"]);
    }
    append(&mut nar, &[b")"]);
    nar
}

/// `depth` directories nested one inside the next, innermost holding a file.
fn nested_directories(depth: usize) -> Vec<u8> {
    let mut nar = Vec::new();
    append(&mut nar, &[b"nix-archive-1"]);
    for _ in 0..depth {
        append(&mut nar, &[b"(", b"type", b"directory"]);
        append(&mut nar, &[b"entry", b"(", b"name", b"d", b"node"]);
    }
    append(
        &mut nar,
        &[b"(", b"type", b"regular", b"contents", b"", b")"],
    );
    for _ in 0..depth {
        append(&mut nar, &[b")", b")"]);
    }
    nar
}

#[test]
fn streaming_and_borrowing_decoders_agree() {
    let _guard = serialized();
    let nar = sample_nar();
    assert_eq!(streamed_events(&nar), borrowed_events(&nar));
}

#[test]
fn exhausted_contents_do_not_probe_the_archive_reader() {
    let _guard = serialized();
    let nar = sample_nar();
    let mut reader = RejectEmptyReads(io::Cursor::new(&nar));

    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular { mut contents, .. } = event {
            let mut bytes = Vec::new();
            contents.read_to_end(&mut bytes)?;
        }
        Ok(())
    })
    .expect("complete payloads must report EOF without touching the archive reader");
}

/// One routine over both decoders, which is the whole point of the two of them
/// sharing an event type. Before `Event` became generic over its contents this
/// had to be written once per decoder.
fn describe<C>(event: &Event<'_, C>) -> String {
    match event {
        Event::DirectoryStart { name } => format!("dir-start {name:?}"),
        Event::DirectoryEnd { name } => format!("dir-end {name:?}"),
        Event::Regular {
            name, executable, ..
        } => format!("regular {name:?} exec={executable}"),
        Event::Symlink { name, target } => format!("symlink {name:?} -> {target:?}"),
    }
}

#[test]
fn one_routine_serves_both_decoders() {
    let _guard = serialized();
    let nar = sample_nar();

    let mut from_slice = Vec::new();
    decode_events(&nar, |event| {
        from_slice.push(describe(&event));
        Ok(())
    })
    .expect("decode_events");

    let mut from_stream = Vec::new();
    let mut reader = io::Cursor::new(&nar);
    decode_events_reader(&mut reader, |event| {
        from_stream.push(describe(&event));
        Ok(())
    })
    .expect("decode_events_reader");

    assert_eq!(from_slice, from_stream);
    assert_eq!(
        from_slice.len(),
        8,
        "root, bin, tool, /bin, data, link, raw, /root"
    );
}

#[test]
fn contents_left_unread_are_skipped() {
    let _guard = serialized();
    let nar = sample_nar();
    let mut reader = io::Cursor::new(&nar);
    let mut names = Vec::new();
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular { name, .. } = event {
            // Deliberately read nothing: the decoder owes the caller the rest
            // of the archive regardless.
            names.push(name.map(<[u8]>::to_vec));
        }
        Ok(())
    })
    .expect("decode_events_reader");
    assert_eq!(
        names,
        [
            Some(b"tool".to_vec()),
            Some(b"data".to_vec()),
            Some(b"raw\xff".to_vec()),
        ]
    );
}

#[test]
fn a_partially_read_file_still_leaves_the_stream_positioned() {
    let _guard = serialized();
    let nar = sample_nar();
    let mut reader = io::Cursor::new(&nar);
    let mut heads = Vec::new();
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular { mut contents, .. } = event {
            let mut first = [0; 4];
            contents.read_exact(&mut first)?;
            heads.push(first);
        }
        Ok(())
    })
    .expect("decode_events_reader");
    // Reaching the third file at all is the positioning claim; the bytes prove
    // the decoder resumed on a token boundary rather than mid-payload.
    assert_eq!(heads, [*b"#!/b", *b"cont", *b"byte"]);
}

/// A destination that takes `budget` bytes and then refuses the rest, standing
/// in for a filesystem that fills up mid-payload.
struct FailingSink {
    budget: usize,
    accepted: Vec<u8>,
}

impl io::Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::Error::other("destination is full"));
        }
        let count = self.budget.min(buf.len());
        self.accepted.extend_from_slice(&buf[..count]);
        self.budget -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `copy_to` pulls bytes out of the archive before it hands them to a writer
/// that may refuse them, so a failed write has to leave the decoder's counter
/// describing what was actually consumed. Carrying the pre-copy figure instead
/// makes the decoder skip those bytes a second time and resume inside whatever
/// follows the file.
#[test]
fn a_failed_destination_write_leaves_the_stream_positioned() {
    let _guard = serialized();
    const PAYLOAD: usize = 200 * 1024;
    const BUDGET: usize = 4096;

    let payload = vec![b'x'; PAYLOAD];
    let root = [
        NamedNode {
            name: b"big",
            node: Node::Regular {
                executable: false,
                contents: &payload,
            },
        },
        NamedNode {
            name: b"tail",
            node: Node::Regular {
                executable: false,
                contents: b"tail-marker",
            },
        },
    ];
    let mut nar = Vec::new();
    encode_tree(&mut nar, &Node::Directory(&root)).expect("encode");

    let mut sink = FailingSink {
        budget: BUDGET,
        accepted: Vec::new(),
    };
    let mut refusals = 0;
    let mut tail = Vec::new();
    let mut reader = io::Cursor::new(&nar);
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular {
            name, mut contents, ..
        } = event
        {
            if name == Some(b"big".as_slice()) {
                // The visitor treats a dead destination as its own business
                // and keeps decoding, which the API explicitly allows.
                assert!(
                    contents.copy_to(&mut sink).is_err(),
                    "the sink was supposed to give out"
                );
                refusals += 1;
            } else {
                contents.read_to_end(&mut tail)?;
            }
        }
        Ok(())
    })
    .expect("the archive after the failed file is still decodable");

    assert_eq!(refusals, 1, "the large file should have been offered once");
    assert_eq!(
        sink.accepted,
        vec![b'x'; BUDGET],
        "the sink took payload bytes, not framing"
    );
    assert_eq!(
        tail,
        b"tail-marker".as_slice(),
        "the file after the failed one arrived intact"
    );
}

#[test]
fn every_truncation_of_an_archive_is_an_error() {
    let _guard = serialized();
    let nar = sample_nar();
    for end in 0..nar.len() {
        let error = streamed_error(&nar[..end]);
        assert!(
            matches!(error, Error::UnexpectedEof | Error::BadMagic),
            "truncating to {end} of {} bytes gave {error:?}",
            nar.len()
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let _guard = serialized();
    let mut nar = sample_nar();
    nar.extend_from_slice(b"junk");
    assert!(
        matches!(streamed_error(&nar), Error::TrailingBytes),
        "expected trailing bytes"
    );
}

#[test]
fn a_visitor_error_stops_the_decode() {
    let _guard = serialized();
    let nar = sample_nar();
    let mut reader = io::Cursor::new(&nar);
    let error = decode_events_reader(&mut reader, |_| {
        Err(Error::Io(io::Error::other("visitor said no")))
    })
    .unwrap_err();
    assert!(matches!(error, Error::Io(_)), "got {error:?}");
}

/// The grammar checks are written out a second time for the streaming decoder,
/// so every one of them is pinned against the borrowing decoder's verdict.
#[test]
fn malformed_archives_are_rejected_exactly_as_the_borrowing_decoder_rejects_them() {
    let _guard = serialized();

    let unsorted = directory_of(&[b"b", b"a"]);
    assert!(
        matches!(streamed_error(&unsorted), Error::UnsortedEntries(..)),
        "descending entries: {:?}",
        streamed_error(&unsorted)
    );

    let duplicate = directory_of(&[b"a", b"a"]);
    assert!(
        matches!(streamed_error(&duplicate), Error::UnsortedEntries(..)),
        "repeated entry: {:?}",
        streamed_error(&duplicate)
    );

    for name in [b"..".as_slice(), b".", b"", b"a/b", b"a\0b"] {
        let nar = directory_of(&[name]);
        assert!(
            matches!(streamed_error(&nar), Error::InvalidName(_)),
            "name {name:?}: {:?}",
            streamed_error(&nar)
        );
    }

    // Nix rejects a node at depth 64; one below the limit still decodes.
    let too_deep = nested_directories(64);
    assert!(
        matches!(streamed_error(&too_deep), Error::MaxDepth(64)),
        "depth 64: {:?}",
        streamed_error(&too_deep)
    );
    let deep_enough = nested_directories(63);
    streamed_events(&deep_enough);

    for nar in [&unsorted, &duplicate, &too_deep] {
        assert_eq!(
            format!("{:?}", streamed_error(nar)),
            format!("{:?}", borrowed_error(nar)),
            "the two decoders disagree about a malformed archive"
        );
    }
}

#[test]
fn nonzero_padding_is_rejected_after_the_payload_is_delivered() {
    let _guard = serialized();
    let mut nar = Vec::new();
    append(&mut nar, &[b"nix-archive-1"]);
    append(
        &mut nar,
        &[b"(", b"type", b"regular", b"contents", b"hello", b")"],
    );
    // "hello" is five bytes, so the last three bytes of its token are padding.
    let payload_end = nar.len() - 8 - 8;
    nar[payload_end - 1] = 1;

    assert!(
        matches!(streamed_error(&nar), Error::BadPadding),
        "got {:?}",
        streamed_error(&nar)
    );
    assert!(matches!(borrowed_error(&nar), Error::BadPadding));
}

#[test]
fn oversized_metadata_tokens_are_refused_before_they_are_allocated() {
    let _guard = serialized();
    let mut nar = Vec::new();
    append(&mut nar, &[b"nix-archive-1"]);
    append(&mut nar, &[b"(", b"type", b"symlink", b"target"]);
    let length_prefix = nar.len();
    append(&mut nar, &[b"target", b")"]);
    // Claim two megabytes without supplying them: the limit has to be checked
    // against the declared length, not against what actually arrives.
    nar[length_prefix..length_prefix + 8].copy_from_slice(&(2u64 * 1024 * 1024).to_le_bytes());

    match streamed_error(&nar) {
        Error::TokenTooLarge { size, limit } => {
            assert_eq!(size, 2 * 1024 * 1024);
            assert_eq!(limit, 1024 * 1024);
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}

/// A corrupt length prefix must not turn the error message into a window onto
/// the rest of the archive.
#[test]
fn error_messages_do_not_quote_unbounded_stretches_of_the_archive() {
    let _guard = serialized();
    let secret = b"SECRET".repeat(600);
    let mut nar = Vec::new();
    append(&mut nar, &[b"nix-archive-1"]);
    append(
        &mut nar,
        &[b"(", b"type", b"regular", b"contents", &secret, b")"],
    );
    // Inflate the length of the "type" token so the cursor loses alignment and
    // lands inside the payload while looking for a control word.
    let type_length_prefix = 24 + 16;
    nar[type_length_prefix..type_length_prefix + 8].copy_from_slice(&4096u64.to_le_bytes());

    let message = streamed_error(&nar).to_string();
    assert!(
        !message.contains("SECRET"),
        "error quoted archive payload: {message}"
    );
    assert!(
        message.len() < 128,
        "error message is {} bytes long: {message}",
        message.len()
    );
}

#[test]
fn read_events_are_printable() {
    let _guard = serialized();
    let nar = sample_nar();
    let mut reader = io::Cursor::new(&nar);
    let mut printed = Vec::new();
    decode_events_reader(&mut reader, |event| {
        printed.push(format!("{event:?}"));
        Ok(())
    })
    .expect("decode_events_reader");
    assert!(printed[0].starts_with("DirectoryStart"), "{:?}", printed[0]);
    assert!(
        printed.iter().any(|line| line.contains("size: 20")),
        "a Regular event should show its declared size: {printed:?}"
    );
}

/// Counts what it is given and checks it is the payload, without keeping any
/// of it.
#[derive(Default)]
struct Verifier {
    bytes: u64,
    corrupt: bool,
    largest_write: usize,
}

impl io::Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.corrupt |= buf.iter().any(|&byte| byte != b'x');
        self.bytes += buf.len() as u64;
        self.largest_write = self.largest_write.max(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The point of the API: a payload far larger than any buffer it is allowed to
/// allocate passes through it intact.
#[test]
fn decoding_a_large_file_does_not_allocate_it() {
    const PAYLOAD: usize = 64 * 1024 * 1024;
    const MAX_EXTRA_LIVE_BYTES: usize = 2 * 1024 * 1024;
    let _guard = serialized();

    let mut nar = Vec::new();
    encode_regular(&mut nar, &vec![b'x'; PAYLOAD], false).expect("encode");

    let mut reader = io::Cursor::new(&nar);
    let before = baseline();

    let mut verifier = Verifier::default();
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Regular { mut contents, .. } = event {
            assert_eq!(contents.size(), PAYLOAD as u64, "declared size");
            io::copy(&mut contents, &mut verifier)?;
        }
        Ok(())
    })
    .expect("decode_events_reader");

    let growth = peak_growth(before);
    assert_eq!(verifier.bytes, PAYLOAD as u64, "whole payload delivered");
    assert!(!verifier.corrupt, "payload bytes were not the ones encoded");
    assert!(
        verifier.largest_write < MAX_EXTRA_LIVE_BYTES,
        "decoder handed over a payload-sized chunk of {} bytes",
        verifier.largest_write
    );
    assert!(
        growth < MAX_EXTRA_LIVE_BYTES,
        "decoding a {PAYLOAD} byte payload grew the live heap by {growth} bytes"
    );
}

/// A flat directory of `count` symlinks, every name and every target the same
/// length so no buffer has cause to grow after the first entry.
fn symlink_directory(count: usize) -> Vec<u8> {
    let names: Vec<String> = (0..count).map(|index| format!("link{index:03}")).collect();
    let targets: Vec<String> = (0..count)
        .map(|index| format!("target{index:03}"))
        .collect();
    let children: Vec<NamedNode<'_>> = names
        .iter()
        .zip(&targets)
        .map(|(name, target)| NamedNode {
            name: name.as_bytes(),
            node: Node::Symlink {
                target: target.as_bytes(),
            },
        })
        .collect();
    let mut nar = Vec::new();
    encode_tree(&mut nar, &Node::Directory(&children)).expect("encode");
    nar
}

fn streaming_decode_allocation_calls(nar: &[u8]) -> usize {
    let mut symlinks = 0;
    let mut reader = io::Cursor::new(nar);
    reset_allocation_calls();
    decode_events_reader(&mut reader, |event| {
        if let ReadEvent::Symlink { .. } = event {
            symlinks += 1;
        }
        Ok(())
    })
    .expect("decode_events_reader");
    let calls = allocation_calls();
    assert!(symlinks > 0, "the archive was supposed to hold symlinks");
    calls
}

/// Symlink targets are leaves, so no two are ever live at once and one buffer
/// reads every one of them. Counting calls rather than bytes is what catches a
/// buffer allocated per symlink: it is freed before the next one, so it never
/// shows up as live memory however many of them there are.
#[test]
fn streaming_decode_does_not_allocate_per_symlink() {
    let _guard = serialized();
    let few = symlink_directory(4);
    let many = symlink_directory(64);

    let few_calls = streaming_decode_allocation_calls(&few);
    let many_calls = streaming_decode_allocation_calls(&many);

    assert_eq!(
        few_calls, many_calls,
        "64 symlinks cost {many_calls} allocations against {few_calls} for 4"
    );
    assert!(
        many_calls <= 4,
        "decoding one flat directory took {many_calls} allocations"
    );
}
