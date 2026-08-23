use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nix_archive::nar::{encode_tree, Encoder, Error, NamedNode, Node};

const REGULAR_GOLDEN: &str = include_str!("fixtures/regular.nar.hex");
const EXECUTABLE_GOLDEN: &str = include_str!("fixtures/executable.nar.hex");
const SYMLINK_GOLDEN: &str = include_str!("fixtures/symlink.nar.hex");
const DIRECTORY_GOLDEN: &str = include_str!("fixtures/directory.nar.hex");

fn golden(hex: &str) -> Vec<u8> {
    let digits: Vec<_> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("golden is hex");
            let low = (pair[1] as char).to_digit(16).expect("golden is hex");
            ((high << 4) | low) as u8
        })
        .collect()
}

#[test]
fn matches_borrowed_tree_for_nested_byte_oriented_archive() {
    let nested_children = [NamedNode {
        name: b"link",
        node: Node::Symlink {
            target: b"target-\xff-bytes",
        },
    }];
    let children = [
        NamedNode {
            name: b"empty",
            node: Node::Directory(&[]),
        },
        NamedNode {
            name: b"file",
            node: Node::Regular {
                executable: true,
                contents: b"streamed payload",
            },
        },
        NamedNode {
            name: b"nested",
            node: Node::Directory(&nested_children),
        },
        NamedNode {
            name: b"weird-\xff-name",
            node: Node::Regular {
                executable: false,
                contents: b"non UTF-8 name",
            },
        },
    ];
    let tree = Node::Directory(&children);
    let mut expected = Vec::new();
    encode_tree(&mut expected, &tree).unwrap();

    let mut encoder = Encoder::new(Vec::new()).unwrap();
    encoder.start_directory(None).unwrap();
    encoder.start_directory(Some(b"empty")).unwrap();
    encoder.end_directory().unwrap();
    let mut file = encoder.start_regular(Some(b"file"), true, 16).unwrap();
    file.write_all(b"streamed ").unwrap();
    file.write_all(b"payload").unwrap();
    file.finish().unwrap();
    encoder.start_directory(Some(b"nested")).unwrap();
    encoder
        .symlink(Some(b"link"), b"target-\xff-bytes")
        .unwrap();
    encoder.end_directory().unwrap();
    encoder
        .regular(Some(b"weird-\xff-name"), false, b"non UTF-8 name")
        .unwrap();
    encoder.end_directory().unwrap();

    assert_eq!(encoder.finish().unwrap(), expected);
}

#[test]
fn matches_nix_store_goldens() {
    let mut regular = Encoder::new(Vec::new()).unwrap();
    regular.regular(None, false, b"hi\n").unwrap();
    assert_eq!(regular.finish().unwrap(), golden(REGULAR_GOLDEN));

    let executable_contents = b"#!/bin/bash\n\ngcc -o hello hello.c\n";
    let mut executable = Encoder::new(Vec::new()).unwrap();
    executable.regular(None, true, executable_contents).unwrap();
    assert_eq!(executable.finish().unwrap(), golden(EXECUTABLE_GOLDEN));

    let mut symlink = Encoder::new(Vec::new()).unwrap();
    symlink.symlink(None, b"hello.c").unwrap();
    assert_eq!(symlink.finish().unwrap(), golden(SYMLINK_GOLDEN));

    let mut directory = Encoder::new(Vec::new()).unwrap();
    directory.start_directory(None).unwrap();
    directory
        .regular(
            Some(b"build.sh"),
            true,
            b"#!/bin/bash\n\ngcc -o hello hello.c\n",
        )
        .unwrap();
    directory
        .regular(
            Some(b"hello.c"),
            false,
            b"#include <stdio.h>\n\nint main(int argc, char *argv[]){ exit 0; }\n",
        )
        .unwrap();
    directory.symlink(Some(b"hi.c"), b"hello.c").unwrap();
    directory.end_directory().unwrap();
    assert_eq!(directory.finish().unwrap(), golden(DIRECTORY_GOLDEN));
}

#[test]
fn rejects_bad_names_and_noncanonical_order_before_writing_nodes() {
    for name in [&b""[..], &b"."[..], &b".."[..], &b"a/b"[..], &b"a\0b"[..]] {
        let mut encoder = Encoder::new(Vec::new()).unwrap();
        encoder.start_directory(None).unwrap();
        assert!(matches!(
            encoder.regular(Some(name), false, b""),
            Err(Error::InvalidName(_))
        ));
    }

    for (first, second) in [(b"b", b"a"), (b"a", b"a")] {
        let mut encoder = Encoder::new(Vec::new()).unwrap();
        encoder.start_directory(None).unwrap();
        encoder.regular(Some(first), false, b"").unwrap();
        assert!(matches!(
            encoder.regular(Some(second), false, b""),
            Err(Error::UnsortedEntries(..))
        ));
    }
}

#[test]
fn enforces_root_and_balanced_directory_events() {
    let mut named_root = Encoder::new(Vec::new()).unwrap();
    assert!(matches!(
        named_root.regular(Some(b"named"), false, b""),
        Err(Error::InvalidEncoderEvent(_))
    ));
    named_root.regular(None, false, b"").unwrap();
    assert!(matches!(
        named_root.symlink(None, b"second"),
        Err(Error::InvalidEncoderEvent(_))
    ));

    let mut unmatched = Encoder::new(Vec::new()).unwrap();
    assert!(matches!(
        unmatched.end_directory(),
        Err(Error::InvalidEncoderEvent(_))
    ));
    unmatched.start_directory(None).unwrap();
    assert!(matches!(
        unmatched.regular(None, false, b""),
        Err(Error::InvalidEncoderEvent(_))
    ));

    let empty = Encoder::new(Vec::new()).unwrap();
    assert!(matches!(empty.finish(), Err(Error::UnfinishedArchive)));

    let mut unfinished = Encoder::new(Vec::new()).unwrap();
    unfinished.start_directory(None).unwrap();
    assert!(matches!(unfinished.finish(), Err(Error::UnfinishedArchive)));
}

#[test]
fn enforces_the_same_maximum_depth_as_tree_encoding() {
    let mut encoder = Encoder::new(Vec::new()).unwrap();
    encoder.start_directory(None).unwrap();
    for _ in 1..64 {
        encoder.start_directory(Some(b"d")).unwrap();
    }
    assert!(matches!(
        encoder.start_directory(Some(b"too-deep")),
        Err(Error::MaxDepth(64))
    ));
    for _ in 0..64 {
        encoder.end_directory().unwrap();
    }
    encoder.finish().unwrap();
}

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn regular_writer_requires_exact_size_and_only_finish_closes_the_node() {
    let output = SharedWriter::default();
    let mut short = Encoder::new(output.clone()).unwrap();
    let mut file = short.start_regular(None, false, 4).unwrap();
    file.write_all(b"abc").unwrap();
    let before_finish = output.bytes();
    assert!(matches!(
        file.finish(),
        Err(Error::RegularSizeMismatch {
            expected: 4,
            actual: 3
        })
    ));
    assert_eq!(output.bytes(), before_finish);
    assert!(matches!(short.finish(), Err(Error::EncoderPoisoned)));

    let output = SharedWriter::default();
    let mut oversized = Encoder::new(output.clone()).unwrap();
    let mut file = oversized.start_regular(None, false, 3).unwrap();
    let before_write = output.bytes();
    assert_eq!(
        file.write(b"four").unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    drop(file);
    assert_eq!(output.bytes(), before_write);
    assert!(matches!(oversized.finish(), Err(Error::EncoderPoisoned)));
}

struct SwitchWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    fail: Arc<Mutex<bool>>,
}

impl Write for SwitchWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if *self.fail.lock().unwrap() {
            Err(io::Error::other("injected writer failure"))
        } else {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write(&[]).map(|_| ())
    }
}

struct InterruptOnceWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    interrupt_next: Arc<AtomicBool>,
}

impl Write for InterruptOnceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.interrupt_next.swap(false, Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected interruption",
            ))
        } else {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn interrupted_regular_write_is_retried_without_poisoning_the_encoder() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let interrupt_next = Arc::new(AtomicBool::new(false));
    let writer = InterruptOnceWriter {
        bytes: bytes.clone(),
        interrupt_next: interrupt_next.clone(),
    };
    let mut encoder = Encoder::new(writer).unwrap();
    let mut file = encoder.start_regular(None, false, 3).unwrap();

    interrupt_next.store(true, Ordering::SeqCst);
    file.write_all(b"hi\n").unwrap();
    file.finish().unwrap();
    encoder.finish().unwrap();

    assert_eq!(*bytes.lock().unwrap(), golden(REGULAR_GOLDEN));
}

#[test]
fn writer_failures_permanently_poison_the_encoder() {
    let fail = Arc::new(Mutex::new(false));
    let writer = SwitchWriter {
        bytes: Arc::default(),
        fail: fail.clone(),
    };
    let mut encoder = Encoder::new(writer).unwrap();
    encoder.start_directory(None).unwrap();
    *fail.lock().unwrap() = true;
    assert!(matches!(
        encoder.symlink(Some(b"link"), b"target"),
        Err(Error::Io(_))
    ));
    *fail.lock().unwrap() = false;
    assert!(matches!(
        encoder.regular(Some(b"recovery"), false, b""),
        Err(Error::EncoderPoisoned)
    ));
    assert!(matches!(encoder.finish(), Err(Error::EncoderPoisoned)));

    let fail = Arc::new(Mutex::new(false));
    let writer = SwitchWriter {
        bytes: Arc::default(),
        fail: fail.clone(),
    };
    let mut encoder = Encoder::new(writer).unwrap();
    let mut file = encoder.start_regular(None, false, 3).unwrap();
    *fail.lock().unwrap() = true;
    assert!(file.write_all(b"abc").is_err());
    drop(file);
    *fail.lock().unwrap() = false;
    assert!(matches!(encoder.finish(), Err(Error::EncoderPoisoned)));
}

#[test]
fn regular_writer_is_send_across_an_async_suspension() {
    fn assert_send<T: Send>(_: T) {}

    let future = async {
        let mut encoder = Encoder::new(Vec::new()).unwrap();
        let mut file = encoder.start_regular(None, false, 3).unwrap();
        std::future::ready(()).await;
        file.write_all(b"abc").unwrap();
        file.finish().unwrap();
        encoder.finish().unwrap()
    };
    assert_send(future);
}
