//! NAR protocol conformance regressions. Keep these cases explicit: they cover
//! wire and filesystem edges that broad round-trip properties can otherwise
//! miss.

#![cfg(unix)]

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nix_archive::nar::{
    decode, encode_path, encode_tree, hash_tree, restore_path, Entry, Error, NamedNode, Node,
};

fn tok(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + (8 - bytes.len() % 8) % 8, 0);
}

fn token_nar(tokens: &[&[u8]]) -> Vec<u8> {
    let mut nar = Vec::new();
    tok(&mut nar, b"nix-archive-1");
    for token in tokens {
        tok(&mut nar, token);
    }
    nar
}

fn assert_unexpected(nar: &[u8], expected: &'static str, got: &str) {
    match decode(nar) {
        Err(Error::UnexpectedToken {
            expected: actual_expected,
            got: actual_got,
        }) => {
            assert_eq!(actual_expected, expected);
            assert_eq!(actual_got, got);
        }
        other => panic!("expected {expected:?}/{got:?} token error, got {other:?}"),
    }
}

#[test]
fn strict_field_order_and_tags_are_enforced() {
    assert_unexpected(
        &token_nar(&[b"(", b"type", b"regular", b"AAAAAAAA"]),
        "contents",
        "AAAAAAAA",
    );

    // `executable` is optional, but only before `contents`.
    assert_unexpected(
        &token_nar(&[
            b"(",
            b"type",
            b"regular",
            b"contents",
            b"payload",
            b"executable",
            b"",
            b")",
        ]),
        ")",
        "executable",
    );

    // Directory entries are exactly `name`, then `node`.
    assert_unexpected(
        &token_nar(&[b"(", b"type", b"directory", b"entry", b"(", b"node"]),
        "name",
        "node",
    );

    assert_unexpected(
        &token_nar(&[b"(", b"type", b"regular", b"executable", b"yes"]),
        "",
        "yes",
    );
    assert_unexpected(
        &token_nar(&[b"(", b"type", b"symlink", b"contents"]),
        "target",
        "contents",
    );
}

/// Exercise values immediately below, at, and above an eight-byte wire block,
/// both at the root and under nested directories.
#[test]
fn alignment_boundary_matrix_round_trips() {
    for contents in [&b""[..], &b"short"[..], &b"block000"[..], &b"block0001"[..]] {
        for executable in [false, true] {
            let regular = Node::Regular {
                executable,
                contents,
            };
            let mut nar = Vec::new();
            encode_tree(&mut nar, &regular).unwrap();
            assert_eq!(nar.len() % 8, 0);
            assert!(matches!(
                decode(&nar).unwrap().as_slice(),
                [Entry::Regular {
                    path,
                    executable: actual_executable,
                    contents: actual_contents,
                }] if path.as_os_str().is_empty()
                    && *actual_executable == executable
                    && *actual_contents == contents
            ));

            let leaf = [NamedNode {
                name: b"a",
                node: regular,
            }];
            let middle = [NamedNode {
                name: b"d",
                node: Node::Directory(&leaf),
            }];
            let nested = Node::Directory(&middle);
            let mut nar = Vec::new();
            encode_tree(&mut nar, &nested).unwrap();
            assert_eq!(nar.len() % 8, 0);
            assert!(decode(&nar).unwrap().iter().any(|entry| matches!(
                entry,
                Entry::Regular {
                    path,
                    executable: actual_executable,
                    contents: actual_contents,
                } if path == Path::new("d/a")
                    && *actual_executable == executable
                    && *actual_contents == contents
            )));
        }

        let symlink = Node::Symlink { target: contents };
        let mut nar = Vec::new();
        encode_tree(&mut nar, &symlink).unwrap();
        assert_eq!(nar.len() % 8, 0);
        assert!(matches!(
            decode(&nar).unwrap().as_slice(),
            [Entry::Symlink { path, target }]
                if path.as_os_str().is_empty() && target == contents
        ));

        let leaf = [NamedNode {
            name: b"a",
            node: symlink,
        }];
        let nested = [NamedNode {
            name: b"d",
            node: Node::Directory(&leaf),
        }];
        let mut nar = Vec::new();
        encode_tree(&mut nar, &Node::Directory(&nested)).unwrap();
        assert_eq!(nar.len() % 8, 0);
        assert!(decode(&nar).unwrap().iter().any(|entry| matches!(
            entry,
            Entry::Symlink { path, target }
                if path == Path::new("d/a") && target == contents
        )));
    }
}

/// Check a fixed complex-tree golden rather than only self-generated round
/// trips.
#[test]
fn complex_tree_golden_decodes_restores_and_reencodes() {
    let nested = [NamedNode {
        name: b".keep",
        node: Node::Regular {
            executable: false,
            contents: b"",
        },
    }];
    let children = [
        NamedNode {
            name: b".keep",
            node: Node::Regular {
                executable: false,
                contents: b"",
            },
        },
        NamedNode {
            name: b"aa",
            node: Node::Symlink {
                target: b"/nix/store/somewhereelse",
            },
        },
        NamedNode {
            name: b"keep",
            node: Node::Directory(&nested),
        },
    ];
    let tree = Node::Directory(&children);

    let (size, sha256) = hash_tree(&tree).unwrap();
    assert_eq!(size, 840);
    assert_eq!(
        sha256,
        [
            0xeb, 0xd5, 0x22, 0x79, 0xa8, 0xdf, 0x02, 0x4c, 0x9f, 0xd5, 0x71, 0x8d, 0xe4, 0x10,
            0x3b, 0xf5, 0xe7, 0x60, 0xdc, 0x7f, 0x2c, 0xf4, 0x90, 0x44, 0xee, 0x7d, 0xea, 0x87,
            0xab, 0x16, 0x91, 0x1a,
        ]
    );

    let mut nar = Vec::new();
    encode_tree(&mut nar, &tree).unwrap();
    let entries = decode(&nar).unwrap();
    assert_eq!(entries.len(), 5);
    assert!(matches!(
        &entries[0],
        Entry::Regular { path, executable: false, contents }
            if path == Path::new(".keep") && contents.is_empty()
    ));
    assert!(matches!(
        &entries[1],
        Entry::Symlink { path, target }
            if path == Path::new("aa") && target == b"/nix/store/somewhereelse"
    ));
    assert!(matches!(
        &entries[2],
        Entry::Regular { path, executable: false, contents }
            if path == Path::new("keep/.keep") && contents.is_empty()
    ));
    assert!(matches!(&entries[3], Entry::Directory { path } if path == Path::new("keep")));
    assert!(matches!(&entries[4], Entry::Directory { path } if path.as_os_str().is_empty()));

    let tmp = tempfile::tempdir().unwrap();
    let restored = tmp.path().join("restored");
    restore_path(&nar, &restored).unwrap();
    assert_eq!(
        fs::read_link(restored.join("aa"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"/nix/store/somewhereelse"
    );

    let mut reencoded = Vec::new();
    encode_path(&mut reencoded, &restored).unwrap();
    assert_eq!(reencoded, nar);
}

fn root_archives() -> Vec<(&'static str, Vec<u8>)> {
    [
        ("directory", Node::Directory(&[])),
        (
            "regular",
            Node::Regular {
                executable: false,
                contents: b"payload",
            },
        ),
        ("symlink", Node::Symlink { target: b"target" }),
    ]
    .into_iter()
    .map(|(kind, node)| {
        let mut nar = Vec::new();
        encode_tree(&mut nar, &node).unwrap();
        (kind, nar)
    })
    .collect()
}

/// Check all three root node types against pre-existing files, directories,
/// and symlinks. Restore must never replace or follow them.
#[test]
fn restore_rejects_every_existing_destination_kind() {
    for (root_kind, nar) in root_archives() {
        for occupied_kind in ["regular", "directory", "dangling-symlink", "live-symlink"] {
            let tmp = tempfile::tempdir().unwrap();
            let destination = tmp.path().join("out");
            let outside = tmp.path().join("outside");
            fs::create_dir(&outside).unwrap();

            match occupied_kind {
                "regular" => fs::write(&destination, b"keep").unwrap(),
                "directory" => fs::create_dir(&destination).unwrap(),
                "dangling-symlink" => {
                    std::os::unix::fs::symlink(tmp.path().join("missing"), &destination).unwrap()
                }
                "live-symlink" => std::os::unix::fs::symlink(&outside, &destination).unwrap(),
                _ => unreachable!(),
            }

            match restore_path(&nar, &destination) {
                Err(Error::Io(error)) => assert_eq!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists,
                    "{root_kind} root over {occupied_kind} returned {error}"
                ),
                other => {
                    panic!("{root_kind} root unexpectedly restored over {occupied_kind}: {other:?}")
                }
            }
            assert!(fs::read_dir(&outside).unwrap().next().is_none());
            if occupied_kind == "regular" {
                assert_eq!(fs::read(&destination).unwrap(), b"keep");
            }
        }
    }
}

/// Destinations whose final lexical component is empty, `.` or `..` are
/// ambiguous and can select a different object than the caller named.
#[test]
fn restore_rejects_invalid_destination_names() {
    let mut nar = Vec::new();
    encode_tree(
        &mut nar,
        &Node::Regular {
            executable: false,
            contents: b"payload",
        },
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let bad_destinations = [
        Path::new("").to_owned(),
        Path::new(".").to_owned(),
        Path::new("..").to_owned(),
        tmp.path().join("out/."),
        tmp.path().join("out/.."),
    ];

    for destination in bad_destinations {
        match restore_path(&nar, &destination) {
            Err(Error::Io(error)) => assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "invalid destination {destination:?} returned {error}"
            ),
            other => panic!("invalid destination {destination:?} was accepted: {other:?}"),
        }
    }
}

#[test]
fn borrowed_tree_encoder_rejects_invalid_and_noncanonical_names() {
    for name in [&b""[..], &b"."[..], &b".."[..], &b"a/b"[..], &b"a\0b"[..]] {
        let children = [NamedNode {
            name,
            node: Node::Directory(&[]),
        }];
        let mut nar = Vec::new();
        assert!(matches!(
            encode_tree(&mut nar, &Node::Directory(&children)),
            Err(Error::InvalidName(_))
        ));
    }

    for names in [[&b"b"[..], &b"a"[..]], [&b"a"[..], &b"a"[..]]] {
        let children = names.map(|name| NamedNode {
            name,
            node: Node::Directory(&[]),
        });
        let mut nar = Vec::new();
        assert!(matches!(
            encode_tree(&mut nar, &Node::Directory(&children)),
            Err(Error::UnsortedEntries(..))
        ));
    }
}

#[test]
fn nonzero_padding_is_rejected_at_every_alignment() {
    for target_len in 1..8 {
        let target = vec![b'x'; target_len];
        let mut nar = token_nar(&[b"(", b"type", b"symlink", b"target"]);
        let padding_start = nar.len() + 8 + target.len();
        tok(&mut nar, &target);
        tok(&mut nar, b")");

        for padding_offset in 0..8 - target_len {
            let mut corrupted = nar.clone();
            corrupted[padding_start + padding_offset] = 1;
            assert!(matches!(decode(&corrupted), Err(Error::BadPadding)));
        }
    }
}
