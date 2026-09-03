#![cfg(windows)]

use std::fs;
use std::path::Path;

use nix_archive::nar::{decode, encode_path, encode_tree, CaseHack, Entry, Error, NamedNode, Node};

#[test]
fn filesystem_encoding_matches_the_portable_tree_encoder() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("alpha"), b"hello").unwrap();
    fs::create_dir(temp.path().join("nested")).unwrap();
    fs::write(temp.path().join("nested").join("zeta"), b"world").unwrap();

    let mut filesystem = Vec::new();
    encode_path(&mut filesystem, temp.path(), CaseHack::Disabled).unwrap();

    let nested = [NamedNode {
        name: b"zeta",
        node: Node::Regular {
            executable: false,
            contents: b"world",
        },
    }];
    let children = [
        NamedNode {
            name: b"alpha",
            node: Node::Regular {
                executable: false,
                contents: b"hello",
            },
        },
        NamedNode {
            name: b"nested",
            node: Node::Directory(&nested),
        },
    ];
    let mut portable = Vec::new();
    encode_tree(&mut portable, &Node::Directory(&children)).unwrap();

    assert_eq!(filesystem, portable);
    assert!(decode(&filesystem).unwrap().iter().any(|entry| matches!(
        entry,
        Entry::Regular { path, contents, executable: false }
            if path == Path::new("nested/zeta") && *contents == b"world"
    )));
}

#[test]
fn collected_decode_rejects_names_that_are_windows_path_syntax() {
    for name in [&b"nested\\escape"[..], &b"C:drive"[..], &b"\xff"[..]] {
        let children = [NamedNode {
            name,
            node: Node::Regular {
                executable: false,
                contents: b"payload",
            },
        }];
        let mut nar = Vec::new();
        encode_tree(&mut nar, &Node::Directory(&children)).unwrap();
        assert!(matches!(decode(&nar), Err(Error::InvalidName(_))));
    }
}
