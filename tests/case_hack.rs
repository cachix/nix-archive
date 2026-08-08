//! Nix's macOS case-collision restoration and dump behavior.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use nix_archive::nar::{
    decode, encode_path_with_case_hack, encode_tree, restore_path_with_case_hack, CaseHack, Entry,
    Error, NamedNode, Node, CASE_HACK_SUFFIX,
};

fn three_way_case_collision_nar() -> Vec<u8> {
    let children = [
        NamedNode {
            name: b"FOO",
            node: Node::Regular {
                executable: false,
                contents: b"upper",
            },
        },
        NamedNode {
            name: b"Foo",
            node: Node::Directory(&[]),
        },
        NamedNode {
            name: b"foo",
            node: Node::Symlink { target: b"FOO" },
        },
    ];
    let mut nar = Vec::new();
    encode_tree(&mut nar, &Node::Directory(&children)).unwrap();
    nar
}

#[test]
fn native_default_matches_nix_platform_default() {
    assert_eq!(
        CaseHack::native(),
        if cfg!(target_os = "macos") {
            CaseHack::Enabled
        } else {
            CaseHack::Disabled
        }
    );
}

#[test]
fn restore_numbers_case_collisions_and_dump_undoes_them() {
    let nar = three_way_case_collision_nar();
    let tmp = tempfile::tempdir().unwrap();
    let restored = tmp.path().join("restored");

    restore_path_with_case_hack(&nar, &restored, CaseHack::Enabled).unwrap();

    assert_eq!(fs::read(restored.join("FOO")).unwrap(), b"upper");
    assert!(restored.join("Foo~nix~case~hack~1").is_dir());
    assert_eq!(
        fs::read_link(restored.join("foo~nix~case~hack~2")).unwrap(),
        OsStr::from_bytes(b"FOO")
    );

    let mut dumped = Vec::new();
    encode_path_with_case_hack(&mut dumped, &restored, CaseHack::Enabled).unwrap();
    assert_eq!(dumped, nar, "case-hack restore/dump did not round trip");
}

#[test]
fn restore_rejects_a_generated_name_that_collides_with_an_explicit_name() {
    let children = [
        NamedNode {
            name: b"Test",
            node: Node::Regular {
                executable: false,
                contents: b"first",
            },
        },
        NamedNode {
            name: b"Test~nix~case~hack~1",
            node: Node::Regular {
                executable: false,
                contents: b"explicit",
            },
        },
        NamedNode {
            name: b"test",
            node: Node::Regular {
                executable: false,
                contents: b"collision",
            },
        },
    ];
    let mut nar = Vec::new();
    encode_tree(&mut nar, &Node::Directory(&children)).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    assert!(matches!(
        restore_path_with_case_hack(&nar, &tmp.path().join("out"), CaseHack::Enabled),
        Err(Error::CaseHackRestoreCollision { .. })
    ));
}

#[test]
fn dump_strips_from_first_suffix_and_sorts_by_the_unhacked_name() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a0"), b"plain").unwrap();
    fs::write(root.join("a~nix~case~hack~99ignored"), b"hacked").unwrap();

    let mut nar = Vec::new();
    encode_path_with_case_hack(&mut nar, &root, CaseHack::Enabled).unwrap();
    let entries = decode(&nar).unwrap();
    let regular: Vec<_> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Regular { path, contents, .. } => Some((
                path.file_name().unwrap().as_bytes().to_vec(),
                contents.to_vec(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        regular,
        [
            (b"a".to_vec(), b"hacked".to_vec()),
            (b"a0".to_vec(), b"plain".to_vec()),
        ]
    );
}

#[test]
fn dump_rejects_true_collision_after_suffix_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("name"), b"one").unwrap();
    let mut hacked = b"name".to_vec();
    hacked.extend_from_slice(CASE_HACK_SUFFIX);
    hacked.extend_from_slice(b"1");
    fs::write(root.join(OsStr::from_bytes(&hacked)), b"two").unwrap();

    let mut nar = Vec::new();
    assert!(matches!(
        encode_path_with_case_hack(&mut nar, &root, CaseHack::Enabled),
        Err(Error::CaseHackEncodeCollision(..))
    ));
}
