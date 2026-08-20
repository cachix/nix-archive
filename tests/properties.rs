//! Property coverage for both hostile bytes and generated valid trees.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nix_archive::nar::{decode, encode_path, restore_reader, CaseHack, Entry};
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum Node {
    Regular { contents: Vec<u8>, executable: bool },
    Symlink(String),
    Directory(BTreeMap<String, Node>),
}

fn nodes() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        (prop::collection::vec(any::<u8>(), 0..128), any::<bool>()).prop_map(
            |(contents, executable)| Node::Regular {
                contents,
                executable,
            }
        ),
        "[a-z][a-z0-9]{0,7}".prop_map(Node::Symlink),
    ];

    leaf.prop_recursive(3, 32, 4, |children| {
        prop::collection::btree_map("[a-z][a-z0-9]{0,7}", children, 0..5).prop_map(Node::Directory)
    })
}

fn materialize(node: &Node, path: &Path) {
    match node {
        Node::Regular {
            contents,
            executable,
        } => {
            fs::write(path, contents).unwrap();
            let mode = if *executable { 0o755 } else { 0o644 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        Node::Symlink(target) => std::os::unix::fs::symlink(target, path).unwrap(),
        Node::Directory(children) => {
            fs::create_dir(path).unwrap();
            for (name, child) in children {
                materialize(child, &path.join(name));
            }
        }
    }
}

fn unpack(entries: &[Entry<'_>], root: &Path) {
    for entry in entries {
        let destination = if entry.path().as_os_str().is_empty() {
            root.to_owned()
        } else {
            root.join(entry.path())
        };
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        match entry {
            Entry::Regular {
                executable,
                contents,
                ..
            } => {
                fs::write(&destination, contents).unwrap();
                let mode = if *executable { 0o755 } else { 0o644 };
                fs::set_permissions(&destination, fs::Permissions::from_mode(mode)).unwrap();
            }
            Entry::Symlink { target, .. } => {
                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target), &destination)
                    .unwrap();
            }
            Entry::Directory { .. } => fs::create_dir_all(&destination).unwrap(),
        }
    }
}

mod hostile_bytes {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = decode(&bytes);
            }));
            prop_assert!(outcome.is_ok());
        }

        #[test]
        fn arbitrary_streamed_input_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let tmp = tempfile::tempdir().unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut reader = bytes.as_slice();
                let _ = restore_reader(&mut reader, &tmp.path().join("restored"), CaseHack::native());
            }));
            prop_assert!(outcome.is_ok());
        }
    }
}

mod valid_trees {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn generated_filesystem_trees_round_trip(node in nodes()) {
            let tmp = tempfile::tempdir().unwrap();
            let source = tmp.path().join("source");
            materialize(&node, &source);

            let mut original = Vec::new();
            encode_path(&mut original, &source, CaseHack::native()).unwrap();
            let entries = decode(&original).unwrap();

            let restored = tmp.path().join("restored");
            unpack(&entries, &restored);
            let mut reencoded = Vec::new();
            encode_path(&mut reencoded, &restored, CaseHack::native()).unwrap();

            prop_assert_eq!(reencoded, original);
        }
    }
}
