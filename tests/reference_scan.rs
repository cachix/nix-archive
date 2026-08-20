//! Reference scanning follows Nix's whole-NAR semantics.

#![cfg(unix)]

use std::fs;

use nix_archive::nar::{hash_path, hash_tree, CaseHack, NamedNode, Node, ReferencePattern};

const NAME_HASH: &str = "dc04vv14dak1c1r48qa0m23vr9jy8sm0";
const CONTENT_HASH: &str = "zc842j0rz61mjsp3h3wp5ly71ak6qgdn";
const TARGET_HASH: &str = "a5cn2i4b83gnsm60d38l3kgb8qfplm11";
const MISSING_HASH: &str = "fn7zvafq26f0c8b17brs7s95s10ibfzs";

#[test]
fn borrowed_tree_scan_covers_names_contents_and_symlink_targets() {
    let content = format!("points at /nix/store/{CONTENT_HASH}-contents");
    let target = format!("/nix/store/{TARGET_HASH}-target");
    let children = [
        NamedNode {
            name: b"contents",
            node: Node::Regular {
                executable: false,
                contents: content.as_bytes(),
            },
        },
        NamedNode {
            name: NAME_HASH.as_bytes(),
            node: Node::Regular {
                executable: false,
                contents: b"",
            },
        },
        NamedNode {
            name: b"symlink",
            node: Node::Symlink {
                target: target.as_bytes(),
            },
        },
    ];
    let tree = Node::Directory(&children);
    let pattern =
        ReferencePattern::new([NAME_HASH, CONTENT_HASH, TARGET_HASH, MISSING_HASH]).unwrap();

    let scan = pattern.scan_tree(&tree).unwrap();
    let nar_hash = hash_tree(&tree).unwrap();

    assert_eq!(scan.matches, [0, 1, 2]);
    assert_eq!(scan.nar_size, nar_hash.size);
    assert_eq!(scan.nar_sha256, nar_hash.sha256);
}

#[test]
fn filesystem_scan_hashes_and_scans_in_one_nar_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join(NAME_HASH),
        format!("/nix/store/{CONTENT_HASH}-contents"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        format!("/nix/store/{TARGET_HASH}-target"),
        root.join("symlink"),
    )
    .unwrap();

    let pattern =
        ReferencePattern::new([NAME_HASH, CONTENT_HASH, TARGET_HASH, MISSING_HASH]).unwrap();
    let scan = pattern.scan_path(&root, CaseHack::native()).unwrap();
    let nar_hash = hash_path(&root, CaseHack::native()).unwrap();

    assert_eq!(scan.matches, [0, 1, 2]);
    assert_eq!(scan.nar_size, nar_hash.size);
    assert_eq!(scan.nar_sha256, nar_hash.sha256);
}

#[test]
fn empty_pattern_still_produces_standard_nar_metadata() {
    let tree = Node::Regular {
        executable: false,
        contents: CONTENT_HASH.as_bytes(),
    };
    let pattern = ReferencePattern::new(Vec::<[u8; 32]>::new()).unwrap();

    let scan = pattern.scan_tree(&tree).unwrap();

    assert!(scan.matches.is_empty());
    let nar_hash = hash_tree(&tree).unwrap();
    assert_eq!(scan.nar_size, nar_hash.size);
    assert_eq!(scan.nar_sha256, nar_hash.sha256);
}

#[test]
fn explicit_case_hack_modes_scan_the_exact_nar_they_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join(format!("{NAME_HASH}~nix~case~hack~1")),
        CONTENT_HASH,
    )
    .unwrap();
    let pattern = ReferencePattern::new([NAME_HASH, CONTENT_HASH]).unwrap();

    for case_hack in [CaseHack::Disabled, CaseHack::Enabled] {
        let scan = pattern.scan_path(&root, case_hack).unwrap();
        let expected = hash_path(&root, case_hack).unwrap();

        assert_eq!(scan.matches, [0, 1]);
        assert_eq!(scan.nar_size, expected.size);
        assert_eq!(scan.nar_sha256, expected.sha256);
    }
}
