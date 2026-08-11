//! Differential harness for nix-archive: `nix-store --dump` is the oracle.
//!
//! `--dump` serializes any filesystem path, needs no store, no daemon and no
//! experimental features, so the oracle here is even simpler than the
//! derivation corpus.
//!
//! The fixture deliberately contains a non UTF-8 filename and a non UTF-8
//! symlink target: the case that made depending on `nix-nar` unacceptable,
//! and precisely what would otherwise ship broken.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix_archive::nar::{decode, encode_path, hash_path, Entry, Error};
use sha2::{Digest as _, Sha256};

const WEIRD_NAME: &[u8] = b"weird-\xff\xfe-name";
const WEIRD_TARGET: &[u8] = b"target-\xff-bytes";
const REGULAR_GOLDEN: &str = include_str!("fixtures/regular.nar.hex");
const EXECUTABLE_GOLDEN: &str = include_str!("fixtures/executable.nar.hex");
const SYMLINK_GOLDEN: &str = include_str!("fixtures/symlink.nar.hex");
const DIRECTORY_GOLDEN: &str = include_str!("fixtures/directory.nar.hex");

fn golden(hex: &str) -> Vec<u8> {
    let digits: Vec<_> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0, "golden hex has an odd length");
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("golden is hex");
            let low = (pair[1] as char).to_digit(16).expect("golden is hex");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn have_nix() -> bool {
    Command::new("nix-store")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn nix_dump(path: &Path) -> Vec<u8> {
    let out = Command::new("nix-store")
        .arg("--dump")
        .arg(path)
        .output()
        .expect("nix-store failed to spawn");
    assert!(
        out.status.success(),
        "nix-store --dump failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Build the fixture tree. Covers: regular, executable, empty file, empty
/// directory, nesting, byte-order sorting edges (`-` sorts before `b`), a
/// symlink, and non UTF-8 in both a name and a target.
fn fixture(root: &Path) {
    fs::create_dir_all(root.join("sub/deeper")).unwrap();
    fs::create_dir_all(root.join("sub/empty-dir")).unwrap();

    fs::write(root.join("hello.txt"), "hello world\n").unwrap();
    fs::write(root.join("empty"), "").unwrap();
    fs::write(root.join("sub/deeper/file"), "nested\n").unwrap();

    fs::write(root.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(root.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();

    // '-' (0x2d) < 'b' (0x62): byte order puts "a" < "a-b" < "ab".
    fs::write(root.join("a"), "1").unwrap();
    fs::write(root.join("a-b"), "2").unwrap();
    fs::write(root.join("ab"), "3").unwrap();

    std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    std::os::unix::fs::symlink("sub", root.join("linkdir")).unwrap();
    std::os::unix::fs::symlink(OsStr::from_bytes(WEIRD_TARGET), root.join("badlink")).unwrap();
    fs::write(
        root.join(OsStr::from_bytes(WEIRD_NAME)),
        "attack of the bytes",
    )
    .unwrap();
}

fn fixture_dir() -> Option<(tempfile::TempDir, PathBuf)> {
    if !have_nix() {
        eprintln!("skipping: nix-store not on PATH");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("tree");
    fs::create_dir(&root).unwrap();
    fixture(&root);
    Some((tmp, root))
}

#[test]
fn offline_regular_and_executable_goldens_match() {
    let mut regular = Vec::new();
    nix_archive::nar::encode_regular(&mut regular, b"hi\n", false).unwrap();
    assert_eq!(regular, golden(REGULAR_GOLDEN));

    let executable_contents = b"#!/bin/bash\n\ngcc -o hello hello.c\n";
    let mut executable = Vec::new();
    nix_archive::nar::encode_regular(&mut executable, executable_contents, true).unwrap();
    assert_eq!(executable, golden(EXECUTABLE_GOLDEN));

    for (nar, expected_executable, expected_contents) in [
        (regular, false, &b"hi\n"[..]),
        (executable, true, &executable_contents[..]),
    ] {
        let entries = decode(&nar).unwrap();
        assert!(matches!(
            entries.as_slice(),
            [Entry::Regular { path, executable, contents }]
                if path.as_os_str().is_empty()
                    && *executable == expected_executable
                    && *contents == expected_contents
        ));
    }
}

#[test]
fn offline_symlink_golden_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink("hello.c", &link).unwrap();

    let mut encoded = Vec::new();
    encode_path(&mut encoded, &link).unwrap();
    assert_eq!(encoded, golden(SYMLINK_GOLDEN));
    assert!(matches!(
        decode(&encoded).unwrap().as_slice(),
        [Entry::Symlink { path, target }]
            if path.as_os_str().is_empty() && target == b"hello.c"
    ));
}

#[test]
fn offline_directory_golden_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("build.sh"),
        b"#!/bin/bash\n\ngcc -o hello hello.c\n",
    )
    .unwrap();
    fs::set_permissions(root.join("build.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("hello.c"),
        b"#include <stdio.h>\n\nint main(int argc, char *argv[]){ exit 0; }\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("hello.c", root.join("hi.c")).unwrap();

    let mut encoded = Vec::new();
    encode_path(&mut encoded, &root).unwrap();
    assert_eq!(encoded, golden(DIRECTORY_GOLDEN));
    assert_eq!(decode(&encoded).unwrap().len(), 4);
}

#[test]
fn encoder_matches_nix_store_dump() {
    let Some((_tmp, root)) = fixture_dir() else {
        return;
    };

    let mut ours = Vec::new();
    encode_path(&mut ours, &root).expect("encode");
    assert_eq!(
        ours,
        nix_dump(&root),
        "NAR bytes differ from nix-store --dump"
    );
}

#[test]
fn encoder_matches_on_non_directory_roots() {
    let Some((_tmp, root)) = fixture_dir() else {
        return;
    };

    for entry in ["hello.txt", "run.sh", "link", "linkdir", "empty"] {
        let path = root.join(entry);
        let mut ours = Vec::new();
        encode_path(&mut ours, &path).expect("encode");
        assert_eq!(ours, nix_dump(&path), "NAR bytes differ for root {entry}");
    }
}

#[test]
fn symlink_to_directory_is_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("tree");
    fs::create_dir_all(root.join("target/subdir")).unwrap();
    fs::write(root.join("target/subdir/file"), b"payload").unwrap();
    std::os::unix::fs::symlink("target", root.join("link-to-directory")).unwrap();

    let mut nar = Vec::new();
    encode_path(&mut nar, &root).unwrap();
    if have_nix() {
        assert_eq!(nar, nix_dump(&root));
    }

    let entries = decode(&nar).unwrap();
    assert!(entries.iter().any(|entry| matches!(
        entry,
        Entry::Symlink { path, target }
            if path == Path::new("link-to-directory") && target == b"target"
    )));
    assert!(!entries.iter().any(|entry| matches!(
        entry,
        Entry::Directory { path } if path == Path::new("link-to-directory")
    )));
}

#[test]
fn only_owner_execute_bit_marks_a_regular_file_executable() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("mode-test");
    fs::write(&file, b"contents").unwrap();

    for (execute_bits, expected) in [
        (0o000, false),
        (0o001, false),
        (0o010, false),
        (0o100, true),
        (0o111, true),
    ] {
        // Keep owner read/write permission so an unprivileged test process can
        // encode the file; `execute_bits` is the complete matrix under test.
        let mode = 0o600 | execute_bits;
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        let mut nar = Vec::new();
        encode_path(&mut nar, &file).unwrap();
        if have_nix() {
            assert_eq!(nar, nix_dump(&file), "Nix parity failed for mode {mode:o}");
        }
        assert!(
            matches!(
                decode(&nar).unwrap().as_slice(),
                [Entry::Regular { executable, .. }] if *executable == expected
            ),
            "wrong executable flag for execute bits {execute_bits:03o}"
        );
    }
}

#[test]
fn hash_path_matches_dump() {
    let Some((_tmp, root)) = fixture_dir() else {
        return;
    };

    let dump = nix_dump(&root);
    let nar_hash = hash_path(&root).expect("hash_path");
    assert_eq!(nar_hash.size, dump.len() as u64);
    let expected: [u8; 32] = Sha256::digest(&dump).into();
    assert_eq!(nar_hash.sha256, expected);
}

/// Unpack a post-order entry stream to disk (children arrive before their
/// directories, so parents are created on demand), then re-encode and compare
/// byte for byte with the original archive.
#[test]
fn decode_unpack_reencode_round_trips() {
    let Some((tmp, root)) = fixture_dir() else {
        return;
    };

    let dump = nix_dump(&root);
    let entries = decode(&dump).expect("decode");

    let base = tmp.path().join("unpacked");
    for entry in &entries {
        let dest = base.join(entry.path());
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        match entry {
            Entry::Regular {
                executable,
                contents,
                ..
            } => {
                fs::write(&dest, contents).unwrap();
                let mode = if *executable { 0o755 } else { 0o644 };
                fs::set_permissions(&dest, fs::Permissions::from_mode(mode)).unwrap();
            }
            Entry::Symlink { target, .. } => {
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &dest).unwrap();
            }
            Entry::Directory { .. } => {
                fs::create_dir_all(&dest).unwrap();
            }
        }
    }

    let mut reencoded = Vec::new();
    encode_path(&mut reencoded, &base).expect("re-encode");
    assert_eq!(reencoded, dump, "unpack + re-encode lost information");
}

#[test]
fn non_utf8_names_and_targets_survive() {
    let Some((_tmp, root)) = fixture_dir() else {
        return;
    };

    let dump = nix_dump(&root);
    let entries = decode(&dump).expect("decode");

    assert!(
        entries.iter().any(|e| matches!(
            e,
            Entry::Symlink { target, .. } if *target == WEIRD_TARGET
        )),
        "non UTF-8 symlink target was not preserved byte exact"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.path().file_name().map(OsStrExt::as_bytes) == Some(WEIRD_NAME)),
        "non UTF-8 file name was not preserved byte exact"
    );
}

#[test]
fn entries_are_post_order_with_root_last() {
    let Some((_tmp, root)) = fixture_dir() else {
        return;
    };

    let dump = nix_dump(&root);
    let entries = decode(&dump).expect("decode");

    let last = entries.last().expect("nonempty");
    assert!(matches!(last, Entry::Directory { path } if path.as_os_str().is_empty()));

    // Every entry must precede the Directory entry of its parent.
    for (i, entry) in entries.iter().enumerate() {
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let parent_pos = entries
            .iter()
            .position(|e| matches!(e, Entry::Directory { path } if path.as_path() == parent))
            .expect("parent directory entry exists");
        assert!(
            i < parent_pos,
            "{:?} does not precede its parent",
            entry.path()
        );
    }
}

/// Local token writer for hand-crafting malformed archives.
fn tok(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + (8 - bytes.len() % 8) % 8, 0);
}

fn directory_nar(names: &[&[u8]]) -> Vec<u8> {
    let mut nar = Vec::new();
    tok(&mut nar, b"nix-archive-1");
    tok(&mut nar, b"(");
    tok(&mut nar, b"type");
    tok(&mut nar, b"directory");
    for name in names {
        tok(&mut nar, b"entry");
        tok(&mut nar, b"(");
        tok(&mut nar, b"name");
        tok(&mut nar, name);
        tok(&mut nar, b"node");
        tok(&mut nar, b"(");
        tok(&mut nar, b"type");
        tok(&mut nar, b"regular");
        tok(&mut nar, b"contents");
        tok(&mut nar, b"x");
        tok(&mut nar, b")");
        tok(&mut nar, b")");
    }
    tok(&mut nar, b")");
    nar
}

fn nested_directory_nar(node_count: usize) -> Vec<u8> {
    fn node(out: &mut Vec<u8>, remaining: usize) {
        tok(out, b"(");
        tok(out, b"type");
        tok(out, b"directory");
        if remaining > 1 {
            tok(out, b"entry");
            tok(out, b"(");
            tok(out, b"name");
            tok(out, b"x");
            tok(out, b"node");
            node(out, remaining - 1);
            tok(out, b")");
        }
        tok(out, b")");
    }

    let mut nar = Vec::new();
    tok(&mut nar, b"nix-archive-1");
    node(&mut nar, node_count);
    nar
}

#[test]
fn rejects_malformed_input_without_panicking() {
    let dump = golden(DIRECTORY_GOLDEN);

    // Every proper prefix must error, never panic.
    for cut in 0..dump.len() {
        assert!(
            decode(&dump[..cut]).is_err(),
            "truncation at {cut} accepted"
        );
    }

    assert!(matches!(decode(b"not a nar"), Err(Error::BadMagic)));

    let mut trailing = dump.clone();
    trailing.extend_from_slice(&[0u8; 8]);
    assert!(matches!(decode(&trailing), Err(Error::TrailingBytes)));

    // Corrupt the padding after the root "(" token.
    let mut bad_padding = golden(REGULAR_GOLDEN);
    assert_eq!(bad_padding[33], 0);
    bad_padding[33] = 1;
    assert!(matches!(decode(&bad_padding), Err(Error::BadPadding)));

    // A hostile length must be rejected before conversion or allocation.
    let mut huge_length = Vec::new();
    tok(&mut huge_length, b"nix-archive-1");
    huge_length.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(decode(&huge_length), Err(Error::UnexpectedEof)));

    // Error reporting must not copy an attacker-sized unexpected token.
    let mut huge_token = Vec::new();
    tok(&mut huge_token, b"nix-archive-1");
    tok(&mut huge_token, &vec![0xff; 1024 * 1024]);
    match decode(&huge_token) {
        Err(Error::UnexpectedToken { got, .. }) => {
            assert!(got.ends_with('…'));
            assert!(
                got.len() < 4096,
                "unexpected-token preview was {} bytes",
                got.len()
            );
        }
        other => panic!("expected bounded unexpected-token error, got {other:?}"),
    }
}

#[test]
fn rejects_unsorted_and_duplicate_entries() {
    // A directory whose entries arrive as "b" then "a", and one with "a" twice.
    for (first, second) in [(b"b", b"a"), (b"a", b"a")] {
        let nar = directory_nar(&[first, second]);
        assert!(matches!(decode(&nar), Err(Error::UnsortedEntries(..))));
    }
}

#[test]
fn rejects_invalid_entry_names() {
    for name in [&b""[..], &b"."[..], &b".."[..], &b"a/b"[..], &b"a\0b"[..]] {
        let nar = directory_nar(&[name]);
        assert!(
            matches!(decode(&nar), Err(Error::InvalidName(..))),
            "invalid name {name:?} was accepted"
        );
    }
}

#[test]
fn directory_depth_matches_nix_limit() {
    assert!(decode(&nested_directory_nar(64)).is_ok());
    assert!(matches!(
        decode(&nested_directory_nar(65)),
        Err(Error::MaxDepth(64))
    ));
}

#[test]
fn case_distinct_names_remain_distinct() {
    let nar = directory_nar(&[b"A", b"a"]);
    let entries = decode(&nar).unwrap();
    let names: Vec<_> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Regular { path, .. } => path.file_name().map(|name| name.as_bytes().to_vec()),
            _ => None,
        })
        .collect();
    assert_eq!(names, [b"A".to_vec(), b"a".to_vec()]);
}
