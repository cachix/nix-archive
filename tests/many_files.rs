//! Wide directories must be sorted canonically without leaking descriptors.

#![cfg(unix)]

use std::fs;
use std::os::unix::ffi::OsStrExt;

use nix_archive::nar::{decode, encode_path, CaseHack, Entry};

fn open_fd_count() -> Option<usize> {
    fs::read_dir("/proc/self/fd").ok().map(Iterator::count)
}

#[test]
fn thousand_file_directory_is_sorted_without_fd_leaks() {
    const FILE_COUNT: usize = 1_001;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("many");
    fs::create_dir(&root).unwrap();

    // Reverse creation order makes a filesystem-order implementation unlikely
    // to accidentally agree with NAR's required byte ordering.
    for index in (0..FILE_COUNT).rev() {
        fs::write(root.join(format!("{index:08}")), b"hi\n").unwrap();
    }

    let before = open_fd_count();
    let mut nar = Vec::new();
    encode_path(&mut nar, &root, CaseHack::native()).unwrap();
    let after = open_fd_count();

    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after <= before + 1,
            "encoding leaked file descriptors: before={before}, after={after}"
        );
    }

    let entries = decode(&nar).unwrap();
    let names: Vec<_> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Regular { path, .. } => path.file_name().map(|name| name.as_bytes().to_vec()),
            _ => None,
        })
        .collect();
    let expected: Vec<_> = (0..FILE_COUNT)
        .map(|index| format!("{index:08}").into_bytes())
        .collect();
    assert_eq!(names, expected);
    assert!(
        matches!(entries.last(), Some(Entry::Directory { path }) if path.as_os_str().is_empty())
    );
}
