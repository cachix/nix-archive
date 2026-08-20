//! NAR encoding from borrowed trees or a filesystem tree.
//!
//! [`encode_tree`] performs no heap allocation when its writer does not.
//! [`encode_path`] streams file contents, but filesystem traversal necessarily
//! allocates directory names so they can be sorted canonically.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::dec::validate_name;
use crate::nar::Error;
use crate::wire::{describe_bytes, pad_len, write_token, MAGIC, MAX_DEPTH};

/// Suffix used by Nix to preserve case-colliding NAR names on macOS.
pub const CASE_HACK_SUFFIX: &[u8] = b"~nix~case~hack~";

/// Whether filesystem encoding/restoration applies Nix's case-collision hack.
///
/// Nix exposes this as the runtime `use-case-hack` setting, so an
/// installation can have it either way on any platform. macOS users who
/// created a case-sensitive APFS volume routinely set it to false, because on
/// such a volume the hack is not merely unnecessary: it rewrites any
/// legitimate name that happens to contain the suffix.
///
/// The setting is a no-op for a tree that carries no case-hack suffix, which
/// is nearly all of them, and only changes the NAR for one that does.
/// [`native`](Self::native) reproduces Nix's default; pass an explicit value
/// to follow a specific installation, or to process an archive whose
/// provenance differs from the current host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseHack {
    Disabled,
    Enabled,
}

impl CaseHack {
    /// Nix's compiled-in default for `use-case-hack`: enabled on macOS,
    /// disabled elsewhere.
    ///
    /// This mirrors what Nix ships rather than probing whether the filesystem
    /// is genuinely case-insensitive. The distinction matters because NAR
    /// bytes feed store-path identity: guessing differently from Nix would
    /// produce different store paths for the same tree. macOS is Nix's proxy
    /// for a case-insensitive filesystem, and matching the proxy is what keeps
    /// hashes identical. Run `nix config show use-case-hack` when an
    /// installation may have overridden it.
    pub const fn native() -> Self {
        if cfg!(target_os = "macos") {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    pub(crate) const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// One borrowed node for allocation-free NAR encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node<'a> {
    Regular {
        executable: bool,
        contents: &'a [u8],
    },
    Symlink {
        target: &'a [u8],
    },
    /// Children must be in strictly ascending byte order by name.
    Directory(&'a [NamedNode<'a>]),
}

/// A named child in a borrowed [`Node::Directory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedNode<'a> {
    pub name: &'a [u8],
    pub node: Node<'a>,
}

/// The byte length and SHA-256 digest of an encoded NAR.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NarHash {
    /// Encoded NAR size in bytes.
    pub size: u64,
    /// SHA-256 of the complete encoded NAR.
    pub sha256: [u8; 32],
}

impl NarHash {
    /// Split the result into `(size, sha256)`.
    pub const fn into_parts(self) -> (u64, [u8; 32]) {
        (self.size, self.sha256)
    }
}

/// Serialize an already-sorted borrowed tree without allocating.
///
/// Allocation freedom assumes that `w` itself does not allocate. Names are
/// validated and directory order is checked while the tree is written.
pub fn encode_tree(w: &mut (impl Write + ?Sized), tree: &Node<'_>) -> Result<(), Error> {
    write_token(w, MAGIC)?;
    encode_tree_node(w, tree, 0)
}

/// NAR size and SHA-256 for [`encode_tree`], without allocation.
pub fn hash_tree(tree: &Node<'_>) -> Result<NarHash, Error> {
    let mut sink = HashSink::new();
    encode_tree(&mut sink, tree)?;
    Ok(sink.finish())
}

/// Serialize the filesystem tree at `path` as a NAR into `w`.
///
/// Matches Nix's native behavior: directory entries in ascending byte order,
/// owner-execute determines executability. File payloads are streamed rather
/// than buffered. Once the root is opened, traversal is descriptor-relative
/// and does not follow symlinks swapped into the tree concurrently.
///
/// `case_hack` is required rather than defaulted because it changes the bytes
/// written, and therefore the hash. Pass [`CaseHack::native`] to reproduce
/// Nix's own default.
pub fn encode_path(
    w: &mut (impl Write + ?Sized),
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    write_token(w, MAGIC)?;
    encode_fs_root(w, path, case_hack)
}

/// NAR size and SHA-256 of the tree at `path`, without keeping the bytes.
///
/// These values are what a `PathInfo` carries as `nar_size` / `nar_sha256`, and
/// what a fixed output derivation with `outputHashMode = "recursive"` is
/// verified against.
///
/// `case_hack` is required rather than defaulted because it changes the hash.
/// Pass [`CaseHack::native`] to reproduce Nix's own default.
pub fn hash_path(path: &Path, case_hack: CaseHack) -> Result<NarHash, Error> {
    let mut sink = HashSink::new();
    encode_path(&mut sink, path, case_hack)?;
    Ok(sink.finish())
}

/// Renamed to [`encode_path`], which now takes the setting directly.
#[deprecated(
    since = "0.3.0",
    note = "use `encode_path`, which now takes `case_hack` directly"
)]
pub fn encode_path_with_case_hack(
    w: &mut (impl Write + ?Sized),
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    encode_path(w, path, case_hack)
}

/// Renamed to [`hash_path`], which now takes the setting directly.
#[deprecated(
    since = "0.3.0",
    note = "use `hash_path`, which now takes `case_hack` directly"
)]
pub fn hash_path_with_case_hack(path: &Path, case_hack: CaseHack) -> Result<NarHash, Error> {
    hash_path(path, case_hack)
}

/// Serialize a single regular file from in-memory bytes as a complete NAR.
pub fn encode_regular(
    w: &mut (impl Write + ?Sized),
    contents: &[u8],
    executable: bool,
) -> Result<(), Error> {
    encode_tree(
        w,
        &Node::Regular {
            executable,
            contents,
        },
    )
}

/// NAR size and SHA-256 for [`encode_regular`].
pub fn hash_regular(contents: &[u8], executable: bool) -> NarHash {
    hash_tree(&Node::Regular {
        executable,
        contents,
    })
    .expect("a regular borrowed node is always valid")
}

pub(crate) struct HashSink {
    hasher: Sha256,
    len: u64,
}

impl HashSink {
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            len: 0,
        }
    }

    pub(crate) fn finish(self) -> NarHash {
        NarHash {
            size: self.len,
            sha256: self.hasher.finalize().into(),
        }
    }
}

impl Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_tree_node(
    w: &mut (impl Write + ?Sized),
    node: &Node<'_>,
    depth: usize,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }

    write_token(w, b"(")?;
    write_token(w, b"type")?;

    match node {
        Node::Regular {
            executable,
            contents,
        } => {
            write_token(w, b"regular")?;
            if *executable {
                write_token(w, b"executable")?;
                write_token(w, b"")?;
            }
            write_token(w, b"contents")?;
            write_token(w, contents)?;
        }
        Node::Symlink { target } => {
            write_token(w, b"symlink")?;
            write_token(w, b"target")?;
            write_token(w, target)?;
        }
        Node::Directory(children) => {
            write_token(w, b"directory")?;
            let mut previous: Option<&[u8]> = None;
            for child in *children {
                validate_name(child.name)?;
                if let Some(previous) = previous {
                    if child.name <= previous {
                        return Err(Error::UnsortedEntries(
                            describe_bytes(child.name),
                            describe_bytes(previous),
                        ));
                    }
                }
                previous = Some(child.name);

                write_token(w, b"entry")?;
                write_token(w, b"(")?;
                write_token(w, b"name")?;
                write_token(w, child.name)?;
                write_token(w, b"node")?;
                encode_tree_node(w, &child.node, depth + 1)?;
                write_token(w, b")")?;
            }
        }
    }

    write_token(w, b")")?;
    Ok(())
}

struct DirectoryName {
    disk: OsString,
    archive_len: usize,
}

impl DirectoryName {
    fn archive_bytes(&self) -> &[u8] {
        &self.disk.as_bytes()[..self.archive_len]
    }
}

fn encode_fs_root(
    w: &mut (impl Write + ?Sized),
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;

    if metadata.file_type().is_symlink() {
        return encode_symlink_node(w, fs::read_link(path)?.as_os_str().as_bytes(), 0);
    }

    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Error::UnsupportedFileType(path.to_owned()));
    }

    let file = open_path_node(path, metadata.is_dir())?;
    let mut diagnostic_path = path.to_owned();
    encode_opened_node(w, file, &mut diagnostic_path, case_hack, 0)
}

fn encode_fs_child(
    w: &mut (impl Write + ?Sized),
    parent: &fs::File,
    name: &OsStr,
    path: &mut PathBuf,
    case_hack: CaseHack,
    depth: usize,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }

    let stat =
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => {
            let target =
                rustix::fs::readlinkat(parent, name, Vec::new()).map_err(io::Error::from)?;
            encode_symlink_node(w, target.as_bytes(), depth)
        }
        FileType::RegularFile => {
            let file = open_child_node(parent, name, false)?;
            encode_opened_node(w, file, path, case_hack, depth)
        }
        FileType::Directory => {
            let file = open_child_node(parent, name, true)?;
            encode_opened_node(w, file, path, case_hack, depth)
        }
        _ => Err(Error::UnsupportedFileType(path.clone())),
    }
}

fn encode_opened_node(
    w: &mut (impl Write + ?Sized),
    mut file: fs::File,
    path: &mut PathBuf,
    case_hack: CaseHack,
    depth: usize,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }

    let metadata = file.metadata()?;
    write_token(w, b"(")?;
    write_token(w, b"type")?;

    if metadata.is_file() {
        write_token(w, b"regular")?;
        // Owner-execute alone decides executability, matching Nix's dump().
        if metadata.permissions().mode() & 0o100 != 0 {
            write_token(w, b"executable")?;
            write_token(w, b"")?;
        }
        write_token(w, b"contents")?;
        // Stream the contents: length from metadata, then a straight copy.
        // If the file changes size mid-encode the archive would be corrupt,
        // so verify the copied length.
        let len = metadata.len();
        w.write_all(&len.to_le_bytes())?;
        let copied = io::copy(&mut file, w)?;
        if copied != len {
            return Err(Error::FileChanged(path.clone()));
        }
        // A regular read cannot sit at EOF early, but it can grow past it.
        if file.take(1).read(&mut [0u8; 1])? != 0 {
            return Err(Error::FileChanged(path.clone()));
        }
        w.write_all(&[0u8; 8][..pad_len(len as usize)])?;
    } else if metadata.is_dir() {
        write_token(w, b"directory")?;
        let mut names = read_directory_names(&file, case_hack)?;
        names.sort_unstable_by(|a, b| a.archive_bytes().cmp(b.archive_bytes()));

        for pair in names.windows(2) {
            if pair[0].archive_bytes() == pair[1].archive_bytes() {
                return Err(Error::CaseHackEncodeCollision(
                    path.join(&pair[0].disk),
                    path.join(&pair[1].disk),
                ));
            }
        }

        for name in names {
            write_token(w, b"entry")?;
            write_token(w, b"(")?;
            write_token(w, b"name")?;
            write_token(w, name.archive_bytes())?;
            write_token(w, b"node")?;
            path.push(&name.disk);
            let result = encode_fs_child(w, &file, &name.disk, path, case_hack, depth + 1);
            path.pop();
            result?;
            write_token(w, b")")?;
        }
    } else {
        return Err(Error::UnsupportedFileType(path.clone()));
    }

    write_token(w, b")")?;
    Ok(())
}

fn encode_symlink_node(
    w: &mut (impl Write + ?Sized),
    target: &[u8],
    depth: usize,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }
    write_token(w, b"(")?;
    write_token(w, b"type")?;
    write_token(w, b"symlink")?;
    write_token(w, b"target")?;
    write_token(w, target)?;
    write_token(w, b")")?;
    Ok(())
}

fn open_flags(directory: bool) -> OFlags {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    flags
}

fn open_path_node(path: &Path, directory: bool) -> io::Result<fs::File> {
    rustix::fs::open(path, open_flags(directory), Mode::empty())
        .map(fs::File::from)
        .map_err(io::Error::from)
}

fn open_child_node(parent: &fs::File, name: &OsStr, directory: bool) -> io::Result<fs::File> {
    rustix::fs::openat(parent, name, open_flags(directory), Mode::empty())
        .map(fs::File::from)
        .map_err(io::Error::from)
}

fn read_directory_names(
    directory: &fs::File,
    case_hack: CaseHack,
) -> io::Result<Vec<DirectoryName>> {
    let entries = Dir::read_from(directory).map_err(io::Error::from)?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let disk = OsString::from_vec(bytes.to_vec());
        let archive_len = if case_hack.is_enabled() {
            find_subslice(disk.as_bytes(), CASE_HACK_SUFFIX)
                .unwrap_or_else(|| disk.as_bytes().len())
        } else {
            disk.as_bytes().len()
        };
        names.push(DirectoryName { disk, archive_len });
    }
    Ok(names)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nar::{decode, Entry};

    /// encode_regular must agree byte for byte with encode_path over the same
    /// contents written to disk (which dump_parity holds against nix-store).
    #[test]
    fn encode_regular_matches_encode_path() {
        for (contents, executable) in [
            (&b"hello\n"[..], false),
            (&b"#!/bin/sh\n"[..], true),
            (&b""[..], false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let file = tmp.path().join("f");
            std::fs::write(&file, contents).unwrap();
            if executable {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let mut from_fs = Vec::new();
            encode_path(&mut from_fs, &file, CaseHack::native()).unwrap();
            let mut from_bytes = Vec::new();
            encode_regular(&mut from_bytes, contents, executable).unwrap();
            assert_eq!(from_bytes, from_fs);
            assert_eq!(
                hash_regular(contents, executable).size,
                from_fs.len() as u64
            );
        }
    }

    #[test]
    fn opened_nodes_cannot_be_redirected_by_path_swaps() {
        let tmp = tempfile::tempdir().unwrap();

        let mut regular = tmp.path().join("regular");
        let moved_regular = tmp.path().join("moved-regular");
        let secret = tmp.path().join("secret");
        fs::write(&regular, b"expected").unwrap();
        fs::write(&secret, b"must not leak").unwrap();
        let opened_regular = open_path_node(&regular, false).unwrap();
        fs::rename(&regular, &moved_regular).unwrap();
        std::os::unix::fs::symlink(&secret, &regular).unwrap();

        let mut regular_nar = Vec::new();
        write_token(&mut regular_nar, MAGIC).unwrap();
        encode_opened_node(
            &mut regular_nar,
            opened_regular,
            &mut regular,
            CaseHack::Disabled,
            0,
        )
        .unwrap();
        assert!(matches!(
            decode(&regular_nar).unwrap().as_slice(),
            [Entry::Regular { contents, .. }] if *contents == b"expected"
        ));

        let mut directory = tmp.path().join("directory");
        let moved_directory = tmp.path().join("moved-directory");
        let outside = tmp.path().join("outside");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("inside"), b"expected child").unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("outside"), b"must not leak").unwrap();
        let opened_directory = open_path_node(&directory, true).unwrap();
        fs::rename(&directory, &moved_directory).unwrap();
        std::os::unix::fs::symlink(&outside, &directory).unwrap();

        let mut directory_nar = Vec::new();
        write_token(&mut directory_nar, MAGIC).unwrap();
        encode_opened_node(
            &mut directory_nar,
            opened_directory,
            &mut directory,
            CaseHack::Disabled,
            0,
        )
        .unwrap();
        let entries = decode(&directory_nar).unwrap();
        assert!(entries.iter().any(|entry| matches!(
            entry,
            Entry::Regular { path, contents, .. }
                if path == Path::new("inside") && *contents == b"expected child"
        )));
        assert!(!entries
            .iter()
            .any(|entry| entry.path() == Path::new("outside")));
    }
}
