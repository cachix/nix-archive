//! Validated NAR encoding from incremental events, borrowed trees, or a filesystem tree.
//!
//! [`encode_tree`] performs no heap allocation when its writer does not.
//! [`encode_path`] streams file contents, but filesystem traversal necessarily
//! allocates directory names so they can be sorted canonically.

#[cfg(unix)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::nar::Error;
use crate::wire::{validate_child_name, write_token, MAGIC, MAX_DEPTH};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootState {
    Empty,
    Open,
    Complete,
}

struct DirectoryState {
    named: bool,
}

trait NameStorage<'name> {
    fn previous(&self, directory: usize) -> Option<&[u8]>;
    fn remember(&mut self, directory: usize, name: &'name [u8]);
    fn clear(&mut self, directory: usize);
}

struct OwnedNames {
    previous: [Vec<u8>; MAX_DEPTH],
}

impl OwnedNames {
    fn new() -> Self {
        Self {
            previous: std::array::from_fn(|_| Vec::new()),
        }
    }
}

impl<'name> NameStorage<'name> for OwnedNames {
    fn previous(&self, directory: usize) -> Option<&[u8]> {
        let previous = &self.previous[directory];
        (!previous.is_empty()).then_some(previous)
    }

    fn remember(&mut self, directory: usize, name: &'name [u8]) {
        let previous = &mut self.previous[directory];
        previous.clear();
        previous.extend_from_slice(name);
    }

    fn clear(&mut self, directory: usize) {
        self.previous[directory].clear();
    }
}

struct BorrowedNames<'tree> {
    previous: [Option<&'tree [u8]>; MAX_DEPTH],
}

impl BorrowedNames<'_> {
    fn new() -> Self {
        Self {
            previous: [None; MAX_DEPTH],
        }
    }
}

impl<'tree> NameStorage<'tree> for BorrowedNames<'tree> {
    fn previous(&self, directory: usize) -> Option<&[u8]> {
        self.previous[directory]
    }

    fn remember(&mut self, directory: usize, name: &'tree [u8]) {
        self.previous[directory] = Some(name);
    }

    fn clear(&mut self, directory: usize) {
        self.previous[directory] = None;
    }
}

struct EncoderCore<W, N> {
    writer: W,
    names: N,
    directories: [DirectoryState; MAX_DEPTH],
    depth: usize,
    root: RootState,
    poisoned: bool,
}

impl<W: Write, N> EncoderCore<W, N> {
    fn new(mut writer: W, names: N) -> Result<Self, Error> {
        write_token(&mut writer, MAGIC)?;
        Ok(Self {
            writer,
            names,
            directories: std::array::from_fn(|_| DirectoryState { named: false }),
            depth: 0,
            root: RootState::Empty,
            poisoned: false,
        })
    }

    fn start_directory<'name>(&mut self, name: Option<&'name [u8]>) -> Result<(), Error>
    where
        N: NameStorage<'name>,
    {
        let named = self.start_node(name)?;
        self.token(b"directory")?;
        self.names.clear(self.depth);
        self.directories[self.depth].named = named;
        self.depth += 1;
        Ok(())
    }

    fn end_directory(&mut self) -> Result<(), Error> {
        self.ensure_usable()?;
        if self.depth == 0 {
            return Err(Error::InvalidEncoderEvent("no directory is open"));
        }
        let named = self.directories[self.depth - 1].named;

        self.token(b")")?;
        if named {
            self.token(b")")?;
        } else {
            self.root = RootState::Complete;
        }
        self.depth -= 1;
        Ok(())
    }

    fn regular<'name>(
        &mut self,
        name: Option<&'name [u8]>,
        executable: bool,
        contents: &[u8],
    ) -> Result<(), Error>
    where
        N: NameStorage<'name>,
    {
        let named = self.start_regular(name, executable, contents.len() as u64)?;
        self.write_all(contents)?;
        self.finish_regular(named, contents.len() as u64)
    }

    fn start_regular<'name>(
        &mut self,
        name: Option<&'name [u8]>,
        executable: bool,
        size: u64,
    ) -> Result<bool, Error>
    where
        N: NameStorage<'name>,
    {
        let named = self.start_node(name)?;
        self.token(b"regular")?;
        if executable {
            self.token(b"executable")?;
            self.token(b"")?;
        }
        self.token(b"contents")?;
        self.write_all(&size.to_le_bytes())?;
        Ok(named)
    }

    fn symlink<'name>(&mut self, name: Option<&'name [u8]>, target: &[u8]) -> Result<(), Error>
    where
        N: NameStorage<'name>,
    {
        let named = self.start_node(name)?;
        self.token(b"symlink")?;
        self.token(b"target")?;
        self.token(target)?;
        self.finish_node(named)
    }

    fn finish(self) -> Result<W, Error> {
        if self.poisoned {
            return Err(Error::EncoderPoisoned);
        }
        if self.root != RootState::Complete || self.depth != 0 {
            return Err(Error::UnfinishedArchive);
        }
        Ok(self.writer)
    }

    fn ensure_usable(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::EncoderPoisoned)
        } else if self.root == RootState::Complete {
            Err(Error::InvalidEncoderEvent("archive is already complete"))
        } else {
            Ok(())
        }
    }

    fn start_node<'name>(&mut self, name: Option<&'name [u8]>) -> Result<bool, Error>
    where
        N: NameStorage<'name>,
    {
        self.ensure_usable()?;

        let named = if self.depth != 0 {
            let name = name.ok_or(Error::InvalidEncoderEvent(
                "a node inside a directory must have a name",
            ))?;
            validate_child_name(name, self.names.previous(self.depth - 1))?;
            true
        } else {
            if name.is_some() {
                return Err(Error::InvalidEncoderEvent("the root must be unnamed"));
            }
            if self.root != RootState::Empty {
                return Err(Error::InvalidEncoderEvent("archive already has a root"));
            }
            false
        };

        if self.depth >= MAX_DEPTH {
            return Err(Error::MaxDepth(MAX_DEPTH));
        }

        if named {
            self.token(b"entry")?;
            self.token(b"(")?;
            self.token(b"name")?;
            self.token(name.expect("a named node has a name"))?;
            self.token(b"node")?;
        }
        self.token(b"(")?;
        self.token(b"type")?;

        if named {
            self.names
                .remember(self.depth - 1, name.expect("a named node has a name"));
        } else {
            self.root = RootState::Open;
        }
        Ok(named)
    }

    fn finish_node(&mut self, named: bool) -> Result<(), Error> {
        self.token(b")")?;
        if named {
            self.token(b")")?;
        } else {
            self.root = RootState::Complete;
        }
        Ok(())
    }

    fn finish_regular(&mut self, named: bool, size: u64) -> Result<(), Error> {
        const ZEROS: [u8; 7] = [0; 7];
        let padding = ((8 - size % 8) % 8) as usize;
        self.write_all(&ZEROS[..padding])?;
        self.finish_node(named)
    }

    fn token(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.ensure_not_poisoned()?;
        if let Err(error) = write_token(&mut self.writer, bytes) {
            self.poisoned = true;
            return Err(Error::Io(error));
        }
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.ensure_not_poisoned()?;
        if let Err(error) = self.writer.write_all(bytes) {
            self.poisoned = true;
            return Err(Error::Io(error));
        }
        Ok(())
    }

    fn ensure_not_poisoned(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::EncoderPoisoned)
        } else {
            Ok(())
        }
    }
}

/// A validated, incremental NAR encoder.
///
/// Nodes are supplied in root-first order. A root has no name, while every
/// node inside a directory must have a name. Directory children must be
/// supplied in strictly increasing raw-byte order.
pub struct Encoder<W> {
    core: EncoderCore<W, OwnedNames>,
}

impl<W: Write> Encoder<W> {
    /// Start an incremental archive and write its magic token.
    pub fn new(writer: W) -> Result<Self, Error> {
        Ok(Self {
            core: EncoderCore::new(writer, OwnedNames::new())?,
        })
    }

    /// Start a directory node.
    pub fn start_directory(&mut self, name: Option<&[u8]>) -> Result<(), Error> {
        self.core.start_directory(name)
    }

    /// Finish the innermost open directory.
    pub fn end_directory(&mut self) -> Result<(), Error> {
        self.core.end_directory()
    }

    /// Write a complete regular-file node from memory.
    pub fn regular(
        &mut self,
        name: Option<&[u8]>,
        executable: bool,
        contents: &[u8],
    ) -> Result<(), Error> {
        self.core.regular(name, executable, contents)
    }

    /// Start a regular-file node whose contents will be streamed.
    ///
    /// The returned writer accepts exactly `size` bytes. Call
    /// [`RegularWriter::finish`] after writing them to emit padding and close
    /// the node.
    pub fn start_regular(
        &mut self,
        name: Option<&[u8]>,
        executable: bool,
        size: u64,
    ) -> Result<RegularWriter<'_, W>, Error> {
        start_regular_writer(&mut self.core, name, executable, size)
    }

    /// Write a complete symbolic-link node.
    pub fn symlink(&mut self, name: Option<&[u8]>, target: &[u8]) -> Result<(), Error> {
        self.core.symlink(name, target)
    }

    /// Validate that the archive is complete and return the underlying writer.
    pub fn finish(self) -> Result<W, Error> {
        self.core.finish()
    }
}

/// A bounded writer for one regular-file payload in an [`Encoder`].
///
/// Dropping this value without a successful [`finish`](Self::finish), writing
/// too many bytes, or encountering a non-retryable underlying writer error
/// poisons the encoder.
pub struct RegularWriter<'a, W> {
    core: &'a mut EncoderCore<W, OwnedNames>,
    expected: u64,
    written: u64,
    named: bool,
    finished: bool,
}

fn start_regular_writer<'encoder, W: Write>(
    core: &'encoder mut EncoderCore<W, OwnedNames>,
    name: Option<&[u8]>,
    executable: bool,
    size: u64,
) -> Result<RegularWriter<'encoder, W>, Error> {
    let named = core.start_regular(name, executable, size)?;
    Ok(RegularWriter {
        core,
        expected: size,
        written: 0,
        named,
        finished: false,
    })
}

impl<W: Write> RegularWriter<'_, W> {
    /// Finish this file after verifying its declared byte count.
    pub fn finish(mut self) -> Result<(), Error> {
        self.core.ensure_not_poisoned()?;
        if self.written != self.expected {
            self.core.poisoned = true;
            return Err(Error::RegularSizeMismatch {
                expected: self.expected,
                actual: self.written,
            });
        }
        self.core.finish_regular(self.named, self.expected)?;
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Write for RegularWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.core.poisoned {
            return Err(io::Error::other("NAR encoder is poisoned"));
        }

        let remaining = self.expected - self.written;
        if buf.len() as u64 > remaining {
            self.core.poisoned = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "regular-file payload exceeds its declared size",
            ));
        }

        match self.core.writer.write(buf) {
            Ok(written) if written <= buf.len() => {
                self.written += written as u64;
                Ok(written)
            }
            Ok(_) => {
                self.core.poisoned = true;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "underlying writer reported writing more bytes than supplied",
                ))
            }
            Err(error) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    self.core.poisoned = true;
                }
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.core.poisoned {
            return Err(io::Error::other("NAR encoder is poisoned"));
        }
        match self.core.writer.flush() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.core.poisoned = true;
                Err(error)
            }
        }
    }
}

impl<W> Drop for RegularWriter<'_, W> {
    fn drop(&mut self) {
        if !self.finished {
            self.core.poisoned = true;
        }
    }
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
pub fn encode_tree<'tree>(w: &mut (impl Write + ?Sized), tree: &Node<'tree>) -> Result<(), Error> {
    let mut encoder = EncoderCore::new(w, BorrowedNames::new())?;
    encode_tree_node(&mut encoder, None, tree)?;
    encoder.finish().map(|_| ())
}

/// NAR size and SHA-256 for [`encode_tree`], without allocation.
pub fn hash_tree(tree: &Node<'_>) -> Result<NarHash, Error> {
    let mut sink = HashSink::new();
    encode_tree(&mut sink, tree)?;
    Ok(sink.finish())
}

/// Serialize the filesystem tree at `path` as a NAR into `w`.
///
/// Matches Nix's native behavior: directory entries are in ascending byte
/// order and file payloads are streamed rather than buffered. On Unix,
/// owner-execute determines executability and descriptor-relative traversal
/// prevents symlinks swapped into the tree from being followed. On Windows,
/// filesystem names and symlink targets must be UTF-8 and regular files are
/// encoded as non-executable.
///
/// `case_hack` is required rather than defaulted because it changes the bytes
/// written, and therefore the hash. Pass [`CaseHack::native`] to reproduce
/// Nix's own default.
pub fn encode_path(
    w: &mut (impl Write + ?Sized),
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let mut encoder = EncoderCore::new(w, OwnedNames::new())?;
    encode_fs_root(&mut encoder, path, case_hack)?;
    encoder.finish().map(|_| ())
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

fn encode_tree_node<'tree, W: Write>(
    encoder: &mut EncoderCore<W, BorrowedNames<'tree>>,
    name: Option<&'tree [u8]>,
    node: &Node<'tree>,
) -> Result<(), Error> {
    match node {
        Node::Regular {
            executable,
            contents,
        } => encoder.regular(name, *executable, contents),
        Node::Symlink { target } => encoder.symlink(name, target),
        Node::Directory(children) => {
            encoder.start_directory(name)?;
            for child in *children {
                encode_tree_node(encoder, Some(child.name), &child.node)?;
            }
            encoder.end_directory()
        }
    }
}

struct DirectoryName {
    disk: OsString,
    #[cfg(unix)]
    archive_len: usize,
    #[cfg(windows)]
    archive: Vec<u8>,
}

impl DirectoryName {
    fn archive_bytes(&self) -> &[u8] {
        #[cfg(unix)]
        {
            &self.disk.as_bytes()[..self.archive_len]
        }
        #[cfg(windows)]
        {
            &self.archive
        }
    }
}

#[cfg(unix)]
fn encode_fs_root<W: Write>(
    encoder: &mut EncoderCore<W, OwnedNames>,
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;

    if metadata.file_type().is_symlink() {
        return encoder.symlink(None, fs::read_link(path)?.as_os_str().as_bytes());
    }

    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Error::UnsupportedFileType(path.to_owned()));
    }

    let file = open_path_node(path, metadata.is_dir())?;
    let mut diagnostic_path = path.to_owned();
    encode_opened_node(encoder, None, file, &mut diagnostic_path, case_hack)
}

#[cfg(unix)]
fn encode_fs_child<W: Write>(
    encoder: &mut EncoderCore<W, OwnedNames>,
    parent: &fs::File,
    name: &OsStr,
    archive_name: &[u8],
    path: &mut PathBuf,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let stat =
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => {
            let target =
                rustix::fs::readlinkat(parent, name, Vec::new()).map_err(io::Error::from)?;
            encoder.symlink(Some(archive_name), target.as_bytes())
        }
        FileType::RegularFile => {
            let file = open_child_node(parent, name, false)?;
            encode_opened_node(encoder, Some(archive_name), file, path, case_hack)
        }
        FileType::Directory => {
            let file = open_child_node(parent, name, true)?;
            encode_opened_node(encoder, Some(archive_name), file, path, case_hack)
        }
        _ => Err(Error::UnsupportedFileType(path.clone())),
    }
}

#[cfg(unix)]
fn encode_opened_node<W: Write>(
    encoder: &mut EncoderCore<W, OwnedNames>,
    name: Option<&[u8]>,
    mut file: fs::File,
    path: &mut PathBuf,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let metadata = file.metadata()?;

    if metadata.is_file() {
        // Owner-execute alone decides executability, matching Nix's dump().
        // Stream the contents: length from metadata, then a straight copy.
        // If the file changes size mid-encode the archive would be corrupt,
        // so verify the copied length.
        let len = metadata.len();
        let executable = metadata.permissions().mode() & 0o100 != 0;
        let mut contents = start_regular_writer(encoder, name, executable, len)?;
        let copied = io::copy(&mut (&mut file).take(len), &mut contents)?;
        if copied != len {
            return Err(Error::FileChanged(path.clone()));
        }
        // A regular read cannot sit at EOF early, but it can grow past it.
        if file.take(1).read(&mut [0u8; 1])? != 0 {
            return Err(Error::FileChanged(path.clone()));
        }
        contents.finish()
    } else if metadata.is_dir() {
        encoder.start_directory(name)?;
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
            path.push(&name.disk);
            let result = encode_fs_child(
                encoder,
                &file,
                &name.disk,
                name.archive_bytes(),
                path,
                case_hack,
            );
            path.pop();
            result?;
        }
        encoder.end_directory()
    } else {
        Err(Error::UnsupportedFileType(path.clone()))
    }
}

#[cfg(unix)]
fn open_flags(directory: bool) -> OFlags {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    flags
}

#[cfg(unix)]
fn open_path_node(path: &Path, directory: bool) -> io::Result<fs::File> {
    rustix::fs::open(path, open_flags(directory), Mode::empty())
        .map(fs::File::from)
        .map_err(io::Error::from)
}

#[cfg(unix)]
fn open_child_node(parent: &fs::File, name: &OsStr, directory: bool) -> io::Result<fs::File> {
    rustix::fs::openat(parent, name, open_flags(directory), Mode::empty())
        .map(fs::File::from)
        .map_err(io::Error::from)
}

#[cfg(unix)]
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

#[cfg(windows)]
fn encode_fs_root<W: Write>(
    encoder: &mut EncoderCore<W, OwnedNames>,
    path: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let mut diagnostic_path = path.to_owned();
    encode_windows_node(encoder, None, &mut diagnostic_path, case_hack)
}

#[cfg(windows)]
fn encode_windows_node<W: Write>(
    encoder: &mut EncoderCore<W, OwnedNames>,
    name: Option<&[u8]>,
    path: &mut PathBuf,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(&*path)?;

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(&*path)?;
        let target = windows_path_bytes(&target)?;
        return encoder.symlink(name, &target);
    }

    if metadata.is_file() {
        let mut file = fs::File::open(&*path)?;
        let len = metadata.len();
        let mut contents = start_regular_writer(encoder, name, false, len)?;
        let copied = io::copy(&mut (&mut file).take(len), &mut contents)?;
        let mut trailing = [0u8; 1];
        if copied != len || file.take(1).read(&mut trailing)? != 0 {
            return Err(Error::FileChanged(path.clone()));
        }
        return contents.finish();
    }

    if !metadata.is_dir() {
        return Err(Error::UnsupportedFileType(path.clone()));
    }

    encoder.start_directory(name)?;
    let mut names = read_windows_directory_names(path, case_hack)?;
    names.sort_unstable_by(|a, b| a.archive_bytes().cmp(b.archive_bytes()));
    for pair in names.windows(2) {
        if pair[0].archive_bytes() == pair[1].archive_bytes() {
            return Err(Error::CaseHackEncodeCollision(
                path.join(&pair[0].disk),
                path.join(&pair[1].disk),
            ));
        }
    }

    for child in names {
        path.push(&child.disk);
        let result = encode_windows_node(encoder, Some(child.archive_bytes()), path, case_hack);
        path.pop();
        result?;
    }
    encoder.end_directory()
}

#[cfg(windows)]
fn read_windows_directory_names(
    directory: &Path,
    case_hack: CaseHack,
) -> io::Result<Vec<DirectoryName>> {
    fs::read_dir(directory)?
        .map(|entry| {
            let disk = entry?.file_name();
            let text = disk.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows NAR paths must be valid UTF-8",
                )
            })?;
            let bytes = text.as_bytes();
            let archive_len = if case_hack.is_enabled() {
                find_subslice(bytes, CASE_HACK_SUFFIX).unwrap_or(bytes.len())
            } else {
                bytes.len()
            };
            let archive = bytes[..archive_len].to_vec();
            Ok(DirectoryName { disk, archive })
        })
        .collect()
}

#[cfg(windows)]
fn windows_path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    path.to_str()
        .map(|path| path.as_bytes().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows NAR symlink targets must be valid UTF-8",
            )
        })
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
        #[cfg(not(unix))]
        let cases = [(&b"hello\n"[..], false), (&b""[..], false)];
        #[cfg(unix)]
        let cases = [
            (&b"hello\n"[..], false),
            (&b"#!/bin/sh\n"[..], true),
            (&b""[..], false),
        ];
        for (contents, executable) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let file = tmp.path().join("f");
            std::fs::write(&file, contents).unwrap();
            #[cfg(unix)]
            if executable {
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

    #[cfg(unix)]
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

        let mut regular_encoder = EncoderCore::new(Vec::new(), OwnedNames::new()).unwrap();
        encode_opened_node(
            &mut regular_encoder,
            None,
            opened_regular,
            &mut regular,
            CaseHack::Disabled,
        )
        .unwrap();
        let regular_nar = regular_encoder.finish().unwrap();
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

        let mut directory_encoder = EncoderCore::new(Vec::new(), OwnedNames::new()).unwrap();
        encode_opened_node(
            &mut directory_encoder,
            None,
            opened_directory,
            &mut directory,
            CaseHack::Disabled,
        )
        .unwrap();
        let directory_nar = directory_encoder.finish().unwrap();
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
