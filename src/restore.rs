//! Restore NAR bytes to a filesystem tree, including Nix's macOS case hack.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rustix::fs::{Mode, OFlags};

use crate::nar::{
    decode_events, decode_events_reader, CaseHack, Error, Event, FileContents, CASE_HACK_SUFFIX,
};
use crate::wire::describe_bytes;

/// Restore a NAR at `destination`.
///
/// **Choose this when the archive is already in memory.**
///
/// Pros: a file's payload is one borrowed slice, so it reaches disk in a
/// single `write`; no decoding allocation beyond the case-collision state.
///
/// Cons: `nar` must be fully in memory. Use [`restore_reader`] when it is not.
///
/// `case_hack` is required rather than defaulted because it decides which
/// names land on disk, and so the hash of any archive dumped from the result.
/// Pass [`CaseHack::native`] to reproduce Nix's own default.
///
/// The destination itself must not exist and its final lexical component must
/// not be empty, `.` or `..`. An error can leave a partially restored tree
/// behind. Child creation is descriptor-relative, so replacing a directory
/// path with a symlink cannot redirect later writes.
pub fn restore(nar: &[u8], destination: &Path, case_hack: CaseHack) -> Result<(), Error> {
    let mut visitor = RestoreVisitor::new(destination, case_hack)?;
    decode_events(nar, |event| visitor.visit(event))?;
    visitor.finish();
    Ok(())
}

/// Restore a NAR read from `reader`.
///
/// **Choose this when the archive is arriving, or is too large to hold.**
///
/// Pros: memory use is bounded by directory depth and metadata rather than
/// payload size, so an archive of any size can be restored; contents go
/// straight from `reader` to disk without ever being held, and because `R` is
/// carried rather than erased, a file-backed archive copies payloads in the
/// kernel rather than a chunk at a time through userspace.
///
/// Cons: metadata tokens are bounded, so a few archives [`restore`] accepts
/// are rejected; `reader`'s framing is consumed in small pieces, so wrap an
/// unbuffered source in a [`BufReader`](std::io::BufReader), and the archive
/// must be the whole of what remains on it.
///
/// `case_hack` carries the same requirement as in [`restore`]. The destination
/// and partial-restoration guarantees are otherwise the same.
pub fn restore_reader<R: Read + ?Sized>(
    reader: &mut R,
    destination: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let mut visitor = RestoreVisitor::new(destination, case_hack)?;
    decode_events_reader(reader, |event| visitor.visit(event))?;
    visitor.finish();
    Ok(())
}

/// Renamed to [`restore`], which now takes the setting directly.
#[deprecated(
    since = "0.3.0",
    note = "use `restore`, which takes a destination path and `case_hack` directly"
)]
pub fn restore_path(nar: &[u8], destination: &Path) -> Result<(), Error> {
    restore(nar, destination, CaseHack::native())
}

/// Renamed to [`restore`], which now takes the setting directly.
#[deprecated(
    since = "0.3.0",
    note = "use `restore`, which now takes `case_hack` directly"
)]
pub fn restore_path_with_case_hack(
    nar: &[u8],
    destination: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    restore(nar, destination, case_hack)
}

/// Renamed to [`restore_reader`], which now takes the setting directly.
#[deprecated(
    since = "0.3.0",
    note = "use `restore_reader`, which now takes `case_hack` directly"
)]
pub fn restore_reader_with_case_hack<R: Read + ?Sized>(
    reader: &mut R,
    destination: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    restore_reader(reader, destination, case_hack)
}

/// How a decoder presents a regular file's contents to the file created for
/// it.
///
/// This is the only thing that differs between the two restore paths, so it is
/// the only thing they state separately: [`decode_events`] hands over a whole
/// payload as one borrowed slice, [`decode_events_reader`] streams it. A third
/// contents flavor is a new impl here rather than an edit at every call site.
trait Contents {
    fn write_to(self, file: &mut fs::File) -> io::Result<()>;
}

impl Contents for &[u8] {
    fn write_to(self, file: &mut fs::File) -> io::Result<()> {
        file.write_all(self)
    }
}

impl<R: Read + ?Sized> Contents for FileContents<'_, R> {
    fn write_to(mut self, file: &mut fs::File) -> io::Result<()> {
        // `copy_to` rather than `io::copy` on the `Read` impl: it keeps the
        // archive's reader type concrete, so a file-backed archive restores
        // through the kernel instead of one userspace round trip per chunk.
        self.copy_to(file).map(drop)
    }
}

/// Turns decoder events into a filesystem tree.
///
/// Both restore APIs are this visitor over one of the two decoders, and differ
/// only in which [`Contents`] impl the decoder's payload type selects.
/// Everything that could otherwise drift between the two, the case-hack
/// numbering, the directory stack, the descriptor-relative creation, lives
/// here once.
struct RestoreVisitor {
    root: RestoreRoot,
    directories: Vec<DirectoryState>,
    case_hack: CaseHack,
}

impl RestoreVisitor {
    fn new(destination: &Path, case_hack: CaseHack) -> Result<Self, Error> {
        Ok(Self {
            root: RestoreRoot::new(destination)?,
            directories: Vec::new(),
            case_hack,
        })
    }

    /// Resolve where a child belongs, then act on it there.
    ///
    /// The parent descriptor and the on-disk name are handed to `act` rather
    /// than returned, which keeps the borrow of `self` inside the call and the
    /// case-hack name borrowed rather than copied.
    fn with_place<T>(
        &mut self,
        name: Option<&[u8]>,
        act: impl FnOnce(&fs::File, &OsStr) -> io::Result<T>,
    ) -> Result<T, Error> {
        let placed = match name {
            Some(name) => {
                let case_hack = self.case_hack;
                let parent = self.directories.last_mut().unwrap_or_else(|| {
                    unreachable!("the decoder emits children only inside directories")
                });
                let disk_name = parent.disk_name(name, case_hack)?;
                act(&parent.directory, &disk_name)
            }
            None => act(&self.root.parent, &self.root.name),
        };
        Ok(placed?)
    }

    fn visit<C: Contents>(&mut self, event: Event<'_, C>) -> Result<(), Error> {
        match event {
            Event::DirectoryStart { name } => {
                let directory = self.with_place(name, create_directory_at)?;
                self.directories.push(DirectoryState::new(directory));
            }
            Event::DirectoryEnd { .. } => {
                self.directories
                    .pop()
                    .unwrap_or_else(|| unreachable!("the decoder emits balanced directory events"));
            }
            Event::Regular {
                name,
                executable,
                contents,
            } => {
                let mut file = self.with_place(name, create_regular_at)?;
                contents.write_to(&mut file)?;
                let mode = if executable { 0o755 } else { 0o644 };
                file.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            Event::Symlink { name, target } => {
                self.with_place(name, |parent, disk_name| {
                    create_symlink_at(parent, disk_name, target)
                })?;
            }
        }
        Ok(())
    }

    fn finish(self) {
        debug_assert!(self.directories.is_empty());
    }
}

struct RestoreRoot {
    parent: fs::File,
    name: OsString,
}

impl RestoreRoot {
    fn new(destination: &Path) -> io::Result<Self> {
        let destination_bytes = destination.as_os_str().as_bytes();
        let end = destination_bytes
            .iter()
            .rposition(|&byte| byte != b'/')
            .map_or(0, |position| position + 1);
        let final_component = destination_bytes[..end]
            .rsplit(|&byte| byte == b'/')
            .next()
            .unwrap_or_default();
        if final_component.is_empty() || final_component == b"." || final_component == b".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "restore destination must end in a file name other than `.` or `..`",
            ));
        }

        let name = destination.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "restore destination must end in a file name",
            )
        })?;
        let parent_path = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = rustix::fs::open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(io::Error::from)?;
        Ok(Self {
            parent,
            name: name.to_owned(),
        })
    }
}

struct DirectoryState {
    directory: fs::File,
    /// Original archive names keyed as Nix's `strcasecmp` map sees them.
    names: BTreeMap<Vec<u8>, OriginalName>,
}

impl DirectoryState {
    fn new(directory: fs::File) -> Self {
        Self {
            directory,
            names: BTreeMap::new(),
        }
    }

    fn disk_name<'a>(
        &mut self,
        name: &'a [u8],
        case_hack: CaseHack,
    ) -> Result<Cow<'a, OsStr>, Error> {
        if !case_hack.is_enabled() {
            return Ok(Cow::Borrowed(OsStr::from_bytes(name)));
        }

        let folded = fold_name(name);
        let collision_number = if let Some(original) = self.names.get_mut(&folded) {
            original.collisions = original
                .collisions
                .checked_add(1)
                .ok_or(Error::CaseHackCounterOverflow)?;
            original.collisions
        } else {
            self.names.insert(
                folded,
                OriginalName {
                    bytes: name.to_vec(),
                    collisions: 0,
                },
            );
            return Ok(Cow::Borrowed(OsStr::from_bytes(name)));
        };

        let mut candidate = Vec::with_capacity(name.len() + CASE_HACK_SUFFIX.len() + 20);
        candidate.extend_from_slice(name);
        candidate.extend_from_slice(CASE_HACK_SUFFIX);
        candidate.extend_from_slice(collision_number.to_string().as_bytes());

        if let Some(existing) = self.names.get(&fold_name(&candidate)) {
            return Err(Error::CaseHackRestoreCollision {
                archive_name: describe_bytes(name),
                generated_name: describe_bytes(&candidate),
                existing_name: describe_bytes(&existing.bytes),
            });
        }

        Ok(Cow::Owned(OsString::from_vec(candidate)))
    }
}

fn create_directory_at(parent: &fs::File, name: &OsStr) -> io::Result<fs::File> {
    rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o777)).map_err(io::Error::from)?;
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(io::Error::from)
}

fn create_regular_at(parent: &fs::File, name: &OsStr) -> io::Result<fs::File> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o666),
    )
    .map(fs::File::from)
    .map_err(io::Error::from)
}

fn create_symlink_at(parent: &fs::File, name: &OsStr, target: &[u8]) -> io::Result<()> {
    rustix::fs::symlinkat(OsStr::from_bytes(target), parent, name).map_err(io::Error::from)
}

struct OriginalName {
    bytes: Vec<u8>,
    collisions: u64,
}

fn fold_name(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|&byte| {
            // SAFETY: `tolower` accepts EOF or any value representable as an
            // unsigned char; converting a u8 to c_int satisfies that contract.
            unsafe { libc::tolower(i32::from(byte)) as u8 }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_descriptor_prevents_symlink_redirection() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = fs::File::open(tmp.path()).unwrap();
        let directory = create_directory_at(&parent, OsStr::new("destination")).unwrap();

        let destination = tmp.path().join("destination");
        let moved = tmp.path().join("moved-destination");
        let outside = tmp.path().join("outside");
        fs::rename(&destination, &moved).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();

        let mut child = create_regular_at(&directory, OsStr::new("child")).unwrap();
        child.write_all(b"anchored").unwrap();

        assert_eq!(fs::read(moved.join("child")).unwrap(), b"anchored");
        assert!(!outside.join("child").exists());
    }
}
