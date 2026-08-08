//! Restore NAR bytes to a filesystem tree, including Nix's macOS case hack.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use crate::nar::{decode_events, CaseHack, Error, Event, CASE_HACK_SUFFIX};
use crate::wire::describe_bytes;

/// Restore a NAR at `destination` using Nix's native case-hack default.
///
/// The destination itself must not exist and its final lexical component must
/// not be empty, `.` or `..`. An error can leave a partially restored tree
/// behind. Child creation is descriptor-relative, so replacing a directory
/// path with a symlink cannot redirect later writes.
pub fn restore_path(nar: &[u8], destination: &Path) -> Result<(), Error> {
    restore_path_with_case_hack(nar, destination, CaseHack::native())
}

/// [`restore_path`] with an explicit Nix case-hack setting.
pub fn restore_path_with_case_hack(
    nar: &[u8],
    destination: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let root = RestoreRoot::new(destination)?;
    let mut directories = Vec::<DirectoryState>::new();

    decode_events(nar, |event| {
        match event {
            Event::DirectoryStart { name } => {
                let is_root = name.is_none();
                let (disk_name, path) = destination_for(name, &root, &mut directories, case_hack)?;
                let directory = if is_root {
                    create_directory_at(&root.parent, &disk_name)?
                } else {
                    let parent = directories.last().ok_or(Error::InvalidRestoreState)?;
                    create_directory_at(&parent.directory, &disk_name)?
                };
                directories.push(DirectoryState::new(path, directory));
            }
            Event::DirectoryEnd { .. } => {
                directories.pop().ok_or(Error::InvalidRestoreState)?;
            }
            Event::Regular {
                name,
                executable,
                contents,
            } => {
                let is_root = name.is_none();
                let (disk_name, _path) = destination_for(name, &root, &mut directories, case_hack)?;
                let mut file = if is_root {
                    create_regular_at(&root.parent, &disk_name)?
                } else {
                    let parent = directories.last().ok_or(Error::InvalidRestoreState)?;
                    create_regular_at(&parent.directory, &disk_name)?
                };
                file.write_all(contents)?;
                let mode = if executable { 0o755 } else { 0o644 };
                file.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            Event::Symlink { name, target } => {
                let is_root = name.is_none();
                let (disk_name, _path) = destination_for(name, &root, &mut directories, case_hack)?;
                if is_root {
                    create_symlink_at(&root.parent, &disk_name, target)?;
                } else {
                    let parent = directories.last().ok_or(Error::InvalidRestoreState)?;
                    create_symlink_at(&parent.directory, &disk_name, target)?;
                }
            }
        }
        Ok(())
    })?;

    if directories.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidRestoreState)
    }
}

struct RestoreRoot {
    parent: fs::File,
    name: OsString,
    path: PathBuf,
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
            path: destination.to_owned(),
        })
    }
}

fn destination_for(
    name: Option<&[u8]>,
    root: &RestoreRoot,
    directories: &mut [DirectoryState],
    case_hack: CaseHack,
) -> Result<(OsString, PathBuf), Error> {
    let Some(name) = name else {
        return Ok((root.name.clone(), root.path.clone()));
    };
    let parent = directories.last_mut().ok_or(Error::InvalidRestoreState)?;
    let disk_name = parent.disk_name(name, case_hack)?;
    let path = parent.path.join(&disk_name);
    Ok((disk_name, path))
}

struct DirectoryState {
    path: PathBuf,
    directory: fs::File,
    /// Original archive names keyed as Nix's `strcasecmp` map sees them.
    names: BTreeMap<Vec<u8>, OriginalName>,
}

impl DirectoryState {
    fn new(path: PathBuf, directory: fs::File) -> Self {
        Self {
            path,
            directory,
            names: BTreeMap::new(),
        }
    }

    fn disk_name(&mut self, name: &[u8], case_hack: CaseHack) -> Result<OsString, Error> {
        if !case_hack.is_enabled() {
            return Ok(OsString::from_vec(name.to_vec()));
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
            return Ok(OsString::from_vec(name.to_vec()));
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

        Ok(OsString::from_vec(candidate))
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
