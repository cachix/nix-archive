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

use crate::dec::validate_name;
use crate::nar::{decode_events, CaseHack, Error, Event, CASE_HACK_SUFFIX};
use crate::wire::{describe_bytes, ERROR_PREVIEW_BYTES, MAGIC, MAX_DEPTH};

/// Names and symlink targets ultimately have to fit in a filesystem object.
/// Keep malformed streamed archives from requesting an effectively unbounded
/// allocation before the operating system can reject them.
const MAX_METADATA_TOKEN: usize = 1024 * 1024;
const MAX_CONTROL_TOKEN: usize = 16;

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
                let directory = if let Some(name) = name {
                    let parent = directories.last_mut().unwrap_or_else(|| {
                        unreachable!("the decoder emits children only inside directories")
                    });
                    let disk_name = parent.disk_name(name, case_hack)?;
                    create_directory_at(&parent.directory, &disk_name)?
                } else {
                    create_directory_at(&root.parent, &root.name)?
                };
                directories.push(DirectoryState::new(directory));
            }
            Event::DirectoryEnd { .. } => {
                directories
                    .pop()
                    .unwrap_or_else(|| unreachable!("the decoder emits balanced directory events"));
            }
            Event::Regular {
                name,
                executable,
                contents,
            } => {
                let mut file = if let Some(name) = name {
                    let parent = directories.last_mut().unwrap_or_else(|| {
                        unreachable!("the decoder emits children only inside directories")
                    });
                    let disk_name = parent.disk_name(name, case_hack)?;
                    create_regular_at(&parent.directory, &disk_name)?
                } else {
                    create_regular_at(&root.parent, &root.name)?
                };
                file.write_all(contents)?;
                let mode = if executable { 0o755 } else { 0o644 };
                file.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            Event::Symlink { name, target } => {
                if let Some(name) = name {
                    let parent = directories.last_mut().unwrap_or_else(|| {
                        unreachable!("the decoder emits children only inside directories")
                    });
                    let disk_name = parent.disk_name(name, case_hack)?;
                    create_symlink_at(&parent.directory, &disk_name, target)?;
                } else {
                    create_symlink_at(&root.parent, &root.name, target)?;
                }
            }
        }
        Ok(())
    })?;

    debug_assert!(directories.is_empty());
    Ok(())
}

/// Restore a NAR read from `reader` using Nix's native case-hack default.
///
/// Unlike [`restore_path`], this API does not require the complete archive in
/// memory. Regular-file contents are copied directly from `reader` to disk;
/// memory use is bounded by directory depth and metadata rather than payload
/// size. The destination and partial-restoration guarantees are otherwise the
/// same as [`restore_path`].
pub fn restore_reader(reader: &mut (impl Read + ?Sized), destination: &Path) -> Result<(), Error> {
    restore_reader_with_case_hack(reader, destination, CaseHack::native())
}

/// [`restore_reader`] with an explicit Nix case-hack setting.
pub fn restore_reader_with_case_hack(
    reader: &mut (impl Read + ?Sized),
    destination: &Path,
    case_hack: CaseHack,
) -> Result<(), Error> {
    let root = RestoreRoot::new(destination)?;
    let mut cursor = ReaderCursor::new(reader);
    cursor.expect_magic()?;
    restore_node(&mut cursor, &root.parent, &root.name, case_hack, 0)?;
    if cursor.is_exhausted()? {
        Ok(())
    } else {
        Err(Error::TrailingBytes)
    }
}

fn restore_node<R: Read + ?Sized>(
    cursor: &mut ReaderCursor<'_, R>,
    parent: &fs::File,
    disk_name: &OsStr,
    case_hack: CaseHack,
    depth: usize,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }

    cursor.expect("(")?;
    cursor.expect("type")?;
    let node_type = cursor.read_control("regular, symlink or directory")?;

    match node_type.as_bytes() {
        b"regular" => {
            let token = cursor.read_control("contents")?;
            let executable = if token.as_bytes() == b"executable" {
                cursor.expect("")?;
                cursor.expect("contents")?;
                true
            } else if token.as_bytes() == b"contents" {
                false
            } else {
                return Err(Error::UnexpectedToken {
                    expected: "contents",
                    got: describe_bytes(token.as_bytes()),
                });
            };

            let mut file = create_regular_at(parent, disk_name)?;
            cursor.copy_token_to(&mut file)?;
            cursor.expect(")")?;
            let mode = if executable { 0o755 } else { 0o644 };
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        b"symlink" => {
            cursor.expect("target")?;
            let mut target = Vec::new();
            cursor.read_bytes(&mut target, MAX_METADATA_TOKEN)?;
            cursor.expect(")")?;
            create_symlink_at(parent, disk_name, &target)?;
        }
        b"directory" => {
            let directory = create_directory_at(parent, disk_name)?;
            let mut state = DirectoryState::new(directory);
            let mut previous_name = Vec::new();
            let mut child_name = Vec::new();

            loop {
                let token = cursor.read_control("entry or )")?;
                if token.as_bytes() == b")" {
                    break;
                }
                if token.as_bytes() != b"entry" {
                    return Err(Error::UnexpectedToken {
                        expected: "entry or )",
                        got: describe_bytes(token.as_bytes()),
                    });
                }

                cursor.expect("(")?;
                cursor.expect("name")?;
                cursor.read_bytes(&mut child_name, MAX_METADATA_TOKEN)?;
                validate_name(&child_name)?;
                if !previous_name.is_empty() && child_name <= previous_name {
                    return Err(Error::UnsortedEntries(
                        describe_bytes(&child_name),
                        describe_bytes(&previous_name),
                    ));
                }
                cursor.expect("node")?;
                let child_disk_name = state.disk_name(&child_name, case_hack)?;
                restore_node(
                    cursor,
                    &state.directory,
                    &child_disk_name,
                    case_hack,
                    depth + 1,
                )?;
                cursor.expect(")")?;

                std::mem::swap(&mut previous_name, &mut child_name);
                child_name.clear();
            }
        }
        _ => {
            return Err(Error::UnexpectedToken {
                expected: "regular, symlink or directory",
                got: describe_bytes(node_type.as_bytes()),
            })
        }
    }

    Ok(())
}

struct ReaderCursor<'a, R: ?Sized> {
    reader: &'a mut R,
}

impl<'a, R: Read + ?Sized> ReaderCursor<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self { reader }
    }

    fn expect_magic(&mut self) -> Result<(), Error> {
        let result = (|| {
            let len = self.read_len()?;
            if len != MAGIC.len() as u64 {
                return Err(Error::BadMagic);
            }
            let mut magic = [0; MAGIC.len()];
            self.read_exact(&mut magic)?;
            self.read_padding(len)?;
            if magic == MAGIC {
                Ok(())
            } else {
                Err(Error::BadMagic)
            }
        })();
        match result {
            Err(Error::Io(error)) => Err(Error::Io(error)),
            Err(_) => Err(Error::BadMagic),
            Ok(()) => Ok(()),
        }
    }

    fn expect(&mut self, expected: &'static str) -> Result<(), Error> {
        let len = self.read_len()?;
        if len != expected.len() as u64 {
            return Err(Error::UnexpectedToken {
                expected,
                got: self.read_description(len)?,
            });
        }

        let mut bytes = [0; MAX_CONTROL_TOKEN];
        let actual = &mut bytes[..expected.len()];
        self.read_exact(actual)?;
        self.read_padding(len)?;
        if actual == expected.as_bytes() {
            Ok(())
        } else {
            Err(Error::UnexpectedToken {
                expected,
                got: describe_bytes(actual),
            })
        }
    }

    fn read_control(&mut self, expected: &'static str) -> Result<ControlToken, Error> {
        let len = self.read_len()?;
        if len > MAX_CONTROL_TOKEN as u64 {
            return Err(Error::UnexpectedToken {
                expected,
                got: self.read_description(len)?,
            });
        }

        let mut token = ControlToken {
            bytes: [0; MAX_CONTROL_TOKEN],
            len: len as usize,
        };
        self.read_exact(&mut token.bytes[..token.len])?;
        self.read_padding(len)?;
        Ok(token)
    }

    fn read_bytes(&mut self, bytes: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
        let len = self.read_len()?;
        if len > limit as u64 {
            return Err(Error::TokenTooLarge { size: len, limit });
        }
        let len = len as usize;
        bytes.clear();
        bytes.resize(len, 0);
        self.read_exact(bytes)?;
        self.read_padding(len as u64)
    }

    fn copy_token_to(&mut self, writer: &mut impl Write) -> Result<(), Error> {
        let len = self.read_len()?;
        let copied = {
            let mut contents = (&mut *self.reader).take(len);
            io::copy(&mut contents, writer)?
        };
        if copied != len {
            return Err(Error::UnexpectedEof);
        }
        self.read_padding(len)
    }

    fn read_len(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_padding(&mut self, len: u64) -> Result<(), Error> {
        let padding_len = ((8 - len % 8) % 8) as usize;
        let mut padding = [0; 7];
        self.read_exact(&mut padding[..padding_len])?;
        if padding[..padding_len].iter().any(|&byte| byte != 0) {
            Err(Error::BadPadding)
        } else {
            Ok(())
        }
    }

    fn read_description(&mut self, len: u64) -> Result<String, Error> {
        let preview_len = len.min(ERROR_PREVIEW_BYTES as u64) as usize;
        let mut preview = vec![0; preview_len];
        self.read_exact(&mut preview)?;
        let mut description = describe_bytes(&preview);
        if len > preview_len as u64 {
            description.push('…');
        }
        Ok(description)
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.reader.read_exact(bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                Error::UnexpectedEof
            } else {
                Error::Io(error)
            }
        })
    }

    fn is_exhausted(&mut self) -> Result<bool, Error> {
        let mut byte = [0];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => return Ok(true),
                Ok(_) => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
    }
}

struct ControlToken {
    bytes: [u8; MAX_CONTROL_TOKEN],
    len: usize,
}

impl ControlToken {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
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
