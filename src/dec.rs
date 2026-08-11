//! NAR decoding, either as allocation-free borrowed events or as a collected
//! post-order entry stream.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::nar::Error;
use crate::wire::{describe_bytes, Cursor, MAGIC, MAX_DEPTH};

/// A root-first decoding event. All byte slices borrow directly from the NAR.
///
/// The root object's `name` is `None`; every child has the raw name from its
/// containing directory. Directories produce a balanced start/end pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    DirectoryStart {
        name: Option<&'a [u8]>,
    },
    DirectoryEnd {
        name: Option<&'a [u8]>,
    },
    Regular {
        name: Option<&'a [u8]>,
        executable: bool,
        contents: &'a [u8],
    },
    Symlink {
        name: Option<&'a [u8]>,
        target: &'a [u8],
    },
}

/// Visit a NAR in its root-first wire order without allocating on valid input.
///
/// Names, file contents, and symlink targets are borrowed from `nar`. The
/// visitor must also avoid allocation if a completely allocation-free decode
/// is required. Events already delivered before a malformed archive is
/// detected are not rolled back.
pub fn decode_events<'a>(
    nar: &'a [u8],
    mut visitor: impl FnMut(Event<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut cursor = Cursor::new(nar);
    if cursor.read_token().map_err(|_| Error::BadMagic)? != MAGIC {
        return Err(Error::BadMagic);
    }

    parse_node(&mut cursor, None, 0, &mut visitor)?;

    if !cursor.is_exhausted() {
        return Err(Error::TrailingBytes);
    }
    Ok(())
}

/// One filesystem object from an archive. Paths are relative to the archive
/// root; the root itself has an empty path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry<'a> {
    Regular {
        path: PathBuf,
        executable: bool,
        /// Borrowed from the archive bytes; never copied.
        contents: &'a [u8],
    },
    Symlink {
        path: PathBuf,
        /// Raw target bytes borrowed from the archive.
        /// NAR imposes no UTF-8 constraint.
        target: &'a [u8],
    },
    /// A directory. Emitted **after** all of its children.
    Directory { path: PathBuf },
}

impl Entry<'_> {
    /// The entry's path relative to the archive root.
    pub fn path(&self) -> &Path {
        match self {
            Entry::Regular { path, .. }
            | Entry::Symlink { path, .. }
            | Entry::Directory { path } => path,
        }
    }
}

/// Decode a NAR into allocated entries in **post-order**: every directory
/// follows its children, and the root comes last with an empty path.
///
/// This convenience API allocates the returned vector and paths. File contents
/// and symlink targets continue to borrow from `nar`. Use [`decode_events`]
/// when decoding must not allocate.
pub fn decode(nar: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let mut entries = Vec::new();
    let mut directory = PathBuf::new();

    decode_events(nar, |event| {
        match event {
            Event::DirectoryStart { name } => {
                if let Some(name) = name {
                    directory.push(OsStr::from_bytes(name));
                }
            }
            Event::DirectoryEnd { name } => {
                entries.push(Entry::Directory {
                    path: directory.clone(),
                });
                if name.is_some() {
                    directory.pop();
                }
            }
            Event::Regular {
                name,
                executable,
                contents,
            } => entries.push(Entry::Regular {
                path: path_for_name(&directory, name),
                executable,
                contents,
            }),
            Event::Symlink { name, target } => entries.push(Entry::Symlink {
                path: path_for_name(&directory, name),
                target,
            }),
        }
        Ok(())
    })?;

    Ok(entries)
}

fn path_for_name(directory: &std::path::Path, name: Option<&[u8]>) -> PathBuf {
    match name {
        Some(name) => directory.join(OsStr::from_bytes(name)),
        None => directory.to_owned(),
    }
}

fn parse_node<'a>(
    cursor: &mut Cursor<'a>,
    name: Option<&'a [u8]>,
    depth: usize,
    visitor: &mut impl FnMut(Event<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::MaxDepth(MAX_DEPTH));
    }

    cursor.expect("(")?;
    cursor.expect("type")?;

    match cursor.read_token()? {
        b"regular" => {
            let mut executable = false;
            let tok = cursor.read_token()?;
            let tok = if tok == b"executable" {
                executable = true;
                cursor.expect("")?;
                cursor.read_token()?
            } else {
                tok
            };
            if tok != b"contents" {
                return Err(Error::UnexpectedToken {
                    expected: "contents",
                    got: describe_bytes(tok),
                });
            }
            let contents = cursor.read_token()?;
            cursor.expect(")")?;
            visitor(Event::Regular {
                name,
                executable,
                contents,
            })?;
        }
        b"symlink" => {
            cursor.expect("target")?;
            let target = cursor.read_token()?;
            cursor.expect(")")?;
            visitor(Event::Symlink { name, target })?;
        }
        b"directory" => {
            visitor(Event::DirectoryStart { name })?;
            let mut previous: Option<&[u8]> = None;
            loop {
                match cursor.read_token()? {
                    b")" => break,
                    b"entry" => {
                        cursor.expect("(")?;
                        cursor.expect("name")?;
                        let child_name = cursor.read_token()?;
                        validate_name(child_name)?;
                        // Nix writes entries in strictly ascending byte order;
                        // accepting anything else would let two archives with
                        // the same digest decode to different trees.
                        if let Some(prev) = previous {
                            if child_name <= prev {
                                return Err(Error::UnsortedEntries(
                                    describe_bytes(child_name),
                                    describe_bytes(prev),
                                ));
                            }
                        }
                        previous = Some(child_name);
                        cursor.expect("node")?;
                        parse_node(cursor, Some(child_name), depth + 1, visitor)?;
                        cursor.expect(")")?;
                    }
                    other => {
                        return Err(Error::UnexpectedToken {
                            expected: "entry or )",
                            got: describe_bytes(other),
                        })
                    }
                }
            }
            visitor(Event::DirectoryEnd { name })?;
        }
        other => {
            return Err(Error::UnexpectedToken {
                expected: "regular, symlink or directory",
                got: describe_bytes(other),
            })
        }
    }
    Ok(())
}

pub(crate) fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0)
    {
        return Err(Error::InvalidName(describe_bytes(name)));
    }
    Ok(())
}
