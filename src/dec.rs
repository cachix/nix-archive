//! NAR decoding, either as allocation-free borrowed events or as a collected
//! post-order entry stream.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::nar::Error;
use crate::wire::{
    describe_bytes, validate_child_name, Cursor, ReaderCursor, MAGIC, MAX_DEPTH, MAX_METADATA_TOKEN,
};

/// A root-first decoding event.
///
/// The root object's `name` is `None`; every child has the raw name from its
/// containing directory. Directories produce a balanced start/end pair.
///
/// `C` is how a regular file's contents are presented, and it is the only
/// thing that differs between the decoders. [`decode_events`] fills it with
/// `&'a [u8]` borrowed straight from the archive; [`decode_events_reader`] fills it
/// with [`FileContents`], a reader valid only for the duration of the visit.
/// Everything else about an event is identical either way, so a routine
/// written generically over `C` serves both decoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a, C = &'a [u8]> {
    DirectoryStart {
        name: Option<&'a [u8]>,
    },
    DirectoryEnd {
        name: Option<&'a [u8]>,
    },
    Regular {
        name: Option<&'a [u8]>,
        executable: bool,
        contents: C,
    },
    Symlink {
        name: Option<&'a [u8]>,
        target: &'a [u8],
    },
}

/// A streamed regular file's contents: [`size`](Self::size) bytes, readable
/// once, in order.
///
/// Yielded by [`decode_events_reader`] as the `contents` of [`Event::Regular`].
/// Reading less than `size` is not an error; the decoder skips the rest and
/// the stream stays positioned for the rest of the archive.
///
/// The bytes arrive before the decoder has checked the token's padding or the
/// node's closing parenthesis, so a truncated or tampered archive can hand
/// over plausible looking contents and only then fail, and an inflated length
/// makes the framing that follows the file look like part of it. A visitor
/// that must not act on unverified bytes should hold them until
/// [`decode_events_reader`] returns, or decode from a slice with [`decode_events`].
///
/// `R` is the archive's own reader type, carried rather than erased so that
/// [`copy_to`](Self::copy_to) can hand [`io::copy`] something it can
/// specialize.
pub struct FileContents<'a, R: ?Sized> {
    size: u64,
    remaining: &'a mut u64,
    reader: &'a mut R,
}

impl<R: ?Sized> FileContents<'_, R> {
    /// Declared length of the contents, known before any of it is read.
    ///
    /// This is what the archive claims. It is confirmed only once the whole
    /// token and its padding have been consumed, which happens after the visit
    /// returns.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<R: Read + ?Sized> FileContents<'_, R> {
    /// Copy whatever is left of the contents into `writer`, and report how much
    /// that was.
    ///
    /// **Prefer this to [`io::copy`] on the [`Read`] impl.** It passes the
    /// archive's own reader type straight through, so a file-backed archive
    /// restoring to a file keeps the kernel-side copy that `io::copy`
    /// specializes to; going through `FileContents` as a plain `Read` erases
    /// that type and costs a userspace round trip per chunk instead.
    ///
    /// A failing `writer` is reported as it arrives, but the count is settled
    /// first: whatever `io::copy` had already drained out of the archive is
    /// subtracted before the error leaves. Dropping that would leave the
    /// decoder skipping bytes it has already handed over, landing the cursor
    /// inside the framing that follows the file.
    pub fn copy_to(&mut self, writer: &mut (impl Write + ?Sized)) -> io::Result<u64> {
        let mut rest = (&mut *self.reader).take(*self.remaining);
        let copied = io::copy(&mut rest, writer);
        // `Take` counted what it let through whether or not the write failed,
        // and what is left of its budget is exactly what this owes the decoder.
        *self.remaining = rest.limit();
        copied
    }
}

impl<R: Read + ?Sized> Read for FileContents<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if *self.remaining == 0 {
            return Ok(0);
        }
        let wanted = (*self.remaining).min(buf.len() as u64) as usize;
        let read = self.reader.read(&mut buf[..wanted])?;
        *self.remaining -= read as u64;
        Ok(read)
    }
}

/// The reader is elided: it has nothing to show, and reading it in order to
/// print it would eat the archive.
impl<R: ?Sized> fmt::Debug for FileContents<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileContents")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// What [`decode_events_reader`] yields: an [`Event`] whose contents are a
/// [`FileContents`] reader rather than a borrowed slice.
pub type ReadEvent<'a, R> = Event<'a, FileContents<'a, R>>;

/// Visit a NAR in its root-first wire order without allocating on valid input.
///
/// **Choose this when the archive is already in memory.** It is the only
/// decoder that hands you contents you are allowed to keep.
///
/// Pros: zero allocation on valid input, the visitor permitting; names,
/// targets, and contents are borrowed straight from `nar` rather than copied,
/// and stay valid as long as `nar` does, so they can outlive the visit; a
/// whole payload is one slice, so hashing or writing it is a single call; no
/// bound on token sizes beyond the slice itself.
///
/// Cons: `nar` must be fully in memory, so peak memory is at least the size of
/// the archive. Use [`decode_events_reader`] when the archive is still arriving, or
/// when it does not fit.
///
/// Events already delivered before a malformed archive is detected are not
/// rolled back.
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
/// **Choose this when you want the tree as data rather than as a visitor.**
///
/// Pros: no callback to write, so the result is easy to index, sort, filter,
/// or assert against; contents and symlink targets still borrow from `nar`
/// rather than being copied.
///
/// Cons: allocates the vector and a `PathBuf` per entry, so it costs memory
/// proportional to the number of entries; post-order reports a directory only
/// after its children, which is the reverse of the order the archive is
/// written in. Use [`decode_events`] when decoding must not allocate, or when
/// root-first order matters.
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
                        validate_child_name(child_name, previous)?;
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

/// Visit a NAR in its root-first wire order without holding the archive in
/// memory.
///
/// **Choose this when the archive is arriving, or is too large to hold.** It
/// is the streaming counterpart of [`decode_events`], in the same relation to
/// it as [`restore_reader`](crate::nar::restore_reader) is to
/// [`restore`](crate::nar::restore).
///
/// Pros: memory use follows directory depth and metadata, never payload size,
/// so an archive of any size passes through; contents can be copied straight
/// into their destination as they arrive; metadata tokens are bounded, so a
/// malformed archive cannot ask for an unbounded allocation.
///
/// Cons: contents are a one-pass reader valid only during the visit, so
/// nothing can be kept without copying it; a payload crosses in small chunks
/// rather than as one slice, which costs a write per chunk downstream; it
/// allocates depth-bounded name buffers and one reused symlink-target buffer
/// where [`decode_events`] allocates nothing; the metadata bounds make it
/// reject a few archives [`decode_events`] accepts; and a file's bytes reach
/// the visitor before the node around them has been validated.
///
/// `reader` is consumed in small pieces, one per length prefix and one per
/// token, so wrap an unbuffered source in a [`BufReader`](std::io::BufReader).
/// The archive must be the whole of what remains on `reader`: anything after
/// it is [`Error::TrailingBytes`], and noticing that consumes the first byte
/// of it, so a NAR embedded in a longer framed stream needs a reader bounded
/// by that framing rather than the underlying stream itself.
///
/// Events already delivered before a malformed archive is detected are not
/// rolled back. See [`FileContents`].
pub fn decode_events_reader<R: Read + ?Sized>(
    reader: &mut R,
    mut visitor: impl FnMut(ReadEvent<'_, R>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut cursor = ReaderCursor::new(reader);
    cursor.expect_magic()?;

    // One buffer for every symlink target in the archive. Targets are leaves,
    // so no two are ever live at once and a single buffer serves the whole
    // decode; the entry names below cannot share it, because a name stays
    // borrowed for as long as its subtree is being parsed.
    let mut target = Vec::new();
    parse_reader_node(&mut cursor, None, 0, &mut target, &mut visitor)?;

    if cursor.is_exhausted()? {
        Ok(())
    } else {
        Err(Error::TrailingBytes)
    }
}

fn parse_reader_node<R: Read + ?Sized>(
    cursor: &mut ReaderCursor<'_, R>,
    name: Option<&[u8]>,
    depth: usize,
    target: &mut Vec<u8>,
    visitor: &mut impl FnMut(ReadEvent<'_, R>) -> Result<(), Error>,
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
            cursor.stream_token(|size, remaining, reader| {
                visitor(ReadEvent::Regular {
                    name,
                    executable,
                    contents: FileContents {
                        size,
                        remaining,
                        reader,
                    },
                })
            })?;
            cursor.expect(")")?;
        }
        b"symlink" => {
            cursor.expect("target")?;
            cursor.read_bytes(target, MAX_METADATA_TOKEN)?;
            cursor.expect(")")?;
            visitor(ReadEvent::Symlink {
                name,
                target: &target[..],
            })?;
        }
        b"directory" => {
            visitor(ReadEvent::DirectoryStart { name })?;
            let mut previous_name: Vec<u8> = Vec::new();
            let mut child_name: Vec<u8> = Vec::new();
            let mut have_previous = false;
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
                validate_child_name(
                    &child_name,
                    have_previous.then_some(previous_name.as_slice()),
                )?;
                have_previous = true;

                cursor.expect("node")?;
                parse_reader_node(cursor, Some(&child_name), depth + 1, target, visitor)?;
                cursor.expect(")")?;

                // `read_bytes` clears the buffer it fills, so trading the two
                // names round keeps both allocations and copies neither.
                std::mem::swap(&mut previous_name, &mut child_name);
            }
            visitor(ReadEvent::DirectoryEnd { name })?;
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
