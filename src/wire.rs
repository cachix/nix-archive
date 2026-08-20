//! The NAR token layer: length-prefixed byte strings, zero-padded to 8 bytes.
//!
//! Every token is `u64 little-endian length ++ bytes ++ zero padding to a
//! multiple of 8`. The whole format is a stream of these.

use std::io::{self, Read, Write};

use crate::nar::Error;

pub(crate) const MAGIC: &[u8] = b"nix-archive-1";
/// Nix rejects a node at depth 64. This also bounds recursive stack use for
/// hostile archives.
pub(crate) const MAX_DEPTH: usize = 64;

pub(crate) fn pad_len(len: usize) -> usize {
    (8 - len % 8) % 8
}

const ZEROS: [u8; 8] = [0; 8];

/// Keep diagnostics for hostile tokens small even when the token itself is
/// enormous. Invalid UTF-8 can expand to three bytes per input byte, so bound
/// the input rather than the resulting `String`.
pub(crate) const ERROR_PREVIEW_BYTES: usize = 1024;

pub(crate) fn describe_bytes(bytes: &[u8]) -> String {
    let end = bytes.len().min(ERROR_PREVIEW_BYTES);
    let mut description = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if end < bytes.len() {
        description.push('…');
    }
    description
}

/// Write one token.
pub(crate) fn write_token(w: &mut (impl Write + ?Sized), bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(&(bytes.len() as u64).to_le_bytes())?;
    w.write_all(bytes)?;
    w.write_all(&ZEROS[..pad_len(bytes.len())])
}

/// Names and symlink targets ultimately have to fit in a filesystem object.
/// Keep a malformed streamed archive from requesting an effectively unbounded
/// allocation before the operating system can reject it.
pub(crate) const MAX_METADATA_TOKEN: usize = 1024 * 1024;
pub(crate) const MAX_CONTROL_TOKEN: usize = 16;

pub(crate) struct ReaderCursor<'a, R: ?Sized> {
    reader: &'a mut R,
}

impl<'a, R: Read + ?Sized> ReaderCursor<'a, R> {
    pub(crate) fn new(reader: &'a mut R) -> Self {
        Self { reader }
    }

    pub(crate) fn expect_magic(&mut self) -> Result<(), Error> {
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

    pub(crate) fn expect(&mut self, expected: &'static str) -> Result<(), Error> {
        let token = self.read_control(expected)?;
        if token.as_bytes() == expected.as_bytes() {
            Ok(())
        } else {
            Err(Error::UnexpectedToken {
                expected,
                got: describe_bytes(token.as_bytes()),
            })
        }
    }

    /// Read the next token, which must be short enough to still be one of the
    /// grammar's keywords.
    ///
    /// A longer token is not a keyword under any reading, and by then the
    /// length prefix is suspect too: the bytes after it are as likely to be
    /// file payload or framing as they are to be the token. Reading them to
    /// dress up a message would copy archive content the caller never asked to
    /// see into an error that gets logged, so an oversized token is reported by
    /// size alone.
    pub(crate) fn read_control(&mut self, expected: &'static str) -> Result<ControlToken, Error> {
        let len = self.read_len()?;
        if len > MAX_CONTROL_TOKEN as u64 {
            return Err(Error::UnexpectedToken {
                expected,
                got: format!("<{len}-byte token>"),
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

    pub(crate) fn read_bytes(&mut self, bytes: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
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

    /// Hand the next token's bytes to `use_contents` as a stream, then consume
    /// whatever it left behind along with the padding.
    ///
    /// The caller never sees the token's size in memory: this is what lets a
    /// multi-gigabyte file payload cross a decoder that allocates nothing for
    /// it. A caller that stops reading early is not an error; the rest of the
    /// token is skipped so the stream stays positioned for what follows.
    ///
    /// `use_contents` receives the reader itself rather than a `dyn Read` or a
    /// pre-made [`Take`](io::Take), together with a counter of how much of the
    /// token is left. Keeping the concrete reader type reachable is what lets
    /// [`io::copy`] pick its kernel-side fast path; erasing it here would cost
    /// every payload a userspace round trip per 8 KiB. In exchange the caller
    /// owes the counter honesty: it must not read past `remaining`, and must
    /// subtract whatever it reads.
    ///
    /// Streaming inverts the usual order of validation. The length is whatever
    /// the archive claims it is, and the trailing padding is only checked once
    /// `use_contents` has returned, so bytes reach the caller before anything
    /// has confirmed they were a well formed token. An inflated length simply
    /// makes the framing that follows look like payload. A caller that cannot
    /// act on unverified bytes has to buffer them itself, or decode from a
    /// slice instead.
    pub(crate) fn stream_token<T>(
        &mut self,
        use_contents: impl FnOnce(u64, &mut u64, &mut R) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let len = self.read_len()?;
        let mut remaining = len;
        let outcome = use_contents(len, &mut remaining, self.reader)?;
        if remaining != 0 {
            let mut rest = (&mut *self.reader).take(remaining);
            io::copy(&mut rest, &mut io::sink())?;
            if rest.limit() != 0 {
                return Err(Error::UnexpectedEof);
            }
        }
        self.read_padding(len)?;
        Ok(outcome)
    }

    pub(crate) fn read_len(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn read_padding(&mut self, len: u64) -> Result<(), Error> {
        let padding_len = pad_len((len % 8) as usize);
        let mut padding = [0; 7];
        self.read_exact(&mut padding[..padding_len])?;
        if padding[..padding_len].iter().any(|&byte| byte != 0) {
            Err(Error::BadPadding)
        } else {
            Ok(())
        }
    }

    pub(crate) fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.reader.read_exact(bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                Error::UnexpectedEof
            } else {
                Error::Io(error)
            }
        })
    }

    pub(crate) fn is_exhausted(&mut self) -> Result<bool, Error> {
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

pub(crate) struct ControlToken {
    bytes: [u8; MAX_CONTROL_TOKEN],
    len: usize,
}

impl ControlToken {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// A borrowing reader over NAR bytes.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.pos == self.data.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read one token, borrowed from the input.
    pub(crate) fn read_token(&mut self) -> Result<&'a [u8], Error> {
        let len_bytes: [u8; 8] = self.take(8)?.try_into().expect("take(8) is 8 bytes");
        let len = u64::from_le_bytes(len_bytes);
        if len > (self.data.len() - self.pos) as u64 {
            return Err(Error::UnexpectedEof);
        }
        let bytes = self.take(len as usize)?;
        let padding = self.take(pad_len(len as usize))?;
        if padding.iter().any(|&b| b != 0) {
            return Err(Error::BadPadding);
        }
        Ok(bytes)
    }

    /// Read one token and require it to be exactly `expected`.
    pub(crate) fn expect(&mut self, expected: &'static str) -> Result<(), Error> {
        let got = self.read_token()?;
        if got == expected.as_bytes() {
            Ok(())
        } else {
            Err(Error::UnexpectedToken {
                expected,
                got: describe_bytes(got),
            })
        }
    }
}
