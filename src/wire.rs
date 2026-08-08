//! The NAR token layer: length-prefixed byte strings, zero-padded to 8 bytes.
//!
//! Every token is `u64 little-endian length ++ bytes ++ zero padding to a
//! multiple of 8`. The whole format is a stream of these.

use std::io::Write;

use crate::nar::Error;

pub(crate) fn pad_len(len: usize) -> usize {
    (8 - len % 8) % 8
}

const ZEROS: [u8; 8] = [0; 8];

/// Keep diagnostics for hostile tokens small even when the token itself is
/// enormous. Invalid UTF-8 can expand to three bytes per input byte, so bound
/// the input rather than the resulting `String`.
const ERROR_PREVIEW_BYTES: usize = 1024;

pub(crate) fn describe_bytes(bytes: &[u8]) -> String {
    let end = bytes.len().min(ERROR_PREVIEW_BYTES);
    let mut description = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if end < bytes.len() {
        description.push('…');
    }
    description
}

/// Write one token.
pub(crate) fn write_token(w: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(&(bytes.len() as u64).to_le_bytes())?;
    w.write_all(bytes)?;
    w.write_all(&ZEROS[..pad_len(bytes.len())])
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
