//! Streaming detection of Nix store-path references.
//!
//! Nix records references by looking for the 32-byte Nix-base32 hash parts of
//! candidate store paths in the complete NAR byte stream.  The scanner here is
//! deliberately byte-oriented: callers retain ownership of store-path types
//! and map the returned candidate indices back to them.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::enc::{encode_path_with_case_hack, encode_tree, CaseHack, HashSink, Node};
use crate::nar::Error as NarError;

/// Length of the Nix-base32 hash part at the start of a store-path name.
pub const REFERENCE_LENGTH: usize = 32;

const OVERLAP_LENGTH: usize = REFERENCE_LENGTH - 1;

/// An invalid candidate passed to [`ReferencePattern::new`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReferencePatternError {
    #[error("reference candidate {index} has length {length}; expected {REFERENCE_LENGTH} bytes")]
    InvalidLength { index: usize, length: usize },
    #[error(
        "reference candidate {index} contains non-Nix-base32 byte {byte:?} at offset {offset}"
    )]
    InvalidByte {
        index: usize,
        offset: usize,
        byte: u8,
    },
}

#[derive(Debug)]
struct ReferencePatternInner {
    /// Head of a linked list of input indices for each unique candidate.
    heads: HashMap<[u8; REFERENCE_LENGTH], usize>,
    /// Previous input index with the same candidate, if any.
    duplicate_next: Vec<Option<usize>>,
}

/// A reusable set of candidate Nix store-path hash parts.
///
/// Construct this once for all outputs of a build, then create a fresh
/// [`ReferenceScanner`] or [`ReferenceWriter`] for each output. Candidates are
/// returned by their input indices, so callers can map matches back to their
/// own store-path type without this crate depending on one.
#[derive(Clone, Debug)]
pub struct ReferencePattern {
    inner: Arc<ReferencePatternInner>,
}

impl ReferencePattern {
    /// Validate and prepare candidate hash parts for repeated scanning.
    ///
    /// Every candidate must contain exactly 32 bytes from Nix's base32
    /// alphabet. Duplicate candidates are accepted; every corresponding input
    /// index is reported when their bytes are found.
    pub fn new<I, P>(candidates: I) -> Result<Self, ReferencePatternError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let candidates = candidates.into_iter();
        let (lower_bound, _) = candidates.size_hint();
        let mut heads = HashMap::with_capacity(lower_bound);
        let mut duplicate_next = Vec::with_capacity(lower_bound);

        for (index, candidate) in candidates.enumerate() {
            let candidate = candidate.as_ref();
            if candidate.len() != REFERENCE_LENGTH {
                return Err(ReferencePatternError::InvalidLength {
                    index,
                    length: candidate.len(),
                });
            }
            if let Some((offset, &byte)) = candidate
                .iter()
                .enumerate()
                .find(|(_, byte)| !is_nix_base32(**byte))
            {
                return Err(ReferencePatternError::InvalidByte {
                    index,
                    offset,
                    byte,
                });
            }

            let mut reference = [0; REFERENCE_LENGTH];
            reference.copy_from_slice(candidate);
            duplicate_next.push(heads.insert(reference, index));
        }

        Ok(Self {
            inner: Arc::new(ReferencePatternInner {
                heads,
                duplicate_next,
            }),
        })
    }

    /// Number of candidates, including duplicates.
    pub fn len(&self) -> usize {
        self.inner.duplicate_next.len()
    }

    /// Whether this pattern has no candidates.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Create independent match state that scans byte chunks directly.
    pub fn scanner(&self) -> ReferenceScanner {
        ReferenceScanner {
            pattern: self.clone(),
            found: vec![false; self.len()],
            remaining: self.len(),
            tail: [0; OVERLAP_LENGTH],
            tail_len: 0,
        }
    }

    /// Wrap a writer and scan exactly the bytes it successfully accepts.
    pub fn writer<W: Write>(&self, inner: W) -> ReferenceWriter<W> {
        ReferenceWriter {
            inner,
            scanner: self.scanner(),
        }
    }

    /// NAR hash, size, and candidate matches for a borrowed tree.
    pub fn scan_tree(&self, tree: &Node<'_>) -> Result<ReferenceScan, NarError> {
        let mut writer = self.writer(HashSink::new());
        encode_tree(&mut writer, tree)?;
        Ok(finish_nar_scan(writer))
    }

    /// NAR hash, size, and candidate matches for a filesystem tree.
    pub fn scan_path(&self, path: &Path) -> Result<ReferenceScan, NarError> {
        self.scan_path_with_case_hack(path, CaseHack::native())
    }

    /// [`ReferencePattern::scan_path`] with an explicit Nix case-hack setting.
    pub fn scan_path_with_case_hack(
        &self,
        path: &Path,
        case_hack: CaseHack,
    ) -> Result<ReferenceScan, NarError> {
        let mut writer = self.writer(HashSink::new());
        encode_path_with_case_hack(&mut writer, path, case_hack)?;
        Ok(finish_nar_scan(writer))
    }
}

/// Match state for one byte stream.
///
/// Calls to [`scan`](Self::scan) may split references at arbitrary byte
/// boundaries. Scanning performs no allocation after construction.
#[derive(Debug)]
pub struct ReferenceScanner {
    pattern: ReferencePattern,
    found: Vec<bool>,
    remaining: usize,
    tail: [u8; OVERLAP_LENGTH],
    tail_len: usize,
}

impl ReferenceScanner {
    /// Scan one successive chunk of the stream.
    pub fn scan(&mut self, bytes: &[u8]) {
        if bytes.is_empty() || self.is_complete() {
            return;
        }

        // A reference can start in the retained tail and finish in this
        // chunk. The boundary buffer contains no window wholly within the new
        // chunk, avoiding duplicate work.
        let prefix_len = bytes.len().min(OVERLAP_LENGTH);
        if self.tail_len + prefix_len >= REFERENCE_LENGTH {
            let mut boundary = [0; OVERLAP_LENGTH * 2];
            boundary[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
            boundary[self.tail_len..self.tail_len + prefix_len]
                .copy_from_slice(&bytes[..prefix_len]);
            self.search(&boundary[..self.tail_len + prefix_len]);
        }

        self.search(bytes);
        if !self.is_complete() {
            self.update_tail(bytes);
        }
    }

    /// Whether every candidate has been found.
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    /// Number of candidate indices found so far.
    pub fn matched_count(&self) -> usize {
        self.found.len() - self.remaining
    }

    /// Found candidate indices in ascending input order.
    pub fn matches(&self) -> impl Iterator<Item = usize> + '_ {
        self.found
            .iter()
            .enumerate()
            .filter_map(|(index, found)| found.then_some(index))
    }

    /// Consume the scanner and collect found indices in ascending input order.
    pub fn into_matches(self) -> Vec<usize> {
        let mut matches = Vec::with_capacity(self.matched_count());
        matches.extend(
            self.found
                .into_iter()
                .enumerate()
                .filter_map(|(index, found)| found.then_some(index)),
        );
        matches
    }

    fn search(&mut self, bytes: &[u8]) {
        let mut offset = 0;
        while !self.is_complete() && offset + REFERENCE_LENGTH <= bytes.len() {
            let window = &bytes[offset..offset + REFERENCE_LENGTH];

            // Match Nix and Lix's backwards alphabet check. Besides enforcing
            // store-reference semantics, it skips quickly over arbitrary
            // binary data without a candidate lookup at every byte.
            let mut valid = true;
            for index in (0..REFERENCE_LENGTH).rev() {
                if !is_nix_base32(window[index]) {
                    offset += index + 1;
                    valid = false;
                    break;
                }
            }
            if !valid {
                continue;
            }

            let reference: &[u8; REFERENCE_LENGTH] = window
                .try_into()
                .expect("the reference window has a fixed length");
            let mut candidate = self.pattern.inner.heads.get(reference).copied();
            while let Some(index) = candidate {
                if !self.found[index] {
                    self.found[index] = true;
                    self.remaining -= 1;
                }
                candidate = self.pattern.inner.duplicate_next[index];
            }
            offset += 1;
        }
    }

    fn update_tail(&mut self, bytes: &[u8]) {
        if bytes.len() >= OVERLAP_LENGTH {
            self.tail
                .copy_from_slice(&bytes[bytes.len() - OVERLAP_LENGTH..]);
            self.tail_len = OVERLAP_LENGTH;
            return;
        }

        let retained = self.tail_len.min(OVERLAP_LENGTH - bytes.len());
        self.tail
            .copy_within(self.tail_len - retained..self.tail_len, 0);
        self.tail[retained..retained + bytes.len()].copy_from_slice(bytes);
        self.tail_len = retained + bytes.len();
    }
}

/// A [`Write`] decorator that scans the bytes accepted by its inner writer.
#[derive(Debug)]
pub struct ReferenceWriter<W> {
    inner: W,
    scanner: ReferenceScanner,
}

impl<W> ReferenceWriter<W> {
    /// Borrow the wrapped writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Mutably borrow the wrapped writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Borrow the scanner and its matches so far.
    pub fn scanner(&self) -> &ReferenceScanner {
        &self.scanner
    }

    /// Recover the wrapped writer and scanner without allocating.
    pub fn into_parts(self) -> (W, ReferenceScanner) {
        (self.inner, self.scanner)
    }
}

impl<W: Write> Write for ReferenceWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.scanner.scan(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reference matches together with the standard NAR metadata from the same
/// serialization pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceScan {
    pub nar_size: u64,
    pub nar_sha256: [u8; 32],
    /// Indices into the candidates passed to [`ReferencePattern::new`].
    pub matches: Vec<usize>,
}

fn finish_nar_scan(writer: ReferenceWriter<HashSink>) -> ReferenceScan {
    let (hash_sink, scanner) = writer.into_parts();
    let nar_hash = hash_sink.finish();
    ReferenceScan {
        nar_size: nar_hash.size,
        nar_sha256: nar_hash.sha256,
        matches: scanner.into_matches(),
    }
}

const fn is_nix_base32(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9' | b'a'..=b'd' | b'f'..=b'n' | b'p'..=b's' | b'v'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::*;

    const HASH_1: &str = "dc04vv14dak1c1r48qa0m23vr9jy8sm0";
    const HASH_2: &str = "zc842j0rz61mjsp3h3wp5ly71ak6qgdn";

    #[test]
    fn empty_pattern_is_immediately_complete() {
        let pattern = ReferencePattern::new(Vec::<[u8; REFERENCE_LENGTH]>::new()).unwrap();
        assert!(pattern.is_empty());

        let mut scanner = pattern.scanner();
        assert!(scanner.is_complete());
        scanner.scan(HASH_1.as_bytes());
        assert_eq!(scanner.matched_count(), 0);
        assert_eq!(scanner.into_matches(), []);
    }

    #[test]
    fn accepts_the_complete_nix_base32_alphabet() {
        let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
        let pattern = ReferencePattern::new([alphabet]).unwrap();
        let mut scanner = pattern.scanner();
        scanner.scan(alphabet);
        assert_eq!(scanner.into_matches(), [0]);
    }

    #[test]
    fn matches_nix_and_lix_chunk_cases() {
        let candidates = vec![HASH_1.to_owned(), HASH_2.to_owned()];
        let pattern = ReferencePattern::new(&candidates).unwrap();

        let mut scanner = pattern.scanner();
        scanner.scan(b"foobar");
        assert_eq!(scanner.matches().collect::<Vec<_>>(), []);

        let bytes = format!("foobar{HASH_1}xyzzy{HASH_2}");
        let mut scanner = pattern.scanner();
        let mut offset = 0;
        for length in [10, 5, 5] {
            scanner.scan(&bytes.as_bytes()[offset..offset + length]);
            offset += length;
        }
        scanner.scan(&bytes.as_bytes()[offset..]);
        assert_eq!(scanner.matches().collect::<Vec<_>>(), [0, 1]);

        let mut scanner = pattern.scanner();
        for byte in bytes.as_bytes() {
            scanner.scan(std::slice::from_ref(byte));
        }
        assert_eq!(scanner.into_matches(), [0, 1]);
    }

    #[test]
    fn finds_references_at_every_chunk_boundary() {
        let pattern = ReferencePattern::new([HASH_1, HASH_2]).unwrap();
        let bytes = format!("prefix-{HASH_1}-middle-{HASH_2}-suffix");

        for split in 0..=bytes.len() {
            let mut scanner = pattern.scanner();
            scanner.scan(&bytes.as_bytes()[..split]);
            scanner.scan(&bytes.as_bytes()[split..]);
            assert_eq!(scanner.into_matches(), [0, 1], "split at {split}");
        }
    }

    #[test]
    fn empty_chunks_do_not_disturb_a_partial_reference() {
        let pattern = ReferencePattern::new([HASH_1]).unwrap();
        let mut scanner = pattern.scanner();

        scanner.scan(&HASH_1.as_bytes()[..16]);
        scanner.scan(&[]);
        scanner.scan(&[]);
        scanner.scan(&HASH_1.as_bytes()[16..]);

        assert_eq!(scanner.into_matches(), [0]);
    }

    #[test]
    fn reports_overlapping_and_duplicate_candidates() {
        let first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
        let pattern = ReferencePattern::new([first, second, first]).unwrap();
        let mut scanner = pattern.scanner();
        scanner.scan(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab");

        assert!(scanner.is_complete());
        assert_eq!(scanner.into_matches(), [0, 1, 2]);
    }

    #[test]
    fn rejects_non_store_hash_candidates() {
        assert_eq!(
            ReferencePattern::new(["short"]).unwrap_err(),
            ReferencePatternError::InvalidLength {
                index: 0,
                length: 5,
            }
        );
        assert_eq!(
            ReferencePattern::new(["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]).unwrap_err(),
            ReferencePatternError::InvalidByte {
                index: 0,
                offset: 0,
                byte: b'e',
            }
        );

        for invalid in [b'e', b'o', b't', b'u', b'A', 0xff] {
            let mut candidate = [b'0'; REFERENCE_LENGTH];
            candidate[17] = invalid;
            assert_eq!(
                ReferencePattern::new([candidate]).unwrap_err(),
                ReferencePatternError::InvalidByte {
                    index: 0,
                    offset: 17,
                    byte: invalid,
                }
            );
        }

        for length in [0, REFERENCE_LENGTH - 1, REFERENCE_LENGTH + 1] {
            let candidate = vec![b'0'; length];
            assert_eq!(
                ReferencePattern::new([candidate]).unwrap_err(),
                ReferencePatternError::InvalidLength { index: 0, length }
            );
        }

        let candidates: [&[u8]; 2] = [HASH_1.as_bytes(), b"bad"];
        assert_eq!(
            ReferencePattern::new(candidates).unwrap_err(),
            ReferencePatternError::InvalidLength {
                index: 1,
                length: 3,
            }
        );
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let written = bytes.len().min(self.limit);
            self.bytes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_scans_only_successfully_written_bytes() {
        let pattern = ReferencePattern::new([HASH_1]).unwrap();
        let bytes = format!("before-{HASH_1}-after");
        let mut writer = pattern.writer(ShortWriter {
            bytes: Vec::new(),
            limit: 3,
        });
        writer.write_all(bytes.as_bytes()).unwrap();
        let (inner, scanner) = writer.into_parts();

        assert_eq!(inner.bytes, bytes.as_bytes());
        assert_eq!(scanner.into_matches(), [0]);
    }

    struct FailAfter {
        bytes: Vec<u8>,
        remaining: usize,
    }

    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected writer failure"));
            }
            let written = bytes.len().min(self.remaining);
            self.bytes.extend_from_slice(&bytes[..written]);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_error_preserves_matches_from_the_accepted_prefix() {
        let pattern = ReferencePattern::new([HASH_1]).unwrap();
        let bytes = format!("x{HASH_1}-unwritten-suffix");
        let accepted = 1 + REFERENCE_LENGTH;
        let mut writer = pattern.writer(FailAfter {
            bytes: Vec::new(),
            remaining: accepted,
        });

        let error = writer.write_all(bytes.as_bytes()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        let (inner, scanner) = writer.into_parts();
        assert_eq!(inner.bytes, bytes.as_bytes()[..accepted]);
        assert_eq!(scanner.into_matches(), [0]);
    }

    struct ZeroWriter;

    impl Write for ZeroWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn zero_writes_and_flush_errors_are_forwarded_without_false_matches() {
        let pattern = ReferencePattern::new([HASH_1]).unwrap();
        let mut writer = pattern.writer(ZeroWriter);

        assert_eq!(
            writer.write_all(HASH_1.as_bytes()).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::Other);
        let (_, scanner) = writer.into_parts();
        assert_eq!(scanner.into_matches(), []);
    }
}
