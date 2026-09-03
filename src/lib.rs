#![doc = include_str!("../README.md")]

mod dec;
mod encoder;
mod refscan;
#[cfg(unix)]
mod restore;
mod wire;

/// The Nix Archive (NAR) format.
///
/// NAR serialization is part of Nix store-path identity, so this module is
/// byte-oriented and tested against `nix-store --dump`.
///
/// # Allocation behavior
///
/// - [`decode_events`](crate::nar::decode_events) visits borrowed root-first
///   events without allocating on valid input; [`decode`](crate::nar::decode)
///   is an allocating post-order convenience API.
/// - [`decode_events_reader`](crate::nar::decode_events_reader) visits the same
///   [`Event`](crate::nar::Event)s from a stream, with a file's contents as a
///   [`FileContents`](crate::nar::FileContents) reader, so memory use follows
///   directory depth and metadata rather than payload size. `Event` is generic
///   over its contents type, so one visitor can serve both decoders.
/// - [`encode_tree`](crate::nar::encode_tree) and
///   [`hash_tree`](crate::nar::hash_tree) serialize an already-sorted borrowed
///   tree without allocating when the writer does not allocate.
/// - [`Encoder`](crate::nar::Encoder) serializes validated root-first events
///   and streams externally backed regular-file contents through
///   [`RegularWriter`](crate::nar::RegularWriter).
/// - [`encode_path`](crate::nar::encode_path) and
///   [`hash_path`](crate::nar::hash_path) allocate directory-name metadata for
///   canonical sorting, while file payloads remain streaming.
/// - [`restore_reader`](crate::nar::restore_reader) recreates a tree from a
///   stream with payload-independent memory use; [`restore`](crate::nar::restore)
///   is the borrowed-slice convenience API. Both require an explicit
///   [`CaseHack`](crate::nar::CaseHack) for Nix's macOS case-collision hack;
///   [`CaseHack::native`](crate::nar::CaseHack::native) reproduces Nix's own
///   default.
///
/// The wire-level APIs preserve names, symlink targets, and contents as raw
/// bytes. Filesystem paths require UTF-8 when collected or encoded on Windows.
pub mod nar {
    pub use crate::dec::{
        decode, decode_events, decode_events_reader, Entry, Event, FileContents, ReadEvent,
    };
    pub use crate::encoder::{
        encode_path, encode_regular, encode_tree, hash_path, hash_regular, hash_tree, CaseHack,
        Encoder, NamedNode, NarHash, Node, RegularWriter, CASE_HACK_SUFFIX,
    };
    #[allow(deprecated)]
    pub use crate::encoder::{encode_path_with_case_hack, hash_path_with_case_hack};
    pub use crate::refscan::{
        ReferencePattern, ReferencePatternError, ReferenceScan, ReferenceScanner, ReferenceWriter,
        REFERENCE_LENGTH,
    };
    #[cfg(unix)]
    pub use crate::restore::{restore, restore_reader};
    #[cfg(unix)]
    #[allow(deprecated)]
    pub use crate::restore::{
        restore_path, restore_path_with_case_hack, restore_reader_with_case_hack,
    };

    use thiserror::Error;

    /// A malformed NAR or filesystem encoding/restoration failure.
    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum Error {
        #[error("unexpected end of archive")]
        UnexpectedEof,
        #[error("not a NAR: bad magic")]
        BadMagic,
        #[error("padding bytes were not zero")]
        BadPadding,
        #[error("expected {expected:?}, got {got:?}")]
        UnexpectedToken { expected: &'static str, got: String },
        #[error("invalid entry name {0:?}")]
        InvalidName(String),
        #[error("directory entries not sorted: {0:?} after {1:?}")]
        UnsortedEntries(String, String),
        #[error("trailing bytes after archive end")]
        TrailingBytes,
        #[error("NAR directory nesting exceeds maximum depth of {0}")]
        MaxDepth(usize),
        #[error("file name collision between {0} and {1} after removing the Nix case-hack suffix")]
        CaseHackEncodeCollision(std::path::PathBuf, std::path::PathBuf),
        #[error(
            "archive name {archive_name:?} maps to {generated_name:?}, which collides with explicit name {existing_name:?}"
        )]
        CaseHackRestoreCollision {
            archive_name: String,
            generated_name: String,
            existing_name: String,
        },
        #[error("too many case-colliding names in one directory")]
        CaseHackCounterOverflow,
        #[error("NAR metadata token is {size} bytes, exceeding the streaming limit of {limit}")]
        TokenTooLarge {
            /// Declared token size.
            size: u64,
            /// Maximum size accepted by the streaming decode and restore APIs.
            limit: usize,
        },
        #[error("file changed size while encoding: {0}")]
        FileChanged(std::path::PathBuf),
        #[error("invalid incremental encoder event: {0}")]
        InvalidEncoderEvent(&'static str),
        #[error("incremental encoder has an unfinished archive")]
        UnfinishedArchive,
        #[error("regular file declared {expected} bytes but received {actual}")]
        RegularSizeMismatch { expected: u64, actual: u64 },
        #[error("incremental encoder is poisoned after a writer failure")]
        EncoderPoisoned,
        #[error("unsupported file type: {0}")]
        UnsupportedFileType(std::path::PathBuf),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }
}
