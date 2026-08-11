#![doc = include_str!("../README.md")]

mod dec;
mod enc;
mod refscan;
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
/// - [`encode_tree`](crate::nar::encode_tree) and
///   [`hash_tree`](crate::nar::hash_tree) serialize an already-sorted borrowed
///   tree without allocating when the writer does not allocate.
/// - [`encode_path`](crate::nar::encode_path) and
///   [`hash_path`](crate::nar::hash_path) allocate directory-name metadata for
///   canonical sorting, while file payloads remain streaming.
/// - [`restore_reader`](crate::nar::restore_reader) recreates a tree from a
///   stream with payload-independent memory use; [`restore_path`](crate::nar::restore_path)
///   is the borrowed-slice convenience API. Both apply Nix's macOS
///   case-collision hack by native default.
///
/// Names, symlink targets, and contents are raw bytes; none require UTF-8.
pub mod nar {
    pub use crate::dec::{decode, decode_events, Entry, Event};
    pub use crate::enc::{
        encode_path, encode_path_with_case_hack, encode_regular, encode_tree, hash_path,
        hash_path_with_case_hack, hash_regular, hash_tree, CaseHack, NamedNode, NarHash, Node,
        CASE_HACK_SUFFIX,
    };
    pub use crate::refscan::{
        ReferencePattern, ReferencePatternError, ReferenceScan, ReferenceScanner, ReferenceWriter,
        REFERENCE_LENGTH,
    };
    pub use crate::restore::{
        restore_path, restore_path_with_case_hack, restore_reader, restore_reader_with_case_hack,
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
        #[error("NAR metadata token is {size} bytes, exceeding the restoration limit of {limit}")]
        TokenTooLarge {
            /// Declared token size.
            size: u64,
            /// Maximum size accepted by streaming restoration.
            limit: usize,
        },
        #[error("file changed size while encoding: {0}")]
        FileChanged(std::path::PathBuf),
        #[error("unsupported file type: {0}")]
        UnsupportedFileType(std::path::PathBuf),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }
}
