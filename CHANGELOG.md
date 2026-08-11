# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

## [0.2.0] - 2026-08-10

### Added

- Add a `nix-archive` command-line tool for packing and unpacking NAR files,
  including standard-input and standard-output support.
- Add `restore_reader` and `restore_reader_with_case_hack` for restoring NARs
  from a stream with payload-independent memory use.
- Add reusable, streaming Nix-compatible store-path reference scanning through
  `ReferencePattern`, `ReferenceScanner`, and `ReferenceWriter`.
- Add `NarHash`, a named result type containing a NAR's byte length and SHA-256
  digest.
- Add Nix daemon comparison benchmarks and include the Apache 2.0 license text.

### Changed

- **Breaking:** Return `NarHash` from the `hash_tree`, `hash_path`,
  `hash_path_with_case_hack`, and `hash_regular` APIs instead of a tuple.
- **Breaking:** Borrow symlink targets in `Entry::Symlink` instead of allocating
  an owned `Vec<u8>`; `Entry::path` now returns `&Path`.
- **Breaking:** Mark the NAR `Error` enum as non-exhaustive and replace the
  internal restoration-state error with a bounded-token error.
- Accept dynamically sized `Write` implementations in encoding APIs.
- Reduce filesystem encoding allocations by reusing diagnostic path storage.

## [0.1.0] - 2026-08-08

### Added

- Initial release with byte-safe NAR encoding, decoding, hashing, filesystem
  traversal and restoration, macOS case-hack support, and conformance tests.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/cachix/nix-archive/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cachix/nix-archive/releases/tag/v0.2.0
[0.1.0]: https://crates.io/crates/nix-archive/0.1.0
