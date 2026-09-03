# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Added

- Support filesystem encoding and collected NAR decoding on Windows. Windows
  filesystem names and symlink targets must be UTF-8, and regular files are
  encoded as non-executable to match Nix's Windows behavior.

### Changed

- Make Unix-only filesystem restoration APIs conditional, so portable wire,
  encoding, hashing, and reference-scanning consumers compile on Windows.

## [0.4.0] - 2026-08-23

### Added

- Add `Encoder` and `RegularWriter` for validated root-first encoding of
  asynchronous or externally backed trees with streamed regular-file payloads.

## [0.3.0] - 2026-08-20

### Added

- Add `decode_events_reader` for decoding a NAR from a stream with
  payload-independent memory use.
- Add `FileContents` and `ReadEvent` for consuming streamed regular-file
  payloads as a one-pass reader. `FileContents::copy_to` preserves the archive
  reader's concrete type so `std::io::copy` can use specialized copy paths.
- Add `--case-hack <native|enabled|disabled>` to the `nix-archive` command for
  installations whose `use-case-hack` setting differs from the host default.

### Changed

- **Breaking:** Require an explicit `CaseHack` in `encode_path`, `hash_path`,
  `restore_reader`, and `ReferencePattern::scan_path`; pass
  `CaseHack::native()` to retain the previous platform-dependent behavior.
- **Breaking:** Remove `Default` from `CaseHack` so hash-affecting behavior
  cannot be selected implicitly.
- Rename `restore_path` to `restore` and retain the old restoration and
  `*_with_case_hack` names as deprecated aliases.
- Generalize `Event` over its regular-file contents type so visitors can work
  with both borrowed and streaming decoders; `ReadEvent` names the streaming
  form.
- Share one restoration visitor between borrowed and streaming decoding so
  validation and case-collision behavior remain consistent.

### Fixed

- Avoid including archive contents in streaming-decoder error messages when a
  malformed token declares an implausible length.

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
[Unreleased]: https://github.com/cachix/nix-archive/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/cachix/nix-archive/releases/tag/v0.4.0
[0.3.0]: https://github.com/cachix/nix-archive/releases/tag/v0.3.0
[0.2.0]: https://github.com/cachix/nix-archive/releases/tag/v0.2.0
[0.1.0]: https://crates.io/crates/nix-archive/0.1.0
