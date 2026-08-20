# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Added

- Add `decode_events_reader` for decoding a NAR from a stream with
  payload-independent memory use. File contents arrive as a reader rather
  than a borrowed slice, so an archive can be ingested as it is received
  instead of being held in memory first.
- Add `FileContents`, the streamed contents of a regular file: a one-pass
  reader that also reports the declared `size`. Its `copy_to` sends the rest of
  the payload somewhere in one call, passing the archive's own reader type
  through so `std::io::copy` can still choose a kernel-side copy; reading it as
  a plain `Read` erases that type and costs a userspace round trip per chunk.
  `FileContents` and `ReadEvent` are therefore generic over the reader type,
  and `decode_events_reader` and `restore_reader` name it rather than taking
  `impl Read`.

### Changed

- Take `CaseHack` as an argument instead of shipping a second function for it.
  `encode_path`, `hash_path`, `restore`, `restore_reader`, and
  `ReferencePattern::scan_path` now require it; the `*_with_case_hack` twins
  are deprecated aliases. The setting changes the NAR bytes and therefore the
  hash, and real installations vary it, so inferring it from `cfg!(target_os)`
  behind the caller was hiding a decision that belongs at the call site. Pass
  `CaseHack::native()` to keep the previous behavior.

  This changes the arity of `encode_path`, `hash_path`, `restore_reader`, and
  `scan_path`, which no alias can absorb: existing calls must add the argument.
- Remove `impl Default for CaseHack`. It was unused, and a `Default` that
  varies by target OS reintroduces exactly the hidden platform dependence the
  change above removes.
- The `nix-archive` command gained `--case-hack <native|enabled|disabled>`,
  so it can pack and unpack for an installation whose `use-case-hack` differs
  from the host default.
- Rename the API surface onto one rule: the base name takes a `&[u8]` and
  `_reader` takes a `std::io::Read`, while anything that touches the filesystem
  takes an explicit `CaseHack`. `restore_path` becomes `restore`, since both
  restore APIs take a destination `&Path` and the `_path` suffix never said
  which one you were calling. The old names, including the `_with_case_hack`
  twins, remain as deprecated aliases, so existing code keeps compiling with a
  warning naming the replacement.
- `Event` is now generic over how a regular file's contents are presented,
  `Event<'a, C = &'a [u8]>`. `decode_events` still yields `Event<'a>`, so
  existing code is unaffected, and `decode_events_reader` yields the same enum
  with `FileContents`. A routine written over `Event<'_, C>` now serves both
  decoders, where previously it had to be written once per decoder.
  `ReadEvent` is a type alias for the streaming instantiation.
- `restore` and `restore_reader` are now one visitor over the two
  decoders rather than two implementations. `restore_reader` no longer walks
  the NAR grammar itself, so the case-hack numbering, the directory stack, and
  the descriptor-relative creation cannot drift between the streaming and
  in-memory paths. The two decoders still implement the grammar separately;
  `tests/streaming_decode.rs` pins them to the same verdicts.
- `Error::TokenTooLarge` no longer describes its limit as a restoration limit,
  now that `decode_events_reader` also reports it.

### Fixed

- Error messages for a token whose declared length is implausible no longer
  quote up to a kilobyte read from the stream. Once a length prefix is corrupt
  those bytes are not the token at all, so the message could carry file
  contents into a caller's logs. An oversized token is now reported by size.

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
