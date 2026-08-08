# nix-archive

Byte-safe encoding, decoding, hashing, and restoration for Nix archive
formats, without linking to Nix.

The crate currently implements the Nix Archive format under
`nix_archive::nar`. NAR names, symlink targets, and file contents are raw
bytes: they are never required to be UTF-8.

`nix-archive` is Unix-only because lossless filesystem paths and executable
mode handling use Unix APIs.

## Highlights

- Byte-exact NAR encoding compatible with `nix-store --dump`.
- Allocation-free borrowed event decoding on valid input.
- Allocation-free borrowed-tree encoding and SHA-256 hashing.
- Streaming filesystem encoding: file payloads are never materialized.
- Descriptor-relative filesystem traversal and restoration resist symlink swaps.
- Post-order collecting decoder for content-addressed tree ingestion.
- Nix-compatible macOS case-collision restoration and re-encoding.
- Non-UTF-8 filenames and symlink targets preserved exactly.
- No Nix runtime, daemon, or casita dependency.

## Installation

```toml
[dependencies]
nix-archive = "0.1"
```

## Decode without allocating

`decode_events` borrows names, targets, and contents directly from the input.
On a valid NAR it performs no heap allocation unless the visitor does.

```rust
use nix_archive::nar::{decode_events, Error, Event};

fn payload_bytes(nar: &[u8]) -> Result<usize, Error> {
    let mut total = 0;
    decode_events(nar, |event| {
        if let Event::Regular { contents, .. } = event {
            total += contents.len();
        }
        Ok(())
    })?;
    Ok(total)
}
```

For callers that want owned relative paths and post-order traversal, `decode`
returns a `Vec<Entry>` with every directory after its children.

## Encode a borrowed tree without allocating

Directory children must already be sorted in strictly ascending byte order.
The encoder validates names and ordering while writing.

```rust
use nix_archive::nar::{encode_tree, Error, NamedNode, Node};

fn main() -> Result<(), Error> {
    let children = [
        NamedNode {
            name: b"hello",
            node: Node::Regular {
                executable: false,
                contents: b"hello world\n",
            },
        },
        NamedNode {
            name: b"hello-link",
            node: Node::Symlink { target: b"hello" },
        },
    ];

    let tree = Node::Directory(&children);
    let mut nar = Vec::new();
    encode_tree(&mut nar, &tree)?;
    Ok(())
}
```

`encode_tree` itself does not allocate when the writer does not allocate.
`hash_tree` computes the NAR size and SHA-256 digest directly.

## Encode or hash a filesystem tree

```rust,no_run
use std::path::Path;
use nix_archive::nar::{encode_path, hash_path, Error};

fn main() -> Result<(), Error> {
    let path = Path::new("./result");
    let mut nar = Vec::new();
    encode_path(&mut nar, path)?;

    let (nar_size, _nar_sha256) = hash_path(path)?;
    assert_eq!(nar_size, nar.len() as u64);
    Ok(())
}
```

Filesystem encoding allocates directory-name metadata so entries can be
sorted canonically, but regular-file payloads are copied directly from disk to
the writer. `hash_path` therefore never constructs the complete archive.

## Restore and the macOS case hack

```rust
use std::path::Path;
use nix_archive::nar::{restore_path, Error};

fn restore(nar: &[u8]) -> Result<(), Error> {
    restore_path(nar, Path::new("./restored"))
}
```

The destination must not exist, and its final lexical component must not be
empty, `.` or `..`. Restoration is not transactional; an error can leave a
partial tree. Child creation is descriptor-relative, so replacing a restored
directory path with a symlink cannot redirect later writes.

On macOS, Nix represents case-colliding names on disk with suffixes such as
`~nix~case~hack~1`. `restore_path` and `encode_path` use the same native
default as Nix: enabled on macOS and disabled elsewhere. The
`*_with_case_hack` functions accept an explicit `CaseHack` setting for tools,
tests, and cross-platform processing.

## Allocation behavior

| API | Heap behavior |
| --- | --- |
| `decode_events` | Zero allocations on valid input with an allocation-free visitor |
| `decode` | Allocates the result vector, paths, and symlink targets |
| `encode_tree` | Zero allocations with an allocation-free writer |
| `hash_tree` | Zero allocations |
| `encode_path` / `hash_path` | Allocates directory metadata; streams file payloads |
| `restore_path` | Allocates path and case-collision state |

These guarantees have allocator-counting integration tests rather than being
inferred from bounded memory use.

## Correctness and testing

The repository includes a standalone `devenv.nix` and lock file providing the
Rust toolchain and `nix-store` differential oracle.

The test suite includes:

- offline byte-for-byte NAR goldens;
- differential checks against `nix-store --dump` when Nix is available;
- strict token/tag ordering and 8-byte alignment-boundary matrices;
- a fixed complex-tree golden covering decode, restore, re-encode, size, and hash;
- arbitrary-input no-panic and generated-filesystem round-trip properties;
- exhaustive truncation checks, hostile lengths, bounded diagnostics, and
  nonzero padding at every alignment;
- non-UTF-8 names and symlink targets;
- executable-bit, sorting, duplicate-name, nesting-depth, and many-file cases;
- restore rejection for invalid or pre-existing destinations of every node type;
- descriptor-anchoring regressions for concurrent path and symlink swaps;
- macOS case-hack round trips and both collision failure modes;
- exact zero-allocation assertions for borrowed decoding, encoding, and hashing.

Run tests with:

```console
devenv shell -- cargo test
```

## Benchmarks

Criterion benchmarks cover borrowed and collecting decode, borrowed-tree
encoding and hashing, 1,000-entry directories, filesystem streaming, and case
hack overhead.

```console
devenv shell -- cargo bench --bench nar
```

## Scope

Only NAR is implemented today. Additional Nix archive formats can be added as
new modules without changing the `nix-archive` package name.

## License

Apache-2.0
