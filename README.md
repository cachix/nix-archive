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
- Streaming Nix-compatible reference scanning with reusable candidate sets.
- Descriptor-relative filesystem traversal and restoration resist symlink swaps.
- Post-order collecting decoder for content-addressed tree ingestion.
- Nix-compatible macOS case-collision restoration and re-encoding.
- Non-UTF-8 filenames and symlink targets preserved exactly.
- No Nix runtime or daemon dependency.

## Installation

```toml
[dependencies]
nix-archive = "0.1"
```

The package also provides a small command-line tool for packing and unpacking
NAR files:

```console
nix-archive pack tree.nar ./tree
nix-archive unpack tree.nar ./restored-tree
```

The unpack destination must not exist. Use `-` in place of `tree.nar` to write
the packed archive to standard output or read the archive from standard input,
matching the streams used by `nix nar pack` and `nix-store --restore`.

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
returns a `Vec<Entry>` with every directory after its children. File contents
and symlink targets remain borrowed from the input archive.

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

    let nar_hash = hash_path(path)?;
    assert_eq!(nar_hash.size, nar.len() as u64);
    Ok(())
}
```

Filesystem encoding allocates directory-name metadata so entries can be
sorted canonically, but regular-file payloads are copied directly from disk to
the writer. `hash_path` therefore never constructs the complete archive.

## Scan for store-path references

Nix discovers output references by searching the complete NAR byte stream for
the 32-byte Nix-base32 hash parts of candidate store paths. A
`ReferencePattern` validates and prepares those candidates once and can then be
reused for every output of a build:

```rust,no_run
use std::path::Path;
use nix_archive::nar::ReferencePattern;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = [
        "dc04vv14dak1c1r48qa0m23vr9jy8sm0",
        "zc842j0rz61mjsp3h3wp5ly71ak6qgdn",
    ];
    let pattern = ReferencePattern::new(candidates)?;
    let scan = pattern.scan_path(Path::new("./result"))?;

    // Indices refer to `candidates`; hash and size came from the same NAR pass.
    println!("{:?} {}", scan.matches, scan.nar_size);
    Ok(())
}
```

For composition with another hash or destination, `pattern.writer(inner)`
returns a `Write` decorator. It scans only bytes successfully accepted by the
inner writer, retains a fixed 31-byte boundary tail, and allocates nothing
while processing chunks.

## Restore and the macOS case hack

```rust
use std::path::Path;
use nix_archive::nar::{restore_path, Error};

fn restore(nar: &[u8]) -> Result<(), Error> {
    restore_path(nar, Path::new("./restored"))
}
```

For archives that are not already in memory, `restore_reader` accepts any
`std::io::Read` and streams regular-file contents directly to disk:

```rust,no_run
use std::{fs::File, io::BufReader, path::Path};
use nix_archive::nar::{restore_reader, Error};

fn restore_file() -> Result<(), Error> {
    let mut nar = BufReader::new(File::open("tree.nar")?);
    restore_reader(&mut nar, Path::new("./restored"))
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
| `decode` | Allocates the result vector and paths; payloads and symlink targets remain borrowed |
| `encode_tree` | Zero allocations with an allocation-free writer |
| `hash_tree` | Zero allocations |
| `encode_path` / `hash_path` | Allocates directory metadata; streams file payloads |
| `ReferencePattern` | Allocates candidate lookup state once; clones share it |
| `ReferenceScanner` / `ReferenceWriter` | Allocates match state at construction; no allocations while scanning |
| `restore_path` / `restore_reader` | Payload-independent; allocates depth-bounded name buffers and case-collision state |

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
- Nix/Lix reference-scanner chunk cases, every split boundary, overlaps, and duplicates;
- whole-NAR reference matches in file contents, entry names, and symlink targets;
- an Antithesis SDK workload comparing randomized payloads, candidate sets, and chunking against an independent naive oracle;
- empty patterns, invalid alphabets, writer failures, case-hack modes, and 32 MiB bounded-memory scanning;
- macOS case-hack round trips and both collision failure modes;
- exact zero-allocation assertions for borrowed decoding, encoding, hashing, and scanning.

Run tests with:

```console
devenv shell -- cargo test
```

The Antithesis workload is also directly runnable as a normal integration
test; its Antithesis assertions are mirrored by native assertions for local
and CI failures:

```console
devenv shell -- cargo test --test antithesis_reference_scan -- --nocapture
```

## Benchmarks

Criterion benchmarks cover borrowed and collecting decode, borrowed-tree
encoding and hashing, reference scanning with reusable candidate sets,
1,000-entry directories, filesystem streaming, case hack overhead, and
filesystem encoding compared with Nix's daemon protocol.

Results from 2026-08-09 on an AMD Ryzen 7 7840S (Linux x86-64), using
`rustc 1.97.1` and Criterion 0.8.2:

| Input | Operation | Time | Throughput |
| --- | --- | ---: | ---: |
| 4 KiB regular file | `decode_events` | 52.6 ns | — |
| 4 KiB regular file | `decode` | 72.3 ns | — |
| 4 KiB regular file | `encode_tree` to counting sink | 22.5 ns | — |
| 4 KiB regular file | `hash_tree` | 2.78 µs | 1.41 GiB/s |
| 1 MiB regular file | `decode_events` | 52.5 ns | — |
| 1 MiB regular file | `decode` | 75.2 ns | — |
| 1 MiB regular file | `encode_tree` to counting sink | 22.7 ns | — |
| 1 MiB regular file | `hash_tree` | 667 µs | 1.46 GiB/s |
| 1,000-entry borrowed directory | `decode_events` | 94.8 µs | 10.5 M entries/s |
| 1,000-entry borrowed directory | `decode` | 141 µs | 7.08 M entries/s |
| 1,000-entry borrowed directory | `encode_tree` to counting sink | 47.4 µs | 21.1 M entries/s |
| 1,000-entry borrowed directory | `hash_tree` | 263 µs | 3.80 M entries/s |
| 8 MiB filesystem file | `encode_path` to counting sink | 1.27 ms | 6.14 GiB/s |
| 1,000-file filesystem directory | `encode_path` | 6.44 ms | 155 K entries/s |
| 1,000-file filesystem directory | `encode_path` with case hack | 14.1 ms | 71.1 K entries/s |

The same run compared filesystem encoding of the installed Nix 2.34.8
package's 4,060,120-byte NAR through a daemon reporting version 2.34.7. The
benchmark verified byte-for-byte equality before timing:

| Implementation | Time | Throughput | Relative time |
| --- | ---: | ---: | ---: |
| `nix-archive` `encode_path` | 849 µs | 4.45 GiB/s | 1.00× |
| Nix 2.34.7 daemon `NarFromPath` | 1.88 ms | 2.01 GiB/s | 2.22× |

The Nix result uses the stock daemon's `NarFromPath` worker-protocol operation.
It includes Unix-socket request and response overhead but excludes connection
setup; both implementations reuse their output buffer and operate on warm
filesystem caches. This compares the full paths users would call, not just Nix's
internal encoder in isolation.

These are Criterion central estimates from one run, so they should be treated
as indicative rather than universal. Borrowed regular-file decoding does not
scan the payload, and the counting sink does not copy it; their timings measure
format traversal and serialization overhead rather than memory bandwidth.
The Nix comparison runs when a daemon socket and a `nix` executable in `PATH`
are available, and otherwise skips without failing the other benchmarks.

```console
devenv shell -- cargo bench --bench nar
```

## Scope

Only NAR is implemented today. Additional Nix archive formats can be added as
new modules without changing the `nix-archive` package name.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
