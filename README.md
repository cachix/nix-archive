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
- Payload-independent streaming event decoding from any `std::io::Read`.
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
nix-archive = "0.4"
```

The optional `cli` feature provides a small command-line tool for packing and
unpacking NAR files. Install it with:

```console
cargo install nix-archive --features cli
```

Then run:

```console
nix-archive pack tree.nar ./tree
nix-archive unpack tree.nar ./restored-tree
```

The unpack destination must not exist. Use `-` in place of `tree.nar` to write
the packed archive to standard output or read the archive from standard input,
matching the streams used by `nix nar pack` and `nix-store --restore`.

## Choosing an API

Five decoding and restoration APIs span two axes: whether the archive is
already in memory, and whether you want a visitor or a data structure.

Names follow one rule: the base name is the in-memory form and `_reader` means
it takes a `std::io::Read` instead of a `&[u8]`. Anything that touches the
filesystem also takes a `CaseHack`, because that choice changes the resulting
NAR bytes and must not be guessed silently; pass `CaseHack::native()` for
Nix's own default.

| | Contents you get | Allocates | Use when |
| --- | --- | --- | --- |
| `decode_events` | `&[u8]` borrowed from the archive, valid as long as it is | nothing | the archive is in memory and you want it fast |
| `decode` | `&[u8]` borrowed, in a returned `Vec<Entry>` | vector plus a path per entry | you want the tree as data, not a callback |
| `decode_events_reader` | `FileContents`, a one-pass reader valid only during the visit | depth-bounded name buffers | the archive is arriving, or does not fit |
| `restore` | written to disk for you | case-collision state | you have the archive and want it on disk |
| `restore_reader` | written to disk for you | case-collision state | it is arriving and you want it on disk |

The split between the slice decoders and the streaming one is not a
convenience; neither can be built from the other:

- **Slice cannot be built from stream.** `decode_events` promises contents
  borrowed from the input, so they outlive the visit and cost no copy. A
  stream has nothing with that lifetime to give: its bytes live in an 8 KiB
  buffer that the next read overwrites. That promise is what lets `decode`
  return a `Vec<Entry>` still pointing into your archive.
- **Stream cannot be built from slice.** Feeding `decode_events` from a socket
  means buffering the whole archive first, which is the exact cost the
  streaming API exists to avoid.

Concretely, on a 4 MiB file: `decode_events` performs zero allocations and
hands you the payload as one slice, so writing it is a single `write` syscall.
`decode_events_reader` allocates two depth-bounded buffers and delivers the
payload as a stream. Read it as a plain `Read` and it arrives in 512 chunks of
8 KiB; hand it somewhere with `FileContents::copy_to` and the whole payload can
cross in one `copy_file_range`, because `copy_to` keeps your reader's own type
rather than erasing it. Pick the trade you want; the type signature tells you
which one you took.

What they *do* share is vocabulary. Both yield `Event`, which is generic over
its contents type, so a routine written over `Event<'_, C>` works with either
decoder:

```rust
use nix_archive::nar::Event;

fn describe<C>(event: &Event<'_, C>) -> String {
    match event {
        Event::DirectoryStart { name } => format!("dir+ {name:?}"),
        Event::DirectoryEnd { name } => format!("dir- {name:?}"),
        Event::Regular { name, executable, .. } => format!("file {name:?} {executable}"),
        Event::Symlink { name, target } => format!("link {name:?} -> {target:?}"),
    }
}
```

`restore` and `restore_reader` are exactly that: one visitor over the two
decoders, so the case-hack numbering, the directory stack, and the
descriptor-relative creation cannot drift apart. The two decoders still walk
the NAR grammar separately; a parity test pins them to the same verdicts.

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

## Decode a stream without buffering it

`decode_events_reader` visits those same events over any `std::io::Read`. A
file's contents arrive as a reader rather than a slice, so memory use follows
directory depth and metadata instead of payload size. The reader is consumed
in small pieces, one per length prefix and one per token, so wrap an
unbuffered source.

```rust,no_run
use std::{fs::File, io::{self, BufReader}};
use nix_archive::nar::{decode_events_reader, Error, ReadEvent};

fn payload_bytes() -> Result<u64, Error> {
    let mut nar = BufReader::new(File::open("tree.nar")?);
    let mut total = 0;
    decode_events_reader(&mut nar, |event| {
        if let ReadEvent::Regular { mut contents, .. } = event {
            total += contents.copy_to(&mut io::sink())?;
        }
        Ok(())
    })?;
    Ok(total)
}
```

A visitor that does not read a file to the end is not an error; the decoder
skips the rest and stays positioned. Metadata tokens are bounded, so a
malformed archive cannot ask for an unbounded allocation, and the archive must
be the whole of what remains on the reader. Because nothing is buffered, a
file's bytes reach the visitor before the node around them has been validated;
a visitor that cannot act on unverified bytes should hold them until
`decode_events_reader` returns.

`restore_reader` is this decoder plus a filesystem writer, so it no longer
walks the grammar itself.

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

For asynchronously loaded or external-backed trees, `Encoder` exposes the
same serialization as validated root-first events. Regular-file contents can
be supplied incrementally and held across an async suspension:

```rust
use std::io::Write;
use nix_archive::nar::{Encoder, Error};

fn main() -> Result<(), Error> {
    let mut encoder = Encoder::new(Vec::new())?;
    encoder.start_directory(None)?;
    let mut file = encoder.start_regular(Some(b"hello"), false, 12)?;
    file.write_all(b"hello world\n")?;
    file.finish()?;
    encoder.end_directory()?;
    let nar = encoder.finish()?;
    assert!(!nar.is_empty());
    Ok(())
}
```

The event encoder validates root and directory structure, raw-byte name order,
nesting depth, and declared file sizes. A writer failure permanently poisons
the encoder so a truncated archive cannot accidentally be completed.

## Encode or hash a filesystem tree

```rust,no_run
use std::path::Path;
use nix_archive::nar::{encode_path, hash_path, CaseHack, Error};

fn main() -> Result<(), Error> {
    let path = Path::new("./result");
    let mut nar = Vec::new();
    encode_path(&mut nar, path, CaseHack::native())?;

    let nar_hash = hash_path(path, CaseHack::native())?;
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
use nix_archive::nar::{CaseHack, ReferencePattern};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = [
        "dc04vv14dak1c1r48qa0m23vr9jy8sm0",
        "zc842j0rz61mjsp3h3wp5ly71ak6qgdn",
    ];
    let pattern = ReferencePattern::new(candidates)?;
    let scan = pattern.scan_path(Path::new("./result"), CaseHack::native())?;

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
use nix_archive::nar::{restore, CaseHack, Error};

fn unpack(nar: &[u8]) -> Result<(), Error> {
    restore(nar, Path::new("./restored"), CaseHack::native())
}
```

For archives that are not already in memory, `restore_reader` accepts any
`std::io::Read` and streams regular-file contents directly to disk:

```rust,no_run
use std::{fs::File, io::BufReader, path::Path};
use nix_archive::nar::{restore_reader, CaseHack, Error};

fn restore_file() -> Result<(), Error> {
    let mut nar = BufReader::new(File::open("tree.nar")?);
    restore_reader(&mut nar, Path::new("./restored"), CaseHack::native())
}
```

The destination must not exist, and its final lexical component must not be
empty, `.` or `..`. Restoration is not transactional; an error can leave a
partial tree. Child creation is descriptor-relative, so replacing a restored
directory path with a symlink cannot redirect later writes.

On macOS, Nix represents case-colliding names on disk with suffixes such as
`~nix~case~hack~1`. `restore` and `encode_path` reproduce Nix's compiled-in
default for its `use-case-hack` setting: enabled on macOS, disabled elsewhere.

That default is a proxy. What the hack really tracks is whether the local
filesystem is case-insensitive, and macOS is only Nix's stand-in for it. This
crate follows the proxy deliberately, because NAR bytes feed store-path
identity and guessing differently from Nix would yield different store paths
for the same tree.

The proxy is loose enough that people correct it by hand. macOS users who
created a case-sensitive APFS volume commonly set `use-case-hack = false`,
since on such a volume the hack is not just unnecessary: with it enabled, a
legitimate file named `notes~nix~case~hack~1` is dumped as `notes`. Measured
on this crate, that single file changes the archive from 304 bytes to 288 and
gives a different hash. For a tree carrying no such suffix, which is nearly
every tree, both settings produce byte-identical output, so flipping the
setting is safe exactly where it is a no-op.

So `encode_path`, `hash_path`, `restore`, `restore_reader`, and
`ReferencePattern::scan_path` all take a `CaseHack` argument rather than
defaulting it. A hash-affecting input that real installations vary should not
be inferred from `cfg!(target_os)` behind the caller's back; `CaseHack::native()`
asks for Nix's default in one visible token, and a tool that reads
`nix config show use-case-hack` can pass what it found instead.

The `nix-archive` command exposes the same choice as `--case-hack
<native|enabled|disabled>`.

## Allocation behavior

| API | Heap behavior |
| --- | --- |
| `decode_events` | Zero allocations on valid input with an allocation-free visitor |
| `decode` | Allocates the result vector and paths; payloads and symlink targets remain borrowed |
| `decode_events_reader` | Payload-independent; allocates depth-bounded name buffers and one reused symlink-target buffer |
| `encode_tree` | Zero allocations with an allocation-free writer |
| `Encoder` | Payload-independent; retains the previous child name at each open directory depth |
| `hash_tree` | Zero allocations |
| `encode_path` / `hash_path` | Allocates directory metadata; streams file payloads |
| `ReferencePattern` | Allocates candidate lookup state once; clones share it |
| `ReferenceScanner` / `ReferenceWriter` | Allocates match state at construction; no allocations while scanning |
| `restore` | Allocates the directory stack, plus per-directory collision state when the case hack is on; payloads are never copied |
| `restore_reader` | Payload-independent; the same, plus `decode_events_reader`'s buffers |

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
- streaming-decoder parity for every validation branch, early payload drops,
  copy failures, and payload-independent allocation counts;
- non-UTF-8 names and symlink targets;
- executable-bit, sorting, duplicate-name, nesting-depth, and many-file cases;
- restore rejection for invalid or pre-existing destinations of every node type;
- descriptor-anchoring regressions for concurrent path and symlink swaps;
- Nix/Lix reference-scanner chunk cases, every split boundary, overlaps, and duplicates;
- whole-NAR reference matches in file contents, entry names, and symlink targets;
- an Antithesis SDK workload comparing randomized payloads, candidate sets, and chunking against an independent naive oracle;
- empty patterns, invalid alphabets, writer failures, case-hack modes, and 32 MiB bounded-memory scanning;
- macOS case-hack round trips and both collision failure modes;
- exact zero-allocation assertions for borrowed decoding, encoding, hashing, and scanning;
- incremental encoding parity, event validation, exact payload sizes, writer
  poisoning, and `Send` across an async suspension.

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

Criterion benchmarks cover borrowed, collecting, and streaming decode (both
`FileContents::copy_to` and ordinary `Read` consumption), borrowed-tree
encoding and hashing, reference scanning with reusable candidate sets,
1,000-entry directories, filesystem streaming, case hack overhead, and
filesystem encoding compared with Nix's daemon protocol.

Results from 2026-08-20 on an AMD Ryzen 7 7840S (Linux x86-64), using
`rustc 1.97.1` and Criterion 0.8.2. Criterion was pinned to one otherwise idle
logical CPU to isolate it from unrelated builds running on the host.

| Input | Operation | Time | Throughput |
| --- | --- | ---: | ---: |
| 4 KiB regular file | `decode_events` | 117 ns | — |
| 4 KiB regular file | `decode` | 146 ns | — |
| 4 KiB regular file | `decode_events_reader` + `copy_to` | 234 ns | 16.7 GiB/s |
| 4 KiB regular file | `decode_events_reader` as `Read` | 292 ns | 13.4 GiB/s |
| 4 KiB regular file | `encode_tree` to counting sink | 25.6 ns | — |
| 4 KiB regular file | `hash_tree` | 2.80 µs | 1.40 GiB/s |
| 1 MiB regular file | `decode_events` | 104 ns | — |
| 1 MiB regular file | `decode` | 127 ns | — |
| 1 MiB regular file | `decode_events_reader` + `copy_to` | 19.5 µs | 50.1 GiB/s |
| 1 MiB regular file | `decode_events_reader` as `Read` | 19.6 µs | 49.8 GiB/s |
| 1 MiB regular file | `encode_tree` to counting sink | 24.7 ns | — |
| 1 MiB regular file | `hash_tree` | 686 µs | 1.42 GiB/s |
| 1,000-entry borrowed directory | `decode_events` | 208 µs | 4.80 M entries/s |
| 1,000-entry borrowed directory | `decode` | 261 µs | 3.82 M entries/s |
| 1,000-entry streaming directory | `decode_events_reader` | 297 µs | 3.37 M entries/s |
| 1,000-entry borrowed directory | `encode_tree` to counting sink | 64.6 µs | 15.5 M entries/s |
| 1,000-entry borrowed directory | `hash_tree` | 296 µs | 3.38 M entries/s |
| 8 MiB filesystem file | `encode_path` to counting sink | 1.58 ms | 4.95 GiB/s |
| 1,000-file filesystem directory | `encode_path` | 6.99 ms | 143 K entries/s |
| 1,000-file filesystem directory | `encode_path` with case hack | 7.07 ms | 142 K entries/s |

The same run compared filesystem encoding of the installed Nix 2.34.8
package's 4,060,120-byte NAR through a daemon reporting version 2.34.7. The
benchmark verified byte-for-byte equality before timing:

| Implementation | Time | Throughput | Relative time |
| --- | ---: | ---: | ---: |
| `nix-archive` `encode_path` | 998 µs | 3.79 GiB/s | 1.00× |
| Nix 2.34.7 daemon `NarFromPath` | 1.90 ms | 1.99 GiB/s | 1.90× |

The Nix result uses the stock daemon's `NarFromPath` worker-protocol operation.
It includes Unix-socket request and response overhead but excludes connection
setup; both implementations reuse their output buffer and operate on warm
filesystem caches. This compares the full paths users would call, not just Nix's
internal encoder in isolation.

These are Criterion central estimates from one run, so they should be treated
as indicative rather than universal. Borrowed regular-file decoding does not
scan the payload, and the counting sink does not copy it; their timings measure
format traversal and serialization overhead rather than memory bandwidth. The
streaming regular-file cases consume the full payload from an in-memory
`Cursor` into that sink, so they measure decoder and `Read` overhead rather
than filesystem I/O. The Nix comparison runs when a daemon socket and a `nix`
executable in `PATH` are available, and otherwise skips without failing the
other benchmarks.

```console
devenv shell -- cargo bench --bench nar
```

## Scope

Only NAR is implemented today. Additional Nix archive formats can be added as
new modules without changing the `nix-archive` package name.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
