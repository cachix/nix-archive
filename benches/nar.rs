//! Run with `cargo bench -p nix-archive --bench nar`.

#[path = "support/nix_daemon.rs"]
mod nix_daemon;

use std::env;
use std::fs;
use std::hint::black_box;
use std::io::{self, Cursor, Write};
use std::path::{Component, Path, PathBuf};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nix_archive::nar::{
    decode, decode_events, decode_events_reader, encode_path, encode_tree, hash_tree, CaseHack,
    NamedNode, Node, ReadEvent, ReferencePattern,
};
use nix_daemon::NixDaemon;

#[derive(Default)]
struct CountingSink {
    bytes: u64,
}

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let bytes = black_box(bytes);
        self.bytes += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn archive(tree: &Node<'_>) -> Vec<u8> {
    let mut nar = Vec::new();
    encode_tree(&mut nar, tree).unwrap();
    nar
}

fn bench_regular(c: &mut Criterion) {
    let mut group = c.benchmark_group("regular");

    for &(label, size) in &[("4_kib", 4 * 1024), ("1_mib", 1024 * 1024)] {
        let contents = vec![0xa5; size];
        let tree = Node::Regular {
            executable: false,
            contents: &contents,
        };
        let nar = archive(&tree);
        group.throughput(Throughput::Bytes(nar.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("decode_events", label),
            &nar,
            |bencher, nar| {
                bencher.iter(|| {
                    let mut events = 0usize;
                    decode_events(black_box(nar), |event| {
                        black_box(event);
                        events += 1;
                        Ok(())
                    })
                    .unwrap();
                    black_box(events)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decode_collect", label),
            &nar,
            |bencher, nar| bencher.iter(|| black_box(decode(black_box(nar)).unwrap())),
        );
        // Measure both payload paths: `copy_to` retains the concrete archive
        // reader type, while using `FileContents` as a `Read` erases it.
        group.bench_with_input(
            BenchmarkId::new("decode_events_reader_copy_to", label),
            &nar,
            |bencher, nar| {
                bencher.iter(|| {
                    let mut reader = Cursor::new(black_box(nar.as_slice()));
                    let mut sink = CountingSink::default();
                    decode_events_reader(&mut reader, |event| {
                        if let ReadEvent::Regular { mut contents, .. } = event {
                            contents.copy_to(&mut sink)?;
                        }
                        Ok(())
                    })
                    .unwrap();
                    black_box(sink.bytes)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decode_events_reader_read", label),
            &nar,
            |bencher, nar| {
                bencher.iter(|| {
                    let mut reader = Cursor::new(black_box(nar.as_slice()));
                    let mut sink = CountingSink::default();
                    decode_events_reader(&mut reader, |event| {
                        if let ReadEvent::Regular { mut contents, .. } = event {
                            io::copy(&mut contents, &mut sink)?;
                        }
                        Ok(())
                    })
                    .unwrap();
                    black_box(sink.bytes)
                });
            },
        );
        group.bench_function(BenchmarkId::new("encode_tree_to_sink", label), |bencher| {
            bencher.iter(|| {
                let mut sink = CountingSink::default();
                encode_tree(&mut sink, black_box(&tree)).unwrap();
                black_box(sink.bytes)
            });
        });
        group.bench_function(BenchmarkId::new("hash_tree", label), |bencher| {
            bencher.iter(|| black_box(hash_tree(black_box(&tree)).unwrap()));
        });
    }

    group.finish();
}

fn bench_directory(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 1_000;
    let names: Vec<_> = (0..ENTRY_COUNT)
        .map(|index| format!("file-{index:04}").into_bytes())
        .collect();
    let children: Vec<_> = names
        .iter()
        .map(|name| NamedNode {
            name,
            node: Node::Regular {
                executable: false,
                contents: b"small directory-entry payload",
            },
        })
        .collect();
    let tree = Node::Directory(&children);
    let nar = archive(&tree);

    let mut group = c.benchmark_group("directory_1000");
    group.throughput(Throughput::ElementsAndBytes {
        elements: ENTRY_COUNT as u64,
        bytes: nar.len() as u64,
    });
    group.bench_function("decode_events", |bencher| {
        bencher.iter(|| {
            let mut events = 0usize;
            decode_events(black_box(&nar), |event| {
                black_box(event);
                events += 1;
                Ok(())
            })
            .unwrap();
            black_box(events)
        });
    });
    group.bench_function("decode_collect", |bencher| {
        bencher.iter(|| black_box(decode(black_box(&nar)).unwrap()));
    });
    group.bench_function("decode_events_reader", |bencher| {
        bencher.iter(|| {
            let mut reader = Cursor::new(black_box(nar.as_slice()));
            let mut events = 0usize;
            decode_events_reader(&mut reader, |event| {
                black_box(event);
                events += 1;
                Ok(())
            })
            .unwrap();
            black_box(events)
        });
    });
    group.bench_function("encode_tree_to_sink", |bencher| {
        bencher.iter(|| {
            let mut sink = CountingSink::default();
            encode_tree(&mut sink, black_box(&tree)).unwrap();
            black_box(sink.bytes)
        });
    });
    group.bench_function("hash_tree", |bencher| {
        bencher.iter(|| black_box(hash_tree(black_box(&tree)).unwrap()));
    });
    group.finish();
}

fn bench_filesystem(c: &mut Criterion) {
    const FILE_SIZE: u64 = 8 * 1024 * 1024;
    const ENTRY_COUNT: usize = 1_000;

    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("file");
    fs::File::create(&file).unwrap().set_len(FILE_SIZE).unwrap();

    let directory = tmp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    for index in 0..ENTRY_COUNT {
        fs::write(directory.join(format!("file-{index:04}")), b"").unwrap();
    }

    let mut group = c.benchmark_group("filesystem_encode");
    group.throughput(Throughput::Bytes(FILE_SIZE));
    group.bench_function("regular_8_mib", |bencher| {
        bencher.iter(|| {
            let mut sink = CountingSink::default();
            encode_path(&mut sink, black_box(&file), CaseHack::Disabled).unwrap();
            black_box(sink.bytes)
        });
    });

    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    for (label, case_hack) in [
        ("directory_1000", CaseHack::Disabled),
        ("directory_1000_case_hack", CaseHack::Enabled),
    ] {
        group.bench_function(label, |bencher| {
            bencher.iter(|| {
                let mut sink = CountingSink::default();
                encode_path(&mut sink, black_box(&directory), case_hack).unwrap();
                black_box(sink.bytes)
            });
        });
    }
    group.finish();
}

fn reference_hash(mut value: usize) -> [u8; 32] {
    const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";
    let mut hash = [b'0'; 32];
    for digit in hash.iter_mut().rev() {
        *digit = ALPHABET[value & 31];
        value >>= 5;
    }
    hash
}

fn bench_reference_scan(c: &mut Criterion) {
    const CONTENT_SIZE: usize = 8 * 1024 * 1024;
    const MAX_CANDIDATES: usize = 4_096;

    // Deterministic binary-like payload with sparse real candidates, matching
    // the shape of Nix's own reference-scanner benchmark.
    let mut state = 0x1234_5678_u32;
    let mut contents = vec![0; CONTENT_SIZE];
    for byte in &mut contents {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8;
    }
    let candidates: Vec<_> = (0..MAX_CANDIDATES).map(reference_hash).collect();
    let stride = CONTENT_SIZE / MAX_CANDIDATES;
    for (index, candidate) in candidates.iter().enumerate() {
        let offset = index * stride;
        contents[offset..offset + candidate.len()].copy_from_slice(candidate);
    }
    let tree = Node::Regular {
        executable: false,
        contents: &contents,
    };

    let mut group = c.benchmark_group("reference_scan_8_mib");
    group.throughput(Throughput::Bytes(CONTENT_SIZE as u64));
    group.bench_function("hash_only", |bencher| {
        bencher.iter(|| black_box(hash_tree(black_box(&tree)).unwrap()));
    });
    for count in [16, 256, MAX_CANDIDATES] {
        let pattern = ReferencePattern::new(&candidates[..count]).unwrap();
        group.bench_function(BenchmarkId::new("hash_and_scan", count), |bencher| {
            bencher.iter(|| black_box(pattern.scan_tree(black_box(&tree)).unwrap()));
        });
    }
    group.finish();
}

fn find_nix_store_path() -> Option<PathBuf> {
    let store_directory = Path::new("/nix/store");
    for directory in env::split_paths(&env::var_os("PATH")?) {
        let Ok(executable) = directory.join("nix").canonicalize() else {
            continue;
        };
        let Ok(relative) = executable.strip_prefix(store_directory) else {
            continue;
        };
        let Some(Component::Normal(store_name)) = relative.components().next() else {
            continue;
        };
        return Some(store_directory.join(store_name));
    }
    None
}

fn bench_nix_comparison(c: &mut Criterion) {
    const DAEMON_SOCKET: &str = "/nix/var/nix/daemon-socket/socket";

    let Some(store_path) = find_nix_store_path() else {
        eprintln!("skipping Nix comparison: could not locate the Nix package store path");
        return;
    };
    let Some(store_path_text) = store_path.to_str() else {
        eprintln!("skipping Nix comparison: Nix store path is not UTF-8");
        return;
    };
    let mut daemon = match NixDaemon::connect(Path::new(DAEMON_SOCKET)) {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("skipping Nix comparison: could not connect to Nix daemon: {error}");
            return;
        }
    };

    let mut expected = Vec::new();
    encode_path(&mut expected, &store_path, CaseHack::Disabled).unwrap();
    let mut nix_output = vec![0; expected.len()];
    daemon
        .nar_from_path(store_path_text, &mut nix_output)
        .unwrap();
    assert_eq!(
        nix_output, expected,
        "nix-archive output differs from Nix daemon NarFromPath"
    );

    eprintln!(
        "benchmarking against Nix {} using {} ({} NAR bytes)",
        daemon.version(),
        store_path.display(),
        expected.len()
    );

    let mut group = c.benchmark_group("nix_comparison");
    group.throughput(Throughput::Bytes(expected.len() as u64));

    let mut ours_output = Vec::with_capacity(expected.len());
    group.bench_function("nix_archive_encode_path", |bencher| {
        bencher.iter(|| {
            ours_output.clear();
            encode_path(&mut ours_output, black_box(&store_path), CaseHack::Disabled).unwrap();
            black_box(ours_output.len())
        });
    });

    group.bench_function("nix_daemon_nar_from_path", |bencher| {
        bencher.iter(|| {
            daemon
                .nar_from_path(black_box(store_path_text), &mut nix_output)
                .unwrap();
            black_box(nix_output.len())
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_regular,
    bench_directory,
    bench_filesystem,
    bench_reference_scan,
    bench_nix_comparison
);
criterion_main!(benches);
