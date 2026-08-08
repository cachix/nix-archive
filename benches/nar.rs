//! Run with `cargo bench -p nix-archive --bench nar`.

use std::fs;
use std::hint::black_box;
use std::io::{self, Write};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nix_archive::nar::{
    decode, decode_events, encode_path_with_case_hack, encode_tree, hash_tree, CaseHack, NamedNode,
    Node,
};

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
            encode_path_with_case_hack(&mut sink, black_box(&file), CaseHack::Disabled).unwrap();
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
                encode_path_with_case_hack(&mut sink, black_box(&directory), case_hack).unwrap();
                black_box(sink.bytes)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_regular, bench_directory, bench_filesystem);
criterion_main!(benches);
