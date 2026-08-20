//! Encoding must stream file payloads instead of materializing them.

#![cfg(unix)]

use std::fs;
use std::io::{self, BufReader, Seek, SeekFrom, Write};

use nix_archive::nar::{encode_path, restore_reader, CaseHack, ReferencePattern};

mod common;

use common::{baseline, peak_growth, serialized};

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    largest_write: usize,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len() as u64;
        self.largest_write = self.largest_write.max(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn large_file_encoding_and_reference_scanning_have_payload_independent_memory_use() {
    let _guard = serialized();
    const FILE_SIZE: u64 = 32 * 1024 * 1024;
    const MAX_EXTRA_LIVE_BYTES: usize = 2 * 1024 * 1024;
    const HASH: &str = "dc04vv14dak1c1r48qa0m23vr9jy8sm0";

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("large-sparse-file");
    let mut file = fs::File::create(&path).unwrap();
    file.set_len(FILE_SIZE).unwrap();
    file.seek(SeekFrom::End(-(HASH.len() as i64))).unwrap();
    file.write_all(HASH.as_bytes()).unwrap();
    drop(file);
    let pattern = ReferencePattern::new([HASH]).unwrap();

    let before = baseline();

    let mut sink = CountingSink::default();
    encode_path(&mut sink, &path, CaseHack::native()).unwrap();

    let growth = peak_growth(before);
    assert!(sink.bytes > FILE_SIZE, "NAR framing was not written");
    assert!(
        sink.largest_write < MAX_EXTRA_LIVE_BYTES,
        "encoder issued a payload-sized write of {} bytes",
        sink.largest_write
    );
    assert!(
        growth < MAX_EXTRA_LIVE_BYTES,
        "encoding a {FILE_SIZE}-byte file grew the live heap by {growth} bytes"
    );

    let before = baseline();

    let scan = pattern.scan_path(&path, CaseHack::native()).unwrap();

    let growth = peak_growth(before);
    assert_eq!(scan.nar_size, sink.bytes);
    assert_eq!(scan.matches, [0]);
    assert!(
        growth < MAX_EXTRA_LIVE_BYTES,
        "scanning a {FILE_SIZE}-byte file grew the live heap by {growth} bytes"
    );
}

#[test]
fn large_file_streaming_restore_has_payload_independent_memory_use() {
    let _guard = serialized();
    const FILE_SIZE: u64 = 32 * 1024 * 1024;
    const MAX_EXTRA_LIVE_BYTES: usize = 2 * 1024 * 1024;

    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("large-sparse-file");
    fs::File::create(&source)
        .unwrap()
        .set_len(FILE_SIZE)
        .unwrap();
    let archive_path = tmp.path().join("large.nar");
    let mut archive = fs::File::create(&archive_path).unwrap();
    encode_path(&mut archive, &source, CaseHack::native()).unwrap();
    drop(archive);

    let before = baseline();

    let mut archive = BufReader::new(fs::File::open(&archive_path).unwrap());
    let restored = tmp.path().join("restored");
    restore_reader(&mut archive, &restored, CaseHack::native()).unwrap();

    let growth = peak_growth(before);
    assert_eq!(fs::metadata(restored).unwrap().len(), FILE_SIZE);
    assert!(
        growth < MAX_EXTRA_LIVE_BYTES,
        "restoring a {FILE_SIZE}-byte file grew the live heap by {growth} bytes"
    );
}
