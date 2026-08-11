//! Encoding must stream file payloads instead of materializing them.

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::io::{self, BufReader, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use nix_archive::nar::{encode_path, restore_reader, ReferencePattern};

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct TrackingAllocator;

fn allocated(size: usize) {
    let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, old, new_size) };
        if !new_ptr.is_null() {
            if new_size >= old.size() {
                allocated(new_size - old.size());
            } else {
                LIVE_BYTES.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

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
    let _guard = TEST_LOCK.lock().unwrap();
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

    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);

    let mut sink = CountingSink::default();
    encode_path(&mut sink, &path).unwrap();

    let peak_growth = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(sink.bytes > FILE_SIZE, "NAR framing was not written");
    assert!(
        sink.largest_write < MAX_EXTRA_LIVE_BYTES,
        "encoder issued a payload-sized write of {} bytes",
        sink.largest_write
    );
    assert!(
        peak_growth < MAX_EXTRA_LIVE_BYTES,
        "encoding a {FILE_SIZE}-byte file grew the live heap by {peak_growth} bytes"
    );

    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);

    let scan = pattern.scan_path(&path).unwrap();

    let peak_growth = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    assert_eq!(scan.nar_size, sink.bytes);
    assert_eq!(scan.matches, [0]);
    assert!(
        peak_growth < MAX_EXTRA_LIVE_BYTES,
        "scanning a {FILE_SIZE}-byte file grew the live heap by {peak_growth} bytes"
    );
}

#[test]
fn large_file_streaming_restore_has_payload_independent_memory_use() {
    let _guard = TEST_LOCK.lock().unwrap();
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
    encode_path(&mut archive, &source).unwrap();
    drop(archive);

    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);

    let mut archive = BufReader::new(fs::File::open(&archive_path).unwrap());
    let restored = tmp.path().join("restored");
    restore_reader(&mut archive, &restored).unwrap();

    let peak_growth = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    assert_eq!(fs::metadata(restored).unwrap().len(), FILE_SIZE);
    assert!(
        peak_growth < MAX_EXTRA_LIVE_BYTES,
        "restoring a {FILE_SIZE}-byte file grew the live heap by {peak_growth} bytes"
    );
}
