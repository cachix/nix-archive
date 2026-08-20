//! Shared heap-tracking harness for the tests that assert on memory use.
//!
//! Each integration test is its own binary, so the `#[global_allocator]` has to
//! be installed once per binary. Declaring it here means every test that pulls
//! this module in measures with the same accounting, rather than each keeping
//! its own copy of the arithmetic to drift.

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// Calls are counted per thread, unlike the byte totals: the harness
    /// allocates on its own threads for as long as a test runs, which a
    /// process-wide counter would fold into the measurement. Const-initialized
    /// so that reaching for it cannot itself allocate.
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

pub struct TrackingAllocator;

fn counted() {
    let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
}

fn allocated(size: usize) {
    counted();
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
                counted();
                LIVE_BYTES.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

/// Every test in a binary shares the counters, so they take turns rather than
/// piling their own allocations into whatever is currently being measured.
pub fn serialized() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Start measuring: the live heap now, with the peak reset to match it.
pub fn baseline() -> usize {
    let live = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(live, Ordering::Relaxed);
    live
}

/// How far the live heap peaked above `baseline` since it was taken.
pub fn peak_growth(baseline: usize) -> usize {
    PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline)
}

/// Start counting this thread's allocator calls again from zero.
///
/// Bytes answer "how much was live at once"; calls answer "how many times did
/// this reach for the heap", which is the question a per-item allocation asks.
/// A buffer reused across a thousand items and one allocated per item can look
/// identical by peak bytes and differ by a thousand calls.
pub fn reset_allocation_calls() {
    CALLS.with(|calls| calls.set(0));
}

/// Allocator calls on this thread since [`reset_allocation_calls`].
pub fn allocation_calls() -> usize {
    CALLS.with(Cell::get)
}
