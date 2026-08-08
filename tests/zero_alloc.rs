//! The borrowed parser and borrowed-tree encoder must not touch the heap.

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use nix_archive::nar::{decode_events, encode_tree, hash_tree, Event, NamedNode, Node};

static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !pointer.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct FixedSink {
    bytes: [u8; 4096],
    len: usize,
}

impl FixedSink {
    fn new() -> Self {
        Self {
            bytes: [0; 4096],
            len: 0,
        }
    }

    fn written(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Write for FixedSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.bytes.len() - self.len;
        let count = remaining.min(bytes.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn reset_allocations() {
    ALLOCATION_CALLS.store(0, Ordering::SeqCst);
}

fn allocation_calls() -> usize {
    ALLOCATION_CALLS.load(Ordering::SeqCst)
}

#[test]
fn borrowed_tree_encoding_hashing_and_event_decoding_allocate_nothing() {
    let nested = [NamedNode {
        name: b"payload",
        node: Node::Regular {
            executable: true,
            contents: b"#!/bin/sh\nexit 0\n",
        },
    }];
    let children = [
        NamedNode {
            name: b"a",
            node: Node::Regular {
                executable: false,
                contents: b"hello",
            },
        },
        NamedNode {
            name: b"dir",
            node: Node::Directory(&nested),
        },
        NamedNode {
            name: b"link",
            node: Node::Symlink { target: b"dir" },
        },
    ];
    let tree = Node::Directory(&children);
    let mut sink = FixedSink::new();

    reset_allocations();
    encode_tree(&mut sink, &tree).unwrap();
    let encoding_allocations = allocation_calls();
    assert_eq!(encoding_allocations, 0, "borrowed-tree encoding allocated");

    reset_allocations();
    let (nar_size, _nar_hash) = hash_tree(&tree).unwrap();
    let hashing_allocations = allocation_calls();
    assert_eq!(hashing_allocations, 0, "borrowed-tree hashing allocated");
    assert_eq!(nar_size, sink.written().len() as u64);

    let mut event_count = 0;
    let mut content_bytes = 0;
    reset_allocations();
    decode_events(sink.written(), |event| {
        event_count += 1;
        if let Event::Regular { contents, .. } = event {
            content_bytes += contents.len();
        }
        Ok(())
    })
    .unwrap();
    let decoding_allocations = allocation_calls();
    assert_eq!(decoding_allocations, 0, "event decoding allocated");
    assert_eq!(event_count, 7);
    assert_eq!(content_bytes, 22);
}
