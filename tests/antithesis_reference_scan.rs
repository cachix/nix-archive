//! Antithesis-controlled property workload for streaming reference scanning.
//!
//! The SDK supplies every workload decision directly so Antithesis can branch
//! on candidates, payloads, and chunk boundaries. Native assertions mirror
//! the Antithesis properties so ordinary `cargo test` runs fail immediately on
//! the same counterexamples.

#![cfg(unix)]

use std::io::Write;

use antithesis_sdk::random;
use nix_archive::nar::{ReferencePattern, REFERENCE_LENGTH};

const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";
const SCENARIO_COUNT: usize = 128;

macro_rules! always {
    ($condition:expr, $message:literal) => {{
        let condition = $condition;
        antithesis_sdk::assert_always!(condition, $message);
        assert!(condition, $message);
    }};
}

fn choose<T: Copy>(choices: &[T]) -> T {
    *random::random_choice(choices).expect("property choices are never empty")
}

fn random_below(exclusive_end: usize) -> usize {
    if exclusive_end == 0 {
        0
    } else {
        (random::get_random() % exclusive_end as u64) as usize
    }
}

fn random_reference() -> [u8; REFERENCE_LENGTH] {
    std::array::from_fn(|_| choose(NIX_BASE32))
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let random = random::get_random().to_le_bytes();
        let remaining = length - bytes.len();
        bytes.extend_from_slice(&random[..remaining.min(random.len())]);
    }
    bytes
}

fn inject(bytes: &mut Vec<u8>, reference: &[u8; REFERENCE_LENGTH], offset: usize) {
    let required = offset + REFERENCE_LENGTH;
    if bytes.len() < required {
        bytes.resize(required, 0xff);
    }
    bytes[offset..required].copy_from_slice(reference);
}

fn arbitrary_candidates() -> Vec<[u8; REFERENCE_LENGTH]> {
    let count = choose(&[1, 2, 3, 8, 32]);
    (0..count).map(|_| random_reference()).collect()
}

fn scenario(kind: usize) -> (Vec<[u8; REFERENCE_LENGTH]>, Vec<u8>) {
    let mut candidates = arbitrary_candidates();
    let mut bytes = random_bytes(choose(&[0, 1, 30, 31, 32, 33, 63, 64, 255, 4_096]));

    match kind {
        // Empty candidate set and empty/non-empty streams.
        0 => candidates.clear(),
        // Guaranteed miss, including lengths around the 32-byte boundary.
        1 => bytes.fill(0xff),
        // One candidate at an arbitrary byte offset.
        2 => {
            let offset = random_below(bytes.len().saturating_add(1));
            inject(&mut bytes, &candidates[0], offset);
        }
        // Every candidate occurs, separated by Antithesis-controlled gaps.
        3 => {
            bytes.clear();
            for candidate in &candidates {
                bytes.extend(random_bytes(random_below(34)));
                bytes.extend_from_slice(candidate);
            }
        }
        // Duplicate input candidates must report every corresponding index.
        4 => {
            let duplicate = candidates[0];
            candidates.push(duplicate);
            let offset = random_below(bytes.len().saturating_add(1));
            inject(&mut bytes, &duplicate, offset);
        }
        // Two distinct matches overlap by 31 bytes.
        5 => {
            let run: [u8; REFERENCE_LENGTH + 1] = std::array::from_fn(|_| choose(NIX_BASE32));
            let first = run[..REFERENCE_LENGTH].try_into().unwrap();
            let second = run[1..].try_into().unwrap();
            candidates = vec![first, second, random_reference()];
            let prefix = random_bytes(random_below(34));
            let suffix = random_bytes(random_below(34));
            bytes = prefix;
            bytes.extend_from_slice(&run);
            bytes.extend(suffix);
        }
        // Matches exactly at the beginning and end of a stream.
        6 => {
            bytes = vec![0xff; REFERENCE_LENGTH * 2 + random_below(65)];
            inject(&mut bytes, &candidates[0], 0);
            let end = bytes.len() - REFERENCE_LENGTH;
            let last = *candidates.last().unwrap();
            inject(&mut bytes, &last, end);
        }
        // Fully arbitrary stream with independently chosen candidate insertion.
        _ => {
            for candidate in &candidates {
                if choose(&[false, true]) {
                    let offset = random_below(bytes.len().saturating_add(1));
                    inject(&mut bytes, candidate, offset);
                }
            }
        }
    }

    (candidates, bytes)
}

fn naive_matches(candidates: &[[u8; REFERENCE_LENGTH]], bytes: &[u8]) -> Vec<usize> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            bytes
                .windows(REFERENCE_LENGTH)
                .any(|window| window == candidate)
                .then_some(index)
        })
        .collect()
}

fn random_chunk_ends(length: usize) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut offset = 0;
    while offset < length {
        let remaining = length - offset;
        let requested = choose(&[1, 2, 3, 7, 15, 31, 32, 33, 63, 64, 127, remaining]);
        offset += requested.min(remaining);
        ends.push(offset);
    }
    ends
}

fn match_spans_boundary(
    candidates: &[[u8; REFERENCE_LENGTH]],
    bytes: &[u8],
    ends: &[usize],
) -> bool {
    ends.iter()
        .copied()
        .filter(|&end| end < bytes.len())
        .any(|end| {
            candidates.iter().any(|candidate| {
                bytes
                    .windows(REFERENCE_LENGTH)
                    .enumerate()
                    .any(|(offset, window)| {
                        window == candidate && offset < end && end < offset + REFERENCE_LENGTH
                    })
            })
        })
}

#[test]
fn antithesis_streaming_reference_properties() {
    antithesis_sdk::antithesis_init();
    antithesis_sdk::lifecycle::setup_complete(&serde_json::json!({
        "workload": "nix-archive reference scanning",
        "scenarios_per_run": SCENARIO_COUNT,
    }));

    let mut saw_empty_candidates = false;
    let mut saw_no_match = false;
    let mut saw_all_matches = false;
    let mut saw_duplicate = false;
    let mut saw_overlap = false;
    let mut saw_one_byte_chunk = false;
    let mut saw_boundary_match = false;

    for iteration in 0..SCENARIO_COUNT {
        let kind = iteration % 8;
        let (candidates, bytes) = scenario(kind);
        let expected = naive_matches(&candidates, &bytes);
        let pattern = ReferencePattern::new(&candidates).unwrap();

        let mut ends = random_chunk_ends(bytes.len());
        if kind == 6 && bytes.len() > 1 {
            // Guarantee a match split after its first byte while other
            // scenarios retain fully Antithesis-controlled chunking.
            ends = vec![1, bytes.len()];
        }

        let mut single = pattern.scanner();
        single.scan(&bytes);
        let single_matches = single.into_matches();

        let mut chunked = pattern.scanner();
        let mut start = 0;
        for &end in &ends {
            chunked.scan(&bytes[start..end]);
            start = end;
        }
        if bytes.is_empty() {
            chunked.scan(&[]);
        }
        let complete = chunked.is_complete();
        let matched_count = chunked.matched_count();
        let chunked_matches = chunked.into_matches();

        let mut writer = pattern.writer(Vec::new());
        let mut start = 0;
        for &end in &ends {
            writer.write_all(&bytes[start..end]).unwrap();
            start = end;
        }
        writer.write_all(&bytes[start..]).unwrap();
        let (written, writer_scanner) = writer.into_parts();
        let writer_matches = writer_scanner.into_matches();

        always!(
            single_matches == expected,
            "Single-chunk scanning agrees with the naive reference oracle"
        );
        always!(
            chunked_matches == expected,
            "Arbitrary chunking agrees with the naive reference oracle"
        );
        always!(
            writer_matches == expected,
            "Writer decoration agrees with the naive reference oracle"
        );
        always!(
            written == bytes,
            "Reference writer preserves every accepted byte"
        );
        always!(
            matched_count == expected.len(),
            "Matched count equals the number of oracle matches"
        );
        always!(
            complete == (expected.len() == candidates.len()),
            "Scanner completion means every candidate index was found"
        );

        let empty_candidates = candidates.is_empty();
        let no_match = !empty_candidates && expected.is_empty();
        let all_matches = !empty_candidates && expected.len() == candidates.len();
        let duplicate = kind == 4;
        let overlap = kind == 5;
        let one_byte_chunk = ends
            .iter()
            .copied()
            .scan(0, |start, end| {
                let length = end - *start;
                *start = end;
                Some(length)
            })
            .any(|length| length == 1);
        let boundary_match = match_spans_boundary(&candidates, &bytes, &ends);

        antithesis_sdk::assert_sometimes!(
            empty_candidates,
            "Workload exercises empty candidate sets"
        );
        antithesis_sdk::assert_sometimes!(no_match, "Workload exercises streams with no matches");
        antithesis_sdk::assert_sometimes!(
            all_matches,
            "Workload exercises streams containing every candidate"
        );
        antithesis_sdk::assert_sometimes!(duplicate, "Workload exercises duplicate candidates");
        antithesis_sdk::assert_sometimes!(overlap, "Workload exercises overlapping references");
        antithesis_sdk::assert_sometimes!(
            one_byte_chunk,
            "Workload exercises one-byte stream chunks"
        );
        antithesis_sdk::assert_sometimes!(
            boundary_match,
            "Workload exercises references spanning chunk boundaries"
        );

        saw_empty_candidates |= empty_candidates;
        saw_no_match |= no_match;
        saw_all_matches |= all_matches;
        saw_duplicate |= duplicate;
        saw_overlap |= overlap;
        saw_one_byte_chunk |= one_byte_chunk;
        saw_boundary_match |= boundary_match;
    }

    assert!(saw_empty_candidates);
    assert!(saw_no_match);
    assert!(saw_all_matches);
    assert!(saw_duplicate);
    assert!(saw_overlap);
    assert!(saw_one_byte_chunk);
    assert!(saw_boundary_match);
}
