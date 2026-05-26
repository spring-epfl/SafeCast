//! Measures how much memory each member needs to store the group state,
//! for different group sizes.
//!
//! Run: cargo run --release --bin memory_usage
//!
//! We replace Rust's default memory allocator with a wrapper that counts
//! how many bytes are currently allocated. To measure the memory of an
//! MlsGroup, we record the byte count before and after dropping it
//! (the difference is the memory that group was using).
//!
//! Results are written to benches/results/memory_usage.json.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Tracking allocator
// ---------------------------------------------------------------------------
//
// A thin wrapper around Rust's default System allocator. Every time memory
// is allocated, we add the size to a global counter. Every time memory is
// freed, we subtract it. This lets us take snapshots of total heap usage
// at any point during execution.

struct TrackingAllocator;

/// Global counter: current number of bytes allocated on the heap.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// Implementing GlobalAlloc tells Rust how our allocator should handle
// memory requests. Whenever the program needs to allocate or free heap memory, it will
// call these methods on our TrackingAllocator.
unsafe impl GlobalAlloc for TrackingAllocator {

    // Called whenever the program needs new heap memory. `layout` contains the
    // number of bytes requested.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // delegating to the real allocator
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            // allocation succeeded: adding its size to the counter
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    // Called whenever heap memory is freed. 
    // `layout` tells us how many bytes are being released.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // delegating to the real allocator
        unsafe { System.dealloc(ptr, layout) };
        // subtracting the freed size from the counter
        ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

// Telling Rust to use our wrapper instead of the default allocator.
#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

/// Returns the current total number of bytes allocated on the heap.
fn current_allocated() -> usize {
    ALLOCATED.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Group setup
// ---------------------------------------------------------------------------
//
// Creates an MLS group with `n` members and returns only the creator
// (member 0) and one receiver (member 1). All other members are added
// to grow the ratchet tree but their state is discarded afterwards.
// Each new member self-updates after joining to populate its leaf with
// fresh HPKE key pairs (no blank nodes in the tree).

use mls_srtp_core::mls::{create_rekey_commit, process_commit, MlsMember, CIPHERSUITE};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const GROUP_SIZES: &[usize] = &[2, 10, 50, 200, 500, 1000, 5000];

fn setup_group(n: usize) -> Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)> {
    assert!(n >= 2);

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // member 0: group creator
    let creator = MlsMember::new("member-0:member");
    let creator_group = MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &group_config,
        creator.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    // we only keep state for member 0 (creator) and member 1 (first joiner)
    let mut members: Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)> =
        vec![(creator_group, creator.provider, creator.signer)];

    for i in 1..n {
        let new_member = MlsMember::new(&format!("member-{i}:member"));
        let kp = new_member.generate_key_package();

        // creator (member 0) adds the new member
        let (add_commit, welcome) = {
            let (ref mut group, ref provider, ref signer) = members[0];
            let (add_commit, welcome, _) = group
                .add_members(provider, signer, &[kp.key_package().clone()])
                .expect("add_members failed");
            group
                .merge_pending_commit(provider)
                .expect("merge_pending_commit failed");
            (add_commit, welcome)
        };

        // new member joins via Welcome message
        let welcome_in: MlsMessageIn = welcome.into();
        let welcome_msg = welcome_in
            .into_welcome()
            .expect("expected Welcome message");
        let ratchet_tree = members[0].0.export_ratchet_tree();
        let mut new_group = StagedWelcome::new_from_welcome(
            &new_member.provider,
            group_config.join_config(),
            welcome_msg,
            Some(ratchet_tree.into()),
        )
        .expect("new_from_welcome failed")
        .into_group(&new_member.provider)
        .expect("into_group failed");

        // member 1 (if it exists) processes the add commit to stay in sync
        if members.len() > 1 {
            let (ref mut group, ref provider, _) = members[1];
            process_commit(group, provider, add_commit.clone());
        }

        // new member self-updates to populate its leaf in the tree
        let update_commit =
            create_rekey_commit(&mut new_group, &new_member.provider, &new_member.signer);

        // only members 0 and 1 process the self-update commit
        for entry in members.iter_mut() {
            let (ref mut group, ref provider, _) = *entry;
            process_commit(group, provider, update_commit.clone());
        }

        // keeping member 1's state; discarding everyone else's after they join
        if i == 1 {
            members.push((new_group, new_member.provider, new_member.signer));
        }
    }

    members
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
//
// For each group size, we:
//   1. build the full group
//   2. read how many bytes are currently on the heap
//   3. drop the creator's MlsGroup, freeing its memory
//   4. read the heap counter again
//   5. calculate the difference = how much memory that group was using
//
// We only measure the MlsGroup itself.

fn main() {
    let mut results: Vec<serde_json::Value> = Vec::new();

    for &n in GROUP_SIZES {
        eprintln!("[setup] Creating {n}-member group...");
        let mut members = setup_group(n);

        // setup_group returns a list of (MlsGroup, provider, signer) tuples.
        // We take the creator's tuple and unpack it so we can drop only the 
        // MlsGroup and measure its memory. 
        // remove(0) takes the tuple out of the members vector and returns it. 
        let (group, _provider, _signer) = members.remove(0);

        // snapshot before dropping
        let before = current_allocated();

        // dropping
        drop(group);

        // snapshot after dropping
        let after = current_allocated();

        // the difference is the memory the group was using
        let group_bytes = before.saturating_sub(after);

        // converting to KB
        let group_kb = group_bytes as f64 / 1024.0;

        // printing
        eprintln!("  n={n}: {group_bytes} bytes ({group_kb:.1} KB)");

        // saving result in JSON format
        results.push(serde_json::json!({
            "group_size": n,
            "bytes": group_bytes,
        }));
    }

    // writing final results to JSON file
    let output_dir = std::path::Path::new("crates/mls-srtp-core/benches/results");
    std::fs::create_dir_all(output_dir).expect("failed to create output dir");
    let output_path = output_dir.join("memory_usage.json");

    let json = serde_json::to_string_pretty(&results).expect("failed to serialize");
    std::fs::write(&output_path, &json).expect("failed to write JSON");

    eprintln!("\nResults written to {}", output_path.display());

    // also printing the final results
    println!("{json}");
}
