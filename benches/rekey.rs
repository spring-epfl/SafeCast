//! Criterion benchmarks for MLS rekey (self-update commit) operations.
//!
//!
//! Measures the cost of rekeying an MLS group (i.e., creating a self-update
//! commit that advances the group to a new epoch with fresh key material).
//! This is the MLS operation that triggers SRTP key rotation: after the
//! epoch advances, each member re-exports fresh SRTP master key and salt
//! via the MLS exporter (RFC 9420 §8.5).
//!
//! Benchmarks (all parameterized by group size):
//!
//!   1. create_rekey_commit: sender creates a self-update commit and merges
//!      it (self_update + merge_pending_commit).
//!
//!   2. process_rekey_commit: receiver processes and merges an incoming
//!      rekey commit (process_message + merge_staged_commit). This involves
//!      decrypting the path secret, recomputing tree hashes, and deriving
//!      the new epoch secret. Does NOT include SRTP key export.
//!
//!   3. export_srtp_keys: standalone cost of deriving SRTP master key +
//!      salt from the current epoch via the MLS exporter (export_secret).
//!
//!   4. sender_rekey_pipeline: create_rekey_commit + export_srtp_keys
//!      (total sender-side cost per epoch change).
//!
//!   5. receiver_rekey_pipeline: process_rekey_commit + export_srtp_keys
//!      (total receiver-side cost per epoch change).
//! 
//! Run: cargo bench --package mls-srtp-core --bench rekey

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use mls_srtp_core::keying::mls::{
    create_rekey_commit, export_srtp_keys, process_commit, ssrc_from_identity, MlsMember,
    CIPHERSUITE,
};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

const GROUP_SIZES: &[usize] = &[2, 10, 50, 200, 500, 1000, 5000];

// ---------------------------------------------------------------------------
// Group setup
// ---------------------------------------------------------------------------

/// Creates an MLS group with `n` members and returns only the 2 members
/// needed for benchmarking (the creator and one receiver).
///
/// Each new member self-updates after joining, producing a fully populated
/// ratchet tree (no blank nodes). This follows the `CommitAfterJoin` variant
/// from OpenMLS's own `large-groups.rs` benchmark example. Without the
/// self-updates, the tree would contain blank internal nodes whose resolution
/// depends on topology, making commit cost vary with which member commits
/// rather than just group size.
///
/// Optimization: Only the creator (member 0) and member 1 maintain
/// up-to-date group state. Each additional member is added, joins via
/// Welcome, and immediately self-updates — which populates all internal
/// nodes along their direct path to the root with fresh HPKE key pairs.
/// Members 0 and 1 process both the add and the self-update commit, so
/// their local ratchet tree reflects the newly filled nodes. The new
/// member's own group state is then discarded: it doesn't need to stay
/// around because it won't participate in the benchmarks. The
/// performance gain comes from avoiding having all members process every
/// subsequent add/self-update. Without this, member i's join would
/// require all i-1 existing members to process two commits, giving
/// O(n^2) total work.
///
/// Returns 2 entries: [(member 0 state), (member 1 state)].
fn setup_group(n: usize) -> Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)> {
    assert!(n >= 2, "need at least 2 members for a meaningful group");

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // Member 0: group creator
    let creator = MlsMember::new("member-0:member");
    let creator_group = MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &group_config,
        creator.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    // We only keep state for member 0 (creator) and member 1 (first joiner).
    // All other members are added to grow the tree but their state is dropped.
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

        // new member joins via Welcome
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

        // Keeping member 1's state and discarding everyone else's after they join.
        // Member 1 is the second member added (i == 1).
        if i == 1 {
            members.push((new_group, new_member.provider, new_member.signer));
        }
        // For i > 1: new_group is dropped here, as we only needed it to
        // self-update and fill its leaf in the tree. Members 0 and 1
        // already processed the update, so their trees are up to date.
    }

    members
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmarks the MLS rekeying pipeline: creating and processing self-update
/// commits that trigger SRTP key rotation. Measures both the sender-side
/// cost of creating a rekey commit and exporting new SRTP keys, as well as
/// the receiver-side cost.
fn bench_mls_rekey(c: &mut Criterion) {

    // pre-creating groups of each size (expensive, done once)
    let groups: Vec<(usize, Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)>)> = GROUP_SIZES
        .iter()
        .map(|&n| {
            eprintln!("[setup] Creating {n}-member group...");
            (n, setup_group(n))
        })
        .collect();

    // --- Benchmark 1: sender creates rekey commit ---
    //
    // Measures: self_update + merge_pending_commit
    // The committer generates a fresh HPKE leaf key pair and encrypts
    // path secrets to O(log n) copath nodes.
    {
        let mut bg = c.benchmark_group("create_rekey_commit");
        for (n, members) in &groups {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[1].0.clone(), members[1].1.clone()),
                    |(mut grp, prov)| {
                        black_box(create_rekey_commit(&mut grp, &prov, &members[1].2));
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Benchmark 2: receiver processes rekey commit ---
    //
    // Measures: process_message + merge_staged_commit
    // The receiver decrypts its path secret, recomputes tree hashes,
    // and derives the new epoch secret.
    {
        let mut bg = c.benchmark_group("process_rekey_commit");
        for (n, members) in &groups {
            // Pre-create one commit from member[1] (outside timed section)
            let mut sender_clone = members[1].0.clone();
            let sender_prov = members[1].1.clone();
            let commit =
                create_rekey_commit(&mut sender_clone, &sender_prov, &members[1].2);

            // benchmarking member[0] processing the commit
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[0].0.clone(), members[0].1.clone(), commit.clone()),
                    |(mut grp, prov, c)| {
                        process_commit(&mut grp, &prov, c);
                        black_box(&grp);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Benchmark 3: SRTP key export only ---
    //
    // Measures: export_srtp_keys (two calls to MLS export_secret: one
    // for the master key, one for the master salt). This isolates the
    // exporter cost from the commit processing cost.
    {
        let mut bg = c.benchmark_group("export_srtp_keys");
        for (n, members) in &groups {
            let ssrc = ssrc_from_identity("member-1:member");

            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter(|| {
                    let (km, _, _) =
                        export_srtp_keys(&members[0].0, members[0].1.crypto(), ssrc);
                    black_box(&km);
                });
            });
        }
        bg.finish();
    }

    // --- Benchmark 4: sender rekey + SRTP key export ---
    //
    // Total sender-side cost per epoch change: creating the rekey commit
    // and then exporting fresh SRTP key material from the new epoch.
    {
        let mut bg = c.benchmark_group("sender_rekey_pipeline");
        for (n, members) in &groups {
            let ssrc = ssrc_from_identity("member-1:member");

            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[1].0.clone(), members[1].1.clone()),
                    |(mut grp, prov)| {
                        let commit = create_rekey_commit(&mut grp, &prov, &members[1].2);
                        black_box(&commit);
                        let (km, _, _) = export_srtp_keys(&grp, prov.crypto(), ssrc);
                        black_box(&km);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Benchmark 5: receiver process + SRTP key export ---
    //
    // Total receiver-side cost per epoch change: processing the incoming
    // rekey commit and then exporting fresh SRTP key material.
    {
        let mut bg = c.benchmark_group("receiver_rekey_pipeline");
        for (n, members) in &groups {
            let mut sender_clone = members[1].0.clone();
            let sender_prov = members[1].1.clone();
            let commit =
                create_rekey_commit(&mut sender_clone, &sender_prov, &members[1].2);
            let ssrc = ssrc_from_identity("member-1:member");

            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[0].0.clone(), members[0].1.clone(), commit.clone()),
                    |(mut grp, prov, c)| {
                        process_commit(&mut grp, &prov, c);
                        let (km, _, _) = export_srtp_keys(&grp, prov.crypto(), ssrc);
                        black_box(&km);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }
}

criterion_group!(benches, bench_mls_rekey);
criterion_main!(benches);
