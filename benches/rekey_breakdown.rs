//! Criterion benchmarks for MLS rekey pipeline component breakdown.
//!
//!
//! Breaks down the sender and receiver rekey pipelines into their individual
//! sub-operations, measured separately across group sizes. This lets us
//! produce a stacked bar chart showing where time is spent in each pipeline.
//!
//! Sender pipeline components:
//!   1. propose_self_update:         Generates fresh HPKE leaf key pair + signs Update proposal
//!   2. commit_builder.build():      Encrypts path secrets to O(log n) copath nodes
//!   3. stage_commit():              Encrypts commit into PrivateMessage
//!   4. merge_pending_commit:        Advances local state to new epoch
//!
//! Receiver pipeline components:
//!   1. unprotect_message:                Decrypts commit
//!   2. process_unverified_message:       Verifies signature + decrypts path secrets
//!   3. merge_staged_commit:              Advances local state to new epoch
//!
//! SRTP key export (~4 µs) is omitted as it is negligible.
//!
//! NOTE: `process_unverified_message` is `pub(crate)` in upstream OpenMLS.
//! We changed it to `pub` in our local fork to allow benchmarking the
//! receiver-side path decryption separately from the framing decryption.
//! 
//! Run: cargo bench --package safecast-core --bench rekey_breakdown

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use safecast_core::keying::mls::{
    create_rekey_commit, process_commit, MlsMember,
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
fn setup_group(n: usize) -> Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)> {
    assert!(n >= 2, "need at least 2 members for a meaningful group");

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

        // member 1 processes the add commit to stay in sync
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
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmarks each individual sub-operation of the MLS rekey pipeline,
/// both sender-side and receiver-side.
fn bench_rekey_breakdown(c: &mut Criterion) {

    // pre-creating groups of each size
    let groups: Vec<(usize, Vec<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair)>)> = GROUP_SIZES
        .iter()
        .map(|&n| {
            eprintln!("[setup] Creating {n}-member group...");
            (n, setup_group(n))
        })
        .collect();

    // =====================================================================
    // Sender-side component breakdown
    //
    // Each benchmark isolates one step by performing all preceding steps
    // in the setup closure (untimed).
    // =====================================================================

    // --- Sender component 1: propose_self_update ---
    //
    // Generates a fresh HPKE leaf key pair and signs an Update proposal.
    // The proposal is queued internally and will be consumed by the commit
    // builder in the next step. Cost is roughly constant across group sizes
    // since it only touches the sender's own leaf node.
    {
        let mut bg = c.benchmark_group("breakdown_sender_propose");
        for (n, members) in &groups {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[1].0.clone(), members[1].1.clone()),
                    |(mut grp, prov)| {
                        let (proposal, _ref) = grp
                            .propose_self_update(
                                &prov,
                                &members[1].2,
                                LeafNodeParameters::default(),
                            )
                            .expect("propose_self_update failed");
                        black_box(proposal);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Sender component 2: commit_builder.build() ---
    //
    // Consumes the pending Update proposal and builds the commit. This is
    // the most expensive sender-side step: it generates fresh HPKE key pairs
    // for each node on the sender's direct path and encrypts the path
    // secrets to all O(log n) copath nodes.
    {
        let mut bg = c.benchmark_group("breakdown_sender_build");
        for (n, members) in &groups {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || {
                        let mut grp = members[1].0.clone();
                        let prov = members[1].1.clone();

                        // propose_self_update runs in setup (not timed)
                        grp.propose_self_update(
                            &prov,
                            &members[1].2,
                            LeafNodeParameters::default(),
                        )
                        .expect("propose_self_update failed");
                        (grp, prov)
                    },
                    |(mut grp, prov)| {
                        let built = grp
                            .commit_builder()
                            .consume_proposal_store(true)
                            .load_psks(prov.storage())
                            .expect("load_psks failed")
                            .build(prov.rand(), prov.crypto(), &members[1].2, |_| true)
                            .expect("build failed");
                        black_box(built);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Sender component 3: build() + stage_commit() together ---
    //
    // stage_commit() encrypts the plaintext commit into a PrivateMessage
    // using AEAD. This benchmark times build() + stage_commit()
    // together, and the notebook derives the stage cost by subtracting
    // the build-only benchmark above. Cost is roughly constant
    // because it is a single AEAD encryption regardless of group size.
    {
        let mut bg = c.benchmark_group("breakdown_sender_build_and_stage");
        for (n, members) in &groups {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || {
                        let mut grp = members[1].0.clone();
                        let prov = members[1].1.clone();

                        // propose_self_update runs in setup (not timed)
                        grp.propose_self_update(
                            &prov,
                            &members[1].2,
                            LeafNodeParameters::default(),
                        )
                        .expect("propose_self_update failed");
                        (grp, prov)
                    },
                    |(mut grp, prov)| {
                        let bundle = grp
                            .commit_builder()
                            .consume_proposal_store(true)
                            .load_psks(prov.storage())
                            .expect("load_psks failed")
                            .build(prov.rand(), prov.crypto(), &members[1].2, |_| true)
                            .expect("build failed")
                            .stage_commit(&prov)
                            .expect("stage_commit failed");
                        black_box(bundle);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Sender component 4: merge_pending_commit ---
    //
    // Advances the sender's group state to the new epoch. Updates the
    // ratchet tree with the new path public keys, derives the new epoch
    // secret from the commit secret, and persists the updated state.
    // Uses self_update() in setup which does propose + commit + stage
    // in one call, leaving only merge_pending_commit for the timed section.
    {
        let mut bg = c.benchmark_group("breakdown_sender_merge_pending");
        for (n, members) in &groups {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || {
                        let mut grp = members[1].0.clone();
                        let prov = members[1].1.clone();

                        // self_update creates the pending commit (in setup, not timed)
                        let _commit = grp
                            .self_update(&prov, &members[1].2, LeafNodeParameters::default())
                            .expect("self_update failed");
                        (grp, prov)
                    },
                    |(mut grp, prov)| {
                        grp.merge_pending_commit(&prov)
                            .expect("merge_pending_commit failed");
                        black_box(&grp);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // =====================================================================
    // Receiver-side component breakdown
    //
    // Each benchmark isolates one step. We pre-create one commit per group
    // size (from member 1) so that all receiver benchmarks process the
    // same commit message.
    // =====================================================================

    // pre-create one commit per group size for receiver benchmarks
    let commits: Vec<(usize, MlsMessageOut)> = groups
        .iter()
        .map(|(n, members)| {
            let mut sender_clone = members[1].0.clone();
            let sender_prov = members[1].1.clone();
            let commit =
                create_rekey_commit(&mut sender_clone, &sender_prov, &members[1].2);
            (*n, commit)
        })
        .collect();

    // --- Receiver component 1: unprotect_message ---
    //
    // AEAD-decrypts the commit.
    {
        let mut bg = c.benchmark_group("breakdown_receiver_unprotect");
        for ((n, members), (_, commit)) in groups.iter().zip(commits.iter()) {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || (members[0].0.clone(), members[0].1.clone(), commit.clone()),
                    |(mut grp, prov, c)| {
                        let unverified = grp
                            .unprotect_message(&prov, c.into_protocol_message().unwrap())
                            .expect("unprotect_message failed");
                        black_box(unverified);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Receiver component 2: process_unverified_message ---
    //
    // Verifies the sender's Ed25519 signature on the commit, then processes
    // the UpdatePath: decrypts the path secret encrypted to this receiver's
    // copath node (HPKE), derives all intermediate node secrets along the
    // direct path, and stages the commit for merging. This is the most
    // expensive receiver-side step.
    //
    // NOTE: This method is `pub(crate)` in upstream OpenMLS. We made it
    // `pub` in our local fork to allow benchmarking it separately.
    {
        let mut bg = c.benchmark_group("breakdown_receiver_verify_stage");
        for ((n, members), (_, commit)) in groups.iter().zip(commits.iter()) {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || {
                        let mut grp = members[0].0.clone();
                        let prov = members[0].1.clone();

                        // unprotect_message runs in setup (not timed)
                        let unverified = grp
                            .unprotect_message(&prov, commit.clone().into_protocol_message().unwrap())
                            .expect("unprotect_message failed");
                        (grp, prov, unverified)
                    },
                    |(grp, prov, unverified)| {
                        let processed = grp
                            .process_unverified_message(
                                &prov,
                                unverified,
                            )
                            .expect("process_unverified_message failed");
                        black_box(processed);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }

    // --- Receiver component 3: merge_staged_commit ---
    //
    // Advances the receiver's group state to the new epoch. 
    //
    // Uses the full process_message() in setup, so that we have a StagedCommit
    // ready for the timed merge.
    {
        let mut bg = c.benchmark_group("breakdown_receiver_merge_staged");
        for ((n, members), (_, commit)) in groups.iter().zip(commits.iter()) {
            bg.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
                b.iter_batched(
                    || {
                        let mut grp = members[0].0.clone();
                        let prov = members[0].1.clone();
                        
                        // process_message in setup (not timed)
                        let processed = grp
                            .process_message(&prov, commit.clone().into_protocol_message().unwrap())
                            .expect("process_message failed");
                        let staged_commit = match processed.into_content() {
                            ProcessedMessageContent::StagedCommitMessage(sc) => *sc,
                            _ => panic!("expected StagedCommitMessage"),
                        };
                        (grp, prov, staged_commit)
                    },
                    |(mut grp, prov, staged_commit)| {
                        grp.merge_staged_commit(&prov, staged_commit)
                            .expect("merge_staged_commit failed");
                        black_box(&grp);
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        bg.finish();
    }
}

criterion_group!(benches, bench_rekey_breakdown);
criterion_main!(benches);
