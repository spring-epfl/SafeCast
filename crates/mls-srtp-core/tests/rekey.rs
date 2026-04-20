//! Integration test for the MLS rekey flow: verifying that a self-update
//! commit rotates SRTP keys for all group members.
//!
//! In MLS, rekeying is done via a self-update commit (RFC 9420 §12.1.2):
//! the committer generates a fresh leaf node with new key material,
//! encrypts path secrets up the tree, and all members advance to a new
//! epoch with fresh group secrets. Since SRTP keys are derived from the
//! epoch secret via `export_secret`, a new epoch means new SRTP keys.
//!
//! These tests verify the full rekey pipeline in-process: create a group,
//! perform a rekey commit, and confirm that (1) all members derive the
//! same fresh keys and (2) the new keys work for SRTP encryption.
//!
//! Run: cargo test --package mls-srtp-core --test rekey -- --nocapture

use mls_srtp_core::mls::{
    create_rekey_commit, export_srtp_keys, process_commit, ssrc_from_identity, MlsMember,
    CIPHERSUITE,
};
use mls_srtp_core::rtp::RtpPacket;
use mls_srtp_core::srtp_session::{create_receiver_session, create_sender_session};

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// Sets up a 3-member group (sender + 2 receivers) and returns each
/// member's (MlsGroup, MlsMember) pair.
///
/// Hardcoded for the 3-member rekey scenario.
fn setup_group() -> Vec<(MlsGroup, MlsMember)> {
    let identities = ["sender-0:sender", "receiver-1:receiver", "receiver-2:receiver"];

    // creating an MlsMember for each identity: each gets its own crypto
    // provider, signing key pair, and credential
    let members: Vec<MlsMember> = identities.iter().map(|id| MlsMember::new(id)).collect();

    // building the group config with the ratchet tree extension enabled
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // the sender (member 0) creates the group
    let mut sender_group = MlsGroup::new(
        &members[0].provider,
        &members[0].signer,
        &group_config,
        members[0].credential_with_key.clone(),
    )
    .expect("failed to create group");

    // generating KeyPackages for both receivers
    let kp1 = members[1].generate_key_package();
    let kp2 = members[2].generate_key_package();

    // adding both receivers in a single commit
    let (_add_commit, welcome, _) = sender_group
        .add_members(
            &members[0].provider,
            &members[0].signer,
            &[
                kp1.key_package().clone(),
                kp2.key_package().clone(),
            ],
        )
        .expect("add_members failed");

    // merging the pending commit to advance the sender's group state to
    // the new epoch that includes the receivers
    sender_group
        .merge_pending_commit(&members[0].provider)
        .expect("merge_pending_commit failed");

    // `add_members` returns the Welcome wrapped in an MlsMessageOut.
    // To pass it to `new_from_welcome`, we need to unwrap it:
    // MlsMessageOut -> MlsMessageIn -> Welcome
    let welcome_in: MlsMessageIn = welcome.into();
    let welcome_msg = welcome_in.into_welcome().expect("expected Welcome");
    let ratchet_tree = sender_group.export_ratchet_tree();

    // receiver 1 joins by processing the Welcome: decrypts group secrets
    // using its private key and reconstructs the group state
    let recv1_group = StagedWelcome::new_from_welcome(
        &members[1].provider,
        group_config.join_config(),
        welcome_msg.clone(),
        Some(ratchet_tree.clone().into()),
    )
    .expect("receiver 1 welcome failed")
    .into_group(&members[1].provider)
    .expect("receiver 1 into_group failed");

    // receiver 2 joins the same way
    let recv2_group = StagedWelcome::new_from_welcome(
        &members[2].provider,
        group_config.join_config(),
        welcome_msg,
        Some(ratchet_tree.into()),
    )
    .expect("receiver 2 welcome failed")
    .into_group(&members[2].provider)
    .expect("receiver 2 into_group failed");

    // assembling (group, member) pairs for each participant
    let mut members = members.into_iter();
    vec![
        (sender_group, members.next().unwrap()),
        (recv1_group, members.next().unwrap()),
        (recv2_group, members.next().unwrap()),
    ]
}

// ---------------------------------------------------------------------------
// Rekey: key rotation
//
// Verifies that a self-update commit (rekey) causes all group members to
// derive fresh SRTP keys. The sender creates a rekey commit, each receiver
// processes it, and we confirm:
//   1. All members agree on keys before and after the rekey
//   2. The post-rekey keys are different from the pre-rekey keys
// ---------------------------------------------------------------------------

#[test]
fn rekey_rotates_srtp_keys() {
    let mut group = setup_group();

    // deriving the sender's SSRC: used as the MLS exporter context so
    // all members export the same key material for this sender
    let sender_ssrc = ssrc_from_identity("sender-0:sender");

    // --- Epoch 1: export initial SRTP keys ---

    // all members export SRTP key material for the sender's SSRC at the
    // current epoch
    let initial_keys: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = group
        .iter()
        .map(|(g, m)| export_srtp_keys(g, m.provider.crypto(), sender_ssrc))
        .collect();

    let (ref init_km, ref init_key, ref init_salt) = initial_keys[0];
    println!("=== Epoch {} (initial) ===", group[0].0.epoch().as_u64());
    println!("  master key:  {}", hex::encode(init_key));
    println!("  master salt: {}", hex::encode(init_salt));

    // all members must derive the same key material for the same SSRC
    // at the same epoch
    for (i, (km, _, _)) in initial_keys.iter().enumerate() {
        assert_eq!(km, init_km, "member {i} has different initial key material");
    }
    println!("  all 3 members agree on key material");

    // --- Sender creates a rekey commit ---

    // the sender performs a self-update: generates a fresh leaf node,
    // encrypts new path secrets up the tree, and stages the commit.
    // `create_rekey_commit` calls `self_update` + `merge_pending_commit`
    // internally (see mls.rs) —> the sender advances to the new epoch.
    let commit = {
        let (ref mut sender_group, ref sender_member) = group[0];
        create_rekey_commit(sender_group, &sender_member.provider, &sender_member.signer)
    };

    println!("\n--- sender created rekey commit ---\n");

    // --- Both receivers process the commit ---

    // each receiver processes the commit to advance to the same new epoch.
    // `process_commit` calls `process_message` (which stages the commit by
    // decrypting the path secret from the sender's UpdatePath) followed by
    // `merge_staged_commit` (which finalizes the epoch transition)
    for i in 1..group.len() {
        let (ref mut recv_group, ref recv_member) = group[i];
        process_commit(recv_group, &recv_member.provider, commit.clone());
    }

    // --- Epoch 2: export new SRTP keys ---

    // all members export SRTP key material again: now at the new epoch,
    // the exporter derives from the new epoch secret, producing fresh keys
    let new_keys: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = group
        .iter()
        .map(|(g, m)| export_srtp_keys(g, m.provider.crypto(), sender_ssrc))
        .collect();

    let (ref new_km, ref new_key, ref new_salt) = new_keys[0];
    println!("=== Epoch {} (after rekey) ===", group[0].0.epoch().as_u64());
    println!("  master key:  {}", hex::encode(new_key));
    println!("  master salt: {}", hex::encode(new_salt));

    // all members must still agree on the key material after the rekey
    for (i, (km, _, _)) in new_keys.iter().enumerate() {
        assert_eq!(km, new_km, "member {i} has different new key material");
    }
    println!("  all 3 members agree on key material");

    // the keys must actually be different from the previous epoch:
    // this confirms that the rekey commit rotated the group secrets
    assert_ne!(init_km, new_km, "keys did not change after rekey");
    println!("\n  keys differ from previous epoch");
}

// ---------------------------------------------------------------------------
// Rekey: end-to-end SRTP pipeline
//
// Verifies that after a rekey commit, the freshly derived SRTP keys
// actually work for encryption and decryption. This is the full pipeline:
// rekey -> export new keys -> create SRTP sessions -> encrypt -> decrypt.
// ---------------------------------------------------------------------------

#[test]
fn rekey_produces_working_srtp_sessions() {
    let mut group = setup_group();
    let sender_ssrc = ssrc_from_identity("sender-0:sender");

    // --- Rekey: sender commits, receivers process ---

    let commit = {
        let (ref mut g, ref m) = group[0];
        create_rekey_commit(g, &m.provider, &m.signer)
    };
    for i in 1..group.len() {
        let (ref mut g, ref m) = group[i];
        process_commit(g, &m.provider, commit.clone());
    }

    // --- Exporting fresh SRTP keys from the new epoch ---

    // both sender and receiver export key material for the sender's SSRC
    // at the new epoch: they must agree (same exporter context + epoch)
    let (sender_km, _, _) =
        export_srtp_keys(&group[0].0, group[0].1.provider.crypto(), sender_ssrc);
    let (recv_km, _, _) =
        export_srtp_keys(&group[1].0, group[1].1.provider.crypto(), sender_ssrc);
    assert_eq!(sender_km, recv_km);

    // --- Creating SRTP sessions and encrypting/decrypting a packet ---

    // initializing libsrtp and creating sessions with the post-rekey keys
    srtp::ensure_init();
    let mut sender_session = create_sender_session(&sender_km);
    let mut receiver_session = create_receiver_session(&recv_km);

    // building a dummy RTP packet
    let original_payload = b"hello after rekey";
    let pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 1,
        timestamp: 960,
        ssrc: sender_ssrc,
        payload: original_payload.to_vec(),
    };

    // encrypting with the sender's SRTP session: `protect` encrypts
    // and appends the GCM authentication tag
    let mut buf = pkt.to_bytes();
    let plaintext_len = buf.len();
    sender_session.protect(&mut buf).expect("protect failed");
    assert_ne!(&buf[12..], original_payload, "payload should be encrypted");
    println!("encrypted: {} bytes -> {} bytes", plaintext_len, buf.len());

    // decrypting with the receiver's SRTP session: `unprotect` verifies
    // the GCM tag and decrypts
    receiver_session
        .unprotect(&mut buf)
        .expect("unprotect failed");
    let decrypted = RtpPacket::from_bytes(&buf).expect("RTP parse failed");

    // the decrypted payload must match the original
    assert_eq!(&decrypted.payload, original_payload);
    println!("decrypted payload matches original");
}
