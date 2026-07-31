//! Integration tests for MLS group creation, Welcome joining, and SRTP
//! key export.
//!
//! These tests exercise the same MLS operations that run over the network
//! in the real client, but pass Welcome messages and group state directly
//! as Rust objects (no Delivery Service or multicast sockets).
//!
//! Run: cargo test --package mls-srtp-core --test mls_group -- --nocapture

use mls_srtp_core::mls::{
    export_srtp_keys, parse_credential_identity, ssrc_from_identity, MlsMember, CIPHERSUITE,
    SRTP_KEY_MATERIAL_LEN,
};

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// Helper: creates a group with the given member identities. The first
/// identity is the creator; the rest join via Welcome.
///
/// Returns a Vec of (MlsGroup, MlsMember) pairs, one per member.
/// Each MlsGroup is the same group seen from that member's local perspective.
fn setup_group(identities: &[&str]) -> Vec<(MlsGroup, MlsMember)> {
    assert!(identities.len() >= 2);

    // creating an MlsMember for each identity: each member gets its own
    // crypto provider, signing key pair, and credential
    let members: Vec<MlsMember> = identities.iter().map(|id| MlsMember::new(id)).collect();

    // building the group config with the ratchet tree extension enabled,
    // so the full tree is included in the Welcome message and joiners can
    // reconstruct the group state without extra fetches from the DS
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // the first member acts as the creator: it initializes a fresh MLS group
    // with its own credential
    let mut creator_group = MlsGroup::new(
        &members[0].provider,
        &members[0].signer,
        &group_config,
        members[0].credential_with_key.clone(),
    )
    .expect("failed to create group");

    // generating a KeyPackage for each joiner
    let joiner_kps: Vec<KeyPackage> = members[1..]
        .iter()
        .map(|m| m.generate_key_package().key_package().clone())
        .collect();

    // adding all joiners in one commit: produces a Commit + Welcome
    let (_commit, welcome, _) = creator_group
        .add_members(&members[0].provider, &members[0].signer, &joiner_kps)
        .expect("add_members failed");

    // merging the pending commit into the creator's own group state so it
    // advances to the new epoch that includes the added members
    creator_group
        .merge_pending_commit(&members[0].provider)
        .expect("merge_pending_commit failed");

    // `add_members` returns the Welcome wrapped in an MlsMessageOut.
    // To pass it to `new_from_welcome`, we need to unwrap it:
    // MlsMessageOut -> MlsMessageIn -> Welcome
    let welcome_in: MlsMessageIn = welcome.into();
    let welcome_msg = welcome_in.into_welcome().expect("expected Welcome");

    // exporting the ratchet tree from the creator: joiners need this to
    // reconstruct the full group state
    let ratchet_tree = creator_group.export_ratchet_tree();

    // each joiner processes the Welcome: `new_from_welcome` decrypts the
    // group secrets using the joiner's private key, then `into_group`
    // produces a usable MlsGroup
    let joiner_groups: Vec<MlsGroup> = members[1..]
        .iter()
        .map(|m| {
            StagedWelcome::new_from_welcome(
                &m.provider,
                group_config.join_config(),
                welcome_msg.clone(),
                Some(ratchet_tree.clone().into()),
            )
            .expect("welcome failed")
            .into_group(&m.provider)
            .expect("into_group failed")
        })
        .collect();

    // reassembling into (group, member) pairs so callers can access each
    // member's group state and crypto provider together
    let mut result = Vec::with_capacity(identities.len());
    let mut members = members.into_iter();
    result.push((creator_group, members.next().unwrap()));
    for group in joiner_groups {
        result.push((group, members.next().unwrap()));
    }
    result
}

// ---------------------------------------------------------------------------
// Group creation and Welcome
//
// These tests verify that MLS group setup works correctly: all members
// end up at the same epoch, see the same group ID, and the group tree
// contains the expected number of members with the correct roles.
// ---------------------------------------------------------------------------

/// After group creation via Welcome, all members share the same epoch,
/// group ID, and member count.
#[test]
fn group_creation_all_members_see_same_group() {
    let ids = ["creator-0:creator", "sender-1:sender", "receiver-2:receiver"];

    // setting up the group
    let group = setup_group(&ids);

    // after the creator adds everyone and each joiner processes the Welcome,
    // all members must be at the same MLS epoch (the epoch advances with
    // each commit, here there is exactly one add-members commit)
    let epoch = group[0].0.epoch();
    for (i, (g, _)) in group.iter().enumerate() {
        assert_eq!(g.epoch(), epoch, "member {i} at wrong epoch");
    }

    // all members must see the same group ID (assigned by the creator when
    // the group is first created; joiners learn it from the Welcome)
    let group_id = group[0].0.group_id().clone();
    for (i, (g, _)) in group.iter().enumerate() {
        assert_eq!(g.group_id(), &group_id, "member {i} has wrong group ID");
    }

    // all members must see 3 members in the ratchet tree (1 creator +
    // 2 joiners added in the single commit)
    for (i, (g, _)) in group.iter().enumerate() {
        assert_eq!(g.members().count(), 3, "member {i} sees wrong member count");
    }

    println!("group ID:    {}", hex::encode(group_id.as_slice()));
    println!("epoch:       {}", epoch.as_u64());
    println!("member count: 3");
}

/// The MLS group tree contains the correct number of senders and receivers
/// based on the identity strings used during group creation.
#[test]
fn group_members_have_correct_roles() {
    let ids = [
        "creator-0:creator",
        "sender-1:sender",
        "sender-2:sender",
        "receiver-3:receiver",
        "receiver-4:receiver",
        "receiver-5:receiver",
    ];
    let group = setup_group(&ids);

    // extracting identities from the MLS group tree and parsing each
    // credential to get the (label, role) pair
    let tree_members: Vec<(String, String)> = group[0]
        .0
        .members()
        .map(|m| {
            let id = String::from_utf8_lossy(m.credential.serialized_content()).to_string();
            let role = parse_credential_identity(&id).1.to_string();
            (id, role)
        })
        .collect();

    // filtering by role to verify the group tree has the expected composition
    let senders: Vec<_> = tree_members
        .iter()
        .filter(|(_, r)| r == "sender")
        .collect();
    let receivers: Vec<_> = tree_members
        .iter()
        .filter(|(_, r)| r == "receiver")
        .collect();

    assert_eq!(senders.len(), 2, "expected 2 senders");
    assert_eq!(receivers.len(), 3, "expected 3 receivers");

    println!("senders:   {:?}", senders.iter().map(|(id, _)| id).collect::<Vec<_>>());
    println!("receivers: {:?}", receivers.iter().map(|(id, _)| id).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// SRTP key export
//
// These tests verify the MLS exporter-based SRTP key derivation: all
// group members must derive identical key material for the same SSRC,
// different SSRCs must produce different keys, and the SSRC derivation
// from identity strings must be deterministic.
// ---------------------------------------------------------------------------

/// Sender and receiver derive identical SRTP key material (master key + salt)
/// when exporting for the same SSRC at the same epoch.
#[test]
fn key_export_sender_receiver_agreement() {
    let ids = ["sender-0:sender", "receiver-1:receiver"];
    let group = setup_group(&ids);

    // deriving the sender's SSRC from its identity string: the SSRC is
    // a deterministic hash of the identity, used as the MLS exporter context
    // to bind key material to a specific sender
    let ssrc = ssrc_from_identity("sender-0:sender");

    // both members export SRTP key material for the sender's SSRC using
    // MLS `export_secret`: the sender does this for its own SSRC, the
    // receiver does it for each sender in the group
    let (km_sender, key_sender, salt_sender) =
        export_srtp_keys(&group[0].0, group[0].1.provider.crypto(), ssrc);
    let (km_receiver, key_receiver, salt_receiver) =
        export_srtp_keys(&group[1].0, group[1].1.provider.crypto(), ssrc);

    // since both members are at the same epoch and use the same exporter
    // context (SSRC), they must derive identical key material
    assert_eq!(km_sender, km_receiver, "key material mismatch");
    assert_eq!(key_sender, key_receiver, "master key mismatch");
    assert_eq!(salt_sender, salt_receiver, "master salt mismatch");

    // the key material must be exactly 28 bytes: 16 bytes master key +
    // 12 bytes master salt (AES-128-GCM parameters per RFC 7714)
    assert_eq!(km_sender.len(), SRTP_KEY_MATERIAL_LEN);

    println!("SSRC:        0x{ssrc:08X}");
    println!("master key:  {}", hex::encode(&key_sender));
    println!("master salt: {}", hex::encode(&salt_sender));
    println!("sender and receiver derive identical keys");
}

/// Two senders with different SSRCs produce different SRTP key material,
/// since the SSRC is used as the MLS exporter context.
#[test]
fn key_export_different_senders_get_different_keys() {
    let ids = ["sender-0:sender", "sender-1:sender", "receiver-2:receiver"];
    let group = setup_group(&ids);

    let ssrc0 = ssrc_from_identity("sender-0:sender");
    let ssrc1 = ssrc_from_identity("sender-1:sender");

    // exporting from the receiver's perspective for two different senders
    let (km0, _, _) = export_srtp_keys(&group[2].0, group[2].1.provider.crypto(), ssrc0);
    let (km1, _, _) = export_srtp_keys(&group[2].0, group[2].1.provider.crypto(), ssrc1);

    // different SSRCs produce different key material because the SSRC is
    // used as the exporter context in `export_secret`
    assert_ne!(km0, km1, "different senders should have different keys");

    println!("sender-0 SSRC=0x{ssrc0:08X}: {}", hex::encode(&km0));
    println!("sender-1 SSRC=0x{ssrc1:08X}: {}", hex::encode(&km1));
}

/// `ssrc_from_identity` is deterministic: same input always produces the
/// same SSRC, different inputs produce different SSRCs.
#[test]
fn ssrc_derived_from_identity_is_deterministic() {
    // the SSRC is derived by hashing the identity string, so the same
    // identity must always produce the same SSRC
    let ssrc1 = ssrc_from_identity("sender-0:sender");
    let ssrc2 = ssrc_from_identity("sender-0:sender");
    let ssrc3 = ssrc_from_identity("receiver-1:receiver");

    assert_eq!(ssrc1, ssrc2, "same identity should produce same SSRC");
    assert_ne!(ssrc1, ssrc3, "different identities should produce different SSRCs");

    println!("sender-0:sender   -> 0x{ssrc1:08X}");
    println!("receiver-1:receiver -> 0x{ssrc3:08X}");
}

/// `parse_credential_identity` correctly splits "label:role" strings
/// into their label and role components.
#[test]
fn credential_identity_parsing() {
    // `parse_credential_identity` splits "label:role" strings
    let (label, role) = parse_credential_identity("sender-48231:sender");
    assert_eq!(label, "sender-48231");
    assert_eq!(role, "sender");

    let (label, role) = parse_credential_identity("receiver-12045:receiver");
    assert_eq!(label, "receiver-12045");
    assert_eq!(role, "receiver");

    let (label, role) = parse_credential_identity("creator-1:creator");
    assert_eq!(label, "creator-1");
    assert_eq!(role, "creator");
}
