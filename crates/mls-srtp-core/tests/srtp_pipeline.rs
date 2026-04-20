//! Integration tests for the full SRTP encrypt/decrypt pipeline.
//!
//! Run: cargo test --package mls-srtp-core --test srtp_pipeline -- --nocapture

use mls_srtp_core::mls::{
    export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE,
};
use mls_srtp_core::rtp::{RtpPacket, RTP_HEADER_LEN};
use mls_srtp_core::srtp_session::{create_receiver_session, create_sender_session};

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// AES-128-GCM authentication tag length (RFC 7714 §8.1).
/// SRTP appends this tag after encryption.
const GCM_TAG_LEN: usize = 16;

/// Sets up a 2-member MLS group (sender + receiver) and exports SRTP
/// key material for the sender's SSRC.
///
/// Returns (key_material, ssrc) ready for creating SRTP sessions.
fn setup_srtp_keys() -> (Vec<u8>, u32) {
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");

    // generating a KeyPackage for the receiver
    let kp = receiver.generate_key_package();

    // building the group config with the ratchet tree extension enabled
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // creating the MLS group as the sender (acts as creator here)
    let mut group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &group_config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create group");

    // adding the receiver in a single commit
    group
        .add_members(
            &sender.provider,
            &sender.signer,
            &[kp.key_package().clone()],
        )
        .expect("add_members failed");

    // merging the pending commit to advance to the new epoch
    group
        .merge_pending_commit(&sender.provider)
        .expect("merge_pending_commit failed");

    // deriving the sender's SSRC from its identity string and exporting
    // SRTP key material using `export_secret`
    let ssrc = ssrc_from_identity("sender-0:sender");
    let (key_material, _, _) = export_srtp_keys(&group, sender.provider.crypto(), ssrc);

    (key_material, ssrc)
}

// ---------------------------------------------------------------------------
// RTP packet round-trip
//
// These tests verify the minimal RTP packet serialization and parsing.
// ---------------------------------------------------------------------------

#[test]
fn rtp_serialize_deserialize_round_trip() {
    // building a minimal RTP packet with the fixed 12-byte header fields
    let pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 42,
        timestamp: 960 * 42,
        ssrc: 0xDEADBEEF,
        payload: b"test payload".to_vec(),
    };

    // serializing to wire format: 12-byte header || payload
    let bytes = pkt.to_bytes();

    // the total length must be exactly header + payload
    assert_eq!(bytes.len(), RTP_HEADER_LEN + pkt.payload.len());

    // the first byte is 0x80 = version 2, no padding, no extension, no CSRCs
    assert_eq!(bytes[0], 0x80);

    // parsing back from wire bytes must recover all fields exactly
    let parsed = RtpPacket::from_bytes(&bytes).expect("parse failed");
    
    assert_eq!(parsed.payload_type, 111);
    assert_eq!(parsed.sequence_number, 42);
    assert_eq!(parsed.timestamp, 960 * 42);
    assert_eq!(parsed.ssrc, 0xDEADBEEF);
    assert_eq!(parsed.payload, b"test payload");
}

#[test]
fn rtp_from_bytes_rejects_short_input() {
    // an RTP packet needs at least 12 bytes for the fixed header;
    // anything shorter must be rejected
    assert!(RtpPacket::from_bytes(&[0u8; 11]).is_none());
    assert!(RtpPacket::from_bytes(&[]).is_none());
}

// ---------------------------------------------------------------------------
// SRTP encrypt/decrypt
//
// These tests exercise the full SRTP pipeline: MLS key export ->
// libsrtp session creation -> protect (encrypt + authenticate) ->
// unprotect (verify + decrypt).
// ---------------------------------------------------------------------------

#[test]
fn srtp_encrypt_decrypt_single_packet() {
    // initializing libsrtp (must be called once before any SRTP operations)
    srtp::ensure_init();
    let (key_material, ssrc) = setup_srtp_keys();

    // creating a sender session (outbound, for encryption) and a receiver
    // session (inbound, for decryption), both keyed with the same
    // MLS-exported master key + salt
    let mut sender_session = create_sender_session(&key_material);
    let mut receiver_session = create_receiver_session(&key_material);

    // building a dummy RTP packet simulating an audio frame
    let payload = b"Hello from sender";

    let pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 1,
        timestamp: 960,
        ssrc,
        payload: payload.to_vec(),
    };

    // serializing to raw RTP bytes, then encrypting with SRTP
    let rtp_bytes = pkt.to_bytes();
    let mut buf = rtp_bytes.clone();
    sender_session.protect(&mut buf).expect("protect failed");

    // after encryption, the buffer grows by the GCM authentication tag
    // (16 bytes for AES-128-GCM per RFC 7714)
    assert_eq!(buf.len(), rtp_bytes.len() + GCM_TAG_LEN);
    // the payload portion must be different from plaintext (encrypted)
    assert_ne!(&buf[RTP_HEADER_LEN..], &rtp_bytes[RTP_HEADER_LEN..]);

    println!(
        "RTP {} bytes -> SRTP {} bytes (+{} overhead)",
        rtp_bytes.len(),
        buf.len(),
        buf.len() - rtp_bytes.len()
    );

    // decrypting the SRTP packet: verifies the GCM tag and
    // recovers the original RTP payload
    receiver_session
        .unprotect(&mut buf)
        .expect("unprotect failed");
    let decrypted = RtpPacket::from_bytes(&buf).expect("RTP parse failed");

    // the decrypted packet must match the original exactly
    assert_eq!(decrypted.payload_type, 111);
    assert_eq!(decrypted.sequence_number, 1);
    assert_eq!(decrypted.ssrc, ssrc);
    assert_eq!(&decrypted.payload, payload);

    println!("payload matches: {:?}", String::from_utf8_lossy(payload));
}

#[test]
fn srtp_encrypt_decrypt_multiple_packets() {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_srtp_keys();

    let mut sender_session = create_sender_session(&key_material);
    let mut receiver_session = create_receiver_session(&key_material);

    // sending 10 packets in sequence, encrypting and decrypting each
    for seq in 1..=10u16 {
        let pkt = RtpPacket {
            payload_type: 111,
            sequence_number: seq,
            timestamp: seq as u32 * 960,
            ssrc,
            payload: format!("frame {seq}").into_bytes(),
        };

        let mut buf = pkt.to_bytes();

        // libsrtp internally tracks the SRTP packet index (ROC || SEQ)
        // for each session, so sequential packets are processed correctly
        sender_session.protect(&mut buf).expect("protect failed");
        receiver_session
            .unprotect(&mut buf)
            .expect("unprotect failed");

        let decrypted = RtpPacket::from_bytes(&buf).unwrap();
        assert_eq!(decrypted.sequence_number, seq);
        assert_eq!(decrypted.payload, format!("frame {seq}").into_bytes());
    }

    println!("10 packets encrypted and decrypted successfully");
}

#[test]
fn srtp_wrong_key_fails_decryption() {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_srtp_keys();

    let mut sender_session = create_sender_session(&key_material);

    let pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 1,
        timestamp: 960,
        ssrc,
        payload: b"secret".to_vec(),
    };
    let mut buf = pkt.to_bytes();
    sender_session.protect(&mut buf).expect("protect failed");

    // creating a receiver session with different (wrong) key material:
    // this simulates an attacker or misconfigured peer trying to decrypt
    // with the wrong key
    let wrong_key = vec![0xFFu8; key_material.len()];
    let mut wrong_session = create_receiver_session(&wrong_key);

    // decryption must fail because the GCM authentication tag won't verify
    // with the wrong key
    assert!(
        wrong_session.unprotect(&mut buf).is_err(),
        "decryption with wrong key should fail"
    );

    println!("decryption with wrong key correctly rejected");
}

#[test]
fn srtp_replay_protection_rejects_duplicate() {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_srtp_keys();

    let mut sender_session = create_sender_session(&key_material);
    let mut receiver_session = create_receiver_session(&key_material);

    let pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 1,
        timestamp: 960,
        ssrc,
        payload: b"once".to_vec(),
    };
    let mut buf = pkt.to_bytes();
    sender_session.protect(&mut buf).expect("protect failed");

    // first decryption succeeds: libsrtp records this sequence number
    // in its replay window (configured to 128 packets in srtp_session.rs)
    let mut buf1 = buf.clone();
    receiver_session
        .unprotect(&mut buf1)
        .expect("first unprotect should succeed");

    // replaying the exact same packet must be rejected: libsrtp's replay
    // protection window (RFC 3711 §3.3.2) detects that sequence number 1
    // was already received and refuses to decrypt it again
    let mut buf2 = buf.clone();
    assert!(
        receiver_session.unprotect(&mut buf2).is_err(),
        "replayed packet should be rejected"
    );

    println!("replay protection correctly rejected duplicate packet");
}
