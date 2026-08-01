//! Validation for the in-place rekey added to our libsrtp fork, reached through
//! `srtp::Session::inplace_rekey`.
//!
//! `srtp_inplace_rekey` installs a new AES-128-GCM session key and salt straight
//! into the existing cipher, skipping the master-to-session KDF and the stream
//! rebuild that default `srtp_update` does. 
//! These two tests pin down that it does exactly that and no more:
//!   1. the encryption is byte-for-byte standard AES-GCM (the per-packet path is
//!      unchanged), and
//!   2. the replay database survives the rekey (which `srtp_update` would break).

use mls_srtp_core::transport::rtp::{RtpPacket, RTP_HEADER_LEN};
use openssl::symm::{encrypt_aead, Cipher};
use srtp::{CryptoPolicy, Error, Session, StreamPolicy};

const SSRC: u32 = 0xDEAD_BEEF;
/// AES-128 session key length.
const KEY_LEN: usize = 16;
/// AEAD session salt length.
const SALT_LEN: usize = 12;
/// libsrtp master key material: key || salt (28 bytes for AES-128-GCM).
const MASTER_LEN: usize = KEY_LEN + SALT_LEN;

/// Creates a session with one specific-SSRC AES-128-GCM stream, seeded from 28
/// bytes of master material. The stream can then be rekeyed in place by SSRC.
fn session_for(ssrc: u32, master: &[u8; MASTER_LEN]) -> Session {
    srtp::ensure_init();
    let mut session = Session::new().expect("srtp_create failed");
    let policy = StreamPolicy {
        rtp: CryptoPolicy::aes_gcm_128_16_auth(),
        rtcp: CryptoPolicy::aes_gcm_128_16_auth(),
        key: master,
        // matching srtp_session.rs (RFC 3711 §3.3.2)
        window_size: 128,
        ..Default::default()
    };
    session.add_stream(ssrc, policy).expect("add_stream failed");
    session
}

/// Builds the RFC 7714 §8.1 GCM IV for the first ROC (=0): the 12-byte block
/// (00 00 || SSRC || ROC || SEQ) XOR the session salt.
fn srtp_gcm_iv(ssrc: u32, roc: u32, seq: u16, salt: &[u8; SALT_LEN]) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[6..10].copy_from_slice(&roc.to_be_bytes());
    iv[10..12].copy_from_slice(&seq.to_be_bytes());
    for (b, s) in iv.iter_mut().zip(salt.iter()) {
        *b ^= s;
    }
    iv
}

fn sample_packet(seq: u16) -> Vec<u8> {
    RtpPacket {
        payload_type: 96,
        sequence_number: seq,
        timestamp: 160_000,
        ssrc: SSRC,
        payload: (0u8..64).collect(),
    }
    .to_bytes()
}

/// After an in-place rekey, `protect` must produce exactly what an independent
/// AES-128-GCM encryption with the same session key+salt and the RFC 7714 IV
/// produces. This pins the cipher rekey and salt install down to the byte.
#[test]
fn inplace_rekey_protect_is_byte_exact() {
    let key = [0x11u8; KEY_LEN];
    let salt = [0x22u8; SALT_LEN];

    // seeding with an arbitrary master, then rekeying to the known session key
    let mut sender = session_for(SSRC, &[0x99u8; MASTER_LEN]);
    sender.inplace_rekey(SSRC, &key, &salt).unwrap();

    let seq = 1000u16;
    let pkt = sample_packet(seq);
    let mut buf = pkt.clone();
    sender.protect(&mut buf).expect("protect failed");

    // independent reference: AES-128-GCM over the payload, header as AAD
    let header = &pkt[..RTP_HEADER_LEN];
    let payload = &pkt[RTP_HEADER_LEN..];
    let iv = srtp_gcm_iv(SSRC, 0, seq, &salt);
    let mut tag = [0u8; 16];
    let ciphertext =
        encrypt_aead(Cipher::aes_128_gcm(), &key, Some(&iv), header, payload, &mut tag).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(header);
    expected.extend_from_slice(&ciphertext);
    expected.extend_from_slice(&tag);

    assert_eq!(buf, expected, "protect output must match independent AES-GCM");
}

/// The replay database must survive an
/// in-place rekey: a packet at an already-seen index is rejected as a replay
/// even after the key changed.
#[test]
fn inplace_rekey_preserves_replay_db() {
    let k0 = [0x01u8; KEY_LEN];
    let s0 = [0x02u8; SALT_LEN];
    let k1 = [0x03u8; KEY_LEN];
    let s1 = [0x04u8; SALT_LEN];

    let mut receiver = session_for(SSRC, &[0xAAu8; MASTER_LEN]);
    receiver.inplace_rekey(SSRC, &k0, &s0).unwrap();

    // generation 0: sender and receiver share k0/s0; seq 100 is accepted
    let mut snd0 = session_for(SSRC, &[0xBBu8; MASTER_LEN]);
    snd0.inplace_rekey(SSRC, &k0, &s0).unwrap();
    let mut p100 = sample_packet(100);
    snd0.protect(&mut p100).unwrap();
    receiver.unprotect(&mut p100).expect("first packet must decrypt");

    // both ends rekey to generation 1 in place
    receiver.inplace_rekey(SSRC, &k1, &s1).unwrap();
    let mut snd1 = session_for(SSRC, &[0xCCu8; MASTER_LEN]);
    snd1.inplace_rekey(SSRC, &k1, &s1).unwrap();

    // a fresh, validly k1-encrypted packet at the already-seen seq 100 must be
    // rejected as a replay: the bitmask carried across the rekey
    let mut p100_again = sample_packet(100);
    snd1.protect(&mut p100_again).unwrap();
    let err = receiver
        .unprotect(&mut p100_again)
        .expect_err("replayed index must be rejected after rekey");
    assert!(
        err == Error::REPLAY_FAIL || err == Error::REPLAY_OLD,
        "expected a replay error, got {err:?}"
    );

    // a new index under the new key still works
    let mut p101 = sample_packet(101);
    snd1.protect(&mut p101).unwrap();
    receiver.unprotect(&mut p101).expect("new index under new key must decrypt");
}
