//! SRTP replay-rejection benchmark: how fast libsrtp rejects a duplicate
//! packet.
//!
//! SRTP maintains a replay window (RFC 3711 §3.3.2) that tracks recently
//! seen sequence numbers. When a duplicate arrives, it is rejected before
//! any decryption happens. This benchmark measures the cost of that
//! rejection path.
//!
//! Measurement design: the `srtp` crate empties the buffer on any failed
//! `unprotect` (its error path calls `buf.set_len(0)`), so a rejected
//! buffer cannot simply be fed in again. The second attempt would measure
//! "reject a zero-length buffer", not a replay rejection 
//! (https://github.com/cisco/libsrtp/blob/6e23ad8d971209e152ef4aa5349be9969e108d14/srtp/srtp.c#L313). 
//! An earlier version of this benchmark had exactly that bug and reported ~4 ns.
//! Hence `iter_batched`: every iteration gets a fresh clone of the
//! ciphertext as untimed setup, and only the rejecting `unprotect` call is
//! timed.
//!
//! The rejection happens at the replay-window check, so the cost should be
//! roughly constant regardless of payload size. We parameterize by size
//! anyway to confirm this.
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench replay_protection

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use mls_srtp_core::keying::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use mls_srtp_core::transport::rtp::RtpPacket;
use mls_srtp_core::transport::srtp_session::{create_receiver_session, create_sender_session};

use openmls::prelude::*;

/// Payload sizes: Opus audio at 20 ms packetization,
/// H.264 FU-A fragments, and the two ST 2110-10 MTU-derived sizes.
const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (40, "audio_speech_40B"),
    (160, "audio_music_160B"),
    (800, "video_fragment_800B"),
    (1200, "video_fragment_1200B"),
    (1424, "st2110_standard_1424B"),
    (8924, "st2110_jumbo_8924B"),
];

/// Builds a 2-member MLS group and exports SRTP key material for the sender.
/// Returns `(key_material, ssrc)`. Runs once, outside any timed loop.
fn setup_mls_group() -> (Vec<u8>, u32) {
    // two MLS members: a sender and a receiver, so the group is non-trivial
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");
    let receiver_kp = receiver.generate_key_package();

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // sender creates the group
    let mut group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &group_config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    // adding the receiver (produces a commit), then advancing the epoch
    group
        .add_members(
            &sender.provider,
            &sender.signer,
            &[receiver_kp.key_package().clone()],
        )
        .expect("failed to add receiver");
    group
        .merge_pending_commit(&sender.provider)
        .expect("failed to merge commit");

    // SSRC from the sender identity, SRTP key material via the MLS exporter
    let ssrc = ssrc_from_identity("sender-0:sender");
    let (key_material, _, _) = export_srtp_keys(&group, sender.provider.crypto(), ssrc);
    (key_material, ssrc)
}

/// Builds a dummy RTP packet with a payload of `payload_size` 0xAB bytes.
/// The payload content does not affect performance; only its length matters.
fn make_rtp_packet(payload_size: usize, seq: u16, ssrc: u32) -> RtpPacket {
    RtpPacket {
        payload_type: 111,
        sequence_number: seq,
        // 960 samples per frame at 48 kHz = 20 ms per frame
        timestamp: seq as u32 * 960,
        ssrc,
        payload: vec![0xAB; payload_size],
    }
}

/// Benchmarks the replay-rejection path for each payload size.
fn bench_replay_protection(c: &mut Criterion) {
    // libsrtp's one-time global init
    srtp::ensure_init();

    // MLS group setup and key export, once, untimed
    let (key_material, ssrc) = setup_mls_group();

    let mut group = c.benchmark_group("srtp_replay_protection");

    for &(size, label) in PAYLOAD_SIZES {
        group.bench_with_input(BenchmarkId::new("reject_replay", label), &size, |b, &sz| {
            let mut sender_session = create_sender_session(&key_material);
            let mut receiver_session = create_receiver_session(&key_material);

            // encrypting a single packet (seq 1)
            let pkt = make_rtp_packet(sz, 1, ssrc);
            let mut buf = pkt.to_bytes();
            sender_session.protect(&mut buf).expect("protect failed");
            let encrypted = buf;

            // decrypting it once so seq 1 enters the replay window
            let mut first = encrypted.clone();
            receiver_session
                .unprotect(&mut first)
                .expect("first unprotect should succeed");

            // every iteration: fresh clone (untimed setup), then the timed
            // rejecting unprotect. The clone is returned so its drop is
            // untimed too (that's how Criterion works). See the module doc
            // for why a fresh clone is required on every iteration.
            b.iter_batched(
                || encrypted.clone(),
                |mut replay_buf| {
                    let result = receiver_session.unprotect(&mut replay_buf);
                    debug_assert!(result.is_err(), "replay must be rejected");
                    black_box(&result);
                    replay_buf
                },
                BatchSize::NumIterations(256),
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_replay_protection);
criterion_main!(benches);
