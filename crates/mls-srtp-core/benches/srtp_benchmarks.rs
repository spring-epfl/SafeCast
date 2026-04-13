//! Criterion benchmarks for MLS-SRTP encryption, decryption, and key export.
//!
//! Run: cargo bench --package mls-srtp-core --bench srtp_benchmarks
//! Output: HTML reports are written to `target/criterion/`
//!
//! Benchmarks:
//!   1. SRTP encryption (protect) across varying RTP payload sizes
//!   2. SRTP decryption (unprotect) across varying RTP payload sizes
//!   3. MLS exporter key derivation
//!
//! Note on packet encryption overhead: SRTP with AES-128-GCM adds a constant 16-byte
//! authentication tag to every packet, regardless of payload size. This is
//! inherent to the GCM AEAD construction and requires no benchmarking.
//! QUESTION: ^ ok?

// `black_box` is a compiler hint that prevents the optimizer from eliminating
// code whose result is "unused" from the compiler's perspective. Without it,
// the compiler could skip the encrypt/decrypt calls since we never
// actually send the result anywhere.
use std::hint::black_box;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use mls_srtp_core::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use mls_srtp_core::rtp::{RtpPacket, RTP_HEADER_LEN};
use mls_srtp_core::srtp_session::{create_receiver_session, create_sender_session};

/// AES-128-GCM authentication tag length in bytes
const GCM_TAG_LEN: usize = 16;

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// Payload sizes representing realistic RTP payloads.
///
/// Audio sizes are based on Opus codes with the default 20 ms packetization interval
/// (RFC 3551: "For packetized audio, the default packetization interval SHOULD
/// have a duration of 20 ms"). Bitrates follow the "sweet spots" from RFC 7587
/// §3.1.1.
///
/// Video sizes represent H.264 FU-A (Fragmentation Unit) fragments that fit
/// within the common 1500-byte Ethernet MTU (RFC 8088 §3.5.1: "the most common
/// IP Maximum Transmission Unit (MTU) in commonly deployed link layers is 1500
/// bytes"). After IP (20 B), UDP (8 B), and RTP (12 B) headers, the maximum
/// RTP payload is ~1460 bytes. Real encoders typically target smaller fragments
/// to leave headroom.
const PAYLOAD_SIZES: &[(usize, &str)] = &[
    // Opus 20 ms @ 16 kbit/s (16000 * 0.020 / 8 = 40 B)
    (40, "audio_speech_40B"),
    // Opus 20 ms @ 64 kbit/s (64000 * 0.020 / 8 = 160 B)
    (160, "audio_music_160B"),
    // H.264 FU-A fragment
    (800, "video_fragment_800B"),
    // H.264 FU-A fragment
    (1200, "video_fragment_1200B"),
    // ST 2110-10 standard (1460 − 8 UDP − 12 RTP − 16 GCM tag)
    (1424, "st2110_standard_1424B"),
    // ST 2110-10 extended/jumbo (8960 − 8 UDP − 12 RTP − 16 GCM tag)
    (8924, "st2110_jumbo_8924B"),
];

/// Sets up a minimal 2-member MLS group and exports SRTP key material for the
/// sender. Returns the group (needed for key-export benchmarks), the sender
/// member (holds the crypto provider), and the 28-byte key material
/// (master_key || master_salt) ready for libsrtp.
fn setup_mls_group() -> (MlsGroup, MlsMember, Vec<u8>) {

    // creating two MLS members: one sender and one receiver
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");

    // generating a KeyPackage for the receiver so the sender can add it
    let receiver_kp = receiver.generate_key_package();

    // configuring the group with the ratchet tree extension so that the full
    // tree is embedded in Welcome messages (not relevant for benchmarking,
    // but required to form a valid group)
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // creating the MLS group with the sender as the initial member
    let mut group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &group_config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    // adding the receiver and advancing to the next epoch
    group
        .add_members(
            &sender.provider,
            &sender.signer,
            &[receiver_kp.key_package().clone()],
        )
        .expect("failed to add receiver");

    // merging the pending commit so the group state reflects both members
    group
        .merge_pending_commit(&sender.provider)
        .expect("failed to merge commit");

    // deriving a deterministic SSRC from the sender identity and exporting
    // the SRTP key material via the MLS exporter
    let ssrc = ssrc_from_identity("sender-0:sender");
    let (key_material, _, _) =
        export_srtp_keys(&group, sender.provider.crypto(), ssrc);

    (group, sender, key_material)
}

/// Creates a dummy RTP packet with a payload of the given size filled with
/// 0xAB bytes. The payload content does not affect AES-GCM performance,
/// so synthetic data is equivalent to real audio/video frames.
/// QUESTION: ^ ok?
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

// ---------------------------------------------------------------------------
// Benchmark 1: SRTP Encryption
// ---------------------------------------------------------------------------

/// Benchmarks SRTP encryption (protect) for each payload size. Measures the
/// full sender-side cost: RTP packet construction, serialization, and
/// encryption via libsrtp.
fn bench_srtp_encrypt(c: &mut Criterion) {

    // initializing libsrtp
    srtp::ensure_init();

    // setting up the MLS group and exporting key material (done once,
    // outside the timed loop)
    let (_group, _sender, key_material) = setup_mls_group();
    let ssrc = ssrc_from_identity("sender-0:sender");

    let mut group = c.benchmark_group("srtp_encrypt");

    for &(size, label) in PAYLOAD_SIZES {

        // telling criterion how many bytes each iteration processes, so it
        // can compute throughput (bytes/sec) in addition to raw latency
        let rtp_len = RTP_HEADER_LEN + size;
        group.throughput(Throughput::Bytes(rtp_len as u64));

        group.bench_with_input(BenchmarkId::new("protect", label), &size, |b, &sz| {

            // Creating the SRTP session outside the timed loop (session
            // creation is a one-time setup cost, not a per-packet cost).
            // Sequence numbers must be unique within a session, so we
            // increment on each iteration.
            let mut session = create_sender_session(&key_material);
            let mut seq: u16 = 0;

            // QUESTION: This loop contains RTP packet construction + serialization
            // on top of the actual protect() call. I kept it this way because I
            // assume a real sender always constructs the packet before encrypting,
            // so this measures the true end-to-end sender cost. Should we also add a
            // separate "raw protect()-only" benchmark, or is this ok?
            b.iter(|| {

                // incrementing the sequence number for each packet
                seq = seq.wrapping_add(1);

                // constructing a dummy RTP packet with the target payload size
                let pkt = make_rtp_packet(sz, seq, ssrc);

                // serializing to wire format (12-byte header || payload)
                let mut buf = pkt.to_bytes();

                // encrypting
                session.protect(&mut buf).expect("protect failed");

                black_box(&buf);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 2: SRTP Decryption
// ---------------------------------------------------------------------------

/// Benchmarks SRTP decryption (unprotect) for each payload size. Pre-encrypts
/// a large batch of packets, then measures the per-packet decryption cost.
fn bench_srtp_decrypt(c: &mut Criterion) {

    // initializing libsrtp
    srtp::ensure_init();

    // setting up the MLS group and exporting key material
    let (_group, _sender, key_material) = setup_mls_group();
    let ssrc = ssrc_from_identity("sender-0:sender");

    let mut group = c.benchmark_group("srtp_decrypt");

    for &(size, label) in PAYLOAD_SIZES {

        // telling criterion how many bytes each iteration processes
        // (using ciphertext size: header + payload + 16-byte GCM auth tag)
        let srtp_len = RTP_HEADER_LEN + size + GCM_TAG_LEN;
        group.throughput(Throughput::Bytes(srtp_len as u64));

        group.bench_with_input(BenchmarkId::new("unprotect", label), &size, |b, &sz| {

            // Pre-encrypting a large batch of packets. Each SRTP packet can
            // only be decrypted once (replay protection rejects duplicates),
            // so we prepare enough up front. If criterion's iteration count
            // exceeds the batch size, we create a fresh sender/receiver
            // session pair and encrypt a new batch.
            let batch_size: u16 = 50_000;

            // Helper that produces a fresh batch of encrypted packets and a
            // matching receiver session. Called once at setup, and again if
            // criterion's iteration count exceeds the batch size.
            let make_batch = |key_material: &[u8]| -> (Vec<Vec<u8>>, srtp::Session) {

                // creating a temporary sender session just for encrypting
                // the batch
                let mut sender_session = create_sender_session(key_material);

                // encrypting `batch_size` packets with incrementing sequence
                // numbers (1..=50000) and collecting the ciphertext buffers
                let encrypted: Vec<Vec<u8>> = (1..=batch_size)
                    .map(|seq| {
                        let pkt = make_rtp_packet(sz, seq, ssrc);
                        let mut buf = pkt.to_bytes();
                        sender_session.protect(&mut buf).expect("protect failed");
                        buf
                    })
                    .collect();

                // creating the receiver session keyed with the same material
                // so it can decrypt the packets produced above
                let receiver_session = create_receiver_session(key_material);
                (encrypted, receiver_session)
            };

            // preparing the initial batch
            let (mut encrypted, mut receiver_session) = make_batch(&key_material);
            let mut idx = 0usize;

            // Note: when the batch is exhausted, one iteration pays the cost
            // of re-encrypting 50,000 packets. This affects <0.002% of
            // iterations (1 in 50,000) and criterion's outlier detection
            // filters these
            // TODO: maybe fix this (using iter_batched?)
            b.iter(|| {

                // recreating the batch if we have exhausted all pre-encrypted
                // packets
                if idx >= encrypted.len() {
                    let (e, r) = make_batch(&key_material);
                    encrypted = e;
                    receiver_session = r;
                    idx = 0;
                }

                // decrypting: libsrtp verifies the 16-byte GCM auth
                // tag, checks the replay window, and decrypts the payload
                receiver_session
                    .unprotect(&mut encrypted[idx])
                    .expect("unprotect failed");
                black_box(&encrypted[idx]);
                idx += 1;
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 3: MLS Key Export
// ---------------------------------------------------------------------------

/// Benchmarks the MLS exporter key derivation: two calls to `export_secret`
/// (one for the 16-byte master key, one for the 12-byte master salt). This
/// operation happens once per MLS epoch change (i.e., when group membership
/// changes), not per packet.
fn bench_mls_key_export(c: &mut Criterion) {

    // setting up the MLS group (the group state is what we export keys from)
    let (group, sender, _key_material) = setup_mls_group();
    let ssrc = ssrc_from_identity("sender-0:sender");

    c.bench_function("mls_key_export", |b| {
        b.iter(|| {

            // exporting SRTP key material: derives master_key (16 B) and
            // master_salt (12 B) from the MLS exporter secret using
            // HKDF-based key derivation
            let (km, _key, _salt) = export_srtp_keys(
                black_box(&group),
                sender.provider.crypto(),
                black_box(ssrc),
            );
            black_box(&km);
        });
    });
}

// registering all benchmark functions as a single group so criterion
// runs them sequentially in one invocation
criterion_group!(
    benches,
    bench_srtp_encrypt,
    bench_srtp_decrypt,
    bench_mls_key_export,
);

// the main() entry point
criterion_main!(benches);