//! Data-plane throughput of the three keying granularities,
//! under ideal delivery. Ideal means: no loss, no reordering, and no jitter. Packets are
//! processed in send order. This isolates the pure
//! crypto + rekey cost (the minimum a receiver can ever pay). What realistic
//! delivery (reordering/loss, driving a `ReceiverKeyManager`) adds on top is
//! a separate benchmark.
//!
//! Measures sustained `protect` (encrypt) and `unprotect` (decrypt) throughput
//! for epoch-only/frame-level/packet-level keying, at each of the 15
//! payload sizes in PAYLOAD_SIZES (16 B to 8924 B). We use Criterion's
//! `iter_custom` to time only the SRTP operation (which, for frame/packet,
//! includes the ratchet + in-place rekey when a generation boundary is
//! crossed).
//!
//! Timing is per packet, so every sample pays the clock readout twice
//! (`Instant::now` + `elapsed`, tens of ns on macOS). At the smallest
//! payloads, where the operation itself is a few hundred ns, this may inflate
//! the absolute numbers by a few percent. At larger payload sizes it is noise.
//! It applies equally to all three granularities, so their comparison
//! is unaffected.
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench granularity_throughput_ideal
//!
//! The granularities differ only in how often the key is rotated:
//!   - epoch-only: never within the epoch
//!   - frame-level: once per frame
//!   - packet-level: every packet
//!
//! Frame model: a frame carries FRAME_BYTES of media, split into packets of
//! payload_size bytes, so a frame is FRAME_BYTES/payload_size packets.
//! Why that ratio matters for frame-level cost: a rekey takes a fixed amount
//! of time regardless of payload size (one ratchet step = two HKDF
//! derivations, plus the in-place key install), and at frame-level it happens
//! only on a frame's FIRST packet (the frame's remaining packets just
//! encrypt). Averaged over the frame, each packet therefore carries
//! rekey_time/packets_per_frame of extra time.
//!
//! In this benchmark, FRAME_BYTES is the size of one uncompressed 1080p frame 
//! in 10-bit 4:2:2 (SMPTE ST 2110-20): 1920 x 1080 pixels x 2.5 bytes per pixel
//! = 5,184,000 B.
//!
//! Why 1080p and not 4K/8K/...: the resolution impacts this bench via one
//! place: packets_per_frame. Bigger frames only make frame-level cheaper: at
//! 1424 B a 1080p frame is ~3,640 packets, a 4K frame ~14,560, an 8K frame
//! ~58,000, so the per-packet share of the rekey shrinks 4x/16x. 1080p is
//! therefore the worst case for frame-level out of them. If frame-level is
//! already close to epoch-only here, it is even closer at 4K/8K. And even
//! this worst case is negligible: a rekey is ~700 ns, so at 1080p/1424 B
//! the per-packet extra is 700/3,640 = ~0.2 ns, about 0.1% of the ~250 ns
//! the packet's crypto costs. The measured lines therefore hold for any format.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use mls_srtp_core::granularity::{Granularity, RekeyingStream};
use mls_srtp_core::ratchet::{StreamRatchet, CHAIN_SECRET_LEN};
use mls_srtp_core::rtp::RTP_HEADER_LEN;

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
const GCM_TAG_LEN: usize = 16;

/// SSRC used for all benchmark streams.
const SSRC: u32 = 0xFEED_F00D;

/// Media bytes in one uncompressed 1080p 10-bit 4:2:2 frame (ST 2110-20):
/// 1920 x 1080 x 2.5 = 5,184,000 B.
const FRAME_BYTES: usize = 1920 * 1080 * 5 / 2;

/// RTP timestamp ticks per frame: 90 kHz clock/60 fps = 1500.
const FRAME_PERIOD: u32 = 1500;

/// First frame's RTP timestamp (the epoch anchor/starting point).
const START_TS: u32 = 0;

/// Pre-encrypted batch size for the decrypt benchmark. SRTP replay protection
/// rejects duplicates, so each ciphertext is decrypted once. Hence, we cycle batches.
/// Kept below 2^16 so sequence numbers do not wrap within a batch.
const DECRYPT_BATCH: usize = 50_000;

/// Payload sizes spanning tiny to jumbo
const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (16, "0016B"),
    (32, "0032B"),
    (40, "0040B"),
    (64, "0064B"),
    (128, "0128B"),
    (160, "0160B_speech"),
    (256, "0256B"),
    (512, "0512B"),
    (800, "0800B_video"),
    (1024, "1024B"),
    (1200, "1200B_video"),
    (1424, "1424B_standard"),
    (2048, "2048B"),
    (4096, "4096B"),
    (8924, "8924B_jumbo"),
];

/// The three granularities with short labels for benchmark ids.
const GRANULARITIES: &[(Granularity, &str)] = &[
    (Granularity::EpochOnly, "epoch"),
    (Granularity::Frame, "frame"),
    (Granularity::Packet, "packet"),
];

/// A fixed 32-byte ratchet seed. The seed source does not affect throughput
/// (the per-generation cost is identical), so a constant keeps the bench
/// self-contained.
fn seed() -> Vec<u8> {
    (0..CHAIN_SECRET_LEN as u8).collect()
}

/// Packets per frame at a given media payload size (at least 1).
fn packets_per_frame(payload_size: usize) -> u64 {
    (FRAME_BYTES / payload_size).max(1) as u64
}

/// RTP timestamp for the `i`-th packet given the frame size: the timestamp
/// advances by FRAME_PERIOD every `ppf` packets, so all packets of a frame share
/// one timestamp (this is what frame-level keying keys on).
fn timestamp_for(i: u64, ppf: u64) -> u32 {
    START_TS.wrapping_add((i / ppf) as u32 * FRAME_PERIOD)
}

/// Writes the fixed RTP header fields into a fresh packet buffer of `rtp_len`
/// bytes (the payload region stays zero, as AES-GCM is content-independent).
fn make_packet_buf(rtp_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; rtp_len];
    buf[0] = 0x80; // V=2, P=0, X=0, CC=0
    buf[1] = 96; // dynamic payload type
    buf[8..12].copy_from_slice(&SSRC.to_be_bytes());
    buf
}

/// Benchmarks `protect` throughput for every granularity x payload size.
fn bench_protect(c: &mut Criterion) {
    // libsrtp's one-time global init, needed before any session exists
    srtp::ensure_init();
    // one Criterion group holds all 3 x 15 benchmark ids of this function
    let mut group = c.benchmark_group("granularity_protect");
    group.measurement_time(Duration::from_secs(10));

    // one benchmark id per (granularity, payload size) combination
    for &(granularity, gran_label) in GRANULARITIES {
        for &(payload_size, size_label) in PAYLOAD_SIZES {
            // plaintext packet length: RTP header + media payload
            let rtp_len = RTP_HEADER_LEN + payload_size;
            // wire packet length: protect appends the 16-byte GCM tag
            let srtp_len = rtp_len + GCM_TAG_LEN;
            // how many packets share one timestamp (= one frame)
            let ppf = packets_per_frame(payload_size);

            // telling Criterion how many bytes one iteration processes, so it
            // reports bytes/s (the Gbps of the figures) instead of just time
            group.throughput(Throughput::Bytes(srtp_len as u64));
            group.bench_with_input(
                BenchmarkId::new(gran_label, size_label),
                &payload_size,
                |b, &_sz| {
                    // one sender stream reused for the whole benchmark run,
                    // so its ratchet/rekey state carries across iterations
                    let mut sender =
                        RekeyingStream::new(granularity, SSRC, StreamRatchet::from_seed(seed()));
                    // one reusable buffer, allocated once at full wire size so
                    // no reallocation ever happens inside the timed region
                    let mut buf = make_packet_buf(srtp_len);
                    // running packet number, kept across Criterion's calls
                    let mut i: u64 = 0;

                    // iter_custom: we run the loop ourselves and hand
                    // Criterion only the time we chose to measure
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            // untimed per-packet setup: writing this packet's
                            // seq and frame-derived timestamp
                            buf[2..4].copy_from_slice(&(i as u16).to_be_bytes());
                            buf[4..8].copy_from_slice(&timestamp_for(i, ppf).to_be_bytes());
                            // truncating to plaintext length, protect appends the tag
                            buf.truncate(rtp_len);

                            // timing the full keyed protect: boundary check, any
                            // rekey, and the encryption
                            let t0 = Instant::now();
                            sender.protect(&mut buf).expect("protect failed");
                            total += t0.elapsed();

                            black_box(&buf);
                            i += 1;
                        }
                        total
                    });
                },
            );
        }
    }
    group.finish();
}

/// Benchmarks `unprotect` throughput for every granularity x payload size.
///
/// Unlike protect, decrypt input cannot be reused: SRTP replay protection
/// rejects a seq it has already accepted, so every unprotect call needs a
/// ciphertext it has not seen. Hence the batch setup: pre-encrypt
/// DECRYPT_BATCH packets, decrypt each exactly once, rebuild when exhausted.
fn bench_unprotect(c: &mut Criterion) {
    // libsrtp's one-time global init, needed before any session exists
    srtp::ensure_init();
    // one Criterion group holds all 3 x 15 benchmark ids of this function
    let mut group = c.benchmark_group("granularity_unprotect");
    group.measurement_time(Duration::from_secs(10));

    // one benchmark id per (granularity, payload size) combination
    for &(granularity, gran_label) in GRANULARITIES {
        for &(payload_size, size_label) in PAYLOAD_SIZES {
            // plaintext packet length: RTP header + media payload
            let rtp_len = RTP_HEADER_LEN + payload_size;
            // wire packet length: protect appends the 16-byte GCM tag
            let srtp_len = rtp_len + GCM_TAG_LEN;
            // how many packets share one timestamp (= one frame)
            let ppf = packets_per_frame(payload_size);

            // telling Criterion how many bytes one iteration processes, so it
            // reports bytes/s (the Gbps of the figures) instead of just time
            group.throughput(Throughput::Bytes(srtp_len as u64));
            group.bench_with_input(
                BenchmarkId::new(gran_label, size_label),
                &payload_size,
                |b, &_sz| {
                    // Encrypts a fresh batch with a sender stream and returns the
                    // ciphertexts plus a fresh receiver stream (same seed, so it
                    // crosses the same generation boundaries) ready to decrypt.
                    let make_batch = || -> (Vec<Vec<u8>>, RekeyingStream) {
                        let mut sender = RekeyingStream::new(
                            granularity,
                            SSRC,
                            StreamRatchet::from_seed(seed()),
                        );
                        let mut buf = make_packet_buf(srtp_len);
                        // same in-order stream shape as the protect bench:
                        // consecutive seq, frame-derived timestamps
                        let encrypted: Vec<Vec<u8>> = (0..DECRYPT_BATCH as u64)
                            .map(|i| {
                                buf[2..4].copy_from_slice(&(i as u16).to_be_bytes());
                                buf[4..8].copy_from_slice(&timestamp_for(i, ppf).to_be_bytes());
                                buf.truncate(rtp_len);
                                sender.protect(&mut buf).expect("protect failed");
                                // keep a copy: buf itself is reused for the next packet
                                buf.clone()
                            })
                            .collect();
                        let receiver = RekeyingStream::new(
                            granularity,
                            SSRC,
                            StreamRatchet::from_seed(seed()),
                        );
                        (encrypted, receiver)
                    };

                    // initial batch: idx walks through it one packet at a time
                    let (mut encrypted, mut receiver) = make_batch();
                    let mut idx = 0usize;

                    // iter_custom: we run the loop ourselves and hand
                    // Criterion only the time we chose to measure
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            // Refreshing the batch when exhausted (fresh
                            // ciphertexts AND a fresh receiver, so seq numbers
                            // and replay state restart together). This runs
                            // before the clock starts, so it is not timed.
                            if idx >= encrypted.len() {
                                let (e, r) = make_batch();
                                encrypted = e;
                                receiver = r;
                                idx = 0;
                            }

                            // timing the full keyed unprotect: boundary check, any
                            // rekey, and the decryption (in place: the ciphertext
                            // buffer becomes the plaintext)
                            let t0 = Instant::now();
                            receiver
                                .unprotect(&mut encrypted[idx])
                                .expect("unprotect failed");
                            total += t0.elapsed();

                            black_box(&encrypted[idx]);
                            idx += 1;
                        }
                        total
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_protect, bench_unprotect);
criterion_main!(benches);
