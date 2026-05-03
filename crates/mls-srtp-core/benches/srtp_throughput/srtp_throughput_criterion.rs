//! SRTP encryption throughput benchmark.
//!
//! Measures sustained `protect()` throughput using Criterion's `iter_custom`,
//! which lets us time only the `protect()` call.
//!
//! The target scenario is uncompressed 1080p60 over SMPTE
//! ST 2110-20 at ~2.4 Gbps. We investigate whether SRTP encryption
//! can keep up with this bitrate.
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench srtp_throughput
//!
//! Design notes:
//!
//! - **Synthetic payload.** The payload region is initially zero-filled.
//!   After the first `protect()` call the payload contains ciphertext, so
//!   subsequent iterations encrypt that ciphertext. This
//!   does not matter because AES-GCM is content-independent.
//!
//! - **Pre-allocated packet buffer.** A single buffer is reused across
//!   every iteration: we overwrite the RTP sequence number (required by
//!   SRTP for IV construction and replay protection) and timestamp in
//!   place. This avoids per-packet `Vec` allocation so the measurement
//!   reflects the cost of SRTP encryption itself rather than allocator
//!   noise.
//!
//! - **Payload sizes.** SMPTE ST 2110-10 defines the maximum allowed UDP
//!   datagram size (i.e. the UDP header + UDP payload combined).
//!   It specifies two size classes:
//!     - standard: max 1460 B per UDP datagram (fits a 1500 B Ethernet MTU)
//!     - extended: max 8960 B per UDP datagram (fits a 9000 B jumbo-frame MTU)
//!   Inside each UDP datagram, the space available for actual media payload
//!   is what remains after subtracting the protocol headers that sit between
//!   the UDP header and the media bytes:
//!     - 8 B  UDP header
//!     - 12 B RTP header (fixed, RFC 3550)
//!     - 16 B SRTP authentication tag (AES-128-GCM, RFC 7714)
//!   So the usable RTP payload per packet is:
//!     - standard: 1460 − 8 − 12 − 16 = 1424 B
//!     - extended: 8960 − 8 − 12 − 16 = 8924 B
//!   These two values (1424 and 8924) are the payload sizes used by this
//!   benchmark.
//!
//! - **RTP metadata.** The sequence number and timestamp are incremented
//!   by 1 each packet. The timestamp is syntactic only and does not model
//!   any real codec's packetization timing.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use mls_srtp_core::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use mls_srtp_core::rtp::RTP_HEADER_LEN;
use mls_srtp_core::srtp_session::{create_sender_session, create_receiver_session};

use openmls::prelude::*;

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
const GCM_TAG_LEN: usize = 16;

/// Payload sizes spanning the full range from tiny to jumbo.
///
/// Three categories sorted in ascending order:
///   - Powers of 2 (16 B .. 4096 B) for the throughput scaling curve
///   - Application-realistic sizes: 160 B (G.711 speech, 20 ms ptime),
///     800 B and 1200 B (typical video)
///   - ST 2110-10 MTU-derived sizes: 1424 B (standard) and 8924 B (jumbo),
///     as computed in the module-level doc comment above
const PAYLOAD_SIZES: &[(usize, &str)] = &[
    // powers of 2
    (16,    "0016B"),
    (32,    "0032B"),
    // powers of 2 (continued)
    (40,    "0040B"),
    (64,    "0064B"),
    (128,   "0128B"),
    // application-realistic: G.711 speech at 20 ms
    (160,   "0160B_speech"),
    // powers of 2 (continued)
    (256,   "0256B"),
    (512,   "0512B"),
    // application-realistic: typical video packet sizes
    (800,   "0800B_video"),
    (1024,  "1024B"),
    (1200,  "1200B_video"),
    // ST 2110-10 standard MTU (1460 − 8 − 12 − 16 = 1424)
    (1424,  "1424B_standard"),
    // powers of 2 (continued)
    (2048,  "2048B"),
    (4096,  "4096B"),
    // ST 2110-10 jumbo MTU (8960 − 8 − 12 − 16 = 8924)
    (8924,  "8924B_jumbo"),
];

/// Builds a 2-member MLS group and exports SRTP key material for the sender.
/// Returns (key_material, ssrc). Identical structure to the Criterion
/// benchmark's `setup_mls_group` at `benches/srtp_operations.rs`.
fn setup_mls_group() -> (Vec<u8>, u32) {

    // creating two MLS members: one sender and one receiver
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");

    // generating a KeyPackage for the receiver so the sender can add it
    let receiver_kp = receiver.generate_key_package();

    // configuring the group with the ratchet tree extension (not relevant
    // for benchmarking, but required to form a valid group)
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
    let (key_material, _, _) = export_srtp_keys(&group, sender.provider.crypto(), ssrc);
    (key_material, ssrc)
}

/// Benchmarks sustained SRTP encryption throughput for each payload size
/// in [`PAYLOAD_SIZES`]. Uses `iter_custom` to time only the `protect()`
/// call itself.
fn bench_srtp_throughput(c: &mut Criterion) {

    // initializing libsrtp
    srtp::ensure_init();

    // setting up the MLS group and exporting key material (done once,
    // outside the timed loop)
    let (key_material, ssrc) = setup_mls_group();

    // creating a Criterion benchmark group that will contain one
    // benchmark per payload size
    let mut group = c.benchmark_group("srtp_throughput");

    // using a long measurement time (10 s) to get a sustained throughput
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        // computing the plaintext and ciphertext sizes:
        // rtp_len  = RTP header + payload (what protect() reads)
        // srtp_len = rtp_len + GCM tag    (what protect() writes)
        let rtp_len = RTP_HEADER_LEN + payload_size;
        let srtp_len = rtp_len + GCM_TAG_LEN;

        // telling Criterion how many bytes each iteration processes,
        // so it can report throughput (bytes/sec) alongside raw latency
        group.throughput(Throughput::Bytes(srtp_len as u64));

        // registering a benchmark named "protect/<label>" that receives
        // the payload size as input and runs the closure for measurement
        group.bench_with_input(
            BenchmarkId::new("protect", label),
            &payload_size,
            |b, &_sz| {

                // creating the SRTP sender session from the exported key material
                let mut session = create_sender_session(&key_material);

                // Pre-allocating the packet buffer, sized for the full SRTP
                // ciphertext (header + payload + tag). Zero-filled: the
                // payload region stays zeroed across iterations (AES-GCM is
                // content-independent)
                let mut buf = vec![0u8; srtp_len];

                // writing the static RTP header fields (unchanged between packets)
                buf[0] = 0x80; // V=2, P=0, X=0, CC=0
                buf[1] = 111;  // payload type (dynamic)
                buf[8..12].copy_from_slice(&ssrc.to_be_bytes()); // SSRC (bytes 8..12)

                // Initializing per-packet RTP metadata. The sequence number
                // is incremented by 1 each packet (as required by SRTP for
                // replay protection). The timestamp increment is syntactic
                // only and does not model any real codec's packetization timing
                let mut seq: u16 = 0;
                let mut timestamp: u32 = 0;

                // Using iter_custom instead of iter so we can time only
                // the protect() call, excluding header writes and truncation.
                // TODO: check if OK to have Instant::now() call at each iteration
                // (elapsed() calls Instant::now() internally)
                // Criterion passes us `iters` (how many iterations to run)
                // and we return the total Duration spent in protect()
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {

                        // writing the per-packet RTP header fields
                        buf[2..4].copy_from_slice(&seq.to_be_bytes());
                        buf[4..8].copy_from_slice(&timestamp.to_be_bytes());

                        // truncating to plaintext RTP length; libsrtp reads
                        // [0..rtp_len] and appends the 16-byte GCM tag,
                        // growing the Vec back to srtp_len
                        buf.truncate(rtp_len);

                        // timing only the protect() call itself
                        let t0 = Instant::now();
                        session.protect(&mut buf).expect("protect failed");
                        total += t0.elapsed();

                        // preventing the compiler from optimizing away the result
                        black_box(&buf);

                        // advancing sequence number and timestamp for the next packet
                        seq = seq.wrapping_add(1);
                        timestamp = timestamp.wrapping_add(1);
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

/// Benchmarks sustained SRTP decryption throughput for each payload size
/// in [`PAYLOAD_SIZES`]. Uses `iter_custom` to time only the `unprotect()`
/// call itself. Pre-encrypts a batch of packets to feed into the decrypt loop.
fn bench_srtp_unprotect_throughput(c: &mut Criterion) {

    // initializing libsrtp
    srtp::ensure_init();

    // setting up the MLS group and exporting key material (done once,
    // outside the timed loop)
    let (key_material, ssrc) = setup_mls_group();

    // creating a Criterion benchmark group that will contain one
    // benchmark per payload size
    let mut group = c.benchmark_group("srtp_throughput");

    // using a long measurement time (10 s) to get a sustained throughput
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        // computing the plaintext and ciphertext sizes (same as protect bench)
        let rtp_len = RTP_HEADER_LEN + payload_size;
        let srtp_len = rtp_len + GCM_TAG_LEN;

        // telling Criterion how many bytes each iteration processes
        group.throughput(Throughput::Bytes(srtp_len as u64));

        group.bench_with_input(
            BenchmarkId::new("unprotect", label),
            &payload_size,
            |b, &_sz| {

                // SRTP replay protection rejects duplicate packets, so each
                // ciphertext can only be decrypted once. We pre-encrypt a
                // large batch and consume them sequentially.
                let batch_size: u16 = 50_000;

                // Helper: creates a fresh sender session, encrypts batch_size
                // packets, and returns a fresh receiver session ready to
                // decrypt them.
                let make_batch = || -> (Vec<Vec<u8>>, srtp::Session) {
                    let mut sender = create_sender_session(&key_material);
                    let mut buf = vec![0u8; srtp_len];

                    // writing static RTP header fields
                    buf[0] = 0x80; // V=2, P=0, X=0, CC=0
                    buf[1] = 111;  // payload type (dynamic)
                    buf[8..12].copy_from_slice(&ssrc.to_be_bytes());

                    // encrypting batch_size packets with incrementing seq numbers
                    let encrypted: Vec<Vec<u8>> = (0..batch_size)
                        .map(|seq| {
                            buf[2..4].copy_from_slice(&seq.to_be_bytes());
                            buf[4..8].copy_from_slice(&(seq as u32).to_be_bytes());
                            buf.truncate(rtp_len);
                            sender.protect(&mut buf).expect("protect failed");
                            buf.clone()
                        })
                        .collect();

                    // creating the receiver session keyed with the same material
                    let receiver = create_receiver_session(&key_material);
                    (encrypted, receiver)
                };

                // preparing the initial batch
                let (mut encrypted, mut receiver) = make_batch();
                let mut idx = 0usize;

                // using iter_custom to time only the unprotect() call,
                // excluding batch preparation overhead
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {

                        // refreshing batch if exhausted (happens only 1 in
                        // 50,000 iterations; criterion's outlier detection
                        // filters it)
                        if idx >= encrypted.len() {
                            let (e, r) = make_batch();
                            encrypted = e;
                            receiver = r;
                            idx = 0;
                        }

                        // timing only the unprotect() call itself
                        let t0 = Instant::now();
                        receiver.unprotect(&mut encrypted[idx]).expect("unprotect failed");
                        total += t0.elapsed();

                        // preventing the compiler from optimizing away the result
                        black_box(&encrypted[idx]);
                        idx += 1;
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_srtp_throughput, bench_srtp_unprotect_throughput);
criterion_main!(benches);
