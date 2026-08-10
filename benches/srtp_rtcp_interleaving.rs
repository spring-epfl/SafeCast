//! SRTCP interleaving benchmark.
//!
//! Measures whether injecting occasional SRTCP `protect_rtcp()` calls
//! into a sustained SRTP `protect()` stream affects RTP encryption
//! throughput.
//!
//! For each of the two ST 2110-10 payload sizes (standard 1424 B and
//! jumbo 8924 B), two benchmarks are run:
//!   1. Baseline: pure `protect()` loop (no RTCP)
//!   2. Interleaved: same loop, but every N-th packet triggers an
//!      additional `protect_rtcp()` call on a 100-byte RTCP packet
//!
//! N is derived from the ST 2110-10 1080p60 (2.58 Gbps)
//! packet rate and a 5-second RTCP interval (RFC 3550 §6.2):
//!   - standard MTU (1424 B): ~226,500 pps  => N ≈ 1,130,000
//!   - jumbo MTU (8924 B):    ~36,100 pps   => N ≈ 180,000
//!
//! Why 1080p60 and not 4K/8K: a 4K stream sends 4x the packets per second, 
//! so N is 4x larger and the per-packet RTCP share (one protect_rtcp every N packets) 
//! is 4x SMALLER (16x at 8K). 1080p is therefore more or less the worst case for
//! RTCP interference. If the effect is negligible here, it is even more
//! negligible at 4K/8K.
//!
//! The RTCP packet size is 100 bytes, based on real-world examples:
//! - ShareTechnote: https://www.sharetechnote.com/html/IMS_SIP_RTP_RTCP.html, 72-byte RTCP packet
//! - Wireshark: https://wiki.wireshark.org/RTCP, 100-byte RTCP packet
//!
//! Run:
//!   cargo bench --package safecast-core --bench srtp_rtcp_interleaving

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use safecast_core::keying::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use safecast_core::transport::rtp::RTP_HEADER_LEN;
use safecast_core::transport::srtp_session::create_sender_session;

use openmls::prelude::*;

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
const GCM_TAG_LEN: usize = 16;

/// RTCP packet size in bytes (100 B, based on Wireshark RTCP sample):
/// https://wiki.wireshark.org/RTCP
const RTCP_LEN: usize = 100;

/// ST 2110-10 uncompressed 1080p60 (4:2:2, 10-bit) bitrate in bits/s.
const BITRATE_BPS: u64 = 2_580_000_000;

/// RTCP sending interval in seconds (RFC 3550 §6.2).
const RTCP_INTERVAL_S: u64 = 5;

/// Computes the number of RTP packets between RTCP packets (N).
///
/// N = packets_per_second * rtcp_interval
///   = (bitrate_bps / 8 / payload_size) * rtcp_interval_s
const fn rtcp_interleave_n(payload_size: u64) -> u64 {
    (BITRATE_BPS / 8 / payload_size) * RTCP_INTERVAL_S
}

/// The two ST 2110-10 MTU-derived payload sizes.
/// N (the RTCP interleaving interval) is computed from the 1080p60 bitrate.
const SCENARIOS: &[(usize, &str, u64)] = &[
    (1424, "1424B_standard", rtcp_interleave_n(1424)),
    (8924, "8924B_jumbo",    rtcp_interleave_n(8924)),
];

/// Builds a 2-member MLS group and exports SRTP key material for the sender.
///
/// Returns `(key_material, ssrc)` where `key_material` is the 28-byte
/// concatenation of master key (16 B) and master salt (12 B), and `ssrc`
/// is the sender's synchronization source identifier derived from its
/// MLS identity.
///
/// This runs once per benchmark function (outside the timed loop).
fn setup_mls_group() -> (Vec<u8>, u32) {

    // creating two MLS members: one sender whose SRTP session we will
    // benchmark, and one receiver so the group has at least two members
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

    // adding the receiver to the group (produces a commit)
    group
        .add_members(
            &sender.provider,
            &sender.signer,
            &[receiver_kp.key_package().clone()],
        )
        .expect("failed to add receiver");

    // advancing the sender's local state to the new epoch
    group
        .merge_pending_commit(&sender.provider)
        .expect("failed to merge commit");

    // deriving SSRC from the sender's identity string and exporting
    // SRTP key material (master key + master salt) via MLS exporter
    let ssrc = ssrc_from_identity("sender-0:sender");
    let (key_material, _, _) = export_srtp_keys(&group, sender.provider.crypto(), ssrc);
    (key_material, ssrc)
}

/// Builds a synthetic 100-byte RTCP Sender Report packet (RFC 3550 §6.4.1).
///
/// The payload content does not affect AES-GCM performance, so we only
/// need a structurally valid header so libsrtp accepts it.
fn make_rtcp_packet(ssrc: u32) -> Vec<u8> {
    let mut buf = vec![0u8; RTCP_LEN];

    // byte 0: V=2 (bits 7-6), P=0, RC=0 => 0x80
    buf[0] = 0x80;
    // byte 1: PT=200 (Sender Report)
    buf[1] = 200;
    // bytes 2-3: length in 32-bit words minus one.
    // total = 100 bytes = 25 words => length field = 24
    let length_field: u16 = (RTCP_LEN / 4 - 1) as u16;
    buf[2..4].copy_from_slice(&length_field.to_be_bytes());
    // bytes 4-7: SSRC
    buf[4..8].copy_from_slice(&ssrc.to_be_bytes());

    buf
}

/// Baseline: `protect()` throughput without any RTCP.
fn bench_baseline(c: &mut Criterion) {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_mls_group();

    let mut group = c.benchmark_group("srtp_rtcp_interleaving");

    // using a long measurement time (10 s) to get a sustained throughput
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label, _n) in SCENARIOS {
        // rtp_len  = 12-byte RTP header + payload (plaintext input to protect())
        // srtp_len = rtp_len + 16-byte GCM tag   (ciphertext output of protect())
        let rtp_len = RTP_HEADER_LEN + payload_size;
        let srtp_len = rtp_len + GCM_TAG_LEN;

        // Criterion uses this to compute throughput in bytes/sec.
        // We report SRTP packet bytes (header + payload + tag), same as
        // the interleaved benchmark, so the two are directly comparable.
        group.throughput(Throughput::Bytes(srtp_len as u64));

        group.bench_with_input(
            BenchmarkId::new("baseline", label),
            &payload_size,
            |b, &_sz| {
                let mut session = create_sender_session(&key_material);

                // pre-allocating the packet buffer with static RTP header fields
                let mut buf = vec![0u8; srtp_len];
                buf[0] = 0x80; // V=2, P=0, X=0, CC=0
                buf[1] = 111;  // payload type (dynamic)
                buf[8..12].copy_from_slice(&ssrc.to_be_bytes());  // SSRC

                let mut seq: u16 = 0;
                let mut timestamp: u32 = 0;

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {

                        // writing per-packet RTP header fields
                        buf[2..4].copy_from_slice(&seq.to_be_bytes());
                        buf[4..8].copy_from_slice(&timestamp.to_be_bytes());

                        // truncating to plaintext length; protect() will
                        // append the 16-byte GCM tag, growing it back
                        buf.truncate(rtp_len);

                        // timing only the protect() call
                        let t0 = Instant::now();
                        session.protect(&mut buf).expect("protect failed");
                        total += t0.elapsed();

                        black_box(&buf);
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

/// Interleaved: same `protect()` loop, but every N-th iteration also
/// calls `protect_rtcp()` on a 100-byte RTCP packet.
///
/// Both `protect()` and `protect_rtcp()` are inside the timed section
/// so that any interference shows up as increased latency.
fn bench_interleaved(c: &mut Criterion) {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_mls_group();

    let mut group = c.benchmark_group("srtp_rtcp_interleaving");
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label, n) in SCENARIOS {
        let rtp_len = RTP_HEADER_LEN + payload_size;
        let srtp_len = rtp_len + GCM_TAG_LEN;

        // throughput reported in SRTP bytes only (not including the
        // occasional RTCP bytes) so it stays comparable to baseline
        group.throughput(Throughput::Bytes(srtp_len as u64));

        group.bench_with_input(
            BenchmarkId::new("interleaved", label),
            &payload_size,
            |b, &_sz| {
                let mut session = create_sender_session(&key_material);

                // RTP buffer (reused across iterations, same as baseline)
                let mut buf = vec![0u8; srtp_len];
                buf[0] = 0x80;                                    // V=2
                buf[1] = 111;                                     // payload type
                buf[8..12].copy_from_slice(&ssrc.to_be_bytes());  // SSRC

                // RTCP template: a valid 100-byte Sender Report.
                // We clone it each time protect_rtcp() is called because
                // libsrtp modifies the buffer in place (appends GCM tag).
                let rtcp_template = make_rtcp_packet(ssrc);

                let mut seq: u16 = 0;
                let mut timestamp: u32 = 0;
                let mut pkt_count: u64 = 0;

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        
                        // per-packet RTP header fields
                        buf[2..4].copy_from_slice(&seq.to_be_bytes());
                        buf[4..8].copy_from_slice(&timestamp.to_be_bytes());
                        buf.truncate(rtp_len);

                        // --- timed section: BOTH RTP and RTCP work ---
                        let t0 = Instant::now();

                        // RTP encryption (every iteration, same as baseline)
                        session.protect(&mut buf).expect("protect failed");

                        // RTCP encryption (every N-th packet only).
                        // For standard MTU at 1080p60, N ≈ 1,130,000,
                        // so this fires roughly once per 5 seconds of
                        // simulated real-time video. Comparing against n - 1
                        // so the first RTCP comes after one full interval.
                        if pkt_count % n == n - 1 {
                            let mut rtcp_buf = rtcp_template.clone();
                            session
                                .protect_rtcp(&mut rtcp_buf)
                                .expect("protect_rtcp failed");
                            black_box(&rtcp_buf);
                        }

                        total += t0.elapsed();

                        // --- end timed section ---

                        black_box(&buf);
                        seq = seq.wrapping_add(1);
                        timestamp = timestamp.wrapping_add(1);
                        pkt_count += 1;
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_baseline, bench_interleaved);
criterion_main!(benches);
