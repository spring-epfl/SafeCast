//! SRTP `protect()` latency across payload sizes: the SRTP half of the
//! fixed-cost breakdown.
//!
//! This is the matched control for `aes_gcm_baseline` (raw AES-GCM over the
//! same 13 sizes, measured the same way): subtracting the two, and fitting a
//! `time = fixed + per_byte x size` line to each, splits SRTP's per-packet
//! cost into a fixed part and a per-byte part and isolates the overhead SRTP
//! adds over raw AES-GCM. Both series are read by `fixed_cost_breakdown.py`
//! (this folder); the write-up is `results.md`. This pair explains the shape
//! of the throughput curves (fig1/fig2) but does not itself feed any figure.
//!
//! Run:
//!   cargo bench --package safecast-core --bench srtp_scaling

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use safecast_core::keying::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use safecast_core::transport::rtp::RTP_HEADER_LEN;
use safecast_core::transport::srtp_session::create_sender_session;

use openmls::prelude::*;

/// AES-128-GCM authentication tag length in bytes
const GCM_TAG_LEN: usize = 16;

/// Many payload sizes to map the scaling curve, ranging from small
/// audio-like payloads to jumbo-frame video payloads and more.
const PAYLOAD_SIZES: &[usize] = &[
    16, 32, 64, 128, 256, 512, 1024, 1424, 2048, 4096, 8192, 8924, 16384,
];

/// Creates a two-member MLS group and exports the SRTP key material.
/// Returns the key material and the sender's SSRC.
fn setup_mls_group() -> (Vec<u8>, u32) {
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");
    let receiver_kp = receiver.generate_key_package();

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &group_config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

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

    let ssrc = ssrc_from_identity("sender-0:sender");
    let (key_material, _, _) = export_srtp_keys(&group, sender.provider.crypto(), ssrc);
    (key_material, ssrc)
}

/// Benchmarks SRTP `protect()` for each payload size.
/// Uses `iter_custom` to time only the protect() call itself,
/// excluding setup and buffer allocation.
fn bench_srtp_scaling(c: &mut Criterion) {
    srtp::ensure_init();
    let (key_material, ssrc) = setup_mls_group();

    let mut group = c.benchmark_group("srtp_scaling");

    // using 5 s measurement time per payload size
    group.measurement_time(Duration::from_secs(5));

    for &payload_size in PAYLOAD_SIZES {
        let rtp_len = RTP_HEADER_LEN + payload_size;
        let srtp_len = rtp_len + GCM_TAG_LEN;

        // telling Criterion the bytes processed per iteration (header + payload + tag)
        group.throughput(Throughput::Bytes(srtp_len as u64));

        group.bench_with_input(
            BenchmarkId::new("protect", payload_size),
            &payload_size,
            |b, &_sz| {

                // creating one SRTP that is reused across iterations,
                // matching real-world usage where a session persists for a stream
                let mut session = create_sender_session(&key_material);

                // pre-allocating buffer with space for header + payload + GCM tag
                let mut buf = vec![0u8; srtp_len];

                // writing the fixed parts of the RTP header:
                // version=2, payload type=111, SSRC
                buf[0] = 0x80;
                buf[1] = 111;
                buf[8..12].copy_from_slice(&ssrc.to_be_bytes());

                let mut seq: u16 = 0;
                let mut timestamp: u32 = 0;

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        
                        // updating per-packet fields: sequence number and timestamp
                        buf[2..4].copy_from_slice(&seq.to_be_bytes());
                        buf[4..8].copy_from_slice(&timestamp.to_be_bytes());

                        // resetting buffer to RTP length (protect() appends the
                        // 16-byte GCM tag, growing it to srtp_len)
                        buf.truncate(rtp_len);

                        // timing only the protect() call: this is the full SRTP
                        // pipeline (stream lookup, replay check, IV construction,
                        // AES-GCM encrypt, tag append)
                        let t0 = Instant::now();
                        session.protect(&mut buf).expect("protect failed");
                        total += t0.elapsed();

                        // preventing the compiler from optimizing away the result
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

criterion_group!(benches, bench_srtp_scaling);
criterion_main!(benches);
