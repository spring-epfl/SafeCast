//! SRTP encryption throughput benchmark.
//!
//! Runs a back-to-back encrypt loop and measures achieved throughput,
//! comparing it against a configurable
//! target bitrate (default 2.4 Gbps, chosen to match uncompressed 1080p60
//! YUV 4:2:2 as carried over SMPTE ST 2110-20).
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench srtp_throughput -- \
//!       --duration 10 \
//!       --payload 1424,8924 \
//!       --target-gbps 2.4
//!
//! Design notes:
//!
//! - **Synthetic payload.** The payload region is zero-filled, as zero bytes produce
//!   identical throughput and latency as real H.264 NAL.
//!
//! - **Pre-allocated packet buffer.** A single buffer is reused across
//!   every iteration: we overwrite the RTP sequence number and timestamp
//!   in place (the payload stays zero-filled). This avoids per-packet
//!   `Vec` allocation so the measurement reflects the cost of SRTP
//!   encryption itself rather than allocator noise.
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
//!   These two values (1424 and 8924) are the default payload sizes used
//!   by this benchmark.
//!
//! - **Warmup.** The first packet through libsrtp triggers the SRTP KDF
//!   (RFC 3711 §4.3.1), and the CPU takes a moment to reach steady-state
//!   clocks. We do `--warmup` seconds of encryption before starting the
//!   measurement to exclude both.
//!
//! - **RTP metadata.** The sequence number and timestamp are incremented
//!   by 1 each packet. The timestamp is syntactic only and does not model
//!   any real codec's packetization timing.

use std::hint::black_box;
use std::time::{Duration, Instant};

use clap::Parser;

use mls_srtp_core::mls::{export_srtp_keys, ssrc_from_identity, MlsMember, CIPHERSUITE};
use mls_srtp_core::rtp::RTP_HEADER_LEN;
use mls_srtp_core::srtp_session::create_sender_session;

use openmls::prelude::*;

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
const GCM_TAG_LEN: usize = 16;

#[derive(Parser, Debug)]
#[command(about = "SRTP encryption throughput benchmark")]
struct Args {
    /// RTP payload size(s) in bytes, comma-separated
    #[arg(long, default_value = "1424,8924")]
    payload: String,

    /// measurement duration per payload size, in seconds
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// warmup duration per payload size, in seconds (excluded from metrics)
    #[arg(long, default_value_t = 2)]
    warmup: u64,

    /// Bitrate (in Gbps) the system must sustain. The report compares
    /// measured throughput against this value to compute how much spare
    /// capacity ("speedup") remains
    #[arg(long, default_value_t = 2.4)]
    target_gbps: f64,

    /// hidden flag passed by `cargo bench` (ignored)
    #[arg(long, hide = true)]
    bench: bool,
}

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

/// Formats a raw bits-per-second number as Gbps / Mbps / kbps.
fn format_bits(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.3} Gbps", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.3} Mbps", bps / 1e6)
    } else {
        format!("{:.3} kbps", bps / 1e3)
    }
}

/// Runs the back-to-back encryption loop for a single payload
/// size and prints the results.
fn run_payload(
    payload_size: usize,
    warmup: Duration,
    duration: Duration,
    target_gbps: f64,
) {

    // initializing libsrtp
    srtp::ensure_init();

    println!("\n─── payload {} B ───", payload_size);

    // setting up the MLS group and exporting key material (done once,
    // outside the timed loop)
    let (key_material, ssrc) = setup_mls_group();

    // creating the SRTP sender session from the exported key material
    let mut session = create_sender_session(&key_material);

    // computing the plaintext and ciphertext sizes:
    // rtp_len  = RTP header + payload (what protect() reads)
    // srtp_len = rtp_len + GCM tag    (what protect() writes)
    let rtp_len = RTP_HEADER_LEN + payload_size;
    let srtp_len = rtp_len + GCM_TAG_LEN;

    // Pre-allocating the packet buffer, sized for the full SRTP ciphertext
    // (header + payload + tag). Zero-filled: the payload region stays
    // zeroed across iterations (AES-GCM is content-independent).
    // We `truncate` to `rtp_len` before each `protect()` call so that
    // libsrtp can append the 16-byte tag without reallocating
    let mut buf = vec![0u8; srtp_len];

    // writing the static RTP header fields (unchanged between packets)
    buf[0] = 0x80; // V=2, P=0, X=0, CC=0
    buf[1] = 111;  // payload type (dynamic)
    buf[8..12].copy_from_slice(&ssrc.to_be_bytes()); // SSRC (bytes 8..12)

    // Initializing the per-packet RTP metadata. The sequence number is
    // incremented by 1 each packet (as required by SRTP for replay
    // protection). The timestamp increment is syntactic only and does
    // not model any real codec's packetization timing
    let mut seq: u16 = 0;
    let mut timestamp: u32 = 0;

    // encrypting one packet and returning how long protect() took
    macro_rules! encrypt_one {
        () => {{
            // writing the per-packet RTP header fields
            buf[2..4].copy_from_slice(&seq.to_be_bytes());
            buf[4..8].copy_from_slice(&timestamp.to_be_bytes());

            // truncating to plaintext RTP length; libsrtp reads
            // [0..rtp_len] and appends the 16-byte GCM tag, growing
            // the Vec back to srtp_len
            buf.truncate(rtp_len);

            // timing only the protect() call itself
            let t0 = Instant::now();
            session.protect(&mut buf).expect("protect failed");
            let elapsed = t0.elapsed();

            // preventing the compiler from optimizing away the result
            black_box(&buf);

            // advancing sequence number and timestamp for the next packet
            seq = seq.wrapping_add(1);
            timestamp = timestamp.wrapping_add(1);

            elapsed
        }};
    }

    // ─── Warmup phase ───────────────────────────────────────────────

    // running protect() in a tight loop for `warmup` seconds to
    // exclude libsrtp's first-packet KDF cost and let the CPU reach
    // steady-state clocks
    let warmup_end = Instant::now() + warmup;
    while Instant::now() < warmup_end {
        let _ = encrypt_one!();
    }

    // ─── Measurement phase ──────────────────────────────────────────

    // accumulators: packet count, total SRTP
    // bytes processed, and cumulative protect() time in nanoseconds
    let mut total_packets: u64 = 0;
    let mut total_srtp_bytes: u64 = 0;
    let mut total_protect_ns: u64 = 0;

    // starting the measurement clock and computing the end time
    let run_start = Instant::now();
    let run_end = run_start + duration;

    while Instant::now() < run_end {
        // encrypting one packet
        let lat = encrypt_one!();

        // updating the accumulators
        total_packets += 1;
        total_srtp_bytes += srtp_len as u64;
        total_protect_ns += lat.as_nanos() as u64;
    }

    // ─── Report ─────────────────────────────────────────────────────

    // deriving throughput and packet rate from the cumulative protect()
    // time, not wall-clock elapsed

    // cumulative protect() time in seconds
    let protect_s = total_protect_ns as f64 / 1e9;
    // bits encrypted per second
    let throughput_bps = (total_srtp_bytes as f64 * 8.0) / protect_s;
    // packets encrypted per second
    let pps = total_packets as f64 / protect_s;

    // computing speedup: how many times faster we are than the target
    // bitrate
    let target_bps = target_gbps * 1e9;
    let speedup = throughput_bps / target_bps;

    println!("  protect() time:    {:.3} s", protect_s);
    println!(
        "  packets:           {} ({:.2} Mpps)",
        total_packets,
        pps / 1e6
    );
    println!(
        "  srtp packet bytes: {:.2} GB  =>  {}",
        total_srtp_bytes as f64 / 1e9,
        format_bits(throughput_bps)
    );
    println!(
        "  target:            {:.3} Gbps  |  speedup x{:.2}",
        target_gbps,
        speedup,
    );
}

/// Main entry point
fn main() {
    let args = Args::parse();

    // parsing the comma-separated payload sizes
    let payload_sizes: Vec<usize> = args
        .payload
        .split(',')
        .map(|s| s.trim().parse::<usize>().expect("invalid payload size"))
        .collect();

    // printing the configuration
    println!(
        "payload sizes:  {:?}\nwarmup:         {} s\nduration:       {} s\ntarget:         {} Gbps",
        payload_sizes, args.warmup, args.duration, args.target_gbps
    );

    // running the benchmark for each payload size
    for size in &payload_sizes {
        run_payload(
            *size,
            Duration::from_secs(args.warmup),
            Duration::from_secs(args.duration),
            args.target_gbps,
        );
    }
}
