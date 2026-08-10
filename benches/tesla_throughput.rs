//! Measures what TESLA adds on top of plain SRTP, per packet and in both
//! directions. Six variants per payload size:
//!
//! - sender: protect() alone, then protect() + authenticate() with each
//!   MAC algorithm (HMAC-SHA256, GMAC);
//! - receiver: unprotect() alone, then the full TESLA process_arrival()
//!   with each MAC algorithm.
//!
//! Run: cargo bench --bench tesla_throughput
//! Output: a table on stdout + benches/results/tesla_throughput/raw.csv

use std::fs;
use std::time::Instant;

use safecast_core::keying::granularity::{Granularity, RekeyingStream};
use safecast_core::keying::mls::CIPHERSUITE;
use safecast_core::keying::ratchet::StreamRatchet;
use safecast_core::receiver::generation::GenerationScheme;
use safecast_core::receiver::ReceiverKeyManager;
use safecast_core::simulation::sender::StreamModel;
use safecast_core::tesla::commitment::TeslaCommitment;
use safecast_core::tesla::mac::TeslaMacAlg;
use safecast_core::tesla::receiver::TeslaReceiver;
use safecast_core::tesla::schedule::TeslaSchedule;
use safecast_core::tesla::sender::TeslaSender;
use safecast_core::tesla::TESLA_EXT_LEN;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

/// The payload sweep. TESLA appends a 34-byte extension to every packet,
/// so the two MTU-anchored payloads shrink by 34 bytes (1424 -> 1390 B,
/// 8924 -> 8890 B) for the packet to still fit the MTU.
const PAYLOADS: [usize; 15] = [
    16, 32, 40, 64, 128, 160, 256, 512, 800, 1024, 1200, 1390, 2048, 4096, 8890,
];

/// Packets measured per variant.
const PACKETS: u64 = 1_000_000;

/// Leading packets whose times are discarded (caches, branch predictors).
const WARMUP: usize = 50_000;

/// Receiver-side packets are produced in slices of this many.
const BATCH: u64 = 4_096;

/// TESLA interval length: 1 ms.
const T_INT_NS: u64 = 1_000_000;

/// Disclosure delay.
const D: u32 = 2;

/// A fixed ratchet seed: both ends of a run derive the same SRTP keys.
const SEED: u8 = 7;
const SSRC: u32 = 0x5454;

/// The TESLA schedule: 1 ms intervals, disclosure delay d = 2. The chain
/// needs one key per 1 ms interval of the run, and how many 1 ms
/// intervals the run's 1_000_000 packets fall into depends on how fast the
/// model sends them: jumbo packets leave ~29 us apart, so the run
/// stretches over ~3 seconds = ~3000 intervals. Small packets leave
/// under 1 us apart, so the run fits in a few intervals total. Hence the
/// chain length is calculated from the model's send times.
fn schedule(model: &StreamModel) -> TeslaSchedule {
    let n_chain = model.send_ns(PACKETS - 1) / T_INT_NS + D as u64 + 2;
    TeslaSchedule::new(0, T_INT_NS, D, n_chain as u32, 0, 16)
}

/// A fresh sender-side SRTP session (epoch-only keying).
fn srtp_sender() -> RekeyingStream {
    RekeyingStream::new(
        Granularity::EpochOnly,
        SSRC,
        StreamRatchet::from_seed(vec![SEED; 32]),
    )
}

/// A fresh receiver-side SRTP session matching [`srtp_sender`].
fn srtp_receiver() -> ReceiverKeyManager {
    ReceiverKeyManager::new(
        GenerationScheme::EpochOnly,
        SSRC,
        StreamRatchet::from_seed(vec![SEED; 32]),
        1,    // key window: epoch-only has a single generation
        4096, // seek cap (not used at epoch-only)
        0,    // libsrtp's default replay window
    )
}

/// One variant's results.
struct Stats {
    mean_ns: f64,
    p50_ns: u64,
    p99_ns: u64,
    p99_9_ns: u64,
    max_ns: u64,
}

/// Reduces the collected per-packet times.
fn reduce(mut samples: Vec<u64>) -> Stats {
    let mean_ns = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
    // sorted, so position k holds the k-th smallest time
    samples.sort_unstable();
    // nearest-rank percentile
    let pct = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    Stats {
        mean_ns,
        p50_ns: pct(0.50),
        p99_ns: pct(0.99),
        p99_9_ns: pct(0.999),
        // the largest value sits at the end of the sorted vec
        max_ns: *samples.last().unwrap(),
    }
}

/// The sender side: encrypts and times packets, optionally appending
/// the TESLA extension
fn run_sender(model: &StreamModel, mac: Option<TeslaMacAlg>) -> Stats {
    let mut crypto = srtp_sender();
    // the TESLA sender only exists in the TESLA variants
    let mut tesla = mac.map(|alg| TeslaSender::new(schedule(model), alg));

    let mut samples = Vec::with_capacity(PACKETS as usize);
    for i in 0..PACKETS {
        // building the plaintext is untimed setup
        let mut buf = model.plain_packet(i);
        buf.reserve(TESLA_EXT_LEN);
        let send_ns = model.send_ns(i);

        // the timed region: encrypt, plus TESLA's addition if enabled
        let t0 = Instant::now();
        crypto.protect(&mut buf).expect("protect failed");
        if let Some(t) = &mut tesla {
            t.authenticate(&mut buf, i, send_ns);
        }
        let dt = t0.elapsed().as_nanos() as u64;

        if i as usize >= WARMUP {
            samples.push(dt);
        }
    }
    reduce(samples)
}

/// Builds the TESLA receiver for a run: the sender signs its commitment,
/// the receiver verifies it (untimed setup).
fn tesla_receiver(model: &StreamModel, tx: &TeslaSender, alg: TeslaMacAlg) -> TeslaReceiver {
    let s = schedule(model);
    let signer =
        SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("key generation failed");
    let commitment = TeslaCommitment {
        anchor: *tx.anchor(),
        t0_ns: s.t0_ns,
        t_int_ns: s.t_int_ns,
        d: s.d,
        n_chain: s.n_chain,
        mac_alg: alg,
        sender_identity: b"bench:sender".to_vec(),
        ssrc: SSRC,
        group_id: b"bench-group".to_vec(),
        epoch: 0,
    };
    let signature = commitment.sign(&signer);
    let provider = OpenMlsRustCrypto::default();
    TeslaReceiver::accept(
        &commitment,
        &signature,
        &signer.to_public_vec(),
        provider.crypto(),
        s.d_t_ns,
        s.g_max,
        srtp_receiver(),
    )
    .expect("the commitment must verify")
}

/// The receiver side: packets are produced in untimed batches, then fed
/// one by one, timing only the receiver call. `mac` = None measures the
/// plain SRTP unprotect. Some(alg) -> the full TESLA process_arrival.
fn run_receiver(model: &StreamModel, mac: Option<TeslaMacAlg>) -> Stats {

    // the producing side (untimed): a sender that encrypts, plus a TESLA
    // sender in the TESLA variants
    let mut crypto = srtp_sender();
    let mut tesla_tx = mac.map(|alg| TeslaSender::new(schedule(model), alg));

    // the measured side: either the plain SRTP receiver or TESLA around it
    let mut plain_rx = None;
    let mut tesla_rx = None;
    match mac {
        None => plain_rx = Some(srtp_receiver()),
        Some(alg) => {
            tesla_rx = Some(tesla_receiver(
                model,
                tesla_tx.as_ref().expect("TESLA sender exists"),
                alg,
            ))
        }
    }

    let mut samples = Vec::with_capacity(PACKETS as usize);
    
    // the run walks the stream in batches: produce BATCH packets, feed
    // them, repeat
    let mut i = 0u64;
    while i < PACKETS {
        // producing one batch of packets, untimed: encrypt each packet
        // and, in the TESLA variants, append its extension
        let end = (i + BATCH).min(PACKETS);
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity((end - i) as usize);
        for j in i..end {
            let mut buf = model.plain_packet(j);
            // room for the extension, so authenticate() never reallocates
            buf.reserve(TESLA_EXT_LEN);
            crypto.protect(&mut buf).expect("protect failed");
            if let Some(t) = &mut tesla_tx {
                t.authenticate(&mut buf, j, model.send_ns(j));
            }
            batch.push(buf);
        }

        // feeding the batch to the receiver, timing each call
        for (k, buf) in batch.iter_mut().enumerate() {
            // each packet "arrives" 100 ns after its send time, 
            // before its key's disclosure
            let arrival_ns = model.send_ns(i + k as u64) + 100;
            // the timed region
            let t0 = Instant::now();
            match (&mut plain_rx, &mut tesla_rx) {
                (Some(rx), _) => {
                    rx.unprotect(buf).expect("unprotect failed");
                }
                (_, Some(rx)) => {
                    rx.process_arrival(buf, arrival_ns)
                        .expect("packet must be delivered");
                }
                _ => unreachable!(),
            }
            let dt = t0.elapsed().as_nanos() as u64;
            // the first WARMUP packets of the run are discarded
            if (i + k as u64) as usize >= WARMUP {
                samples.push(dt);
            }
        }
        i = end;
    }

    // the correctness gate of the TESLA variants: everything delivered
    // and verified, nothing forged, only the final d intervals waiting
    if let Some(rx) = &tesla_rx {
        let s = rx.stats();
        assert_eq!(s.delivered, PACKETS, "not every packet was delivered");
        assert_eq!(s.forged, 0, "no packet may look forged");
        assert_eq!(
            s.verified + rx.unsettled(),
            PACKETS,
            "every packet is verified or waits in the final d intervals"
        );
    }
    reduce(samples)
}

/// Throughput in Gbit/s that one core sustains at this per-packet time.
fn gbps(payload: usize, mean_ns: f64) -> f64 {
    (payload * 8) as f64 / mean_ns
}

fn main() {
    // the CSV the notebook plots from: starts as the header line, and
    // every measured variant below appends one row
    let dir = "benches/results/tesla_throughput";
    fs::create_dir_all(dir).expect("cannot create results dir");
    let mut csv = String::from("side,mac,payload,packets,warmup,mean_ns,p50_ns,p99_ns,p99_9_ns,max_ns,gbps\n");

    // each side (sender/receiver) runs three times: without TESLA
    // ("none", the baseline) and with TESLA under each MAC algorithm
    let macs = [
        ("none", None),
        ("hmac", Some(TeslaMacAlg::HmacSha256)),
        ("gmac", Some(TeslaMacAlg::GmacAes128)),
    ];

    // one stream model per payload size, six variants each
    for &payload in &PAYLOADS {
        let model = StreamModel::new(payload, SSRC);
        println!("payload {payload} B, {PACKETS} packets per variant:");
        for (side, run) in [
            ("sender", true),
            ("receiver", false),
        ] {
            for (mac_name, mac) in macs {
                // the measurement itself: one full run of 1_000_000 packets
                let st = if run {
                    run_sender(&model, mac)
                } else {
                    run_receiver(&model, mac)
                };
                // the throughput
                let g = gbps(payload, st.mean_ns);
                println!(
                    "  {side:8} {mac_name:4}  mean {:8.1} ns  p50 {:6} ns  p99 {:6} ns  p99.9 {:7} ns  max {:8} ns  {g:6.2} Gbit/s",
                    st.mean_ns, st.p50_ns, st.p99_ns, st.p99_9_ns, st.max_ns
                );
                // one CSV row per variant
                csv.push_str(&format!(
                    "{side},{mac_name},{payload},{PACKETS},{WARMUP},{:.1},{},{},{},{},{:.3}\n",
                    st.mean_ns, st.p50_ns, st.p99_ns, st.p99_9_ns, st.max_ns, g
                ));
            }
        }
    }

    let path = format!("{dir}/raw.csv");
    fs::write(&path, csv).expect("cannot write CSV");
    println!("results written to {path}");
}
