//! Per-packet receiver cost under realistic delivery: the keying
//! granularities driven by the simulated network.
//!
//!   1. `sim::network::disturb` turns the stream's send times into an
//!      arrival order taking into account jitter, loss, and dual-path merge. 
//!      This happens before anything is timed.
//!   2. `SimulatedSender` produces the encrypted packet bytes, and can only
//!      do so in send order, like the real sender it models: its crypto
//!      state (the ratchet and libsrtp's counters) moves forward with every
//!      packet it encrypts, so packet i cannot be produced before packets
//!      0..i-1. Hence, when the arrival order asks for packet 583 while
//!      the sender stands at 570, packets 570..=583 are produced, and
//!      those whose arrival turn has not come yet wait in a stash.
//!   3. This bench walks the arrival order and feeds each packet to a
//!      `ReceiverKeyManager`, timing only the `unprotect` (decrypt) call.
//!
//! What one run reports:
//!   - Latency: mean/p50/p99/p99.9/max ns per decryption over the
//!     successful calls after the first --warmup calls (successful =
//!     a plaintext is returned. A fail means a drop, which is counted but not timed).
//!   - Throughput: implied by the latency mean, as packet-bits/mean.
//!   - Robustness: the keying-loss rate = receiver drops_behind/network
//!     delivered. Of the packets the network actually delivered, the
//!     fraction the receiver threw away because their key was already
//!     deleted.
//!   - (Correctness checks: the network's and the
//!     receiver's stats must match. Any failure means a
//!     simulator bug and aborts the run before numbers are printed.).
//!
//! Run (defaults = dual path, 100 us jitter per path, 1e-4 loss per copy, 2 ms path skew):
//!   cargo bench --package mls-srtp-core --bench realistic_receiver
//! Zero-disturbance run for the ideal-benchmark comparison:
//!   cargo bench --package mls-srtp-core --bench realistic_receiver -- \
//!       --jitter-ns 0 --loss 0 --single-path

use std::collections::HashMap;
use std::time::Instant;

use clap::Parser;

use mls_srtp_core::granularity::Granularity;
use mls_srtp_core::ratchet::{StreamRatchet, CHAIN_SECRET_LEN};
use mls_srtp_core::receiver::generation::GenerationScheme;
use mls_srtp_core::receiver::ReceiverKeyManager;
use mls_srtp_core::rtp::RTP_HEADER_LEN;
use mls_srtp_core::sim::network::{disturb, LossModel, NetworkConfig, PathConfig};
use mls_srtp_core::sim::sender::{SimulatedSender, StreamModel, FRAME_PERIOD, GCM_TAG_LEN, START_TS};

/// SSRC of the simulated stream.
const SSRC: u32 = 0xFEED_F00D;

/// Path A's fixed transit time. Path B adds the skew on top of the same
/// base, and a delay shared by both paths shifts every arrival equally.
/// This value is mostly to simulate a real transit time.
const BASE_DELAY_NS: u64 = 1_000_000;

/// A fixed 32-byte ratchet seed, used by sender and receiver alike so both
/// derive the same key chain.
fn ratchet_seed() -> Vec<u8> {
    (0..CHAIN_SECRET_LEN as u8).collect()
}

#[derive(Parser, Debug)]
#[command(about = "Receiver cost + keying loss under simulation")]
struct Args {
    /// keying granularity: epoch, frame or packet
    #[arg(long, default_value = "packet")]
    granularity: String,

    /// media payload bytes per packet (1424 = the standard ST 2110 size)
    #[arg(long, default_value_t = 1424)]
    payload: usize,

    /// packets to send. Default 1,000,000, so the p99.9 estimate rests on
    /// about 1,000 samples
    #[arg(long, default_value_t = 1_000_000)]
    packets: u64,

    /// per-path jitter in ns: each copy's random extra delay is uniform in
    /// 0..=this value
    #[arg(long, default_value_t = 100_000)]
    jitter_ns: u64,

    /// per-copy loss probability on each path (0 = lossless)
    #[arg(long, default_value_t = 1e-4)]
    loss: f64,

    /// path B's extra base delay over path A in ns (the ST 2022-7 skew)
    #[arg(long, default_value_t = 2_000_000)]
    skew_ns: u64,

    /// send over path A only: no ST 2022-7 dual-path redundancy and no merge
    #[arg(long)]
    single_path: bool,

    /// K: how many generation keys the receiver keeps (its ring size).
    /// At frame level a generation is a frame, so K counts frames there
    #[arg(long, default_value_t = 512)]
    key_window: usize,

    /// most ratchet steps one packet may demand at once (the work bound a
    /// forged packet cannot exceed), to protect against a DoS attack
    #[arg(long, default_value_t = 4096)]
    seek_cap: u64,

    /// replay window in packets: packets arriving more than this
    /// far behind the newest one are rejected. At packet-level keying it
    /// should be set to --key-window
    #[arg(long, default_value_t = 1024)]
    replay_window: u64,

    /// network RNG seed: same seed + same config -> identical run
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// arrivals processed before the timing stats start counting, so cold
    /// caches and CPU clock ramp-up stay out of the results
    #[arg(long, default_value_t = 50_000)]
    warmup: u64,

    /// hidden flag passed by `cargo bench` (ignored)
    #[arg(long, hide = true)]
    bench: bool,
}

/// Parsing the --granularity flag into the enum the receiver expects.
fn parse_granularity(s: &str) -> Granularity {
    match s {
        "epoch" => Granularity::EpochOnly,
        "frame" => Granularity::Frame,
        "packet" => Granularity::Packet,
        other => panic!("unknown granularity {other:?} (use epoch, frame or packet)"),
    }
}

/// The --loss flag as a loss model: 0 skips the loss,
/// anything else is the per-copy independent loss probability.
fn loss_model(p: f64) -> LossModel {
    if p == 0.0 {
        LossModel::None
    } else {
        LossModel::Independent { p }
    }
}

/// Mean of the measured decrypt times (one ns value per `unprotect` call).
fn mean_ns(samples: &[u64]) -> f64 {
    samples.iter().sum::<u64>() as f64 / samples.len() as f64
}

/// Percentile of the decrypt times. q is the fraction of calls to cover.
/// For instance, q = 0.99 gives the "p99", the time that 99% of the decrypts
/// stayed at or below. q = 0.5 gives the median.
fn pct(sorted: &[u64], q: f64) -> u64 {
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn main() {
    let args = Args::parse();
    let granularity = parse_granularity(&args.granularity);

    // ------------------------------------------------------------------
    // 1. Setup: the stream model and its two endpoints, keyed from the
    //    same ratchet seed
    // ------------------------------------------------------------------

    // the stream blueprint: given a packet index i it answers, by formula,
    // what that packet looks like (header fields, payload bytes) and when
    // it leaves the sender
    let model = StreamModel::new(args.payload, SSRC);

    // the encrypting side: hands out the model's packets one by one in
    // send order, rekeying at every `granularity` boundary with keys drawn
    // from the ratchet
    let mut sender =
        SimulatedSender::new(model, granularity, StreamRatchet::from_seed(ratchet_seed()));

    // How the receiver maps an arriving packet's header to a generation
    // (= which key decrypts it). The rule needs the stream's zero points,
    // and they must match where the sender starts counting. In our setup, 
    // the first frame carries timestamp START_TS and the first packet has index 0.
    let scheme = GenerationScheme::for_granularity(granularity, START_TS, FRAME_PERIOD, 0);

    // the receiver under test: decrypts whatever arrives, in arrival
    // order, keeping the last K generation keys. Seeded with the same
    // ratchet seed as the sender, so both derive the same key chain.
    // Also applies the seek-cap and replay-window limits.
    let mut receiver = ReceiverKeyManager::new(
        scheme,
        SSRC,
        StreamRatchet::from_seed(ratchet_seed()),
        args.key_window,
        args.seek_cap,
        args.replay_window,
    );

    // ------------------------------------------------------------------
    // 2. Network: send times in, arrival order out
    // ------------------------------------------------------------------

    // path A: the primary path, carrying one copy of every packet; the
    // configured jitter and loss act on top of the fixed transit time
    let path_a = PathConfig {
        base_delay_ns: BASE_DELAY_NS,
        jitter_ns: args.jitter_ns,
        loss: loss_model(args.loss),
    };

    // path B: the path of the redundant ST 2022-7 copy: same jitter and
    // loss level, but its transit time is longer by the skew. None in
    // single-path mode, which switches duplication off.
    let path_b = (!args.single_path).then_some(PathConfig {
        base_delay_ns: BASE_DELAY_NS + args.skew_ns,
        jitter_ns: args.jitter_ns,
        loss: loss_model(args.loss),
    });

    // the whole network between sender and receiver: the path(s), plus the
    // RNG seed driving every random decision (jitter and losses)
    let cfg = NetworkConfig {
        path_a,
        path_b,
        seed: args.seed,
    };

    // Pushing all packets through the network. We get back the arrival order
    // (one (arrival time, packet index) pair per delivered packet, sorted
    // by arrival) and stats about what the network did to the stream
    // (e.g., copies lost per path).
    let (schedule, net) = disturb(args.packets, |i| model.send_ns(i), &cfg);

    // ------------------------------------------------------------------
    // 3. Measurement loop: producing each arriving packet and benchmarking the
    //    decryption
    // ------------------------------------------------------------------

    // produced-but-not-yet-arrived packets, keyed by packet index
    let mut stash: HashMap<u64, Vec<u8>> = HashMap::new();

    // per-call decrypt times (ns) of the successful calls, split at the
    // warmup boundary: `warm` is reported but not part of the results,
    // `measured` is what the stats below are computed from
    let warmup = (args.warmup as usize).min(schedule.len());
    let mut warm: Vec<u64> = Vec::with_capacity(warmup);
    let mut measured: Vec<u64> = Vec::with_capacity(schedule.len() - warmup);

    // one unprotect per delivered packet, in arrival order
    for (call, &(_arrival_ns, i)) in schedule.iter().enumerate() {
        // untimed setup: fetching packet i's encrypted bytes. The sender only
        // produces in send order, so a late packet that arrives too early forces
        // production of everything sent before it (that hasn't arrived yet). Those 
        // go to the stash until their own arrival turn.
        let mut buf = match stash.remove(&i) {
            Some(b) => b,
            None => {
                // not in the stash, so not produced yet: i must still lie
                // ahead of the production cursor
                assert!(
                    sender.cursor() <= i,
                    "packet {i} neither stashed nor producible"
                );
                loop {
                    // producing the next packet in send order
                    let (j, b) = sender.next_protected();
                    // reached packet i: these are the bytes to feed below
                    // to the receiver
                    if j == i {
                        break b;
                    }
                    // a packet sent before i that has not arrived yet:
                    // stashed until its own arrival turn
                    stash.insert(j, b);
                }
            }
        };

        // the timed decrypt call of the receiver
        let t0 = Instant::now();
        let res = receiver.unprotect(&mut buf);
        let dt = t0.elapsed().as_nanos() as u64;

        // untimed bookkeeping: a successful decrypt contributes its time,
        // unless it is in the warmup phase
        match res {
            Ok(_) => {
                if call < warmup {
                    warm.push(dt);
                } else {
                    measured.push(dt);
                }
            }
            // drops are legitimate outcomes (key already deleted, replay,
            // or seek cap reached). RecvStats counted them and the
            // correctness checks below verify that everything adds up
            Err(_) => {}
        }
    }

    // everything the receiver counted, to be checked against the network's counters below
    let recv = receiver.stats();

    // ------------------------------------------------------------------
    // 4. Correctness checks: the network's counters and the receiver's
    //    counters match. Any mismatch means the simulator or the receiver miscounted,
    //    and no number below would be trustworthy.
    // ------------------------------------------------------------------

    // every packet the network delivered ended as exactly one receiver
    // outcome: decrypted or one of the four drop reasons
    let drops =
        recv.drops_behind + recv.drops_seek_cap + recv.drops_replay + recv.drops_auth;
    assert_eq!(
        net.delivered,
        recv.decrypted + drops,
        "ledger mismatch: network delivered vs receiver outcomes"
    );

    // the simulation never corrupts bytes, so authentication can only fail
    // through a real key/nonce bug: the auth-failure count must be 0 here
    assert_eq!(recv.drops_auth, 0, "auth failure on a genuine packet");

    // every generation 0..=frontier was derived exactly once, so the
    // derivation count must equal frontier + 1: catch-ups never re-derive,
    // no derivation was rolled back (drops_auth = 0, asserted above)
    let frontier_plus_one = receiver.frontier().map_or(0, |f| f + 1);
    assert_eq!(
        recv.catchup_steps, frontier_plus_one,
        "derivation count disagrees with the frontier"
    );

    // packet-level only: an arrival that jumped over s missing packets lands s + 1 generations past the
    // frontier, so the worst network jump and the worst receiver catch-up must agree exactly
    if matches!(granularity, Granularity::Packet) && recv.drops_seek_cap == 0 && net.delivered > 0
    {
        assert_eq!(
            recv.max_catchup,
            net.displacement.max_gap + 1,
            "worst catch-up disagrees with the worst network gap"
        );
    }

    // ------------------------------------------------------------------
    // 5. Results: the keying-loss rate and the timing statistics
    // ------------------------------------------------------------------

    // the K tradeoff: of the packets the network delivered, 
    // the fraction the receiver dropped because their key was already deleted
    let keying_loss = if net.delivered > 0 {
        recv.drops_behind as f64 / net.delivered as f64
    } else {
        0.0
    };

    assert!(
        !measured.is_empty(),
        "no successful decrypts after warmup: nothing to report (packets={}, warmup={})",
        args.packets,
        args.warmup
    );

    // mean of the measured decrypt times, in ns
    let mean_measured = mean_ns(&measured);

    // call order is no longer needed, we sort for the percentiles
    // calculated below 
    let mut sorted = measured;
    sorted.sort_unstable();
    
    // wire bytes per packet for the throughput calculation
    let wire_len = RTP_HEADER_LEN + args.payload + GCM_TAG_LEN;
    // throughput: bits-per-packet/ns-per-packet = Gbps
    let gbps = (wire_len as f64 * 8.0) / mean_measured;

    // ------------------------------------------------------------------
    // 6. Report
    // ------------------------------------------------------------------

    println!("== Realistic Receiver Report ==");

    // --- configuration ---

    // the stream configuration of this run
    println!(
        "config    granularity={} payload={} B packets={} seed={}",
        args.granularity, args.payload, args.packets, args.seed
    );

    // the network configuration: dual-path with skew, or single path
    match cfg.path_b {
        Some(b) => println!(
            "network   dual-path (ST 2022-7): jitter={} ns/path loss={} /copy skew={} ns",
            args.jitter_ns,
            args.loss,
            b.base_delay_ns - cfg.path_a.base_delay_ns
        ),
        None => println!(
            "network   single-path: jitter={} ns loss={}",
            args.jitter_ns, args.loss
        ),
    }

    // --- network stats ---

    // network ledger: what arrived, what was lost on which path, which
    // path's copy won the merge
    println!(
        "delivery  delivered={} lost_packets={} (copies lost: a={} b={}) wins a/b={}/{} duplicates_dropped={}",
        net.delivered,
        net.lost_packets,
        net.lost_a,
        net.lost_b,
        net.wins_a,
        net.wins_b,
        net.duplicates_dropped
    );
    let disp = net.displacement;
    // measured disorder of the arrivals: how far behind packets landed
    // (lateness) and how many not-yet-arrived packets an arrival jumped
    // over
    println!(
        "disorder  reordered={} lateness p50/p99/p99.9/max={}/{}/{}/{} gaps={} max_gap={}",
        disp.reordered, disp.p50, disp.p99, disp.p99_9, disp.max_lateness, disp.gaps, disp.max_gap
    );

    // --- receiver stats ---

    // the receiver's three limits
    println!(
        "limits    key_window K={} seek_cap={} replay_window={}",
        args.key_window, args.seek_cap, args.replay_window
    );

    // receiver ledger: every delivered packet's fate (decrypted, or which drop reason)
    println!(
        "outcome   decrypted={} drops: behind={} seek_cap={} replay={} auth={}",
        recv.decrypted, recv.drops_behind, recv.drops_seek_cap, recv.drops_replay, recv.drops_auth
    );

    // the receiver's work counters: key-ring hits, cipher installs,
    // ratchet derivations, worst single catch-up
    println!(
        "          cache_hits={} installs={} catchup_steps={} max_catchup={}",
        recv.cache_hits, recv.installs, recv.catchup_steps, recv.max_catchup
    );

    // the robustness result: of the delivered packets, the fraction lost
    // because their key was already deleted
    println!(
        "keying    loss rate = {}/{} = {:.3e}",
        recv.drops_behind, net.delivered, keying_loss
    );

    // --- timing ---

    // how many timing samples the stats below rest on, and what was
    // excluded as warmup
    println!(
        "timing    {} measured calls (first {} of {} arrivals skipped as warmup)",
        sorted.len(),
        warmup,
        schedule.len()
    );

    // the latency distribution and the throughput its mean implies
    println!(
        "          mean={:.1} ns p50={} p99={} p99.9={} max={} ns -> {:.2} Gbps at {} B wire",
        mean_measured,
        pct(&sorted, 0.50),
        pct(&sorted, 0.99),
        pct(&sorted, 0.999),
        sorted.last().unwrap(),
        gbps,
        wire_len
    );

    if !warm.is_empty() {
        // an empirical check whether warmup was effective
        println!(
            "warmup    warmup-region mean={:.1} ns vs measured mean={:.1} ns",
            mean_ns(&warm),
            mean_measured
        );
    }
}
