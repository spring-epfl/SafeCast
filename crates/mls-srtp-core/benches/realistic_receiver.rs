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
//!   - Path attribution: the latency stats above say how slow the calls
//!     were, but not which calls were slow or why. For instance, are the slowest
//!     packets (the p99.9 and above) the ones that derived many keys at
//!     once? Why does disturbance change the mean? To answer such
//!     questions from data instead of guesses, every successful decrypt
//!     is classified by the generation g it reports vs the highest g
//!     seen so far (advance = derived new keys, current = newest key
//!     reused, straggler = old key served a late packet), and the timing
//!     is reported per class. Advances are additionally split by depth =
//!     how many keys that one call derived, showing how the cost grows 
//!     with the keys derived.
//!   - (Correctness checks: the network's and the
//!     receiver's stats must match. Any failure means a
//!     simulator bug and aborts the run before numbers are printed.)
//!
//! Run (defaults = dual path, 100 us jitter per path, 1e-4 loss per copy, 2 ms path skew):
//!   cargo bench --package mls-srtp-core --bench realistic_receiver
//! Zero-disturbance run for the ideal-benchmark comparison:
//!   cargo bench --package mls-srtp-core --bench realistic_receiver -- \
//!       --jitter-ns 0 --loss 0 --single-path

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use clap::Parser;

use mls_srtp_core::granularity::Granularity;
use mls_srtp_core::ratchet::{StreamRatchet, CHAIN_SECRET_LEN};
use mls_srtp_core::receiver::generation::GenerationScheme;
use mls_srtp_core::receiver::{ReceiverKeyManager, RecvStats};
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
    #[arg(long, default_value_t = 512)]
    replay_window: u64,

    /// network RNG seed: same seed + same config -> identical run
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// arrivals processed before the timing stats start counting, so cold
    /// caches and CPU clock ramp-up stay out of the results.
    /// TODO: warmup=0 gives the same stats as warmup=200000. Maybe because 
    /// disturb() runs before the timed loop and warms the CPU/caches. Might 
    /// be worth removing this flag.
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

/// The granularity's name, as printed in reports and CSV rows.
fn gran_label(g: Granularity) -> &'static str {
    match g {
        Granularity::EpochOnly => "epoch",
        Granularity::Frame => "frame",
        Granularity::Packet => "packet",
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

/// Everything that defines one run. The single-run mode fills this from
/// the command-line flags, the sweep constructs one per configuration.
struct RunConfig {
    granularity: Granularity, // keying granularity: epoch, frame or packet
    payload: usize,           // media payload bytes per packet
    packets: u64,             // number of packets to send
    jitter_ns: u64,           // per-path jitter: each copy's random extra delay is uniform in 0..=this
    loss: f64,                // per-copy loss probability on each path
    skew_ns: u64,             // path B's extra base delay over path A (ST 2022-7)
    single_path: bool,        // path A only: no dual-path redundancy and no merge
    key_window: usize,        // K: how many generation keys the receiver keeps (its ring size)
    seek_cap: u64,            // most ratchet steps one packet may demand at once
    replay_window: u64,       // packets more than this far behind the newest one are rejected
    seed: u64,                // network RNG seed: same seed and config give an identical run
    warmup: u64,              // arrivals processed before the timing stats start counting
}

/// Timing summary of one kind of successful decrypt:
/// advance (derived new keys), current (reused the newest key) or
/// straggler (an old key served a late packet). This struct holds one
/// kind's timing: how many calls it had, their mean, p99 and max.
/// n = 0 means no call of that kind occurred in the run.
struct ClassSummary {
    n: usize,
    mean: f64,
    p99: u64,
    max: u64,
}

/// Builds the ClassSummary of one kind: takes the decrypt times the
/// measurement loop collected for that kind (advance, current or
/// straggler) and computes their count, mean, p99 and max.
fn summarize_class(mut times: Vec<u64>) -> ClassSummary {
    if times.is_empty() {
        return ClassSummary { n: 0, mean: 0.0, p99: 0, max: 0 };
    }
    let mean = mean_ns(&times);
    // pct() picks percentiles by index into a sorted list, so we sort first
    times.sort_unstable();
    ClassSummary {
        n: times.len(),
        mean,
        p99: pct(&times, 0.99),
        max: *times.last().unwrap(),
    }
}

/// Everything one run produced. `print_report` prints this and
/// `csv_row` renders it as one CSV line.
struct Outcome {
    /// The network's ground-truth counters (delivery, losses, disorder).
    net: NetworkStats,
    /// The receiver's counters (outcomes per packet, work done).
    recv: RecvStats,
    /// How many packets the arrival schedule contained.
    arrivals: usize,
    /// How many arrivals were skipped as warmup.
    warmup_used: usize,
    /// The keying-loss rate: drops/delivered.
    keying_loss: f64,
    /// Of the delivered packets, the fraction not decrypted for any reason.
    undecrypted: f64,
    /// Bytes of one packet on the wire (header + payload + tag).
    wire_len: usize,
    /// Throughput implied by the mean: wire_bits/mean = Gbps.
    gbps: f64,
    /// The measured decrypt times summarized.
    measured_n: usize,
    mean_ns: f64,
    p50: u64,
    p99: u64,
    p999: u64,
    max: u64,
    /// The warmup region's sample count and mean (None when warmup was 0).
    warm_n: usize,
    warm_mean: Option<f64>,
    /// Path attribution: per-class timing summaries.
    advance: ClassSummary,
    current: ClassSummary,
    straggler: ClassSummary,
    /// depth -> (how many advances derived that many keys, their ns summed).
    depth_stats: BTreeMap<u64, (u64, u64)>,
}

/// Runs one full measurement: builds the stream, disturbs it, walks the
/// arrival order timing each `unprotect`, verifies the counters, and
/// returns everything as an `Outcome`. Panics when a correctness check
/// fails, so no untrustworthy numbers can be reported.
fn run(cfg: &RunConfig) -> Outcome {
    // ------------------------------------------------------------------
    // 1. Setup: the stream model and its two endpoints, keyed from the
    //    same ratchet seed
    // ------------------------------------------------------------------

    // the stream blueprint: given a packet index i it answers, by formula,
    // what that packet looks like (header fields, payload bytes) and when
    // it leaves the sender
    let model = StreamModel::new(cfg.payload, SSRC);

    // the encrypting side: hands out the model's packets one by one in
    // send order, rekeying at every `granularity` boundary with keys drawn
    // from the ratchet
    let mut sender =
        SimulatedSender::new(model, cfg.granularity, StreamRatchet::from_seed(ratchet_seed()));

    // How the receiver maps an arriving packet's header to a generation
    // (= which key decrypts it). The rule needs the stream's zero points,
    // and they must match where the sender starts counting. In our setup, 
    // the first frame carries timestamp START_TS and the first packet has index 0.
    let scheme = GenerationScheme::for_granularity(cfg.granularity, START_TS, FRAME_PERIOD, 0);

    // the receiver under test: decrypts whatever arrives, in arrival
    // order, keeping the last K generation keys. Seeded with the same
    // ratchet seed as the sender, so both derive the same key chain.
    // Also applies the seek-cap and replay-window limits.
    let mut receiver = ReceiverKeyManager::new(
        scheme,
        SSRC,
        StreamRatchet::from_seed(ratchet_seed()),
        cfg.key_window,
        cfg.seek_cap,
        cfg.replay_window,
    );

    // ------------------------------------------------------------------
    // 2. Network: send times in, arrival order out
    // ------------------------------------------------------------------

    // path A: the primary path, carrying one copy of every packet; the
    // configured jitter and loss act on top of the fixed transit time
    let path_a = PathConfig {
        base_delay_ns: BASE_DELAY_NS,
        jitter_ns: cfg.jitter_ns,
        loss: loss_model(cfg.loss),
    };

    // path B: the path of the redundant ST 2022-7 copy: same jitter and
    // loss level, but its transit time is longer by the skew. None in
    // single-path mode, which switches duplication off.
    let path_b = (!cfg.single_path).then_some(PathConfig {
        base_delay_ns: BASE_DELAY_NS + cfg.skew_ns,
        jitter_ns: cfg.jitter_ns,
        loss: loss_model(cfg.loss),
    });

    // the whole network between sender and receiver: the path(s), plus the
    // RNG seed driving every random decision (jitter and losses)
    let net_cfg = NetworkConfig {
        path_a,
        path_b,
        seed: cfg.seed,
    };

    // Pushing all packets through the network. We get back the arrival order
    // (one (arrival time, packet index) pair per delivered packet, sorted
    // by arrival) and stats about what the network did to the stream
    // (e.g., copies lost per path).
    let (schedule, net) = disturb(cfg.packets, |i| model.send_ns(i), &net_cfg);

    // ------------------------------------------------------------------
    // 3. Measurement loop: producing each arriving packet and benchmarking the
    //    decryption
    // ------------------------------------------------------------------

    // produced-but-not-yet-arrived packets, keyed by packet index
    let mut stash: HashMap<u64, Vec<u8>> = HashMap::new();

    // per-call decrypt times (ns) of the successful calls, split at the
    // warmup boundary: `warm` is reported but not part of the results,
    // `measured` is what the stats below are computed from
    let warmup = (cfg.warmup as usize).min(schedule.len());
    let mut warm: Vec<u64> = Vec::with_capacity(warmup);
    let mut measured: Vec<u64> = Vec::with_capacity(schedule.len() - warmup);

    // Path attribution.
    //   g above max_g = advance   (this call derived new keys)
    //   g equal       = current   (the key is reused)
    //   g below       = straggler (a late packet served by an old key)
    // We keep one list of decrypt times per kind. Advances are
    // additionally grouped by their depth (= keys derived by that call).
    // depth_stats maps each depth to how many advances had it and to the
    // total of their decrypt times, from which the report computes the
    // mean cost per depth.
    let mut max_g: Option<u64> = None;
    let mut advance_times: Vec<u64> = Vec::new();
    let mut current_times: Vec<u64> = Vec::new();
    let mut straggler_times: Vec<u64> = Vec::new();
    // depth -> (how many advances had that depth, their decrypt ns summed)
    // BTreeMap so the report iterates depths in ascending order "for free"
    let mut depth_stats: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

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
            Ok(g) => {
                if call < warmup {
                    warm.push(dt);
                } else {
                    measured.push(dt);
                }

                // path attribution: classifying this call by g vs max_g
                match max_g {
                    // straggler: an old key served this late packet
                    Some(m) if g < m => {
                        if call >= warmup {
                            straggler_times.push(dt);
                        }
                    }
                    // current: the newest key reused
                    Some(m) if g == m => {
                        if call >= warmup {
                            current_times.push(dt);
                        }
                    }
                    // advance: g lies above everything seen (or is the
                    // first packet), so this call derived new keys (depth
                    // is how many)
                    _ => {
                        let depth = match max_g {
                            Some(m) => g - m,
                            // first packet: generations 0..=g were derived
                            None => g + 1,
                        };
                        if call >= warmup {
                            advance_times.push(dt);
                            // this depth's entry, created as (0, 0) on
                            // its first advance
                            let e = depth_stats.entry(depth).or_insert((0, 0));
                            // one more advance call of this depth
                            e.0 += 1;
                            // and its decrypt time is added to the total
                            e.1 += dt;
                        }
                        max_g = Some(g);
                    }
                }
            }
            // drops are legitimate outcomes (key already deleted, replay,
            // or seek cap reached). RecvStats counted them and the
            // correctness checks below verify that everything adds up
            Err(_) => {}
        }
    }

    // everything the receiver counted, to be checked against the network's counters below
    let recv = receiver.stats().clone();

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
    if matches!(cfg.granularity, Granularity::Packet)
        && recv.drops_seek_cap == 0
        && net.delivered > 0
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

    // the all-cause failure rate: of the delivered packets, the fraction
    // not decrypted for any reason (key deleted, replay window, seek cap).
    // Unlike keying_loss it does not depend on which check caught a packet
    let undecrypted = if net.delivered > 0 {
        (net.delivered - recv.decrypted) as f64 / net.delivered as f64
    } else {
        0.0
    };

    assert!(
        !measured.is_empty(),
        "no successful decrypts after warmup: nothing to report (packets={}, warmup={})",
        cfg.packets,
        cfg.warmup
    );

    // mean of the measured decrypt times, in ns
    let mean_measured = mean_ns(&measured);

    // call order is no longer needed, we sort for the percentiles
    // calculated below 
    let mut sorted = measured;
    sorted.sort_unstable();

    // wire bytes per packet for the throughput calculation
    let wire_len = RTP_HEADER_LEN + cfg.payload + GCM_TAG_LEN;
    // throughput: bits-per-packet/ns-per-packet = Gbps
    let gbps = (wire_len as f64 * 8.0) / mean_measured;

    Outcome {
        net,
        recv,
        arrivals: schedule.len(),
        warmup_used: warmup,
        keying_loss,
        undecrypted,
        wire_len,
        gbps,
        measured_n: sorted.len(),
        mean_ns: mean_measured,
        p50: pct(&sorted, 0.50),
        p99: pct(&sorted, 0.99),
        p999: pct(&sorted, 0.999),
        max: *sorted.last().unwrap(),
        warm_n: warm.len(),
        warm_mean: (!warm.is_empty()).then(|| mean_ns(&warm)),
        advance: summarize_class(advance_times),
        current: summarize_class(current_times),
        straggler: summarize_class(straggler_times),
        depth_stats,
    }
}


/// Prints the full single-run report.
fn print_report(cfg: &RunConfig, out: &Outcome) {
    println!("== Realistic Receiver Report ==");

    // --- configuration ---

    // the stream configuration of this run
    println!(
        "config    granularity={} payload={} B packets={} seed={}",
        gran_label(cfg.granularity),
        cfg.payload,
        cfg.packets,
        cfg.seed
    );

    // the network configuration: dual-path with skew, or single path
    if cfg.single_path {
        println!(
            "network   single-path: jitter={} ns loss={}",
            cfg.jitter_ns, cfg.loss
        );
    } else {
        println!(
            "network   dual-path (ST 2022-7): jitter={} ns/path loss={} /copy skew={} ns",
            cfg.jitter_ns, cfg.loss, cfg.skew_ns
        );
    }

    // --- network stats ---

    // network ledger: what arrived, what was lost on which path, which
    // path's copy won the merge
    println!(
        "delivery  delivered={} lost_packets={} (copies lost: a={} b={}) wins a/b={}/{} duplicates_dropped={}",
        out.net.delivered,
        out.net.lost_packets,
        out.net.lost_a,
        out.net.lost_b,
        out.net.wins_a,
        out.net.wins_b,
        out.net.duplicates_dropped
    );
    let disp = out.net.displacement;
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
        cfg.key_window, cfg.seek_cap, cfg.replay_window
    );

    // receiver ledger: every delivered packet's fate (decrypted, or which drop reason)
    println!(
        "outcome   decrypted={} drops: behind={} seek_cap={} replay={} auth={}",
        out.recv.decrypted,
        out.recv.drops_behind,
        out.recv.drops_seek_cap,
        out.recv.drops_replay,
        out.recv.drops_auth
    );

    // the receiver's work counters: key-ring hits, cipher installs,
    // ratchet derivations, worst single catch-up
    println!(
        "          cache_hits={} installs={} catchup_steps={} max_catchup={}",
        out.recv.cache_hits, out.recv.installs, out.recv.catchup_steps, out.recv.max_catchup
    );

    // Path attribution: per-class timing of the successful decrypts.
    // Prints one line of timing stats for one class's summary: how many
    // calls, their mean, p99 and max.
    let class_line = |name: &str, c: &ClassSummary| {
        // a class that never occurred in this run (e.g. stragglers in a
        // zero-disturbance run) is still printed as n=0
        if c.n == 0 {
            println!("{name} n=0");
        } else {
            println!(
                "{name} n={} mean={:.1} ns p99={} ns max={} ns",
                c.n, c.mean, c.p99, c.max
            );
        }
    };
    // One line per class. The second and third name start with spaces so
    // their columns line up under the "paths" label.
    class_line("paths     advance   (g above max, derives keys):", &out.advance);
    class_line("          current   (g equals max, key reused): ", &out.current);
    class_line("          straggler (g below max, old key):     ", &out.straggler);

    // advances broken down by depth (keys derived by that one call):
    // count and mean per depth, so the cost growth with depth is visible
    if !out.depth_stats.is_empty() {
        // collecting one text piece per depth, smallest depth first
        let depths: Vec<String> = out
            .depth_stats
            .iter()
            // d = the depth, n = advance calls of that depth, sum = their
            // decrypt times added up --> sum/n = the mean cost at that depth
            .map(|(d, (n, sum))| format!("d={d}: n={n} mean={:.0} ns", *sum as f64 / *n as f64))
            .collect();
        // all pieces on one report line, e.g.:
        //   depths    d=1: n=261 mean=1300 ns; d=2: n=14 mean=1937 ns
        println!("depths    {}", depths.join("; "));
    }

    // the robustness result: of the delivered packets, the fraction lost
    // because their key was already deleted
    println!(
        "keying    loss rate = {}/{} = {:.3e}",
        out.recv.drops_behind, out.net.delivered, out.keying_loss
    );

    // --- timing ---

    // how many timing samples the stats below rest on, and what was
    // excluded as warmup
    println!(
        "timing    {} measured calls (first {} of {} arrivals skipped as warmup)",
        out.measured_n, out.warmup_used, out.arrivals
    );

    // the latency distribution and the throughput its mean implies
    println!(
        "          mean={:.1} ns p50={} p99={} p99.9={} max={} ns -> {:.2} Gbps at {} B wire",
        out.mean_ns, out.p50, out.p99, out.p999, out.max, out.gbps, out.wire_len
    );

    if let Some(warm_mean) = out.warm_mean {
        // an empirical check whether warmup was effective
        println!(
            "warmup    warmup-region mean={:.1} ns vs measured mean={:.1} ns",
            warm_mean, out.mean_ns
        );
    }
}

        );
/// Entry point. Two modes: --sweep runs the whole measurement grid and
/// exports to a CSV, everything else is one run of one configuration with the
/// report printed.
fn main() {
    // the command-line flags, with defaults for everything not given
    let args = Args::parse();

    // single-run mode: the flags become the one configuration to measure
    let cfg = RunConfig {
        granularity: parse_granularity(&args.granularity),
        payload: args.payload,
        packets: args.packets,
        jitter_ns: args.jitter_ns,
        loss: args.loss,
        skew_ns: args.skew_ns,
        single_path: args.single_path,
        key_window: args.key_window,
        seek_cap: args.seek_cap,
        replay_window: args.replay_window,
        seed: args.seed,
        warmup: args.warmup,
    };

    // the measurement itself: builds the stream, disturbs it, and 
    // times every decrypt
    let out = run(&cfg);

    // the full human-readable report on stdout
    print_report(&cfg, &out);

    // a single run appends to tahe CSV when asked
    if let Some(path) = &args.csv {
        append_csv(path, &csv_row("single", &cfg, &out, 1, screen_ok(&out)));
    }
}
