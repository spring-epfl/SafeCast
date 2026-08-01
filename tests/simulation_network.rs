//! Tests for the simulated network (sim::network). Covers: zero
//! disturbance changes nothing, the seed determines the run, jitter
//! creates reordering, the two loss models lose at their
//! configured rate and shape, the dual-path merge rescues and reorders,
//! duplicates are dropped, and a packet is lost only if both
//! copies are lost.

use mls_srtp_core::simulation::network::{disturb, LossModel, NetworkConfig, PathConfig};

/// Send times for the tests: one packet every 1000 ns. Not a realistic
/// pacing (1424 B packets of 1080p60 leave ~4578 ns apart), and it does
/// not have to be: the network model only adds delays to whatever send
/// times it is given, and every property tested here holds for any
/// spacing. A round number makes the expected values in the tests checkable by
/// hand. The real runs use StreamModel::send_ns, the realistic schedule.
const SPACING_NS: u64 = 1000;

/// Send time of packet i: packet 0 leaves at 0, packet 1 at 1000 ns, ...
/// (this is the `send_ns` function the tests hand to `disturb`).
fn send(i: u64) -> u64 {
    i * SPACING_NS
}

/// Base transit time of every test path: 50 us. A pure shift that all
/// packets get alike, so its exact value doesn't affect any assertion.
const BASE_DELAY_NS: u64 = 50_000;

/// A path with the given jitter and loss, base delay BASE_DELAY_NS.
fn path(jitter_ns: u64, loss: LossModel) -> PathConfig {
    PathConfig {
        base_delay_ns: BASE_DELAY_NS,
        jitter_ns,
        loss,
    }
}

/// Single-path network around one path config.
fn single(p: PathConfig, seed: u64) -> NetworkConfig {
    NetworkConfig {
        path_a: p,
        path_b: None,
        seed,
    }
}

/// No jitter, no loss, one path: every packet arrives, in send order, at
/// exactly send time + base delay, with zero displacement.
#[test]
fn zero_disturbance_changes_nothing() {
    // every packet is checked individually below, so a modest count suffices
    let n = 10_000;
    // jitter 0, loss None: the most boring network possible
    let (schedule, stats) = disturb(n, send, &single(path(0, LossModel::None), 7));
    // every single packet arrives
    assert_eq!(stats.delivered, n);
    assert_eq!(stats.lost_packets, 0);
    for (k, &(arrival, idx)) in schedule.iter().enumerate() {
        // send order preserved: k-th arrival is packet k
        assert_eq!(idx, k as u64);
        // arrival = send + base delay, nothing else
        assert_eq!(arrival, send(idx) + BASE_DELAY_NS);
    }
    // no packet ever arrives late
    assert_eq!(stats.displacement.max_lateness, 0);
    assert_eq!(stats.displacement.reordered, 0);
    // no packet ever jumps over another one
    assert_eq!(stats.displacement.gaps, 0);
    assert_eq!(stats.displacement.max_gap, 0);
}

/// The seed determines the run: same seed = identical schedule and stats,
/// different seed = different schedule.
#[test]
fn seed_determines_the_run() {
    // packets per run; every one gets its own jitter draw, so two runs
    // with different seeds cannot produce the same schedule by chance
    let n = 50_000;
    // a config with real randomness (jitter and loss), seed 42
    let cfg = single(path(10_000, LossModel::Independent { p: 0.01 }), 42);
    // running the identical config twice...
    let (sched_1, stats_1) = disturb(n, send, &cfg);
    let (sched_2, stats_2) = disturb(n, send, &cfg);
    // ...gives the identical result
    assert_eq!(sched_1, sched_2);
    assert_eq!(stats_1.delivered, stats_2.delivered);
    // a different seed draws different jitter/losses
    let other = NetworkConfig { seed: 43, ..cfg };
    let (sched_3, _) = disturb(n, send, &other);
    assert_ne!(sched_1, sched_3);
}

/// Jitter creates reordering.
/// With up to 10,000 ns of extra delay and packets 1000 ns apart, a packet
/// can be overtaken by at most 10 later packets.
#[test]
fn jitter_creates_bounded_reordering() {
    // enough packets that plenty of overtakes happen, some near the bound
    let n = 100_000;
    // single path: up to 10,000 ns extra delay per packet, no loss
    let (schedule, stats) = disturb(n, send, &single(path(10_000, LossModel::None), 1));
    // nothing is lost, order is disturbed
    assert_eq!(stats.delivered, n);
    assert!(stats.displacement.reordered > 0, "jitter must reorder");
    // lateness can never exceed jitter span/send spacing
    assert!(
        stats.displacement.max_lateness <= 10_000 / SPACING_NS,
        "lateness {} exceeds the physical bound",
        stats.displacement.max_lateness
    );
    // the schedule is sorted by arrival time
    assert!(schedule.windows(2).all(|w| w[0].0 <= w[1].0));
}

/// With loss probability p, about a fraction p of all packets actually
/// gets lost (here: 1% of 200,000 = ~2,000). And the counters add up:
/// every packet is either delivered or lost.
#[test]
fn loss_rate_and_conservation() {
    // sized so the expected loss count (~2,000) is statistically stable
    let n = 200_000;
    // single path, no jitter, each packet lost with probability 1%
    let (_, stats) = disturb(n, send, &single(path(0, LossModel::Independent { p: 0.01 }), 5));
    // conservation: every packet is either delivered or lost, none vanish
    assert_eq!(stats.delivered + stats.lost_packets, n);
    // expected losses: around 2000, depending on the RNG
    assert!(
        (1700..=2300).contains(&stats.lost_packets),
        "loss rate off: {} lost",
        stats.lost_packets
    );
}

/// Bursty (Gilbert-Elliott) loss loses several consecutive packets in a
/// row (a "run"). On average, a run is 1/p_bad_to_good packets long, here
/// 1/0.3 = ~3.3 packets. (The previous test's independent loss, in
/// contrast, loses isolated single packets.)
#[test]
fn bursty_loss_comes_in_runs() {
    // number of packets sized for ~300 loss runs (n x p_good_to_bad)
    let n = 300_000;
    // a loss run starts rarely (1 in 1000 packets) and then lasts
    // 1/0.3 = ~3.3 packets on average
    let loss = LossModel::GilbertElliott {
        p_good_to_bad: 0.001,
        p_bad_to_good: 0.3,
    };
    // no jitter, so delivered packets stay in send order and every loss
    // run shows up as a gap between consecutive delivered indices
    let (schedule, stats) = disturb(n, send, &single(path(0, loss), 11));
    // conservation: every packet is either delivered or lost, none vanish
    assert_eq!(stats.delivered + stats.lost_packets, n);
    // verifying the claim above
    assert!(
        schedule.windows(2).all(|w| w[0].1 < w[1].1),
        "without jitter, delivered indices must be strictly increasing"
    );

    // collecting the length of every loss run: walking the delivered indices
    // and recording how many packets are missing between each pair of
    // consecutive deliveries
    let mut runs: Vec<u64> = Vec::new();
    let mut prev: Option<u64> = None;
    for &(_, idx) in &schedule {
        if let Some(p) = prev {
            // delivered p, then delivered idx: the indices in between
            // (if any) were lost as one consecutive run
            if idx > p + 1 {
                runs.push(idx - p - 1);
            }
        }
        prev = Some(idx);
    }

    assert!(!runs.is_empty(), "no loss runs at all");

    // the average loss-run length over the whole stream
    let mean = runs.iter().sum::<u64>() as f64 / runs.len() as f64;
    // mean run length must be near 1/0.3 = 3.33 (band covers RNG noise)
    assert!(
        (2.6..=4.2).contains(&mean),
        "mean burst length {mean} not near 3.33"
    );

    // the tracked gap counters must agree with the runs found by this test:
    // each loss run makes exactly one arrival jump over exactly that many packets
    assert_eq!(stats.displacement.gaps, runs.len() as u64);
    assert_eq!(
        stats.displacement.max_gap,
        *runs.iter().max().unwrap()
    );
}

/// Dual path with a lossy path A and a slower lossless path B: every
/// packet still arrives (B rescues every A loss), and each rescued packet
/// arrives late by the skew.
/// When both copies survive, the merge keeps one and counts the twin.
#[test]
fn dual_path_rescues_and_reorders() {
    // sized for ~5,000 A losses (5% of n): plenty of rescues to check
    let n = 100_000;
    let cfg = NetworkConfig {
        // A loses 5% of copies, no jitter
        path_a: path(0, LossModel::Independent { p: 0.05 }),
        // B is identical but 5000 ns slower (the skew = 5 packet spacings)
        // and has no loss, so it rescues every A loss
        path_b: Some(PathConfig {
            base_delay_ns: BASE_DELAY_NS + 5 * SPACING_NS,
            jitter_ns: 0,
            loss: LossModel::None,
        }),
        seed: 3,
    };
    // sending everything through the dual-path network
    let (schedule, stats) = disturb(n, send, &cfg);
    // nothing is ever fully lost: B carries whatever A drops
    assert_eq!(stats.delivered, n);
    assert_eq!(stats.lost_packets, 0);
    // one entry per packet: the merge never delivers a packet twice
    assert_eq!(schedule.len() as u64, n);
    // every A loss is exactly one B win
    assert_eq!(stats.wins_b, stats.lost_a);
    // for the other n - lost_a packets both copies arrived (B loses
    // nothing), so each of them had its slower twin dropped by the merge
    assert_eq!(stats.duplicates_dropped, n - stats.lost_a);
    assert!(stats.lost_a > 0, "test needs some A losses to mean anything");
    // a rescued packet arrives 5 spacings late, so it is overtaken by at
    // most (and typically exactly) the 5 packets sent right after it
    assert!(stats.displacement.max_lateness <= 5);
    // and with thousands of rescues, at least some packets did arrive
    // out of order (otherwise the skew had no effect at all)
    assert!(stats.displacement.reordered > 0);
}

/// A packet is lost only if BOTH copies are lost.
#[test]
fn packet_lost_only_if_both_copies_lost() {
    // few packets suffice
    let n = 1_000;
    // a path that loses every single copy (p=1.0)
    let dead = LossModel::Independent { p: 1.0 };
    // A dead, B clean: all n arrive via B
    let cfg = NetworkConfig {
        path_a: path(0, dead),
        path_b: Some(path(0, LossModel::None)),
        seed: 2,
    };
    let (_, stats) = disturb(n, send, &cfg);
    // everything delivered, every delivery came from B
    assert_eq!(stats.delivered, n);
    assert_eq!(stats.wins_b, n);
    // A lost all its copies, yet not one packet was lost
    assert_eq!(stats.lost_a, n);
    assert_eq!(stats.lost_packets, 0);

    // both paths dead
    let cfg = NetworkConfig {
        path_a: path(0, dead),
        path_b: Some(path(0, dead)),
        seed: 2,
    };
    let (schedule, stats) = disturb(n, send, &cfg);
    // nothing delivered, all n counted as lost packets
    assert!(schedule.is_empty());
    assert_eq!(stats.lost_packets, n);
}
