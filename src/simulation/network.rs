//! The simulated network: decides, for every sent packet, when it arrives
//! at the receiver, or that it is lost. Reordering emerges from the
//! arrival times, exactly as in a real network (a packet delayed
//! longer than the send spacing gets overtaken by later packets).
//!
//! The model is ST 2022-7 dual-path protection, the way broadcast
//! facilities run: every packet travels twice, over two independent paths.
//! Each copy arrives at send_time + the path's base delay + a per-packet
//! random jitter, unless the path's loss model drops it. The receiver-side
//! merge keeps whichever copy arrives first and drops the other. Hence, a packet
//! is lost only if both copies are lost. Setting `path_b: None` gives the
//! single-path mode (plain jitter + loss).
//!
//! Besides the arrivals themselves, the run reports how much displacement
//! (arriving out of place) actually happened, in both directions.
//! Backwards: a packet's lateness is how far its number lies behind the
//! highest packet number that arrived before it. Forwards: a gap is an
//! arrival jumping past packets that have not arrived yet. Lateness is
//! counted in packets, so what it demands in key history differs per
//! granularity. At packet-level every packet is its own generation, so a
//! late packet needs the key from lateness generations back. At
//! frame-level a generation spans thousands of packets, so the same
//! lateness usually stays inside its own frame and needs no old key.
//! Epoch-only has a single key regardless.
//!
//! One seeded RNG drives all randomness: the same seed and config
//! result in identical runs.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Loss behavior of one path.
#[derive(Clone, Copy, Debug)]
pub enum LossModel {
    /// No copy is ever lost on this path.
    None,
    /// Each copy is lost independently with probability `p` (isolated,
    /// single-packet losses; "iid loss" in the literature).
    Independent { p: f64 },
    /// Bursty loss (Gilbert-Elliott): the path is either GOOD (delivers
    /// everything) or BAD (drops everything), and may switch state. 
    /// Losses therefore come in runs of consecutive packets,
    /// like a switch buffer overflowing.
    GilbertElliott {
        p_good_to_bad: f64,
        p_bad_to_good: f64,
    },
}

/// One network path: fixed transit time, per-packet jitter, loss.
#[derive(Clone, Copy, Debug)]
pub struct PathConfig {
    /// Fixed transit time of this path in ns, which simulates the real travel
    /// time that every packet on this path pays. The per-packet jitter below comes on top of it.
    pub base_delay_ns: u64,
    /// Per-packet random extra delay: uniform in 0..=jitter_ns.
    pub jitter_ns: u64,
    /// Whether and how this path loses copies.
    pub loss: LossModel,
}

/// The whole network between sender and receiver.
#[derive(Clone, Copy, Debug)]
pub struct NetworkConfig {
    pub path_a: PathConfig,
    /// The second, redundant path (ST 2022-7). `None` = single-path mode.
    pub path_b: Option<PathConfig>,
    /// RNG seed: same seed + same config = bit-identical run.
    pub seed: u64,
}

/// How much displacement (arriving out of place) the delivered packets
/// actually experienced, in both directions. Backwards: a packet's
/// lateness is how far its number lies behind the highest packet number
/// that arrived before it. Forwards: a gap is an arrival jumping past
/// packets that have not arrived yet.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisplacementStats {
    /// Delivered packets that arrived out of order (lateness > 0).
    pub reordered: u64,
    /// The single worst lateness of the run.
    pub max_lateness: u64,
    /// Half of all delivered packets had lateness <= p50.
    pub p50: u64,
    /// 99% of all delivered packets had lateness <= p99.
    pub p99: u64,
    /// 99.9% of all delivered packets had lateness <= p99_9.
    pub p99_9: u64,
    /// Arrivals that jumped past at least one not-yet-arrived packet.
    pub gaps: u64,
    /// The largest number of packets such an arrival skipped over.
    pub max_gap: u64,
}

/// Ground-truth counters of one network run.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkStats {
    /// Packets the sender sent.
    pub sent: u64,
    /// Packets that reached the receiver.
    pub delivered: u64,
    /// Copies lost on path A/path B.
    pub lost_a: u64,
    pub lost_b: u64,
    /// Packets never delivered at all (dual-path: both copies lost;
    /// single-path: the one copy lost).
    pub lost_packets: u64,
    /// Deliveries per path: whose copy the receiver ended up with - the
    /// earlier one when both survived, the surviving one otherwise.
    /// In single-path mode every delivery counts as a path A win.
    pub wins_a: u64,
    pub wins_b: u64,
    /// Second copies dropped by the merge (both copies survived).
    pub duplicates_dropped: u64,
    /// The measured displacement of the delivered packets: how far behind
    /// packets arrived (lateness) and how far ahead they jumped (gaps).
    pub displacement: DisplacementStats,
}

/// Per-path loss state: the RNG decisions of one path's loss model.
struct LossState {
    model: LossModel,
    /// Gilbert-Elliott only: currently in the BAD (dropping) state.
    in_bad: bool,
}

impl LossState {
    fn new(model: LossModel) -> Self {
        // Gilbert-Elliott starts in the GOOD state
        LossState {
            model,
            in_bad: false,
        }
    }

    /// Decides whether the next copy on this path is lost.
    fn next_lost(&mut self, rng: &mut ChaCha20Rng) -> bool {
        match self.model {
            // this path never loses a copy
            LossModel::None => false,
            // independent coin flip per copy: random::<f64>() is uniform
            // in 0..1, so "< p" comes out true with probability p
            LossModel::Independent { p } => rng.random::<f64>() < p,
            LossModel::GilbertElliott {
                p_good_to_bad,
                p_bad_to_good,
            } => {
                // the current state decides this copy's fate: BAD loses it
                let lost = self.in_bad;
                // then the state may flip, which affects the NEXT copy
                if self.in_bad {
                    // leave BAD with probability p_bad_to_good, ending the
                    // loss run
                    if rng.random::<f64>() < p_bad_to_good {
                        self.in_bad = false;
                    }
                } else if rng.random::<f64>() < p_good_to_bad {
                    // enter BAD with probability p_good_to_bad,
                    // starting a new loss run
                    self.in_bad = true;
                }
                lost
            }
        }
    }
}

/// One copy's arrival time on one path, or None if the path lost it.
fn copy_arrival(
    path: &PathConfig,
    send_ns: u64,
    loss: &mut LossState,
    rng: &mut ChaCha20Rng,
) -> Option<u64> {
    if loss.next_lost(rng) {
        return None;
    }
    // transit = fixed base delay + this copy's random jitter
    Some(send_ns + path.base_delay_ns + rng.random_range(0..=path.jitter_ns))
}

/// Sends packets 0..n through the network. Returns what the receiver
/// gets: one `(arrival time, packet index)` pair per delivered packet,
/// ordered by arrival. Reading the list front to back
/// is reading the order the receivers gets the packets.
///
/// Parameters: `n` is how many packets the sender sends (indices 0..n).
/// `send_ns` maps a packet index to its send time in ns (for the media
/// stream that is `StreamModel::send_ns`; tests pass simpler functions).
/// `cfg` is the network itself: the path(s) with their delay, jitter and
/// loss, plus the RNG seed.
pub fn disturb(
    n: u64,
    send_ns: impl Fn(u64) -> u64,
    cfg: &NetworkConfig,
) -> (Vec<(u64, u64)>, NetworkStats) {

    // RNG for all randomness in this run
    let mut rng = ChaCha20Rng::seed_from_u64(cfg.seed);
    // per-path loss state (path B's only exists in dual-path mode)
    let mut loss_a = LossState::new(cfg.path_a.loss);
    let mut loss_b = cfg.path_b.map(|p| LossState::new(p.loss));

    // one (arrival time, packet index) entry per delivered packet,
    // sorted into arrival order at the end
    let mut schedule: Vec<(u64, u64)> = Vec::with_capacity(n as usize);
    let mut stats = NetworkStats {
        sent: n,
        ..Default::default()
    };

    // sending each packet over both paths (or one, in single-path mode)
    for i in 0..n {
        // when packet i leaves the sender
        let s = send_ns(i);
        // when the path A copy arrives (None if the path lost it)
        let a = copy_arrival(&cfg.path_a, s, &mut loss_a, &mut rng);
        // same for the path B copy, if a path B exists
        let b = match (&cfg.path_b, &mut loss_b) {
            (Some(path), Some(state)) => copy_arrival(path, s, state, &mut rng),
            _ => None,
        };

        match (a, b) {
            // both copies lost (single-path: the one copy lost)
            (None, None) => {

                // counting a loss on path A
                stats.lost_a += 1;
                // only counting a B loss if a path B existed at all
                if cfg.path_b.is_some() {
                    stats.lost_b += 1;
                }
                // no copy made it: the packet itself is gone
                stats.lost_packets += 1;
            }
            // only the A copy survived: it is delivered unopposed
            (Some(t), None) => {
                // only counting a B loss if a path B existed at all
                if cfg.path_b.is_some() {
                    stats.lost_b += 1;
                }
                // counting a win for path A
                stats.wins_a += 1;
                // the surviving copy is added to the schedule
                schedule.push((t, i));
            }
            // only the B copy survived: B rescued a packet A lost
            (None, Some(t)) => {
                // counting a loss on path A
                stats.lost_a += 1;
                // counting a win for path B
                stats.wins_b += 1;
                // the surviving copy is added to the schedule
                schedule.push((t, i));
            }
            // both survived: the earlier copy is delivered
            (Some(ta), Some(tb)) => {
                if ta <= tb {
                    // counting a win for path A
                    stats.wins_a += 1;
                } else {
                    // counting a win for path B
                    stats.wins_b += 1;
                }
                // the earlier copy is added to the schedule
                schedule.push((ta.min(tb), i));
                // the later copy is the duplicate the merge throws away
                stats.duplicates_dropped += 1;
            }
        }
    }

    // arrival order = sorting by arrival time
    schedule.sort_by_key(|&(t, _)| t);
    // everything that survived, counted after the merge
    stats.delivered = schedule.len() as u64;
    // lateness and gap statistics of the arrival order (see DisplacementStats)
    stats.displacement = measure_displacement(&schedule);

    (schedule, stats)
}

/// Walks the sorted schedule and measures each delivery's displacement in
/// both directions: its lateness (how far its index lies behind the
/// highest index delivered before it, where 0 = in order) and its gap (how many
/// not-yet-arrived packets it jumped over).
fn measure_displacement(schedule: &[(u64, u64)]) -> DisplacementStats {
    // one lateness value per delivered packet, filled during the walk
    let mut lateness: Vec<u64> = Vec::with_capacity(schedule.len());
    // highest packet index seen so far in arrival order
    let mut max_seen: Option<u64> = None;
    // forward jumps: arrivals that skipped packets, and the worst skip
    let mut gaps = 0;
    let mut max_gap = 0;
    for &(_, idx) in schedule {
        // this packet's lateness: how far behind the newest packet it is
        let d = match max_seen {
            // behind the newest delivered packet: late by the difference
            Some(m) if idx < m => m - idx,
            // not late
            _ => 0,
        };
        lateness.push(d);
        // how many not-yet-arrived packets this arrival jumped over
        let skipped = match max_seen {
            // very first arrival: packets 0..idx are all still missing
            None => idx,
            // ahead of the newest: the packets between them are missing
            // (idx right after the newest: nothing between, skipped = 0)
            Some(m) if idx > m => idx - m - 1,
            // behind the newest: this arrival jumped over nothing
            _ => 0,
        };
        if skipped > 0 {
            // a real jump: counting the event and tracking the worst one
            gaps += 1;
            max_gap = max_gap.max(skipped);
        }
        // a packet ahead of everything seen becomes the new reference
        if max_seen.is_none_or(|m| idx > m) {
            max_seen = Some(idx);
        }
    }

    // nothing was delivered at all: nothing to measure
    if lateness.is_empty() {
        return DisplacementStats::default();
    }
    // how many packets arrived out of order at all
    let reordered = lateness.iter().filter(|&&d| d > 0).count() as u64;
    // sorted, so position k holds the k-th smallest lateness
    lateness.sort_unstable();
    // nearest-rank percentile on the sorted lateness values
    let pct = |q: f64| lateness[((lateness.len() - 1) as f64 * q).round() as usize];
    DisplacementStats {
        reordered,
        // the largest value sits at the end of the sorted vec
        max_lateness: *lateness.last().unwrap(),
        // half of the packets are at or below this
        p50: pct(0.50),
         // 99% of the packets are at or below this
        p99: pct(0.99),
         // 99.9% of the packets are at or below this
        p99_9: pct(0.999),
        // the gap counters
        gaps,
        max_gap,
    }
}
