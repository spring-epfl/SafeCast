//! The TESLA disclosure schedule and the receiver's per-packet accept
//! test.
//!
//! The sender slices its stream into short, equal time slots
//! called intervals, numbered 1, 2, 3, ... Each interval has its own MAC
//! key: packets sent during interval 5 are tagged with key number 5. The
//! whole schedule is three numbers, fixed before the stream starts and
//! known to every receiver: when interval 1 begins (`t0_ns`), how long
//! each interval lasts (`t_int_ns`), and how many intervals exist
//! (`n_chain`).
//!
//! Keys go public on a fixed delay: interval 5's key rides inside the
//! packets sent d intervals later (i.e., during interval 5 + d). A packet
//! claiming interval 5 is therefore only trustworthy if it arrived while
//! the sender could not yet have reached interval 5 + d. Any later, and
//! the key it was tagged with may already be public, so anyone could have
//! forged it. That check is the accept test defined in this module.

/// The verdict of the per-packet accept test, one variant per counter the
/// receiver keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntervalCheck {
    /// The key of this packet's interval is provably still secret, so we buffer it.
    Safe,
    /// The sender may already be disclosing this interval's key: the packet
    /// can no longer prove anything (TESLA's "unsafe" case).
    UnsafeLate,
}

/// The TESLA schedule of one stream: the interval timetable (when they
/// start, how long they last, how many exist), the disclosure delay d,
/// the clock bound D_t the safety test relies on, and the cap on hash
/// work per disclosed key.
#[derive(Debug, Clone, Copy)]
pub struct TeslaSchedule {
    /// Start of media interval 1 on the shared timebase.
    pub t0_ns: u64,
    /// Interval duration T_int in ns.
    pub t_int_ns: u64,
    /// Key disclosure delay d in intervals. Must be >= 2: with d = 1 a
    /// packet sent at the end of interval i has zero travel budget, since
    /// K_i's disclosure is due the moment the interval ends. Under
    /// ST 2022-7 dual-path delivery, d is additionally
    /// lower-bounded by the rescue path: packets rescued via path B arrive
    /// late by base + skew + jitter, and the travel budget for a packet
    /// sent at the end of its interval is (d-1)*T_int - D_t. So d must be
    /// sized such that this budget covers the rescue path's full delay,
    /// otherwise every rescued packet fails the safety test.
    pub d: u32,
    /// Last usable media interval (inclusive): the chain is K_0..=K_n_chain
    /// with K_0 the anchor.
    pub n_chain: u32,
    /// Upper bound D_t on how far the sender's clock can be ahead of the
    /// receiver's. The safety test reads the receiver's
    /// clock pessimistically as t + D_t.
    pub d_t_ns: u64,
    /// Misordering cap g: the most chain steps one
    /// disclosure may demand, bounding the hash work a forged interval
    /// index can force.
    pub g_max: u32,
}

impl TeslaSchedule {
    /// Creates the schedule.
    pub fn new(t0_ns: u64, t_int_ns: u64, d: u32, n_chain: u32, d_t_ns: u64, g_max: u32) -> Self {
        assert!(t_int_ns > 0, "interval duration must be positive");
        assert!(d >= 2, "d = 1 gives zero travel budget");
        assert!(n_chain >= 1, "the chain must contain at least one media interval");
        assert!(g_max >= 1, "a zero misordering cap rejects every disclosure");
        TeslaSchedule {
            t0_ns,
            t_int_ns,
            d,
            n_chain,
            d_t_ns,
            g_max,
        }
    }

    /// The media interval a packet sent at `send_ns` belongs to (sender
    /// side). Interval 1 starts at t0_ns.
    pub fn interval_of(&self, send_ns: u64) -> u32 {
        assert!(send_ns >= self.t0_ns, "send time before the stream start");
        let i = 1 + (send_ns - self.t0_ns) / self.t_int_ns;
        assert!(i <= self.n_chain as u64, "chain exhausted: interval {i} > {}", self.n_chain);
        i as u32
    }

    /// Which key a packet of `interval` carries: the one from d intervals
    /// ago. The first d intervals have no key that old yet, so they carry
    /// K_0 (index 0), which is public anyway.
    pub fn disclosed_index(&self, interval: u32) -> u32 {
        interval.saturating_sub(self.d)
    }

    /// Upper bound x on the media interval the sender can currently be in,
    /// judged pessimistically from the receiver's clock: the sender's clock
    /// is at most `arrival_ns + D_t`.
    pub fn sender_upper_bound(&self, arrival_ns: u64) -> u64 {
        // the sender's clock can be at most D_t ahead of the receiver's,
        // so right now it reads at most arrival time + D_t
        let sender_clock = arrival_ns.saturating_add(self.d_t_ns);
        // turning that clock reading into an interval number: time passed
        // since the stream start, divided by the interval length, plus 1
        // because intervals are numbered from 1
        1 + sender_clock.saturating_sub(self.t0_ns) / self.t_int_ns
    }

    /// The receiver's per-packet accept test for a packet labeled with
    /// `interval`, arriving at `arrival_ns` (receiver clock): the safety
    /// condition x < i + d.
    pub fn accepts(&self, arrival_ns: u64, interval: u32) -> IntervalCheck {
        // the latest interval the sender could be in right now
        let x = self.sender_upper_bound(arrival_ns);
        // safe only if the sender cannot yet have reached interval i + d,
        // the one in which it starts disclosing this packet's key
        if x < interval as u64 + self.d as u64 {
            IntervalCheck::Safe
        } else {
            IntervalCheck::UnsafeLate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Our example: T_int = 1 s, d = 2,
    /// D_t = 0.1 s, packet of media interval 6 (spanning 5 s..6 s of
    /// stream time).
    fn params() -> TeslaSchedule {
        TeslaSchedule::new(0, 1_000_000_000, 2, 100, 100_000_000, 16)
    }

    /// A packet of interval 6 is safe only while the sender cannot yet be
    /// in interval 8 (= 6 + d), where it starts disclosing key 6. With
    /// 1-second intervals, interval n is the n-th second of the stream and
    /// so spans n-1 s to n s: interval 8 starts at 7 s. Hence, an arrival
    /// before that moment must be accepted, and one after it must be
    /// rejected.
    #[test]
    fn safety_boundaries() {
        let p = params();
        // arrival at 6.4 s: the sender's clock reads at most 6.5 s, which
        // lies inside interval 7 -> not interval 8 yet, key 6 still secret
        assert_eq!(p.accepts(6_400_000_000, 6), IntervalCheck::Safe);
        // arrival at 7.2 s: the sender's clock reads at most 7.3 s, which
        // lies inside interval 8 -> key 6 may already be going out
        assert_eq!(p.accepts(7_200_000_000, 6), IntervalCheck::UnsafeLate);
    }

    /// The sender maps a packet's send time to its interval number, and
    /// an interval number to the key its packets carry. With 1-second
    /// intervals: everything sent in the first second belongs to
    /// interval 1, the second second to interval 2, and so on. And with
    /// d = 2, interval 3 is the first to carry a real past key (key 1);
    /// intervals 1 and 2 have no key from 2 intervals back, so they carry
    /// the public K_0.
    #[test]
    fn interval_assignment_and_disclosure() {
        let p = params();
        // sends at 0 s and just under 1 s: both in interval 1
        assert_eq!(p.interval_of(0), 1);
        assert_eq!(p.interval_of(999_999_999), 1);
        // a send at exactly 1 s: the first packet of interval 2
        assert_eq!(p.interval_of(1_000_000_000), 2);
        // intervals 1 and 2 carry K_0. Interval 3 is the first to
        // disclose a real key, the one of interval 1
        assert_eq!(p.disclosed_index(1), 0);
        assert_eq!(p.disclosed_index(2), 0);
        assert_eq!(p.disclosed_index(3), 1);
    }

}
