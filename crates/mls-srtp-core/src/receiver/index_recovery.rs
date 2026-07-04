//! RFC 3711 sequence-number index recovery: turning a wrapping 16-bit RTP
//! sequence number back into a packet's true position in the stream.

/// Recovers a packet's true position in the stream (the "extended sequence
/// index") from the 16-bit sequence number in its header (RFC 3711 §3.3.1).
///
/// Why we care: a realistic receiver simulation feeds it traces of 500k
/// to 5 million packets per run (the 16-bit seq counter wraps many
/// times within a single benchmark). Without this unwrapping, the first wrap
/// (~65k packets in, ~0.3 s of 1080p60) would make the receiver misread
/// "seq = 100" as generation 100 instead of 65636 and pick the wrong key. 
///
/// The problem: the header's seq field is only 16 bits, so it wraps back to 0
/// every 65536 packets. A packet saying "seq = 3" could therefore be at
/// position 3, or 65539 (= 65536 + 3), or 131075, ... - one candidate per
/// wrap ("rollover"). The true position is
/// `index = rollover_count * 65536 + seq`, but the rollover count is not in
/// the packet: the receiver must infer it.
///
/// The inference: packets do not teleport, so a new packet must be near the
/// newest one seen so far (a little ahead, or a reordered little behind).
/// Among the candidates, pick the one closest to the highest EXTENDED index seen.
/// Example: highest seen = 65530, "seq = 3" arrives; candidates are 3
/// (65527 behind) and 65539 (9 ahead). Clearly 65539 is the correct one, as 
/// the packet just crossed the wrap. `recover` is exactly this nearest-candidate choice,
/// written as RFC 3711 Appendix A's comparisons: only the previous, same, or
/// next rollover can ever be closest, and two tests decide which of the three it is.
#[derive(Debug, Default, Clone)]
pub struct IndexRecovery {
    /// Highest EXTENDED index among authenticated packets. None until the
    /// first packet authenticates.
    highest: Option<u64>,
}

impl IndexRecovery {
    /// Recovers the extended index of `seq`.
    pub fn recover(&self, seq: u16) -> u64 {

        // Before the first authenticated packet the index is `seq` itself.
        let Some(highest) = self.highest else {
            return seq as u64;
        };
        // splitting the highest index into its two halves:
        // roc = how many times the seq counter has wrapped so far,
        // s_l = the 16-bit seq of that highest packet (RFC 3711's names)
        let roc = highest >> 16;
        let s_l = (highest & 0xFFFF) as i32;
        let seq_i = seq as i32;
        // deciding which rollover the incoming seq belongs to: previous
        // (roc-1), same (roc), or next (roc+1) - whichever places it closest
        // to the highest extended index seen.
        let v = if s_l < 32_768 {
            // the newest packet sits in the LOWER half of the seq range,
            // meaning the counter wrapped recently
            if seq_i - s_l > 32_768 {
                // incoming seq is more than half the range ABOVE the newest:
                // "far ahead" is implausible, so it is really a late packet
                // from just BEFORE the recent wrap. The RFC computes
                // (roc-1) mod 2^32. At roc 0 no previous rollover exists in
                // this epoch, so the result stays at rollover 0.
                roc.saturating_sub(1)
            } else {
                // close to the newest packet: same rollover
                roc
            }
        } else if s_l - 32_768 > seq_i {
            // the newest packet sits in the UPPER half (a wrap is coming up)
            // and the incoming seq is more than half the range BELOW it:
            // "far behind" is implausible, so it is really the start of the
            // NEXT rollover (the counter just wrapped)
            roc + 1
        } else {
            // close to the newest packet: same rollover
            roc
        };
        // reassembling the full position: rollover count in the high bits,
        // the packet's own 16-bit seq in the low bits
        (v << 16) | seq as u64
    }

    /// Conditionally updates s_l and ROC from an authenticated packet's
    /// extended index. RFC 3711 §3.3.1 requires this to happen only "after
    /// the packet has been processed and authenticated" (Named after
    /// the RFC's "update" wording; unrelated to MLS commits.)
    pub fn update(&mut self, index: u64) {
        if self.highest.is_none_or(|h| index > h) {
            self.highest = Some(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no packet seen yet, there is no "highest index" to
    /// compare against, so we just return
    /// the raw sequence number (i.e. rollover count 0).
    #[test]
    fn index_recovery_cold_start() {
        let rec = IndexRecovery::default();
        // nothing recorded yet -> the index is the seq value itself
        assert_eq!(rec.recover(0), 0);
        assert_eq!(rec.recover(500), 500);
    }

    /// A packet stays in the current rollover when its seq number is near the
    /// last-seen one: when the two 16-bit numbers differ by less than half
    /// the range (32_768). Note "differ" means plain subtraction of the two seq
    /// values, which is NOT the same as how many packets apart they are. Right
    /// at a wrap, one packet reads 65_535 and the next reads 0: physically just
    /// 1 packet apart, but 65_535 - 0 = 65_535 apart in raw value (the counter
    /// jumped from 65_535 down to 0). That big raw-value gap is what makes the
    /// code infer a new rollover. Here every seq is within 10 of the 40_000
    /// reference, so the gap is tiny -> same rollover, index == seq.
    #[test]
    fn index_recovery_within_rollover() {
        let mut rec = IndexRecovery::default();
        // last packet seen was number 40_000
        rec.update(40_000);
        // 40_010 is 10 ahead of 40_000: tiny gap, no wrap, so index = 40_010
        assert_eq!(rec.recover(40_010), 40_010);
        // 39_990 is 10 behind (a reordered packet): still no wrap, index = 39_990
        assert_eq!(rec.recover(39_990), 39_990);
    }

    /// Both directions across a 65_536-packet wrap resolve to the right
    /// rollover: forward past the wrap, a late packet from just before the wrap, 
    /// and a small late packet once we are already in rollover 1.
    #[test]
    fn index_recovery_across_wrap() {
        let mut rec = IndexRecovery::default();
        // reference is 65_530 in rollover 0, near the wrap
        rec.update(65_530);
        // seq 3 is far below the reference: reading it in rollover 0 (index 3)
        // would be a huge jump back, so it is the start of rollover 1
        assert_eq!(rec.recover(3), 65_536 + 3);
        // now we move the reference just past the wrap, into rollover 1 (seq 2)
        rec.update(65_536 + 2);
        // seq 65_534 arriving now is a late packet from BEFORE the wrap: reading
        // it in rollover 1 would be a huge jump forward, so it stays rollover 0
        assert_eq!(rec.recover(65_534), 65_534);
        // seq 50 is close to the rollover-1 reference: it stays in rollover 1
        assert_eq!(rec.recover(50), 65_536 + 50);
    }
}
