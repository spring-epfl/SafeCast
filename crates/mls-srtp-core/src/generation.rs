//! Receiver-side mapping from a packet's header to its generation index `g`.
//!
//! A generation index `g` is a counter (0, 1, 2, ...) that resets to 0 at the
//! start of each epoch and selects that generation's SRTP key. Both ends must
//! compute the same `g` for a packet, or they derive different SRTP keys.
//! The sender gets `g` implicitly (it rekeys at each boundary it emits, see
//! [`crate::granularity`]). However, the receiver sees packets possibly out of order,
//! so it must compute `g` from each packet's header alone. [`GenerationScheme`]
//! is that rule, one variant per keying granularity.
//!
//! Frame-level works from the RTP timestamp: the timestamp is tied to the
//! shared PTP clock, so both ends agree on `g` for free. A per-packet `g`
//! instead has to come from the packet's sequence number, which is not tied
//! to that clock. Hence, the receiver cannot work out where the epoch's
//! packet counting started just from the timestamp, the way it can for
//! frames. That case needs the epoch's starting index (`base`) handed over
//! explicitly, plus [`crate::index_recovery::IndexRecovery`] to unwrap the
//! 16-bit sequence number.

use crate::granularity::Granularity;

/// How a packet is mapped to its generation index `g`.
///
/// Why this exists next to [`Granularity`]: Granularity is an enum
/// (epoch-only/frame/packet) with no data in its variants. That is enough for
/// the sender: at frame-level it remembers the previous packet's timestamp
/// and rekeys when it changes, and at packet-level it rekeys on every packet.
/// The receiver, however, sees packets possibly out of order, so "the
/// previous packet" means nothing there. It instead computes each packet's
/// generation number from the header, and for that the variants must carry
/// data: Frame needs the epoch's starting timestamp and the ticks per frame,
/// Packet needs the index the epoch started at (base). GenerationScheme is
/// the enum whose variants carry those numbers.
#[derive(Debug, Clone, Copy)]
pub enum GenerationScheme {
    /// One key for the whole epoch: every packet is generation 0.
    EpochOnly,
    /// One key per video frame: `g` is derived from the RTP timestamp
    /// (see [`frame_generation`]).
    Frame {
        /// Timestamp of the epoch's first frame (the zero point).
        epoch_start_ts: u32,
        /// RTP timestamp ticks per frame (clock rate/frame rate),
        /// e.g. 90000/60 = 1500 ticks for 60 fps video.
        /// (90000 is the standard RTP clock rate for video)
        frame_period: u32,
    },
    /// One key per packet: `g = extended sequence index - base`, where the
    /// extended index is recovered from the 16-bit RTP sequence number by
    /// [`crate::index_recovery::IndexRecovery`] and `base` is the extended
    /// index of the epoch's first packet.
    Packet {
        /// Extended index of the epoch's first packet.
        base: u64,
    },
}

impl GenerationScheme {
    /// Builds the receiver-side scheme matching a sender granularity, filling
    /// in the reference points the receiver needs: `epoch_start_ts` and
    /// `frame_period` for frame-level, `base` for packet-level (the epoch-only
    /// scheme needs none).
    pub fn for_granularity(
        granularity: Granularity,
        epoch_start_ts: u32,
        frame_period: u32,
        base: u64,
    ) -> Self {
        match granularity {
            Granularity::EpochOnly => GenerationScheme::EpochOnly,
            Granularity::Frame => GenerationScheme::Frame {
                epoch_start_ts,
                frame_period,
            },
            Granularity::Packet => GenerationScheme::Packet { base },
        }
    }
}

/// Frame-level rekeying generation index `g`: which frame of the current epoch a packet
/// belongs to.
///
/// The RTP timestamp is a counter that ticks at a fixed rate. For video, that is 90000
/// ticks per second, the 90 kHz RTP clock. Sources:
/// - RFC 3551 section 5: "All of these video encodings use an RTP timestamp frequency
/// of 90,000 Hz"
/// - RFC 4175, the uncompressed-video format ST 2110 uses, requires its `rate`
/// parameter to be 90000).
/// Every packet of one video frame carries the same timestamp. The parameter `frame_period`
/// is how many ticks the timestamp advances from one frame to the next, that is,
/// clock rate / frame rate, e.g. 90000 / 60 = 1500 ticks at 60 fps. So the timestamp's
/// distance from the epoch's first frame, divided by `frame_period`, counts the frames
/// since then, which is `g`. All packets of a frame share a timestamp, so they map to
/// the same `g`, and `g` steps by one at each frame boundary.
///
/// The parameter `epoch_start_ts` is the timestamp of the current epoch's first
/// frame (the zero point). At that frame `ts == epoch_start_ts`, so the result is
/// 0 and `g` is 0. `g` then grows through the epoch. Each new epoch passes a new
/// `epoch_start_ts`, so `g` counts from 0 again within every epoch. This matches the
/// ratchet, which is re-seeded with fresh key material per epoch and therefore
/// numbers its generations from 0 each time. The subtraction wraps modulo 2^32
/// like the RTP timestamp, so it stays correct across a timestamp rollover within
/// an epoch.
///
/// `frame_period` must be non-zero and a whole
/// number (which it the case for the standard rates: 90000 / 60 = 1500,
/// 90000 / 30 = 3000, 90000 / 29.97 = 3003).
pub fn frame_generation(ts: u32, epoch_start_ts: u32, frame_period: u32) -> u64 {
    debug_assert_ne!(frame_period, 0, "frame_period must be non-zero");
    // measuring elapsed clock ticks since the epoch's first frame, wrapping at 2^32
    // the wrapping happens correctly due to u32 type
    let elapsed = ts.wrapping_sub(epoch_start_ts);
    // dividing elapsed ticks by ticks-per-frame to get the frame number
    (elapsed / frame_period) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each frame's packets (sharing one timestamp) map to one generation, and
    /// the generation increments by one per frame period.
    #[test]
    fn frame_generation_increments_per_frame() {

        // epoch's first-frame timestamp: the anchor/zero point
        let start = 1000u32;
        // ticks per frame (90 kHz clock/60 fps)
        let period = 1500u32;
        // the epoch's first frame is generation 0
        assert_eq!(frame_generation(start, start, period), 0);
        // a later packet within the same frame's timestamp stays in generation 0
        // (recall that all packets of a frame share the same timestamp)
        assert_eq!(frame_generation(start, start, period), 0);
        // the next frame's timestamp is one generation on
        assert_eq!(frame_generation(start + period, start, period), 1);
        // a partway-into-the-frame timestamp still rounds down to that frame
        assert_eq!(frame_generation(start + period + 700, start, period), 1);
        // 5 frames later, the generation is 5
        assert_eq!(frame_generation(start + 5 * period, start, period), 5);
    }

    /// A timestamp that has wrapped past 2^32 still yields the right generation,
    /// because the distance from the epoch start is computed modulo 2^32.
    #[test]
    fn frame_generation_survives_timestamp_wrap() {
        let period = 1500u32;
        // starting two frame periods before the 32-bit wrap
        let start = u32::MAX - 2 * period + 1;
        // three frames later the timestamp has wrapped past zero
        let ts = start.wrapping_add(3 * period);
        assert_eq!(frame_generation(ts, start, period), 3);
    }
}
