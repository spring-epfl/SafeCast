//! Minimal RTP packet construction and parsing (RFC 3550).
//!
//! Only supports the fixed 12-byte header with no optional fields.
//! The 12 bytes are: version/flags (1) + payload type (1) + sequence number (2)
//! + timestamp (4) + SSRC (4). The version/flags byte is hardcoded to 0x80,
//! which means:
//!   - Version = 2 (the only version of RTP in use)
//!   - Padding = off (no extra padding bytes at the end of the payload)
//!   - Extension = off (no application-specific header extension present)
//!   - CSRC count = 0 (no CSRCs)
//!
//!
//! This is sufficient for feeding RTP packets into libsrtp's protect/unprotect.
//!
//! It also defines `frame_generation`, which computes the ratchet generation `g`
//! for frame-level keying. A generation index `g` is a counter
//! (0, 1, 2, ...) that resets to 0 at the start of each epoch and selects that
//! generation's SRTP key by counting frames since the epoch's first
//! frame. Both ends must compute the same `g` for a packet, or they derive
//! different SRTP keys.
//!
//! Packet-level keying uses the same idea but counts packets, and is not computed
//! here. Frame-level works because the RTP timestamp is tied to the shared PTP
//! clock, so both ends agree on `g` for free. A per-packet `g` instead has to come
//! from the packet's sequence number, which is not tied to that clock. Hence, the
//! receiver cannot work out where the epoch's packet counting started just from
//! the timestamp, the way it can for frames. That case needs a different mechanism
//! and is out of scope for this module.

/// Fixed RTP header size in bytes: version/flags (1) + payload type (1)
/// + sequence number (2) + timestamp (4) + SSRC (4) = 12 bytes (RFC 3550 §5.1).
pub const RTP_HEADER_LEN: usize = 12;

/// A minimal RTP packet: fixed 12-byte header + payload.
pub struct RtpPacket {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Serializes into the wire format: 12-byte header || payload.
    ///
    /// libsrtp's `protect` API operates on raw RTP
    /// bytes, not on a Rust struct
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RTP_HEADER_LEN + self.payload.len());
        buf.push(0x80); 
        buf.push(self.payload_type & 0x7F);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parses from wire bytes (assumes no CSRC and no extensions).
    ///
    /// After libsrtp `unprotect` returns decrypted bytes,
    /// we need to reconstruct `RtpPacket`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < RTP_HEADER_LEN {
            return None;
        }
        Some(Self {
            payload_type: data[1] & 0x7F,
            sequence_number: u16::from_be_bytes([data[2], data[3]]),
            timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ssrc: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            payload: data[RTP_HEADER_LEN..].to_vec(),
        })
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
