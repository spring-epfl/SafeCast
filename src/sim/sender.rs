//! The simulated sender: creates every packet of the media stream (header
//! fields, payload bytes, send time) and produces its SRTP-encrypted bytes
//! in send order.
//!
//! The stream is 1080p60 uncompressed video, same frame model as the
//! granularity_throughput_ideal benchmark (so the simulator's
//! zero-disturbance runs are directly comparable to it): one frame is
//! FRAME_BYTES of media, split into FRAME_BYTES/payload_size packets that
//! all share the frame's RTP timestamp. At 60 fps a frame lasts 16.7 ms,
//! and instead of sending a frame's packets as one burst, the sender sends
//! one packet every 16.7 ms/packets_per_frame (at 1424 B payloads: one
//! every ~4.6 us). That smooth spacing is required by ST 2110-21. Each payload
//! embeds its packet index, so any decrypted packet can be verified without
//! storing plaintext.
//!
//! Packets are computed on demand, never stored: given a packet number i,
//! [`StreamModel`]'s methods compute that packet's seq, timestamp, send
//! time, and payload bytes directly from i. This way the stream takes no
//! memory, as storing millions of ready-made packets would take gigabytes.

use crate::keying::granularity::{Granularity, RekeyingStream};
use crate::keying::ratchet::StreamRatchet;
use crate::transport::rtp::RTP_HEADER_LEN;

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
/// `protect` appends this to every packet.
pub const GCM_TAG_LEN: usize = 16;

/// Media bytes in one uncompressed 1080p 10-bit 4:2:2 frame (ST 2110-20):
/// 1920 x 1080 x 2.5 = 5,184,000 B.
pub const FRAME_BYTES: usize = 1920 * 1080 * 5 / 2;

/// RTP timestamp ticks per frame: 90 kHz clock/60 fps = 1500.
pub const FRAME_PERIOD: u32 = 1500;

/// Frames per second of the modeled video.
pub const FPS: u64 = 60;

/// First frame's RTP timestamp (the epoch anchor/starting point).
pub const START_TS: u32 = 0;

/// The blueprint of one packet stream: its fixed shape (payload size,
/// packets per frame, SSRC), plus one method per packet property: given a
/// packet number i, they compute that packet's RTP timestamp, its send
/// time, its payload bytes, and its plaintext packet.
#[derive(Clone, Copy, Debug)]
pub struct StreamModel {
    /// Media payload bytes per packet.
    payload_size: usize,
    /// Packets per frame: FRAME_BYTES/payload_size.
    ppf: u64,
    /// Stream identifier written into every packet's RTP header.
    ssrc: u32,
}

impl StreamModel {
    /// Creates the stream blueprint for one payload size and SSRC.
    pub fn new(payload_size: usize, ssrc: u32) -> Self {
        // the payload must fit the 8-byte index stamp (see payload());
        // every real size does, the smallest we ever bench is 16 B
        assert!(payload_size >= 8, "payload must fit the 8-byte index stamp");
        StreamModel {
            payload_size,
            // how many payload-size pieces one frame's media splits into
            ppf: (FRAME_BYTES / payload_size).max(1) as u64,
            ssrc,
        }
    }

    /// Packets per frame of this stream.
    pub fn packets_per_frame(&self) -> u64 {
        self.ppf
    }

    /// Media payload bytes per packet.
    pub fn payload_size(&self) -> usize {
        self.payload_size
    }

    /// The SSRC of the stream.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// RTP timestamp of packet i: all packets of a frame share their
    /// frame's timestamp, which advances by FRAME_PERIOD per frame.
    /// Computed with wrapping arithmetic because 32-bit long.
    pub fn timestamp(&self, i: u64) -> u32 {
        START_TS.wrapping_add(((i / self.ppf) as u32).wrapping_mul(FRAME_PERIOD))
    }

    /// Send time of packet i, in nanoseconds since the stream start.
    /// Frame f starts at f/FPS seconds, and its packets leave evenly spaced
    /// across the frame duration (ST 2110-21-style pacing).
    pub fn send_ns(&self, i: u64) -> u64 {
        // frame number
        let f = i / self.ppf;
        // position within the frame
        let p = i % self.ppf;
        // 1 s = 1e9 ns, so one frame lasts 1e9/FPS ns and frame f starts at:
        let frame_start = f * 1_000_000_000 / FPS;
        // a frame's packets are 1e9/(FPS*ppf) ns apart, so packet p adds:
        let offset = p * 1_000_000_000 / (FPS * self.ppf);
        // the packet leaves when its frame starts plus its position's offset
        frame_start + offset
    }

    /// Media payload of packet i: all zeros, except the first 8 bytes hold
    /// i itself. That stamp makes every packet's payload unique, so a
    /// decrypted buffer can be checked to really be packet i.
    pub fn payload(&self, i: u64) -> Vec<u8> {
        // zero-filled payload
        let mut payload = vec![0u8; self.payload_size];
        // stamping the packet index into the first 8 bytes
        payload[..8].copy_from_slice(&i.to_le_bytes());
        payload
    }

    /// The complete plaintext packet i (12-byte RTP header || payload),
    /// exactly as it looks before `protect`/after a correct `unprotect`.
    pub fn plain_packet(&self, i: u64) -> Vec<u8> {
        let rtp_len = RTP_HEADER_LEN + self.payload_size;
        let mut buf = Vec::with_capacity(rtp_len + GCM_TAG_LEN);
        // same header layout as RtpPacket::to_bytes (rtp.rs)
        buf.push(0x80); // V=2, P=0, X=0, CC=0
        buf.push(96); // dynamic payload type
        // seq field: i mod 65,536 (the field is 16-bit, so it wraps)
        buf.extend_from_slice(&(i as u16).to_be_bytes());
        // timestamp field
        buf.extend_from_slice(&self.timestamp(i).to_be_bytes());
        // SSRC field
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        // payload field
        buf.extend_from_slice(&self.payload(i));
        // the buffer is now the full plaintext packet, ready for encryption
        buf
    }
}

/// The simulated sender itself: encrypts the modeled stream's packets in
/// send order. Wraps the sender-side `RekeyingStream`, which rekeys at each
/// generation boundary exactly as a real sender would. Its ratchet state
/// advances packet by packet, so packets can only be produced sequentially
/// - hence a cursor-style producer instead of a by-index function.
pub struct SimulatedSender {
    /// The stream blueprint (per-packet header fields, payload, pacing).
    model: StreamModel,
    /// The crypto: encrypts, rekeying at generation boundaries.
    crypto: RekeyingStream,
    /// Index of the next packet to produce.
    next_i: u64,
}

impl SimulatedSender {
    /// Creates the sender for the given stream, keying with `granularity`
    /// from `ratchet`. The receiver must be seeded from the same ratchet
    /// seed to derive the same keys.
    pub fn new(model: StreamModel, granularity: Granularity, ratchet: StreamRatchet) -> Self {
        SimulatedSender {
            model,
            // the crypto session gets the stream's SSRC
            crypto: RekeyingStream::new(granularity, model.ssrc(), ratchet),
            next_i: 0,
        }
    }

    /// Index of the packet the next `next_protected` call will produce.
    pub fn cursor(&self) -> u64 {
        self.next_i
    }

    /// Produces the next packet in send order: builds plaintext packet
    /// `cursor()`, protects it (rekeying first if it starts a new
    /// generation), and returns `(index, protected bytes)`.
    pub fn next_protected(&mut self) -> (u64, Vec<u8>) {
        let i = self.next_i;
        // plaintext bytes
        let mut buf = self.model.plain_packet(i);
        // encrypting in place
        self.crypto
            .protect(&mut buf)
            .expect("protect failed in the simulated sender");
        self.next_i = i + 1;
        (i, buf)
    }
}
