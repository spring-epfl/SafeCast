//! Wiring the three keying granularities onto the ratchet + in-place rekey.
//!
//! A generation is the span that shares one SRTP key (see [`crate::ratchet`]).
//! The granularity decides how long that span is:
//!   - [`Granularity::EpochOnly`]: one key for the whole epoch (never rekey
//!     within the epoch). This is the baseline.
//!   - [`Granularity::Frame`]: one key per video frame (rekey when the RTP
//!     timestamp changes, since all packets of a frame share a timestamp).
//!   - [`Granularity::Packet`]: one key per packet (rekey every packet).
//!   - [`Granularity::EveryN`]: one key per n consecutive packets (rekey
//!     when the packet count crosses a multiple of n).
//!
//! [`RekeyingStream`] ties a libsrtp session, a [`StreamRatchet`], and a
//! granularity together. It advances the ratchet and installs the next
//! generation's key with `inplace_rekey` at each generation boundary, then runs
//! the default `protect` (encrypt) or `unprotect` (decrypt).
//!
//! It keeps only a single key and advances on every timestamp change. That is
//! correct for a sender (it emits packets in timestamp order and never
//! needs an old key again), but it desyncs under reordering. Hence, its
//! `unprotect` side is a receiver only for in-order delivery,
//! needed for specific benchmarks.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use srtp::{CryptoPolicy, Error, Session, StreamPolicy};

use crate::ratchet::{split_key_salt, StreamRatchet};
use crate::rtp::RTP_HEADER_LEN;

/// Replay window size libsrtp tracks, matching srtp_session.rs (RFC 3711 §3.3.2).
const WINDOW_SIZE: u64 = 128;

/// How often the SRTP key is rotated within one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    /// One key for the whole epoch: never rekey within the epoch (baseline).
    EpochOnly,
    /// One key per video frame: rekey when the RTP timestamp changes.
    Frame,
    /// One key per packet: rekey on every packet.
    Packet,
    /// One key per `n` consecutive packets: rekey when the packet count
    /// crosses a multiple of `n`. Packet-level keying is the n = 1 case,
    /// frame-level the n = packets-per-frame case. EveryN covers
    /// everything between.
    EveryN(u32),
}

/// A single-SSRC SRTP stream that rekeys at the boundary set by its
/// [`Granularity`], driving the [`StreamRatchet`] forward one generation per boundary.
///
/// One instance handles one direction: call only `protect` on a sender and only
/// `unprotect` on a receiver (libsrtp fixes the stream's direction on the first
/// such call).
pub struct RekeyingStream {
    session: Session,
    ratchet: StreamRatchet,
    provider: OpenMlsRustCrypto,
    granularity: Granularity,
    ssrc: u32,
    /// Generation currently installed in the session's cipher.
    installed_gen: u64,
    /// RTP timestamp of the previous packet, for frame-boundary detection.
    last_ts: Option<u32>,
    /// Whether at least one packet has been processed (so the first packet does
    /// not trigger a spurious rekey).
    started: bool,
    /// Packets processed so far, for the every-n-packets boundary rule.
    packet_count: u64,
}

impl RekeyingStream {
    /// Creates a stream for `ssrc` with AES-128-GCM, driven by `ratchet` at the
    /// given `granularity`. The session is created with a throwaway master key
    /// and immediately rekeyed to the ratchet's generation 0, so the first
    /// packet is protected under the ratchet.
    pub fn new(granularity: Granularity, ssrc: u32, ratchet: StreamRatchet) -> Self {
        // libsrtp needs its one-time global init before any session is created
        srtp::ensure_init();

        // An empty SRTP session, the stream for this SSRC is added below.
        // A "stream" is libsrtp's per-SSRC crypto context: the cipher, its
        // key+salt, and the replay database for that one media source. One
        // session can hold several streams (one per SSRC). We use just one.
        let mut session = Session::new().expect("srtp_create failed");

        // throwaway master key: the stream needs a cipher to exist before
        // inplace_rekey can target it; install_next_generation overwrites it
        let throwaway = [0u8; 28];

        // AES-128-GCM for both RTP and RTCP, keyed with the throwaway for now
        let policy = StreamPolicy {
            rtp: CryptoPolicy::aes_gcm_128_16_auth(),
            rtcp: CryptoPolicy::aes_gcm_128_16_auth(),
            key: &throwaway,
            window_size: WINDOW_SIZE,
            ..Default::default()
        };

        // registering the stream for this SSRC under that policy
        session.add_stream(ssrc, policy).expect("add_stream failed");

        // bundling the session with the ratchet and boundary-tracking state
        let mut stream = RekeyingStream {
            session,
            ratchet,
            provider: OpenMlsRustCrypto::default(),
            granularity,
            ssrc,
            installed_gen: 0,
            last_ts: None,
            started: false,
            packet_count: 0,
        };

        // installing generation 0 over the throwaway key
        stream.install_next_generation();

        // handing back the ready-to-use stream
        stream
    }

    /// Generation currently installed in the cipher.
    pub fn generation(&self) -> u64 {
        self.installed_gen
    }

    /// Derives the next generation's key+salt from the ratchet and installs it in
    /// place, preserving the replay database. Advances the ratchet by one.
    fn install_next_generation(&mut self) {
        // pulling the next generation number and its 28-byte key+salt off the ratchet
        let (g, key_salt) = self.ratchet.next_key_salt(self.provider.crypto());

        // splitting the 28 bytes into the 16-byte key and 12-byte salt
        let (key, salt) = split_key_salt(&key_salt);

        // swapping the new key+salt into the live cipher, keeping the replay database
        self.session
            .inplace_rekey(self.ssrc, key, salt)
            .expect("inplace_rekey failed");

        // recording which generation is now installed
        self.installed_gen = g;
    }

    /// Advances to the generation this packet (with RTP timestamp `ts`) belongs
    /// to, rekeying if the granularity's boundary was crossed since the last
    /// packet. Both ends apply the same rule to the same packet order, so they
    /// install the same generation.
    fn advance_for(&mut self, ts: u32) {
        // deciding whether this packet starts a new generation
        let crossed_boundary = match self.granularity {
            // epoch-only never rekeys within the epoch
            Granularity::EpochOnly => false,
            // packet-level rekeys on every packet after the first
            Granularity::Packet => self.started,
            // frame-level rekeys when the timestamp changes (a new frame)
            Granularity::Frame => self.started && self.last_ts != Some(ts),
            // every-n rekeys when this packet's number is a multiple of n
            // (the first packet of each n-packet generation)
            Granularity::EveryN(n) => self.started && self.packet_count % n as u64 == 0,
        };

        // if so, ratcheting forward and install the next generation's key
        if crossed_boundary {
            self.install_next_generation();
        }

        // remembering this timestamp for the next packet's frame-boundary check
        self.last_ts = Some(ts);

        // past the first packet now, so future packets can trigger a rekey
        self.started = true;

        // one more packet processed, for the every-n boundary rule
        self.packet_count += 1;
    }

    /// Reads the 32-bit RTP timestamp from a packet's fixed header (bytes 4..8,
    /// big-endian). For SRTP-GCM the header is in the clear, so the receiver can
    /// read it before `unprotect`.
    fn timestamp(packet: &[u8]) -> u32 {
        // the packet must be at least a full RTP header long to hold a timestamp
        debug_assert!(packet.len() >= RTP_HEADER_LEN, "packet shorter than RTP header");
        // bytes 4..8 are the big-endian 32-bit timestamp
        u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]])
    }

    /// Rekeys if a generation boundary was crossed, then encrypts the RTP packet
    /// in place (header || payload -> header || ciphertext || tag).
    pub fn protect(&mut self, buf: &mut Vec<u8>) -> Result<(), Error> {
        // rekeying first if this packet's timestamp starts a new generation
        self.advance_for(Self::timestamp(buf));
        // then encrypting in place under the now-current key
        self.session.protect(buf)
    }

    /// Rekeys if a generation boundary was crossed, then decrypts the SRTP packet
    /// in place (header || ciphertext || tag -> header || payload).
    pub fn unprotect(&mut self, buf: &mut Vec<u8>) -> Result<(), Error> {
        // rekeying first if this packet's timestamp starts a new generation
        self.advance_for(Self::timestamp(buf));
        // then decrypting in place under the now-current key
        self.session.unprotect(buf)
    }
}
