//! Tests for the receiver-side key manager. A sender (using
//! RekeyingStream) produces the ciphertexts, and the ReceiverKeyManager must
//! handle them under the ways real delivery happens:
//!   - in order: exactly as sent
//!   - reordered: every packet arrives, just not in send order
//!   - with gaps: some packets never arrive (loss), leaving holes in the seq
//!   - duplicated: the same packet arrives more than once (a replay)

use mls_srtp_core::granularity::{Granularity, RekeyingStream};
use mls_srtp_core::ratchet::StreamRatchet;
use mls_srtp_core::receiver::{GenerationScheme, RecvDrop, ReceiverKeyManager};
use mls_srtp_core::rtp::RtpPacket;

// Unique identifier for the test stream.
const SSRC: u32 = 0x5EED_CAFE;
/// First frame's RTP timestamp (the epoch anchor/starting point).
const START_TS: u32 = 90_000;
/// Ticks per frame (90 kHz/60 fps).
const PERIOD: u32 = 1500;

/// A fixed 32-byte ratchet seed shared by sender and receiver.
fn seed() -> Vec<u8> {
    (0..32u8).collect()
}

/// Builds `frames x ppf` in-order RTP packets with per-packet distinct
/// payloads (ppf = packets per frame). Each packet gets a different
/// payload (derived from its seq), so when a test compares decrypted bytes
/// against the original it is checking real content, not an all-same buffer
/// that would match by accident.
fn make_plain(frames: u32, ppf: u32, payload_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // RTP sequence number, counting across the whole stream (not per frame)
    let mut seq: u16 = 0;
    for f in 0..frames {
        for _ in 0..ppf {
            out.push(
                RtpPacket {
                    payload_type: 96,
                    sequence_number: seq,
                    // all packets of frame f share the frame's timestamp
                    timestamp: START_TS + f * PERIOD,
                    ssrc: SSRC,
                    // per-packet distinct byte pattern, derived from seq
                    payload: vec![(seq as u8).wrapping_mul(7).wrapping_add(3); payload_len],
                }
                .to_bytes(),
            );
            seq = seq.wrapping_add(1);
        }
    }
    out
}

/// Encrypts the packets in send order with a normal sender (a RekeyingStream
/// that rekeys at each generation boundary, exactly as a real sender would).
/// The tests then feed these ciphertexts to the receiver in whatever broken
/// order the scenario calls for.
fn encrypt_all(granularity: Granularity, plain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // the sender's ratchet starts from the same seed as the receiver's
    let mut sender = RekeyingStream::new(granularity, SSRC, StreamRatchet::from_seed(seed()));
    // encrypt each plaintext packet in order and collect the ciphertexts
    plain
        .iter()
        .map(|p| {
            // protect() encrypts in place, so encrypt a copy and keep the plaintext
            let mut buf = p.clone();
            sender.protect(&mut buf).expect("protect failed");
            buf
        })
        .collect()
}

/// Builds the receiver-side GenerationScheme that matches a sender
/// granularity, filling in the reference points (epoch start timestamp, ticks
/// per frame) from the test's constants.
///
/// Why the receiver needs its own type at all: Granularity is an enum
/// (epoch-only/frame/packet) with no data in its variants. That is enough for
/// the sender: at frame-level it remembers the previous packet's timestamp
/// and rekeys when it changes, and at packet-level it rekeys on every packet. 
/// The receiver, however sees packets possibly out of order, so "the previous packet" means nothing
/// there. It instead computes each packet's generation number from the
/// header, and for that the variants must carry data: Frame needs the epoch's
/// starting timestamp and the ticks per frame, Packet needs the index the
/// epoch started at (base). GenerationScheme is the enum whose variants
/// carry those numbers.
fn scheme_for(granularity: Granularity) -> GenerationScheme {
    match granularity {
        // one generation for the whole epoch: every packet maps to 0
        Granularity::EpochOnly => GenerationScheme::EpochOnly,
        // generation = (timestamp - epoch_start_ts)/frame_period
        Granularity::Frame => GenerationScheme::Frame {
            epoch_start_ts: START_TS,
            frame_period: PERIOD,
        },
        // generation = extended seq index - base (base 0: stream starts at seq 0)
        Granularity::Packet => GenerationScheme::Packet { base: 0 },
    }
}

/// Builds the receiver under test. 
/// `k` is how many recent generation keys it keeps
/// `seek_cap` is the most ratchet steps it will do for one packet. 
/// The final 0 picks libsrtp's default replay window (128).
fn receiver(granularity: Granularity, k: usize, seek_cap: u64) -> ReceiverKeyManager {
    ReceiverKeyManager::new(
        scheme_for(granularity),
        SSRC,
        // same seed as the sender in encrypt_all, so both derive the same keys
        StreamRatchet::from_seed(seed()),
        k,
        seek_cap,
        0,
    )
}

