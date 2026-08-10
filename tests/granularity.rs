//! Round-trip correctness for the three keying granularities.
//!
//! For each granularity a sender and a receiver are seeded from the same `S_0`
//! and fed the same packet stream (several frames, several packets per frame).
//! Both must stay key-synchronized with no per-packet signaling, so every packet
//! the sender protects must decrypt on the receiver, and the generation count at
//! the end must match the granularity's boundary rule.
//!
//! This is an idealized in-order simulation: no network, no loss, no
//! reordering, no jitter. The sender's protected bytes are
//! handed directly to the receiver's `unprotect` (an in-memory buffer).

use safecast_core::keying::granularity::{Granularity, RekeyingStream};
use safecast_core::keying::ratchet::StreamRatchet;
use safecast_core::transport::rtp::RtpPacket;

const SSRC: u32 = 0x1234_5678;
/// Frames in the test stream.
const FRAMES: u32 = 4;
/// Packets per frame (all sharing one timestamp).
const PACKETS_PER_FRAME: u32 = 5;
/// Ticks the RTP timestamp advances per frame (90 kHz/60 fps = 1500).
const FRAME_PERIOD: u32 = 1500;
/// First frame's timestamp (the epoch starting point).
const START_TS: u32 = 9000;

/// A fixed, obviously-not-secret 32-byte ratchet seed.
fn seed() -> Vec<u8> {
    (0..32u8).collect()
}

/// Builds one RTP packet. `frame` is which frame it belongs to; `pkt` is its
/// index within that frame (resets to 0 each frame); `seq` is the RTP sequence
/// number, which keeps counting across the whole stream. The payload is made
/// distinct per (frame, pkt).
fn packet(frame: u32, pkt: u32, seq: u16) -> Vec<u8> {
    RtpPacket {
        payload_type: 96,
        sequence_number: seq,
        // all packets of a frame share the frame's timestamp
        timestamp: START_TS + frame * FRAME_PERIOD,
        ssrc: SSRC,
        payload: vec![(frame as u8).wrapping_mul(31).wrapping_add(pkt as u8); 200],
    }
    .to_bytes()
}

/// Drives a full sender->receiver round trip for `granularity` and returns the
/// final installed generation on the receiver (== sender's, since both advance
/// their ratchet the same way). Panics if any packet fails to decrypt or the
/// payload differs.
fn run_round_trip(granularity: Granularity) -> u64 {

    // ratchets of both ends get the SAME seed, so they derive the same ratchet
    // and stay key-synchronized without any per-packet signaling
    let mut sender = RekeyingStream::new(granularity, SSRC, StreamRatchet::from_seed(seed()));
    let mut receiver = RekeyingStream::new(granularity, SSRC, StreamRatchet::from_seed(seed()));

    // RTP sequence number, incremented once per packet across the whole stream
    let mut seq: u16 = 0;
    
    // outer loop over frames, inner loop over the packets that make up each frame
    for frame in 0..FRAMES {
        for pkt in 0..PACKETS_PER_FRAME {
            // the plaintext packet the sender starts from and the receiver must recover
            let original = packet(frame, pkt, seq);

            // sender encrypts in place
            let mut wire = original.clone();
            sender.protect(&mut wire).expect("protect failed");
            // the wire bytes must now differ from plaintext
            assert_ne!(wire, original, "packet should be encrypted");

            // receiver decrypts in place
            receiver.unprotect(&mut wire).expect("unprotect failed");
            assert_eq!(wire, original, "decrypted packet must match original");

            // both ends landed on the same generation
            assert_eq!(
                sender.generation(),
                receiver.generation(),
                "sender/receiver generation diverged at frame {frame} pkt {pkt}"
            );

            // advancing the stream-wide sequence number for the next packet
            seq = seq.wrapping_add(1);
        }
    }
    // sender and receiver agree, so returning either end's generation is fine
    receiver.generation()
}

/// Epoch-only never rekeys: one generation (0) for the whole stream.
#[test]
fn epoch_only_keeps_one_generation() {
    let final_gen = run_round_trip(Granularity::EpochOnly);
    assert_eq!(final_gen, 0, "epoch-only must stay at generation 0");
}

/// Frame-level rekeys once per frame: the generation equals frames - 1.
#[test]
fn frame_level_advances_once_per_frame() {
    let final_gen = run_round_trip(Granularity::Frame);
    assert_eq!(
        final_gen,
        (FRAMES - 1) as u64,
        "frame-level must reach generation FRAMES-1"
    );
}

/// Packet-level rekeys on every packet: the generation equals total packets - 1.
#[test]
fn packet_level_advances_every_packet() {
    let final_gen = run_round_trip(Granularity::Packet);
    assert_eq!(
        final_gen,
        (FRAMES * PACKETS_PER_FRAME - 1) as u64,
        "packet-level must reach generation totalPackets-1"
    );
}

/// One key per n consecutive packets: with 4 frames x 5 packets = 20 packets
/// and n = 6, the last packet (number 19) belongs to generation 19/6 = 3.
#[test]
fn every_n_advances_once_per_n_packets() {
    let final_gen = run_round_trip(Granularity::EveryN(6));
    assert_eq!(
        final_gen, 3,
        "every-6 keying must reach generation floor(19/6) = 3"
    );
}
