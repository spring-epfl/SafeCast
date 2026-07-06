//! Tests for the simulated sender (sim::sender). Covers the frame
//! structure (packets per frame, one timestamp per frame), the payload
//! index stamp, the evenly paced send times, and a frame-level
//! encrypt/decrypt round trip.

use mls_srtp_core::granularity::{Granularity, RekeyingStream};
use mls_srtp_core::ratchet::StreamRatchet;
use mls_srtp_core::sim::sender::{SimulatedSender, StreamModel, FPS, FRAME_PERIOD, START_TS};

/// Unique identifier for the test stream.
const SSRC: u32 = 0x5EED_CAFE;

/// A fixed 32-byte ratchet seed shared by sender and receiver.
fn seed() -> Vec<u8> {
    (0..32u8).collect()
}

/// The frame structure must match the ideal benchmark's model exactly:
/// ppf = FRAME_BYTES/payload packets per frame, all sharing the frame's
/// timestamp, which advances by FRAME_PERIOD at each frame boundary.
#[test]
fn frame_structure_matches_ideal_bench_model() {
    let stream = StreamModel::new(1424, SSRC);
    // one 1080p frame is FRAME_BYTES = 1920 x 1080 px x 2.5 B/px =
    // 5,184,000 B; split into 1424 B payloads = 3640 packets per frame
    assert_eq!(stream.packets_per_frame(), 3640);
    // every packet of frame 0 carries the frame's timestamp
    assert_eq!(stream.timestamp(0), START_TS);
    assert_eq!(stream.timestamp(3639), START_TS);
    // the first packet of frame 1 steps by exactly one FRAME_PERIOD
    assert_eq!(stream.timestamp(3640), START_TS + FRAME_PERIOD);
    // jumbo payload: 5,184,000 / 8924 = 580 packets per frame
    assert_eq!(StreamModel::new(8924, SSRC).packets_per_frame(), 580);
}

/// Packet i carries seq = i mod 65,536 with no offset, and same-seq 
/// packets still differ in payload.
#[test]
fn seq_wraps_but_payload_stays_unique() {
    let stream = StreamModel::new(1424, SSRC);
    // reading the seq field (header bytes 2-3) of the built packet
    let seq_of = |i: u64| {
        let pkt = stream.plain_packet(i);
        u16::from_be_bytes([pkt[2], pkt[3]])
    };
    assert_eq!(seq_of(0), 0);
    assert_eq!(seq_of(65_535), 65_535);
    // the field wraps back to 0...
    assert_eq!(seq_of(65_536), 0);
    assert_eq!(seq_of(65_537), 1);
    // ...but packets 0 and 65,536 (both carrying seq 0) still differ in
    // content: the first 8 payload bytes hold the full packet index
    assert_ne!(stream.payload(0), stream.payload(65_536));
}

/// Send times: frame f starts at exactly f/FPS seconds, packets within a
/// frame are evenly spaced across the frame duration, and the sequence is
/// strictly increasing (also across frame boundaries).
#[test]
fn send_times_are_evenly_paced_and_monotonic() {
    let stream = StreamModel::new(1424, SSRC);
    // one 1080p frame (FRAME_BYTES = 5,184,000 B) split into 1424 B
    // payloads = 3640 packets per frame
    let ppf = stream.packets_per_frame();
    // packet 0 (first packet of frame 0) leaves at time 0
    assert_eq!(stream.send_ns(0), 0);
    // one frame lasts 1e9 ns/60 fps = 16,666,666 ns, so packet 3640 (the
    // first packet of frame 1) leaves exactly one frame duration later
    assert_eq!(stream.send_ns(ppf), 1_000_000_000/FPS);
    // and the first packet of frame 2 leaves at exactly twice that
    assert_eq!(stream.send_ns(2 * ppf), 2 * 1_000_000_000 / FPS);
    // within a frame: 16,666,666 ns/3640 packets = ~4578 ns between packets
    let spacing = stream.send_ns(1) - stream.send_ns(0);
    assert!(
        (4578..=4579).contains(&spacing),
        "unexpected spacing {spacing} ns"
    );
    // strictly increasing over two whole frames, including the boundary
    let mut prev = stream.send_ns(0);
    for i in 1..=2 * ppf {
        let t = stream.send_ns(i);
        assert!(t > prev, "send time not increasing at packet {i}");
        prev = t;
    }
}

/// Frame-level round trip: encrypt every packet with the SimulatedSender,
/// decrypt in send order with a receiver seeded from the same ratchet
/// seed. Frame level only, because that is the one granularity where this
/// module's own logic decides the rekeying (the timestamps it generates
/// mark the frame boundaries). Epoch-only and packet-level rekeying do not
/// depend on the stream shape and are covered by
/// tests/granularity.rs on the underlying RekeyingStream.
#[test]
fn round_trip_frame_level() {
    // jumbo payload: one 1080p frame (FRAME_BYTES = 5,184,000 B)
    // split into 8924 B payloads = 580 packets per frame
    let stream = StreamModel::new(8924, SSRC);
    // the sender under test
    let mut sender =
        SimulatedSender::new(stream, Granularity::Frame, StreamRatchet::from_seed(seed()));
    // in-order receiver, seeded like the sender, so it derives the same keys
    let mut receiver =
        RekeyingStream::new(Granularity::Frame, SSRC, StreamRatchet::from_seed(seed()));
    // 3 frames = 1740 packets, so two frame boundaries (= two rekeys)
    // are crossed
    for i in 0..(3 * stream.packets_per_frame()) {
        // producing encrypted packet i
        let (j, mut buf) = sender.next_protected();
        // the sender hands out indices sequentially from 0
        assert_eq!(j, i);
        // decrypting; a failure here means sender and receiver disagree
        // about the key of packet i
        receiver
            .unprotect(&mut buf)
            .unwrap_or_else(|e| panic!("unprotect failed at packet {i}: {e:?}"));
        // authentication guarantees buf == whatever the sender
        // encrypted, and this checks the sender encrypted the right thing
        assert_eq!(
            buf,
            stream.plain_packet(i),
            "round-trip mismatch at packet {i}"
        );
    }
    // the two rekeys really happened: after frames 0, 1, 2 the receiver's
    // ratchet must sit at generation 2.
    assert_eq!(receiver.generation(), 2);
}