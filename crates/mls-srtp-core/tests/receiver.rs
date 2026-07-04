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
fn create_packets(frames: u32, ppf: u32, payload_len: usize) -> Vec<Vec<u8>> {
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
fn receiver_scheme_for(granularity: Granularity) -> GenerationScheme {
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
        receiver_scheme_for(granularity),
        SSRC,
        // same seed as the sender in encrypt_all, so both derive the same keys
        StreamRatchet::from_seed(seed()),
        k,
        seek_cap,
        0,
    )
}

// --------------------------------------------------------------------------
// All three granularities
// --------------------------------------------------------------------------

/// Test 1: Equivalence on the easy case: on an undisturbed in-order stream the new
/// receiver must produce the same bytes and use the same generation per
/// packet as the old in-order-only receiver (RekeyingStream).
#[test]
fn in_order_equivalence_with_old_receiver() {
    // the equivalence must hold for all three granularities
    for granularity in [Granularity::EpochOnly, Granularity::Frame, Granularity::Packet] {
        let plain = create_packets(4, 5, 64);
        let cipher = encrypt_all(granularity, &plain);

        // old in-order-only receiver (a RekeyingStream used on the decrypt side)
        let mut old = RekeyingStream::new(granularity, SSRC, StreamRatchet::from_seed(seed()));
        // new windowed receiver (the ReceiverKeyManager under test)
        let mut new = receiver(granularity, 8, 1_000);

        // feeding the same ciphertext to both receivers, packet by packet
        for (i, ct) in cipher.iter().enumerate() {
            let mut a = ct.clone();
            old.unprotect(&mut a).expect("old-receiver unprotect failed");
            let mut b = ct.clone();
            new.unprotect(&mut b).expect("windowed unprotect failed");

            // both must recover the exact plaintext...
            assert_eq!(a, plain[i], "old-receiver plaintext mismatch at {i}");
            assert_eq!(b, plain[i], "windowed plaintext mismatch at {i}");
            // ...and be on the same generation after each packet
            assert_eq!(
                Some(old.generation()),
                new.installed_generation(),
                "generation diverged at packet {i} ({granularity:?})"
            );
        }
        // every packet was delivered (none dropped)
        assert_eq!(new.stats().delivered, cipher.len() as u64);
    }
}

// --------------------------------------------------------------------------
// Packet-level keying (one generation per packet, so packet i <-> generation i)
// --------------------------------------------------------------------------

/// Test 2: Reordering within the window: every packet decrypts, and the
/// counters come out exactly as this delivery order predicts.
///
/// The whole test runs at packet-level keying: one generation per packet, so
/// packet i is encrypted under generation i, which makes the expected counter
/// values below easy to compute.
///
/// Delivery order: 64 packets in chunks of 8, each chunk reversed, so packets
/// arrive as 7,6,...,0, then 15,14,...,8, and so on. The first packet of each
/// chunk (7, then 15, ...) is 8 generations past what the receiver has seen,
/// so it triggers one catch-up that derives those 8 keys into the window. The
/// other 7 packets of the chunk then find their key already there (cache
/// hits). Hence the asserts below: derivations total = 64 (each generation
/// derived exactly once), cache hits = 64 - 8 (all but each chunk's first
/// packet), max catch-up = 8 (one chunk).
#[test]
fn shuffle_within_window_decrypts_everything() {
    // 8 frames x 8 packets = 64 packets
    let plain = create_packets(8, 8, 64);
    let cipher = encrypt_all(Granularity::Packet, &plain);
    let n = cipher.len() as u64;

    // building the delivery order: splitting the 64 packets into chunks of 8 and
    // reverse each chunk, giving 7,6,...,0, 15,14,...,8, ...
    // a packet arrives at most 7 positions away from its send position, which
    // is well inside the key window (K=16) and libsrtp's replay window (128)
    let chunk = 8usize;
    let mut order: Vec<usize> = Vec::new();
    for c in 0..(cipher.len() / chunk) {
        for i in (c * chunk..(c + 1) * chunk).rev() {
            order.push(i);
        }
    }

    // delivering in that shuffled order: every packet must decrypt to its
    // original bytes, none may be dropped
    let mut rx = receiver(Granularity::Packet, 16, 1_000);
    for &i in &order {
        let mut buf = cipher[i].clone();
        rx.unprotect(&mut buf)
            .unwrap_or_else(|e| panic!("packet {i} dropped: {e:?}"));
        assert_eq!(buf, plain[i], "plaintext mismatch at {i}");
    }

    // the counters must match the prediction in the doc comment above
    let s = rx.stats();
    
    // all 64 packets came through
    assert_eq!(s.delivered, n);
    
    // no packet was dropped for any reason
    assert_eq!(s.drops_behind + s.drops_seek_cap + s.drops_replay + s.drops_auth, 0);
    
    // 64 ratchet steps in total: each of the 64 generations was derived
    // exactly once (reordering caused no repeated derivation work)
    assert_eq!(s.catchup_steps, n);
    
    // each chunk's first packet triggers the catch-up (not a hit); the other
    // 7 find their key already in the window: 64 - 8 hits
    assert_eq!(s.cache_hits, n - (n / chunk as u64));

    // the largest single catch-up was one chunk's worth: 8 steps
    assert_eq!(s.max_catchup, chunk as u64);
}

/// Test 3: A late packet older than the key window (the receiver keeps only
/// the K most recent generation keys, older ones are deleted for forward
/// secrecy) is dropped as keying-loss without touching the ratchet.
#[test]
fn late_packet_behind_window_is_clean_keying_loss() {
    
    // 24 packets
    let plain = create_packets(4, 6, 64); // generations 0..=23
    let cipher = encrypt_all(Granularity::Packet, &plain);

    // key window of K=8: only the 8 most recent generation keys are kept
    let mut rx = receiver(Granularity::Packet, 8, 1_000);

    // delivering packets 0..=22 in order, but hold backing packet 2 (it will be
    // delivered late below, after its key has fallen out of the window)
    for (i, ct) in cipher.iter().enumerate().take(23) {
        if i == 2 {
            continue;
        }
        let mut buf = ct.clone();
        rx.unprotect(&mut buf).expect("in-order packet failed");
    }

    // newest generation seen (the "frontier") is 22, so with K=8 the kept
    // keys are generations 15..=22; generation 2's key is long deleted
    assert_eq!(rx.frontier(), Some(22));

    // now delivering the held-back packet 2: its key was discarded when the
    // window moved past it, so the receiver cannot decrypt it
    let mut late = cipher[2].clone();
    assert_eq!(rx.unprotect(&mut late), Err(RecvDrop::BehindWindow));
    // the drop is counted
    assert_eq!(rx.stats().drops_behind, 1);
    // ...and the receiver's frontier must not move because of a dropped packet
    assert_eq!(rx.frontier(), Some(22), "drop must not move the frontier");

    // finally, the next fresh packet (generation 23) still decrypts: the
    // dropped packet left no damage behind
    let mut next = cipher[23].clone();
    rx.unprotect(&mut next).expect("stream must continue after the drop");
}

/// Test 4: How the receiver handles packets that jump AHEAD of what it has
/// seen (a gap: the packets in between were lost or are still in flight).
/// Three scenario tests, in order:
///
///   (a) an honest jump within the seek cap: the receiver ratchets forward
///       ("catches up") exactly the gap's worth of steps, no more;
///   (b) a jump beyond the seek cap: dropped outright
///   (c) a FORGED packet claiming a future generation within the cap: the
///       receiver does the catch-up work on a clone of its ratchet, the
///       packet then fails GCM authentication, and the clone is thrown away,
///       so the receiver's real state is untouched
#[test]
fn gap_catchup_seek_cap_and_d8() {
    // 170 packets in one frame (frames are irrelevant at packet-level keying,
    // we just need generations 0..=169 to play with)
    let plain: Vec<Vec<u8>> = create_packets(1, 170, 64);
    let cipher = encrypt_all(Granularity::Packet, &plain);

    // seek cap 100: the receiver refuses to ratchet more than 100 steps
    // forward for any single packet
    let mut rx = receiver(Granularity::Packet, 16, 100);

    // warm-up: delivering packets 0..=5 in order, receiver's frontier (newest
    // generation seen) lands at 5
    for ct in cipher.iter().take(6) {
        let mut buf = ct.clone();
        rx.unprotect(&mut buf).expect("in-order packet failed");
    }

    // (a) honest in-cap jump: packet 50 arrives while the frontier is 5, as
    // if packets 6..=49 were lost. Jump of 45 <= cap 100, so it must decrypt
    let mut jump = cipher[50].clone();
    rx.unprotect(&mut jump).expect("in-cap catch-up failed");
    // the frontier moved to 50, and the catch-up took exactly 45 ratchet
    // steps (generations 6..=50), not one more
    assert_eq!(rx.frontier(), Some(50));
    assert_eq!(rx.stats().max_catchup, 45);

    // (b) beyond-cap jump: packet 165 is a jump of 115 > 100 from frontier 50
    let mut too_far = cipher[165].clone();
    assert_eq!(rx.unprotect(&mut too_far), Err(RecvDrop::SeekCapExceeded));
    // counted in its own drop bucket, and the frontier did not move
    assert_eq!(rx.stats().drops_seek_cap, 1);
    assert_eq!(rx.frontier(), Some(50), "capped drop moved the frontier");

    // (c) a forged packet claiming generation 70 (jump 20,
    // inside the cap, so the receiver will do the catch-up work before
    // discovering the forgery)
    let steps_before = rx.stats().catchup_steps;
    // hand-built packet, never touched by the sender: its "ciphertext" is
    // garbage, so GCM authentication will reject it
    let mut forged = RtpPacket {
        payload_type: 96,
        sequence_number: 70, // claims generation 70
        timestamp: START_TS,
        ssrc: SSRC,
        payload: vec![0xAB; 80], // garbage, will not authenticate
    }
    .to_bytes();
    assert_eq!(rx.unprotect(&mut forged), Err(RecvDrop::AuthFail));

    // 1 auth-fail drop 
    assert_eq!(rx.stats().drops_auth, 1);
    // the 20 catch-up steps were done on a clone and thrown away when auth
    // failed, so the receiver's real position is untouched
    assert_eq!(rx.frontier(), Some(50), "forged packet moved the frontier");
    // the work itself is still counted (it did happen and cost time)
    assert_eq!(
        rx.stats().catchup_steps - steps_before,
        20,
        "the bounded derivation work is accounted"
    );
    // also counted in the wasted-work counter, so a measurement can
    // tell useful catch-up work apart from work an attacker made us burn
    assert_eq!(
        rx.stats().catchup_steps_wasted, 20,
        "discarded (rolled-back) catch-up work is accounted separately"
    );

    // after all three scenarios, the genuine generation-51 packet still
    // decrypts: nothing above corrupted the receiver's state
    let mut next = cipher[51].clone();
    rx.unprotect(&mut next).expect("stream must continue after D8 events");
}

/// Test 5: A duplicated packet is rejected by replay protection.
#[test]
fn duplicate_is_rejected_as_replay() {
    // 12 packets
    let plain = create_packets(2, 6, 64);
    let cipher = encrypt_all(Granularity::Packet, &plain);

    // K=16 keeps every key for the 12 packets, so a duplicate
    // can never be rejected for a missing key, only as a replay
    let mut rx = receiver(Granularity::Packet, 16, 1_000);

    // delivering packets 0..=10 in order; all decrypt normally
    for ct in cipher.iter().take(11) {
        let mut buf = ct.clone();
        rx.unprotect(&mut buf).expect("in-order packet failed");
    }

    // delivering packet 5 a second time: its generation (5) is still in the key
    // window, so the key lookup succeeds and the packet reaches libsrtp,
    // where the replay database notices seq 5 was already accepted
    let mut dup = cipher[5].clone();
    assert_eq!(rx.unprotect(&mut dup), Err(RecvDrop::SrtpReplay));
    // the drop lands in the replay bucket...
    assert_eq!(rx.stats().drops_replay, 1);
    // ...and not in the missing-key bucket: the two causes stay separable
    assert_eq!(rx.stats().drops_behind, 0, "replay must not count as keying-loss");

    // the next fresh packet (11) still decrypts: rejecting the duplicate
    // did not disturb the receiver's state
    let mut next = cipher[11].clone();
    rx.unprotect(&mut next).expect("stream must continue after replay");
}

/// Test 6: Determinism: the same scenario twice yields byte-identical stats.
#[test]
fn identical_runs_produce_identical_stats() {
    // one full scenario: encrypt 64 packets, deliver them with every chunk of
    // 8 reversed (same shuffle as test 2), and return the resulting counters
    let run = || {
        let plain = create_packets(8, 8, 64);
        let cipher = encrypt_all(Granularity::Packet, &plain);
        let chunk = 8usize;
        let mut rx = receiver(Granularity::Packet, 16, 1_000);
        for c in 0..(cipher.len() / chunk) {
            for i in (c * chunk..(c + 1) * chunk).rev() {
                let mut buf = cipher[i].clone();
                let _ = rx.unprotect(&mut buf);
            }
        }
        rx.stats().clone()
    };
    // nothing in the pipeline is time- or randomness-dependent, so the exact
    // same scenario must produce the exact same counters
    assert_eq!(run(), run());
}

// --------------------------------------------------------------------------
// Frame-level keying (one generation per frame)
//
// The key-window/catch-up/drop machinery is the same code as at packet level and
// is covered by the packet-level tests above. The only frame-specific piece
// is the timestamp -> generation mapping (frame_generation function, unit-tested
// in rtp.rs), so the tests here focus on what only happens at frame level:
// several packets share one generation, so the receiver installs a key once
// and reuses it for the whole frame. Reordering across a frame boundary
// disturbs that reuse: the receiver must switch back to the previous
// frame's key and forward again (extra installs).
// --------------------------------------------------------------------------

/// Test 8: A late packet from the previous frame costs exactly two extra key
/// installs: back to the old frame's key, then forward again.
#[test]
fn late_frame_packet_flip_flop_costs_two_installs() {
    let plain = create_packets(3, 2, 64);
    let cipher = encrypt_all(Granularity::Frame, &plain);

    let mut rx = receiver(Granularity::Frame, 4, 1_000);
    // f0p0 f0p1 f1p0 f2p0 (withholding f1p1 = index 3)
    for i in [0usize, 1, 2, 4] {
        let mut buf = cipher[i].clone();
        rx.unprotect(&mut buf).expect("in-order packet failed");
    }
    // installs so far: one per new frame = 3: f0p1 rode on the key installed for f0p0
    // (4 packets delivered, only 3 installs)
    assert_eq!(rx.stats().installs, 3);

    // the late frame-1 packet needs the frame-1 key, forcing an install back
    let mut late = cipher[3].clone();
    rx.unprotect(&mut late).expect("late packet must decrypt");
    assert_eq!(rx.stats().installs, 4);

    // and the next frame-2 packet forces an install forward again:
    let mut fwd = cipher[5].clone();
    rx.unprotect(&mut fwd).expect("packet after the late one failed");
    assert_eq!(rx.stats().installs, 5);
    assert_eq!(rx.stats().delivered, 6);
}
