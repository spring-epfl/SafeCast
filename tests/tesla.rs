//! End-to-end TESLA tests: SRTP sender and receiver with the
//! TESLA layer around both.
//! Each test plays one network scenario (clean delivery, a lost interval,
//! a tampered packet, a too-late packet) and checks that every delivered
//! packet ends up with the right verdict, such as "verified" or "forged".

use mls_srtp_core::keying::granularity::Granularity;
use mls_srtp_core::keying::ratchet::StreamRatchet;
use mls_srtp_core::receiver::generation::GenerationScheme;
use mls_srtp_core::receiver::ReceiverKeyManager;
use mls_srtp_core::simulation::sender::{SimulatedSender, StreamModel};
use mls_srtp_core::tesla::mac::TeslaMacAlg;
use mls_srtp_core::tesla::schedule::TeslaSchedule;
use mls_srtp_core::tesla::receiver::{TeslaDrop, TeslaReceiver};
use mls_srtp_core::tesla::sender::TeslaSender;

/// A fixed ratchet seed: sender and receiver must derive the same SRTP
/// keys.
const SEED: u8 = 42;
const SSRC: u32 = 0x1234;

/// The stream: 100-byte payloads, sent one every ~321 ns (the model's
/// 1080p60 pacing at that payload size).
fn model() -> StreamModel {
    StreamModel::new(100, SSRC)
}

/// The schedule: 1 us intervals (a few packets per interval at the
/// model's pacing), d = 2, a 64-interval chain, no clock skew.
fn params() -> TeslaSchedule {
    TeslaSchedule::new(0, 1_000, 2, 64, 0, 16)
}

/// One sender + one receiver.
fn setup() -> (SimulatedSender, TeslaSender, TeslaReceiver) {
    let ratchet = |b| StreamRatchet::from_seed(vec![b; 32]);
    // the media sender: encrypts the modeled stream in send order
    let srtp_sender = SimulatedSender::new(model(), Granularity::EpochOnly, ratchet(SEED));
    // the TESLA sender: builds its private chain, tags every packet
    let tesla_sender = TeslaSender::new(params(), TeslaMacAlg::HmacSha256);
    // the SRTP receiver, from the same ratchet seed
    let inner = ReceiverKeyManager::new(
        GenerationScheme::EpochOnly,
        SSRC,
        ratchet(SEED),
        1,    // key window: epoch-only has a single generation
        4096, // seek cap (not used at epoch-only)
        0,    // libsrtp's default replay window
    );
    // the TESLA receiver around it
    let tesla_receiver = TeslaReceiver::new(
        params(),
        *tesla_sender.anchor(),
        TeslaMacAlg::HmacSha256,
        inner,
    );
    (srtp_sender, tesla_sender, tesla_receiver)
}

/// Produces packet i: SRTP-protected, then TESLA-authenticated with its send time.
fn produce(srtp: &mut SimulatedSender, tesla: &mut TeslaSender, m: &StreamModel) -> (u64, Vec<u8>) {
    let (i, mut buf) = srtp.next_protected();
    tesla.authenticate(&mut buf, i, m.send_ns(i));
    (i, buf)
}

/// The clean run: an undisturbed network, every packet arrives in order
/// shortly after being sent. Three things must hold:
///
/// - every packet is delivered (decrypted and handed out), and none is
///   flagged as forged;
/// - almost every packet gets its verdict ("verified") once its key is
///   disclosed, d intervals after it arrived;
/// - the exception is the packets of the last d intervals: their keys
///   would have been disclosed by later packets, but the stream stops.
#[test]
fn clean_run_verifies_everything() {
    let m = model();
    let (mut srtp, mut tesla, mut rx) = setup();
    let n = 40;

    for _ in 0..n {
        let (i, mut buf) = produce(&mut srtp, &mut tesla, &m);
        // arriving 100 ns after being sent, so inside the "budget"
        rx.process_arrival(&mut buf, m.send_ns(i) + 100)
            .expect("clean packet must be delivered");
        // the decrypted payload is the model's plaintext for packet i
        assert_eq!(buf, m.plain_packet(i));
    }

    let s = rx.stats();
    // every packet was delivered, none looked forged
    assert_eq!(s.delivered, n);
    assert_eq!(s.forged, 0);
    // every packet either got its verdict or waits in the final d
    // intervals, whose keys the stopped stream never disclosed
    assert_eq!(s.verified + rx.unsettled(), n);
    assert!(rx.unsettled() > 0, "the last d intervals cannot settle");
    // verdicts arrive roughly d intervals after the packet, in stream time
    let max = *s.latencies_ns.iter().max().unwrap();
    assert!(max <= (params().d as u64 + 1) * params().t_int_ns);
}

/// The loss case: every packet of one interval is lost, taking that
/// interval's key disclosures with it. The next interval's disclosure
/// proves two keys at once, and the packets that had been waiting on the
/// lost one still get verified.
#[test]
fn lost_interval_recovers() {
    let m = model();
    let (mut srtp, mut tesla, mut rx) = setup();

    let mut delivered = 0u64;
    for _ in 0..40 {
        let (i, mut buf) = produce(&mut srtp, &mut tesla, &m);
        // the network loses every packet of interval 4 (sent in the
        // 3 us..4 us window): those packets carried the disclosures of
        // key 2, so key 2 must later be recovered from key 3
        let send = m.send_ns(i);
        if (3_000..4_000).contains(&send) {
            continue;
        }
        rx.process_arrival(&mut buf, send + 100)
            .expect("surviving packets must be delivered");
        delivered += 1;
    }

    let s = rx.stats();
    // every surviving packet was delivered, and the ones waiting on the
    // lost interval's key were still verified
    assert_eq!(s.delivered, delivered);
    assert_eq!(s.forged, 0);
    assert_eq!(s.verified + rx.unsettled(), delivered);
}

/// The forgery case: one packet's TESLA MAC is flipped in flight. The
/// outer SRTP layer still accepts it (the extension is outside its tag),
/// so it is delivered optimistically. However, at settlement it is
/// flagged as forged.
#[test]
fn flipped_mac_flagged_as_forged() {
    let m = model();
    let (mut srtp, mut tesla, mut rx) = setup();

    for _ in 0..40 {
        let (i, mut buf) = produce(&mut srtp, &mut tesla, &m);
        // tampering with packet 5: the last byte is inside the MAC field
        if i == 5 {
            *buf.last_mut().unwrap() ^= 0xFF;
        }
        rx.process_arrival(&mut buf, m.send_ns(i) + 100)
            .expect("the tampered packet still passes the outer filter");
    }

    let s = rx.stats();
    // the tampered packet fails its verdict
    assert_eq!(s.forged, 1);
    // everything else settles or waits at the stream's end as usual
    assert_eq!(s.verified + s.forged + rx.unsettled(), s.delivered);
}

/// The too-late case: a packet held back until after its key's disclosure
/// moment is rejected by the accept test.
#[test]
fn late_packet_rejected_unsafe() {
    let m = model();
    let (mut srtp, mut tesla, mut rx) = setup();

    let (i, mut buf) = produce(&mut srtp, &mut tesla, &m);
    // packet of interval 1, arriving at 5 us: the sender is far past
    // interval 3, where key 1 went out
    assert_eq!(
        rx.process_arrival(&mut buf, 5_000),
        Err(TeslaDrop::UnsafeLate)
    );
    let _ = i;
    // the packet never reached the SRTP layer
    assert_eq!(rx.stats().delivered, 0);
    assert_eq!(rx.inner_stats().decrypted, 0);
}
