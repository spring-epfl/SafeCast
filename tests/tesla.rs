//! End-to-end TESLA tests: SRTP sender and receiver with the
//! TESLA layer around both.
//! Each test plays one network scenario (clean delivery, a lost interval,
//! a tampered packet, a too-late packet) and checks that every delivered
//! packet ends up with the right verdict, such as "verified" or "forged".

use safecast_core::keying::granularity::Granularity;
use safecast_core::keying::mls::{ssrc_from_identity, MlsMember, CIPHERSUITE};
use safecast_core::keying::ratchet::StreamRatchet;
use safecast_core::receiver::generation::GenerationScheme;
use safecast_core::receiver::ReceiverKeyManager;
use safecast_core::simulation::sender::{SimulatedSender, StreamModel};
use safecast_core::tesla::commitment::TeslaCommitment;
use safecast_core::tesla::mac::TeslaMacAlg;
use safecast_core::tesla::schedule::TeslaSchedule;
use safecast_core::tesla::receiver::{TeslaDrop, TeslaReceiver};
use safecast_core::tesla::sender::TeslaSender;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// The two group members: the sender creates the group, the receiver
/// joins via Welcome.
const SENDER_ID: &str = "camera-1:sender";
const RECEIVER_ID: &str = "screen-2:receiver";

/// The sender's stream identifier, derived from its identity.
fn ssrc() -> u32 {
    ssrc_from_identity(SENDER_ID)
}

/// The stream: 100-byte payloads, sent one every ~321 ns (the model's
/// 1080p60 pacing at that payload size).
fn model() -> StreamModel {
    StreamModel::new(100, ssrc())
}

/// The schedule: 1 us intervals (a few packets per interval at the
/// model's pacing), d = 2, a 64-interval chain, no clock skew.
fn params() -> TeslaSchedule {
    TeslaSchedule::new(0, 1_000, 2, 64, 0, 16)
}

/// A two-member MLS group: the sender creates it, the receiver
/// joins via Welcome. Returns each side's own view of the group together
/// with its member state (crypto provider + signing key).
fn setup_group() -> ((MlsGroup, MlsMember), (MlsGroup, MlsMember)) {
    let sender = MlsMember::new(SENDER_ID);
    let receiver = MlsMember::new(RECEIVER_ID);
    // the ratchet tree rides in the Welcome so the joiner needs no
    // extra fetches
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    // the sender creates the group...
    let mut sender_group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create group");
    // ...and adds the receiver
    let kp = receiver.generate_key_package().key_package().clone();
    let (_commit, welcome, _) = sender_group
        .add_members(&sender.provider, &sender.signer, &[kp])
        .expect("add_members failed");
    sender_group
        .merge_pending_commit(&sender.provider)
        .expect("merge_pending_commit failed");
    // the receiver joins from the Welcome
    let welcome_in: MlsMessageIn = welcome.into();
    let welcome_msg = welcome_in.into_welcome().expect("expected Welcome");
    let tree = sender_group.export_ratchet_tree();
    let receiver_group = StagedWelcome::new_from_welcome(
        &receiver.provider,
        config.join_config(),
        welcome_msg,
        Some(tree.into()),
    )
    .expect("welcome failed")
    .into_group(&receiver.provider)
    .expect("into_group failed");
    ((sender_group, sender), (receiver_group, receiver))
}

/// One sender + one receiver, bootstrapped through MLS: the SRTP
/// keys come from each side's own group exporter, the commitment is
/// signed with the sender's MLS leaf key, and the receiver takes the
/// sender's public key from its own view of the group tree.
fn setup() -> (SimulatedSender, TeslaSender, TeslaReceiver) {
    let ((sender_group, sender_member), (receiver_group, receiver_member)) = setup_group();
    let p = params();

    // both sides derive the SRTP ratchet from their own group view
    let tx_ratchet =
        StreamRatchet::seed_from_exporter(&sender_group, sender_member.provider.crypto(), ssrc());
    let rx_ratchet = StreamRatchet::seed_from_exporter(
        &receiver_group,
        receiver_member.provider.crypto(),
        ssrc(),
    );

    // the media sender: encrypts the modeled stream in send order
    let srtp_sender = SimulatedSender::new(model(), Granularity::EpochOnly, tx_ratchet);
    // the TESLA sender: builds its private chain, tags every packet
    let tesla_sender = TeslaSender::new(p, TeslaMacAlg::HmacSha256);

    // the sender publishes its commitment, signed with its MLS leaf key
    let commitment = TeslaCommitment {
        anchor: *tesla_sender.anchor(),
        t0_ns: p.t0_ns,
        t_int_ns: p.t_int_ns,
        d: p.d,
        n_chain: p.n_chain,
        mac_alg: TeslaMacAlg::HmacSha256,
        sender_identity: SENDER_ID.as_bytes().to_vec(),
        ssrc: ssrc(),
        group_id: sender_group.group_id().as_slice().to_vec(),
        epoch: sender_group.epoch().as_u64(),
    };
    let signature = commitment.sign(&sender_member.signer);

    // the receiver takes the sender's public key from its own view of the
    // group tree
    let sender_leaf_key = receiver_group
        .members()
        .find(|m| m.credential.serialized_content() == SENDER_ID.as_bytes())
        .expect("sender must be in the receiver's group view")
        .signature_key;

    // the SRTP receiver, keyed from the receiver's own exporter seed
    let inner = ReceiverKeyManager::new(
        GenerationScheme::EpochOnly,
        ssrc(),
        rx_ratchet,
        1,    // key window: epoch-only has a single generation
        4096, // seek cap (not used at epoch-only)
        0,    // libsrtp's default replay window
    );
    // the TESLA receiver, constructible from the verified commitment
    let tesla_receiver = TeslaReceiver::accept(
        &commitment,
        &signature,
        &sender_leaf_key,
        receiver_member.provider.crypto(),
        p.d_t_ns,
        p.g_max,
        inner,
    )
    .expect("the commitment must verify");
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
