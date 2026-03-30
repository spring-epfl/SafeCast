//! MLS-SRTP Demo: Exporting MLS group keys to protect SRTP media.
//!
//! Demonstrates the full pipeline:
//!   MLS group setup (RFC 9420)
//!   -> key export via the MLS exporter (RFC 9420 §8.5)
//!   -> SRTP protection using libsrtp with AEAD-AES-128-GCM (RFC 7714)

// Our library modules: MLS group helpers, RTP packet construction, libsrtp sessions
use mls_srtp_demo::mls::{
    export_srtp_keys, MlsMember, CIPHERSUITE, SRTP_MASTER_KEY_LABEL, SRTP_MASTER_SALT_LABEL,
};
use mls_srtp_demo::rtp::RtpPacket;
use mls_srtp_demo::srtp_session::{create_receiver_session, create_sender_session};

// OpenMLS: the MLS protocol implementation
use openmls::prelude::*;
// Needed to access the cryptographic provider for key export
use openmls_traits::OpenMlsProvider;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

fn green(msg: impl AsRef<str>) -> String {
    format!("{}{}{}", GREEN, msg.as_ref(), RESET)
}

fn red(msg: impl AsRef<str>) -> String {
    format!("{}{}{}", RED, msg.as_ref(), RESET)
}

fn main() {
    println!("=== MLS-SRTP Demo ===");
    println!("Demonstrates exporting MLS group keys to protect SRTP media.\n");

    // initializing libsrtp's global state
    srtp::ensure_init();

    // -----------------------------------------------------------------------
    // Step 1: creating MLS group with Alice and Bob
    //
    // Alice creates the group, then adds Bob using his KeyPackage.
    // Bob joins by processing the Welcome message. 
    // After this step, both share the same group epoch and key schedule.
    // -----------------------------------------------------------------------
    println!("--- Step 1: MLS Group Setup ---\n");

    let alice = MlsMember::new("Alice");
    let bob = MlsMember::new("Bob");

    // Selecting the MLS ciphersuite for all MLS-internal crypto
    // (handshake encryption, key schedule, signatures, etc.)
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true) // embeds the ratchet tree inside Welcome messages
        .build();

    // Alice creates a new MLS group (she is the only member at epoch 0)
    let mut alice_group = MlsGroup::new(
        &alice.provider,
        &alice.signer,
        &group_config,
        alice.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    println!(
        "Alice created MLS group (id: {})",
        hex::encode(alice_group.group_id().as_slice())
    );

    // Bob generates a KeyPackage (a one-time-use bundle that allows
    // Alice to add him without Bob being online at the time)
    let bob_kp = bob.generate_key_package();

    // Alice adds Bob: this produces a Commit (group state update) and
    // a Welcome (encrypted group state for the new member)
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice.provider,
            &alice.signer,
            &[bob_kp.key_package().clone()],
        )
        .expect("failed to add Bob");

    // Alice applies her own Commit to advance to epoch 1
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("failed to merge pending commit");

    // Bob processes the Welcome to join the group at epoch 1
    let welcome_in: MlsMessageIn = welcome.into();
    let welcome_msg = welcome_in
        .into_welcome()
        .expect("expected Welcome message");

    // Bob decrypts the Welcome, then joins the group at epoch 1
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob.provider,
        group_config.join_config(),
        welcome_msg,
        None, // ratchet tree is already embedded in the Welcome
    )
    .expect("failed to stage welcome")
    .into_group(&bob.provider)
    .expect("failed to join group");

    println!("Bob joined the group via Welcome message.");
    println!("Group epoch: {}", alice_group.epoch().as_u64());
    println!("Group members: Alice, Bob\n");

    // -----------------------------------------------------------------------
    // Step 2: Exporting SRTP keying material from MLS
    //
    // Both Alice and Bob call the MLS exporter with the same labels and
    // context. Since they share the same exporter_secret (derived from
    // the group's epoch_secret), they produce identical output.
    // -----------------------------------------------------------------------
    println!("--- Step 2: MLS Key Export for SRTP ---\n");

    let sender_id = b"Alice";
    let ssrc: u32 = 0xDEADBEEF;

    // Both sides export
    let (alice_km, alice_mk, alice_ms) =
        export_srtp_keys(&alice_group, alice.provider.crypto(), sender_id, ssrc);
    let (bob_km, bob_mk, bob_ms) =
        export_srtp_keys(&bob_group, bob.provider.crypto(), sender_id, ssrc);

    // the results must be identical    
    assert_eq!(alice_mk, bob_mk, "Master keys must match!");
    assert_eq!(alice_ms, bob_ms, "Master salts must match!");

    println!(
        "Exporter context: (sender_id={:?}, SSRC=0x{:08X})",
        String::from_utf8_lossy(sender_id),
        ssrc
    );
    println!(
        "Master key  (label=\"{}\", {} bytes): {}",
        SRTP_MASTER_KEY_LABEL,
        alice_mk.len(),
        hex::encode(&alice_mk)
    );
    println!(
        "Master salt (label=\"{}\", {} bytes): {}",
        SRTP_MASTER_SALT_LABEL,
        alice_ms.len(),
        hex::encode(&alice_ms)
    );
    println!("Alice and Bob derived identical master keys.");
    println!(
        "Key material for SRTP ({} bytes): {}\n",
        alice_km.len(),
        hex::encode(&alice_km)
    );

    // -----------------------------------------------------------------------
    // Step 3: Creating SRTP sessions
    //
    // We pass the 28-byte key material (master_key || master_salt) to
    // libsrtp, which internally runs the SRTP KDF (RFC 3711 §4.3.1)
    // to derive session encryption keys and session salt.
    // -----------------------------------------------------------------------
    println!("--- Step 3: Creating SRTP Sessions ---\n");

    let mut alice_srtp = create_sender_session(&alice_km);
    let mut bob_srtp = create_receiver_session(&bob_km);
    println!("Alice: outbound SRTP session created.");
    println!("Bob:   inbound SRTP session created.");
    println!();

    // -----------------------------------------------------------------------
    // Step 4: Protecting RTP packets with SRTP
    //
    // Alice serializes RTP packets and calls protect(), which:
    //   - Constructs the 12-byte IV per RFC 7714 §8.1
    //   - Encrypts the payload with AES-128-GCM
    //   - Appends a 16-byte authentication tag
    // -----------------------------------------------------------------------
    println!("--- Step 4: SRTP Protection (Alice -> Bob) ---\n");

    // Building three synthetic RTP packets simulating audio.
    // The RTP timestamp (RFC 3550 §5.1) is measured in media clock ticks (not wall-clock
    // time). For 48kHz audio with 20ms frames: 48000 x 0.020 = 960 ticks per
    // frame, so timestamps go 960, 1920, 2880, ...
    let packets = vec![
        RtpPacket {
            payload_type: 111,
            sequence_number: 1,
            timestamp: 960,
            ssrc,
            payload: b"Hello from Alice - audio frame 1".to_vec(),
        },
        RtpPacket {
            payload_type: 111,
            sequence_number: 2,
            timestamp: 1920,
            ssrc,
            payload: b"Hello from Alice - audio frame 2".to_vec(),
        },
        RtpPacket {
            payload_type: 111,
            sequence_number: 3,
            timestamp: 2880,
            ssrc,
            payload: b"Hello from Alice - audio frame 3".to_vec(),
        },
    ];

    // collecting the encrypted packets for Bob
    let mut srtp_packets = Vec::new();

    // protecting each RTP packet with SRTP
    for pkt in &packets { 
        let rtp_bytes = pkt.to_bytes();
        let mut buf = rtp_bytes.clone();

        // encrypting (the buffer grows by 16 bytes: the GCM auth tag)
        alice_srtp.protect(&mut buf).expect("srtp_protect failed");

        println!(
            "RTP seq={} ({} bytes) -> SRTP ({} bytes, +{} overhead)",
            pkt.sequence_number,
            rtp_bytes.len(),
            buf.len(),
            buf.len() - rtp_bytes.len()
        );
        println!(
            "  RTP payload:  {:?}",
            String::from_utf8_lossy(&pkt.payload)
        );
        println!(
            "  SRTP encrypted (first 32 bytes): {}...",
            hex::encode(&buf[12..std::cmp::min(44, buf.len())])
        );

        srtp_packets.push(buf);
    }
    println!();

    // -----------------------------------------------------------------------
    // Step 5: Decrypting on receiver side (Bob)
    //
    // Bob calls unprotect(), which verifies the GCM auth tag and decrypts
    // the payload. The buffer shrinks by 16 bytes (tag removed).
    // libsrtp also enforces replay protection via the sliding window.
    // -----------------------------------------------------------------------
    println!("--- Step 5: SRTP Decryption (Bob receives) ---\n");

    for (i, srtp_bytes) in srtp_packets.iter().enumerate() {
        let mut buf = srtp_bytes.clone();
        // decrypting: verifies the GCM auth tag, then strips it (buf shrinks by 16 bytes)
        bob_srtp
            .unprotect(&mut buf)
            .expect("Bob: SRTP decryption failed");

        // parsing the decrypted RTP packet
        let rtp = RtpPacket::from_bytes(&buf).expect("invalid RTP");
        let original = &packets[i];

        // comparing against the original
        assert_eq!(rtp.payload, original.payload);
        assert_eq!(rtp.sequence_number, original.sequence_number);
        assert_eq!(rtp.ssrc, original.ssrc);

        println!(
            "SRTP seq={} -> decrypted payload: {:?}",
            rtp.sequence_number,
            String::from_utf8_lossy(&rtp.payload)
        );
    }
    println!("\n{}\n", green("All packets decrypted and verified successfully."));

    // -----------------------------------------------------------------------
    // Step 6: Tamper detection
    //
    // We flip a bit in the ciphertext and verify that unprotect() rejects it.
    // We create a fresh receiver session because the original bob_srtp
    // has already seen seq=1 and would reject it as a replay.
    // -----------------------------------------------------------------------
    println!("--- Step 6: Tamper Detection ---\n");

    let mut tamper_recv = create_receiver_session(&bob_km);
    let mut tampered = srtp_packets[0].clone();

    tampered[20] ^= 0xFF; // flipping a bit in the encrypted payload

    match tamper_recv.unprotect(&mut tampered) {
        Ok(_) => println!("{}", red("ERROR: Tampered packet was accepted!")),
        Err(e) => println!("{}", green(format!("Tampered packet correctly rejected: {}", e))),
    }

    // -----------------------------------------------------------------------
    // Step 7: Rekeying
    //
    // Alice sends a self-update Commit, which advances the MLS epoch.
    // This rotates the group's key schedule: the new epoch_secret (and
    // therefore exporter_secret) is derived from fresh key material,
    // so old keys cannot decrypt new-epoch traffic (forward secrecy).
    //
    // Both sides export new SRTP keys and create new SRTP sessions.
    // We verify that:
    //   (a) new keys differ from old keys
    //   (b) new keys work for protect/unprotect
    //   (c) old keys cannot decrypt new-epoch packets
    // -----------------------------------------------------------------------
    println!("\n--- Step 7: MLS Epoch Advancement (Rekeying) ---\n");

    let old_mk = alice_mk;

    // Alice sends a self-update Commit (refreshes her leaf key material)
    let commit_bundle = alice_group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .expect("self-update failed");

    let commit = commit_bundle.into_commit();

    // Alice applies her own Commit to advance to epoch 2
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("failed to merge self-update");

    // Bob processes Alice's Commit
    let processed = bob_group
        .process_message(
            &bob.provider,
            commit
                .into_protocol_message()
                .expect("expected protocol message"),
        )
        .expect("Bob: process commit failed");

    // applying the staged commit to advance Bob's group state to epoch 2
    if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
        bob_group
            .merge_staged_commit(&bob.provider, *staged)
            .expect("Bob: merge staged commit failed");
    }

    println!("Alice advanced the epoch via self-update commit.");
    println!("New epoch: {}", alice_group.epoch().as_u64());

    // exporting new SRTP keys from the new epoch
    let (new_alice_km, new_alice_mk, new_alice_ms) =
        export_srtp_keys(&alice_group, alice.provider.crypto(), sender_id, ssrc);
    let (new_bob_km, new_bob_mk, new_bob_ms) =
        export_srtp_keys(&bob_group, bob.provider.crypto(), sender_id, ssrc);
    
    // verifying both sides derived identical new keys
    assert_eq!(new_alice_mk, new_bob_mk);
    assert_eq!(new_alice_ms, new_bob_ms);
    
    // verifying the new keys differ from the old epoch's keys
    assert_ne!(
        old_mk, new_alice_mk,
        "Keys must change after epoch advance"
    );

    println!("New master key: {}", hex::encode(&new_alice_mk));
    println!("{}", green("Old and new keys differ: confirmed."));

    // creating new SRTP sessions with the new epoch's keys
    let mut new_alice_srtp = create_sender_session(&new_alice_km);
    let mut new_bob_srtp = create_receiver_session(&new_bob_km);

    // our test packet simulating post-rekey audio
    let test_pkt = RtpPacket {
        payload_type: 111,
        sequence_number: 4,
        timestamp: 3840,
        ssrc,
        payload: b"Post-rekey audio frame".to_vec(),
    };

    // protecting with new-epoch keys
    let mut srtp_buf = test_pkt.to_bytes();
    new_alice_srtp
        .protect(&mut srtp_buf)
        .expect("protect failed");

    // decrypting with new-epoch keys —> should succeed
    let mut rtp_buf = srtp_buf.clone();
    new_bob_srtp
        .unprotect(&mut rtp_buf)
        .expect("new-epoch decrypt failed");
    let decoded = RtpPacket::from_bytes(&rtp_buf).unwrap();
    assert_eq!(decoded.payload, test_pkt.payload);
    println!(
        "{}",
        green(format!(
            "Post-rekey packet protected and decrypted successfully: {:?}",
            String::from_utf8_lossy(&decoded.payload)
        ))
    );

    // attempting to decrypt with OLD epoch keys —> should fail
    let mut old_recv = create_receiver_session(&bob_km);
    let mut old_buf = srtp_buf.clone();
    match old_recv.unprotect(&mut old_buf) {
        Ok(_) => println!("{}", red("ERROR: Old keys decrypted new-epoch packet!")),
        Err(e) => println!(
            "{}",
            green(format!("Old-epoch keys cannot decrypt new-epoch packet: {}", e))
        ),
    }

    println!("\n=== Demo Complete ===");
}
