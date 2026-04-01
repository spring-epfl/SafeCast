//! Bob: MLS group joiner and SRTP multicast receiver.
//!
//! Demonstrates the "receiver" side of the MLS-SRTP pipeline:
//!   1. Register identity + public key with AS, upload KeyPackages to DS
//!   2. Poll DS for Welcome message from Alice
//!   3. Process Welcome and join the MLS group
//!   4. Verify Alice's credential by cross-checking AS and group tree
//!   5. Export SRTP master key and salt from the MLS group epoch
//!   6. Join multicast group, receive and decrypt SRTP packets

use mls_srtp_common::ds_client::DsClient;
use mls_srtp_common::mls::{
    export_srtp_keys, MlsMember, CIPHERSUITE, SRTP_MASTER_KEY_LABEL, SRTP_MASTER_SALT_LABEL,
};
use mls_srtp_common::multicast;
use mls_srtp_common::rtp::RtpPacket;
use mls_srtp_common::srtp_session::create_receiver_session;

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// ANSI escape: magenta text for Bob's prefix
const TAG: &str = "\x1b[35m[Bob]\x1b[0m";
/// ANSI escape: green for success messages
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

/// Wraps a message in green ANSI color for terminal output.
fn green(msg: impl AsRef<str>) -> String {
    format!("{}{}{}", GREEN, msg.as_ref(), RESET)
}

/// Base URL of the Authentication Service.
const AS_URL: &str = "http://127.0.0.1:8001";
/// Base URL of the OpenMLS Delivery Service.
const DS_URL: &str = "http://127.0.0.1:8080";

#[tokio::main]
async fn main() {
    println!("{TAG} === Bob (MLS Group Joiner/SRTP Receiver) ===");

    // initializing libsrtp's global state
    srtp::ensure_init();
    let mut client = DsClient::new(AS_URL, DS_URL);
    // creating Bob's MLS identity with a fresh Ed25519 signing key
    let bob = MlsMember::new("Bob");

    // -----------------------------------------------------------------------
    // Step 1: Registering with AS and DS
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 1: Registration ---");

    // registering Bob's identity and public signing key with the AS so
    // other clients can later verify his credential
    client
        .register_with_as("Bob", &bob.signer.to_public_vec())
        .await
        .expect("AS registration failed");
    println!("{TAG} Registered with Authentication Service.");

    // generating two KeyPackages for DS registration;
    // the OpenMLS DS requires at least 2
    let bob_kp1 = bob.generate_key_package();
    let bob_kp2 = bob.generate_key_package();

    // computing hash references for each KeyPackage: the DS uses these
    // to match incoming Welcome messages to the correct recipient
    let kp1_hash = bob_kp1
        .key_package()
        .hash_ref(bob.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();
    let kp2_hash = bob_kp2
        .key_package()
        .hash_ref(bob.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();

    // converting to KeyPackageIn (the wire type expected by the DS)
    let kp1_in: KeyPackageIn = bob_kp1.key_package().clone().into();
    let kp2_in: KeyPackageIn = bob_kp2.key_package().clone().into();

    // uploading KeyPackages to the DS; the response includes an auth token
    // that we will need for subsequent DS operations
    client
        .register_with_ds(b"Bob", vec![(kp1_hash, kp1_in), (kp2_hash, kp2_in)])
        .await
        .expect("DS registration failed");
    println!("{TAG} Registered with Delivery Service (with 2 KeyPackages).");

    // -----------------------------------------------------------------------
    // Step 2: Waiting for Welcome message from Alice
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 2: Waiting for Welcome ---");
    println!("{TAG} Polling DS for messages...");

    // polling the DS message queue until a Welcome message arrives
    let welcome_msg: Welcome = loop {
        let msgs = client
            .recv_messages()
            .await
            .expect("DS recv messages failed");

        // scanning the message batch for a Welcome (skipping non-Welcome messages)
        let mut found = None;
        for msg in msgs {
            if let Some(welcome) = msg.into_welcome() {
                found = Some(welcome);
                break;
            }
        }
        if let Some(welcome) = found {
            break welcome;
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    println!("{TAG} Received Welcome message.");

    // -----------------------------------------------------------------------
    // Step 3: Processing Welcome and joining MLS group
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 3: Joining MLS Group ---");

    // using the same group configuration as Alice (must match for join to succeed)
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // processing the Welcome in two stages (RFC 9420 §12.4.3.1):
    //   1. StagedWelcome: decrypt and validate the Welcome, extract group info
    //   2. into_group: finalize and create the MlsGroup state
    let bob_group = StagedWelcome::new_from_welcome(
        &bob.provider,
        group_config.join_config(),
        welcome_msg,
        // no external ratchet tree needed (it is embedded in the Welcome
        // via use_ratchet_tree_extension(true))
        None,
    )
    .expect("failed to stage welcome")
    .into_group(&bob.provider)
    .expect("failed to join group");

    println!(
        "{TAG} Joined MLS group (id: {})",
        hex::encode(bob_group.group_id().as_slice())
    );
    println!("{TAG} Group epoch: {}", bob_group.epoch().as_u64());

    // -----------------------------------------------------------------------
    // Step 4: Verifying Alice's credential via AS
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 4: Credential Verification ---");

    // fetching Alice's public signing key from the AS
    let alice_pk_from_as = client
        .lookup_as("Alice")
        .await
        .expect("AS lookup for Alice failed");

    // finding Alice's leaf node in the group's ratchet tree by matching
    // the credential content (identity) against "Alice"
    let alice_pk_from_tree: Vec<u8> = bob_group
        .members()
        .find(|m| {
            let cred = m.credential.serialized_content();
            cred == b"Alice"
        })
        .map(|m| m.signature_key.to_vec())
        .expect("Alice not found in group tree");

    // cross-checking: the public key from the AS must match the one in
    // Alice's leaf node (this proves Alice's group membership is authentic
    // and the group was not set up by an impersonator)
    assert_eq!(
        alice_pk_from_as, alice_pk_from_tree,
        "Alice's public key from AS does not match group tree!"
    );
    println!(
        "{TAG} {}",
        green("Alice's credential verified: AS public key matches group tree signature key.")
    );

    // -----------------------------------------------------------------------
    // Step 5: Exporting SRTP keys
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 5: SRTP Key Export ---");

    // using the same sender_id and SSRC as Alice so both sides derive
    // identical SRTP keys from the shared MLS exporter_secret
    let sender_id = b"Alice";
    let ssrc: u32 = 0xDEADBEEF;

    // deriving SRTP master key (16 bytes) and master salt (12 bytes) from
    // the MLS group's exporter_secret
    let (key_material, master_key, master_salt) =
        export_srtp_keys(&bob_group, bob.provider.crypto(), sender_id, ssrc);

    println!(
        "{TAG} Exporter context: (sender_id={:?}, SSRC=0x{:08X})",
        String::from_utf8_lossy(sender_id),
        ssrc
    );
    println!(
        "{TAG} Master key  (label=\"{}\", {} bytes): {}",
        SRTP_MASTER_KEY_LABEL,
        master_key.len(),
        hex::encode(&master_key)
    );
    println!(
        "{TAG} Master salt (label=\"{}\", {} bytes): {}",
        SRTP_MASTER_SALT_LABEL,
        master_salt.len(),
        hex::encode(&master_salt)
    );

    // -----------------------------------------------------------------------
    // Step 6: Receiving SRTP packets from multicast
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 6: Receiving SRTP from Multicast ---");

    // creating the inbound SRTP session with the same key material Alice uses
    let mut bob_srtp = create_receiver_session(&key_material);

    // creating the multicast receiver socket (binds to 0.0.0.0:5004, joins
    // the multicast group via IGMP)
    let socket = multicast::create_multicast_receiver()
        .expect("failed to create multicast receiver");

    println!(
        "{TAG} Joined multicast group {}:{}, waiting for packets...",
        multicast::MULTICAST_ADDR,
        multicast::MULTICAST_PORT
    );

    // 2048 bytes for this demo
    let mut buf = vec![0u8; 2048];
    let mut received = 0;
    let expected = 3;

    // timeout after 30 seconds of no packets
    let timeout = std::time::Duration::from_secs(30);

    while received < expected {
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {

                // copying the received bytes into a separate buffer because
                // libsrtp's unprotect modifies the buffer in-place
                let mut pkt_buf = buf[..len].to_vec();

                // decrypting and verifying the SRTP packet
                bob_srtp
                    .unprotect(&mut pkt_buf)
                    .expect("SRTP decryption failed");

                // parsing the decrypted RTP packet to extract the payload
                let rtp = RtpPacket::from_bytes(&pkt_buf).expect("invalid RTP");

                println!(
                    "{TAG} SRTP from {} -> seq={}, decrypted payload: {:?}",
                    src,
                    rtp.sequence_number,
                    String::from_utf8_lossy(&rtp.payload)
                );

                received += 1;
            }
            Ok(Err(e)) => {
                eprintln!("{TAG} Receive error: {}", e);
                break;
            }
            Err(_) => {
                println!("{TAG} Timeout waiting for packets.");
                break;
            }
        }
    }

    println!(
        "{TAG} {}",
        green(format!(
            "Received and decrypted {}/{} SRTP packets successfully.",
            received, expected
        ))
    );
    println!();
    println!("{TAG} === Bob Done ===");
}
