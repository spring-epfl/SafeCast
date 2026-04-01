//! Alice: MLS group creator and SRTP multicast sender.
//!
//! Demonstrates the "sender" side of the MLS-SRTP pipeline:
//!   1. Register identity + public key with AS, upload KeyPackages to DS
//!   2. Fetch Bob's KeyPackage from DS
//!   3. Verify Bob's credential by cross-checking AS and KeyPackage
//!   4. Create an MLS group and add Bob (produces Welcome + Commit)
//!   5. Deliver the Welcome message to Bob via DS
//!   6. Export SRTP master key and salt from the MLS group epoch
//!   7. Send SRTP-protected RTP packets over IP multicast UDP

use mls_srtp_common::ds_client::DsClient;
use mls_srtp_common::mls::{
    export_srtp_keys, MlsMember, CIPHERSUITE, SRTP_MASTER_KEY_LABEL, SRTP_MASTER_SALT_LABEL,
};
use mls_srtp_common::multicast;
use mls_srtp_common::rtp::RtpPacket;
use mls_srtp_common::srtp_session::create_sender_session;

use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// ANSI escape: cyan text for Alice's prefix
const TAG: &str = "\x1b[36m[Alice]\x1b[0m";
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
    println!("{TAG} === Alice (MLS Group Creator/SRTP Sender) ===");

    // initializing libsrtp's global state
    srtp::ensure_init();
    let mut client = DsClient::new(AS_URL, DS_URL);

    // creating Alice's MLS identity with a fresh Ed25519 signing key
    let alice = MlsMember::new("Alice");

    // -----------------------------------------------------------------------
    // Step 1: Registering with AS and DS
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 1: Registration ---");

    // registering Alice's identity and public signing key with the AS so
    // other clients can later verify her credential
    client
        .register_with_as("Alice", &alice.signer.to_public_vec())
        .await
        .expect("AS registration failed");
    println!("{TAG} Registered with Authentication Service.");

    // generating two KeyPackages for DS registration;
    // the OpenMLS DS requires at least 2 (it keeps one as a permanent
    // reserve and only hands out the others via consume_key_package)
    let alice_kp1 = alice.generate_key_package();
    let alice_kp2 = alice.generate_key_package();

    // computing hash references for each KeyPackage: the DS uses these
    // to match incoming Welcome messages to the correct recipient
    let kp1_hash = alice_kp1
        .key_package()
        .hash_ref(alice.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();
    let kp2_hash = alice_kp2
        .key_package()
        .hash_ref(alice.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();

    // converting to KeyPackageIn (the type expected by the DS)
    let kp1_in: KeyPackageIn = alice_kp1.key_package().clone().into();
    let kp2_in: KeyPackageIn = alice_kp2.key_package().clone().into();

    // uploading KeyPackages to the DS; the response includes an auth token
    // that we will need for subsequent DS operations
    client
        .register_with_ds(b"Alice", vec![(kp1_hash, kp1_in), (kp2_hash, kp2_in)])
        .await
        .expect("DS registration failed");
    println!("{TAG} Registered with Delivery Service.");

    // -----------------------------------------------------------------------
    // Step 2: Fetching for Bob's KeyPackage
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 2: Fetching Bob's KeyPackage ---");
    println!("{TAG} Polling DS for Bob's KeyPackage...");

    // polling until Bob registers and his KeyPackage becomes available
    let bob_kp_bytes = loop {
        match client
            .consume_key_package(b"Bob")
            .await
            .expect("DS consume KP failed")
        {
            Some(bytes) => break bytes,
            None => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };

    // deserializing the TLS-encoded KeyPackage received from the DS
    let bob_kp_in = KeyPackageIn::tls_deserialize_exact(&bob_kp_bytes)
        .expect("failed to deserialize Bob's KeyPackage");

    println!("{TAG} Got Bob's KeyPackage from DS.");

    // -----------------------------------------------------------------------
    // Step 3: Verifying Bob's credential via AS
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 3: Credential Verification ---");

    // fetching Bob's public signing key from the AS
    let bob_pk_from_as = client
        .lookup_as("Bob")
        .await
        .expect("AS lookup for Bob failed");

    // validating Bob's KeyPackage (checks signature, ciphersuite, lifetime)
    // and extracting his public signing key from the leaf node
    let bob_kp_ref: KeyPackage = bob_kp_in
        .clone()
        .validate(alice.provider.crypto(), ProtocolVersion::Mls10)
        .expect("Bob's KeyPackage validation failed");
    let bob_pk_from_kp = bob_kp_ref.leaf_node().signature_key().as_slice();

    // cross-checking (RFC 9420 §5.3.1): the public key from the AS must match the one in
    // Bob's KeyPackage (this proves Bob's KeyPackage is authentic and
    // not forged by a malicious DS)
    assert_eq!(
        bob_pk_from_as, bob_pk_from_kp,
        "Bob's public key from AS does not match KeyPackage!"
    );
    println!(
        "{TAG} {}",
        green("Bob's credential verified: AS public key matches KeyPackage signature key.")
    );

    // -----------------------------------------------------------------------
    // Step 4: Creating MLS group and adding Bob
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 4: MLS Group Setup ---");

    // configuring the group to include the ratchet tree in Welcome messages
    // so Bob can join without fetching it separately from the DS
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // creating a new MLS group with Alice as the sole initial member
    let mut alice_group = MlsGroup::new(
        &alice.provider,
        &alice.signer,
        &group_config,
        alice.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    println!(
        "{TAG} Created MLS group (id: {})",
        hex::encode(alice_group.group_id().as_slice())
    );

    // adding Bob to the group using his verified KeyPackage;
    // this produces a Commit (for existing members) and a Welcome (for Bob)
    let (_commit, welcome, _group_info) = alice_group
        .add_members(&alice.provider, &alice.signer, &[bob_kp_ref])
        .expect("failed to add Bob");

    // merging the pending commit locally to advance Alice's group state
    // to the new epoch (where Bob is a member)
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("failed to merge pending commit");

    println!("{TAG} Added Bob to the group.");
    println!("{TAG} Group epoch: {}", alice_group.epoch().as_u64());

    // -----------------------------------------------------------------------
    // Step 5: Delivering Welcome to Bob via DS
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 5: Delivering Welcome ---");

    // serializing the Welcome
    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("Welcome serialization failed");

    // sending to the DS, which routes it to Bob based on KeyPackage hashes
    client
        .send_welcome(&welcome_bytes)
        .await
        .expect("failed to send Welcome via DS");

    println!(
        "{TAG} Welcome message delivered to Bob via DS ({} bytes).",
        welcome_bytes.len()
    );

    // -----------------------------------------------------------------------
    // Step 6: Exporting SRTP keys
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 6: SRTP Key Export ---");

    // the sender_id and SSRC are packed into the exporter context so that
    // each RTP stream derives its own independent SRTP key and salt
    let sender_id = b"Alice";
    let ssrc: u32 = 0xDEADBEEF;

    // deriving SRTP master key (16 bytes) and master salt (12 bytes) from
    // the MLS group's exporter_secret via two separate export_secret calls
    let (key_material, master_key, master_salt) =
        export_srtp_keys(&alice_group, alice.provider.crypto(), sender_id, ssrc);

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
    // Step 7: Creating SRTP session and sending packets over multicast
    // -----------------------------------------------------------------------
    println!();
    println!("{TAG} --- Step 7: Sending SRTP over Multicast ---");

    // creating the outbound SRTP session with the exported key material;
    // libsrtp handles the SRTP KDF and IV construction internally
    let mut alice_srtp = create_sender_session(&key_material);

    // creating the multicast sender socket
    let socket = multicast::create_multicast_sender()
        .await
        .expect("failed to create multicast sender");
    let dest = multicast::multicast_dest();

    println!("{TAG} Multicast destination: {}", dest);

    // giving Bob a moment to join the multicast group before sending
    println!("{TAG} Waiting 2 seconds for Bob to set up receiver...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // constructing 3 synthetic RTP packets simulating an audio stream
    // (incrementing timestamps by 960 which represents 20ms at 48kHz)
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

    for pkt in &packets {

        // serializing the RTP packet to wire format (12-byte header + payload)
        let rtp_bytes = pkt.to_bytes();
        let mut buf = rtp_bytes.clone();

        // encrypting
        alice_srtp.protect(&mut buf).expect("srtp_protect failed");

        println!(
            "{TAG} RTP seq={} ({} bytes) -> SRTP ({} bytes, +{} overhead)",
            pkt.sequence_number,
            rtp_bytes.len(),
            buf.len(),
            buf.len() - rtp_bytes.len()
        );
        println!(
            "{TAG}   Payload: {:?}",
            String::from_utf8_lossy(&pkt.payload)
        );

        // sending the SRTP packet to the multicast group
        socket
            .send_to(&buf, &dest)
            .await
            .expect("multicast send failed");

        // simulating real-time pacing (20ms per frame)
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    println!("{TAG} {}", green("All SRTP packets sent over multicast."));
    println!();
    println!("{TAG} === Alice Done ===");
}
