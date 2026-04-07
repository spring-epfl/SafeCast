//! MLS-SRTP client with configurable participants.
//!
//! A binary that can act as a group creator, sender, or receiver. The creator
//! sets up the MLS group and delivers Welcome messages but does not participate
//! in SRTP traffic. Senders and receivers join the group via Welcome.
//! Identities are auto-generated and peers are discovered dynamically via the
//! Delivery Service.
//!
//! Usage examples:
//!   # Creator (sets up the group, waits for 1 sender and 3 receivers):
//!   mls-srtp-client --mode creator --senders 1 --receivers 3
//!
//!   # Sender (registers, joins via Welcome, sends SRTP):
//!   mls-srtp-client --mode sender --packets 3
//!
//!   # Receiver (registers, joins via Welcome, receives SRTP):
//!   mls-srtp-client --mode receiver --packets 3

use std::collections::HashMap;

use clap::{Parser, ValueEnum};

use mls_srtp_core::ds_client::DsClient;
use mls_srtp_core::mls::{
    export_srtp_keys, parse_credential_identity, ssrc_from_identity, MlsMember, CIPHERSUITE,
};
use mls_srtp_core::multicast;
use mls_srtp_core::rtp::RtpPacket;
use mls_srtp_core::srtp_session::{create_receiver_session, create_sender_session};

use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const RESET: &str = "\x1b[0m";

fn green(msg: impl AsRef<str>) -> String {
    format!("{GREEN}{}{RESET}", msg.as_ref())
}

/// The role this client plays in the MLS-SRTP session.
#[derive(Clone, ValueEnum)]
enum Mode {
    /// Create the MLS group and add all peers (no SRTP traffic).
    Creator,
    /// Join the group via Welcome, then send SRTP packets over multicast.
    Sender,
    /// Join the group via Welcome, then receive SRTP packets from multicast.
    Receiver,
}

#[derive(Parser)]
#[command(about = "MLS-SRTP client, senders/receivers join it")]
struct Cli {
    /// Run as creator (group setup only), sender, or receiver.
    #[arg(long)]
    mode: Mode,

    /// Number of senders to wait for before creating the group (creator only).
    #[arg(long, default_value = "1")]
    senders: u32,

    /// Number of receivers to wait for before creating the group (creator only).
    #[arg(long, default_value = "1")]
    receivers: u32,

    /// Number of SRTP packets to send (sender only).
    #[arg(long, default_value = "3")]
    packets: u32,

    /// Base URL of the Authentication Service.
    #[arg(long, default_value = "http://127.0.0.1:8001")]
    as_url: String,

    /// Base URL of the OpenMLS Delivery Service.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    ds_url: String,
}

/// Generates a unique credential identity based on mode and process ID.
/// Format is "label:role" (e.g. "sender-48231:sender" or "receiver-12045:receiver").
fn generate_identity(mode: &Mode) -> String {
    let pid = std::process::id();
    match mode {
        Mode::Creator => format!("creator-{pid}:creator"),
        Mode::Sender => format!("sender-{pid}:sender"),
        Mode::Receiver => format!("receiver-{pid}:receiver"),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // auto-generating a unique identity for this client based on its role.
    let identity = generate_identity(&cli.mode);
    let (label, _) = parse_credential_identity(&identity);
    let is_creator = matches!(cli.mode, Mode::Creator);
    let is_sender = matches!(cli.mode, Mode::Sender);
    let role_label = match cli.mode {
        Mode::Creator => "Creator",
        Mode::Sender => "Sender",
        Mode::Receiver => "Receiver",
    };

    // building a colored log prefix like "[sender-48231]" or "[receiver-12045]"
    let tag_color = match cli.mode {
        Mode::Creator => CYAN,
        Mode::Sender => CYAN,
        Mode::Receiver => MAGENTA,
    };
    let tag = format!("{tag_color}[{label}]{RESET}");

    println!("{tag} === {label} (MLS {role_label}) ===");

    // initializing libsrtp (must be called once before any SRTP operations)
    srtp::ensure_init();

    // setting up the DS client (used to talk to the AS and DS over HTTP)
    // and the MLS member (holds the crypto provider, signing key, and credential)
    let mut ds_client = DsClient::new(&cli.as_url, &cli.ds_url);
    let member = MlsMember::new(&identity);

    // -----------------------------------------------------------------------
    // Step 1: Registration (AS + DS)
    //
    // Every client (sender or receiver) must first register its identity
    // and Ed25519 public signing key with the Authentication Service, and
    // upload KeyPackages to the Delivery Service so that the group creator
    // can later add it to the MLS group.
    //
    // The AS identity must match the credential identity embedded in our
    // KeyPackages ("label:role"), so that peers can look us up by parsing
    // the credential from the MLS group tree.
    // -----------------------------------------------------------------------
    println!();
    println!("{tag} --- Step 1: Registration ---");

    // registering our identity + public signing key with the AS so other
    // participants can later verify our credential
    ds_client
        .register_with_as(&identity, &member.signer.to_public_vec())
        .await
        .expect("AS registration failed");
    println!("{tag} Registered with Authentication Service.");

    // generating two KeyPackages
    let kp1 = member.generate_key_package();
    let kp2 = member.generate_key_package();

    // computing the hash reference for each KeyPackage (the DS indexes
    // KeyPackages by these hashes)
    let kp1_hash = kp1
        .key_package()
        .hash_ref(member.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();
    let kp2_hash = kp2
        .key_package()
        .hash_ref(member.provider.crypto())
        .expect("KP hash failed")
        .as_slice()
        .to_vec();

    // converting to the wire format expected by the DS registration endpoint
    let kp1_in: KeyPackageIn = kp1.key_package().clone().into();
    let kp2_in: KeyPackageIn = kp2.key_package().clone().into();

    // uploading KeyPackages to the DS. This also returns an auth token that
    // we store internally for subsequent DS requests
    ds_client
        .register_with_ds(
            identity.as_bytes(),
            vec![(kp1_hash, kp1_in), (kp2_hash, kp2_in)],
        )
        .await
        .expect("DS registration failed");
    println!("{tag} Registered with Delivery Service.");

    // -----------------------------------------------------------------------
    // Step 2: Group setup (role-dependent)
    //
    // The creator discovers peers via the DS, fetches and verifies their
    // KeyPackages, creates the MLS group, adds everyone, and delivers
    // the Welcome message through the DS.
    //
    // Senders and receivers poll the DS until they receive a Welcome
    // message, then use it to join the group.
    // -----------------------------------------------------------------------
    let group = if is_creator {
        create_group(&cli, &identity, &tag, &mut ds_client, &member).await
    } else {
        join_group(&tag, &mut ds_client, &member).await
    };

    // -----------------------------------------------------------------------
    // Step 3: Verifying all group members against the AS
    //
    // After joining the group, every participant independently verifies that
    // each peer's signature key in the MLS group tree matches the public key
    // registered with the Authentication Service. This prevents an attacker
    // from inserting a rogue key into the group tree.
    // -----------------------------------------------------------------------
    println!();
    println!("{tag} --- Credential Verification ---");
    verify_group_members(&tag, &ds_client, &group, &identity).await;

    // the creator's job is done after group setup and verification: it does
    // not participate in SRTP traffic
    if is_creator {
        println!();
        println!("{tag} === {label} Done (group created) ===");
        return;
    }

    // -----------------------------------------------------------------------
    // Step 4: SRTP key export
    //
    // MLS provides an `export_secret` API that derives key material bound
    // to a (label, context) pair and the current group epoch. We use this
    // to derive per-sender SRTP master key + salt. Each sender is identified
    // by a deterministic SSRC derived from its credential identity.
    //
    // Senders export their own key material; receivers export key material
    // for every group member with the "sender" role, since only senders
    // transmit SRTP packets.
    // -----------------------------------------------------------------------
    println!();
    println!("{tag} --- SRTP Key Export ---");

    // collecting all member identities from the MLS group tree,
    // parsing each credential to extract (label, role)
    let all_members: Vec<(String, String)> = group
        .members()
        .map(|m| {
            let id = String::from_utf8_lossy(m.credential.serialized_content()).to_string();
            let (_label, role) = parse_credential_identity(&id);
            let role = role.to_string();
            (id, role)
        })
        .collect();

    // only members with the "sender" role will transmit SRTP packets
    let sender_identities: Vec<&String> = all_members
        .iter()
        .filter(|(_, r)| r == "sender")
        .map(|(id, _)| id)
        .collect();

    // deriving our SSRC (Synchronization Source identifier) from our identity
    let my_ssrc = ssrc_from_identity(&identity);

    if is_sender {
        // sender exports its own key material
        let (key_material, _, _) =
            export_srtp_keys(&group, member.provider.crypto(), my_ssrc);
        println!(
            "{tag} Sender keys exported (SSRC=0x{my_ssrc:08X})."
        );

        // -----------------------------------------------------------------
        // Step 5: Multicast send
        // -----------------------------------------------------------------
        println!();
        println!("{tag} --- SRTP Multicast ---");
        send_srtp(&tag, label, my_ssrc, &key_material, cli.packets).await;
    } else {
        // receiver exports SRTP key material for each sender in the group
        // and creates one SRTP receiver session per sender, keyed by SSRC
        let mut receiver_sessions: HashMap<u32, srtp::Session> = HashMap::new();
        for sender_id in &sender_identities {
            let sender_ssrc = ssrc_from_identity(sender_id);
            let (key_material, _, _) = export_srtp_keys(
                &group,
                member.provider.crypto(),
                sender_ssrc,
            );
            let (sender_label, _) = parse_credential_identity(sender_id);
            println!(
                "{tag} Receiver keys for {sender_label} (SSRC=0x{sender_ssrc:08X}) exported."
            );
            // creating a libsrtp session configured for decryption with this
            // sender's key material
            let session = create_receiver_session(&key_material);
            receiver_sessions.insert(sender_ssrc, session);
        }

        // -----------------------------------------------------------------
        // Step 5: Multicast receive
        // -----------------------------------------------------------------
        println!();
        println!("{tag} --- SRTP Multicast ---");
        let expected_packets = sender_identities.len() as u32 * cli.packets;
        recv_srtp(&tag, receiver_sessions, expected_packets).await;
    }

    println!();
    println!("{tag} === {label} Done ===");
}

// ---------------------------------------------------------------------------
// Group creation (creator role)
//
// The creator performs dynamic peer discovery by polling the DS for the list
// of registered clients. Once all expected senders and receivers have
// registered, it fetches and verifies their KeyPackages, creates the MLS
// group with all members, and delivers the Welcome message through the DS.
// ---------------------------------------------------------------------------

async fn create_group(
    cli: &Cli,
    identity: &str,
    tag: &str,
    ds_client: &mut DsClient,
    member: &MlsMember,
) -> MlsGroup {

    let expected_peers = cli.senders + cli.receivers;

    // polling GET /clients/list on the DS until we see all expected peers
    // (excluding ourselves)
    println!();
    println!(
        "{tag} --- Discovering Peers (waiting for {} sender(s) + {} receiver(s)) ---",
        cli.senders, cli.receivers
    );

    let peer_identities: Vec<String> = loop {
        let clients = ds_client.list_clients().await.expect("DS list clients failed");

        // converting raw identity bytes to strings and filtering out ourselves
        let peers: Vec<String> = clients
            .into_iter()
            .map(|id| String::from_utf8_lossy(&id).to_string())
            .filter(|n| n != identity)
            .collect();

        if peers.len() >= expected_peers as usize {
            println!("{tag} Discovered {} peer(s): {}", peers.len(), peers.join(", "));
            break peers;
        }

        println!(
            "{tag} Found {}/{} peers, waiting...",
            peers.len(),
            expected_peers
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    // Fetching and verifying KeyPackages for each discovered peer.
    //
    // For each peer, we consume (pop) one KeyPackage from the DS and verify
    // that the signing key inside the KeyPackage matches the public key
    // the peer registered with the Authentication Service. This ensures
    // nobody tampered with the KeyPackage in transit.
    println!();
    println!("{tag} --- Fetching Peer KeyPackages ---");

    let mut peer_kps: Vec<KeyPackage> = Vec::new();
    for peer_id in &peer_identities {
        let (peer_label, _) = parse_credential_identity(peer_id);
        println!("{tag} Fetching {peer_label}'s KeyPackage...");

        // polling until the peer's KeyPackage is available on the DS (it may
        // not be ready yet if registration is still in progress)
        let kp_bytes = loop {
            match ds_client
                .consume_key_package(peer_id.as_bytes())
                .await
                .expect("DS consume KP failed")
            {
                Some(bytes) => break bytes,
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        };

        // deserializing the TLS-encoded KeyPackage from the DS response
        let kp_in = KeyPackageIn::tls_deserialize_exact(&kp_bytes)
            .expect("failed to deserialize peer KeyPackage");

        // fetching the peer's public key from the AS for cross-verification
        let pk_from_as = ds_client
            .lookup_as(peer_id)
            .await
            .expect("AS lookup failed");

        // validating the KeyPackage cryptographically (signature, ciphersuite,
        // protocol version) and extracting the verified KeyPackage
        let kp_ref: KeyPackage = kp_in
            .validate(member.provider.crypto(), ProtocolVersion::Mls10)
            .expect("KeyPackage validation failed");
        let pk_from_kp = kp_ref.leaf_node().signature_key().as_slice();

        // ensuring the key in the KeyPackage matches what the AS has on record
        assert_eq!(
            pk_from_as, pk_from_kp,
            "{peer_label}'s public key from AS does not match KeyPackage!"
        );
        println!(
            "{tag} {}",
            green(format!(
                "{peer_label}'s credential verified: AS key matches KeyPackage."
            ))
        );

        peer_kps.push(kp_ref);
    }

    // Creating the MLS group and adding all discovered peers.
    //
    // We create a fresh group with the ratchet tree extension enabled
    // (so the full tree is included in the Welcome message, allowing
    // joiners to reconstruct the group state without extra fetches).
    // All peers are added in a single Commit to minimize round trips.
    println!();
    println!("{tag} --- MLS Group Setup ---");

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new(
        &member.provider,
        &member.signer,
        &group_config,
        member.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    println!(
        "{tag} Created MLS group (id: {})",
        hex::encode(group.group_id().as_slice())
    );

    // adding all peers in a single commit
    let (_commit, welcome, _group_info) = group
        .add_members(&member.provider, &member.signer, &peer_kps)
        .expect("failed to add members");

    // merging the pending commit into our own group state so we advance
    // to the new epoch that includes the added members
    group
        .merge_pending_commit(&member.provider)
        .expect("failed to merge pending commit");

    println!(
        "{tag} Added {} peer(s) to the group.",
        peer_identities.len()
    );
    println!("{tag} Group epoch: {}", group.epoch().as_u64());

    // Delivering the Welcome message to all joiners via the DS.
    //
    // The Welcome contains encrypted group secrets and the ratchet tree,
    // allowing each joiner to reconstruct the group state. The DS routes
    // it to the correct recipients by matching the embedded KeyPackage
    // hash references against its stored KeyPackages.
    println!();
    println!("{tag} --- Delivering Welcome ---");

    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("Welcome serialization failed");

    ds_client
        .send_welcome(&welcome_bytes)
        .await
        .expect("failed to send Welcome via DS");

    println!(
        "{tag} Welcome delivered to {} peer(s) via DS ({} bytes).",
        peer_identities.len(),
        welcome_bytes.len()
    );

    group
}

// ---------------------------------------------------------------------------
// Group joining (sender/receiver role)
//
// Senders and receivers poll the DS for incoming messages until they receive
// a Welcome. The Welcome contains everything needed to reconstruct the MLS
// group state: encrypted group secrets, the ratchet tree, and the group
// configuration.
// ---------------------------------------------------------------------------

async fn join_group(
    tag: &str,
    ds_client: &mut DsClient,
    member: &MlsMember,
) -> MlsGroup {
    println!();
    println!("{tag} --- Waiting for Welcome ---");
    println!("{tag} Polling DS for messages...");

    // polling the DS inbox until a Welcome message arrives
    let welcome_msg: Welcome = loop {
        let msgs = ds_client
            .recv_messages()
            .await
            .expect("DS recv messages failed");

        let mut found = None;
        for msg in msgs {
            // MLS messages can be Welcome, Commit, or application messages
            // we only care about Welcome here
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

    println!("{tag} Received Welcome message.");

    println!();
    println!("{tag} --- Joining MLS Group ---");

    // building the same group config the creator used (must match ciphersuite)
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // processing the Welcome: decrypting the group secrets using our private key
    // (from the KeyPackage the creator consumed), reconstructing the ratchet
    // tree, and producing a group state
    let group = StagedWelcome::new_from_welcome(
        &member.provider,
        group_config.join_config(),
        welcome_msg,
        None, // no external ratchet tree (it is embedded in the Welcome)
    )
    .expect("failed to stage welcome")
    .into_group(&member.provider)
    .expect("failed to join group");

    println!(
        "{tag} Joined MLS group (id: {})",
        hex::encode(group.group_id().as_slice())
    );
    println!("{tag} Group epoch: {}", group.epoch().as_u64());

    group
}

// ---------------------------------------------------------------------------
// Credential verification (all roles)
//
// For each peer in the MLS group tree, we fetch their public key from the AS
// and assert it matches the signature key stored in the group tree. This
// is an additional layer of trust on top of MLS's own KeyPackage validation:
// the AS acts as a trusted directory that binds identities to keys.
// ---------------------------------------------------------------------------

async fn verify_group_members(
    tag: &str,
    ds_client: &DsClient,
    group: &MlsGroup,
    my_identity: &str,
) {
    for m in group.members() {
        // The credential encodes "label:role"; we use the full identity for
        // AS lookup (since the AS stores keys under the same "label:role" string).
        let identity = String::from_utf8_lossy(m.credential.serialized_content()).to_string();

        if identity == my_identity {
            continue;
        }

        let (peer_label, _role) = parse_credential_identity(&identity);

        // fetching the peer's registered public key from the AS
        let pk_from_as = ds_client
            .lookup_as(&identity)
            .await
            .expect("AS lookup failed");

        // comparing against the signature key in the MLS group tree
        assert_eq!(
            pk_from_as,
            m.signature_key.as_slice(),
            "{peer_label}'s AS key does not match group tree!"
        );
        println!(
            "{tag} {}",
            green(format!(
                "{peer_label}'s credential verified: AS key matches group tree."
            ))
        );
    }
}

// ---------------------------------------------------------------------------
// SRTP sending
//
// Constructs dummy RTP audio packets, encrypts each with libsrtp using the
// MLS-exported key material, and sends the resulting SRTP packets to the
// multicast group address. A short delay between packets simulates a
// real-time audio stream.
// ---------------------------------------------------------------------------

async fn send_srtp(tag: &str, label: &str, ssrc: u32, key_material: &[u8], num_packets: u32) {
    // creating a libsrtp sender session configured with AES-128-CM + HMAC-SHA1-80,
    // keyed with the MLS-exported master key and salt.
    let mut srtp_session = create_sender_session(key_material);

    // binding a UDP socket for sending to the multicast group.
    let socket = multicast::create_multicast_sender()
        .await
        .expect("failed to create multicast sender");
    let dest = multicast::multicast_dest();

    println!("{tag} Multicast destination: {dest}");

    // giving receivers time to join the multicast group before we start sending.
    println!("{tag} Waiting 2 seconds for receivers to set up...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    for i in 1..=num_packets {
        // building a dummy RTP packet with a text payload simulating audio data
        let pkt = RtpPacket {
            payload_type: 111,
            sequence_number: i as u16,
            timestamp: i * 960, // 960 samples per frame at 48kHz = 20ms
            ssrc,
            payload: format!("Hello from {label} - audio frame {i}").into_bytes(),
        };

        // Serializing to raw RTP bytes, then encrypting in-place with SRTP.
        // SRTP appends an authentication tag, increasing the packet size.
        let rtp_bytes = pkt.to_bytes();
        let mut buf = rtp_bytes.clone();
        srtp_session.protect(&mut buf).expect("srtp_protect failed");

        println!(
            "{tag} RTP seq={} ({} bytes) -> SRTP ({} bytes, +{} overhead)",
            pkt.sequence_number,
            rtp_bytes.len(),
            buf.len(),
            buf.len() - rtp_bytes.len()
        );

        // sending the encrypted SRTP packet to the multicast group
        socket
            .send_to(&buf, &dest)
            .await
            .expect("multicast send failed");

        // small delay to simulate real-time packet spacing
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    println!("{tag} {}", green("All SRTP packets sent over multicast."));
}

// ---------------------------------------------------------------------------
// SRTP receiving
//
// Listens on the multicast group for incoming SRTP packets. For each packet,
// extracts the SSRC from the RTP header to select the correct decryption
// session (each sender has its own MLS-derived key), decrypts the SRTP
// payload, and displays the contents.
// ---------------------------------------------------------------------------

async fn recv_srtp(
    tag: &str,
    mut sessions: HashMap<u32, srtp::Session>,
    expected_packets: u32,
) {
    // joining the multicast group and binding a UDP socket for receiving
    let socket = multicast::create_multicast_receiver()
        .expect("failed to create multicast receiver");

    println!(
        "{tag} Joined multicast group {}:{}, waiting for packets...",
        multicast::MULTICAST_ADDR,
        multicast::MULTICAST_PORT
    );

    let mut buf = vec![0u8; 2048];
    let mut received: u32 = 0;
    let timeout = std::time::Duration::from_secs(30);

    // we keep receiving until we have got all expected packets or we time out
    while received < expected_packets {
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                let mut pkt_buf = buf[..len].to_vec();

                // The SSRC field is at bytes 8-11 of the RTP header. We need
                // it to look up the correct SRTP session for decryption, since
                // each sender uses a different MLS-derived key.
                if pkt_buf.len() < 12 {
                    eprintln!("{tag} Received packet too short ({len} bytes), skipping.");
                    continue;
                }
                let ssrc = u32::from_be_bytes([pkt_buf[8], pkt_buf[9], pkt_buf[10], pkt_buf[11]]);

                // looking up the SRTP session for this sender's SSRC.
                let session = match sessions.get_mut(&ssrc) {
                    Some(s) => s,
                    None => {
                        eprintln!("{tag} Unknown SSRC 0x{ssrc:08X}, skipping packet.");
                        continue;
                    }
                };

                // decrypting the SRTP packet in-place (removing auth tag, decrypting payload)
                session
                    .unprotect(&mut pkt_buf)
                    .expect("SRTP decryption failed");

                // parsing the decrypted bytes back into an RTP packet structure
                let rtp = RtpPacket::from_bytes(&pkt_buf).expect("invalid RTP");

                println!(
                    "{tag} SRTP from {src} -> SSRC=0x{ssrc:08X}, seq={}, payload: {:?}",
                    rtp.sequence_number,
                    String::from_utf8_lossy(&rtp.payload)
                );

                received += 1;
            }
            Ok(Err(e)) => {
                eprintln!("{tag} Receive error: {e}");
                break;
            }
            Err(_) => {
                println!("{tag} Timeout waiting for packets.");
                break;
            }
        }
    }

    println!(
        "{tag} {}",
        green(format!(
            "Received and decrypted {received}/{expected_packets} SRTP packets."
        ))
    );
}
