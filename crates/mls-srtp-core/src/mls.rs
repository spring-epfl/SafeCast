//! MLS group management and SRTP key export.
//!
//! Provides helpers to create MLS group members and to export SRTP keying
//! material via the MLS exporter (RFC 9420 §8.5). The exporter derives
//! pseudorandom output from the group's `exporter_secret`, which is itself
//! derived from the group's `epoch_secret`:
//!
//!   epoch_secret --(DeriveSecret(., "exporter"))--> exporter_secret
//!
//! Then, each call to MLS-Exporter does two more steps:
//!
//!   MLS-Exporter(Label, Context, Length) =
//!       ExpandWithLabel(DeriveSecret(exporter_secret, Label),
//!                       "exported", Hash(Context), Length)

use std::hash::{Hash, Hasher};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

/// MLS ciphersuite used throughout the demo.
/// AES-128-GCM here matches the SRTP cipher (AEAD_AES_128_GCM).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// MLS exporter label for the SRTP master key.
pub const SRTP_MASTER_KEY_LABEL: &str = "SRTP master key";

/// MLS exporter label for the SRTP master salt.
pub const SRTP_MASTER_SALT_LABEL: &str = "SRTP master salt";

/// SRTP AEAD_AES_128_GCM master key length (RFC 7714 §12): 128 bits.
pub const AES_128_GCM_KEY_LEN: usize = 16;

/// SRTP AEAD_AES_128_GCM master salt length (RFC 7714 §12): 96 bits.
pub const AES_128_GCM_SALT_LEN: usize = 12;

/// Combined key material length for libsrtp: master_key || master_salt = 28 bytes.
pub const SRTP_KEY_MATERIAL_LEN: usize = AES_128_GCM_KEY_LEN + AES_128_GCM_SALT_LEN;

/// Derives a deterministic SSRC from a credential identity by hashing it.
///
/// This allows receivers to compute the expected SSRC for any sender
/// without out-of-band signaling.
pub fn ssrc_from_identity(identity: &str) -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    identity.hash(&mut hasher);
    hasher.finish() as u32
}

/// An MLS group member with its own cryptographic provider, signing key, and credential.
///
/// Each member gets an independent `OpenMlsRustCrypto` provider (which includes
/// its own key store), so members can operate independently as they would on
/// separate devices.
pub struct MlsMember {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential_with_key: CredentialWithKey,
}

impl MlsMember {
    /// Creates a new MLS member with a fresh signing key and a basic credential
    /// (RFC 9420 §5.3: "a bare assertion of an identity, without any additional information").
    ///
    /// The credential identity should encode the member's role (e.g. "sender-48231:sender"),
    /// allowing other group members to determine each peer's SRTP role
    /// (sender or receiver) from the MLS group tree.
    pub fn new(identity: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("failed to generate signature key pair");
        // storing the signing key in this member's key store so OpenMLS can find it
        signer
            .store(provider.storage())
            .expect("failed to store signer");
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self {
            provider,
            signer,
            credential_with_key,
        }
    }

    /// Generates a KeyPackage that can be used to add this member to a group.
    /// In MLS, a KeyPackage is a signed, one-time-use bundle containing the
    /// member's public key and credential (RFC 9420 §10).
    pub fn generate_key_package(&self) -> KeyPackageBundle {
        KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .expect("failed to build key package")
    }
}

/// Parses a credential identity string of the form label:role into its
/// components. Returns (label, role).
pub fn parse_credential_identity(identity: &str) -> (&str, &str) {
    identity
        .rsplit_once(':')
        .expect("credential identity must be in 'label:role' format")
}

/// Builds the context byte string passed to the MLS exporter.
///
/// The MLS exporter takes three inputs: a label, a length,
/// and a **context** (an arbitrary byte string that gets hashed into the
/// derivation so that different inputs produce different output keys).
///
/// We use the SSRC (which uniquely identifies the RTP stream) as context
/// so that each sender within the same MLS group epoch derives its own
/// independent SRTP key and salt.
///
/// Wire format: `SSRC [4 bytes]`
pub fn build_exporter_context(ssrc: u32) -> Vec<u8> {
    ssrc.to_be_bytes().to_vec()
}

/// Exports SRTP master key and master salt from an MLS group.
///
/// Makes two separate `export_secret()` calls with distinct labels:
///   - `"SRTP master key"` -> 16-byte master key
///   - `"SRTP master salt"` -> 12-byte master salt
///
/// Returns a tuple of:
///   - `key_material`: concatenated `master_key || master_salt` (28 bytes)
///     ready to pass directly to libsrtp
///   - `master_key`: the 16-byte key (for logging)
///   - `master_salt`: the 12-byte salt (for logging)
///
/// Both members of the same MLS group in the same epoch will derive
/// identical output, since they share the same `exporter_secret`.
pub fn export_srtp_keys(
    group: &MlsGroup,
    crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
    ssrc: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let context = build_exporter_context(ssrc);

    // first exporter call: master key
    let master_key = group
        .export_secret(crypto, SRTP_MASTER_KEY_LABEL, &context, AES_128_GCM_KEY_LEN)
        .expect("export master key failed");

    // second exporter call: master salt
    let master_salt = group
        .export_secret(crypto, SRTP_MASTER_SALT_LABEL, &context, AES_128_GCM_SALT_LEN)
        .expect("export master salt failed");

    // libsrtp expects key || salt concatenated as a single buffer
    let mut key_material = Vec::with_capacity(SRTP_KEY_MATERIAL_LEN);
    key_material.extend_from_slice(&master_key);
    key_material.extend_from_slice(&master_salt);

    (key_material, master_key, master_salt)
}
