//! The signed commitment (i.e., the message that bootstraps a TESLA stream).
//! It carries the chain's starting point K_0 and the schedule, signed with
//! the sender's MLS leaf key.
//!
//! Every TESLA check traces back to K_0 and the
//! schedule, so those two cannot be authenticated by TESLA itself. 
//! The signature closes that hole:
//! the MLS leaf key is the per-member identity key the group already
//! trusts, so it can vouch for the starting point.
//!
//! Beyond K_0 and the schedule numbers, the commitment binds its context:
//! which sender, which stream (SSRC), which group and epoch, and which
//! MAC algorithm.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;

use crate::keying::mls::CIPHERSUITE;
use crate::tesla::chain::ChainKey;
use crate::tesla::mac::TeslaMacAlg;
use crate::tesla::schedule::TeslaSchedule;

/// Domain separator.
const DOMAIN: &[u8] = b"MLS-SRTP TESLA commitment";

/// What the sender commits to, before its stream starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeslaCommitment {
    /// The chain's public starting point K_0.
    pub anchor: ChainKey,
    /// The schedule: when interval 1 begins...
    pub t0_ns: u64,
    /// ...how long each interval lasts...
    pub t_int_ns: u64,
    /// ...the disclosure delay d...
    pub d: u32,
    /// ...and how many intervals exist.
    pub n_chain: u32,
    /// Which MAC algorithm tags this stream's packets.
    pub mac_alg: TeslaMacAlg,
    /// Context binding: the sender's credential identity...
    pub sender_identity: Vec<u8>,
    /// ...its stream...
    pub ssrc: u32,
    /// ...and the MLS group and epoch this commitment belongs to.
    pub group_id: Vec<u8>,
    pub epoch: u64,
}

impl TeslaCommitment {
    /// The bytes that get signed: domain separator, then every field in a
    /// fixed order, variable-length fields with a length prefix.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(&self.t0_ns.to_be_bytes());
        out.extend_from_slice(&self.t_int_ns.to_be_bytes());
        out.extend_from_slice(&self.d.to_be_bytes());
        out.extend_from_slice(&self.n_chain.to_be_bytes());
        // the MAC algorithm as one byte
        out.push(match self.mac_alg {
            TeslaMacAlg::HmacSha256 => 0,
            TeslaMacAlg::GmacAes128 => 1,
        });
        // variable-length fields, each length-prefixed
        out.extend_from_slice(&(self.sender_identity.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sender_identity);
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(&(self.group_id.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out
    }

    /// Signs the commitment with the sender's MLS leaf key.
    pub fn sign(&self, signer: &SignatureKeyPair) -> Vec<u8> {
        signer.sign(&self.to_bytes()).expect("signing failed")
    }

    /// Checks the signature against the sender's public key. A receiver
    /// accepts the commitment (and with it the anchor and schedule) only
    /// if this passes.
    pub fn verify(
        &self,
        signature: &[u8],
        sender_public_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> bool {
        crypto
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                &self.to_bytes(),
                sender_public_key,
                signature,
            )
            .is_ok()
    }

    /// The schedule this commitment pins, completed with the two
    /// receiver-local values: the clock bound
    /// D_t (from the receiver's time sync) and the hash-work cap.
    pub fn schedule(&self, d_t_ns: u64, g_max: u32) -> TeslaSchedule {
        TeslaSchedule::new(self.t0_ns, self.t_int_ns, self.d, self.n_chain, d_t_ns, g_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An example commitment to sign and verify (the field values are
    /// arbitrary).
    fn commitment() -> TeslaCommitment {
        TeslaCommitment {
            anchor: [7u8; 20],
            t0_ns: 0,
            t_int_ns: 1_000_000,
            d: 2,
            n_chain: 64,
            mac_alg: TeslaMacAlg::HmacSha256,
            sender_identity: b"camera-1:sender".to_vec(),
            ssrc: 0x1234,
            group_id: b"studio-group".to_vec(),
            epoch: 3,
        }
    }

    /// The sender signs, the receiver verifies with the sender's public
    /// key: the commitment is accepted. Any changed field (here: the MAC
    /// algorithm swapped) or a signature from someone else's key must be
    /// rejected.
    #[test]
    fn sign_verify_and_tamper() {
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::OpenMlsProvider;

        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("key generation failed");

        // the sender signs its commitment
        let c = commitment();
        let sig = c.sign(&signer);

        // the receiver verifies it against the sender's public key
        assert!(c.verify(&sig, &signer.to_public_vec(), provider.crypto()));

        // a tampered field (the MAC algorithm swapped) breaks the signature
        let mut altered = c.clone();
        altered.mac_alg = TeslaMacAlg::GmacAes128;
        assert!(!altered.verify(&sig, &signer.to_public_vec(), provider.crypto()));

        // a signature by some other key is rejected
        let other = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("key generation failed");
        assert!(!c.verify(&sig, &other.to_public_vec(), provider.crypto()));
    }
}
