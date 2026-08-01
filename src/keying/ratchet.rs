//! Per-stream key ratchet for fine-grained forward secrecy.
//!
//! The MLS group hands us one fresh secret per epoch (epochs change only
//! when the group rekeys: a join, leave, or scheduled commit). Instead of
//! keying SRTP once per epoch, we subdivide each epoch into generations and
//! give each generation its own SRTP key. A generation is the span that shares
//! one key; the index `g` counts them (0, 1, 2, ...). The granularity sets how
//! long a generation is: one packet (packet-level), one video frame
//! (frame-level), or the whole epoch (epoch-only, where one
//! generation == one epoch). One epoch hence typically contains many generations.
//!
//! Each generation `g` has a secret `S_g`. On entering generation `g` we expand
//! `S_g` twice and then discard it: one expand gives generation `g`'s SRTP key
//! and salt, the other gives the next secret `S_{g+1}`.
//!
//!   S_{g+1}                  = HKDF-Expand(S_g, "next generation",  32)
//!   SRTP key(16) || salt(12) = HKDF-Expand(S_g, "srtp key material", 28)
//!
//! Only `S_g` carries forward. The SRTP key+salt is consumed by AES-GCM and
//! never reused to derive anything. As HKDF-Expand is one-way, leaking `S_g`
//! exposes no earlier keys, and the two distinct labels keep the SRTP key+salt 
//! and the chain independent. `S_0` is re-seeded each epoch from the MLS exporter, 
//! bound to (epoch, SSRC). One ratchet == one SSRC == one sender 
//! (multi-sender per stream is out of scope).

use openmls::prelude::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HashType;

use crate::keying::mls::{build_exporter_context, AES_128_GCM_KEY_LEN, SRTP_KEY_MATERIAL_LEN};

/// HKDF-Expand `info` label for the forward chain step (`S_g -> S_{g+1}`).
pub const CHAIN_LABEL: &[u8] = b"next generation";

/// HKDF-Expand `info` label for the per-generation SRTP key and salt.
pub const KEY_MATERIAL_LABEL: &[u8] = b"srtp key material";

/// Chain-secret length in bytes (`L_chain`): one SHA-256 output length.
pub const CHAIN_SECRET_LEN: usize = 32;

/// MLS exporter label used to seed `S_0` at each epoch.
pub const SRTP_RATCHET_SEED_LABEL: &str = "SRTP ratchet seed";

/// The per-generation SRTP session key and salt: `key(16) || salt(12)`.
pub type KeySalt = [u8; SRTP_KEY_MATERIAL_LEN];

/// A forward-only hash ratchet for one SRTP stream within one MLS epoch.
///
/// Holds the current chain secret `S_g` and the generation index `g`.
#[derive(Clone)]
pub struct StreamRatchet {
    /// Current chain secret `S_g`.
    chain_secret: Vec<u8>,
    /// Current generation index `g`.
    generation: u64,
}

impl StreamRatchet {
    /// Builds a ratchet from a raw 32-byte seed `S_0`. 
    /// Generation starts at 0.
    pub fn from_seed(seed: Vec<u8>) -> Self {
        // rejecting a wrong-sized seed
        assert_eq!(
            seed.len(),
            CHAIN_SECRET_LEN,
            "ratchet seed must be {CHAIN_SECRET_LEN} bytes"
        );
        // starting the chain at S_0, generation 0
        Self {
            chain_secret: seed,
            generation: 0,
        }
    }

    /// Seeds `S_0` directly from an MLS group's exporter for the given SSRC.
    ///
    /// The exporter is epoch-scoped (the `exporter_secret` changes every epoch)
    /// and we bind the SSRC into the context, so the seed is unique per
    /// (epoch, SSRC). This avoids AES-GCM (key, nonce) reuse. Both members of the same
    /// group/epoch derive an identical seed, hence an identical ratchet sequence.
    pub fn seed_from_exporter(group: &MlsGroup, crypto: &impl OpenMlsCrypto, ssrc: u32) -> Self {
        // binding the SSRC into the exporter context
        let context = build_exporter_context(ssrc);
        // exporting the 32-byte S_0 from this epoch's exporter secret
        let seed = group
            .export_secret(crypto, SRTP_RATCHET_SEED_LABEL, &context, CHAIN_SECRET_LEN)
            .expect("export ratchet seed failed");
        // building the ratchet from the exported seed
        Self::from_seed(seed)
    }

    /// Current generation index `g`.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Derives the current generation's SRTP key and salt (28 bytes:
    /// `key(16) || salt(12)`). Does not advance the chain.
    pub fn derive_key_salt(&self, crypto: &impl OpenMlsCrypto) -> KeySalt {
        // expanding S_g under the SRTP key material label into 28 bytes
        let out = crypto
            .hkdf_expand(
                HashType::Sha2_256,
                &self.chain_secret,
                KEY_MATERIAL_LABEL,
                SRTP_KEY_MATERIAL_LEN,
            )
            .expect("hkdf_expand (key material) failed");
        // copying into a fixed-size array: key(16) || salt(12)
        let mut buf = [0u8; SRTP_KEY_MATERIAL_LEN];
        buf.copy_from_slice(out.as_slice());
        buf
    }

    /// Advances the chain one step: `S_g -> S_{g+1}`, incrementing the
    /// generation index. One-way (the old `S_g` is overwritten).
    pub fn advance(&mut self, crypto: &impl OpenMlsCrypto) {
        // expanding S_g under the chain label into the next secret S_{g+1}
        let next = crypto
            .hkdf_expand(
                HashType::Sha2_256,
                &self.chain_secret,
                CHAIN_LABEL,
                CHAIN_SECRET_LEN,
            )
            .expect("hkdf_expand (chain step) failed");
        // overwriting S_g with S_{g+1} (dropping the old secret) and bumping g
        self.chain_secret = next.as_slice().to_vec();
        self.generation += 1;
    }

    /// MAIN DRIVER: Derives the current generation's key and salt, then advances the chain.
    /// Returns `(g, key_salt)` and leaves the ratchet positioned at generation `g+1`.
    ///
    /// This is the operation we benchmark: two `HKDF-Expand`s
    /// (one for the key and salt, one for the chain step).
    pub fn next_key_salt(&mut self, crypto: &impl OpenMlsCrypto) -> (u64, KeySalt) {
        // recording the current generation g before advancing
        let g = self.generation;
        // deriving generation g's key+salt, then advancing the chain to S_{g+1}
        let key_salt = self.derive_key_salt(crypto);
        self.advance(crypto);
        (g, key_salt)
    }
}

/// Splits the key+salt into `(key, salt)` slices: `key(16)`, `salt(12)`.
pub fn split_key_salt(key_salt: &KeySalt) -> (&[u8], &[u8]) {
    key_salt.split_at(AES_128_GCM_KEY_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    /// A throwaway crypto provider for the tests.
    fn crypto() -> OpenMlsRustCrypto {
        OpenMlsRustCrypto::default()
    }

    /// A fixed, obviously-not-secret seed for deterministic tests.
    fn test_seed() -> Vec<u8> {
        (0..CHAIN_SECRET_LEN as u8).collect()
    }

    /// The same seed produces the same generation indices and key+salt
    /// sequence, so two endpoints sharing `S_0` stay in lockstep.
    #[test]
    fn ratchet_is_deterministic() {
        let provider = crypto();
        let mut a = StreamRatchet::from_seed(test_seed());
        let mut b = StreamRatchet::from_seed(test_seed());
        for expected_g in 0..8u64 {
            // advancing both ratchets one generation and comparing their output
            let (ga, ks_a) = a.next_key_salt(provider.crypto());
            let (gb, ks_b) = b.next_key_salt(provider.crypto());
            assert_eq!(ga, expected_g);
            assert_eq!(gb, expected_g);
            assert_eq!(ks_a, ks_b, "same seed must yield identical key+salt at gen {expected_g}");
        }
    }

    /// The key+salt is a derived value, and each
    /// generation produces a different key+salt.
    #[test]
    fn key_salt_is_derived_and_distinct_per_generation() {
        let provider = crypto();
        let r = StreamRatchet::from_seed(test_seed());

        // deriving the key+salt at generation 0
        let ks0 = r.derive_key_salt(provider.crypto());

        // chaining S_0 -> S_1, then deriving generation 1's key+salt
        let mut r1 = r.clone();
        r1.advance(provider.crypto());
        let ks1 = r1.derive_key_salt(provider.crypto());

        // checking the key+salt is a derived value, not the raw seed
        assert_ne!(&ks0[..], &test_seed()[..SRTP_KEY_MATERIAL_LEN]);
        // checking consecutive generations produce different key+salt
        assert_ne!(ks0, ks1, "key+salt must change after a chain step");
    }

    /// `advance` and `next_key_salt` both move the generation index forward by
    /// one, and `next_key_salt` returns the pre-advance generation.
    #[test]
    fn generation_counter_advances() {
        let provider = crypto();
        let mut r = StreamRatchet::from_seed(test_seed());
        assert_eq!(r.generation(), 0);
        // advancing once moves the counter to 1
        r.advance(provider.crypto());
        assert_eq!(r.generation(), 1);
        // deriving-and-advancing returns gen 1 and leaves the ratchet at gen 2
        let (g, _) = r.next_key_salt(provider.crypto());
        assert_eq!(g, 1);
        assert_eq!(r.generation(), 2);
    }

    /// Two ratchets seeded differently produce different key+salt, so distinct
    /// streams or epochs don't collide.
    #[test]
    fn different_seeds_diverge() {
        let provider = crypto();
        let mut a = StreamRatchet::from_seed(test_seed());
        // flipping one seed byte to get a distinct seed
        let mut other: Vec<u8> = test_seed();
        other[0] ^= 0xFF;
        let mut b = StreamRatchet::from_seed(other);
        let (_, ks_a) = a.next_key_salt(provider.crypto());
        let (_, ks_b) = b.next_key_salt(provider.crypto());
        assert_ne!(ks_a, ks_b, "distinct seeds must yield distinct key+salt");
    }

    /// The 28-byte key+salt splits into a 16-byte SRTP key and a 12-byte salt.
    #[test]
    fn key_salt_splits_16_12() {
        let provider = crypto();
        let r = StreamRatchet::from_seed(test_seed());
        let ks = r.derive_key_salt(provider.crypto());
        let (key, salt) = split_key_salt(&ks);
        assert_eq!(key.len(), 16);
        assert_eq!(salt.len(), 12);
    }
}
