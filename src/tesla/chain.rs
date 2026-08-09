//! The TESLA one-way key chain.
//!
//! The sender picks a private random "final key" K_N and hashes backwards:
//! K_i = F(K_{i+1}). Only K_0 is published (signed, in the
//! commitment). One-wayness gives receivers everything at once: any
//! disclosed key verifies by hashing it down to a key they already trust,
//! nobody can run the chain forwards to predict unrevealed keys, and keys
//! lost with their packets are recovered for free while hashing down.
//!
//! Two hash functions do all the work here, both built from HMAC-SHA256:
//!
//! - F: the chain step. Its output is cut from SHA-256's 32 bytes to 20,
//!   the disclosed-key size RFC 4383 §6 defines
//! - F': the MAC-key derivation
//!
//! Applied to the same chain key K_i, F computes the next-lower chain
//! element K_{i-1} and F' computes interval i's MAC key K'_i. The only
//! thing keeping those two apart is the one-byte message, as F hashes the
//! byte 0x00 and F' the byte 0x01.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

/// Chain-key length n_p in bytes.
pub const TESLA_KEY_LEN: usize = 20;

/// One element of the key chain.
pub type ChainKey = [u8; TESLA_KEY_LEN];

/// The chain step F: K_i = trunc_20(HMAC-SHA256(K_{i+1}, 0x00)).
pub fn f_step(key: &ChainKey) -> ChainKey {
    // HMAC keyed with K_{i+1}, computing K_i
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    // the message is the single byte 0x00 (0x01 is F', keeping the two apart)
    h.update(&[0x00]);
    // 32-byte HMAC-SHA256 output
    let out = h.finalize().into_bytes();
    // cutting to the 20-byte chain-key size
    let mut k = [0u8; TESLA_KEY_LEN];
    k.copy_from_slice(&out[..TESLA_KEY_LEN]);
    k
}

/// The MAC-key derivation F': K'_i = trunc_{n_f}(HMAC-SHA256(K_i, 0x01)).
/// `n_f` is set by the MAC instantiation (32 for HMAC-SHA256, 16 for GMAC).
pub fn mac_key(key: &ChainKey, n_f: usize) -> Vec<u8> {
    assert!(n_f <= 32, "F' cannot output more than one SHA-256 block");
    // HMAC keyed with the interval's chain key
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    // the message is the single byte 0x01
    h.update(&[0x01]);
    // cutting the 32-byte output to the MAC's key size
    h.finalize().into_bytes()[..n_f].to_vec()
}

/// The sender's chain: keys[i] = K_i for i in
/// 0..=n_chain, where K_0 is the public anchor.
pub struct TeslaChain {
    keys: Vec<ChainKey>,
}

impl TeslaChain {
    /// Builds the chain backwards from the final key K_n_chain.
    pub fn from_final_key(k_final: ChainKey, n_chain: u32) -> Self {
        let n = n_chain as usize;
        let mut keys = vec![[0u8; TESLA_KEY_LEN]; n + 1];
        keys[n] = k_final;
        // hashing backwards: K_i = F(K_{i+1}), down to the anchor K_0
        for i in (0..n).rev() {
            keys[i] = f_step(&keys[i + 1]);
        }
        TeslaChain { keys }
    }

    /// Builds a chain from fresh OS-seeded randomness.
    pub fn generate(n_chain: u32) -> Self {
        let mut k_final = [0u8; TESLA_KEY_LEN];
        rand::rng().fill_bytes(&mut k_final);
        Self::from_final_key(k_final, n_chain)
    }

    /// K_i
    pub fn key(&self, i: u32) -> &ChainKey {
        &self.keys[i as usize]
    }

    /// The public anchor K_0 (what the signed commitment carries).
    pub fn anchor(&self) -> &ChainKey {
        &self.keys[0]
    }
}

/// What a disclosed-key candidate turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disclosure {
    /// The candidate hash-verified against the trusted key. Carries the
    /// newly trusted `(index, key)` pairs in ascending order: the last is
    /// the candidate itself, the earlier ones are keys whose own
    /// disclosure packets were never received. They
    /// fall out as intermediate values while hashing the candidate down,
    /// so the packets waiting for them can still be verified.
    New(Vec<(u32, ChainKey)>),
    /// The candidate's index is not newer than the trusted index: nothing
    /// to do (normal, as d consecutive intervals disclose the same key).
    NotNew,
    /// The candidate does not hash down to the trusted key: garbage or
    /// forgery.
    Invalid,
    /// The claimed index is more than g_max beyond the trusted index: the
    /// cap refuses the hash work.
    TooFarAhead,
    /// The claimed index lies beyond the committed chain.
    BeyondChain,
}

/// The receiver's side of the chain. The receiver never holds the chain
/// itself (only the sender has it): all it holds is the newest key it has
/// proven genuine, starting from the signed K_0. Each incoming disclosed
/// key is checked by hashing it down to that trusted key ([`Self::check`]):
/// if it matches, it becomes the new trusted key.
pub struct ChainVerifier {
    /// Highest chain index that exists (from the commitment): claims
    /// beyond it are rejected without any hashing.
    n_chain: u32,
    /// Most hash steps one check may spend, so a packet claiming an
    /// absurdly high index is rejected.
    g_max: u32,
    /// Index of the newest proven-genuine key...
    trusted_index: u32,
    /// ...and that key itself. Starts at (0, K_0) from the commitment.
    trusted_key: ChainKey,
}

impl ChainVerifier {
    /// Starts trusting the signed anchor K_0.
    pub fn new(anchor: ChainKey, n_chain: u32, g_max: u32) -> Self {
        ChainVerifier {
            n_chain,
            g_max,
            trusted_index: 0,
            trusted_key: anchor,
        }
    }

    /// Index of the newest trusted key.
    pub fn trusted_index(&self) -> u32 {
        self.trusted_index
    }

    /// Checks a disclosed-key candidate claiming index `index`. On success
    /// the verifier's trust advances to the candidate. On any failure the
    /// state is untouched.
    pub fn check(&mut self, candidate: &ChainKey, index: u32) -> Disclosure {
        if index <= self.trusted_index {
            return Disclosure::NotNew;
        }
        if index > self.n_chain {
            return Disclosure::BeyondChain;
        }
        let gap = index - self.trusted_index;
        if gap > self.g_max {
            return Disclosure::TooFarAhead;
        }

        // hashing the candidate down towards the trusted key, while collecting
        // the intermediate keys: after step s the value is K_{index-s}
        // (if the candidate is genuine)
        let mut recovered: Vec<(u32, ChainKey)> = Vec::with_capacity(gap as usize);
        // the candidate itself is the first collected key (still unproven:
        // only handed out if the loop below reaches the trusted key)
        recovered.push((index, *candidate));
        // the running value: starts at the candidate, drops one chain
        // index per hash
        let mut k = *candidate;
        for s in 1..=gap {
            // one chain step down: k was (claimed) K_{index-s+1}, now K_{index-s}
            k = f_step(&k);
            // the chain index this value claims to be
            let idx = index - s;
            // keys between the candidate and the trusted key are the ones
            // whose own disclosures we never saw: we collect them too. The
            // final value (idx == trusted_index) is not collected, as it is
            // only compared against the trusted key below.
            if idx > self.trusted_index {
                recovered.push((idx, k));
            }
        }

        // after `gap` steps the value must be the trusted key itself
        if k != self.trusted_key {
            return Disclosure::Invalid;
        }

        // trust advances to the candidate
        self.trusted_index = index;
        self.trusted_key = *candidate;
        recovered.reverse();

        // returning the newly trusted keys
        Disclosure::New(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain of n media intervals, built from a fixed final key
    /// for determinism.
    fn test_chain(n: u32) -> TeslaChain {
        TeslaChain::from_final_key([7u8; TESLA_KEY_LEN], n)
    }

    /// The normal, no-loss case: the sender discloses K_1, K_2, ..., K_8
    /// one after the other, and a receiver that starts off knowing only
    /// K_0 accepts every one of them.
    #[test]
    fn chain_roundtrip() {
        // the sender's chain (8 media intervals)
        let chain = test_chain(8);
        // the receiver: knows only the anchor K_0 at this point
        let mut v = ChainVerifier::new(*chain.anchor(), 8, 16);
        // feeding the disclosures in sender order
        for i in 1..=8 {
            match v.check(chain.key(i), i) {
                // each key must verify, and with no losses there is
                // nothing to recover: the new key is the only one returned
                Disclosure::New(keys) => {
                    assert_eq!(keys, vec![(i, *chain.key(i))]);
                }
                other => panic!("key {i} should verify, got {other:?}"),
            }
        }
    }

    /// The loss case: the packets disclosing K_1, K_2 and K_3 never
    /// arrive, so the first disclosure the receiver ever sees is K_4.
    /// That one call must prove K_4 genuine AND hand back the three
    /// missed keys, so the packets still waiting for them can be verified.
    #[test]
    fn gap_recovery() {
        // the sender's chain (8 media intervals)
        let chain = test_chain(8);
        // the receiver: knows only the anchor K_0 at this point
        let mut v = ChainVerifier::new(*chain.anchor(), 8, 16);
        // K_4 arrives as the very first disclosure
        match v.check(chain.key(4), 4) {
            // all four keys come back: K_1..K_3 recovered along the way,
            // K_4 itself last
            Disclosure::New(keys) => {
                let expect: Vec<_> = (1..=4).map(|i| (i, *chain.key(i))).collect();
                assert_eq!(keys, expect);
            }
            other => panic!("expected New, got {other:?}"),
        }
        // trust has advanced to K_4
        assert_eq!(v.trusted_index(), 4);
        // a disclosure of K_3 arriving late now brings nothing new
        assert_eq!(v.check(chain.key(3), 3), Disclosure::NotNew);
        assert_eq!(v.trusted_index(), 4);
    }

    /// The forgery case: an attacker sends a made-up value claiming to be
    /// K_3. Hashing it down does not land on K_0, so the receiver rejects
    /// it, and keeps its state intact for the genuine key.
    #[test]
    fn tampered_key_rejected() {
        // the sender's chain (8 media intervals)
        let chain = test_chain(8);
        // the receiver: knows only the anchor K_0 at this point
        let mut v = ChainVerifier::new(*chain.anchor(), 8, 16);
        // the real K_3 with one byte flipped
        let mut bad = *chain.key(3);
        bad[0] ^= 0xFF;
        // rejected: hashing it 3 times does not produce K_0
        assert_eq!(v.check(&bad, 3), Disclosure::Invalid);
        // the rejection left no trace: trust still sits at the anchor
        assert_eq!(v.trusted_index(), 0);
        // so the genuine K_3, arriving right after, still verifies
        assert!(matches!(v.check(chain.key(3), 3), Disclosure::New(_)));
    }

}
