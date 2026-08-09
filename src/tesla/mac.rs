//! The TESLA MAC: the tag each packet carries under its interval's
//! secret key. Two interchangeable algorithms:
//!
//! - HMAC-SHA256
//! - GMAC: AES-GCM run with no plaintext, so only its authentication part
//!   executes. Backed by OpenSSL, whose GHASH ran about 4x faster than
//!   the RustCrypto implementation when both were measured (tests/micro_mac.rs).
//!
//! Both tags are cut to the spec's 10 bytes.
//!
//! What the tag covers: every byte of the packet plus its ROC. The header's
//! sequence number is 16-bit and wraps, so packet n and packet n + 65,536
//! have identical headers. If the tag did not cover it, a
//! recorded packet could be replayed one wrap later and its tag would
//! still verify.
//!

use hmac::{Hmac, Mac};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use sha2::Sha256;

use crate::tesla::chain::{mac_key, ChainKey};

/// TESLA MAC length in bytes: the spec's default of 80 bits.
pub const TESLA_MAC_LEN: usize = 10;

/// Which TESLA MAC instantiation a stream runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeslaMacAlg {
    /// HMAC-SHA256
    HmacSha256,
    /// GMAC: AES-128-GCM over empty plaintext
    GmacAes128,
}

impl TeslaMacAlg {
    /// F' output length
    pub fn mac_key_len(&self) -> usize {
        match self {
            TeslaMacAlg::HmacSha256 => 32,
            TeslaMacAlg::GmacAes128 => 16,
        }
    }

    /// Derives interval `i`'s MAC key K'_i = F'(K_i) and runs the key
    /// setup. Called once per interval.
    pub fn prepare(&self, chain_key: &ChainKey) -> PreparedMac {
        let key = mac_key(chain_key, self.mac_key_len());

        // sized for the algorithm in use
        match self {
            // keying the HMAC
            TeslaMacAlg::HmacSha256 => PreparedMac::Hmac(
                <Hmac<Sha256> as Mac>::new_from_slice(&key)
                    .expect("HMAC accepts any key length"),
            ),
            // keying the AES-GCM context: the key schedule runs here,
            // once (per-packet tag() calls only set a fresh nonce)
            TeslaMacAlg::GmacAes128 => {
                let mut ctx = CipherCtx::new().expect("CipherCtx::new failed");
                ctx.encrypt_init(Some(Cipher::aes_128_gcm()), Some(&key), None)
                    .expect("GCM key init failed");
                PreparedMac::Gmac(ctx)
            }
        }
    }
}

/// The state of whichever MAC algorithm the stream
/// runs. Each variant holds its keyed object: for HMAC a hash state with the key
/// already absorbed, for GMAC an AES cipher with the key schedule already
/// run. [`Self::tag`] then only does the per-packet work.
pub enum PreparedMac {
    Hmac(Hmac<Sha256>),
    Gmac(CipherCtx),
}

impl PreparedMac {

    /// Tags one packet: `packet` is every byte before the TESLA extension,
    /// `ext_index` the packet's full index.
    pub fn tag(&mut self, ext_index: u64, packet: &[u8]) -> [u8; TESLA_MAC_LEN] {
        // the 10-byte output, filled by whichever branch runs
        let mut tag = [0u8; TESLA_MAC_LEN];

        match self {
            PreparedMac::Hmac(prepared) => {
                // the ROC: the high bits of the position, as 4 bytes
                let roc = ((ext_index >> 16) as u32).to_be_bytes();
                // finalize() below destroys the hash state, so this packet
                // works on a copy and `prepared` stays intact for the
                // interval's next packet
                let mut h = prepared.clone();
                // feeding the 4 ROC bytes, then the packet bytes: the tag
                // is computed over ROC || packet
                h.update(&roc);
                h.update(packet);
                // cutting the 32-byte HMAC output down to the 10-byte tag
                tag.copy_from_slice(&h.finalize().into_bytes()[..TESLA_MAC_LEN]);
            }
            PreparedMac::Gmac(ctx) => {
                // the packet's full position as the 96-bit nonce
                let mut nonce = [0u8; 12];
                nonce[4..].copy_from_slice(&ext_index.to_be_bytes());
                // re-initializing only the nonce: the key schedule from
                // prepare() is kept
                ctx.encrypt_init(None, None, Some(&nonce))
                    .expect("GCM nonce init failed");
                // feeding the packet as associated data (no plaintext), so
                // only GCM's authentication part runs
                ctx.cipher_update(packet, None).expect("GCM aad failed");
                ctx.cipher_final(&mut []).expect("GCM final failed");
                // the 16-byte GCM tag, cut down to the 10-byte tag
                let mut full = [0u8; 16];
                ctx.tag(&mut full).expect("GCM tag failed");
                tag.copy_from_slice(&full[..TESLA_MAC_LEN]);
            }
        }
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tesla::chain::TESLA_KEY_LEN;

    /// The shared suite: every property below holds for both
    /// instantiations.
    fn algs() -> [TeslaMacAlg; 2] {
        [TeslaMacAlg::HmacSha256, TeslaMacAlg::GmacAes128]
    }

    /// The receiver verifies a tag by recomputing it, so the same inputs
    /// must always give the same tag. And any changed input (packet
    /// bytes, position, key) must give a different one.
    #[test]
    fn deterministic_and_input_sensitive() {
        // a fixed chain key and packet as the reference inputs
        let chain_key = [5u8; TESLA_KEY_LEN];
        let packet: Vec<u8> = (0u8..64).collect();
        // every property must hold for both algorithms
        for alg in algs() {
            // the reference tag: index 7, the packet above
            let mut p = alg.prepare(&chain_key);
            let t = p.tag(7, &packet);
            // recomputing with identical inputs gives the identical tag
            assert_eq!(t, p.tag(7, &packet), "{alg:?} must be deterministic");
            // the receiver prepares its own state from the same chain key
            // and must compute the same tag as the sender's state
            assert_eq!(t, alg.prepare(&chain_key).tag(7, &packet));

            // flipping one payload byte changes the tag
            let mut other = packet.clone();
            other[10] ^= 1;
            assert_ne!(t, p.tag(7, &other), "{alg:?} must bind the packet");

            // same packet at an index one seq-wrap later (= ROC + 1)
            // changes the tag
            assert_ne!(
                t,
                p.tag(7 + (1 << 16), &packet),
                "{alg:?} must bind the ROC"
            );

            // a different interval key changes the tag
            let mut p2 = alg.prepare(&[6u8; TESLA_KEY_LEN]);
            assert_ne!(t, p2.tag(7, &packet), "{alg:?} must bind the key");
        }
    }

}
