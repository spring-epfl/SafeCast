//! TESLA-style per-sender source authentication.
//!
//! In an MLS group every member holds the SRTP group key, so the AES-GCM tag
//! only proves "some group member sent this": any member can forge packets
//! as any other. TESLA restores per-sender authentication by using time 
//! as the asymmetry: each packet carries a MAC under a key
//! that is still secret when the packet arrives and is only disclosed some
//! intervals later, once knowing it can no longer help a forger. 
//! Receivers buffer the packets, and verify them when the key
//! is disclosed.
//!
//! The pieces, one submodule each:
//!   - [`schedule`]: the timetable. Time is sliced into numbered intervals,
//!     each with its own key, and every key has a known "publication" moment.
//!     Holds the receiver's per-packet test "could this packet's key
//!     already be public?" (which is the question all of TESLA's security rests on).
//!   - [`chain`]: the keys themselves. The sender derives them all from
//!     one private random value. A receiver can prove any disclosed key
//!     genuine starting from just the one signed starting point.
//!   - [`mac`]: how a packet is tagged with its interval's key. This MAC
//!     is the one real cost TESLA adds to the sender's per-packet path, so
//!     it comes in two interchangeable algorithms (HMAC-SHA256 and GMAC)
//!     whose cost the benches investigate.

/// The one-way key chain.
pub mod chain;
/// The TESLA MAC.
pub mod mac;
/// The disclosure schedule and the receiver's accept test.
pub mod schedule;
/// The receiver: buffers delivered packets and verifies them on disclosure.
pub mod receiver;
/// The sender: tags outgoing packets and discloses "expired" keys.
pub mod sender;

use chain::{ChainKey, TESLA_KEY_LEN};
use mac::TESLA_MAC_LEN;

/// Wire size of the TESLA authentication extension appended after the SRTP
/// packet:
/// interval i (4 B) || disclosed key (20 B) || TESLA MAC (10 B).
pub const TESLA_EXT_LEN: usize = 4 + TESLA_KEY_LEN + TESLA_MAC_LEN;

/// Appends the TESLA authentication extension to a protected packet
/// (header || ciphertext || GCM tag -> ... || i || disclosed key || MAC).
pub fn append_extension(
    buf: &mut Vec<u8>,
    interval: u32,
    disclosed: &ChainKey,
    mac: &[u8; TESLA_MAC_LEN],
) {
    buf.extend_from_slice(&interval.to_be_bytes());
    buf.extend_from_slice(disclosed);
    buf.extend_from_slice(mac);
}

/// Strips the TESLA extension off a received packet, returning
/// `(interval, disclosed key, MAC)` and leaving `buf` as the plain SRTP
/// packet (header || ciphertext || GCM tag), ready for SRTP `unprotect`.
/// Returns `None` if the packet is too short to carry an extension.
pub fn split_extension(buf: &mut Vec<u8>) -> Option<(u32, ChainKey, [u8; TESLA_MAC_LEN])> {
    // the packet must hold the extension plus at least something in front
    // of it (the SRTP layers validate the rest)
    if buf.len() <= TESLA_EXT_LEN {
        return None;
    }
    let base = buf.len() - TESLA_EXT_LEN;

    // interval number: 4 bytes
    let interval = u32::from_be_bytes(buf[base..base + 4].try_into().unwrap());

    // disclosed key: the next 20 bytes
    let mut disclosed = [0u8; TESLA_KEY_LEN];
    disclosed.copy_from_slice(&buf[base + 4..base + 4 + TESLA_KEY_LEN]);

    // TESLA MAC: the last 10 bytes
    let mut mac = [0u8; TESLA_MAC_LEN];
    mac.copy_from_slice(&buf[base + 4 + TESLA_KEY_LEN..]);

    // the buffer shrinks back to the plain SRTP packet
    buf.truncate(base);
    Some((interval, disclosed, mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sender appends the extension, the receiver strips it: the
    /// receiver must read the interval, key and MAC the
    /// sender wrote, and be left with the untouched SRTP packet.
    #[test]
    fn extension_roundtrip() {

        // stand-in for a protected SRTP packet (content is irrelevant here)
        let packet: Vec<u8> = (0u8..100).collect();
        let mut buf = packet.clone();

        // sender side: appending an extension with recognizable values
        let disclosed = [0xAB; TESLA_KEY_LEN];
        let mac = [0xCD; TESLA_MAC_LEN];
        append_extension(&mut buf, 0x01020304, &disclosed, &mac);
        // the extension added exactly its 34 bytes
        assert_eq!(buf.len(), packet.len() + TESLA_EXT_LEN);

        // receiver side: stripping it again
        let (i, d, m) = split_extension(&mut buf).expect("extension present");
        // every field comes back as written...
        assert_eq!(i, 0x01020304);
        assert_eq!(d, disclosed);
        assert_eq!(m, mac);
        // ...and the packet itself is what the sender had
        assert_eq!(buf, packet);
    }

}
