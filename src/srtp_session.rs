//! SRTP session creation using libsrtp (via the `srtp` crate).
//!
//! Configures AEAD_AES_128_GCM with a 16-byte authentication tag (RFC 7714).
//! libsrtp handles the SRTP KDF (RFC 3711 §4.3.1) and IV construction
//! (RFC 7714 §8.1) internally (we just supply the master key material).

use srtp::{CryptoPolicy, Session, StreamPolicy};

/// Creates an outbound (sender) SRTP session with AES-128-GCM.
///
/// `key_material` must be 28 bytes: master_key (16) || master_salt (12).
///
/// libsrtp can be configured per-SSRC or with a catch-all template.
/// `with_outbound_template` applies the same crypto policy to all
/// outgoing SSRCs, so we don't have to register each one individually.
pub fn create_sender_session(key_material: &[u8]) -> Session {
    let policy = StreamPolicy {
        rtp: CryptoPolicy::aes_gcm_128_16_auth(),
        rtcp: CryptoPolicy::aes_gcm_128_16_auth(),
        key: key_material,
        // replay protection window: libsrtp tracks the last 128 sequence
        // numbers and rejects duplicates (RFC 3711 §3.3.2)
        window_size: 128,
        ..Default::default()
    };
    Session::with_outbound_template(policy).expect("failed to create sender SRTP session")
}

/// Creates an inbound (receiver) SRTP session with AES-128-GCM.
///
/// `key_material` must be 28 bytes: master_key (16) || master_salt (12).
///
/// Same as above but for incoming packets: `with_inbound_template` applies
/// the crypto policy to all incoming SSRCs without registering each one.
pub fn create_receiver_session(key_material: &[u8]) -> Session {
    let policy = StreamPolicy {
        rtp: CryptoPolicy::aes_gcm_128_16_auth(),
        rtcp: CryptoPolicy::aes_gcm_128_16_auth(),
        key: key_material,
        // replay protection window: libsrtp tracks the last 128 sequence
        // numbers and rejects duplicates (RFC 3711 §3.3.2)
        window_size: 128,
        ..Default::default()
    };
    Session::with_inbound_template(policy).expect("failed to create receiver SRTP session")
}
