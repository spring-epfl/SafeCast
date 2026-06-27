//! MLS-SRTP shared library: building blocks for the MLS -> SRTP pipeline.
//!
//! Modules:
//!   - [`mls`]: MLS group member management and key export (RFC 9420)
//!   - [`ratchet`]: MLS-seeded per-stream key ratchet for fine-grained forward secrecy
//!   - [`rtp`]: minimal RTP packet construction and parsing (RFC 3550)
//!   - [`srtp_session`]: SRTP session creation with AES-128-GCM (RFC 7714)
//!   - [`ds_client`]: HTTP client for the Authentication Service and Delivery Service
//!   - [`multicast`]: IP multicast UDP socket helpers for SRTP media transport

pub mod mls;
pub mod ratchet;
pub mod rtp;
pub mod srtp_session;
pub mod ds_client;
pub mod multicast;
