//! MLS-SRTP library: exporting MLS group keys to protect SRTP media.
//!
//! This crate provides the building blocks for the MLS -> SRTP pipeline:
//!   - [`mls`]: MLS group member management and key export (RFC 9420)
//!   - [`srtp_session`]: SRTP session creation with AES-128-GCM (RFC 7714)
//!   - [`rtp`]: minimal RTP packet construction and parsing (RFC 3550)

pub mod mls;
pub mod rtp;
pub mod srtp_session;
