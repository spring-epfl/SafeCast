//! The media transport layer the keying schemes plug into.
//!
//! - [`rtp`]: minimal RTP packet construction and parsing (RFC 3550)
//! - [`srtp_session`]: SRTP session creation with AES-128-GCM (RFC 7714)

pub mod rtp;
pub mod srtp_session;
