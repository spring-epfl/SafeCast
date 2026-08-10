//! SafeCast shared library: building blocks for the MLS -> SRTP pipeline.
//!
//! Group keying:
//!   - [`keying::mls`]: MLS group member management and key export (RFC 9420)
//!   - [`keying::ratchet`]: MLS-seeded per-stream key ratchet for
//!     fine-grained forward secrecy
//!   - [`keying::granularity`]: SRTP streams that rotate their ratchet key
//!     never (epoch-only), once per frame, or every packet.
//!
//! Transport:
//!   - [`transport::rtp`]: minimal RTP packet construction and parsing (RFC 3550)
//!   - [`transport::srtp_session`]: SRTP session creation with AES-128-GCM (RFC 7714)
//!
//! Receiver side:
//!   - [`receiver`]: real-network receiver: keeps the last K generation keys so
//!     late/reordered packets still decrypt
//!   - [`receiver::generation`]: mapping from a packet's header to its
//!     generation index `g`
//!   - [`receiver::index_recovery`]: RFC 3711 sequence-number unwrapping
//!
//! Simulation:
//!   - [`simulation`]: simulation of realistic delivery (reordering,
//!     loss) for benchmarking the keying granularities under a disturbed
//!     network instead of ideal in-order delivery
//!
//! Source authentication:
//!   - [`tesla`]: TESLA-style per-sender authentication (RFC 4082/4383)

pub mod keying;
pub mod receiver;
pub mod simulation;
pub mod tesla;
pub mod transport;
