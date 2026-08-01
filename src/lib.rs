//! MLS-SRTP shared library: building blocks for the MLS -> SRTP pipeline.
//!
//! Group keying:
//!   - [`mls`]: MLS group member management and key export (RFC 9420)
//!   - [`keying::ratchet`]: MLS-seeded per-stream key ratchet for
//!     fine-grained forward secrecy
//!   - [`keying::granularity`]: SRTP streams that rotate their ratchet key
//!     never (epoch-only), once per frame, or every packet. Mostly sender
//!     side, but its `unprotect` works when packets arrive exactly in send
//!     order; some throughput benchmarks use it that way.
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
//! Simulation (evaluation only):
//!   - [`sim`]: trace-driven simulation of realistic delivery (reordering,
//!     loss) for benchmarking the keying granularities under a disturbed
//!     network instead of ideal in-order delivery
//!
//! (The live demo's networking, the AS/DS HTTP client and the IP-multicast
//! socket helpers, lives in demo/mls-srtp-client.)

pub mod keying;
pub mod mls;
pub mod receiver;
pub mod sim;
pub mod transport;
