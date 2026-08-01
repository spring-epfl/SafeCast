//! Group keying: how an MLS group secret becomes a chain of short-lived
//! SRTP keys.
//!
//! - [`mls`]: MLS group member management and per-sender key export (RFC 9420)
//! - [`ratchet`]: the MLS-seeded per-stream key ratchet (HKDF chain) that
//!   derives generation keys `key_0, key_1, ...` from the exported seed
//! - [`granularity`]: SRTP streams that advance that ratchet never
//!   (epoch-only), once per frame, or on every packet

pub mod granularity;
pub mod mls;
pub mod ratchet;
