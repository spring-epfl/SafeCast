//! Fine-grained, within-epoch keying: how one MLS epoch secret becomes a
//! chain of short-lived SRTP keys.
//!
//! - [`ratchet`]: the MLS-seeded per-stream key ratchet (HKDF chain) that
//!   derives generation keys `key_0, key_1, ...` from the exported seed
//! - [`granularity`]: SRTP streams that advance that ratchet never
//!   (epoch-only), once per frame, or on every packet

pub mod granularity;
pub mod ratchet;
