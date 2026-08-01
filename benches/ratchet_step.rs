//! Microbenchmarks for the per-generation ratchet cost.
//!
//! Per generation the data plane pays a fixed cost: two HKDF-Expands 
//! (one for the SRTP key+salt, one for the chain step) plus an 
//! AES-128-GCM key setup to
//! install the new key. This benchmark times each piece so we can predict, before
//! building the data path, where packet-level keying stops keeping up with a
//! format's bitrate.
//!
//! The AES-128-GCM key setup has two parts. The key schedule expands the 16-byte key into
//! the per-round subkeys AES uses internally on every block. The GHASH H subkey
//! is a key-derived value that GCM's authentication step multiplies by. 
//! Both are derived from the key, so a new key forces recomputing both.
//!
//! Run: cargo bench --package mls-srtp-core --bench ratchet_step

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

use mls_srtp_core::keying::ratchet::{StreamRatchet, CHAIN_SECRET_LEN};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

/// A fixed 32-byte ratchet seed `S_0`. The per-generation cost is independent of
/// the secret value, so a constant seed is fine for timing.
fn test_seed() -> Vec<u8> {
    (0..CHAIN_SECRET_LEN as u8).collect()
}

/// Times the combined `next_key_salt` (a key+salt derive plus a
/// chain advance), the operation the data plane actually runs each generation.
fn bench_next_key_salt(c: &mut Criterion) {
    let provider = OpenMlsRustCrypto::default();
    let mut ratchet = StreamRatchet::from_seed(test_seed());
    c.bench_function("ratchet_next_key_salt", |b| {
        b.iter(|| {
            black_box(ratchet.next_key_salt(provider.crypto()));
        });
    });
}

/// The chain step alone (one HKDF-Expand): advancing `S_g -> S_{g+1}`.
fn bench_chain_step(c: &mut Criterion) {
    let provider = OpenMlsRustCrypto::default();
    let mut ratchet = StreamRatchet::from_seed(test_seed());
    c.bench_function("ratchet_chain_step", |b| {
        b.iter(|| {
            // advancing the chain only
            ratchet.advance(provider.crypto());
        });
    });
}

/// The key+salt derivation alone (one HKDF-Expand), without advancing.
fn bench_key_salt(c: &mut Criterion) {
    let provider = OpenMlsRustCrypto::default();
    let ratchet = StreamRatchet::from_seed(test_seed());
    c.bench_function("ratchet_key_salt", |b| {
        b.iter(|| {
            // deriving the current generation's key+salt only
            black_box(ratchet.derive_key_salt(provider.crypto()));
        });
    });
}

/// AES-128-GCM key setup.
fn bench_gcm_key_setup(c: &mut Criterion) {
    // a fixed 16-byte key
    let key = [0x42u8; 16];
    let cipher = Cipher::aes_128_gcm();
    c.bench_function("gcm_key_setup", |b| {
        // creating the cipher once, then re-keying that same cipher each iteration
        let mut ctx = CipherCtx::new().unwrap();
        b.iter(|| {
            // installing the new key: triggers the AES key schedule + GHASH H subkey
            ctx.encrypt_init(Some(cipher), Some(black_box(&key)), None)
                .unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_next_key_salt,
    bench_chain_step,
    bench_key_salt,
    bench_gcm_key_setup,
);
criterion_main!(benches);
