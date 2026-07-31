//! PEP (Privacy Encryption Protocol) throughput benchmark.
//! 
//! Benchmarks the encryption and decryption throughput of PEP's RTP payload
//! protection modes (AES-128-CTR and AES-128-CTR_CMAC-64), as specified in
//! VSF TR-10-13.
//!
//! Modes benchmarked (§20):
//!   - AES-128-CTR (mandatory mode): encryption only, no authentication
//!   - AES-128-CTR_CMAC-64 (optional): AES-128-CTR + 64-bit truncated
//!     AES-CMAC, mac-then-encrypt
//!
//! Uses the same 15 payload sizes and the same `iter_custom` timing approach
//! as the SRTP benchmark.
//!
//! Design notes:
//!
//! - **IV construction.** PEP (§20) constructs a 128-bit IV as
//!   `iv'_ctr = iv' || ctr`, where `iv'` is a fixed 64-bit value from
//!   the SDP transport parameters and `ctr` is a 64-bit counter that
//!   increments per data slice. We do the same in our benchmark: `build_iv()`
//!   concatenates a fixed 8-byte `iv'` with a big-endian 64-bit packet
//!   counter.
//!
//! - **CMAC key.** PEP (§20) uses the same privacy cipher key for both
//!   AES-CTR encryption and CMAC computation. We do the same here,
//!   using a single synthetic key for both operations.
//!
//! - **Mac-then-encrypt.** For CMAC-64 modes (§20), PEP computes CMAC
//!   over the plaintext payload, truncates to 64 bits, appends the tag,
//!   and then encrypts (payload + tag) with AES-CTR.
//!
//! - **Payload only.** Like SRTP, PEP encrypts only the RTP payload, not
//!   the header (§20). Unlike SRTP, PEP does not authenticate the header:
//!   the CTR-only mode has no authentication at all, and CTR_CMAC-64
//!   authenticates only the payload.
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench pep_throughput

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::Cipher as SymmCipher;

use mls_srtp_core::rtp::RTP_HEADER_LEN;

/// Synthetic 128-bit AES key (key value is irrelevant to AES throughput).
const KEY: [u8; 16] = [0x01; 16];

/// Fixed 64-bit `iv'` value (first half of the 128-bit IV).
const IV_PRIME: [u8; 8] = [0x02; 8];

/// PEP CMAC-64: 128-bit AES-CMAC truncated to 64 bits (8 bytes).
const CMAC_TAG_LEN: usize = 8;

/// Constructs the 128-bit IV: `iv'_ctr = iv' || ctr`.
#[inline]
fn build_iv(ctr: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&IV_PRIME);
    iv[8..].copy_from_slice(&ctr.to_be_bytes());
    iv
}

/// Same payload sizes as the SRTP throughput benchmark, from tiny audio
/// payloads to ST 2110-10 jumbo-frame video payloads.
const PAYLOAD_SIZES: &[(usize, &str)] = &[
    // powers of 2
    (16,    "0016B"),
    (32,    "0032B"),
    (40,    "0040B"),
    (64,    "0064B"),
    (128,   "0128B"),
    // application-realistic: G.711 speech at 20 ms
    (160,   "0160B_speech"),
    // powers of 2 (continued)
    (256,   "0256B"),
    (512,   "0512B"),
    // application-realistic: typical video packet sizes
    (800,   "0800B_video"),
    (1024,  "1024B"),
    (1200,  "1200B_video"),
    // ST 2110-10 standard MTU (1460 − 8 − 12 − 16 = 1424)
    (1424,  "1424B_standard"),
    // powers of 2 (continued)
    (2048,  "2048B"),
    (4096,  "4096B"),
    // ST 2110-10 jumbo MTU (8960 − 8 − 12 − 16 = 8924)
    (8924,  "8924B_jumbo"),
];

// -------------------------------------------------------------------------
// AES-128-CTR (mandatory mode, §20) — no authentication
// -------------------------------------------------------------------------

/// Benchmarks PEP AES-128-CTR encryption throughput.
///
/// Per packet: reinitialize IV, then AES-128-CTR encrypt the payload.
/// No authentication tag is produced (mandatory mode has no integrity
/// protection).
fn bench_pep_ctr_encrypt(c: &mut Criterion) {
    let cipher = Cipher::aes_128_ctr();
    let mut group = c.benchmark_group("pep_throughput");
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        // output packet on the wire: RTP header (clear) + encrypted payload
        let pep_len = RTP_HEADER_LEN + payload_size;
        group.throughput(Throughput::Bytes(pep_len as u64));

        group.bench_with_input(
            BenchmarkId::new("ctr_encrypt", label),
            &payload_size,
            |b, &sz| {
                let plaintext = vec![0u8; sz];
                let mut ciphertext = vec![0u8; sz + 16]; // +16: OpenSSL may need extra block for cipher_final

                // setting cipher algorithm and key once,
                // IV is set per-packet below
                let mut ctx = CipherCtx::new().unwrap();
                ctx.encrypt_init(Some(cipher), Some(&KEY), None).unwrap();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for pkt in 0..iters {

                        // building per-packet IV: iv' || ctr
                        let iv = build_iv(pkt);

                        // --- timed section: only the AES-CTR encryption ---
                        let t0 = Instant::now();

                        // setting this packet's IV (cipher + key are already set)
                        ctx.encrypt_init(None, None, Some(&iv)).unwrap();

                        // encrypting the payload with AES-128-CTR
                        let count = ctx
                            .cipher_update(&plaintext, Some(&mut ciphertext))
                            .unwrap();

                        // finalizing (flushes any remaining partial block)
                        let _ = ctx.cipher_final(&mut ciphertext[count..]).unwrap();

                        total += t0.elapsed();

                        black_box(&ciphertext);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

/// Benchmarks PEP AES-128-CTR decryption throughput.
///
/// AES-CTR decryption is the same operation as encryption (XOR with
/// keystream), but we use the decrypt API path for correctness.
fn bench_pep_ctr_decrypt(c: &mut Criterion) {
    let cipher = Cipher::aes_128_ctr();
    let mut group = c.benchmark_group("pep_throughput");
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        let pep_len = RTP_HEADER_LEN + payload_size;
        group.throughput(Throughput::Bytes(pep_len as u64));

        group.bench_with_input(
            BenchmarkId::new("ctr_decrypt", label),
            &payload_size,
            |b, &sz| {
                let ciphertext_in = vec![0u8; sz];
                let mut plaintext_out = vec![0u8; sz + 16];

                // setting cipher algorithm and key once
                let mut ctx = CipherCtx::new().unwrap();
                ctx.decrypt_init(Some(cipher), Some(&KEY), None).unwrap();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for pkt in 0..iters {

                        // building per-packet IV: iv' || ctr
                        let iv = build_iv(pkt);

                        // --- timed section: only the AES-CTR decryption ---
                        let t0 = Instant::now();

                        // setting this packet's IV
                        ctx.decrypt_init(None, None, Some(&iv)).unwrap();

                        // decrypting the payload with AES-128-CTR
                        let count = ctx
                            .cipher_update(&ciphertext_in, Some(&mut plaintext_out))
                            .unwrap();

                        // finalizing
                        let _ = ctx.cipher_final(&mut plaintext_out[count..]).unwrap();

                        total += t0.elapsed();

                        black_box(&plaintext_out);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

// -------------------------------------------------------------------------
// AES-128-CTR_CMAC-64 (§20) — mac-then-encrypt
// -------------------------------------------------------------------------

/// Benchmarks PEP AES-128-CTR_CMAC-64 encryption throughput.
///
/// Per packet (mac-then-encrypt, §20):
///   1. Compute AES-CMAC over the plaintext payload, truncate to 64 bits
///   2. Append the 8-byte MAC to the payload
///   3. Encrypt (payload + MAC) with AES-128-CTR
fn bench_pep_ctr_cmac_encrypt(c: &mut Criterion) {
    let ctr_cipher = Cipher::aes_128_ctr();
    let cmac_cipher = SymmCipher::aes_128_cbc();

    let mut group = c.benchmark_group("pep_throughput");
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        // output packet: header (clear) + encrypted(payload + 8-byte MAC)
        let pep_len = RTP_HEADER_LEN + payload_size + CMAC_TAG_LEN;
        group.throughput(Throughput::Bytes(pep_len as u64));

        group.bench_with_input(
            BenchmarkId::new("ctr_cmac64_encrypt", label),
            &payload_size,
            |b, &sz| {
                let encrypt_len = sz + CMAC_TAG_LEN;
                let mut plain_with_mac = vec![0u8; encrypt_len];
                let mut ciphertext = vec![0u8; encrypt_len + 16];

                // CMAC signing key (same key as encryption, per §20).
                let cmac_pkey = PKey::cmac(&cmac_cipher, &KEY).unwrap();

                // Setting CTR cipher algorithm and key once;
                // IV is set per-packet below
                let mut ctx = CipherCtx::new().unwrap();
                ctx.encrypt_init(Some(ctr_cipher), Some(&KEY), None).unwrap();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for pkt in 0..iters {
                        let iv = build_iv(pkt);
                        let t0 = Instant::now();

                        // 1. computing CMAC over payload, then truncating to 64 bits
                        let mut signer = Signer::new_without_digest(&cmac_pkey).unwrap();
                        signer.update(&plain_with_mac[..sz]).unwrap();
                        let mut full_mac = [0u8; 16];
                        signer.sign(&mut full_mac).unwrap();
                        plain_with_mac[sz..].copy_from_slice(&full_mac[..CMAC_TAG_LEN]);

                        // 2. encrypting (payload + MAC) with AES-128-CTR
                        ctx.encrypt_init(None, None, Some(&iv)).unwrap();
                        let count = ctx
                            .cipher_update(&plain_with_mac, Some(&mut ciphertext))
                            .unwrap();
                        let _ = ctx.cipher_final(&mut ciphertext[count..]).unwrap();

                        total += t0.elapsed();

                        black_box(&ciphertext);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

/// Benchmarks PEP AES-128-CTR_CMAC-64 decryption throughput.
///
/// Per packet (decrypt-then-verify):
///   1. Decrypt with AES-128-CTR to recover (payload + MAC)
///   2. Recompute CMAC over the payload portion, truncate to 64 bits
///   3. Compare with the received MAC (verification)
fn bench_pep_ctr_cmac_decrypt(c: &mut Criterion) {
    let ctr_cipher = Cipher::aes_128_ctr();
    let cmac_cipher = SymmCipher::aes_128_cbc();

    let mut group = c.benchmark_group("pep_throughput");
    group.measurement_time(Duration::from_secs(10));

    for &(payload_size, label) in PAYLOAD_SIZES {

        let pep_len = RTP_HEADER_LEN + payload_size + CMAC_TAG_LEN;
        group.throughput(Throughput::Bytes(pep_len as u64));

        group.bench_with_input(
            BenchmarkId::new("ctr_cmac64_decrypt", label),
            &payload_size,
            |b, &sz| {
                let total_len = sz + CMAC_TAG_LEN;

                // CMAC signing key (same key as encryption, per §20)
                let cmac_pkey = PKey::cmac(&cmac_cipher, &KEY).unwrap();

                // arbitrary ciphertext buffer (AES and CMAC performance is
                // data-independent, so content does not affect timing)
                let ciphertext_in = vec![0u8; total_len];
                let mut decrypted = vec![0u8; total_len + 16];

                // setting CTR cipher algorithm and key once;
                // IV is set per-packet below
                let mut ctx = CipherCtx::new().unwrap();
                ctx.decrypt_init(Some(ctr_cipher), Some(&KEY), None).unwrap();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for pkt in 0..iters {
                        let iv = build_iv(pkt);
                        let t0 = Instant::now();

                        // 1. decrypting with AES-128-CTR
                        ctx.decrypt_init(None, None, Some(&iv)).unwrap();
                        let count = ctx
                            .cipher_update(&ciphertext_in, Some(&mut decrypted))
                            .unwrap();
                        let _ = ctx.cipher_final(&mut decrypted[count..]).unwrap();

                        // 2. recomputing CMAC over payload portion and verifying
                        let mut signer = Signer::new_without_digest(&cmac_pkey).unwrap();
                        signer.update(&decrypted[..sz]).unwrap();
                        let mut computed_mac = [0u8; 16];
                        signer.sign(&mut computed_mac).unwrap();

                        // 3. comparing with the received MAC
                        let mac_ok =
                            computed_mac[..CMAC_TAG_LEN] == decrypted[sz..sz + CMAC_TAG_LEN];

                        total += t0.elapsed();

                        black_box(mac_ok);
                        black_box(&decrypted);
                        black_box(&computed_mac);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_pep_ctr_encrypt,
    bench_pep_ctr_decrypt,
    bench_pep_ctr_cmac_encrypt,
    bench_pep_ctr_cmac_decrypt,
);
criterion_main!(benches);
