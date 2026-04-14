//! Raw AES-128-GCM benchmark: calls OpenSSL directly, bypassing libsrtp2.
//!
//! This benchmark performs only the OpenSSL AES-GCM calls that libsrtp2
//! makes internally, without any of the SRTP-specific work (stream lookup, 
//! replay check, IV construction, etc.).
//!
//! By comparing the results with `srtp_scaling` (which measures the full
//! `protect()` call), the difference isolates the SRTP overhead:
//!   SRTP overhead = protect() time − raw AES-GCM time
//!
//! Reuses the EVP_CIPHER_CTX across iterations, only reinitializing the IV
//! each time via encrypt_init(None, None, Some(iv)). This mirrors what
//! libsrtp2 does per packet in aes_gcm_ossl.c.
//!
//! Run:
//!   cargo bench --package mls-srtp-core --bench aes_gcm_baseline

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

/// Synthetic 128-bit AES key (all 0x01 for simplicity)
const KEY: [u8; 16] = [0x01; 16];

/// 12-byte IV, the standard GCM nonce length (RFC 7714 §8.1).
const IV: [u8; 12] = [0x02; 12];

/// 12-byte AAD matching the size of a fixed RTP header (RFC 3550).
/// In SRTP, the RTP header is authenticated but not encrypted.
const AAD: [u8; 12] = [0x03; 12];

/// AES-128-GCM authentication tag length in bytes (RFC 7714).
const TAG_LEN: usize = 16;

/// Same payload sizes as the SRTP payload scaling benchmark, ranging from
/// small audio-like payloads to jumbo-frame video payloads.
const PAYLOAD_SIZES: &[usize] = &[
    16, 32, 64, 128, 256, 512, 1024, 1424, 2048, 4096, 8192, 8924, 16384,
];

/// Benchmarks raw AES-128-GCM encryption for each payload size.
/// Uses `iter_custom` to time only the per-packet OpenSSL calls,
/// excluding setup and buffer allocation.
fn bench_raw_aes_gcm(c: &mut Criterion) {
    let cipher = Cipher::aes_128_gcm();

    let mut group = c.benchmark_group("raw_aes_gcm");

    // using 5 s measurement time per payload size
    group.measurement_time(Duration::from_secs(5));

    for &payload_size in PAYLOAD_SIZES {
        // telling Criterion the bytes processed per iteration (payload + tag)
        let total_size = payload_size + TAG_LEN;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", payload_size),
            &payload_size,
            |b, &sz| {

                // pre-allocating plaintext and ciphertext buffers
                let plaintext = vec![0u8; sz];
                let mut ciphertext = vec![0u8; sz + 16];
                let mut tag = [0u8; TAG_LEN];
                let mut iv = IV;

                // one-time full init: setting cipher algorithm + key (no IV yet)
                // This is the equivalent of libsrtp2's srtp_aes_gcm_openssl_context_init,
                // which runs once at session creation, not per packet
                let mut ctx = CipherCtx::new().unwrap();
                ctx.encrypt_init(Some(cipher), Some(&KEY), None).unwrap();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let t0 = Instant::now();

                        // per-packet: reinit with IV only (cipher=None, key=None).
                        // Equivalent to libsrtp2's srtp_aes_gcm_openssl_set_iv,
                        // which calls EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, 1)
                        ctx.encrypt_init(None, None, Some(&iv)).unwrap();

                        // process the AAD (RTP header): authenticated but not encrypted.
                        // Equivalent to libsrtp2's srtp_aes_gcm_openssl_set_aad,
                        // which calls EVP_Cipher(ctx, NULL, aad, aad_len)
                        ctx.cipher_update(&AAD, None).unwrap();

                        // encrypt the payload in place.
                        // Equivalent to libsrtp2's srtp_aes_gcm_openssl_encrypt,
                        // which calls EVP_Cipher(ctx, buf, buf, enc_len)
                        let count = ctx.cipher_update(&plaintext, Some(&mut ciphertext)).unwrap();

                        // finalize GCM: computes the GHASH authentication tag.
                        // Equivalent to the EVP_Cipher(ctx, NULL, NULL, 0) call
                        // inside libsrtp2's srtp_aes_gcm_openssl_get_tag
                        let _ = ctx.cipher_final(&mut ciphertext[count..]).unwrap();

                        // retrieve the 16-byte GCM authentication tag.
                        // Equivalent to EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)
                        ctx.tag(&mut tag).unwrap();

                        total += t0.elapsed();

                        // preventing the compiler from optimizing away the result
                        black_box(&ciphertext);
                        black_box(&tag);

                        // incrementing IV (like SRTP increments the packet index)
                        iv[11] = iv[11].wrapping_add(1);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_raw_aes_gcm);
criterion_main!(benches);
