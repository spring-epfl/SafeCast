//! Criterion benchmarks for the MLS-SRTP key derivation pipeline.
//!
//! Run: cargo bench --package mls-srtp-core --bench key_derivation
//!
//! The full key derivation pipeline has two stages:
//!
//!   1. MLS key export: two calls to `export_secret` (RFC 9420 §8.5) derive
//!      the 16-byte SRTP master key and 12-byte master salt from the MLS
//!      group's exporter secret.
//!
//!   2. SRTP KDF (RFC 3711 §4.3.1): derives session-level cipher and salt
//!      keys from the master key material using AES-128-CTR as a PRF.
//!      For AES-128-GCM there is no separate authentication key (GCM handles
//!      authentication internally), so the KDF produces 4 keys total:
//!        - RTP cipher key (16 B):  AES-CTR(master_key, salt XOR label=0x00)
//!        - RTP salt (12 B):        AES-CTR(master_key, salt XOR label=0x02)
//!        - RTCP cipher key (16 B): AES-CTR(master_key, salt XOR label=0x03)
//!        - RTCP salt (12 B):       AES-CTR(master_key, salt XOR label=0x05)
//!      The SRTP KDF benchmark calls a C implementation (benches/c/srtp_kdf.c)
//!      extracted from libsrtp2's `srtp_stream_init_keys()`.
//!
//! Both stages run once at session setup and again on each MLS epoch change
//! (new epoch -> new exporter secret -> new master key -> new session keys).
//! Neither runs per packet.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

use mls_srtp_core::mls::{
    export_srtp_keys, ssrc_from_identity, MlsMember,
    CIPHERSUITE,
};

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

// FFI binding to the C implementation in benches/c/srtp_kdf.c.
// Copy-pasted libsrtp2 KDF.
unsafe extern "C" {
    fn srtp_kdf_ensure_init() -> i32;
    fn srtp_kdf_derive(
        key_material: *const u8,     // 30 bytes in (16 key + 12 salt + 2 padding)
        rtp_cipher_key: *mut u8,     // 16 bytes out
        rtp_salt: *mut u8,           // 12 bytes out
        rtcp_cipher_key: *mut u8,    // 16 bytes out
        rtcp_salt: *mut u8,          // 12 bytes out
    ) -> i32;
}

/// SRTP_AES_ICM_128_KEY_LEN_WSALT = SRTP_SALT_LEN (14) + SRTP_AES_128_KEY_LEN (16) = 30
const SRTP_AES_ICM_128_KEY_LEN_WSALT: usize = 30;

/// Calls the C SRTP KDF implementation via FFI.
/// Pads the 28-byte key material (16 key + 12 salt) to 30 bytes
/// to match SRTP_AES_ICM_128_KEY_LEN_WSALT (the AES-ICM KDF expects
/// a 14-byte salt, so we zero-pad the 12-byte GCM salt by 2 bytes).
///
/// Caller must call `srtp_kdf_ensure_init()` once before the first call.
fn srtp_kdf(master_key: &[u8; 16], master_salt: &[u8; 12]) {

    // packing master key and salt into the 30-byte buffer the C KDF expects
    let mut key_material = [0u8; SRTP_AES_ICM_128_KEY_LEN_WSALT];
    key_material[..16].copy_from_slice(master_key);
    key_material[16..28].copy_from_slice(master_salt);
    // bytes 28..30 are zero (padding to 14-byte ICM salt)

    // output buffers for the 4 derived session keys
    let mut rtp_cipher_key = [0u8; 16];
    let mut rtp_salt = [0u8; 12];
    let mut rtcp_cipher_key = [0u8; 16];
    let mut rtcp_salt = [0u8; 12];

    // calling the C KDF (4 x AES-128-CTR keystream generations)
    let ret = unsafe {
        srtp_kdf_derive(
            key_material.as_ptr(),
            rtp_cipher_key.as_mut_ptr(),
            rtp_salt.as_mut_ptr(),
            rtcp_cipher_key.as_mut_ptr(),
            rtcp_salt.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0, "SRTP KDF failed with code {ret}");

    // preventing the compiler from optimizing away the derived keys
    black_box(&rtp_cipher_key);
    black_box(&rtp_salt);
    black_box(&rtcp_cipher_key);
    black_box(&rtcp_salt);
}

/// Sets up a minimal 2-member MLS group and exports SRTP key material for the
/// sender. Also initializes the libsrtp crypto kernel for the C KDF benchmark.
/// Returns the group, the sender member, and the separated master key
/// and master salt.
fn setup_mls_group() -> (MlsGroup, MlsMember, [u8; 16], [u8; 12]) {

    // initializing the libsrtp crypto kernel (needed for the C KDF benchmark)
    let ret = unsafe { srtp_kdf_ensure_init() };
    assert_eq!(ret, 0, "srtp_kdf_ensure_init failed");

    // creating two members with credentials
    let sender = MlsMember::new("sender-0:sender");
    let receiver = MlsMember::new("receiver-0:receiver");

    // receiver publishes a KeyPackage so the sender can add them
    let receiver_kp = receiver.generate_key_package();

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // sender creates the group
    let mut group = MlsGroup::new(
        &sender.provider,
        &sender.signer,
        &group_config,
        sender.credential_with_key.clone(),
    )
    .expect("failed to create MLS group");

    // sender adds the receiver to the group via an Add commit
    group
        .add_members(
            &sender.provider,
            &sender.signer,
            &[receiver_kp.key_package().clone()],
        )
        .expect("failed to add receiver");

    // sender merges its own pending commit to advance to the new epoch
    group
        .merge_pending_commit(&sender.provider)
        .expect("failed to merge commit");

    // deriving the sender's SSRC and export SRTP key material from the current epoch
    let ssrc = ssrc_from_identity("sender-0:sender");
    let (_, master_key, master_salt) =
        export_srtp_keys(&group, sender.provider.crypto(), ssrc);

    let master_key: [u8; 16] = master_key.try_into().unwrap();
    let master_salt: [u8; 12] = master_salt.try_into().unwrap();

    (group, sender, master_key, master_salt)
}

// ---------------------------------------------------------------------------
// Benchmark 1: MLS Key Export
// ---------------------------------------------------------------------------

/// Benchmarks the MLS exporter key derivation: two calls to `export_secret`
/// (one for the 16-byte master key, one for the 12-byte master salt).
///
/// This runs once per MLS epoch change (when group membership changes).
fn bench_mls_key_export(c: &mut Criterion) {
    let (group, sender, _, _) = setup_mls_group();
    let ssrc = ssrc_from_identity("sender-0:sender");

    // measuring two export_secret calls: one for master key, one for master salt
    c.bench_function("mls_key_export", |b| {
        b.iter(|| {
            let (km, _key, _salt) = export_srtp_keys(
                black_box(&group),
                sender.provider.crypto(),
                black_box(ssrc),
            );
            black_box(&km);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 2: SRTP KDF
// ---------------------------------------------------------------------------

/// Benchmarks the SRTP KDF (RFC 3711 §4.3.1) in isolation by calling the
/// C implementation extracted from libsrtp2's `srtp_stream_init_keys()`.
fn bench_srtp_kdf(c: &mut Criterion) {
    let (_group, _sender, master_key, master_salt) = setup_mls_group();

    // measuring only the SRTP KDF: 4 AES-128-CTR keystream generations
    c.bench_function("srtp_kdf", |b| {
        b.iter(|| {
            srtp_kdf(black_box(&master_key), black_box(&master_salt));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 3: Full Pipeline (MLS export + SRTP KDF)
// ---------------------------------------------------------------------------

/// Benchmarks the full key derivation pipeline: MLS key export followed by
/// SRTP KDF. This is the cost every group member pays when an MLS epoch
/// change occurs and new session keys must be derived.
fn bench_full_key_derivation(c: &mut Criterion) {
    let (group, sender, _, _) = setup_mls_group();
    let ssrc = ssrc_from_identity("sender-0:sender");

    // measuring both stages: the total cost on each epoch change
    c.bench_function("full_key_derivation", |b| {
        b.iter(|| {
            // stage 1: MLS exporter derives master key + master salt
            let (_, key, salt) = export_srtp_keys(
                black_box(&group),
                sender.provider.crypto(),
                black_box(ssrc),
            );

            // stage 2: SRTP KDF turns master key material into session keys
            let master_key: [u8; 16] = key.try_into().unwrap();
            let master_salt: [u8; 12] = salt.try_into().unwrap();
            srtp_kdf(black_box(&master_key), black_box(&master_salt));
        });
    });
}

criterion_group!(
    benches,
    bench_mls_key_export,
    bench_srtp_kdf,
    bench_full_key_derivation,
);

criterion_main!(benches);
