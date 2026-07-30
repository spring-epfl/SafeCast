srtp2-sys (fork)
================

Rust binding for libsrtp2. Forked from [HyeonuPark/srtp2-sys](https://github.com/HyeonuPark/srtp2-sys).

# Why this fork?

The original [`srtp2-sys` crate (v3.0.2)](https://crates.io/crates/srtp2-sys) bundles libsrtp
v2.3.0, which has a bug that adds ~120 ns of unnecessary
overhead to every SRTP encryption (`protect()`) call when using OpenSSL 3.

SRTP uses AES-128-GCM for authenticated encryption. In GCM mode, the
sender generates an authentication tag as output, while the
receiver must be told the expected tag so it can verify data
integrity. The OpenSSL API call `EVP_CIPHER_CTX_ctrl(SET_TAG)` is how you
provide this expected tag. As stated in the
[OpenSSL documentation](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/#gcm-and-ocb-modes):
"For GCM, this call is only valid when decrypting data."

In libsrtp v2.3.0, the function
[`srtp_aes_gcm_openssl_set_aad()`](https://github.com/cisco/libsrtp/blob/3ba20a1bb464f8cdebdd63bbbba821528db0f15b/crypto/cipher/aes_gcm_ossl.c#L266)
calls `SET_TAG` even on encrypt contexts. On OpenSSL 3,
this triggers an error path: OpenSSL
[detects the invalid usage](https://github.com/openssl/openssl/blob/2fab90bb5e19/providers/implementations/ciphers/ciphercommon_gcm.c#L266),
calls `ERR_raise()` (which pushes an error onto the per-thread error stack),
and returns failure. libsrtp ignores the return value, so encryption still
works correctly, but the `ERR_raise()` call costs ~120 ns, wasted on every
single packet.

This was fixed in cisco/libsrtp in
[commit `837ba9d9`](https://github.com/cisco/libsrtp/commit/837ba9d99aa1163fa1a1d6eef39e1343f1a73d67)
("set dummy tag only when decrypting") by wrapping the `SET_TAG` call in
`if (c->dir == srtp_direction_decrypt)`. This fix was included from libsrtp
v2.6.0 onward. The original `srtp2-sys` crate was never
updated to pick it up.

# The changes

1. Updated the bundled libsrtp submodule from v2.3.0 to v2.8.0 (latest
   stable), which includes the fix along with all other improvements.
2. Added `ac_cv_search_EVP_CIPHER_CTX_reset` to the configure environment in
   `build.rs` (libsrtp v2.8.0 checks for this function, which didn't exist in
   v2.3.0's configure script).
