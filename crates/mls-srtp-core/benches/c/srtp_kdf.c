/*
 * SRTP Key Derivation Function (RFC 3711 §4.3.1)
 *
 * Copy-pasted from libsrtp2's srtp/srtp.c. 
 * The only change is removing `static` from the
 * function signatures so they are callable from Rust via FFI.
 *
 * These functions use libsrtp2's internal cipher abstraction
 * (srtp_cipher_t, srtp_cipher_set_iv, srtp_cipher_encrypt, etc.)
 * which are compiled into the libsrtp2.a static library and linked
 * automatically via the srtp2-sys crate.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "cipher.h"
#include "crypto_kernel.h"
#include "datatypes.h"
#include "err.h"
#include "srtp.h"

/* --- Copy-pasted from srtp.c lines 572-583 --- */

typedef enum {
    label_rtp_encryption = 0x00,
    label_rtp_msg_auth = 0x01,
    label_rtp_salt = 0x02,
    label_rtcp_encryption = 0x03,
    label_rtcp_msg_auth = 0x04,
    label_rtcp_salt = 0x05,
    label_rtp_header_encryption = 0x06,
    label_rtp_header_salt = 0x07
} srtp_prf_label;

/* --- Copy-pasted from srtp.c lines 669-745 (non-OPENSSL_KDF path) ---
 *     Only change: removed `static` from function signatures.          */

/*
 * srtp_kdf_t represents a key derivation function.  The SRTP
 * default KDF is the only one implemented at present.
 */
typedef struct {
    srtp_cipher_t *cipher; /* cipher used for key derivation  */
} srtp_kdf_t;

srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf,
                                const uint8_t *key,
                                int key_len)
{
    srtp_cipher_type_id_t cipher_id;
    srtp_err_status_t stat;

    switch (key_len) {
    case SRTP_AES_ICM_256_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_256;
        break;
    case SRTP_AES_ICM_192_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_192;
        break;
    case SRTP_AES_ICM_128_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_128;
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }

    stat = srtp_crypto_kernel_alloc_cipher(cipher_id, &kdf->cipher, key_len, 0);
    if (stat)
        return stat;

    stat = srtp_cipher_init(kdf->cipher, key);
    if (stat) {
        srtp_cipher_dealloc(kdf->cipher);
        return stat;
    }
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf,
                                    srtp_prf_label label,
                                    uint8_t *key,
                                    unsigned int length)
{
    srtp_err_status_t status;
    v128_t nonce;

    /* set eigth octet of nonce to <label>, set the rest of it to zero */
    v128_set_to_zero(&nonce);
    nonce.v8[7] = label;

    status = srtp_cipher_set_iv(kdf->cipher, (uint8_t *)&nonce,
                                srtp_direction_encrypt);
    if (status)
        return status;

    /* generate keystream output */
    octet_string_set_to_zero(key, length);
    status = srtp_cipher_encrypt(kdf->cipher, key, &length);
    if (status)
        return status;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf)
{
    srtp_err_status_t status;
    status = srtp_cipher_dealloc(kdf->cipher);
    if (status)
        return status;
    kdf->cipher = NULL;
    return srtp_err_status_ok;
}

/* --- End of copy-pasted code --- */

/*
 * One-time initialization: must be called before srtp_kdf_derive().
 * Ensures the libsrtp crypto kernel is ready.
 */
int srtp_kdf_ensure_init(void)
{
    srtp_err_status_t stat = srtp_init();
    if (stat != srtp_err_status_ok && stat != srtp_err_status_bad_param)
        return -1;
    return 0;
}

/*
 * Entry point for the Rust benchmark: runs the full SRTP KDF for
 * AES-128-GCM, matching the sequence in srtp_stream_init_keys().
 *
 * key_material must be 30 bytes: master_key (16) || master_salt (12)
 * || 2 zero-padding bytes (to match SRTP_AES_ICM_128_KEY_LEN_WSALT = 30).
 *
 * Caller must call srtp_kdf_ensure_init() once before the first call.
 */
int srtp_kdf_derive(const uint8_t *key_material, /* 30 bytes in  */
                    uint8_t *rtp_cipher_key,      /* 16 bytes out */
                    uint8_t *rtp_salt,            /* 12 bytes out */
                    uint8_t *rtcp_cipher_key,     /* 16 bytes out */
                    uint8_t *rtcp_salt)           /* 12 bytes out */
{
    srtp_kdf_t kdf;
    srtp_err_status_t stat;

    /* RTP key derivation */
    stat = srtp_kdf_init(&kdf, key_material, SRTP_AES_ICM_128_KEY_LEN_WSALT);
    if (stat) return -1;

    stat = srtp_kdf_generate(&kdf, label_rtp_encryption, rtp_cipher_key, 16);
    if (stat) return -1;

    stat = srtp_kdf_generate(&kdf, label_rtp_salt, rtp_salt, 12);
    if (stat) return -1;

    stat = srtp_kdf_clear(&kdf);
    if (stat) return -1;

    /* RTCP key derivation */
    stat = srtp_kdf_init(&kdf, key_material, SRTP_AES_ICM_128_KEY_LEN_WSALT);
    if (stat) return -1;

    stat = srtp_kdf_generate(&kdf, label_rtcp_encryption, rtcp_cipher_key, 16);
    if (stat) return -1;

    stat = srtp_kdf_generate(&kdf, label_rtcp_salt, rtcp_salt, 12);
    if (stat) return -1;

    stat = srtp_kdf_clear(&kdf);
    if (stat) return -1;

    return 0;
}
