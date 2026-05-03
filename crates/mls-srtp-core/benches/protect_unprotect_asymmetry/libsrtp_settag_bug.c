/*
 * libsrtp_settag_bug.c — Demonstrates the root cause of the SRTP protect-vs-
 * unprotect timing asymmetry.
 *
 * BACKGROUND
 * ==========
 * AES-128-GCM uses AES in CTR mode for both encryption and decryption, so
 * protect (encrypt) and unprotect (decrypt) should have the same throughput.
 * Yet benchmarks consistently show protect is ~120-140 ns slower per packet,
 * independent of payload size (i.e. a fixed per-packet overhead, not per-byte).
 *
 * ROOT CAUSE
 * ==========
 * The bug is in libsrtp's OpenSSL backend (aes_gcm_ossl.c), in the function
 * srtp_aes_gcm_openssl_set_aad().
 * Source: 
 * https://github.com/cisco/libsrtp/blob/3ba20a1bb464f8cdebdd63bbbba821528db0f15b/crypto/cipher/aes_gcm_ossl.c#L266 
 * Before processing AAD, it calls:
 *
 *     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, &dummy_tag);
 *
 * with a zeroed-out dummy tag. The comment says "OpenSSL requires the Tag to
 * be set before processing AAD", but that is only true for DECRYPTION:
 *
 *   - Decryption: The receiver needs to know the expected authentication tag
 *     so it can verify data integrity after decryption. OpenSSL requires this
 *     tag to be provided via SET_TAG before calling EVP_DecryptFinal. libsrtp
 *     sets a dummy here because the real tag hasn't been extracted from the
 *     packet yet at this point.
 *
 *   - Encryption: The sender GENERATES the tag as output (it doesn't receive
 *     one). Calling SET_TAG on an encrypt context is meaningless. OpenSSL's own
 *     documentation states: "For GCM, this call is only valid when decrypting
 *     data." (https://docs.openssl.org/3.0/man3/EVP_EncryptInit/#gcm-and-ocb-modes)
 *
 * When SET_TAG is called on an encrypt context, OpenSSL 3 detects the invalid
 * usage, calls ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG), and returns 0
 * (failure). The check is in ossl_gcm_set_ctx_params():
 * https://github.com/openssl/openssl/blob/2fab90bb5e19/providers/implementations/ciphers/ciphercommon_gcm.c#L266 
 * libsrtp ignores the return value, so encryption still works. But
 * the ERR_raise() call, which pushes an error onto OpenSSL's per-thread error
 * stack, costs ~100-120 ns per invocation. This happens on every single
 * protect call, adding ~120 ns of pure waste.
 *
 * The fix was applied upstream in cisco/libsrtp commit 837ba9d9 ("set dummy tag only when decrypting"). 
 * https://github.com/cisco/libsrtp/commit/837ba9d99aa1163fa1a1d6eef39e1343f1a73d67
 * The bundled libsrtp in the Rust srtp2-sys crate (v3.0.2) is based on libsrtp 2.3.0-pre, 
 * which predates the fix.
 *
 * THIS BENCHMARK
 * ==============
 * This program replicates libsrtp's exact per-packet OpenSSL calling sequence
 * (with a reused EVP_CIPHER_CTX, matching libsrtp's session model) and then
 * isolates the issue step by step:
 *
 *   TEST 1 — Overall: protect vs unprotect per-packet cost (confirms the gap).
 *   TEST 2 — Step breakdown: times each OpenSSL call individually to show
 *            set_aad is the only asymmetric step.
 *   TEST 3 — Isolation: splits set_aad into SET_TAG(dummy) and EVP_Cipher(AAD)
 *            to prove SET_TAG(dummy) alone accounts for the entire difference.
 *
 * Compile:
 *   cc -O2 -o libsrtp_settag_bug libsrtp_settag_bug.c \
 *      -I/opt/homebrew/opt/openssl@3/include \
 *      -L/opt/homebrew/opt/openssl@3/lib -lcrypto
 *
 * Run:
 *   ./libsrtp_settag_bug
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach_time.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY_LEN     16
#define IV_LEN      12
#define TAG_LEN     16
#define AAD_LEN     12   /* RTP header size */
#define ITERS       500000

static uint8_t KEY[KEY_LEN] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
static uint8_t AAD[AAD_LEN] = {0x80,0x6f,0x00,0x01,0x00,0x00,0x03,0xc0,
                                0xde,0xad,0xbe,0xef};

static mach_timebase_info_data_t timebase;

static inline uint64_t now_ns(void) {
    return mach_absolute_time() * timebase.numer / timebase.denom;
}

/*
 * Exact libsrtp PROTECT (encrypt) per-packet OpenSSL call sequence.
 */
static inline void do_protect(EVP_CIPHER_CTX *ctx,
                               const uint8_t *iv,
                               const uint8_t *aad, int aad_len,
                               uint8_t *buf, int buf_len,
                               uint8_t *tag)
{
    uint8_t dummy_tag[TAG_LEN];

    /* set_iv */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, 1);

    /* set_aad, THIS CONTAINS THE BUG: SET_TAG is invalid on encrypt ctx */
    memset(dummy_tag, 0, TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
    EVP_Cipher(ctx, NULL, aad, aad_len);

    /* encrypt */
    EVP_Cipher(ctx, buf, buf, buf_len);

    /* get_tag: finalize + retrieve generated tag */
    EVP_Cipher(ctx, NULL, NULL, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
}

/*
 * Exact libsrtp UNPROTECT (decrypt) per-packet OpenSSL call sequence.
 */
static inline void do_unprotect(EVP_CIPHER_CTX *ctx,
                                 const uint8_t *iv,
                                 const uint8_t *aad, int aad_len,
                                 uint8_t *buf, int buf_len,
                                 const uint8_t *tag)
{
    uint8_t dummy_tag[TAG_LEN];
    uint8_t tag_copy[TAG_LEN];

    /* set_iv */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, 0);

    /* set_aad, SET_TAG is valid here: tells OpenSSL the expected tag length */
    memset(dummy_tag, 0, TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
    EVP_Cipher(ctx, NULL, aad, aad_len);

    /* decrypt: provide the real tag, decrypt data, verify tag */
    memcpy(tag_copy, tag, TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_copy);
    EVP_Cipher(ctx, buf, buf, buf_len);
    EVP_Cipher(ctx, NULL, NULL, 0);
}

int main(void)
{
    mach_timebase_info(&timebase);

    typedef struct { int size; const char *label; } size_entry;
    size_entry sizes[] = {
        {40,   "40B"},
        {160,  "160B"},
        {1424, "1424B"},
        {8924, "8924B"},
    };
    int nsizes = sizeof(sizes)/sizeof(sizes[0]);

    /* measuring timing overhead */
    uint64_t overhead_total = 0;
    for (int i = 0; i < ITERS; i++) {
        uint64_t t0 = now_ns();
        overhead_total += now_ns() - t0;
    }
    double overhead_ns = (double)overhead_total / ITERS;
    fprintf(stderr, "Timing overhead: %.1f ns\n\n", overhead_ns);

    /* ======================================================================
     * SET_TAG on an encrypt context fails in OpenSSL 3.
     *
     * This sanity check confirms the failure. TESTs 1-3 below cover the 
     * investigations that led to this finding.
     * ====================================================================== */
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 1);
        uint8_t dummy[TAG_LEN] = {0};
        int ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy);
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "KEY FINDING: SET_TAG on encrypt ctx returned %d (expected 0 = failure)\n", ret);
        fprintf(stderr, "  OpenSSL error: %s\n", err_buf);
        fprintf(stderr, "  This ERR_raise() call costs ~120 ns and happens on every protect.\n\n");
        ERR_clear_error();
        EVP_CIPHER_CTX_free(ctx);
    }

    /* ======================================================================
     * TEST 1 — Overall protect vs unprotect timing
     *
     * Replicates libsrtp's exact calling pattern with separate sender
     * (encrypt) and receiver (decrypt) contexts, each reused across packets.
     * ====================================================================== */
    fprintf(stderr, "=== TEST 1: overall protect vs unprotect ===\n\n");

    for (int si = 0; si < nsizes; si++) {
        int payload_len = sizes[si].size;
        const char *label = sizes[si].label;

        uint8_t *plaintext  = calloc(1, payload_len);
        uint8_t *ciphertext = calloc(1, payload_len);
        uint8_t *decrypted  = calloc(1, payload_len);
        uint8_t tag[TAG_LEN];
        memset(plaintext, 0xAB, payload_len);

        EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(enc_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);
        EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(dec_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);

        uint8_t iv[IV_LEN] = {0};

        /* warm up */
        memcpy(ciphertext, plaintext, payload_len);
        do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
        memcpy(decrypted, ciphertext, payload_len);
        do_unprotect(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);

        /* benchmarking protect */
        uint64_t total_protect = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            iv[2] = (uint8_t)(((i+1) >> 16) & 0xFF);
            memcpy(ciphertext, plaintext, payload_len);

            uint64_t t0 = now_ns();
            do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
            total_protect += now_ns() - t0;
        }

        /* benchmarking unprotect */
        uint64_t total_unprotect = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            iv[2] = (uint8_t)(((i+1) >> 16) & 0xFF);

            memcpy(ciphertext, plaintext, payload_len);
            do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);

            memcpy(decrypted, ciphertext, payload_len);
            uint64_t t0 = now_ns();
            do_unprotect(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);
            total_unprotect += now_ns() - t0;
        }

        double prot_ns  = (double)total_protect / ITERS - overhead_ns;
        double unprot_ns = (double)total_unprotect / ITERS - overhead_ns;
        fprintf(stderr, "  %6s: protect=%7.1f ns  unprotect=%7.1f ns  diff=%+.1f ns (%+.1f%%)\n",
                label, prot_ns, unprot_ns,
                prot_ns - unprot_ns,
                (prot_ns - unprot_ns) / unprot_ns * 100.0);

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext); free(ciphertext); free(decrypted);
    }

    /* ======================================================================
     * TEST 2 — Per-step breakdown (standard 1424B payload)
     *
     * Times each OpenSSL call in the protect/unprotect sequence individually.
     * This reveals that set_aad is the ONLY step that differs between the
     * two directions.
     * ====================================================================== */
    fprintf(stderr, "\n=== TEST 2: per-step timing breakdown (1424B payload) ===\n\n");
    {
        int payload_len = 1424;
        uint8_t *plaintext  = calloc(1, payload_len);
        uint8_t *ciphertext = calloc(1, payload_len);
        uint8_t *decrypted  = calloc(1, payload_len);
        uint8_t tag[TAG_LEN], dummy_tag[TAG_LEN], tag_copy[TAG_LEN];
        memset(plaintext, 0xAB, payload_len);
        uint8_t iv[IV_LEN] = {0};

        EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(enc_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);
        EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(dec_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);

        /* warm up */
        memcpy(ciphertext, plaintext, payload_len);
        do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
        memcpy(decrypted, ciphertext, payload_len);
        do_unprotect(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);

        uint64_t enc_set_iv = 0, enc_set_aad = 0, enc_encrypt = 0, enc_get_tag = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            memcpy(ciphertext, plaintext, payload_len);
            uint64_t t;

            t = now_ns();
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(enc_ctx, NULL, NULL, NULL, iv, 1);
            enc_set_iv += now_ns() - t;

            memset(dummy_tag, 0, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
            EVP_Cipher(enc_ctx, NULL, AAD, AAD_LEN);
            enc_set_aad += now_ns() - t;

            t = now_ns();
            EVP_Cipher(enc_ctx, ciphertext, ciphertext, payload_len);
            enc_encrypt += now_ns() - t;

            t = now_ns();
            EVP_Cipher(enc_ctx, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
            enc_get_tag += now_ns() - t;
        }

        uint64_t dec_set_iv = 0, dec_set_aad = 0, dec_set_tag = 0,
                 dec_decrypt = 0, dec_verify = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);

            memcpy(ciphertext, plaintext, payload_len);
            do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
            memcpy(decrypted, ciphertext, payload_len);
            uint64_t t;

            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(dec_ctx, NULL, NULL, NULL, iv, 0);
            dec_set_iv += now_ns() - t;

            memset(dummy_tag, 0, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
            EVP_Cipher(dec_ctx, NULL, AAD, AAD_LEN);
            dec_set_aad += now_ns() - t;

            memcpy(tag_copy, tag, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_copy);
            dec_set_tag += now_ns() - t;

            t = now_ns();
            EVP_Cipher(dec_ctx, decrypted, decrypted, payload_len);
            dec_decrypt += now_ns() - t;

            t = now_ns();
            EVP_Cipher(dec_ctx, NULL, NULL, 0);
            dec_verify += now_ns() - t;
        }

        fprintf(stderr, "  ENCRYPT steps (ns/call):\n");
        fprintf(stderr, "    set_iv:     %7.1f\n", (double)enc_set_iv / ITERS - overhead_ns);
        fprintf(stderr, "    set_aad:    %7.1f  <-- the culprit\n", (double)enc_set_aad / ITERS - overhead_ns);
        fprintf(stderr, "    encrypt:    %7.1f\n", (double)enc_encrypt / ITERS - overhead_ns);
        fprintf(stderr, "    get_tag:    %7.1f\n", (double)enc_get_tag / ITERS - overhead_ns);
        double enc_total = (double)(enc_set_iv + enc_set_aad + enc_encrypt + enc_get_tag) / ITERS - 4*overhead_ns;
        fprintf(stderr, "    TOTAL:      %7.1f\n", enc_total);

        fprintf(stderr, "\n  DECRYPT steps (ns/call):\n");
        fprintf(stderr, "    set_iv:     %7.1f\n", (double)dec_set_iv / ITERS - overhead_ns);
        fprintf(stderr, "    set_aad:    %7.1f\n", (double)dec_set_aad / ITERS - overhead_ns);
        fprintf(stderr, "    set_tag:    %7.1f\n", (double)dec_set_tag / ITERS - overhead_ns);
        fprintf(stderr, "    decrypt:    %7.1f\n", (double)dec_decrypt / ITERS - overhead_ns);
        fprintf(stderr, "    verify:     %7.1f\n", (double)dec_verify / ITERS - overhead_ns);
        double dec_total = (double)(dec_set_iv + dec_set_aad + dec_set_tag + dec_decrypt + dec_verify) / ITERS - 5*overhead_ns;
        fprintf(stderr, "    TOTAL:      %7.1f\n", dec_total);
        fprintf(stderr, "\n  DIFF (enc-dec): %+.1f ns\n", enc_total - dec_total);

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext); free(ciphertext); free(decrypted);
    }

    /* ======================================================================
     * TEST 3 — Isolating SET_TAG(dummy) within set_aad
     *
     * The set_aad step consists of two calls:
     *   1. EVP_CIPHER_CTX_ctrl(SET_TAG, dummy)   — set expected tag (length)
     *   2. EVP_Cipher(ctx, NULL, aad, len)       — process the AAD
     *
     * This test times each sub-call separately, proving that SET_TAG(dummy)
     * alone is responsible for the entire asymmetry.
     * ====================================================================== */
    fprintf(stderr, "\n=== TEST 3: isolating SET_TAG(dummy) within set_aad ===\n\n");
    {
        int payload_len = 1424;
        uint8_t *plaintext  = calloc(1, payload_len);
        uint8_t *ciphertext = calloc(1, payload_len);
        uint8_t *decrypted  = calloc(1, payload_len);
        uint8_t tag[TAG_LEN], dummy_tag[TAG_LEN], tag_copy[TAG_LEN];
        memset(plaintext, 0xAB, payload_len);
        uint8_t iv[IV_LEN] = {0};

        EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(enc_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);
        EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(dec_ctx, EVP_aes_128_gcm(), NULL, KEY, NULL, 0);

        /* warm up */
        memcpy(ciphertext, plaintext, payload_len);
        do_protect(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
        memcpy(decrypted, ciphertext, payload_len);
        do_unprotect(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);

        uint64_t enc_settag = 0, enc_aad = 0;
        uint64_t dec_settag = 0, dec_aad = 0;

        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            memcpy(ciphertext, plaintext, payload_len);
            uint64_t t;

            /* ENCRYPT path */
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(enc_ctx, NULL, NULL, NULL, iv, 1);

            memset(dummy_tag, 0, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
            enc_settag += now_ns() - t;

            t = now_ns();
            EVP_Cipher(enc_ctx, NULL, AAD, AAD_LEN);
            enc_aad += now_ns() - t;

            EVP_Cipher(enc_ctx, ciphertext, ciphertext, payload_len);
            EVP_Cipher(enc_ctx, NULL, NULL, 0);
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

            /* DECRYPT path */
            memcpy(decrypted, ciphertext, payload_len);
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(dec_ctx, NULL, NULL, NULL, iv, 0);

            memset(dummy_tag, 0, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
            dec_settag += now_ns() - t;

            t = now_ns();
            EVP_Cipher(dec_ctx, NULL, AAD, AAD_LEN);
            dec_aad += now_ns() - t;

            memcpy(tag_copy, tag, TAG_LEN);
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_copy);
            EVP_Cipher(dec_ctx, decrypted, decrypted, payload_len);
            EVP_Cipher(dec_ctx, NULL, NULL, 0);
        }

        fprintf(stderr, "  SET_TAG(dummy):  enc=%7.1f ns  dec=%7.1f ns  diff=%+.1f ns\n",
                (double)enc_settag/ITERS - overhead_ns,
                (double)dec_settag/ITERS - overhead_ns,
                ((double)enc_settag - (double)dec_settag) / ITERS);
        fprintf(stderr, "  EVP_Cipher(AAD): enc=%7.1f ns  dec=%7.1f ns  diff=%+.1f ns\n",
                (double)enc_aad/ITERS - overhead_ns,
                (double)dec_aad/ITERS - overhead_ns,
                ((double)enc_aad - (double)dec_aad) / ITERS);
        fprintf(stderr, "\n  Conclusion: SET_TAG(dummy) on encrypt ctx costs ~%.0f ns extra\n",
                ((double)enc_settag - (double)dec_settag) / ITERS);
        fprintf(stderr, "  because OpenSSL 3 rejects the call and invokes ERR_raise(),\n");
        fprintf(stderr, "  which pushes an error onto the per-thread error stack.\n");

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext); free(ciphertext); free(decrypted);
    }

    return 0;
}
