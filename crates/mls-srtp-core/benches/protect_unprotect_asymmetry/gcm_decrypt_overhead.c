/*
 * gcm_decrypt_overhead.c — Investigates why AES-128-GCM decryption (unprotect)
 * is ~20-40 ns slower than encryption (protect), which are used in SRTP. 
 *
 * BACKGROUND
 * ==========
 * With the libsrtp SET_TAG bug fixed (v2.8.0), protect no longer wastes ~120 ns
 * on error handling (ERR_raise() call). Now the asymmetry is reversed: unprotect is
 * slower by ~20-40 ns per packet, independent of payload size.
 *
 * This program replicates the OpenSSL calling sequences used by libsrtp
 * v2.8.0 (see srtp/srtp.c, functions srtp_protect_aead and
 * srtp_unprotect_aead) and isolates the extra work that decryption must
 * perform.
 *
 * CALLING SEQUENCES (from libsrtp v2.8.0 srtp/srtp.c)
 * ====================================================
 * PROTECT (encrypt):
 *   1. EVP_CIPHER_CTX_ctrl(SET_IVLEN) + EVP_CipherInit_ex(iv, enc=1) — set IV
 *   2. EVP_Cipher(NULL, aad, aad_len)                                — process AAD
 *   3. EVP_Cipher(buf, buf, len)                                     — encrypt payload
 *   4. EVP_Cipher(NULL, NULL, 0)                                     — finalize
 *   5. EVP_CIPHER_CTX_ctrl(GET_TAG)                                  — retrieve generated tag
 *
 * UNPROTECT (decrypt):
 *   1. EVP_CIPHER_CTX_ctrl(SET_IVLEN) + EVP_CipherInit_ex(iv, enc=0) — set IV
 *   2. EVP_CIPHER_CTX_ctrl(SET_TAG, dummy) + memset                  — tell OpenSSL tag length
 *   3. EVP_Cipher(NULL, aad, aad_len)                                — process AAD
 *   4. EVP_CIPHER_CTX_ctrl(SET_TAG, real_tag) + memcpy               — provide actual tag
 *   5. EVP_Cipher(buf, buf, len)                                     — decrypt payload
 *   6. EVP_Cipher(NULL, NULL, 0)                                     — finalize + verify tag
 *
 * EXTRA WORK IN DECRYPT
 * =====================
 *   + SET_TAG(dummy) + memset(16B)           [step 2, not present in encrypt]
 *   + SET_TAG(real_tag) + memcpy(16B)        [step 4, not present in encrypt]
 *   + constant-time tag verification         [inside step 6's finalize]
 *   - GET_TAG                                [step 5 in encrypt, not in decrypt]
 *
 * Net extra = (SET_TAG_dummy + SET_TAG_real + verify) - GET_TAG
 *
 * FINDINGS
 * ===========
 * The ~20-40 ns decrypt overhead comes almost entirely from two extra
 * OpenSSL API calls (~15 ns each) that the decrypt path requires: one
 * to declare the expected tag length before processing, and another to
 * provide the actual authentication tag for verification. Neither is
 * needed on the encrypt path (which only retrieves the generated tag
 * at the end). The constant-time tag verification itself adds negligible
 * cost.
 *
 * THIS BENCHMARK
 * ==============
 *   TEST 1 — Overall: confirms unprotect > protect by ~20-40 ns.
 *   TEST 2 — Per-step breakdown: identifies which operations cost more.
 *
 * Compile:
 *   cc -O2 -o gcm_decrypt_overhead gcm_decrypt_overhead.c \
 *      -I/opt/homebrew/opt/openssl@3/include \
 *      -L/opt/homebrew/opt/openssl@3/lib -lcrypto
 *
 * Run:
 *   ./gcm_decrypt_overhead
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
#define ITERS       2000000

static uint8_t KEY[KEY_LEN] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
static uint8_t AAD[AAD_LEN] = {0x80,0x6f,0x00,0x01,0x00,0x00,0x03,0xc0,
                                0xde,0xad,0xbe,0xef};

static mach_timebase_info_data_t timebase;

static inline uint64_t now_ns(void) {
    return mach_absolute_time() * timebase.numer / timebase.denom;
}

/*
 * libsrtp v2.8.0 protect (encrypt) per-packet sequence.
 */
static inline void do_protect_fixed(EVP_CIPHER_CTX *ctx,
                                     const uint8_t *iv,
                                     const uint8_t *aad, int aad_len,
                                     uint8_t *buf, int buf_len,
                                     uint8_t *tag)
{
    /* set_iv */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, 1);

    /* set_aad: just process the AAD, no SET_TAG on encrypt */
    EVP_Cipher(ctx, NULL, aad, aad_len);

    /* encrypt */
    EVP_Cipher(ctx, buf, buf, buf_len);

    /* get_tag: finalize + retrieve generated tag */
    EVP_Cipher(ctx, NULL, NULL, 0);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
}

/*
 * libsrtp v2.8.0 unprotect (decrypt) per-packet sequence.
 */
static inline void do_unprotect_fixed(EVP_CIPHER_CTX *ctx,
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

    /* OpenSSL requires the expected tag length to be configured before
     * processing any data in decrypt mode. In libsrtp, the real tag
     * hasn't been parsed from the packet yet at this point, so this
     * first SET_TAG call just communicates the length (16 bytes); the
     * buffer content is irrelevant (hence "dummy"). The real tag is
     * provided via a second SET_TAG call after AAD processing. */
    memset(dummy_tag, 0, TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
    EVP_Cipher(ctx, NULL, aad, aad_len);

    /* decrypt: provide real tag, then decrypt, then verify */
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
        {16,    "16B"},
        {160,   "160B"},
        {1424,  "1424B"},
        {8924,  "8924B"},
    };
    int nsizes = sizeof(sizes)/sizeof(sizes[0]);

    /* Measure the cost of calling now_ns() itself (back-to-back with no
     * work in between), so we can subtract it from each timed section. */
    uint64_t overhead_total = 0;
    for (int i = 0; i < ITERS; i++) {
        uint64_t t0 = now_ns();
        overhead_total += now_ns() - t0;
    }
    double overhead_ns = (double)overhead_total / ITERS;
    fprintf(stderr, "Timing overhead: %.1f ns\n\n", overhead_ns);

    /* ======================================================================
     * TEST 1 — Overall protect vs unprotect
     *
     * Confirms that unprotect is slower than protect.
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
        do_protect_fixed(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
        memcpy(decrypted, ciphertext, payload_len);
        do_unprotect_fixed(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);

        /* benchmarking protect */
        uint64_t total_protect = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            iv[2] = (uint8_t)(((i+1) >> 16) & 0xFF);
            memcpy(ciphertext, plaintext, payload_len);

            uint64_t t0 = now_ns();
            do_protect_fixed(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
            total_protect += now_ns() - t0;
        }

        /* benchmarking unprotect */
        uint64_t total_unprotect = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            iv[2] = (uint8_t)(((i+1) >> 16) & 0xFF);

            memcpy(ciphertext, plaintext, payload_len);
            do_protect_fixed(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);

            memcpy(decrypted, ciphertext, payload_len);
            uint64_t t0 = now_ns();
            do_unprotect_fixed(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);
            total_unprotect += now_ns() - t0;
        }

        /* average ns per encrypt/decrypt call, with timer overhead subtracted */
        double prot_ns  = (double)total_protect / ITERS - overhead_ns;
        double unprot_ns = (double)total_unprotect / ITERS - overhead_ns;

        /* printing comparison: positive diff = decrypt slower */
        fprintf(stderr, "  %6s: protect=%7.1f ns  unprotect=%7.1f ns  diff=%+.1f ns\n",
                label, prot_ns, unprot_ns, unprot_ns - prot_ns);

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext); free(ciphertext); free(decrypted);
    }

    /* ======================================================================
     * TEST 2 — Per-step breakdown (1424B payload)
     *
     * Times each operation in both directions to identify which steps differ.
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
        do_protect_fixed(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
        memcpy(decrypted, ciphertext, payload_len);
        do_unprotect_fixed(dec_ctx, iv, AAD, AAD_LEN, decrypted, payload_len, tag);

        /* --- ENCRYPT per-step --- */
        uint64_t enc_set_iv = 0, enc_aad = 0, enc_encrypt = 0,
                 enc_finalize = 0, enc_get_tag = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);
            memcpy(ciphertext, plaintext, payload_len);
            uint64_t t;

            /* step 1: set IV */
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(enc_ctx, NULL, NULL, NULL, iv, 1);
            enc_set_iv += now_ns() - t;

            /* step 2: process AAD */
            t = now_ns();
            EVP_Cipher(enc_ctx, NULL, AAD, AAD_LEN);
            enc_aad += now_ns() - t;

            /* step 3: encrypt payload */
            t = now_ns();
            EVP_Cipher(enc_ctx, ciphertext, ciphertext, payload_len);
            enc_encrypt += now_ns() - t;

            /* step 4: finalize */
            t = now_ns();
            EVP_Cipher(enc_ctx, NULL, NULL, 0);
            enc_finalize += now_ns() - t;

            /* step 5: get tag */
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
            enc_get_tag += now_ns() - t;
        }

        /* --- DECRYPT per-step --- */
        uint64_t dec_set_iv = 0, dec_set_tag_dummy = 0, dec_aad = 0,
                 dec_set_tag_real = 0, dec_decrypt = 0, dec_verify = 0;
        for (int i = 0; i < ITERS; i++) {
            iv[0] = (uint8_t)((i+1) & 0xFF);
            iv[1] = (uint8_t)(((i+1) >> 8) & 0xFF);

            /* prepare valid ciphertext */
            memcpy(ciphertext, plaintext, payload_len);
            do_protect_fixed(enc_ctx, iv, AAD, AAD_LEN, ciphertext, payload_len, tag);
            memcpy(decrypted, ciphertext, payload_len);
            uint64_t t;

            /* step 1: set IV */
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
            EVP_CipherInit_ex(dec_ctx, NULL, NULL, NULL, iv, 0);
            dec_set_iv += now_ns() - t;

            /* step 2: SET_TAG(dummy), required before AAD on decrypt */
            memset(dummy_tag, 0, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, dummy_tag);
            dec_set_tag_dummy += now_ns() - t;

            /* step 3: process AAD */
            t = now_ns();
            EVP_Cipher(dec_ctx, NULL, AAD, AAD_LEN);
            dec_aad += now_ns() - t;

            /* step 4: SET_TAG(real), providing actual tag for verification */
            memcpy(tag_copy, tag, TAG_LEN);
            t = now_ns();
            EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_copy);
            dec_set_tag_real += now_ns() - t;

            /* step 5: decrypt payload */
            t = now_ns();
            EVP_Cipher(dec_ctx, decrypted, decrypted, payload_len);
            dec_decrypt += now_ns() - t;

            /* step 6: finalize + verify tag */
            t = now_ns();
            EVP_Cipher(dec_ctx, NULL, NULL, 0);
            dec_verify += now_ns() - t;
        }

        /* printing average ns per step for each encrypt call (5 steps) */
        fprintf(stderr, "  ENCRYPT steps (ns/call):\n");
        fprintf(stderr, "    set_iv:        %7.1f\n", (double)enc_set_iv / ITERS - overhead_ns);
        fprintf(stderr, "    aad:           %7.1f\n", (double)enc_aad / ITERS - overhead_ns);
        fprintf(stderr, "    encrypt:       %7.1f\n", (double)enc_encrypt / ITERS - overhead_ns);
        fprintf(stderr, "    finalize:      %7.1f\n", (double)enc_finalize / ITERS - overhead_ns);
        fprintf(stderr, "    get_tag:       %7.1f\n", (double)enc_get_tag / ITERS - overhead_ns);

        /* subtracting 5x overhead because each of the 5 steps has its own timer pair */
        double enc_total = (double)(enc_set_iv + enc_aad + enc_encrypt + enc_finalize + enc_get_tag) / ITERS - 5*overhead_ns;
        fprintf(stderr, "    TOTAL:         %7.1f\n", enc_total);

        /* printing average ns per step for each decrypt call (6 steps).
         * Steps marked "<-- extra" are not present in the encrypt path. */
        fprintf(stderr, "\n  DECRYPT steps (ns/call):\n");
        fprintf(stderr, "    set_iv:        %7.1f\n", (double)dec_set_iv / ITERS - overhead_ns);
        fprintf(stderr, "    set_tag_dummy: %7.1f  <-- extra (not in encrypt)\n", (double)dec_set_tag_dummy / ITERS - overhead_ns);
        fprintf(stderr, "    aad:           %7.1f\n", (double)dec_aad / ITERS - overhead_ns);
        fprintf(stderr, "    set_tag_real:  %7.1f  <-- extra (not in encrypt)\n", (double)dec_set_tag_real / ITERS - overhead_ns);
        fprintf(stderr, "    decrypt:       %7.1f\n", (double)dec_decrypt / ITERS - overhead_ns);
        fprintf(stderr, "    verify:        %7.1f  <-- same as encrypt's finalize, but also checks tag\n", (double)dec_verify / ITERS - overhead_ns);
        /* Subtract 6x overhead because each of the 6 steps has its own timer pair */
        double dec_total = (double)(dec_set_iv + dec_set_tag_dummy + dec_aad + dec_set_tag_real + dec_decrypt + dec_verify) / ITERS - 6*overhead_ns;
        fprintf(stderr, "    TOTAL:         %7.1f\n", dec_total);
        fprintf(stderr, "\n  DIFF (unprotect - protect): %+.1f ns\n", dec_total - enc_total);

        /* Taking apart the difference:
         *   - set_tag_dummy/real: extra API calls only in decrypt
         *   - verify vs finalize: tag comparison cost in decrypt's finalize
         *   - minus get_tag: encrypt-only step that partially offsets the gap */
        double extra_set_tag_dummy = (double)dec_set_tag_dummy / ITERS - overhead_ns;
        double extra_set_tag_real = (double)dec_set_tag_real / ITERS - overhead_ns;
        double enc_finalize_ns = (double)enc_finalize / ITERS - overhead_ns;
        double dec_verify_ns = (double)dec_verify / ITERS - overhead_ns;
        double enc_get_tag_ns = (double)enc_get_tag / ITERS - overhead_ns;
        double verify_overhead = dec_verify_ns - enc_finalize_ns;

        fprintf(stderr, "\n  --- Sources of extra decrypt cost ---\n");
        fprintf(stderr, "    SET_TAG(dummy):                    %+.1f ns\n", extra_set_tag_dummy);
        fprintf(stderr, "    SET_TAG(real_tag):                 %+.1f ns\n", extra_set_tag_real);
        fprintf(stderr, "    verify vs finalize (tag check):    %+.1f ns\n", verify_overhead);
        fprintf(stderr, "    minus GET_TAG (encrypt-only):      -%.1f ns\n", enc_get_tag_ns);
        fprintf(stderr, "    -----------------------------------------\n");
        fprintf(stderr, "    Net extra:                         %+.1f ns\n",
                extra_set_tag_dummy + extra_set_tag_real + verify_overhead - enc_get_tag_ns);

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext); free(ciphertext); free(decrypted);
    }

    return 0;
}
