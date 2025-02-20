/*
 *  Example ECDSA program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_ECDSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>
#endif

//#define N_SIGNS 6
//#define CONSOLE_OUTPUT
/*
 * Uncomment to show key and signature details
 */
#define VERBOSE
//#define COMPLETE_OUTPUT

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1
#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY

#if !defined(ECPARAMS)
#define ECPARAMS mbedtls_ecp_curve_list()->grp_id
#endif

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    mbedtls_exit(0);
}
#else
#if defined(VERBOSE)
static void dump_buf(const char *title, unsigned char *buf, size_t len, FILE *output)
{
    size_t i;

#if defined(CONSOLE_OUTPUT)
        mbedtls_printf("%s", title);
#endif
    for (i = 0; i < len; i++)
    {
#if defined(CONSOLE_OUTPUT)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
                        "0123456789ABCDEF"[buf[i] % 16]);
#endif
        printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
                       "0123456789ABCDEF"[buf[i] % 16]);
    }
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf("\n");
#endif
    printf(" ");
}

static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key, FILE *output)
{
    unsigned char buf[300];
    size_t len;

    if (mbedtls_ecp_write_public_key(key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &len, buf, sizeof(buf)) != 0)
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf(title, buf, len, output);
}
#else
#define dump_buf(a, b, c)
#define dump_pubkey(a, b)
#endif

int mbedtls_ctr_drbg_nonrandom(void *p_rng,
                               unsigned char *output, size_t output_len)
{
    int p = 2;
    memset(output, output_len-1, 0);
    output[output_len-1] = p;
    return 0;
}

int main(int argc, char *argv[])
{
#if defined(CONSOLE_OUTPUT)
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    printf("\nDETERMINISTIC ECDSA\n");
#else
    printf("\nNON DETERMINISTIC ECDSA\n");
#endif
#endif
    char *p;
    int num;

    long conv = strtol(argv[1], &p, 10);
    if (*p != '\0' || conv > INT_MAX || conv < INT_MIN) {
        num = 4;
    } else {
        num = conv;
    }
    #define N_SIGNS num

    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg, ctr_drbg2;
    unsigned char messages[N_SIGNS][2];
    unsigned char hash[N_SIGNS][32];
    unsigned char signs[N_SIGNS][MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len[N_SIGNS];
    const char *pers = "ecdsa";
    ((void)argv);
    FILE *output;
    output = fopen("../signatures/mock.txt", "w");

    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    for (int i = 0; i < N_SIGNS; i++)
    {
        memset(signs[i], 0, sizeof(signs[i]));
        snprintf(messages[i], sizeof(messages[i]), "%d", i);
        
        // Print the message
#if defined(COMPLETE_OUTPUT)
        printf("%s ", messages[i]);
#endif
        //memset(messages[i], i + '0', sizeof(messages[i])-1);
        //messages[i][99] = '\0';
        //printf("Message: %s\n", messages[i]);
        //dump_buf("  + Hash: ", messages[i], sizeof(messages[i]), output);
    }
#if defined(COMPLETE_OUTPUT)
    printf("\n");
#endif

    if (argc != 2)
    {
        mbedtls_printf("usage: ecdsa\n");
#if defined(_WIN32)
        mbedtls_printf("\n");
#endif
        goto exit;
    }

    /*
     * Generate a key pair for signing
     */
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);
#endif

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf(" ok\n  . Generating key pair...");
    fflush(stdout);
#endif

    if ((ret = mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,
                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
        goto exit;
    }

    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_grp_id(grp_id);
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf(" ok (key size: %d bits)\n", (int)curve_info->bit_size);
#endif

    dump_pubkey("  + Public key: ", &ctx_sign, output);
    printf("\n");
    /*
     * Compute message hash
     */
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf("  . Computing message hash...\n");
    fflush(stdout);
#endif

    for (int i = 0; i < N_SIGNS; i++)
    {
        //dump_buf("  + Hash: ", messages[i], sizeof(messages[i]), output);
        if ((ret = mbedtls_sha256(messages[i], sizeof(char), hash[i], 0)) != 0)
        {
            mbedtls_printf(" failed\n  ! mbedtls_sha256 returned %d\n", ret);
            goto exit;
        }
        else
        {
#if defined(COMPLETE_OUTPUT)
            //printf("  + Message: %s\n", messages[i]);
            dump_buf("  + Hash: ", hash[i], sizeof(hash[i]), output);
#endif
        }
        //printf("\nHash: %s\n", hash[i]);
    }
#if defined(COMPLETE_OUTPUT)
    printf("\n");
#endif
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf(" ok\n");
#endif
    /*
     * Sign message hash
     */

    for (int i = 0; i < N_SIGNS; i++)
    {
        //mbedtls_printf("  . Signing message %i hash...", i);
        //fflush(stdout);
        if ((ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256,
                                                 hash[i], sizeof(hash[i]),
                                                 signs[i], sizeof(signs[i]), &sig_len[i],
                                                 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret);
            goto exit;
        }
        //mbedtls_printf(" ok (signature length = %u)\n", (unsigned int)sig_len[i]);

        dump_buf("", signs[i], sig_len[i], output);
        //fprintf(output, signs[i]);
    }

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf("  . Preparing verification context...");
    fflush(stdout);
#endif

    if ((ret = mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_export returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_set_public_key returned %d\n", ret);
        goto exit;
    }

    /*
     * Verify signature
     */
#if defined(CONSOLE_OUTPUT)
    mbedtls_printf(" ok\n");
    fflush(stdout);
#endif

    for (int i = 0; i < N_SIGNS; i++)
    {
#if defined(CONSOLE_OUTPUT)
        mbedtls_printf("  . Verifying signature %i...", i);
#endif
        fflush(stdout);
        if ((ret = mbedtls_ecdsa_read_signature(&ctx_verify,
                                                hash[i], sizeof(hash[i]),
                                                signs[i], sig_len[i])) != 0)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret);
            goto exit;
        }
#if defined(CONSOLE_OUTPUT)
        mbedtls_printf(" ok\n");
        fflush(stdout);
#endif
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}
#endif
