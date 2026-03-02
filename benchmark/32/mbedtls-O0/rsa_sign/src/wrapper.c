/*
 * RSA signing checking for constant time violation - mbedtls version
 * Following the same pattern as OpenSSL and BearSSL implementations
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/private/rsa.h"
#include "mbedtls/pem.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "../../common.h"

// Use PKCS#1 format key for simpler parsing
#include "../../../private_key_pem_pkcs1.h"

// Include internal header for RSA parsing
#include "rsa_internal.h"

mbedtls_rsa_context rsa;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;
unsigned char hash[32];  // SHA-256 hash

int warmup(const unsigned char *in, int inlen, unsigned char *out) {
    int ret;
    mbedtls_pem_context pem;
    size_t use_len;
    const unsigned char *der_key;
    size_t der_key_len;
    mbedtls_md_context_t md_ctx;

    // Initialize contexts
    mbedtls_rsa_init(&rsa);
    mbedtls_pem_init(&pem);

    // Parse PEM to get DER format (PKCS#1 format)
    ret = mbedtls_pem_read_buffer(&pem,
                                  "-----BEGIN RSA PRIVATE KEY-----",
                                  "-----END RSA PRIVATE KEY-----",
                                  (const unsigned char *)PRIVATE_KEY_PEM_PKCS1,
                                  NULL, 0, &use_len);

    if (ret != 0) {
        printf("Failed to parse PEM: -0x%04x\n", -ret);
        mbedtls_pem_free(&pem);
        return -1;
    }

    // Get the DER data from PEM context
    der_key = mbedtls_pem_get_buffer(&pem, &der_key_len);

    // Parse the DER key directly into RSA context (PKCS#1 DER format)
    ret = mbedtls_rsa_parse_key(&rsa, der_key, der_key_len);
    mbedtls_pem_free(&pem);

    if (ret != 0) {
        printf("Failed to parse RSA key: -0x%04x\n", -ret);
        return -1;
    }

    // Set padding mode for signing
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    // Initialize RNG for signing (needed for blinding)
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    const char *pers = "rsa_sign";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char *)pers, strlen(pers));

    // Decode RSA components to byte arrays
    decode_rsa(&rsa);

    // Hash the input message using SHA-256
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, in, inlen);
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    // Perform first signing (warmup) - sign the hash
    ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                 MBEDTLS_MD_SHA256, 32, hash, out);

    return (ret == 0) ? 0 : -1;
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    // Encode RSA components back from byte arrays
    // This is where symbolic values can be injected for analysis
    encode_rsa(&rsa);

    printf("Length of the components: n:%zu e:%zu d:%zu\n", len_n, len_e, len_d);

    // Perform second signing (actual test) - sign the hash (already computed in warmup)
    int ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                     MBEDTLS_MD_SHA256, 32, hash, out);

    if (ret != 0) {
        return -1;
    }

    // Return the signature length (RSA modulus size)
    return mbedtls_rsa_get_len(&rsa);
}

int rsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    if (warmup(in, inlen, out) == -1)
        return -1;

    int outlen = tester_main(in, inlen, out);

    // Cleanup
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    // Free the byte arrays
    free(rsa_n); free(rsa_e); free(rsa_d);
    free(rsa_p); free(rsa_q);
    free(rsa_dp); free(rsa_dq); free(rsa_qp);

    return outlen;
}
