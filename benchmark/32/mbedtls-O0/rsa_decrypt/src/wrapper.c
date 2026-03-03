/*
 * RSA decryption checking for constant time violation - mbedtls version
 * Following the same pattern as OpenSSL and BearSSL implementations
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/private/rsa.h"
#include "mbedtls/pem.h"
#include "mbedtls/private/entropy.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/error.h"
#include "../../common.h"

// Use PKCS#1 format key for simpler parsing  mbedtls_mpi_resize_clear
#include "../../../private_key_pem_pkcs1.h"

// Include internal header for RSA parsing
#include "rsa_internal.h"

mbedtls_rsa_context rsa;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

void warmup(const unsigned char *in, int inlen, unsigned char *out) {
    int ret;
    mbedtls_pem_context pem;
    size_t use_len;
    const unsigned char *der_key;
    size_t der_key_len;

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
        return;
    }

    // Get the DER data from PEM context
    der_key = mbedtls_pem_get_buffer(&pem, &der_key_len);

    // Parse the DER key directly into RSA context (PKCS#1 DER format)
    ret = mbedtls_rsa_parse_key(&rsa, der_key, der_key_len);
    mbedtls_pem_free(&pem);

    if (ret != 0) {
        printf("Failed to parse RSA key: -0x%04x\n", -ret);
        return;
    }

    // Set padding mode
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    // Initialize RNG for decryption (needed for blinding)
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    const char *pers = "rsa_decrypt";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char *)pers, strlen(pers));

    // Decode RSA components to byte arrays
    decode_rsa(&rsa);

    // Perform first decryption (warmup)
    size_t olen;
    mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                             &olen, in, out, 512);
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    // Encode RSA components back from byte arrays
    // This is where symbolic values can be injected for analysis
    encode_rsa(&rsa);

    printf("Length of the components: n:%zu e:%zu d:%zu\n", len_n, len_e, len_d);

    // Perform second decryption (actual test)
    size_t olen;
    int ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                       &olen, in, out, 512);

    if (ret != 0) {
        return -1;
    }

    return (int)olen;
}

int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
    warmup(in, inlen, out);
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
