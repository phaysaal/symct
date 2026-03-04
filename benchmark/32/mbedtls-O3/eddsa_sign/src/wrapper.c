#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"

unsigned char exported_key[128]; // For EdDSA keys
size_t exported_key_len = 0;

void warmup(void) {
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) return;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attributes, 255); // Ed25519 uses 255 bits

    status = psa_generate_key(&attributes, &key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "warmup: psa_generate_key failed: %d\n", status);
        goto cleanup;
    }

    status = psa_export_key(key_id, exported_key, sizeof(exported_key), &exported_key_len);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "warmup: psa_export_key failed: %d\n", status);
    }

cleanup:
    psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = 0;
    size_t sig_len = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "tester_main: psa_crypto_init failed: %d\n", status);
        return -1;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));

    status = psa_import_key(&attributes, exported_key, exported_key_len, &key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "tester_main: psa_import_key failed: %d\n", status);
        goto cleanup;
    }

    status = psa_sign_message(key_id, PSA_ALG_PURE_EDDSA,
                              in, inlen, out, 512, &sig_len);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "tester_main: psa_sign_message failed: %d\n", status);
        goto cleanup;
    }

cleanup:
    psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return sig_len;
}

#ifdef EXAMPLE_EDDSA_SIGN
int eddsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    warmup();
    return tester_main(in, inlen, out);
}
#endif