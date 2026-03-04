/*
 * BearSSL ECDSA signing wrapper
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bearssl.h>
#include "ec_private_key_pem.h"
#include "../../common.h"

/* ---- ECDSA signing using br_ecdsa_i31_sign_asn1 ---- */
static int ecdsa_sign(const unsigned char *hash, int hash_len,
                      unsigned char *sig, int *sig_len)
{
    const br_ec_impl *ec_impl = &br_ec_prime_i31;
    const br_hash_class *hf = &br_sha256_vtable;

    size_t sig_size = br_ecdsa_i31_sign_asn1(ec_impl, hf, hash, &g_ec_key, sig);

    if (sig_size == 0) {
        fprintf(stderr, "ECDSA signing failed\n");
        return 0;
    }

    *sig_len = (int)sig_size;
    return 1;
}

/* ---- Harness entrypoints ---- */

void warmup(const unsigned char *in, int inlen, unsigned char *out)
{
    if (load_ec_priv_from_pem_string(EC_PRIVATE_KEY_PEM) != 0) {
        fprintf(stderr, "Failed to load EC private key\n");
        return;
    }

    decode_ec_bearssl(&g_ec_key);

    int siglen = 256;
    unsigned char dummy[256];
    ecdsa_sign(in, inlen, dummy, &siglen);
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out)
{
    encode_ec_bearssl(&g_ec_key);

    /* printf("EC key curve: %d, key length: %zu bytes\n",
       g_ec_key.curve, g_ec_key.xlen); */

    int siglen = 256;
    if (!ecdsa_sign(in, inlen, out, &siglen)) {
        fprintf(stderr, "ECDSA signing failed\n");
        return -1;
    }

    return siglen;
}

int ecdsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out)
{
    warmup(in, inlen, out);
    int siglen = tester_main(in, inlen, out);
    free_ec_bearssl();
    free_ec_bearssl_heap();
    return siglen;
}
