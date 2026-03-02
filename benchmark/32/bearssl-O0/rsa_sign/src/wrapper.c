/*
 * BearSSL RSA signing wrapper (PKCS#1 v1.5)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bearssl.h>
#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h"

/* ---- PKCS#1 v1.5 signing ---- */
static int rsa_sign_pkcs1_v15(const unsigned char *hash, int hash_len,
                              unsigned char *sig, int *sig_len)
{
    size_t modlen = (g_key.n_bitlen + 7) / 8;
    if (*sig_len < (int)modlen)
        return 0;

    /* SHA-256 prefix (change if needed) */
    static const unsigned char der_prefix_sha256[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,
        0x05,0x00,0x04,0x20
    };

    unsigned char em[4096];
    if (modlen > sizeof(em))
        return 0;

    size_t tlen = sizeof(der_prefix_sha256) + hash_len;
    unsigned char *T = malloc(tlen);
    if (!T) return 0;
    memcpy(T, der_prefix_sha256, sizeof(der_prefix_sha256));
    memcpy(T + sizeof(der_prefix_sha256), hash, hash_len);

    /* EMSA-PKCS1-v1_5 encode: 0x00 0x01 PS 0x00 T */
    size_t ps_len = modlen - 3 - tlen;
    em[0] = 0x00;
    em[1] = 0x01;
    memset(em + 2, 0xFF, ps_len);
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len, T, tlen);
    free(T);

    memcpy(sig, em, modlen);
    uint32_t ok = br_rsa_i31_private(sig, &g_key);
    if (!ok)
        return 0;

    *sig_len = (int)modlen;
    return 1;
}

/* ---- Harness entrypoints ---- */

void warmup(const unsigned char *in, int inlen, unsigned char *out)
{
    if (load_priv_from_pem_string(PRIVATE_KEY_PEM) != 0)
        return;

    decode_rsa_bearssl(&g_key);

    int siglen = 1024;
    unsigned char dummy[1024];
    rsa_sign_pkcs1_v15(in, inlen, dummy, &siglen);
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out)
{
    encode_rsa_bearssl(&g_key);

    printf("Length of components: n:%u p:%zu q:%zu\n",
           g_key.n_bitlen, g_key.plen, g_key.qlen);

    int siglen = 1024;
    if (!rsa_sign_pkcs1_v15(in, inlen, out, &siglen)) {
        fprintf(stderr, "RSA signing failed\n");
        return -1;
    }

    return siglen;
}

int rsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out)
{
    warmup(in, inlen, out);
    int siglen = tester_main(in, inlen, out);
    free_rsa_bearssl();
    free_rsa_bearssl_heap();
    return siglen;
}
