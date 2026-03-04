/*
 * wolfSSL EdDSA signing wrapper for constant-time verification
 */

#ifndef FIPS_VERSION3_GE
#define FIPS_VERSION3_GE(maj, min, patch) 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif

#include <wolfcrypt/ed25519.h>
#include <wolfcrypt/asn_public.h>
#include <wolfcrypt/asn.h>
#include <wolfcrypt/error-crypt.h>
#include <wolfcrypt/coding.h>

#include "ed25519_private_key_pem.h"
#include "../../common.h"

static ed25519_key ed_key;  /* wolfSSL Ed25519 key */
static WC_RNG rng_global;

#define MAX_OUTPUT_LEN 512
#define MAX_DER_SIZE 16384
byte derBuf[MAX_DER_SIZE];
int derSz = 0;
byte signature[ED25519_SIG_SIZE];

/* Manual PEM to DER conversion for Ed25519 private keys */
static int convert_pem_to_der(const byte* pem, int pemSz, byte* der,
                              unsigned int derSz, const char* header, const char* footer)
{
    const char* headerEnd;
    const char* footerStart;
    int base64Sz;
    int ret;

    /* Find header */
    headerEnd = XSTRSTR((const char*)pem, header);
    if (headerEnd == NULL) {
        return -1;
    }
    headerEnd += XSTRLEN(header);

    /* Skip to end of line */
    while (*headerEnd == '\r' || *headerEnd == '\n') {
        headerEnd++;
    }

    /* Find footer */
    footerStart = XSTRSTR(headerEnd, footer);
    if (footerStart == NULL) {
        return -1;
    }

    /* Calculate base64 size */
    base64Sz = (int)(footerStart - headerEnd);

    /* Decode base64 */
    ret = Base64_Decode((const byte*)headerEnd, base64Sz, der, &derSz);
    if (ret != 0) {
        return ret;
    }

    return derSz;
}


int warmup(const unsigned char *in, int inlen, unsigned char *out) {
    int ret = 0;
    word32 idx = 0;
    word32 outlen = ED25519_SIG_SIZE;

    /* Convert PEM to DER */
    derSz = convert_pem_to_der((const byte*)ED25519_PRIVATE_KEY_PEM, ED25519_PRIVATE_KEY_PEM_LEN,
                               derBuf, MAX_DER_SIZE,
                               "-----BEGIN PRIVATE KEY-----",
                               "-----END PRIVATE KEY-----");

    if (derSz <= 0) {
        fprintf(stderr, "PEM to DER conversion failed: %d\n", derSz);
        return -1;
    }

    /* Initialize Ed25519 key */
    ret = wc_ed25519_init(&ed_key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_init failed: %d\n", ret);
        return -1;
    }

    /* Decode Ed25519 private key from DER (PKCS#8 format) */
    ret = wc_Ed25519PrivateKeyDecode(derBuf, &idx, &ed_key, derSz);
    if (ret != 0) {
        fprintf(stderr, "wc_Ed25519PrivateKeyDecode failed: %d (%s)\n",
                ret, wc_GetErrorString(ret));
        wc_ed25519_free(&ed_key);
        return -1;
    }

    /* Generate public key from private key if not already set */
    if (ed_key.pubKeySet == 0) {
        unsigned char pubKey[ED25519_PUB_KEY_SIZE];
        ret = wc_ed25519_make_public(&ed_key, pubKey, sizeof(pubKey));
        if (ret != 0) {
            fprintf(stderr, "wc_ed25519_make_public failed: %d\n", ret);
            wc_ed25519_free(&ed_key);
            return -1;
        }
    }

    /* Initialize RNG (Ed25519 signing is deterministic, but wolfSSL may need it) */
    ret = wc_InitRng(&rng_global);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        wc_ed25519_free(&ed_key);
        return -1;
    }

    /* Decode Ed25519 key to extract private key */
    decode_eddsa(&ed_key);

    /* First signing (warmup) - Ed25519 signs messages directly, no hashing needed */
    ret = wc_ed25519_sign_msg(in, inlen, signature, &outlen, &ed_key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_sign_msg warmup failed: %d\n", ret);
        wc_FreeRng(&rng_global);
        wc_ed25519_free(&ed_key);
        return -1;
    }

    return 0;
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    int ret = 0;
    word32 outlen = ED25519_SIG_SIZE;

    /* Encode Ed25519 key from buffers (simulate secret injection) */
    encode_eddsa(&ed_key);

    printf("Ed25519 private key length: %u bytes\n", len_eddsa_private_key);

    /* Second signing (actual test) */
    ret = wc_ed25519_sign_msg(in, inlen, out, &outlen, &ed_key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_sign_msg failed: %d\n", ret);
        return -1;
    }

    return (int)outlen;
}

int eddsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    int result = warmup(in, inlen, out);
    if (result == -1)
        return -1;

    int outlen = tester_main(in, inlen, out);

    /* Cleanup */
    wc_FreeRng(&rng_global);
    wc_ed25519_free(&ed_key);
    free_eddsa_buf();

    return outlen;
}
