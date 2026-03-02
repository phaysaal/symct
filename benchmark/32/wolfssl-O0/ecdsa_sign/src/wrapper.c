/*
 * wolfSSL ECDSA signing wrapper for constant-time verification
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

#include <wolfcrypt/ecc.h>
#include <wolfcrypt/asn_public.h>
#include <wolfcrypt/asn.h>
#include <wolfcrypt/error-crypt.h>
#include <wolfcrypt/coding.h>
#include <wolfcrypt/sha256.h>

#include "ec_private_key_pem.h"
#include "../../common.h"

static ecc_key ecc;        /* wolfSSL ECC key */
static WC_RNG rng_global;

#define MAX_OUTPUT_LEN 512
#define MAX_DER_SIZE 16384
byte derBuf[MAX_DER_SIZE];
int derSz = 0;
wc_Sha256 sha;
byte hash[WC_SHA256_DIGEST_SIZE];
byte signature[256];

/* Manual PEM to DER conversion for EC private keys */
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
    word32 outlen = MAX_OUTPUT_LEN;

    /* Convert PEM to DER */
    derSz = convert_pem_to_der((const byte*)EC_PRIVATE_KEY_PEM, EC_PRIVATE_KEY_PEM_LEN,
                               derBuf, MAX_DER_SIZE,
                               "-----BEGIN EC PRIVATE KEY-----",
                               "-----END EC PRIVATE KEY-----");

    if (derSz <= 0) {
        fprintf(stderr, "PEM to DER conversion failed: %d\n", derSz);
        return -1;
    }

    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_init failed: %d\n", ret);
        return -1;
    }

    /* Decode EC private key from DER */
    ret = wc_EccPrivateKeyDecode(derBuf, &idx, &ecc, derSz);
    if (ret != 0) {
        fprintf(stderr, "wc_EccPrivateKeyDecode failed: %d (%s)\n",
                ret, wc_GetErrorString(ret));
        wc_ecc_free(&ecc);
        return -1;
    }

    /* Initialize RNG */
    ret = wc_InitRng(&rng_global);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        wc_ecc_free(&ecc);
        return -1;
    }

    /* Decode ECC key to extract private key */
    decode_ecc(&ecc);

    /* Hash the input */
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        fprintf(stderr, "wc_InitSha256 failed: %d\n", ret);
        wc_FreeRng(&rng_global);
        wc_ecc_free(&ecc);
        return -1;
    }

    ret = wc_Sha256Update(&sha, in, inlen);
    if (ret != 0) {
        fprintf(stderr, "wc_Sha256Update failed: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRng(&rng_global);
        wc_ecc_free(&ecc);
        return -1;
    }

    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0) {
        fprintf(stderr, "wc_Sha256Final failed: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRng(&rng_global);
        wc_ecc_free(&ecc);
        return -1;
    }

    /* First signing (warmup) */
    ret = wc_ecc_sign_hash(hash, WC_SHA256_DIGEST_SIZE, signature, &outlen, &rng_global, &ecc);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_sign_hash warmup failed: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRng(&rng_global);
        wc_ecc_free(&ecc);
        return -1;
    }

    return 0;
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    int ret = 0;
    word32 outlen = MAX_OUTPUT_LEN;

    /* Encode ECC key from buffers (simulate secret injection) sp_bitsused */
    encode_ecc(&ecc);

    printf("ECC key type: %d, key size: %d bits\n", ecc.type, ecc.dp->size * 8);

    /* Second signing (actual test) */
    ret = wc_ecc_sign_hash(hash, WC_SHA256_DIGEST_SIZE, out, &outlen, &rng_global, &ecc);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_sign_hash failed: %d\n", ret);
        return -1;
    }

    return (int)outlen;
}

int ecdsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    int result = warmup(in, inlen, out);
    if (result == -1)
        return -1;

    int outlen = tester_main(in, inlen, out);

    /* Cleanup */
    wc_Sha256Free(&sha);
    wc_FreeRng(&rng_global);
    wc_ecc_free(&ecc);
    free_ecc_buf();

    return outlen;
}
