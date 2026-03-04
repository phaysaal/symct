
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

///#include <wolfcrypt/settings.h>
#include <wolfcrypt/rsa.h>
#include <wolfcrypt/asn_public.h>
#include <wolfcrypt/asn.h>
#include <wolfcrypt/error-crypt.h>
#include <wolfcrypt/coding.h>

#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h" /* provides decode_rsa() which we implement for RsaKey */

static RsaKey rsa;         /* wolfSSL RSA key (private) */
static WC_RNG rng;

#define MAX_OUTPUT_LEN 512
#define MAX_DER_SIZE 16384
byte derBuf[MAX_DER_SIZE];
int derSz = 0;

/* Manual PEM to DER conversion for private keys */
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

    /* init rng and rsa structure */
    wc_InitRng(&rng);
    wc_InitRsaKey(&rsa, NULL);

    /* Check format and convert */
    if (XSTRSTR((char*)PRIVATE_KEY_PEM, "BEGIN RSA PRIVATE KEY") != NULL) {
        printf("Format: Traditional RSA PRIVATE KEY\n");
        derSz = convert_pem_to_der((const byte*)PRIVATE_KEY_PEM, (long)PRIVATE_KEY_PEM_len, derBuf, MAX_DER_SIZE,
                                   "-----BEGIN RSA PRIVATE KEY-----",
                                   "-----END RSA PRIVATE KEY-----");
    }
    else if (XSTRSTR((char*)PRIVATE_KEY_PEM, "BEGIN PRIVATE KEY") != NULL) {
        printf("Format: PKCS#8 PRIVATE KEY\n");
        derSz = convert_pem_to_der((const byte*)PRIVATE_KEY_PEM, (long)PRIVATE_KEY_PEM_len, derBuf, MAX_DER_SIZE,
                                   "-----BEGIN PRIVATE KEY-----",
                                   "-----END PRIVATE KEY-----");

        /* For PKCS#8, unwrap to get traditional format */
        if (derSz > 0) {
            word32 inOutIdx = 0;
            ret = wc_GetPkcs8TraditionalOffset(derBuf, &inOutIdx, derSz);
            if (ret >= 0 && inOutIdx < (word32)derSz) {
                printf("Unwrapping PKCS#8...\n");
                int traditionalSz = derSz - inOutIdx;
                XMEMMOVE(derBuf, derBuf + inOutIdx, traditionalSz);
                derSz = traditionalSz;
            }
        }
    }
    else {
        printf("Error: Unknown PEM format\n");
        return -1;
    }

    if (derSz <= 0) {
        printf("Error: PEM to DER conversion failed: %d\n", derSz);
        return derSz;
    }

    printf("DER size: %d bytes\n", derSz);

    /* Decode PKCS#1/PKCS#8 DER into RsaKey */
    {
        word32 idx = 0;
        int ret = wc_RsaPrivateKeyDecode(derBuf, &idx, &rsa, derSz);

        if (ret != 0) {
            fprintf(stderr, "wc_RsaPrivateKeyDecode failed: %d\n", ret);
            goto done;
        }
    }
    printf("Success!!\n");
    /* Fill common arrays (len_n, len_e, len_d, ...) that main_template expects */
    decode_rsa(&rsa);

    ret = wc_RsaSetRNG(&rsa, &rng);
    if (ret != 0) {
      fprintf(stderr, "wc_RsaSetRNG failed: %d\n", ret);
      goto done;
    }

    int outlen = wc_RsaPrivateDecrypt_ex(in, inlen,
                                         out, MAX_OUTPUT_LEN,
                                         &rsa,
                                         WC_RSA_OAEP_PAD,
                                         WC_HASH_TYPE_SHA256,
                                         WC_MGF1SHA256,
                                         NULL, 0);

    if (outlen < 0) {
        fprintf(stderr, "Decryption failed: %d (%s)\n",
                outlen, wc_GetErrorString(outlen));
        return -1;
    }

    printf("   Decrypted length: %d bytes\n\n", outlen);

done:
    return ret;
}

/* Optional helper used by the harness: print/inspect / run one decrypt */
int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    encode_rsa(&rsa);
    printf("Length of the components: n:%u e:%u d:%u p:%d q:%d\n", len_n, len_e, len_d, len_p, len_q);

    int outlen = wc_RsaPrivateDecrypt_ex(in, inlen,
                                         out, MAX_OUTPUT_LEN,
                                         &rsa,
                                         WC_RSA_OAEP_PAD,
                                         WC_HASH_TYPE_SHA256,
                                         WC_MGF1SHA256,
                                         NULL, 0);
    return outlen;
}

/* This is the exact function main_template expects to call */
int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
  int ret;
  warmup(in, inlen, out);
  ret = tester_main(in, inlen, out);

  wc_FreeRsaKey(&rsa);
  wc_FreeRng(&rng);
  free_buf();
  return ret;
}
