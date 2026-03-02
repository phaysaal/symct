
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

#include <wolfcrypt/rsa.h>
#include <wolfcrypt/asn_public.h>
#include <wolfcrypt/asn.h>
#include <wolfcrypt/error-crypt.h>
#include <wolfcrypt/coding.h>

#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h"

static RsaKey rsa;         /* wolfSSL RSA key (private) */
static WC_RNG rng_global;

#define MAX_OUTPUT_LEN 512
#define MAX_DER_SIZE 16384
byte derBuf[MAX_DER_SIZE];
int derSz = 0;
wc_Sha256 sha;
byte hash[WC_SHA256_DIGEST_SIZE];
byte signature[256];

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
    word32 idx = 0;
    
    /* Check format and convert */
    if (XSTRSTR((char*)PRIVATE_KEY_PEM, "BEGIN RSA PRIVATE KEY") != NULL) {
        derSz = convert_pem_to_der((const byte*)PRIVATE_KEY_PEM, (long)PRIVATE_KEY_PEM_len, derBuf, MAX_DER_SIZE,
                                   "-----BEGIN RSA PRIVATE KEY-----",
                                   "-----END RSA PRIVATE KEY-----");
    }
    else if (XSTRSTR((char*)PRIVATE_KEY_PEM, "BEGIN PRIVATE KEY") != NULL) {
      //printf("Format: PKCS#8 PRIVATE KEY\n");
        derSz = convert_pem_to_der((const byte*)PRIVATE_KEY_PEM, (long)PRIVATE_KEY_PEM_len, derBuf, MAX_DER_SIZE,
                                   "-----BEGIN PRIVATE KEY-----",
                                   "-----END PRIVATE KEY-----");
        
        /* For PKCS#8, unwrap to get traditional format */
        if (derSz > 0) {
            word32 inOutIdx = 0;
            ret = wc_GetPkcs8TraditionalOffset(derBuf, &inOutIdx, derSz);
            if (ret >= 0 && inOutIdx < (word32)derSz) {
                int traditionalSz = derSz - inOutIdx;
                XMEMMOVE(derBuf, derBuf + inOutIdx, traditionalSz);
                derSz = traditionalSz;
            }
        }
    }
    else {
        return -1;
    }

    if (derSz <= 0) {
        return derSz;
    }
    
    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRsaKey failed: %d\n", ret);
        return -1;
    }
    ret = wc_RsaPrivateKeyDecode(derBuf, &idx, &rsa, derSz);
    if (ret != 0) {
        fprintf(stderr, "wc_RsaPrivateKeyDecode failed: %d (%s)\n", 
                ret, wc_GetErrorString(ret));
        wc_FreeRsaKey(&rsa);
        return -1;
    }

    ret = wc_InitRng(&rng_global);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        wc_FreeRsaKey(&rsa);
        return -1;
    }
    /* Set RNG for RSA key (enables blinding) */
    ret = wc_RsaSetRNG(&rsa, &rng_global);
    if (ret != 0) {
        fprintf(stderr, "wc_RsaSetRNG failed: %d\n", ret);
        wc_FreeRng(&rng_global);
        wc_FreeRsaKey(&rsa);
        return -1;
    }
    decode_rsa(&rsa);


    int sigLen = wc_RsaSSL_Sign(in, inlen, out, wc_RsaEncryptSize(&rsa), 
                            &rsa, &rng_global);
    
    if (sigLen < 0) {
      fprintf(stderr, "Decryption failed: %d (%s)\n", 
                sigLen, wc_GetErrorString(sigLen));
      return -1;
    }
    
    //printf("   ✓ Decrypted: %s\n", out);
    //printf("   Decrypted length: %d bytes\n\n", outlen);
    
    return ret;
}

/* Optional helper used by the harness: print/inspect / run one decrypt */
int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    encode_rsa(&rsa);
    
    /* Sign - BINSEC will analyze this for CT violations */
    int sigLen = wc_RsaSSL_Sign(in, inlen, out, wc_RsaEncryptSize(&rsa), 
                            &rsa, &rng_global);
    
    return sigLen;
}

/* This is the exact function main_template expects to call */
int rsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
  int ret;
  if(warmup(in, inlen, out) == -1)
    return -1;
  ret = tester_main(in, inlen, out);
  
  wc_FreeRsaKey(&rsa);
  wc_FreeRng(&rng_global);
  free_buf();
  return ret;
}
