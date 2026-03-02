/*
 * EdDSA signing checking for constant time violation.
 * Here ED25519_PRIVATE_KEY_PEM key is loaded and secret is injected.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "ed25519_private_key_pem.h"
#include "../../common.h"

EVP_PKEY *pkey = NULL;


int warmup(const unsigned char *in, int inlen, unsigned char *out) {
    BIO *bio = BIO_new_mem_buf(ED25519_PRIVATE_KEY_PEM, ED25519_PRIVATE_KEY_PEM_LEN);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return -1;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        fprintf(stderr, "Failed to read Ed25519 private key from PEM\n");
        return -1;
    }

    // Verify it's an Ed25519 key
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "Key is not Ed25519\n");
        EVP_PKEY_free(pkey);
        pkey = NULL;
        return -1;
    }

    // decode_eddsa(pkey);

    // Perform one sign operation (warmup)
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t outlen = 64;
    if (!md_ctx) return -1;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    if (EVP_DigestSign(md_ctx, out, &outlen, in, inlen) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
        }
    EVP_MD_CTX_free(md_ctx);

    return 0;
}


int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
  // encode_eddsa(&pkey);

    printf("Ed25519 private key length: %zu bytes\n", len_eddsa_private_key);

    size_t outlen = 64;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return -1;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
       EVP_MD_CTX_free(md_ctx);
       return -1;
     }
    int result = EVP_DigestSign(md_ctx, out, &outlen, in, inlen);
    EVP_MD_CTX_free(md_ctx);

    return result == 1 ? outlen : -1;
}

int eddsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    if (warmup(in, inlen, out) == -1)
        return -1;
    int outlen = tester_main(in, inlen, out);
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (eddsa_private_key) {
        free(eddsa_private_key);
        eddsa_private_key = NULL;
    }
    return outlen;
}
