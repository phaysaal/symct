/*
 * RSA OAEP decryption checking for constant time violation.
 * Here PRIVATE_KEY_PEM key is loaded in the middle and secret is injected.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h"

RSA *rsa;
BIO *bio;
void warmup(const unsigned char *in, int inlen, unsigned char *out) {

  bio = BIO_new_mem_buf(PRIVATE_KEY_PEM, PRIVATE_KEY_PEM_LEN);
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

  decode_rsa(rsa);

  RSA_private_decrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
  BIO_free(bio);
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
  encode_rsa(rsa);
  printf("Length of the components: n:%d e:%d d:%d\n", len_n, len_e, len_d);

  int outlen = RSA_private_decrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);

  return outlen;
}

int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
  warmup(in, inlen, out);
  int outlen = tester_main(in, inlen, out);
  RSA_free(rsa);
  return outlen;
}
