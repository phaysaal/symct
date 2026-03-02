/*
 * ECDSA signing checking for constant time violation.
 * Here PRIVATE_KEY_PEM key is loaded and secret is injected.
 */
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include "ec_private_key_pem.h"
#include "../../common.h"

EC_KEY *ec_key;

int warmup(const unsigned char *in, int inlen, unsigned char *out) {
  unsigned int outlen;
  BIO *bio = BIO_new_mem_buf(EC_PRIVATE_KEY_PEM, -1);
  if (!bio) return -1;

  ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
  if (!ec_key) {
    BIO_free(bio);
    return -1;
  }

  decode_ec(ec_key);

  // Perform ECDSA signing
  outlen = ECDSA_size(ec_key);
  ECDSA_sign(0, in, inlen, out, &outlen, ec_key);

  BIO_free(bio);
  return 0;
}


int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
  encode_ec(ec_key);
  unsigned int outlen = ECDSA_size(ec_key);
  int result = ECDSA_sign(0, in, inlen, out, &outlen, ec_key);
  return result == 1 ? outlen : -1;
}

int ecdsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
  if (warmup(in, inlen, out) == -1)
    return -1;
  int outlen = tester_main(in, inlen, out);
  EC_KEY_free(ec_key);
  return outlen;
}
