#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <string.h>
#include "private_key_pem.h"
#include "../../common.h"

RSA *rsa;

int warmup(const unsigned char *in, int inlen, unsigned char *out) {
  unsigned int outlen;
  BIO *bio = BIO_new_mem_buf(PRIVATE_KEY_PEM, -1);
  if (!bio) return -1;
  
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  if (!rsa) {
    BIO_free(bio);
    return -1;
  }
  decode_rsa(rsa);
  RSA_sign(NID_sha256, in, inlen, out, &outlen, rsa);
  BIO_free(bio);
  return 0;
}


int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
  encode_rsa(rsa);
  unsigned int outlen;
  int result = RSA_sign(NID_sha256, in, inlen, out, &outlen, rsa);
  return result == 1 ? outlen : -1;
}

int rsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
  if (warmup(in, inlen, out) == -1)
    return -1;
  int outlen = tester_main(in, inlen, out);
  RSA_free(rsa);
  return outlen;
}

