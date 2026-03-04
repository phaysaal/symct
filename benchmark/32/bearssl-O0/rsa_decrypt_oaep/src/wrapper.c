// bear_wrapper.c
/*
 * BearSSL RSA OAEP decryption checking for constant-time violations.
 * PRIVATE_KEY_PEM is loaded in warmup() and secret is injected via your hooks.
 * Padding: OAEP with SHA-256.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bearssl.h>
#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h"

static int rsa_decrypt_oaep(const unsigned char *in, int inlen,
                            unsigned char *out, int *outlen) {
    size_t modlen = (g_key.n_bitlen + 7) / 8;
    if (inlen != (int)modlen) {
        fprintf(stderr, "Input must be exactly %zu bytes for raw RSA\n", modlen);
        return 0;
    }
    // BearSSL OAEP decrypt works in-place
    unsigned char *tmp = malloc(modlen);
    if (!tmp) return 0;
    memcpy(tmp, in, modlen);

    size_t len = modlen;
    uint32_t ok = br_rsa_i31_oaep_decrypt(&br_sha256_vtable,
                                           NULL, 0,
                                           &g_key, tmp, &len);
    if (!ok) { free(tmp); return 0; }

    if (len > (size_t)*outlen) { free(tmp); return 0; }
    memcpy(out, tmp, len);
    *outlen = (int)len;
    secure_zero(tmp, modlen);
    free(tmp);
    return 1;
}

// ---------------- Public API matching your OpenSSL shape ----------------

void warmup(const unsigned char *in, int inlen, unsigned char *out) {
  int dummy_len = inlen;
  unsigned char dummy[4];
  unsigned char *tmpout = out ? out : dummy;
  if (!out) { dummy_len = sizeof(dummy); }

  size_t modlen = (g_key.n_bitlen + 7) / 8;
  if (inlen == (int)modlen) {
    (void)rsa_decrypt_oaep(in, inlen, tmpout, &dummy_len);
  }
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    encode_rsa_bearssl(&g_key);

    printf("Length of the components: n:%u p:%zu q:%zu\n",
           g_key.n_bitlen, g_key.plen, g_key.qlen);

    int outcap = inlen;
    int outlen = outcap;
    if (!rsa_decrypt_oaep(in, inlen, out, &outlen)) {
        fprintf(stderr, "RSA OAEP decryption failed\n");
        return -1;
    }
    return outlen;
}

void load_key_and_prepare () {
  if (load_priv_from_pem_string(PRIVATE_KEY_PEM) != 0) {
    return;
  }
  decode_rsa_bearssl(&g_key);
}

int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
  load_key_and_prepare ();
  warmup(in, inlen, out);
  int outlen = tester_main(in, inlen, out);
  test_end ();
  return outlen;
}
