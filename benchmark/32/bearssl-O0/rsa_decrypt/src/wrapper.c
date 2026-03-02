// bear_wrapper.c
/*
 * BearSSL RSA decryption checking for constant-time violations.
 * PRIVATE_KEY_PEM is loaded in warmup() and secret is injected via your hooks.
 * Padding: PKCS#1 v1.5 (manual unpad after raw RSA).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bearssl.h>
#include "private_key_pem.h"
#include "public_key_pem.h"
#include "../../common.h"

// static br_rsa_private_key g_key;

// PKCS#1 v1.5 unpad: EM = 0x00 0x02 PS(>=8 nonzero) 0x00 M
static int pkcs1_v15_unpad(const unsigned char *em, size_t emlen,
                           unsigned char *out, int *outlen) {
    if (emlen < 11) return 0; // too short
    if (em[0] != 0x00 || em[1] != 0x02) return 0;
    size_t i = 2;
    // PS: nonzero bytes until 0x00 separator; length >= 8
    size_t ps_len = 0;
    for (; i < emlen; i++) {
        if (em[i] == 0x00) break;
        ps_len++;
    }
    if (i >= emlen || ps_len < 8) return 0;
    // i now at the 0x00 separator; message starts at i+1
    size_t mlen = emlen - (i + 1);
    if (mlen > (size_t)*outlen) return 0;
    memcpy(out, em + i + 1, mlen);
    *outlen = (int)mlen;
    return 1;
}

static int rsa_decrypt_pkcs1_v15(const unsigned char *in, int inlen,
                                 unsigned char *out, int *outlen) {
    size_t modlen = (g_key.n_bitlen + 7) / 8;
    if (inlen != (int)modlen) {
        fprintf(stderr, "Input must be exactly %zu bytes for raw RSA\n", modlen);
        return 0;
    }
    // BearSSL raw RSA is in-place
    unsigned char *tmp = malloc(modlen);
    if (!tmp) return 0;
    memcpy(tmp, in, modlen);

    uint32_t ok = br_rsa_i31_private(tmp, &g_key);
    if (!ok) { free(tmp); return 0; }

    int ulen = *outlen;
    ok = pkcs1_v15_unpad(tmp, modlen, out, &ulen);
    secure_zero(tmp, modlen);
    free(tmp);
    if (!ok) return 0;
    *outlen = ulen;
    return 1;
}

// ---------------- Public API matching your OpenSSL shape ----------------

void warmup(const unsigned char *in, int inlen, unsigned char *out) {
  // 3) Do a warmup decrypt (same size/semantics as tester_main)
  int outcap = inlen; // for PKCS#1 v1.5, plaintext <= inlen-11
  (void)outcap; // warmup: ignore result on purpose
  int dummy_len = inlen; // set cap; function will shrink it
  unsigned char dummy[4]; // not used; we just exercise timing path
  unsigned char *tmpout = out ? out : dummy;
  if (!out) { dummy_len = sizeof(dummy); }
  
  // Only call if input size equals modulus size
  size_t modlen = (g_key.n_bitlen + 7) / 8;
  if (inlen == (int)modlen) {
    (void)rsa_decrypt_pkcs1_v15(in, inlen, tmpout, &dummy_len);
  }
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    // 1) Restore (possibly modified) key components
    encode_rsa_bearssl(&g_key);

    printf("Length of the components: n:%u p:%zu q:%zu\n",
           g_key.n_bitlen, g_key.plen, g_key.qlen);

    // 2) Decrypt PKCS#1 v1.5 (like RSA_private_decrypt with RSA_PKCS1_PADDING)
    int outcap = inlen;      // worst-case cap (plaintext <= modlen-11)
    int outlen = outcap;
    if (!rsa_decrypt_pkcs1_v15(in, inlen, out, &outlen)) {
        fprintf(stderr, "RSA decryption failed\n");
        return -1;
    }
    return outlen;
}

void load_key_and_prepare () {
  // 1) Load key from embedded PEM
  if (load_priv_from_pem_string(PRIVATE_KEY_PEM) != 0) {
    return;
  }
  // 2) Let save secrets to inject instrumented buffers
  decode_rsa_bearssl(&g_key);
}



int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
  load_key_and_prepare ();
  warmup(in, inlen, out);
  int outlen = tester_main(in, inlen, out);
  test_end ();
  return outlen;
}
