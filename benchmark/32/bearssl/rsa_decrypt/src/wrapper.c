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

static br_rsa_private_key g_key;

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) { *v++ = 0; }
}


// ---- owned storage so g_key stays valid across calls ----
static unsigned char *P=NULL,*Q=NULL,*DP=NULL,*DQ=NULL,*IQ=NULL;
static size_t PL=0,QL=0,DPL=0,DQL=0,IQL=0;

static void zero_free(unsigned char **p, size_t *len) {
    if (*p) { secure_zero(*p, *len); free(*p); *p=NULL; *len=0; }
}

static void free_rsa_bearssl_heap(void) {
    zero_free(&P, &PL);
    zero_free(&Q, &QL);
    zero_free(&DP, &DPL);
    zero_free(&DQ, &DQL);
    zero_free(&IQ, &IQL);
    memset(&g_key, 0, sizeof g_key);
}

// Deep-copy decoder-owned buffers into our storage
static int deep_copy_key_from_decoder(const br_rsa_private_key *k) {
    PL=k->plen; QL=k->qlen; DPL=k->dplen; DQL=k->dqlen; IQL=k->iqlen;
    P  = malloc(PL); Q  = malloc(QL); DP = malloc(DPL); DQ = malloc(DQL); IQ = malloc(IQL);
    if (!P || !Q || !DP || !DQ || !IQ) return -1;

    memcpy(P,  k->p,  PL);
    memcpy(Q,  k->q,  QL);
    memcpy(DP, k->dp, DPL);
    memcpy(DQ, k->dq, DQL);
    memcpy(IQ, k->iq, IQL);

    g_key.p = P;  g_key.plen  = PL;
    g_key.q = Q;  g_key.qlen  = QL;
    g_key.dp= DP; g_key.dplen = DPL;
    g_key.dq= DQ; g_key.dqlen = DQL;
    g_key.iq= IQ; g_key.iqlen = IQL;
    g_key.n_bitlen = k->n_bitlen;
    return 0;
}

// Stream PEM -> skey decoder
static int load_priv_from_pem_string(const char *pem) {
    br_pem_decoder_context pc;
    br_skey_decoder_context sk;
    br_pem_decoder_init(&pc);
    br_skey_decoder_init(&sk);

    // Route decoded DER into the skey decoder
    br_pem_decoder_setdest(&pc,
        (void (*)(void *, const void *, size_t)) &br_skey_decoder_push,
        &sk);

    const unsigned char *data = (const unsigned char *)pem;
    size_t len = strlen(pem);

    size_t off = 0;
    for (;;) {
        size_t used = br_pem_decoder_push(&pc, data + off, len - off);
        off += used;

        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            // Optional: check object name if you want ("RSA PRIVATE KEY" / "PRIVATE KEY")
            // printf("PEM object: %s\n", br_pem_decoder_name(&pc));
        } else if (ev == BR_PEM_END_OBJ) {
            break; // DER fully fed to skey decoder
        } else if (ev == BR_PEM_ERROR) {
            fprintf(stderr, "PEM decoding error\n");
            return -1;
        }
        if (used == 0) break; // all input consumed
    }

    int err = br_skey_decoder_last_error(&sk);
    if (err != 0) {
        fprintf(stderr, "Key decoding error: %d\n", err);
        return -1;
    }
    if (br_skey_decoder_key_type(&sk) != BR_KEYTYPE_RSA) {
        fprintf(stderr, "Not an RSA key\n");
        return -1;
    }
    const br_rsa_private_key *k = br_skey_decoder_get_rsa(&sk);
    if (!k) {
        fprintf(stderr, "Decoder returned NULL RSA key\n");
        return -1;
    }
    if (deep_copy_key_from_decoder(k) != 0) {
        fprintf(stderr, "Out of memory for RSA key copy\n");
        return -1;
    }
    return 0;
}

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

// Raw RSA private op + PKCS#1 v1.5 unpad
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
    // 1) Load key from embedded PEM
    if (load_priv_from_pem_string(PRIVATE_KEY_PEM) != 0) {
        return;
    }

    // 2) Let your hook capture secrets / inject instrumented buffers
    decode_rsa_bearssl(&g_key);

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

int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out) {
    warmup(in, inlen, out);
    int outlen = tester_main(in, inlen, out);
    free_rsa_bearssl();           // your hook cleanup (if any)
    free_rsa_bearssl_heap();      // our heap cleanup + zeroize
    return outlen;
}
