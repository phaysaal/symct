/*
 * wolfSSL EdDSA (Ed25519) Key Generation Benchmark with RNG Interception
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

#include <wolfcrypt/ed25519.h>
#include <wolfcrypt/random.h>
#include <wolfcrypt/error-crypt.h>

/* 1MB buffer */
#define MAX_RAND_BYTES 1048576
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0;

WC_RNG *rng;
ed25519_key *key;

/* Prototype for the real function (provided by library) */
int __real_wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);

/* Wrapper function */
int __wrap_wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz) {
    if (record_mode) {
        int ret = __real_wc_RNG_GenerateBlock(rng, output, sz);
        if (ret != 0) return ret;

        if (global_rand_len + sz > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow. Req: %d, Curr: %d, Max: %d\n",
                    sz, global_rand_len, MAX_RAND_BYTES);
            return -1;
        }
        memcpy(global_rand_buf + global_rand_len, output, sz);
        global_rand_len += sz;
        return 0;
    } else {
        /* Replay */
        if (global_rand_idx + sz > global_rand_len) {
            fprintf(stderr, "Global rand buffer underflow. Req: %d, Left: %d\n",
                    sz, global_rand_len - global_rand_idx);
            memset(output, 0, sz);
            return -1;
        }
        memcpy(output, global_rand_buf + global_rand_idx, sz);
        global_rand_idx += sz;
        return 0;
    }
}

void warmup(void) {
    rng = malloc(sizeof(WC_RNG) + 1024);
    key = malloc(sizeof(ed25519_key) + 1024);
    int ret;

    if (!rng || !key) {
        fprintf(stderr, "Malloc failed in warmup\n");
        if (rng) free(rng);
        if (key) free(key);
        return;
    }

    ret = wc_InitRng(rng);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        free(rng);
        free(key);
        return;
    }

    ret = wc_ed25519_init(key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_init failed: %d\n", ret);
        wc_FreeRng(rng);
        free(rng);
        free(key);
        return;
    }

    record_mode = 1;
    global_rand_len = 0;

    /* Generate Ed25519 key */
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_make_key failed in warmup: %d (%s)\n",
                ret, wc_GetErrorString(ret));
    }

    /* wc_ed25519_free(key);
    wc_FreeRng(rng);
    free(key);
    free(rng); */
}

int tester_main(unsigned char *out) {
  /* WC_RNG *rng = malloc(sizeof(WC_RNG) + 1024);
     ed25519_key *key = malloc(sizeof(ed25519_key) + 1024); */
    int out_len = 0;
    int ret;

    /* if (!rng || !key) {
        fprintf(stderr, "Malloc failed in tester_main\n");
        if (rng) free(rng);
        if (key) free(key);
        return 0;
    }

    ret = wc_InitRng(rng);
    if (ret != 0) {
        fprintf(stderr, "wc_InitRng failed: %d\n", ret);
        free(rng);
        free(key);
        return 0;
    }

    ret = wc_ed25519_init(key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_init failed: %d\n", ret);
        wc_FreeRng(rng);
        free(rng);
        free(key);
        return 0;
        } */

    record_mode = 0;
    global_rand_idx = 0;

    /* TAINT POINT: global_rand_buf is fully populated here */

    /* Generate Ed25519 key - deterministic with replayed RNG */
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        fprintf(stderr, "wc_ed25519_make_key failed in tester_main: %d (%s)\n",
                ret, wc_GetErrorString(ret));
        wc_ed25519_free(key);
        wc_FreeRng(rng);
        free(key);
        free(rng);
        return 0;
    }

    /* Export private key to output buffer */
    word32 privSz = ED25519_PRV_KEY_SIZE;
    word32 pubSz = ED25519_PUB_KEY_SIZE;
    unsigned char pub[ED25519_PUB_KEY_SIZE];

    ret = wc_ed25519_export_key(key, out, &privSz, pub, &pubSz);
    if (ret == 0) {
        out_len = privSz;
    } else {
        fprintf(stderr, "wc_ed25519_export_key failed: %d\n", ret);
    }

    wc_ed25519_free(key);
    wc_FreeRng(rng);
    free(key);
    free(rng);

    return out_len;
}

int eddsa_keygen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
