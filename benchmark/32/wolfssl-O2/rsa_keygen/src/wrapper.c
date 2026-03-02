/*
 * WolfSSL RSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* 1MB buffer */
#define MAX_RAND_BYTES 1048576
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0;

WC_RNG *rng;
RsaKey *key;

/* Prototype for the real function (provided by library) */
int __real_wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);

/* Wrapper function */
int __wrap_wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz) {
    if (record_mode) {
        int ret = __real_wc_RNG_GenerateBlock(rng, output, sz);
        if (ret != 0) return ret; /* Error */
        
        if (global_rand_len + sz > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow. Req: %d, Curr: %d, Max: %d\n", sz, global_rand_len, MAX_RAND_BYTES);
            return -1; /* MEMORY_E ? */
        }
        memcpy(global_rand_buf + global_rand_len, output, sz);
        global_rand_len += sz;
        return 0;
    } else {
        /* Replay */
        if (global_rand_idx + sz > global_rand_len) {
             fprintf(stderr, "Global rand buffer underflow. Req: %d, Left: %d\n", sz, global_rand_len - global_rand_idx);
             /* Fill with 0 to avoid crash, but this is a failure */
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
    key = malloc(sizeof(RsaKey) + 1024);
    int ret;
    
    if (!rng || !key) { fprintf(stderr, "Malloc failed in warmup\n"); return; }

    ret = wc_InitRng(rng);
    if (ret != 0) { fprintf(stderr, "wc_InitRng failed: %d\n", ret); free(rng); free(key); return; }
    
    ret = wc_InitRsaKey(key, NULL);
    if (ret != 0) { fprintf(stderr, "wc_InitRsaKey failed: %d\n", ret); free(rng); free(key); return; }
    
    record_mode = 1;
    global_rand_len = 0;
    
    ret = wc_MakeRsaKey(key, 2048, 65537, rng);
    if (ret != 0) {
        fprintf(stderr, "wc_MakeRsaKey failed in warmup: %d\n", ret);
    }
    
    /* wc_FreeRsaKey(key);
    wc_FreeRng(rng);
    free(key);
    free(rng); */
}

int tester_main(unsigned char *out) {
  /* WC_RNG *rng = malloc(sizeof(WC_RNG) + 1024);
     RsaKey *key = malloc(sizeof(RsaKey) + 1024); */
    int out_len = 0;
    int ret;
    
    /* if (!rng || !key) { fprintf(stderr, "Malloc failed in tester_main\n"); return 0; }

    ret = wc_InitRng(rng);
    if (ret != 0) { fprintf(stderr, "wc_InitRng failed: %d\n", ret); goto err_alloc; }

    ret = wc_InitRsaKey(key, NULL);
    if (ret != 0) { fprintf(stderr, "wc_InitRsaKey failed: %d\n", ret); goto err_rng; } */
    
    record_mode = 0;
    global_rand_idx = 0;
    
    /* TAINT POINT */
    
    ret = wc_MakeRsaKey(key, 2048, 65537, rng);
    if (ret != 0) {
        fprintf(stderr, "wc_MakeRsaKey failed in tester_main: %d\n", ret);
        goto err_key;
    }
    
    /* Export P factor for verification */
    byte *e = malloc(256);
    byte *n = malloc(512);
    byte *d = malloc(512);
    byte *p = malloc(256);
    byte *q = malloc(256);
    
    if (!e || !n || !d || !p || !q) {
        fprintf(stderr, "Malloc failed\n");
        goto cleanup_bufs;
    }

    word32 eSz = 256, nSz = 512, dSz = 512, pSz = 256, qSz = 256;
    
    ret = wc_RsaExportKey(key, e, &eSz, n, &nSz, d, &dSz, p, &pSz, q, &qSz);
    if (ret == 0) {
        memcpy(out, p, pSz);
        out_len = pSz;
    } else {
        fprintf(stderr, "wc_RsaExportKey failed: %d\n", ret);
    }

cleanup_bufs:
    if(e) free(e); 
    if(n) free(n); 
    if(d) free(d); 
    if(p) free(p); 
    if(q) free(q);

err_key:
    wc_FreeRsaKey(key);
    // err_rng:
    wc_FreeRng(rng);
    // err_alloc:
    free(key);
    free(rng);
    return out_len;
}

int rsa_gen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
