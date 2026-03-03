/*
 * Mbed TLS RSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/private/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/private/entropy.h"

/*
 * Mbed TLS RSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/private/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/private/entropy.h"

/* 1MB buffer */
#define MAX_RAND_BYTES 2097152
#define MAX_OUTPUT_LEN 1024
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0;

mbedtls_rsa_context *ctx;

/* Custom RNG Callback */
int custom_rng(void *p_rng, unsigned char *output, size_t len) {
    (void)p_rng; // Unused

    if (record_mode) {
        /* Record Mode: Get real random data */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            fprintf(stderr, "Failed to open /dev/urandom\n");
            return MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
        }
        size_t read_len = fread(output, 1, len, f);
        fclose(f);

        if (read_len != len) {
            fprintf(stderr, "Failed to read random bytes\n");
            return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
        }

        if (global_rand_len + len > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow\n");
            return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
        }
        memcpy(global_rand_buf + global_rand_len, output, len);
        global_rand_len += len;
        return 0;
    } else {
        /* Replay Mode: Use recorded data */
        if (global_rand_idx + len > global_rand_len) {
            fprintf(stderr, "Global rand buffer underflow. Req: %zu, Left: %d\n", len, global_rand_len - global_rand_idx);
            return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
        }
        memcpy(output, global_rand_buf + global_rand_idx, len);
        global_rand_idx += len;
        return 0;
    }
}

void warmup(void) {
    fprintf(stderr, "Entering warmup...\n");
    ctx = malloc(sizeof(mbedtls_rsa_context) + 65536);
    int ret;

    if (!ctx) { fprintf(stderr, "Malloc failed in warmup\n"); return; }

    fprintf(stderr, "Zeroing ctx...\n");
    memset(ctx, 0, sizeof(mbedtls_rsa_context) + 65536);
    
    fprintf(stderr, "Calling mbedtls_rsa_init...\n");
    mbedtls_rsa_init(ctx);
    fprintf(stderr, "mbedtls_rsa_init done.\n");

    record_mode = 1;
    global_rand_len = 0;

    /* Generate a 2048-bit key with exponent 65537 */
    fprintf(stderr, "Calling mbedtls_rsa_gen_key...\n");
    ret = mbedtls_rsa_gen_key(ctx, custom_rng, NULL, 2048, 65537);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_rsa_gen_key failed in warmup: -0x%04x\n", -ret);
    }
    fprintf(stderr, "mbedtls_rsa_gen_key done.\n");

    /*
      mbedtls_rsa_free(ctx);
       free(ctx); //*/
}

int tester_main(unsigned char *out) {
  
  fprintf(stderr, "Entering tester_main...\n");
  /*
    mbedtls_rsa_context *ctx = malloc(sizeof(mbedtls_rsa_context) + 65536); //*/
  int ret;
  int out_len = 0;
  
    /*
    if (!ctx) { fprintf(stderr, "Malloc failed in tester_main\n"); return 0; } //*/

    //*
      memset(ctx, 0, sizeof(mbedtls_rsa_context) + 65536);   //*/
    fprintf(stderr, "Calling mbedtls_rsa_init in tester_main...\n");
    mbedtls_rsa_init(ctx);

    record_mode = 0;
    global_rand_idx = 0;

    /* TAINT POINT */

    fprintf(stderr, "Calling mbedtls_rsa_gen_key in tester_main...\n");
    ret = mbedtls_rsa_gen_key(ctx, custom_rng, NULL, 2048, 65537);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_rsa_gen_key failed in tester_main: -0x%04x\n", -ret);
        goto cleanup;
    }
    fprintf(stderr, "mbedtls_rsa_gen_key done in tester_main.\n");

    /* Export P factor */
    fprintf(stderr, "Exporting key components...\n");
    
    /* Allocate buffers for key components */
    size_t len = mbedtls_rsa_get_len(ctx);
    unsigned char *P = malloc(len);
    
    if (!P) {
        fprintf(stderr, "Malloc failed for P\n");
        goto cleanup;
    }
    
    /* We only care about P for verification in this test */
    /* mbedtls_rsa_export_raw(ctx, N, N_len, P, P_len, Q, Q_len, D, D_len, E, E_len) */
    /* Since we only want P, we can pass NULL for others, but we need to provide length */
    /* Actually mbedtls_rsa_export_raw might require all if we don't check impl. */
    /* Let's try exporting just P. */
    
    ret = mbedtls_rsa_export_raw(ctx, NULL, 0, P, len, NULL, 0, NULL, 0, NULL, 0);
    
    if (ret != 0) {
        fprintf(stderr, "mbedtls_rsa_export_raw failed: -0x%04x\n", -ret);
    } else {
        /* P is likely half the length of N, but export_raw fills the buffer with leading zeros if needed */
        /* However, P length is len / 2 */
        /* Let's re-read the docs or just export everything to be safe */
        
        /* Retry with correct size estimation */
        free(P);
        P = malloc(len); /* P is smaller than N, so len is safe upper bound */
        size_t p_len = len / 2; 
        /* mbedtls_rsa_export_raw expects the buffer size to be exactly what it writes? 
           Usually it writes leading zeros. 
           Let's use mbedtls_rsa_export with mpi and write binary manually if needed, 
           BUT we don't have mpi definitions if we don't include bignum.h? 
           Wait, rsa.h includes bignum.h. 
        */
        
        mbedtls_mpi MP;
        mbedtls_mpi_init(&MP);
        
        if ((ret = mbedtls_rsa_export(ctx, NULL, &MP, NULL, NULL, NULL)) != 0) {
             fprintf(stderr, "mbedtls_rsa_export failed: -0x%04x\n", -ret);
        } else {
             size_t actual_p_len = mbedtls_mpi_size(&MP);
             fprintf(stderr, "P size: %zu\n", actual_p_len);
             if (actual_p_len > MAX_OUTPUT_LEN) actual_p_len = MAX_OUTPUT_LEN;
             mbedtls_mpi_write_binary(&MP, out, actual_p_len);
             out_len = actual_p_len;
        }
        mbedtls_mpi_free(&MP);
    }
    if (P) free(P);

cleanup:
    mbedtls_rsa_free(ctx);
    free(ctx);
    return out_len;
}

int rsa_gen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
