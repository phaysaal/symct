/*
 * mbedtls ECDSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "mbedtls/private/ecdsa.h"
#include "mbedtls/private/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"

/* Global buffer to capture/replay random bytes */
#define MAX_RAND_BYTES 65536
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0; /* 1 = record, 0 = replay */

mbedtls_ecdsa_context ecdsa;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

/* Custom entropy function for RNG interception */
static int custom_entropy_func(void *data, unsigned char *output, size_t len) {
    (void)data;

    if (record_mode) {
        /* Record mode: get real entropy and save it */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            fprintf(stderr, "Failed to open /dev/urandom\n");
            return -1;
        }
        size_t read_len = fread(output, 1, len, f);
        fclose(f);

        if (read_len != len) {
            fprintf(stderr, "Failed to read requested random bytes\n");
            return -1;
        }

        if (global_rand_len + (int)len > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow!\n");
            return -1;
        }
        memcpy(global_rand_buf + global_rand_len, output, len);
        global_rand_len += len;
    } else {
        /* Replay mode: return data from global buffer */
        if (global_rand_idx + (int)len > global_rand_len) {
            fprintf(stderr, "Global rand buffer underflow! Needed %zu, have %d\n",
                    len, global_rand_len - global_rand_idx);
            memset(output, 0, len);
            return -1;
        }
        memcpy(output, global_rand_buf + global_rand_idx, len);
        global_rand_idx += len;
    }
    return 0;
}

/* Custom random function that uses our recorded/replayed entropy */
static int custom_rng_func(void *p_rng, unsigned char *output, size_t output_len) {
    return mbedtls_ctr_drbg_random(p_rng, output, output_len);
}

void warmup(void) {
    int ret;

    /* Initialize PSA Crypto - REQUIRED for mbedtls 3.x */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "Failed to initialize PSA crypto: %d\n", (int)status);
        return;
    }

    /* Record Phase */
    record_mode = 1;
    global_rand_len = 0;

    /* Initialize contexts */
    mbedtls_ecp_keypair_init(&ecdsa);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    /* Seed the DRBG with custom entropy function */
    const char *pers = "ecdsa_keygen";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, custom_entropy_func, NULL,
                                 (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed: %s\n", error_buf);
        return;
    }

    /* Load the group (P-256 / secp256r1) */
    ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
        return;
    }

    /* Generate the keypair */
    ret = mbedtls_ecp_gen_keypair(&ecdsa.MBEDTLS_PRIVATE(grp),
                                   &ecdsa.MBEDTLS_PRIVATE(d),
                                   &ecdsa.MBEDTLS_PRIVATE(Q),
                                   custom_rng_func, &ctr_drbg);
    if (ret != 0) {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "mbedtls_ecp_gen_keypair failed in warmup: %s\n", error_buf);
        return;
    }

    /* Cleanup for warmup */
    /* mbedtls_ecp_keypair_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    */
}

int tester_main(unsigned char *out) {
    int ret;

    /* Replay Phase */
    record_mode = 0;
    global_rand_idx = 0;

    /* TAINT POINT: global_rand_buf is fully populated here */

    /* Re-initialize contexts for replay */
    /*
      mbedtls_ecp_keypair_init(&ecdsa);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    */
    
    /* Re-seed the DRBG with replayed entropy */
    /* const char *pers = "ecdsa_keygen";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, custom_entropy_func, NULL,
                                 (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed in replay: -0x%04x\n", -ret);
        return -1;
        } */

    /* Load the group (P-256 / secp256r1) */
    /*
    ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_ecp_group_load failed: -0x%04x\n", -ret);
        return -1;
    } */

    /* Generate the keypair - deterministic with replayed RNG */
    ret = mbedtls_ecp_gen_keypair(&ecdsa.MBEDTLS_PRIVATE(grp),
                                   &ecdsa.MBEDTLS_PRIVATE(d),
                                   &ecdsa.MBEDTLS_PRIVATE(Q),
                                   custom_rng_func, &ctr_drbg);
    if (ret != 0) {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "mbedtls_ecp_gen_keypair failed in tester_main: %s\n", error_buf);
        mbedtls_ecp_keypair_free(&ecdsa);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return -1;
    }

    /* Export private key to output buffer */
    size_t key_len = mbedtls_mpi_size(&ecdsa.MBEDTLS_PRIVATE(d));
    if (key_len > 4096) {
        fprintf(stderr, "Key too large\n");
        mbedtls_ecp_keypair_free(&ecdsa);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return -1;
    }

    ret = mbedtls_mpi_write_binary(&ecdsa.MBEDTLS_PRIVATE(d), out, key_len);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_mpi_write_binary failed: -0x%04x\n", -ret);
        mbedtls_ecp_keypair_free(&ecdsa);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return -1;
    }

    mbedtls_ecp_keypair_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return (int)key_len;
}

int ecdsa_keygen_tester(unsigned char *out) {
    warmup();
    int outlen = tester_main(out);

    /* Final cleanup */
    mbedtls_entropy_free(&entropy);

    return outlen;
}
