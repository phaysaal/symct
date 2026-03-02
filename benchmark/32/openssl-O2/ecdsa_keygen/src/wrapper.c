/*
 * ECDSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

/* Global buffer to capture/replay random bytes */
#define MAX_RAND_BYTES 65536
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0; /* 1 = record, 0 = replay */

/* Custom RNG Method */
static int custom_rand_bytes(unsigned char *buf, int num) {
    if (record_mode) {
        /* In record mode, generate deterministic data and save it */
        for (int i = 0; i < num; i++) {
            buf[i] = (unsigned char)(global_rand_len + i);
        }

        if (global_rand_len + num > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow!\n");
            return 0;
        }
        memcpy(global_rand_buf + global_rand_len, buf, num);
        global_rand_len += num;
    } else {
        /* In replay mode, return data from the global buffer */
        if (global_rand_idx + num > global_rand_len) {
            fprintf(stderr, "Global rand buffer underflow during replay! Needed %d, have %d left\n",
                    num, global_rand_len - global_rand_idx);
            return 0;
        }
        memcpy(buf, global_rand_buf + global_rand_idx, num);
        global_rand_idx += num;
    }
    return 1;
}

static int custom_rand_status(void) { return 1; }
static int custom_rand_seed(const void *buf, int num) { return 1; }
static void custom_rand_cleanup(void) { }
static int custom_rand_add(const void *buf, int num, double randomness) { return 1; }
static int custom_rand_pseudorand(unsigned char *buf, int num) { return custom_rand_bytes(buf, num); }

RAND_METHOD custom_rand_method = {
    custom_rand_seed,
    custom_rand_bytes,
    custom_rand_cleanup,
    custom_rand_add,
    custom_rand_pseudorand,
    custom_rand_status
};

void warmup(void) {
    EC_KEY *ec_key = NULL;

    /* Hook the RNG */
    RAND_set_rand_method(&custom_rand_method);

    /* Record Phase */
    record_mode = 1;
    global_rand_len = 0;

    /* Create EC_KEY with P-256 curve (secp256r1/prime256v1) */
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    /* Generate key pair to populate the random trace */
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "EC_KEY_generate_key failed in warmup\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return;
    }

    EC_KEY_free(ec_key);
}

int tester_main(unsigned char *out) {
    EC_KEY *ec_key = NULL;

    /* Replay Phase */
    record_mode = 0;
    global_rand_idx = 0;

    /*
     * HERE is where you would taint global_rand_buf if you were doing
     * symbolic execution constant-time analysis. The 'random' bytes
     * determining the private key are now in a fixed buffer.
     */

    /* Create EC_KEY with P-256 curve */
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* This call will now be deterministic based on global_rand_buf */
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "EC_KEY_generate_key failed in tester_main\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return -1;
    }

    /* Serialize private key to out */
    BIO *bp = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_ECPrivateKey(bp, ec_key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "PEM_write error\n");
        BIO_free(bp);
        EC_KEY_free(ec_key);
        return -1;
    }
    int len = BIO_read(bp, out, 4096);

    BIO_free(bp);
    EC_KEY_free(ec_key);

    return len;
}

int ecdsa_keygen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
