/*
 * RSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Global buffer to capture/replay random bytes */
#define MAX_RAND_BYTES 65536
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0; /* 1 = record, 0 = replay */

/* Custom RNG Method */
static int custom_rand_bytes(unsigned char *buf, int num) {
  if (record_mode) { // RSA_generate_key_ex
        /* In record mode, we generate real random data and save it */
        /* For simplicity in this harness, we use a simple LCG or just 0xAA pattern 
           if we don't want to rely on system RNG, but better to use system RNG 
           to ensure key generation actually succeeds (finding primes requires real randomness) */
        
        /* Using /dev/urandom or just a simple fill for reproducibility in this specific test context */
        /* Let's use a deterministic PRNG for "recording" so the "first pass" is also stable across runs of the binary */
        for (int i = 0; i < num; i++) {
            buf[i] = (unsigned char)(global_rand_len + i); // Simple counter pattern or use rand()
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
            fprintf(stderr, "Global rand buffer underflow during replay! Needed %d, have %d left\n", num, global_rand_len - global_rand_idx);
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
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    
    /* Hook the RNG */
    RAND_set_rand_method(&custom_rand_method);

    /* Record Phase */
    record_mode = 1;
    global_rand_len = 0;
    
    bn = BN_new();
    BN_set_word(bn, RSA_F4);
    rsa = RSA_new();
    
    /* Generate key to populate the random trace */
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "RSA_generate_key_ex failed in warmup\n");
        ERR_print_errors_fp(stderr);
    } else {
        // fprintf(stderr, "Warmup key gen success. Used %d random bytes.\n", global_rand_len);
    }

    RSA_free(rsa);
    BN_free(bn);
}

int tester_main(unsigned char *out) {
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    
    /* Replay Phase */
    record_mode = 0;
    global_rand_idx = 0;
    
    /* 
     * HERE is where you would taint global_rand_buf if you were doing 
     * symbolic execution constant-time analysis. The 'random' bytes 
     * determining the prime factors are now in a fixed buffer.
     */

    bn = BN_new();
    BN_set_word(bn, RSA_F4);
    rsa = RSA_new();

    /* This call will now be deterministic based on global_rand_buf */
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "RSA_generate_key_ex failed in tester_main\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        BN_free(bn);
        return -1;
    }

    /* Serialize private key to out */
    BIO *bp = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "PEM_write error\n");
    }
    int len = BIO_read(bp, out, 4096); /* Assuming 4096 is enough for PEM 2048 */
    
    BIO_free(bp);
    RSA_free(rsa);
    BN_free(bn);
    
    return len;
}

int rsa_gen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
