/*
 * BearSSL ECDSA Key Generation Benchmark with RNG Interception
 */
#include <stdio.h>
#include <string.h>
#include <bearssl.h>

/* Global buffer to capture/replay random bytes */
#define MAX_RAND_BYTES 65536
unsigned char global_rand_buf[MAX_RAND_BYTES];
int global_rand_idx = 0;
int global_rand_len = 0;
int record_mode = 0; /* 1 = record, 0 = replay */

/* Custom PRNG Context */
typedef struct {
    const br_prng_class *vtable;
} custom_prng_context;

/* Custom PRNG Methods */
static void custom_prng_init(const br_prng_class **ctx, const void *params,
                             const void *seed, size_t seed_len) {
    (void)ctx; (void)params; (void)seed; (void)seed_len;
}

static void custom_prng_generate(const br_prng_class **ctx, void *out, size_t len) {
    unsigned char *buf = out;
    (void)ctx;

    if (record_mode) {
        /* Record mode: generate random data from /dev/urandom */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            fprintf(stderr, "Failed to open /dev/urandom\n");
            return;
        }
        size_t read_len = fread(buf, 1, len, f);
        fclose(f);

        if (read_len != len) {
            fprintf(stderr, "Failed to read requested random bytes\n");
            return;
        }

        if (global_rand_len + len > MAX_RAND_BYTES) {
            fprintf(stderr, "Global rand buffer overflow! current: %d, requested: %zu, max: %d\n",
                    global_rand_len, len, MAX_RAND_BYTES);
            return;
        }
        memcpy(global_rand_buf + global_rand_len, buf, len);
        global_rand_len += len;
    } else {
        /* Replay mode: return data from global buffer */
        if (global_rand_idx + len > global_rand_len) {
            fprintf(stderr, "Global rand buffer underflow! Needed %zu, have %d\n",
                    len, global_rand_len - global_rand_idx);
            memset(buf, 0, len);
            return;
        }
        memcpy(buf, global_rand_buf + global_rand_idx, len);
        global_rand_idx += len;
    }
}

static void custom_prng_update(const br_prng_class **ctx, const void *seed, size_t seed_len) {
    (void)ctx; (void)seed; (void)seed_len;
}

/* Custom PRNG Vtable */
static const br_prng_class custom_prng_vtable = {
    sizeof(custom_prng_context),
    custom_prng_init,
    custom_prng_generate,
    custom_prng_update
};

/* Buffers for key components */
unsigned char kbuf_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
unsigned char kbuf_pub[BR_EC_KBUF_PUB_MAX_SIZE];

void warmup(void) {
    custom_prng_context rng_ctx;
    br_ec_private_key sk;

    /* Initialize our custom PRNG context */
    rng_ctx.vtable = &custom_prng_vtable;

    /* Record Phase */
    record_mode = 1;
    global_rand_len = 0;

    /* Use the i31 EC implementation with P-256 curve (secp256r1) */
    const br_ec_impl *ec_impl = &br_ec_prime_i31;

    size_t key_len = br_ec_keygen((const br_prng_class **)&rng_ctx,
                                   ec_impl, &sk, kbuf_priv,
                                   BR_EC_secp256r1);

    if (key_len == 0) {
        fprintf(stderr, "br_ec_keygen failed in warmup\n");
    }
}

int tester_main(unsigned char *out) {
    custom_prng_context rng_ctx;
    br_ec_private_key sk;
    br_ec_public_key pk;

    /* Initialize our custom PRNG context */
    rng_ctx.vtable = &custom_prng_vtable;

    /* Replay Phase */
    record_mode = 0;
    global_rand_idx = 0;

    /* TAINT POINT: global_rand_buf is fully populated here */

    const br_ec_impl *ec_impl = &br_ec_prime_i31;

    size_t priv_len = br_ec_keygen((const br_prng_class **)&rng_ctx,
                                    ec_impl, &sk, kbuf_priv,
                                    BR_EC_secp256r1);

    if (priv_len == 0) {
        fprintf(stderr, "br_ec_keygen failed in tester_main\n");
        return -1;
    }

    /* Compute public key from private key */
    size_t pub_len = br_ec_compute_pub(ec_impl, &pk, kbuf_pub, &sk);

    if (pub_len == 0) {
        fprintf(stderr, "br_ec_compute_pub failed\n");
        return -1;
    }

    /* Output the private key bytes */
    if (priv_len > 4096) return -1;
    memcpy(out, sk.x, priv_len);

    return (int)priv_len;
}

int ecdsa_keygen_tester(unsigned char *out) {
    warmup();
    return tester_main(out);
}
