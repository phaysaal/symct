/*
 * ECDSA signing checking for constant time violation - mbedtls version
 * Following the same pattern as RSA implementations
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "mbedtls/private/ecdsa.h"
#include "mbedtls/private/ecp.h"
#include "mbedtls/private/entropy.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "psa/crypto.h"
#include "ec_private_key_pem.h"
#include "../../common.h"

mbedtls_ecdsa_context ecdsa;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;
unsigned char hash[32];  // SHA-256 hash

int warmup(const unsigned char *in, int inlen, unsigned char *out) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_md_context_t md_ctx;

    // Initialize PSA Crypto - REQUIRED for mbedtls 3.x
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA crypto: %d\n", (int)status);
        return -1;
    }

    // Initialize contexts
    mbedtls_pk_init(&pk);
    mbedtls_ecp_keypair_init(&ecdsa);

    // Parse PEM key
    ret = mbedtls_pk_parse_key(&pk,
                               (const unsigned char *)EC_PRIVATE_KEY_PEM,
                               EC_PRIVATE_KEY_PEM_LEN + 1,  // +1 for null terminator
                               NULL, 0);

    if (ret != 0) {
        printf("Failed to parse PEM: -0x%04x\n", -ret);
        mbedtls_pk_free(&pk);
        return -1;
    }

    // Extract the EC keypair from PK context
    // Note: mbedtls_pk_ec is not available, we extract from PSA
    mbedtls_svc_key_id_t key_id = pk.MBEDTLS_PRIVATE(priv_id);
    uint8_t export_buf[512];
    size_t export_len;
    
    // Export Private Key
    psa_status_t export_status = psa_export_key(key_id, export_buf, sizeof(export_buf), &export_len);
    if (export_status != PSA_SUCCESS) {
        printf("Failed to export PSA key: %d\n", export_status);
        mbedtls_pk_free(&pk);
        return -1;
    }

    // Load 'd' (private key)
    mbedtls_mpi_read_binary(&ecdsa.MBEDTLS_PRIVATE(d), export_buf, export_len);
    memset(export_buf, 0, sizeof(export_buf));

    // Load Group (Assuming SECP256R1)
    if (mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1) != 0) {
        printf("Failed to load group\n");
        mbedtls_pk_free(&pk);
        return -1;
    }

    // Load Public Key 'Q'
    if (pk.MBEDTLS_PRIVATE(pub_raw_len) > 0) {
        mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp), 
                                      &ecdsa.MBEDTLS_PRIVATE(Q),
                                      pk.MBEDTLS_PRIVATE(pub_raw),
                                      pk.MBEDTLS_PRIVATE(pub_raw_len));
    } else {
        // Compute Q = d * G
        mbedtls_ecp_mul(&ecdsa.MBEDTLS_PRIVATE(grp), 
                        &ecdsa.MBEDTLS_PRIVATE(Q), 
                        &ecdsa.MBEDTLS_PRIVATE(d), 
                        &ecdsa.MBEDTLS_PRIVATE(grp).G, 
                        mbedtls_ctr_drbg_random, &ctr_drbg);
    }

    mbedtls_pk_free(&pk);

    // Initialize RNG for signing
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    const char *pers = "ecdsa_sign";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const unsigned char *)pers, strlen(pers));

    // Decode ECDSA components to byte arrays
    decode_ecdsa(&ecdsa);

    // Hash the input message using SHA-256
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, in, inlen);
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    // Perform first signing (warmup)
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_ecdsa_sign(&ecdsa.MBEDTLS_PRIVATE(grp), &r, &s, &ecdsa.MBEDTLS_PRIVATE(d),
                             hash, 32, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret == 0) {
        // Encode signature to DER format for output
        unsigned char *p = out + 256;  // Work backwards
        size_t len = 0;

        len += mbedtls_asn1_write_mpi(&p, out, &s);
        len += mbedtls_asn1_write_mpi(&p, out, &r);
        len += mbedtls_asn1_write_len(&p, out, len);
        len += mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

        memmove(out, p, len);
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0) ? 0 : -1;
}

int tester_main(const unsigned char *in, int inlen, unsigned char *out) {
    // Encode ECDSA components back from byte arrays
    // This is where symbolic values can be injected for analysis
    encode_ecdsa(&ecdsa);

    printf("EC key curve: %d, private key length: %zu bytes\n",
           ecdsa.MBEDTLS_PRIVATE(grp).id, len_ec_d);

    // Perform second signing (actual test)
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecdsa_sign(&ecdsa.MBEDTLS_PRIVATE(grp), &r, &s, &ecdsa.MBEDTLS_PRIVATE(d),
                                 hash, 32, mbedtls_ctr_drbg_random, &ctr_drbg);

    size_t sig_len = 0;
    if (ret == 0) {
        // Encode signature to DER format
        unsigned char *p = out + 256;  // Work backwards
        size_t len = 0;

        len += mbedtls_asn1_write_mpi(&p, out, &s);
        len += mbedtls_asn1_write_mpi(&p, out, &r);
        len += mbedtls_asn1_write_len(&p, out, len);
        len += mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

        memmove(out, p, len);
        sig_len = len;
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0) ? (int)sig_len : -1;
}

int ecdsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out) {
    if (warmup(in, inlen, out) == -1)
        return -1;

    int outlen = tester_main(in, inlen, out);

    // Cleanup
    mbedtls_ecp_keypair_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    // Free the byte arrays
    if (ec_d) free(ec_d);

    return outlen;
}
