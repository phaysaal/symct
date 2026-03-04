#include "common.h"
#include "mbedtls/private/bignum.h"
#include <stdlib.h>
#include <string.h>

/* Global RSA component buffers */
unsigned char *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dp, *rsa_dq, *rsa_qp;
size_t len_n, len_e, len_d, len_p, len_q, len_dp, len_dq, len_qp;

/* Global ECDSA component buffers */
unsigned char *ec_d = NULL;
size_t len_ec_d = 0;

void decode_rsa(mbedtls_rsa_context *ctx) {
    // Export N, E, D, P, Q (basic components)
    len_n = mbedtls_rsa_get_len(ctx);
    rsa_n = malloc(len_n);

    len_e = mbedtls_rsa_get_len(ctx);
    rsa_e = malloc(len_e);

    len_d = mbedtls_rsa_get_len(ctx);
    rsa_d = malloc(len_d);

    len_p = mbedtls_rsa_get_len(ctx) / 2;
    rsa_p = malloc(len_p);

    len_q = mbedtls_rsa_get_len(ctx) / 2;
    rsa_q = malloc(len_q);

    // Export the basic components
    mbedtls_rsa_export_raw(ctx,
                           rsa_n, len_n,    // N
                           rsa_p, len_p,    // P
                           rsa_q, len_q,    // Q
                           rsa_d, len_d,    // D
                           rsa_e, len_e);   // E

    // Export CRT parameters (DP, DQ, QP)
    mbedtls_mpi DP, DQ, QP;
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_rsa_export_crt(ctx, &DP, &DQ, &QP);

    // Convert CRT parameters to byte arrays
    len_dp = mbedtls_mpi_size(&DP);
    rsa_dp = malloc(len_dp);
    mbedtls_mpi_write_binary(&DP, rsa_dp, len_dp);

    len_dq = mbedtls_mpi_size(&DQ);
    rsa_dq = malloc(len_dq);
    mbedtls_mpi_write_binary(&DQ, rsa_dq, len_dq);

    len_qp = mbedtls_mpi_size(&QP);
    rsa_qp = malloc(len_qp);
    mbedtls_mpi_write_binary(&QP, rsa_qp, len_qp);

    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
}

void encode_rsa(mbedtls_rsa_context *ctx) {
    // Import basic components (N, P, Q, D, E)
    mbedtls_rsa_import_raw(ctx,
                           rsa_n, len_n,    // N
                           rsa_p, len_p,    // P
                           rsa_q, len_q,    // Q
                           rsa_d, len_d,    // D
                           rsa_e, len_e);   // E

    // Complete the RSA context (calculates derived values including CRT params)
    mbedtls_rsa_complete(ctx);
}

void decode_ecdsa(mbedtls_ecdsa_context *ctx) {
    // Export the private key 'd' from the ECDSA context
    len_ec_d = mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(d));
    ec_d = malloc(len_ec_d);
    mbedtls_mpi_write_binary(&ctx->MBEDTLS_PRIVATE(d), ec_d, len_ec_d);
}

void encode_ecdsa(mbedtls_ecdsa_context *ctx) {
    // Import the private key 'd' back into the ECDSA context
    mbedtls_mpi_read_binary(&ctx->MBEDTLS_PRIVATE(d), ec_d, len_ec_d);
}
