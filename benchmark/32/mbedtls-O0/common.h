#ifndef MBEDTLS_COMMON_H
#define MBEDTLS_COMMON_H

#include "mbedtls/private/rsa.h"
#include "mbedtls/private/ecdsa.h"
#include "mbedtls/private/ecp.h"
#include "mbedtls/private/bignum.h"
#include <stddef.h>

/* Extern declarations for RSA component buffers (defined in common.c) */
extern unsigned char *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dp, *rsa_dq, *rsa_qp;
extern size_t len_n, len_e, len_d, len_p, len_q, len_dp, len_dq, len_qp;

/* Extern declarations for ECDSA component buffers (defined in common.c) */
extern unsigned char *ec_d;
extern size_t len_ec_d;

/**
 * decode_rsa - Extract RSA components from mbedtls_rsa_context to byte arrays
 * @ctx: The RSA context to extract from
 *
 * This function exports all RSA components (N, E, D, P, Q, DP, DQ, QP) from
 * the RSA context into separate byte arrays stored in global variables.
 * This serves as the "injection point" for symbolic execution tools.
 */
void decode_rsa(mbedtls_rsa_context *ctx);

/**
 * encode_rsa - Reconstruct mbedtls_rsa_context from byte arrays
 * @ctx: The RSA context to populate
 *
 * This function imports all RSA components from the global byte arrays back
 * into an RSA context. After this, symbolic execution can track how the
 * secret key material flows through the cryptographic operations.
 */
void encode_rsa(mbedtls_rsa_context *ctx);

/**
 * decode_ecdsa - Extract ECDSA private key from mbedtls_ecdsa_context to byte array
 * @ctx: The ECDSA context to extract from
 *
 * This function exports the EC private key from the ECDSA context into a byte array
 * stored in a global variable. This serves as the "injection point" for symbolic
 * execution tools.
 */
void decode_ecdsa(mbedtls_ecdsa_context *ctx);

/**
 * encode_ecdsa - Reconstruct mbedtls_ecdsa_context from byte array
 * @ctx: The ECDSA context to populate
 *
 * This function imports the EC private key from the global byte array back
 * into an ECDSA context. After this, symbolic execution can track how the
 * secret key material flows through the cryptographic operations.
 */
void encode_ecdsa(mbedtls_ecdsa_context *ctx);

#endif /* MBEDTLS_COMMON_H */
