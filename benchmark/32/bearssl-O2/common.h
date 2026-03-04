#ifndef BEARSSL_COMMON_H
#define BEARSSL_COMMON_H

#include <bearssl.h>
#include <stddef.h>

/* ============================================================
 * Common BearSSL helpers for private key handling and utilities
 * ============================================================
 */

/* ---- Global RSA key ---- */
extern br_rsa_private_key g_key;

/* ---- Shared RSA component buffers (used by both stub and loader) ---- */
extern unsigned char *rsa_d, *rsa_p, *rsa_q, *rsa_dp, *rsa_dq, *rsa_iq;
extern size_t len_d, len_p, len_q, len_dp, len_dq, len_iq;

/* ---- Global EC key ---- */
extern br_ec_private_key g_ec_key;

/* ---- Shared EC component buffers ---- */
extern unsigned char *ec_x;
extern size_t len_ec_x;

/* ---- Core lifecycle helpers ---- */

/* Secure zero implementation (replacement for br_zero) */
void secure_zero(void *p, size_t n);

/* Free all allocated RSA component buffers and reset g_key */
void free_rsa_bearssl_heap(void);

/* Load RSA private key from PEM string (PKCS#1 or unencrypted PKCS#8) */
int load_priv_from_pem_string(const char *pem);

/* ---- Hooks for secret-injection analysis ---- */
void decode_rsa_bearssl(const br_rsa_private_key *key);
void encode_rsa_bearssl(br_rsa_private_key *key);
void free_rsa_bearssl(void);
void test_end(void);

/* ---- EC key management ---- */
int load_ec_priv_from_pem_string(const char *pem);
void decode_ec_bearssl(const br_ec_private_key *key);
void encode_ec_bearssl(br_ec_private_key *key);
void free_ec_bearssl(void);
void free_ec_bearssl_heap(void);

#endif /* BEARSSL_COMMON_H */
