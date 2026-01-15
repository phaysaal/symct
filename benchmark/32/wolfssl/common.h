/*
 * common.h -- wolfSSL adaptation of the OpenSSL common helpers used by main_template.c
 *
 * Exposes the same globals used by the OpenSSL harness so main_template.c remains unchanged.
 *
 * It provides:
 *   - rsa_n,rsa_e,rsa_d,... buffers and their lengths len_n,len_e,len_d,...
 *   - void decode_rsa(RsaKey *key) : extract key components into those buffers
 *
 * The arrays are malloc'd by decode_rsa. Caller can free or reuse process lifetime.
 */

#ifndef COMMON_H_WOLFSSL
#define COMMON_H_WOLFSSL

#include <stdlib.h>
#include <string.h>
#include <options.h>
#include <wolfcrypt/rsa.h>
#include <wolfcrypt/ecc.h>
#include <wolfcrypt/ed25519.h>
#include <wolfcrypt/integer.h> /* mp_ helpers */
#include "poison.h"

static unsigned char *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
static unsigned char *rsa_p = NULL, *rsa_q = NULL, *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;
static unsigned int len_n = 0, len_e = 0, len_d = 0, len_p = 0, len_q = 0, len_dmp1 = 0, len_dmq1 = 0, len_iqmp = 0;

/* ECC key components */
static unsigned char *ecc_k = NULL;  /* private key */
static unsigned int len_ecc_k = 0;

/* Ed25519 key components */
static unsigned char *eddsa_private_key = NULL;  /* k field: 64 bytes (32 secret + 32 pub) */
static unsigned char *eddsa_public_key = NULL;   /* p field: 32 bytes compressed public */
static unsigned int len_eddsa_private_key = 0;
static unsigned int len_eddsa_public_key = 0;

/* Extract components from a loaded RsaKey into the global buffers and len_* vars. */
static void decode_rsa(RsaKey *key) {
    /* mp_unsigned_bin_size gives number of bytes needed */
    len_n    = (unsigned int)mp_unsigned_bin_size(&key->n);
    len_e    = (unsigned int)mp_unsigned_bin_size(&key->e);
    len_d    = (unsigned int)mp_unsigned_bin_size(&key->d);
    len_p    = (unsigned int)mp_unsigned_bin_size(&key->p);
    len_q    = (unsigned int)mp_unsigned_bin_size(&key->q);
    len_dmp1 = (unsigned int)mp_unsigned_bin_size(&key->dP);
    len_dmq1 = (unsigned int)mp_unsigned_bin_size(&key->dQ);
    len_iqmp = (unsigned int)mp_unsigned_bin_size(&key->u);

    /* allocate buffers (caller should not assume these are small) */
    if (len_n)    rsa_n    = malloc(len_n);
    if (len_e)    rsa_e    = malloc(len_e);
    if (len_d)    rsa_d    = malloc(len_d);
    if (len_p)    rsa_p    = malloc(len_p);
    if (len_q)    rsa_q    = malloc(len_q);
    if (len_dmp1) rsa_dmp1 = malloc(len_dmp1);
    if (len_dmq1) rsa_dmq1 = malloc(len_dmq1);
    if (len_iqmp) rsa_iqmp = malloc(len_iqmp);

    /* fill buffers with big-endian unsigned binary form */
    if (len_n)    mp_to_unsigned_bin(&key->n, rsa_n);
    if (len_e)    mp_to_unsigned_bin(&key->e, rsa_e);
    if (len_d)    mp_to_unsigned_bin(&key->d, rsa_d);
    if (len_p)    mp_to_unsigned_bin(&key->p, rsa_p);
    if (len_q)    mp_to_unsigned_bin(&key->q, rsa_q);
    if (len_dmp1) mp_to_unsigned_bin(&key->dP, rsa_dmp1);
    if (len_dmq1) mp_to_unsigned_bin(&key->dQ, rsa_dmq1);
    if (len_iqmp) mp_to_unsigned_bin(&key->u, rsa_iqmp);

    
    //poison(rsa_n, len_n);
    //poison(rsa_e, len_e);
    //poison(rsa_d, len_d);
    //poison(rsa_p, len_p);
    /*poison(rsa_q, len_q);
    poison(rsa_dmp1, len_dmp1);
    poison(rsa_dmq1, len_dmq1);
    poison(rsa_iqmp, len_iqmp);
    */
}

/* encode_rsa kept for compatibility with harness: here it does nothing special
   because main_template expects to print len_* that were filled by decode_rsa(). */
static void encode_rsa(RsaKey *key) {
  /* Import FROM buffer TO key */
 
  
  
  mp_read_unsigned_bin(&key->n, rsa_n, len_n);
  mp_read_unsigned_bin(&key->e, rsa_e, len_e);
  mp_read_unsigned_bin(&key->d, rsa_d, len_d);
  mp_read_unsigned_bin(&key->p, rsa_p, len_p);
  mp_read_unsigned_bin(&key->q, rsa_q, len_q);
  mp_read_unsigned_bin(&key->dP, rsa_dmp1, len_dmp1);
  mp_read_unsigned_bin(&key->dQ, rsa_dmq1, len_dmq1);
  mp_read_unsigned_bin(&key->u, rsa_iqmp, len_iqmp);
}

static void free_buf() {

    /* Import FROM buffer TO key */
  if (rsa_n) free(rsa_n);
  if (rsa_e) free(rsa_e);
  if (rsa_d) free(rsa_d);
  if (rsa_p) free(rsa_p);
  if (rsa_q) free(rsa_q);
  if (rsa_dmp1) free(rsa_dmp1);
  if (rsa_dmq1) free(rsa_dmq1);
  if (rsa_iqmp) free(rsa_iqmp);
}

/* Extract ECC private key from ecc_key into global buffer */
static void decode_ecc(ecc_key *key) {
    /* Extract the private key 'k' */
    len_ecc_k = (unsigned int)mp_unsigned_bin_size(&key->k);

    if (len_ecc_k > 0) {
        ecc_k = malloc(len_ecc_k);
        mp_to_unsigned_bin(&key->k, ecc_k);
    }
}

/* Import ECC private key from global buffer back to ecc_key */
static void encode_ecc(ecc_key *key) {
    if (len_ecc_k > 0 && ecc_k != NULL) {
        mp_read_unsigned_bin(&key->k, ecc_k, len_ecc_k);
    }
}

/* Free ECC buffers */
static void free_ecc_buf() {
    if (ecc_k) {
        free(ecc_k);
        ecc_k = NULL;
    }
    len_ecc_k = 0;
}

/* Extract Ed25519 private key from ed25519_key into global buffer */
static void decode_eddsa(ed25519_key *key) {
    /* Ed25519 k field contains 32-byte secret + 32-byte public = 64 bytes total */
    len_eddsa_private_key = ED25519_PRV_KEY_SIZE;
    eddsa_private_key = malloc(len_eddsa_private_key);
    memcpy(eddsa_private_key, key->k, len_eddsa_private_key);

    /* Also save the compressed public key p field */
    len_eddsa_public_key = ED25519_PUB_KEY_SIZE;
    eddsa_public_key = malloc(len_eddsa_public_key);
    memcpy(eddsa_public_key, key->p, len_eddsa_public_key);
}

/* Import Ed25519 private key from global buffer back to ed25519_key */
static void encode_eddsa(ed25519_key *key) {
    if (len_eddsa_private_key > 0 && eddsa_private_key != NULL) {
        memcpy(key->k, eddsa_private_key, len_eddsa_private_key);
        key->privKeySet = 1;
    }
    if (len_eddsa_public_key > 0 && eddsa_public_key != NULL) {
        memcpy(key->p, eddsa_public_key, len_eddsa_public_key);
        key->pubKeySet = 1;
    }
}

/* Free Ed25519 buffers */
static void free_eddsa_buf() {
    if (eddsa_private_key) {
        free(eddsa_private_key);
        eddsa_private_key = NULL;
    }
    if (eddsa_public_key) {
        free(eddsa_public_key);
        eddsa_public_key = NULL;
    }
    len_eddsa_private_key = 0;
    len_eddsa_public_key = 0;
}

#endif /* COMMON_H_WOLFSSL */
