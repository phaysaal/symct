// common.h
#include <bearssl.h>
#include <stdlib.h>
#include <string.h>

// Global buffers for BearSSL key components
static unsigned char *rsa_p, *rsa_q, *rsa_dp, *rsa_dq, *rsa_iq;
static size_t len_p, len_q, len_dp, len_dq, len_iq;

void decode_rsa_bearssl(const br_rsa_private_key *key) {
    // Store key components in separate buffers for secret injection pattern
    
    len_p = key->plen;
    len_q = key->qlen;
    len_dp = key->dplen;
    len_dq = key->dqlen;
    len_iq = key->iqlen;
    
    rsa_p = malloc(len_p);
    memcpy(rsa_p, key->p, len_p);
    
    rsa_q = malloc(len_q);
    memcpy(rsa_q, key->q, len_q);
    
    rsa_dp = malloc(len_dp);
    memcpy(rsa_dp, key->dp, len_dp);
    
    rsa_dq = malloc(len_dq);
    memcpy(rsa_dq, key->dq, len_dq);
    
    rsa_iq = malloc(len_iq);
    memcpy(rsa_iq, key->iq, len_iq);
}

void encode_rsa_bearssl(br_rsa_private_key *key) {
    // Restore key components from stored buffers (simulating secret injection)
    key->p = rsa_p;
    key->q = rsa_q;
    key->dp = rsa_dp;
    key->dq = rsa_dq;
    key->iq = rsa_iq;
    key->plen = len_p;
    key->qlen = len_q;
    key->dplen = len_dp;
    key->dqlen = len_dq;
    key->iqlen = len_iq;
}

void free_rsa_bearssl(void) {
    if (rsa_p) free(rsa_p);
    if (rsa_q) free(rsa_q);
    if (rsa_dp) free(rsa_dp);
    if (rsa_dq) free(rsa_dq);
    if (rsa_iq) free(rsa_iq);
    
    rsa_p = rsa_q = rsa_dp = rsa_dq = rsa_iq = NULL;
}
