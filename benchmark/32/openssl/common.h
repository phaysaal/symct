#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

static unsigned char *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dmp1, *rsa_dmq1, *rsa_iqmp;
static unsigned int  len_n,  len_e, len_d, len_p, len_q, len_dmp1, len_dmq1, len_iqmp;

void decode_rsa(RSA *rsa) {
  const BIGNUM *ln, *le, *ld, *lp, *lq, *ldmp1, *ldmq1, *liqmp;
  RSA_get0_key(rsa, &ln, &le, &ld);
  
  len_n = BN_num_bytes(ln);
  rsa_n = malloc(len_n);
  BN_bn2bin(ln, rsa_n);

  len_e = BN_num_bytes(le);
  rsa_e = malloc(len_e);
  BN_bn2bin(le, rsa_e);

  len_d = BN_num_bytes(ld);
  rsa_d = malloc(len_d);
  BN_bn2bin(ld, rsa_d);

  RSA_get0_factors(rsa, &lp, &lq);
  
  len_p = BN_num_bytes(lp);
  rsa_p = malloc(len_p);
  BN_bn2bin(lp, rsa_p);

  len_q = BN_num_bytes(lq);
  rsa_q = malloc(len_q);
  BN_bn2bin(lq, rsa_q);

  RSA_get0_crt_params(rsa, &ldmp1, &ldmq1, &liqmp);

  len_dmp1 = BN_num_bytes(ldmp1);
  rsa_dmp1 = malloc(len_dmp1);
  BN_bn2bin(ldmp1, rsa_dmp1);

  len_dmq1 = BN_num_bytes(ldmq1);
  rsa_dmq1 = malloc(len_dmq1);
  BN_bn2bin(ldmq1, rsa_dmq1);

  len_iqmp = BN_num_bytes(liqmp);
  rsa_iqmp = malloc(len_iqmp);
  BN_bn2bin(liqmp, rsa_iqmp);

  
}


void encode_rsa(RSA *rsa) {
  BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
  n = BN_bin2bn(rsa_n, len_n, NULL);
  e = BN_bin2bn(rsa_e, len_e, NULL);
  d = BN_bin2bn(rsa_d, len_d, NULL);
  p = BN_bin2bn(rsa_p, len_p, NULL);
  q = BN_bin2bn(rsa_q, len_q, NULL);
  dmp1 = BN_bin2bn(rsa_dmp1, len_dmp1, NULL);
  dmq1 = BN_bin2bn(rsa_dmq1, len_dmq1, NULL);
  iqmp = BN_bin2bn(rsa_iqmp, len_iqmp, NULL);
  RSA_set0_key(rsa, n, e, d);
  RSA_set0_factors(rsa, p, q);
  RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
  
}
