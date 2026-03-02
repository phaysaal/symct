#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT_LEN 512

#ifdef EXAMPLE_RSA_ENCRYPT
extern const unsigned char PLAINTEXT[];
extern const unsigned int PLAINTEXT_LEN;
extern int rsa_encrypt_tester(const unsigned char *in, int inlen, unsigned char *out);
#elif defined(EXAMPLE_RSA_DECRYPT)
extern const unsigned char CIPHERTEXT[];
extern const unsigned int CIPHERTEXT_LEN;
extern int rsa_decrypt_tester(const unsigned char *in, int inlen, unsigned char *out);
#elif defined(EXAMPLE_SIGN)
extern const unsigned char PLAINTEXT[];
extern const unsigned int PLAINTEXT_LEN;
extern int sign_tester(const unsigned char *in, int inlen, unsigned char *out);
#elif defined(EXAMPLE_KEY_EXCHANGE)
// Use a simulated symmetric session key (e.g., 32-byte nonce)
unsigned char simulated_secret[32] = {
  0xa3, 0x2f, 0x9c, 0x01, 0x88, 0x74, 0x23, 0x5d,
  0xfa, 0xb7, 0x11, 0x6c, 0x9a, 0xcd, 0x39, 0xde,
  0x55, 0x26, 0x77, 0x5e, 0x44, 0x90, 0xae, 0xb2,
  0x10, 0x0f, 0x61, 0x5a, 0x3d, 0x99, 0x02, 0x4b
};
extern int key_exchange_tester(const unsigned char *in, int inlen, unsigned char *out);
#else
#error "No EXAMPLE_xxx defined"
#endif

int main() {
    unsigned char out[MAX_OUTPUT_LEN];
    int outlen;

#ifdef EXAMPLE_RSA_ENCRYPT
    outlen = rsa_encrypt_tester(PLAINTEXT, PLAINTEXT_LEN, out);
#elif defined(EXAMPLE_RSA_DECRYPT)
    outlen = rsa_decrypt_tester(CIPHERTEXT, CIPHERTEXT_LEN, out);
#elif defined(EXAMPLE_SIGN)
    outlen = sign_tester(PLAINTEXT, PLAINTEXT_LEN, out);
#elif defined(EXAMPLE_KEY_EXCHANGE)
    outlen = key_exchange_tester(simulated_secret, sizeof(simulated_secret), out);
#endif

    if (outlen <= 0) {
        fprintf(stderr, "Operation failed\n");
        return 1;
    }

    // Print output (hex)
    for (int i = 0; i < outlen; ++i)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}
