#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT_LEN 512

extern const unsigned char PLAINTEXT[];
extern const unsigned int PLAINTEXT_LEN;
extern int eddsa_sign_tester(const unsigned char *in, int inlen, unsigned char *out);

int main() {
    unsigned char out[MAX_OUTPUT_LEN];
    int outlen;

    outlen = eddsa_sign_tester(PLAINTEXT, PLAINTEXT_LEN, out);

    if (outlen <= 0) {
        fprintf(stderr, "EdDSA signing failed\n");
        return 1;
    }

    // Print output (hex)
    for (int i = 0; i < outlen; ++i)
        printf("0x%02x, ", out[i]);
    printf("\n");

    return 0;
}
