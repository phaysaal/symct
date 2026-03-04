#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT_LEN 4096

extern int ecdsa_keygen_tester(unsigned char *out);

int main() {
    unsigned char out[MAX_OUTPUT_LEN];
    int outlen;

    outlen = ecdsa_keygen_tester(out);

    if (outlen <= 0) {
        fprintf(stderr, "Operation failed\n");
        return 1;
    }

    /* Print private key scalar (hex) */
    printf("Generated EC private key scalar (hex): ");
    for (int i = 0; i < outlen; ++i) {
        printf("%02x", out[i]);
    }
    printf("\n");

    return 0;
}
