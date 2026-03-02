#include <stdio.h>
#include <string.h>

#define MAX_OUTPUT_LEN 4096

extern int eddsa_keygen_tester(unsigned char *out);

int main() {
    unsigned char out[MAX_OUTPUT_LEN];
    int outlen;

    outlen = eddsa_keygen_tester(out);

    if (outlen <= 0) {
        fprintf(stderr, "Operation failed\n");
        return 1;
    }

    /* Print private key (hex) */
    printf("Generated Ed25519 private key (hex): ");
    for (int i = 0; i < outlen; ++i) {
        printf("%02x", out[i]);
    }
    printf("\n");

    return 0;
}
