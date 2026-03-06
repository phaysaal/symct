SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ciphertext.c \
      ../../../../common/inputs/private_key_pem.c \
      ../../../../common/inputs/public_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../../lib -I../../lib/wolfssl -Wall -O0 -g \
         -DEXAMPLE_RSA_DECRYPT -DWOLFSSL_NO_SP_MATH -m32

# Link statically against libwolfssl.a in ../../lib
# Keep -m32 if you use 32-bit build environment
# LDFLAGS = -no-pie -Wl,-Bstatic -L../../lib -lwolfssl -Wl,-Bdynamic -ldl -lm -lpthread

LDFLAGS = -no-pie -Wl,-Bstatic -L../../lib/ -lwolfssl -Wl,-Bdynamic -ldl -lm -lpthread -m32

all:
	$(CC) $(CFLAGS) $(SRC) -o ../bin/rsa_decrypt_wolfssl-O0_32 $(LDFLAGS)

clean:
	rm -f ../bin/rsa_decrypt_wolfssl-O0_32
