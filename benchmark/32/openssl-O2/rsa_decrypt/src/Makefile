SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ciphertext.c \
      ../../../../common/inputs/private_key_pem.c \
      ../../../../common/inputs/public_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../../lib/include \
         -L../../lib/ -Wall -O2 -g \
         -DEXAMPLE_RSA_DECRYPT -DOPENSSL_API_COMPAT=0x10100000L

LDFLAGS = -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -m32

all:
	cc $(CFLAGS) $(SRC) -o ../bin/rsa_decrypt_openssl-O2_32 $(LDFLAGS)

clean:
	rm -f ../bin/rsa_decrypt_openssl-O2_32
