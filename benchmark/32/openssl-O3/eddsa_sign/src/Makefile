SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ed25519_private_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../../lib/include \
         -L../../lib/ -Wall -O3 -g \
         -DEXAMPLE_EDDSA_SIGN -DOPENSSL_API_COMPAT=0x10100000L

LDFLAGS = -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -m32

all:
	cc $(CFLAGS) $(SRC) -o ../bin/eddsa_sign_openssl-O3_32 $(LDFLAGS)

clean:
	rm -f ../bin/eddsa_sign_openssl-O3_32