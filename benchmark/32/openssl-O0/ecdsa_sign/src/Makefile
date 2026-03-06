SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ec_private_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../../lib/include \
         -L../../lib/ -Wall -O0 -g \
         -DEXAMPLE_ECDSA_SIGN -DOPENSSL_API_COMPAT=0x10100000L

LDFLAGS = -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -m32

all:
	cc $(CFLAGS) $(SRC) -o ../bin/ecdsa_sign_openssl-O0_32 $(LDFLAGS)

clean:
	rm -f ../bin/ecdsa_sign_openssl-O0_32
