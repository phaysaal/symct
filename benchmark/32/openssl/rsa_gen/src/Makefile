SRC = wrapper.c main_template.c

CFLAGS = -I../../../../common/inputs -I. -I../../lib/include \
         -L../../lib/ -Wall -O0 -g \
         -DEXAMPLE_RSA_GENERATE_KEY -DOPENSSL_API_COMPAT=0x10100000L

LDFLAGS = -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -m32

all:
	cc $(CFLAGS) $(SRC) -o ../bin/rsa_gen_openssl_32 $(LDFLAGS)

clean:
	rm -f ../bin/rsa_gen_openssl_32