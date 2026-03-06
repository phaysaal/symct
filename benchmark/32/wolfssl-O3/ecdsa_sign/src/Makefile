SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ec_private_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../.. -I../../lib -I../../lib/wolfssl -Wall -O3 -g \
         -DEXAMPLE_ECDSA_SIGN -DWOLFSSL_NO_SP_MATH -m32

# Link statically against libwolfssl.a in ../../lib
LDFLAGS = -no-pie -Wl,-Bstatic -L../../lib/ -lwolfssl -Wl,-Bdynamic -ldl -lm -lpthread -m32

all:
	$(CC) $(CFLAGS) $(SRC) -o ../bin/ecdsa_sign_wolfssl-O3_32 $(LDFLAGS)

clean:
	rm -f ../bin/ecdsa_sign_wolfssl-O3_32
