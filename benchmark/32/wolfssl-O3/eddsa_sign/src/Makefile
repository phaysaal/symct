SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/ed25519_private_key_pem.c

CFLAGS = -I../../../../common/inputs -I. -I../.. -I../../lib -I../../lib/wolfssl -Wall -O3 -g \
         -DEXAMPLE_EDDSA_SIGN -DHAVE_ED25519 -DHAVE_ED25519_SIGN -DWOLFSSL_NO_SP_MATH -m32

# Link statically against libwolfssl.a in ../../lib
LDFLAGS = -no-pie -Wl,-Bstatic -L../../lib/ -lwolfssl -Wl,-Bdynamic -ldl -lm -lpthread -m32

all:
	$(CC) $(CFLAGS) $(SRC) -o ../bin/eddsa_sign_wolfssl-O3_32 $(LDFLAGS)

clean:
	rm -f ../bin/eddsa_sign_wolfssl-O3_32
