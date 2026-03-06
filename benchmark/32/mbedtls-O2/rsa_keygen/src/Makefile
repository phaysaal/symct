# Makefile
CC = gcc
CFLAGS = -I../../../../common/inputs -I. \
         -I../../lib/include \
         -I../../lib/tf-psa-crypto/include \
         -I../../lib/tf-psa-crypto/drivers/builtin/include \
         -I../../lib/include \
         -I../../lib/tf-psa-crypto/include \
         -I../../lib/tf-psa-crypto/drivers/builtin/include \
         -I../../lib/tests/include \
         -I../../lib/framework/tests/include \
         -I../../lib/tests/include \
         -I../../lib/library \
         -I../../lib/tf-psa-crypto/core \
         -I../../lib/tf-psa-crypto/drivers/builtin/src \
         -Wall -O2 -g \
         -DEXAMPLE_RSA_GENERATE_KEY -m32 -no-pie

LDFLAGS = -L../../lib -lmbedtls -lmbedx509 -lmbedcrypto -ltfpsacrypto -ldl -lm -lpthread -m32

TARGET = ../bin/rsa_keygen_mbedtls-O2_32
SRC = wrapper.c main_template.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
