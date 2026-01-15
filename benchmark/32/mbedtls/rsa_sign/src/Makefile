CC = gcc
CFLAGS = -Wall -O0 -g -DEXAMPLE_RSA_SIGN -m32 -no-pie
LDFLAGS = -L../../lib/build/library -lmbedtls -lmbedx509 -lmbedcrypto -ltfpsacrypto -ldl -lm -lpthread -m32

# Adjust include paths to be relative to the Makefile's location
INCLUDES = \
    -I../../lib/include \
    -I../../../../common/inputs -I. \
    -I../../lib/tf-psa-crypto/include \
    -I../../lib/tf-psa-crypto/drivers/builtin/include \
    -I../../lib/build/include \
    -I../../lib/build/tf-psa-crypto/include \
    -I../../lib/build/tf-psa-crypto/drivers/builtin/include \
    -I../../lib/build/tests/include \
    -I../../lib/framework/tests/include \
    -I../../lib/tests/include \
    -I../../lib/library \
    -I../../lib/tf-psa-crypto/core \
    -I../../lib/tf-psa-crypto/drivers/builtin/src

SRC = wrapper.c main_template.c ../../common.c \
      ../../../../common/inputs/plaintext.c \
      ../../../../common/inputs/private_key_pem.c

TARGET = ../bin/rsa_sign_mbedtls_32

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(INCLUDES) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
