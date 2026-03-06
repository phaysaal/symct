CC = gcc
CFLAGS = -Wall -O3 -g -DEXAMPLE_RSA_DECRYPT -DOAEP -m32 -no-pie
LDFLAGS = -L../../lib -lmbedtls -lmbedx509 -lmbedcrypto -ltfpsacrypto -ldl -lm -lpthread -m32

# Adjust include paths to be relative to the Makefile's location
INCLUDES = \
    -I../../lib/include \
    -I../../../../common/inputs -I. \
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
    -I../../lib/tf-psa-crypto/drivers/builtin/src

SRC = wrapper.c main_template.c ../../common.c \
      ../../../../common/inputs/ciphertext.c \
      ../../../../common/inputs/private_key_pem.c

TARGET = ../bin/rsa_decrypt_oaep_mbedtls-O3_32

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(INCLUDES) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
