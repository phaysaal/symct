CC = gcc
SRC = wrapper.c main_template.c \
      ../../../../common/inputs/plaintext.c

CFLAGS = -I../../../../common/inputs -I. \
         -I../../lib/include \
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
         -I../../lib/tf-psa-crypto/drivers/builtin/src \
         -Wall -O0 -g \
         -DEXAMPLE_EDDSA_SIGN -m32 -no-pie

LDFLAGS = -L/home/faisal/code/lsl/sct/benchmark/32/mbedtls/lib/build/library -lmbedtls -lmbedx509 -lmbedcrypto -ltfpsacrypto -ldl -lm -lpthread -m32

TARGET = ../bin/eddsa_sign_mbedtls_32

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)
