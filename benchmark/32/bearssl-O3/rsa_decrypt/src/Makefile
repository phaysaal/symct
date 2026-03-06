# Makefile
CC = gcc
CFLAGS = -I../../../../common/inputs -I../.. -I../../lib/include \
	-Wall -O3 -g -m32 -DEXAMPLE_RSA_DECRYPT -no-pie

LDFLAGS = -m32 -L../../lib -lbearssl -no-pie

# Source files
SOURCES = wrapper.c main_template.c \
	../../../../common/inputs/plaintext.c \
	../../../../common/inputs/ciphertext.c \
	../../../../common/inputs/private_key_pem.c \
	../../../../common/inputs/public_key_pem.c \
	../../common.c


OBJECTS = $(SOURCES:.c=.o)
TARGET = ../bin/rsa_decrypt_bearssl-O3_32

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

test: $(TARGET)
	./$(TARGET)

.PHONY: all clean test
