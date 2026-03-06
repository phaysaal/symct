# Makefile
CC = gcc
CFLAGS = -I../../../../common/inputs -I../.. -I../../lib -I../../lib/wolfssl \
	-Wall -O2 -g -m32 -DEXAMPLE_RSA_GENERATE_KEY -DWOLFSSL_KEY_GEN -DWOLFSSL_SP_MATH -DWOLFSSL_SP_MATH_ALL -DWC_RSA_BLINDING -DHAVE_HASHDRBG -DHAVE_GETPID=1 -DSP_INT_BITS=4096 -no-pie

# -Wl,--wrap=wc_RNG_GenerateBlock to intercept RNG
LDFLAGS = -m32 -L../../lib -lwolfssl -no-pie -Wl,--wrap=wc_RNG_GenerateBlock

# Source files
SOURCES = wrapper.c main_template.c

OBJECTS = $(SOURCES:.c=.o)
TARGET = ../bin/rsa_keygen_wolfssl-O2_32

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
