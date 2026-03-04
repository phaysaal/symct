# Makefile
CC = gcc
CFLAGS = -I../../../../common/inputs -I. -I../.. -I../../lib -I../../lib/wolfssl \
	-Wall -O0 -g -m32 -DEXAMPLE_EDDSA_KEYGEN -DHAVE_ED25519 -DHAVE_ED25519_SIGN -DWOLFSSL_NO_SP_MATH -no-pie

# -Wl,--wrap=wc_RNG_GenerateBlock to intercept RNG
LDFLAGS = -no-pie -Wl,-Bstatic -L../../lib/ -lwolfssl -Wl,-Bdynamic -ldl -lm -lpthread -m32 -Wl,--wrap=wc_RNG_GenerateBlock

# Source files
SOURCES = wrapper.c main_template.c

OBJECTS = $(SOURCES:.c=.o)
TARGET = ../bin/eddsa_keygen_wolfssl_32

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
