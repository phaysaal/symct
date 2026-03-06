# Makefile
CC = gcc
CFLAGS = -I../../../../common/inputs -I../.. -I../../lib/include \
	-Wall -O3 -g -m32 -DEXAMPLE_ECDSA_KEYGEN -no-pie -fno-inline

LDFLAGS = -m32 -L../../lib -lbearssl -no-pie

# Source files
SOURCES = wrapper.c main_template.c

OBJECTS = $(SOURCES:.c=.o)
TARGET = ../bin/ecdsa_keygen_bearssl-O3_32

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
