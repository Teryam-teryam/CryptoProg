CC=g++
CFLAGS=-std=c++11 -Wall -Wextra
LDFLAGS=-lcryptopp

all: crypto

crypto: crypto.cpp
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f crypto
