CC=g++
CFLAGS=-std=c++11 -Wall -Wextra -O2
LDFLAGS=-lcryptopp

all: e_d

e_d: e_d.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

e_d.o: e_d.cpp
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f *.o e_d

.PHONY: all clean
