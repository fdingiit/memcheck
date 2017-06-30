CC ?= gcc
LDFLAGS +=-Wl,--no-as-needed -ldl -m32
#CFLAGS=-g -O2 -Wall
CFLAGS +=-g -std=c99 -Wall -Wformat=0 -m32

all: memcheck.so

memcheck.o: memcheck.c mhash.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

memcheck.so: memcheck.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

.PHONY: clean
clean:
	rm -f *.o *.so
