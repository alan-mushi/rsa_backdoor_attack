CC=gcc
CFLAGS=-Wall -O0 -ggdb

.PHONY: all

all: wiener main

wiener: wiener.c
	$(CC) $(CFLAGS) -c -o $@.o $<

main: wiener
	$(CC) $(CFLAGS) -o $@ $@.c -lssl -lcrypto $<.o
