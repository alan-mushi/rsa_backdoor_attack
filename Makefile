CC=gcc
CFLAGS=-Wall -O3 -g

all: main

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

main: wiener.o main.o
	$(CC) $(CFLAGS) -o $@ -lssl -lcrypto $^

clean:
	rm -f *.o main 2> /dev/null
