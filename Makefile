CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -pthread -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto
TARGETS = server client

.PHONY: all clean

all: $(TARGETS)

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

clean:
	rm -f $(TARGETS) *.o

run-server: server
	./server

run-client: client
	./client
