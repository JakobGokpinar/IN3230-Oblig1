CC = gcc
CFLAGS = -Wall -g

all: mip_daemon ping_server ping_client

mip_daemon: mip_daemon.c common.c common.h
	$(CC) $(CFLAGS) -o mip_daemon mip_daemon.c common.c

ping_server: ping_server.c common.c common.h
	$(CC) $(CFLAGS) -o ping_server ping_server.c common.c

ping_client: ping_client.c common.c common.h
	$(CC) $(CFLAGS) -o ping_client ping_client.c common.c

clean:
	rm -f mip_daemon ping_server ping_client