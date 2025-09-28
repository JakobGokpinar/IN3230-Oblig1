/* ping_client.c start */

#include "common.h"

/*
* Ping Client properties:
* Does not have MAC addr.
* Has MIP addr. 
*/
/* Client should know the MIP addr of the destination
 Client should know the the message it sends 
*/
int main(int argc, char *argv[]) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s [-h] <socket_lower> <message> <destination_host>\n", argv[0]); //socket lower: e.g. usockA, dst_host: e.g 20
		exit(EXIT_FAILURE);
	}

	char *unix_path = argv[1];
	char *user_msg  = argv[2];
	uint8_t dst_mip = (uint8_t)atoi(argv[3]);

    printf("<info> I am ping client with socket: %s, msg: %s, host destination: %u\n", unix_path, user_msg, dst_mip);

	int socketfd;
	struct sockaddr_un addr;
	int rc;
	char payload[1500];
	uint8_t output_buf[1500];
	uint8_t in_buf[1500];
	char *reply_msg;
    struct timespec t0; 
	struct timespec t1;

	socketfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (socketfd < 0) {
		printf("Error in ping_client.c socket\n");
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path)-1);

	/* int sockfd, struct sockaddr *addr, socklen_t addrlen */
	rc = connect(socketfd, (struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) {
		printf("ping_client got erron in connect()");
		perror("connect");
        close(socketfd);
        exit(EXIT_FAILURE);
	}

	int n = snprintf(payload, sizeof(payload), "PING:%s", user_msg); //Format a string safely into a buffer. Instead of printing to standard output, it writes the formatted result into a character array
	if (n < 0 || n >= (int)sizeof(payload)) {
        fprintf(stderr, "message too long\n");
        close(socketfd);
        return EXIT_FAILURE;
    }

	output_buf[0] = dst_mip;
	memcpy(output_buf+1, payload, (size_t)n + 1); //Include the '0'

	clock_gettime(CLOCK_MONOTONIC, &t0); // get time before sending

	//payload + '0' + dst_mip
	rc = send(socketfd, output_buf, (size_t)n + 1 + 1, 0);
	if (rc < 0) {
		perror("send");
		close(socketfd);
		exit(EXIT_FAILURE);
	}

	// Wait up to 1000 ms for reply
	struct pollfd pfd = { .fd = socketfd, .events = POLLIN };
	int pret = poll(&pfd, 1, 1000);
	if (pret == 0) {
		printf("timeout\n");
		close(socketfd);
		return 0;
	}
	if (pret < 0) {
		perror("poll");
		close(socketfd);
		exit(EXIT_FAILURE);
	}


	rc = recv(socketfd, in_buf, sizeof(in_buf)-1, 0); //make place for '0' at the end
	if (rc <= 0) {
        perror("recv");
        close(socketfd);
        exit(EXIT_FAILURE);
    }
	in_buf[rc] = '\0';

	clock_gettime(CLOCK_MONOTONIC, &t1); //get time after receiving

	double rtt_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                  + (t1.tv_nsec - t0.tv_nsec) / 1e6;

	uint8_t src_mip = in_buf[0]; // who replied to us
	reply_msg = (char*)(in_buf + 1);

	if (strncmp(reply_msg, "PONG:", 5) == 0) {
		printf("from %u: %s (%.2f ms)\n", src_mip, reply_msg, rtt_ms); //print details
	} else {
		printf("unexpected reply from %u: %s (%.2f ms)\n", src_mip, reply_msg, rtt_ms); //unexpected msg
	}

	close(socketfd);
	return 0;
}

/* ping_client.c end */