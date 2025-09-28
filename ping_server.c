/* start ping_server */

#include "common.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-h] <socket_lower>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *unix_path = argv[1]; //socket_lower e.g. usockB
    printf("<info> I am host server with socket: %s\n", unix_path);

	int serverfd;
	struct sockaddr_un addr;
	int rc;
	uint8_t buf[1500];

	/*
	* Message Format that comes to ping_server:
	* First byte: MIP address (who sent the message)
	* The rest: SDU payload (ping text)
	*/

	// 1. Create Unix Socket
	serverfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (serverfd < 0) { 
		perror("socket"); 
		exit(EXIT_FAILURE); 
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);

	// 2. Connect to the deamons's Socket
	/* int socket_fd, const struct sockaddr* addr, socklen_t addrlen */
	// We didn't use listen() and accept() because we don't want multiple connections to the server at the same time
	rc = connect(serverfd, (struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) {
		printf("Error in connect() in ping_server \n");
		perror("connect"); 
		close(serverfd);
		exit(EXIT_FAILURE);
	}	

	// 3. Loop: receive pings, respond with PONG
	while (1) {
		int nbytes = recv(serverfd, buf, sizeof(buf)-1, 0);
		if (nbytes <= 0) {
            perror("recv");
            break;
        }

		uint8_t src_addr = buf[0]; //Source MIP addr.
		buf[nbytes] = '\0';
		char *msg = (char *)(buf + 1);

		printf("[PingServer] Got PING from %u: %s\n", src_addr, msg);

		// Build reply
        char reply[1500];
        snprintf(reply, sizeof(reply), "PONG:%s", msg);

        // First byte must be destination MIP (the original sender)
        uint8_t output_buf[1500];
        output_buf[0] = src_addr;
        strcpy((char*)(output_buf + 1), reply);

        // Send back to daemon
        send(serverfd, output_buf, strlen(reply)+1, 0);
	}
    close(serverfd);
    return 0;
}

/* end ping_server */
