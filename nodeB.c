#include <stdlib.h> /*free*/
#include <stdio.h> /*printf*/

#include <string.h> /*memset*/

#include <sys/epoll.h> /*epoll*/

#include "common.h"

int main(){
	struct ifs_data local_ifs;
	int raw_sock, rc;

	struct epoll_event ev, events[MAX_EVENTS];
	int epollfd;

	raw_sock = create_raw_socket();
	init_ifs(&local_ifs, raw_sock, MIP_ADDR_B); //store interface node addresses

	//set up epoll
	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("epoll_create1");
		close(raw_sock);
		exit(EXIT_FAILURE);
	}

	//Adding raw socket to epoll
	ev.events = EPOLLIN|EPOLLHUP; //fd for Read | hup for always monitor
	ev.data.fd = raw_sock;

	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
		perror("epoll_ctl: raw_sock");
		exit(EXIT_FAILURE);
	}

	printf("\n<nodeB> Hi! My MAC address is: ");
	print_mac_addr(local_ifs.addr[0].sll_addr, 6);
	
	//epoll waits forever for incoming packets
	while(1){
		rc = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if(rc == -1) {
			perror("epoll wait");
			break;
		} else if (events->data.fd == raw_sock) {
			printf("\n <info> nodeA PING\n");
			rc = handle_mip_packet(&local_ifs);
			if (rc<1) {
				printf("We got an error in receiver.c \n");
				perror("recv");
				break;
			}
			uint8_t dst_addr[] = ETH_MAC_A;
			uint8_t packet[] = "PONG";
			send_mip_packet(&local_ifs, dst_addr, MIP_ADDR_B, packet);
		}
	}
	close(raw_sock);
	return 0;
}
