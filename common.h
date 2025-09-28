/* common.h - shared types & prototypes for IN3230 MIP assignment */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <net/if.h>        // for if_nametoindex and struct ifreq
#include <linux/if_ether.h>   // for ETH_P_ALL and ETH_P_xxx
#include <sys/epoll.h>
#include <time.h>
#include <poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/ethernet.h>	/* ETH_*, ETH_DATA_LEN=1500 */
#include <arpa/inet.h>		/* htons */

#define ETH_BROADCAST {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

#define MAX_IFS 3
#define MAX_EVENTS 10
#define MAX_ARP_TABLE_ENTRIES 10

#define SDU_MIP 0x01
#define SDU_PING 0x02

#define MIP_ARP_REQUEST 0x00
#define MIP_ARP_RESPONSE 0x01

/* 
* Custom EtherType for MIP. 
* All outgoing packets must set Ethertype to 0x88B5.
* Socket filters incoming packets by Ethertype (only MIP). 
* RAW socket capturing Ethernet frames with a given Ethertype identifying MIP traffic: ETH_P_MIP
*/ 
#define ETH_P_MIP 0x88B5 


/* A simple ether frame container used by this assignment */
struct ether_frame {
    uint8_t dst_addr[6]; /* 6-byte MAC addr */
    uint8_t src_addr[6]; /* 6-byte MAC addr */
    uint8_t eth_proto[2]; /* network byte order expected by some code; we keep opaque */
    uint8_t payload[ETH_DATA_LEN]; // Standard Ethernet has an MTU of 1500 bytes, maximum payload size ever see in a normal Ethernet frame.
} __attribute__((packed));

/* 
* MIP header layout (32 bits).
* Also known as 'Mip Pdu'
* Mip Pdu = Header + Sdu
*/
struct mip_header {
    uint8_t dst;        // 8-bits   0xff   1
    uint8_t src;        // 8-bits   1      5
    uint8_t ttl: 4;      /* 4 bits used */
    uint16_t sdu_len: 9; /* 9 bits used (value in 32-bit words) */
    uint8_t sdu_type: 3; /* 3-bits, 0x01 MIP-ARP, 0x02-Ping*/
};

/*
* Also known as 'Mip Sdu'
*/
struct arp_header {
    uint8_t type; /* 1-bit, 0x00 Request, 0x01 Response*/
    uint8_t addr; // 5   5
    uint8_t padding[3];
} __attribute__((packed));

/* Store MIP address -> MAC address mapping */
struct mip_arp_table {
    uint8_t mip_addr;        // 8-bit MIP address
    uint8_t mac_addr[6];          // corresponding MAC address
    int interface_index;            // interface where MAC is reachable
};

/* abstraction for all the network interfaces the daemon will use. */
struct ifs_data {
    struct sockaddr_ll addr[MAX_IFS]; //one element per network interface
    int ifn;      /* number of interfaces stored */
    int rsock;    /* raw socket descriptor */
    uint8_t mip_addrs[MAX_IFS]; /* Store Mip address of each interface */
};

void print_mac_addr(uint8_t *addr, size_t len);
void get_mac_from_interfaces(struct ifs_data *ifs);
void init_ifs(struct ifs_data *ifs, int rsock);
int create_raw_socket(void);

//int send_arp_request(struct ifs_data *ifs);
//int handle_arp_packet(struct ifs_data *ifs);
//int send_arp_response(struct ifs_data *ifs, struct sockaddr_ll*, struct ether_frame *eframe);

int send_mip_packet(struct ifs_data*, uint8_t src_mip, uint8_t dst_mip, uint8_t sdu_type, size_t sdu_len, const uint8_t *sdu, struct sockaddr_ll*);

//int handle_mip_packet(struct ifs_data *);

int recv_mip_frame(struct ifs_data *ifs, struct ether_frame*, struct sockaddr_ll*);
void debug_interfaces(struct ifs_data *interfaces);

#endif /* COMMON_H */