/* common.c */

#include "common.h"

void print_mac_addr(uint8_t *addr, size_t len)
{
    size_t i;
    for (i = 0; i < len - 1; i++)
        printf("%02x:", addr[i]);
    printf("%02x\n", addr[i]);
}

// Find all network interfaces on the machine and store them (with MAC addresses)
void get_mac_from_interfaces(struct ifs_data *ifs)
{
    struct ifaddrs *ifaces, *ifp;
    int i = 0;

    // get linked list of interfaces
    if (getifaddrs(&ifaces)) {
        perror("getifaddrs");
        exit(-1);
    }

    for (ifp = ifaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr != NULL && //ifa_addr: AF_PACKET
            ifp->ifa_addr->sa_family == AF_PACKET &&
            strcmp("lo", ifp->ifa_name))
        {
            if (i < MAX_IFS) {
                memcpy(&(ifs->addr[i++]),
                       (struct sockaddr_ll*)ifp->ifa_addr,
                       sizeof(struct sockaddr_ll));
            }
        }
    }
    ifs->ifn = i;
    freeifaddrs(ifaces);
}

void init_ifs(struct ifs_data *ifs, int rsock)
{
    get_mac_from_interfaces(ifs);
    ifs->rsock = rsock;
}

/* Create RAW packet socket */
int create_raw_socket(void)
{
    int sd;
    /* We'll open ETH_P_ALL and filter in user space */
    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP)); // kernel delivers only frames with Ethertype 0x88B5 (eth_p_mip)
    if (sd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    return sd;
}

/* ARP and MIP are 2 different things
* ARP -> L2, find MAC addresses
* MIP -> Can be a Arp or a Ping
*/
/* Send a broadcast MIP-ARP request for lookup of some address (my_mip is our MIP addr) */
int send_arp_request(struct ifs_data *ifs)
{
	struct ether_frame frame_hdr;
	struct msghdr	*msg;
	struct iovec	msgvec[1];
	int    rc;

	/* Fill in Ethernet header. ARP request is a BROADCAST packet. */
	uint8_t dst_addr[] = ETH_BROADCAST;
	memcpy(frame_hdr.dst_addr, dst_addr, 6);
	memcpy(frame_hdr.src_addr, ifs->addr[0].sll_addr, 6);
	/* Match the ethertype in packet_socket.c: */
	frame_hdr.eth_proto[0] = frame_hdr.eth_proto[1] = 0xFF;

	/* Point to frame header */
	msgvec[0].iov_base = &frame_hdr;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	/* Allocate a zeroed-out message info struct */
	msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));

	/* Fill out message metadata struct */
	/* host A and C (senders) have only one interface, which is stored in
	 * the first element of the array when we walked through the interface
	 * list.
	 */
	msg->msg_name	 = &(ifs->addr[0]);
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iovlen	 = 1;
	msg->msg_iov	 = msgvec;

	/* Send message via RAW socket */
	rc = sendmsg(ifs->rsock, msg, 0);
	if (rc == -1) {
		perror("sendmsg");
		free(msg);
		return -1;
	}

	/* Remember that we allocated this on the heap; free it */
	free(msg);

	return rc;
}

int handle_arp_packet(struct ifs_data *ifs)
{
	struct sockaddr_ll so_name;
	struct ether_frame frame_hdr;
	struct msghdr	msg = {0};
	struct iovec	msgvec[1];
	int    rc;

	/* Point to frame header */
	msgvec[0].iov_base = &frame_hdr;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	/* Fill out message metadata struct */
	msg.msg_name	= &so_name;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iovlen	= 1;
	msg.msg_iov	= msgvec;

	rc = recvmsg(ifs->rsock, &msg, 0);
	if (rc <= 0) {
		perror("sendmsg");
		return -1;
	}

	/* Send back the ARP response via the same receiving interface */
	/* Send ARP response only if the request was a broadcast ARP request
	 * This is so dummy!
	 */
	int check = 0;
	uint8_t brdcst[] = ETH_BROADCAST;
	for (int i = 0; i < 6; i++) {
		if (frame_hdr.dst_addr[i] != brdcst[i])
		check = -1;
	}
	if (!check) {
		/* Handling an ARP request */
		printf("\nWe received a handshake offer from the neighbor: ");
		print_mac_addr(frame_hdr.src_addr, 6);

		/* print the if_index of the receiving interface */
		printf("We received an incoming packet from iface with index %d\n",
		       so_name.sll_ifindex);

		rc = send_arp_response(ifs, &so_name, &frame_hdr);
		if (rc < 0)
		perror("send_arp_response");
	}

	/* Node received an ARP Reply */
	printf("\nHello from neighbor ");
	print_mac_addr(frame_hdr.src_addr, 6);

	return rc;
}

/* send_arp_response: given the received frame, turn it around and unicast reply 
* @param interfaces: contains raw socket
* @param @node: the destination node we want to send to and we got the initial package from 
* @param eframe: Pointer to the buffer where the function will put the Ethernet frame  
* Return: number of bytes sent through raw socket
*/
int send_arp_response(struct ifs_data *interfaces, struct sockaddr_ll *node, struct ether_frame *eframe)
{
    struct mip_header *mip_header = (struct mip_header*)eframe->payload; //eframe->payload begins with a mip_header;
    struct arp_header *arp_header = (struct arp_header*)(eframe->payload + sizeof(struct mip_header));
    struct msghdr msg = {0}; //Allocate on stack
    struct iovec iov; //We need only once read/write operation
    int rc;

    /* Put source addr into destination addr. Swap */
    memcpy(eframe->dst_addr, eframe->src_addr, 6);

    /* Find the right sender and put it into source addr 
    *  Initial destination address is now the source address 
    */
    for (int i = 0; i < interfaces->ifn; i++) {
        if (interfaces->addr[i].sll_ifindex == node->sll_ifindex) {
            memcpy(eframe->src_addr, interfaces->addr[i].sll_addr, 6);
            break;
        }
    }

    mip_header->dst = mip_header->src; //Fill Mip address. eframe->dst_addr gives MAC address
    mip_header->ttl = 1;
    mip_header->sdu_len = 1;
    mip_header->sdu_type = SDU_MIP;

    arp_header->type = MIP_ARP_RESPONSE;
    arp_header->addr = mip_header->src;
    memset(arp_header->padding, 0, sizeof(arp_header->padding));

    // Set Ethertype to MIP
    eframe->eth_proto[0] = (ETH_P_MIP >> 8) & 0xFF; //low-byte
    eframe->eth_proto[1] = ETH_P_MIP & 0xFF; // high-byte

    iov.iov_base = eframe;
    iov.iov_len = sizeof(struct ether_frame);

    msg.msg_name = node;
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    rc = sendmsg(interfaces->rsock, &msg, 0);
    if (rc == -1) {
        perror("sendmsg");
        return -1;
    }
    return rc;
}

/* Convenience: send a MIP packet (constructs ether_frame with MIP header in payload)
   sdu is raw bytes (not padded); sdu_len is bytes. Returns bytes sent or -1. 

* Unifying function for all outgoing MIP traffic (ARP responses, SDU_PING)
* @param interfaces: contains raw socket
* @param src_mip/dst_mip: MIP addresses
* @param sdu_type: Mip-Arp or Sdu_Ping
* @param sdu_len: payload len (arp_header)
* @param sdu: payload (arp_header)
* @param dst_node: destination Ethernet interface (from ARP table or Broadcast)
* Return: number of bytes sent
*/
int send_mip_packet(struct ifs_data *interfaces, uint8_t src_mip, uint8_t dst_mip, uint8_t sdu_type, size_t sdu_len, const uint8_t *sdu, struct sockaddr_ll *dst_node)
{
    struct ether_frame eframe;
    struct mip_header mip_hdr;
    struct msghdr msg = {0};
    struct iovec msgvec;
    int rc;

    // 1. Build the Ethernet Frame
    // Set destination MAC address
    if (dst_node) {
        memcpy(eframe.dst_addr, dst_node->sll_addr, 6);
    } else {
        //Fall back to Broadcast
        uint8_t broadcast[6] = ETH_BROADCAST;
        memcpy(eframe.dst_addr, broadcast, 6);
    }
    // Source Mac address
    memcpy(eframe.src_addr, interfaces->addr[0].sll_addr, 6); //why addr[0].sll_addr?
    // Ethertype for MIP
    eframe.eth_proto[0] = (ETH_P_MIP >> 8) & 0xFF;
    eframe.eth_proto[1] = ETH_P_MIP & 0xFF;

    // 2. Build MIP Data Unit (PDU - Header + SDU)
    mip_hdr.dst = dst_mip;
    mip_hdr.src = src_mip;
    mip_hdr.ttl = 15;  // default TTL
    mip_hdr.sdu_len = (sdu_len + 3) / 4; // in 32-bit words, length or arp_header
    mip_hdr.sdu_type = sdu_type; //ARP or Ping

    memcpy(eframe.payload, &mip_hdr, sizeof(mip_hdr));
    if (sdu_len > sizeof(eframe.payload) - sizeof(mip_hdr)) {
        sdu_len = sizeof(eframe.payload) - sizeof(mip_hdr);
    }
    // Put arp_header into payload
    memcpy(eframe.payload+sizeof(mip_hdr), sdu, sdu_len);

    msgvec.iov_base = &eframe;
    msgvec.iov_len  = sizeof(eframe);

    msg.msg_name = dst_node; // or &ifs->addr[0] if broadcast
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = &msgvec;
    msg.msg_iovlen = 1;

    rc = sendmsg(interfaces->rsock, &msg, 0);
    if (rc == -1) {
        printf("Error sendmsg in common.c send_mip_packet\n");
        perror("sendmsg");
        return -1;
    }
    return rc;
}

/*
* @param interfaces: has raw socket, interfaces, MACs
* Return: bytes processed
* Side-effects:
* Updated MIP-to-MAC mapping table
* Sends ARP responses
* Passes MIP packets to upper layer
*/
int handle_mip_packet(struct ifs_data* interfaces)
{
	struct sockaddr_ll  so_name;
	struct ether_frame  ether_frame;
    struct msghdr msg = {0};
	struct iovec        msgvec[3];
	uint8_t             packet[256];
	int                 rc;

	msgvec[0].iov_base = &ether_frame;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	msgvec[2].iov_base = (void *)packet;
	msgvec[2].iov_len  = 256;

	msg.msg_name    = &so_name;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iovlen  = 3;
	msg.msg_iov     = msgvec;

	rc = recvmsg(interfaces->rsock, &msg, 0);
	if (rc <= 0) {
		perror("sendmsg");
		return -1;
	}

	printf("<info>: We got a MIP pkt. with content 's' from node d with MAC addr.: ");
	print_mac_addr(ether_frame.src_addr, 6);

	return rc;
}

/*
* @param interfaces: Holds the raw socket
* @param eframe: A pointer to the buffer where the function will put the received Ethernet frame  
* @Return number of bytes received from Ethernet
*/
int recv_mip_frame(struct ifs_data* interfaces, struct ether_frame* eframe, struct sockaddr_ll* source_node)
{
    // Zero-initialize the entire struct. 
    // Source address of the received frame
    struct sockaddr_ll from = {0}; 
    struct msghdr msg = {0}; //zero-initialize the entire struct.

    // Build a msghdr and iovec so we can call recvmsg().
    struct iovec iov[1]; 
    ssize_t rc;

    iov[0].iov_base = eframe; //point to the frame buffer
    iov[0].iov_len = sizeof(struct ether_frame); //max size to receive
    
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    //recvmsg() pulls in the next Ethernet frame from the raw socket.
    //If data arrives successfully → the function copies it into your eframe.
    rc = recvmsg(interfaces->rsock, &msg, 0);
    if (rc <= 0) {
        perror("recvmsg");
        return -1;
    }

    if (source_node)
        *source_node = from;  // copy received interface info back to caller
    
    return rc;
}

/* end common.c */