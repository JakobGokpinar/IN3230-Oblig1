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
        printf("Sending to MAC: %02x:%02x:%02x:%02x:%02x:%02x via if %d\n",
            dst_node->sll_addr[0], dst_node->sll_addr[1], dst_node->sll_addr[2],
            dst_node->sll_addr[3], dst_node->sll_addr[4], dst_node->sll_addr[5],
            dst_node->sll_ifindex);
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

    // Choose the right destination sockaddr_ll
    struct sockaddr_ll *send_addr;
    if (dst_node) {
        send_addr = dst_node;
    } else {
        // For broadcast, use first interface
        send_addr = &interfaces->addr[0];
    }

    // CRITICAL FIX: Ensure interface index is set correctly
    if (send_addr->sll_ifindex == 0) {
        send_addr->sll_ifindex = interfaces->addr[0].sll_ifindex;
    }


    msg.msg_name = send_addr;
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = &msgvec;
    msg.msg_iovlen = 1;


    printf("Attempting to send MIP packet: src=%d, dst=%d, type=0x%02x, len=%zu via if=%d\n",
        src_mip, dst_mip, sdu_type, sdu_len, send_addr->sll_ifindex);

    rc = sendmsg(interfaces->rsock, &msg, 0);
    if (rc == -1) {
        printf("Error sendmsg in common.c send_mip_packet\n");
        perror("sendmsg");
        printf("Interface details: family=%d, ifindex=%d\n", 
            send_addr->sll_family, send_addr->sll_ifindex);
        return -1;
    }
    printf("send_mip_packet successfully sent %d bytes\n", rc);
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

void debug_interfaces(struct ifs_data *interfaces) {
    printf("\n=== Interface Debug Info ===\n");
    printf("Number of interfaces found: %d\n", interfaces->ifn);
    
    for (int i = 0; i < interfaces->ifn; i++) {
        printf("Interface %d:\n", i);
        printf("  Family: %d\n", interfaces->addr[i].sll_family);
        printf("  Protocol: 0x%04x\n", interfaces->addr[i].sll_protocol);
        printf("  Interface Index: %d\n", interfaces->addr[i].sll_ifindex);
        printf("  MAC Address: ");
        print_mac_addr(interfaces->addr[i].sll_addr, 6);
        printf("  Address Length: %d\n", interfaces->addr[i].sll_halen);
    }
    printf("==============================\n\n");
}
/* end common.c */