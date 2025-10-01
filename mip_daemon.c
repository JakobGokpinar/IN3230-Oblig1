/* mip_daemon.c - Complete fixed version */

#include "common.h"

void update_arp_table(uint8_t mip_addr, uint8_t* mac_addr, int if_index);
struct sockaddr_ll* find_mac_for_mip(uint8_t mip_addr);

struct mip_arp_table arp_table[MAX_ARP_TABLE_ENTRIES];
int arp_table_size = 0;
uint8_t my_mip_addr = 0;

#define MAX_CLIENTS 10
int clients[MAX_CLIENTS];
int num_clients = 0;

void add_client(int fd) {
    if (num_clients < MAX_CLIENTS) {
        //fd stands for file descriptor - it's a unique integer that the operating system assigns to each open file, socket, or I/O resource.
        clients[num_clients++] = fd; 
        printf("[Daemon] add_client(): client with fd=%d (total clients on host: %d)\n", fd, num_clients);
    }
}

void remove_client(int fd) {
    for (int i = 0; i < num_clients; i++) {
        if (clients[i]== fd) {
            // Shift remaining clients down
            for (int j = i; j < num_clients - 1; j++) {
                clients[j] = clients[j + 1];
            }
            num_clients--;
            printf("[Daemon] remove_client() client fd=%d (number of clients on host: %d)\n", fd, num_clients);
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *unix_path = argv[1];
    my_mip_addr = atoi(argv[2]);

    if (argc == 4) {
        unix_path = argv[2];
        my_mip_addr = atoi(argv[3]);
    }

    struct ifs_data interfaces;
    int rsocket;
    int epollfd;
    struct epoll_event ev; 
    struct epoll_event events[MAX_EVENTS];
    int rc;

    struct sockaddr_ll source_node;
    struct ether_frame ether_frame;
    struct mip_header *mip_hdr;
    struct arp_header *arp_hdr, arp_req;

    int usocket;
    struct sockaddr_un usock_addr = {0};
    int wc;

    printf("<info> I am host %s with MIP addr: %u\n", unix_path, my_mip_addr);
    
    // 1. RAW Socket Setup
    rsocket = create_raw_socket();
    init_ifs(&interfaces, rsocket);
    debug_interfaces(&interfaces);

    //ARP broadcasting discovery
    arp_req.type = MIP_ARP_REQUEST;
    arp_req.addr = 0xFF; // broadcast discovery
    memset(arp_req.padding, 0, sizeof(arp_req.padding));
    send_mip_packet(&interfaces, my_mip_addr, 0xFF, SDU_MIP, 
                    sizeof(arp_req), (uint8_t*)&arp_req, NULL);
    sleep(1);
    printf("[Daemon] ARP discovery complete\n\n");

    // 2. UNIX Socket setup
    usocket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (usocket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    // Unlink old socket path
    unlink(unix_path);
    
    // 2.2 Initialize the struct sockaddr *addr
    usock_addr.sun_family = AF_UNIX;
    strncpy(usock_addr.sun_path, unix_path, sizeof(usock_addr.sun_path)-1);

    // 2.3 Bind the socket and address space together
    wc = bind(usocket, (struct sockaddr*)&usock_addr, sizeof(usock_addr));
    if (wc < 0) {
        perror("bind unix");
        exit(EXIT_FAILURE);
    }

    // 2.4 CRITICAL FIX: Make the socket listen for connections
    if (listen(usocket, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // 3. Epoll setup
    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = rsocket;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, rsocket, &ev) == -1) {
        perror("epoll_ctl: rsocket");
        exit(EXIT_FAILURE);
    }
    
    ev.events = EPOLLIN;
    ev.data.fd = usocket;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, usocket, &ev) == -1) {
        perror("epoll_ctl: usock");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int n = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == rsocket) {
                // Handle incoming MIP packets from network
                rc = recv_mip_frame(&interfaces, &ether_frame, &source_node);
                if (rc <= 0) continue;

                mip_hdr = (struct mip_header*)ether_frame.payload;
                size_t sdu_len = mip_hdr->sdu_len * 4;
                uint8_t* sdu = ether_frame.payload + sizeof(struct mip_header);
                arp_hdr = (struct arp_header*)sdu;

                if (mip_hdr->sdu_type == SDU_MIP) {
                    switch (arp_hdr->type) {
                        case MIP_ARP_REQUEST: {
                            //printf("[Daemon] Received ARP request for MIP %d from MIP %d\n", mip_hdr->dst, mip_hdr->src);
                            
                            update_arp_table(mip_hdr->src, ether_frame.src_addr, source_node.sll_ifindex);

                            if (mip_hdr->dst == my_mip_addr || mip_hdr->dst == 0xFF) {
                                struct arp_header arp_resp;
                                arp_resp.type = MIP_ARP_RESPONSE;
                                arp_resp.addr = my_mip_addr;
                                memset(arp_resp.padding, 0, sizeof(arp_resp.padding));

                                send_mip_packet(&interfaces, my_mip_addr, mip_hdr->src, SDU_MIP, 
                                              sizeof(arp_resp), (uint8_t*)&arp_resp, &source_node);
                                printf("[Daemon] Sent ARP response to MIP %d\n", mip_hdr->src);
                            }
                        } break;

                        case MIP_ARP_RESPONSE: {
                            printf("[Daemon] Received ARP response from MIP %d\n", arp_hdr->addr);
                            update_arp_table(arp_hdr->addr, ether_frame.src_addr, source_node.sll_ifindex);
                        } break;

                        default: 
                            printf("Unknown arp header type: 0x%02x\n", arp_hdr->type);
                        break;
                    }
                    
                } else if (mip_hdr->sdu_type == SDU_PING) {
                    printf("[Daemon] Received MSG from MIP %d to MIP %d\n", mip_hdr->src, mip_hdr->dst);
                    
                    if (mip_hdr->dst == my_mip_addr) {
                        // This ping is for us - forward to upper layer
                        uint8_t outbuf[1500];
                        outbuf[0] = mip_hdr->src; // who it came from
                        memcpy(outbuf+1, sdu, sdu_len); // copy the message
                        
                        // Forward to ALL connected clients (server and/or clients)
                        for (int j = 0; j < num_clients; j++) {
                            int sent = send(clients[j], outbuf, sdu_len+1, 0);
                            if (sent > 0) {
                                printf("[Daemon] Forwarded packet to client fd=%dn", clients[j]);
                            }
                        }

                    } 
                    /*else {
                        printf("[Daemon] PING not for us (dst=%d, we are %d)\n", mip_hdr->dst, my_mip_addr);
                    }*/
                } else {
                    printf("Unknown sdu type: 0x%02x\n", mip_hdr->sdu_type);
                }
                
            } else if (events[i].data.fd == usocket) {
                // New client connection
                struct sockaddr_un client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(usocket, (struct sockaddr*)&client_addr, &client_len);
                
                if (client_fd < 0) {
                    perror("accept");
                    continue;
                }
                
                printf("[Daemon] New client connected (fd=%d)\n", client_fd);
                add_client(client_fd);
                
                // Add client socket to epoll
                struct epoll_event client_ev;
                client_ev.events = EPOLLIN;
                client_ev.data.fd = client_fd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &client_ev) == -1) {
                    perror("epoll_ctl: client");
                    close(client_fd);
                    remove_client(client_fd);
                    continue;
                }
                
            } else {
                // This is a client socket (ping_client or ping_server)
                int client_fd = events[i].data.fd;
                uint8_t buf[1500];
                int nbytes = recv(client_fd, buf, sizeof(buf), 0);
                
                if (nbytes <= 0) {
                    // Client disconnected
                    printf("[Daemon] Client fd=%d disconnected\n", client_fd);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, client_fd, NULL);
                    close(client_fd);
                    remove_client(client_fd);
                    continue;
                }
                
                if (nbytes > 1) {
                    uint8_t dst_mip = buf[0];
                    uint8_t *payload = buf + 1;
                    size_t payload_len = nbytes - 1;

                    //printf("[Daemon] Client fd=%d wants to send to MIP %d: %.*s\n", client_fd, dst_mip, (int)payload_len, payload);

                    struct sockaddr_ll *dst_node = find_mac_for_mip(dst_mip);

                    if (!dst_node) {
                        printf("[Daemon] No ARP entry for MIP %d, sending ARP request\n", dst_mip);
                        struct arp_header arp_req;
                        arp_req.type = MIP_ARP_REQUEST;
                        arp_req.addr = dst_mip;
                        memset(arp_req.padding, 0, sizeof(arp_req.padding));
                        
                        send_mip_packet(&interfaces, my_mip_addr, dst_mip, SDU_MIP, 
                                      sizeof(arp_req), (uint8_t*)&arp_req, NULL);
                        
                        //printf("[Daemon] Packet dropped - ARP resolution needed\n");
                        continue;
                    }

                    // Send out via raw socket
                    send_mip_packet(&interfaces, my_mip_addr, dst_mip, SDU_PING, payload_len, payload, dst_node);
                    printf("[Daemon] Sent MIP packet to %d\n", dst_mip);
                }
            }
        }
    }
}

void update_arp_table(uint8_t mip_addr, uint8_t* mac_addr, int if_index) {
   /* printf("[ARP] Learned MIP %d -> MAC %02x:%02x:%02x:%02x:%02x:%02x via if %d\n",
        mip_addr,
        mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
        if_index);*/

    // Check if MIP is already in the table
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].mip_addr == mip_addr) {
            // Update existing entry
            memcpy(arp_table[i].mac_addr, mac_addr, 6);
            arp_table[i].interface_index = if_index;
            return;
        }
    }

    // Add new entry if not found
    if (arp_table_size < MAX_ARP_TABLE_ENTRIES) {
        arp_table[arp_table_size].mip_addr = mip_addr;
        memcpy(arp_table[arp_table_size].mac_addr, mac_addr, 6);
        arp_table[arp_table_size].interface_index = if_index;
        arp_table_size++;
    } else {
        fprintf(stderr, "ARP table is full, cannot add new MIP %u\n", mip_addr);
    }
}

struct sockaddr_ll* find_mac_for_mip(uint8_t mip_addr) {
    static struct sockaddr_ll dest_addr;
    
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].mip_addr == mip_addr) {
            dest_addr.sll_family = AF_PACKET;
            dest_addr.sll_ifindex = arp_table[i].interface_index;
            memcpy(dest_addr.sll_addr, arp_table[i].mac_addr, 6);
            return &dest_addr;
        }
    }
    return NULL; // Not found
}

/* end mip_daemon.c */


