# Socket System Calls Cheat Sheet
(My own notes for using different functions in socket programming)

### send() vs write()
- `write()` → generic system call, works on any file descriptor.
- `send()` → socket-specific.

### send() vs sendto()
- `sendto()` → requires specifying dest. address with each call.
- `send()` → assumes the socket is already connected (after `connect()`).

### read() vs recv()
- Same story as `send()` vs `write()`.

### SOCK_SEQPACKET vs SOCK_STREAM
- `SOCK_STREAM` → TCP.
- `SOCK_SEQPACKET` → message boundaries preserved, great for ping/pong style.

### bind()
- Tells the OS where the socket lives.

### listen()
- Marks socket as passive; will accept incoming connections.

### accept()
- Takes one connection request off the backlog created by `listen()`.

### memset()
- Zero-out `struct sockaddr_un` before filling it.

### epoll() vs select()
- `select()` → monitor several file descriptors, wait until ready.
- `epoll()` → more scalable and efficient.

### recvmsg() vs recv()
- `recv()` → simplest way, just puts bytes into buffer.
- `recvmsg()` → advanced, can return metadata too.

### sendmsg() vs send()
- `send()` → simple, one buffer, common for TCP/UDP.
- `sendmsg()` → powerful, can send multiple buffers (`struct iovec[]`), uses `struct msghdr`.

```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);