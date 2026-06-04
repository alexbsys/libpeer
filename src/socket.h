#ifndef SOCKET_H_
#define SOCKET_H_

#include "address.h"

typedef struct UdpSocket {
  int fd;
  Address bind_addr;
} UdpSocket;

#define TCP_SOCKET_RX_CAP 16384

typedef struct TcpSocket {
  int fd;
  Address bind_addr;
  uint8_t rx_buf[TCP_SOCKET_RX_CAP];
  int rx_len;
} TcpSocket;

int udp_socket_open(UdpSocket* udp_socket, int family, int port);

int udp_socket_bind(UdpSocket* udp_socket, int port);

void udp_socket_close(UdpSocket* udp_socket);

int udp_socket_sendto(UdpSocket* udp_socket, Address* bind_addr, const uint8_t* buf, int len);

int udp_socket_recvfrom(UdpSocket* udp_sock, Address* bind_addr, uint8_t* buf, int len);

int udp_socket_add_multicast_group(UdpSocket* udp_socket, Address* mcast_addr);

int tcp_socket_open(TcpSocket* tcp_socket, int family);

int tcp_socket_connect(TcpSocket* tcp_socket, Address* addr);

void tcp_socket_close(TcpSocket* tcp_socket);

int tcp_socket_send(TcpSocket* tcp_socket, const uint8_t* buf, int len);

int tcp_socket_recv(TcpSocket* tcp_socket, uint8_t* buf, int len);

/** Block until len bytes received or error (for STUN/TCP framing). */
int tcp_socket_recv_exact(TcpSocket* tcp_socket, uint8_t* buf, int len);

/** Read len bytes from the stream reassembly buffer (non-blocking append from socket). */
int tcp_socket_read_buffered(TcpSocket* tcp_socket, uint8_t* buf, int len);

/** Append any readable bytes from the kernel into rx_buf. Returns bytes read or -1. */
int tcp_socket_rx_fill(TcpSocket* tcp_socket);

void tcp_socket_rx_reset(TcpSocket* tcp_socket);

void tcp_socket_set_recv_timeout_ms(TcpSocket* tcp_socket, int ms);

#endif  // SOCKET_H_
