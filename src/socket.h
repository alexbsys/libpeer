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
  /* Scratch for framing one outbound TURN ChannelData frame (payload + 4-byte
   * header + padding). Kept here (heap, via the owning Agent) instead of on the
   * caller's stack: stun_tcp_send_channel_data() runs from the webrtc_bus video
   * task whose stack is only ~6 KB, and a 1.4 KB stack array there overflowed it. */
  uint8_t tx_frame[1400 + 4 + 4];
  /* Non-blocking TX tail. The TURN-TCP socket is non-blocking and ChannelData is
   * a length-prefixed byte stream, so a frame must never be left partially on the
   * wire (that desyncs the relay and drops the peer). When send() takes only part
   * of a frame we stash the remainder here and flush it later (tcp_socket_tx_flush),
   * instead of blocking under the per-peer lock. While a tail is pending, new
   * frames are dropped cleanly to preserve stream order. */
  uint8_t tx_pending[1400 + 4 + 4];
  int tx_pending_len;
  int tx_pending_off;
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

/** Non-blocking flush of any buffered TX tail. Returns 1 if nothing pending /
 * fully flushed, 0 if a tail is still pending, -1 on a hard socket error. Safe to
 * call often (e.g. from the loop's TURN drain) — it only acts when a tail exists. */
int tcp_socket_tx_flush(TcpSocket* tcp_socket);

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
