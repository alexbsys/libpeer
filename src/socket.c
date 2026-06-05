#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "socket.h"
#include "utils.h"

/* Bound for non-blocking TCP connect (TURN-over-TCP control channel). Keep it
 * short: it runs under the per-peer lock, so a long stall freezes other tasks. */
#ifndef TCP_CONNECT_TIMEOUT_MS
#define TCP_CONNECT_TIMEOUT_MS 4000
#endif

int udp_socket_add_multicast_group(UdpSocket* udp_socket, Address* mcast_addr) {
  int ret = 0;
  struct ip_mreq imreq = {0};
  struct in_addr iaddr = {0};

  imreq.imr_interface.s_addr = INADDR_ANY;
  // IPV4 only
  imreq.imr_multiaddr.s_addr = mcast_addr->sin.sin_addr.s_addr;

  if ((ret = setsockopt(udp_socket->fd, IPPROTO_IP, IP_MULTICAST_IF, &iaddr, sizeof(struct in_addr))) < 0) {
    LOGE("Failed to set IP_MULTICAST_IF: %d", ret);
    return ret;
  }

  if ((ret = setsockopt(udp_socket->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imreq, sizeof(struct ip_mreq))) < 0) {
    LOGE("Failed to set IP_ADD_MEMBERSHIP: %d", ret);
    return ret;
  }

  return 0;
}

static int socket_avoid_stdio_fd(int fd) {
  if (fd <= 2) {
    int dupfd = fcntl(fd, F_DUPFD, 3);
    if (dupfd >= 0) {
      close(fd);
      return dupfd;
    }
  }
  return fd;
}

int udp_socket_open(UdpSocket* udp_socket, int family, int port) {
  int ret;
  int reuse = 1;
  struct sockaddr* sa;
  socklen_t sock_len;

  udp_socket->bind_addr.family = family;
  switch (family) {
    case AF_INET6:
      udp_socket->fd = socket(AF_INET6, SOCK_DGRAM, 0);
      udp_socket->fd = socket_avoid_stdio_fd(udp_socket->fd);
      udp_socket->bind_addr.sin6.sin6_family = AF_INET6;
      udp_socket->bind_addr.sin6.sin6_port = htons(port);
      udp_socket->bind_addr.sin6.sin6_addr = in6addr_any;
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      udp_socket->fd = socket(AF_INET, SOCK_DGRAM, 0);
      udp_socket->fd = socket_avoid_stdio_fd(udp_socket->fd);
      udp_socket->bind_addr.sin.sin_family = AF_INET;
      udp_socket->bind_addr.sin.sin_port = htons(port);
      udp_socket->bind_addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if (udp_socket->fd < 0) {
    LOGE("Failed to create socket errno=%d (%s)", errno, strerror(errno));
    return -1;
  }

  do {
    if ((ret = setsockopt(udp_socket->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) < 0) {
      LOGW("reuse failed. ignore");
    }

    if ((ret = bind(udp_socket->fd, sa, sock_len)) < 0) {
      LOGE("Failed to bind socket: %d", ret);
      break;
    }

    if ((ret = getsockname(udp_socket->fd, sa, &sock_len)) < 0) {
      LOGE("Get socket info failed");
      break;
    }
  } while (0);

  if (ret < 0) {
    udp_socket_close(udp_socket);
    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      break;
    case AF_INET:
    default:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin.sin_port);
      break;
  }

  return 0;
}

void udp_socket_close(UdpSocket* udp_socket) {
  if (udp_socket->fd >= 0) {
    close(udp_socket->fd);
    udp_socket->fd = -1;
  }
}

int udp_socket_sendto(UdpSocket* udp_socket, Address* addr, const uint8_t* buf, int len) {
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret = -1;

  if (udp_socket->fd < 0) {
    LOGE("sendto before socket init");
    return -1;
  }

  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&addr->sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      addr->sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&addr->sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = sendto(udp_socket->fd, buf, len, 0, sa, sock_len)) < 0) {
    LOGE("Failed to sendto: %s", strerror(errno));
    return -1;
  }

  return ret;
}

int udp_socket_recvfrom(UdpSocket* udp_socket, Address* addr, uint8_t* buf, int len) {
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin;
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret;

  if (udp_socket->fd < 0) {
    LOGE("recvfrom before socket init");
    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = recvfrom(udp_socket->fd, buf, len, 0, sa, &sock_len)) < 0) {
    LOGE("Failed to recvfrom: %s", strerror(errno));
    return -1;
  }

  if (addr) {
    switch (udp_socket->bind_addr.family) {
      case AF_INET6:
        addr->family = AF_INET6;
        addr->port = htons(sin6.sin6_port);
        memcpy(&addr->sin6, &sin6, sizeof(struct sockaddr_in6));
        break;
      case AF_INET:
      default:
        addr->family = AF_INET;
        addr->port = htons(sin.sin_port);
        memcpy(&addr->sin, &sin, sizeof(struct sockaddr_in));
        break;
    }
  }

  return ret;
}

void tcp_socket_rx_reset(TcpSocket* tcp_socket) {
  if (tcp_socket) {
    tcp_socket->rx_len = 0;
  }
}

int tcp_socket_rx_fill(TcpSocket* tcp_socket) {
  int space;
  int r;

  if (!tcp_socket || tcp_socket->fd < 0) {
    return -1;
  }
  space = TCP_SOCKET_RX_CAP - tcp_socket->rx_len;
  if (space <= 0) {
    LOGE("TCP rx buffer full");
    return -1;
  }
  r = (int)recv(tcp_socket->fd, tcp_socket->rx_buf + tcp_socket->rx_len, (size_t)space, MSG_DONTWAIT);
  if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
  if (r == 0) {
    return -1;
  }
  tcp_socket->rx_len += r;
  return r;
}

int tcp_socket_read_buffered(TcpSocket* tcp_socket, uint8_t* buf, int len) {
  int got = 0;

  if (!tcp_socket || tcp_socket->fd < 0 || !buf || len <= 0) {
    return -1;
  }
  while (got < len) {
    if (tcp_socket->rx_len == 0) {
      if (tcp_socket_rx_fill(tcp_socket) <= 0) {
        return got > 0 ? got : -1;
      }
    }
    {
      int take = len - got;
      if (take > tcp_socket->rx_len) {
        take = tcp_socket->rx_len;
      }
      memcpy(buf + got, tcp_socket->rx_buf, (size_t)take);
      memmove(tcp_socket->rx_buf, tcp_socket->rx_buf + take, (size_t)(tcp_socket->rx_len - take));
      tcp_socket->rx_len -= take;
      got += take;
    }
  }
  return got;
}

int tcp_socket_open(TcpSocket* tcp_socket, int family) {
  tcp_socket_rx_reset(tcp_socket);
  tcp_socket->bind_addr.family = family;
  switch (family) {
    case AF_INET6:
      tcp_socket->fd = socket(AF_INET6, SOCK_STREAM, 0);
      break;
    case AF_INET:
    default:
      tcp_socket->fd = socket(AF_INET, SOCK_STREAM, 0);
      break;
  }

  if (tcp_socket->fd < 0) {
    LOGE("Failed to create socket");
    return -1;
  }
  return 0;
}

int tcp_socket_connect(TcpSocket* tcp_socket, Address* addr) {
  char addr_string[ADDRSTRLEN];
  int ret;
  struct sockaddr* sa;
  socklen_t sock_len;

  if (tcp_socket->fd < 0) {
    LOGE("Connect before socket init");
    return -1;
  }

  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&addr->sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      addr->sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&addr->sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  addr_to_string(addr, addr_string, sizeof(addr_string));
  LOGI("Connecting to server: %s:%d", addr_string, addr->port);

  /* Non-blocking connect with a bounded timeout. A plain blocking connect() to an
   * unreachable/filtered TURN-over-TCP server stalls on the lwip SYN-retransmit
   * timer for ~60-75 s. libpeer runs this from peer_connection_loop/create_answer
   * while the per-peer lock is held, so that one connect froze every task that
   * funnels through the lock (video, signaling/candidates, LCD). Cap it. */
  {
    int flags = fcntl(tcp_socket->fd, F_GETFL, 0);
    if (flags >= 0) {
      fcntl(tcp_socket->fd, F_SETFL, flags | O_NONBLOCK);
    }
  }
  ret = connect(tcp_socket->fd, sa, sock_len);
  if (ret < 0 && errno == EINPROGRESS) {
    fd_set wfds;
    struct timeval tv;
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    FD_ZERO(&wfds);
    FD_SET(tcp_socket->fd, &wfds);
    tv.tv_sec = TCP_CONNECT_TIMEOUT_MS / 1000;
    tv.tv_usec = (TCP_CONNECT_TIMEOUT_MS % 1000) * 1000;
    ret = select(tcp_socket->fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
      LOGE("TCP connect to %s:%d timed out (%d ms)", addr_string, addr->port, TCP_CONNECT_TIMEOUT_MS);
      tcp_socket_close(tcp_socket);
      return -1;
    }
    if (getsockopt(tcp_socket->fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0 || so_err != 0) {
      LOGE("TCP connect to %s:%d failed (so_error=%d)", addr_string, addr->port, so_err);
      tcp_socket_close(tcp_socket);
      return -1;
    }
  } else if (ret < 0) {
    LOGE("Failed to connect to server");
    tcp_socket_close(tcp_socket);
    return -1;
  }

  {
    int one = 1;
    setsockopt(tcp_socket->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    tcp_socket_set_recv_timeout_ms(tcp_socket, 50);
  }

  tcp_socket_rx_reset(tcp_socket);
  /* Socket already left in O_NONBLOCK mode from the connect above. */

  LOGI("Server is connected");
  return 0;
}

void tcp_socket_set_recv_timeout_ms(TcpSocket* tcp_socket, int ms) {
  struct timeval tv;
  if (!tcp_socket || tcp_socket->fd < 0) {
    return;
  }
  if (ms < 0) {
    ms = 0;
  }
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  setsockopt(tcp_socket->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(tcp_socket->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void tcp_socket_close(TcpSocket* tcp_socket) {
  if (tcp_socket->fd >= 0) {
    close(tcp_socket->fd);
    tcp_socket->fd = -1;
  }
  tcp_socket_rx_reset(tcp_socket);
}

int tcp_socket_recv_exact(TcpSocket* tcp_socket, uint8_t* buf, int len) {
  return tcp_socket_read_buffered(tcp_socket, buf, len);
}

int tcp_socket_send(TcpSocket* tcp_socket, const uint8_t* buf, int len) {
  int sent = 0;

  if (tcp_socket->fd < 0) {
    LOGE("sendto before socket init");
    return -1;
  }

  while (sent < len) {
    int ret = send(tcp_socket->fd, buf + sent, (size_t)(len - sent), MSG_NOSIGNAL);
    if (ret < 0) {
      LOGE("Failed to send: %s", strerror(errno));
      return -1;
    }
    sent += ret;
  }
  return sent;
}

int tcp_socket_recv(TcpSocket* tcp_socket, uint8_t* buf, int len) {
  int ret;

  if (tcp_socket->fd < 0) {
    LOGE("recvfrom before socket init");
    return -1;
  }

  ret = recv(tcp_socket->fd, buf, len, 0);
  if (ret < 0) {
    LOGE("Failed to recv: %s", strerror(errno));
    return -1;
  }
  return ret;
}
