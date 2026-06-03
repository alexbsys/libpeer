#include <string.h>

#include "stun.h"
#include "stun_tcp.h"
#include "utils.h"

#define STUN_TCP_HEADER_SIZE ((int)sizeof(StunHeader))

static int stun_tcp_is_channel_prefix(const uint8_t* b0, const uint8_t* b1) {
  uint16_t n = (uint16_t)(((uint16_t)*b0 << 8) | *b1);
  return n >= STUN_CHANNEL_NUMBER_MIN && n <= STUN_CHANNEL_NUMBER_MAX;
}

int stun_is_channel_data_prefix(const uint8_t* buf, int len, uint16_t* channel, int* payload_len) {
  int plen;
  int padded;
  if (!buf || len < 4 || !channel || !payload_len) {
    return 0;
  }
  if (!stun_tcp_is_channel_prefix(&buf[0], &buf[1])) {
    return 0;
  }
  *channel = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
  plen = (int)(((uint16_t)buf[2] << 8) | buf[3]);
  if (plen < 0) {
    return 0;
  }
  padded = (plen + 3) & ~3;
  if (4 + padded > len) {
    return 0;
  }
  *payload_len = plen;
  return 1;
}

int stun_pack_channel_data(uint8_t* frame, int frame_cap, uint16_t channel, const uint8_t* data, int len) {
  uint16_t ch_net;
  uint16_t len_net;
  int padded;
  int total;

  if (!frame || !data || len <= 0) {
    return -1;
  }
  if (channel < STUN_CHANNEL_NUMBER_MIN || channel > STUN_CHANNEL_NUMBER_MAX) {
    return -1;
  }
  padded = (len + 3) & ~3;
  total = 4 + padded;
  if (total > frame_cap) {
    return -1;
  }
  ch_net = htons(channel);
  len_net = htons((uint16_t)len);
  memcpy(frame, &ch_net, 2);
  memcpy(frame + 2, &len_net, 2);
  memcpy(frame + 4, data, (size_t)len);
  if (padded > len) {
    memset(frame + 4 + len, 0, (size_t)(padded - len));
  }
  return total;
}

int stun_tcp_send(TcpSocket* tcp, const uint8_t* buf, int len) {
  if (!tcp || tcp->fd < 0 || !buf || len < STUN_TCP_HEADER_SIZE) {
    return -1;
  }
  /* TURN/STUN over TCP (coturn, browsers): one STUN message per write, no RFC4571 prefix. */
  return tcp_socket_send(tcp, buf, len);
}

int stun_tcp_send_channel_data(TcpSocket* tcp, uint16_t channel, const uint8_t* data, int len) {
  uint8_t frame[STUN_ATTR_BUF_SIZE + 4];
  int total;

  if (!tcp || tcp->fd < 0 || !data || len <= 0 || len > (int)(sizeof(frame) - 4)) {
    return -1;
  }
  total = stun_pack_channel_data(frame, (int)sizeof(frame), channel, data, len);
  if (total < 0) {
    return -1;
  }
  return tcp_socket_send(tcp, frame, total);
}

int stun_tcp_recv_packet(TcpSocket* tcp, uint8_t* buf, int bufsize) {
  int is_channel = 0;
  uint16_t channel = 0;
  return stun_tcp_recv_turn_frame(tcp, buf, bufsize, &is_channel, &channel);
}

int stun_tcp_recv_turn_frame(TcpSocket* tcp, uint8_t* buf, int bufsize, int* is_channel,
                             uint16_t* channel_number) {
  uint8_t prefix[4];
  StunHeader* header;
  int attr_len;
  int total;
  int payload_len;
  int padded;

  if (!tcp || tcp->fd < 0 || !buf || bufsize < 4 || !is_channel || !channel_number) {
    return -1;
  }
  *is_channel = 0;
  *channel_number = 0;

  if (tcp_socket_recv_exact(tcp, prefix, 4) != 4) {
    return -1;
  }

  if (stun_tcp_is_channel_prefix(&prefix[0], &prefix[1])) {
    *is_channel = 1;
    *channel_number = (uint16_t)(((uint16_t)prefix[0] << 8) | prefix[1]);
    payload_len = (int)(((uint16_t)prefix[2] << 8) | prefix[3]);
    padded = (payload_len + 3) & ~3;
    total = 4 + padded;
    if (total > bufsize || payload_len < 0) {
      LOGE("STUN/TCP ChannelData too large %d", total);
      return -1;
    }
    memcpy(buf, prefix, 4);
    if (padded > 0 && tcp_socket_recv_exact(tcp, buf + 4, padded) != padded) {
      return -1;
    }
    return total;
  }

  if (bufsize < STUN_TCP_HEADER_SIZE) {
    return -1;
  }
  memcpy(buf, prefix, 4);
  if (tcp_socket_recv_exact(tcp, buf + 4, STUN_TCP_HEADER_SIZE - 4) != STUN_TCP_HEADER_SIZE - 4) {
    return -1;
  }
  header = (StunHeader*)buf;
  if (header->magic_cookie != htonl(MAGIC_COOKIE)) {
    LOGE("STUN/TCP bad magic cookie");
    return -1;
  }
  attr_len = (int)ntohs(header->length);
  total = STUN_TCP_HEADER_SIZE + attr_len;
  if (total > bufsize) {
    LOGE("STUN/TCP message too large %d", total);
    return -1;
  }
  if (attr_len > 0 && tcp_socket_recv_exact(tcp, buf + STUN_TCP_HEADER_SIZE, attr_len) != attr_len) {
    return -1;
  }
  return total;
}
