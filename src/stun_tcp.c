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

  /* RFC 8656 §12.4: ChannelData is padded to a 4-byte boundary only over stream

   * transports (TCP/TLS). Over UDP coturn relays it unpadded, so the datagram is

   * exactly 4 + plen bytes — validate against the unpadded payload length. */

  if (4 + plen > len) {

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



static int stun_tcp_rx_have(TcpSocket* tcp, int need) {

  while (tcp->rx_len < need) {

    int r = tcp_socket_rx_fill(tcp);

    if (r < 0) {

      return -1;

    }

    if (r == 0) {

      return 0;

    }

  }

  return 1;

}



static int stun_tcp_frame_total(TcpSocket* tcp, const uint8_t prefix[4], int bufsize, int* is_channel,

                                uint16_t* channel_number) {

  StunHeader header;

  int attr_len;

  int total;

  int payload_len;

  int padded;



  if (stun_tcp_is_channel_prefix(&prefix[0], &prefix[1])) {

    *is_channel = 1;

    *channel_number = (uint16_t)(((uint16_t)prefix[0] << 8) | prefix[1]);

    payload_len = (int)(((uint16_t)prefix[2] << 8) | prefix[3]);

    padded = (payload_len + 3) & ~3;

    total = 4 + padded;

    if (payload_len < 0 || total > bufsize) {

      return -1;

    }

    return total;

  }



  *is_channel = 0;

  *channel_number = 0;

  if (stun_tcp_rx_have(tcp, STUN_TCP_HEADER_SIZE) <= 0) {

    return 0;

  }

  memcpy(&header, tcp->rx_buf, (size_t)STUN_TCP_HEADER_SIZE);

  if (header.magic_cookie != htonl(MAGIC_COOKIE)) {

    LOGE("STUN/TCP bad magic cookie");

    return -1;

  }

  attr_len = (int)ntohs(header.length);

  total = STUN_TCP_HEADER_SIZE + attr_len;

  if (total > bufsize) {

    LOGE("STUN/TCP message too large %d", total);

    return -1;

  }

  return total;

}



int stun_tcp_recv_packet(TcpSocket* tcp, uint8_t* buf, int bufsize) {

  int is_channel = 0;

  uint16_t channel = 0;

  return stun_tcp_recv_turn_frame(tcp, buf, bufsize, &is_channel, &channel);

}



int stun_tcp_recv_turn_frame(TcpSocket* tcp, uint8_t* buf, int bufsize, int* is_channel,

                             uint16_t* channel_number) {

  uint8_t prefix[4];

  int total;

  int have;



  if (!tcp || tcp->fd < 0 || !buf || bufsize < 4 || !is_channel || !channel_number) {

    return -1;

  }

  *is_channel = 0;

  *channel_number = 0;



  have = stun_tcp_rx_have(tcp, 4);

  if (have <= 0) {

    return have;

  }



  memcpy(prefix, tcp->rx_buf, 4);

  total = stun_tcp_frame_total(tcp, prefix, bufsize, is_channel, channel_number);

  if (total <= 0) {

    return total;

  }



  have = stun_tcp_rx_have(tcp, total);

  if (have <= 0) {

    return have;

  }



  memcpy(buf, tcp->rx_buf, (size_t)total);

  memmove(tcp->rx_buf, tcp->rx_buf + total, (size_t)(tcp->rx_len - total));

  tcp->rx_len -= total;

  return total;

}

