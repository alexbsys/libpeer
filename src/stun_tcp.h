#ifndef STUN_TCP_H_
#define STUN_TCP_H_

#include "socket.h"

/** STUN over TCP: send one self-delimited STUN message (header.length + 20). */
int stun_tcp_send(TcpSocket* tcp, const uint8_t* buf, int len);

/** Read one STUN message into buf; returns total length or -1. */
int stun_tcp_recv_packet(TcpSocket* tcp, uint8_t* buf, int bufsize);

/** Pack RFC 5766 ChannelData header + payload (padded to 4 bytes). Returns total length or -1. */
int stun_pack_channel_data(uint8_t* frame, int frame_cap, uint16_t channel, const uint8_t* data, int len);

/** True if buf starts with a valid TURN channel number prefix. */
int stun_is_channel_data_prefix(const uint8_t* buf, int len, uint16_t* channel, int* payload_len);

/** Send one TURN ChannelData frame (RFC 5766). */
int stun_tcp_send_channel_data(TcpSocket* tcp, uint16_t channel, const uint8_t* data, int len);

/**
 * Read one STUN message or ChannelData frame.
 * Returns total bytes in buf, sets *is_channel and *channel_number when ChannelData.
 */
int stun_tcp_recv_turn_frame(TcpSocket* tcp, uint8_t* buf, int bufsize, int* is_channel,
                             uint16_t* channel_number);

#endif
