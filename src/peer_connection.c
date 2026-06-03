#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"
#include "config.h"
#include "dtls_srtp.h"
#include "peer_connection.h"
#include "ports.h"
#include "rtcp.h"
#include "rtp.h"
#include "rtp_nack_cache.h"
#include "sctp.h"
#include "sdp.h"
#include "utils.h"

#define STATE_CHANGED(pc, curr_state)                                 \
  if (pc->oniceconnectionstatechange && pc->state != curr_state) {    \
    pc->oniceconnectionstatechange(curr_state, pc->config.user_data); \
    pc->state = curr_state;                                           \
  }

struct PeerConnection {
  PeerConfiguration config;
  PeerConnectionState state;
  Agent agent;
  DtlsSrtp dtls_srtp;
  Sctp sctp;

  char sdp[CONFIG_SDP_BUFFER_SIZE];

  void (*onicecandidate)(char* sdp, void* user_data);
  void (*oniceconnectionstatechange)(PeerConnectionState state, void* user_data);
  void (*on_connected)(void* userdata);
  void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* user_data);

  uint8_t temp_buf[CONFIG_MTU];
  uint8_t agent_buf[CONFIG_MTU];
  int agent_ret;
  int b_local_description_created;

  sdp_remote_offer_layout_t remote_offer_layout;
  int have_remote_offer_layout;

  RtpEncoder artp_encoder;
  RtpEncoder vrtp_encoder;
  RtpDecoder vrtp_decoder;
  RtpDecoder artp_decoder;

  uint32_t remote_assrc;
  uint32_t remote_vssrc;

  rtp_nack_cache_t nack_cache;
  uint16_t rtx_seq_number;
  uint32_t last_pts_us;
  uint32_t rtp_ts_origin_90k;
  int rtp_ts_origin_set;
};

/* RFC 4588 RTX resend: separate SSRC/PT, OSN + original payload. */
static int peer_connection_resend_nack_rtp(void* user, const uint8_t* rtp, int len) {
  PeerConnection* pc = (PeerConnection*)user;
  if (!pc || len < 12 || len > (int)sizeof(pc->temp_buf) - 2) {
    return -1;
  }
  const int hdr_len = 12;
  const int plen = len - hdr_len;
  if (plen <= 0) {
    return -1;
  }

  RtpHeader* nh = (RtpHeader*)pc->temp_buf;
  memcpy(nh, rtp, (size_t)hdr_len);
  nh->type = PT_H264_RTX;
  nh->ssrc = htonl((uint32_t)SSRC_H264_RTX);
  nh->seq_number = htons(pc->rtx_seq_number++);

  const uint16_t osn = ntohs(((const RtpHeader*)rtp)->seq_number);
  uint8_t* out_pl = pc->temp_buf + hdr_len;
  out_pl[0] = (uint8_t)(osn >> 8);
  out_pl[1] = (uint8_t)(osn & 0xff);
  memcpy(out_pl + 2, rtp + hdr_len, (size_t)plen);

  int n = hdr_len + 2 + plen;
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, pc->temp_buf, &n);
  return agent_send(&pc->agent, pc->temp_buf, n);
}

static void peer_connection_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
  PeerConnection* pc = (PeerConnection*)user_data;
  rtp_nack_cache_store(&pc->nack_cache, data, (int)size);
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  agent_send(&pc->agent, data, size);
}

/* RTP/RTCP use version 2 in the top two bits (RFC 3550). Those must not be fed to mbedTLS
 * during DTLS handshake — on low-latency LAN paths they can arrive on the same ICE socket
 * before DTLS completes and cause MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE / CONN_EOF. */
static int peer_connection_looks_like_rtp_or_rtcp(const uint8_t* buf, int n) {
  return n >= 1 && (buf[0] & 0xC0) == 0x80;
}

static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int recv_max = 0;
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  const int handshake_phase = (dtls_srtp->state != DTLS_SRTP_STATE_CONNECTED);

  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  while (recv_max < CONFIG_TLS_READ_TIMEOUT && pc->state == PEER_CONNECTION_CONNECTED) {
    ret = agent_recv(&pc->agent, buf, len);

    if (ret > 0) {
      if (handshake_phase && peer_connection_looks_like_rtp_or_rtcp(buf, ret)) {
        LOGD("skip RTP/RTCP (%d B) during DTLS handshake", ret);
        ret = -1;
      } else {
        break;
      }
    }

    recv_max++;
  }
  return ret;
}

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  // LOGD("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len);
  return agent_send(&pc->agent, buf, len);
}

static void peer_connection_incoming_rtcp(PeerConnection* pc, uint8_t* buf, size_t len) {
  RtcpHeader* rtcp_header;
  size_t pos = 0;

  while (pos < len) {
    rtcp_header = (RtcpHeader*)(buf + pos);

    switch (rtcp_header->type) {
      case RTCP_RR:
        if (rtcp_header->rc > 0 && pos + 16 <= len) {
          uint32_t flcnpl = ntohl(*(uint32_t*)(buf + pos + 12));
          uint8_t fraction = (uint8_t)(flcnpl >> 24);
          uint32_t cumulative = flcnpl & 0x00FFFFFFu;
          if (pc->on_receiver_packet_loss && (fraction > 0 || cumulative > 0)) {
            pc->on_receiver_packet_loss((float)fraction / 256.0f, cumulative,
                                        pc->config.user_data);
          }
        }
        break;
      case RTCP_PSFB: {
        int fmt = rtcp_header->rc;
        LOGD("RTCP_PSFB %d", fmt);
        // PLI and FIR
        if ((fmt == 1 || fmt == 4) && pc->config.on_request_keyframe) {
          pc->config.on_request_keyframe(pc->config.user_data);
        }
        break;
      }
      case RTCP_RTPFB: {
        /* RFC 4585: fmt=1 Generic NACK (PID + BLP). */
        int fmt = rtcp_header->rc;
        if (fmt != 1) {
          break;
        }
        size_t block_bytes = 4 * ((size_t)ntohs(rtcp_header->length) + 1u);
        if (pos + block_bytes > len || block_bytes < 12 + 4) {
          break;
        }
        uint32_t media_ssrc = ntohl(*(uint32_t*)(buf + pos + 8));
        if (media_ssrc != pc->vrtp_encoder.ssrc) {
          break;
        }
        const uint8_t* fci = buf + pos + 12;
        int fci_len = (int)(block_bytes - 12);
        rtp_nack_cache_process_fci(&pc->nack_cache, fci, fci_len, peer_connection_resend_nack_rtp, pc);
        break;
      }
      default:
        break;
    }

    pos += 4 * ntohs(rtcp_header->length) + 4;
  }
}

const char* peer_connection_state_to_string(PeerConnectionState state) {
  switch (state) {
    case PEER_CONNECTION_NEW:
      return "new";
    case PEER_CONNECTION_CHECKING:
      return "checking";
    case PEER_CONNECTION_CONNECTED:
      return "connected";
    case PEER_CONNECTION_COMPLETED:
      return "completed";
    case PEER_CONNECTION_FAILED:
      return "failed";
    case PEER_CONNECTION_CLOSED:
      return "closed";
    case PEER_CONNECTION_DISCONNECTED:
      return "disconnected";
    default:
      return "unknown";
  }
}

PeerConnectionState peer_connection_get_state(PeerConnection* pc) {
  return pc->state;
}

void* peer_connection_get_sctp(PeerConnection* pc) {
  return &pc->sctp;
}

PeerConnection* peer_connection_create(PeerConfiguration* config) {
  PeerConnection* pc = calloc(1, sizeof(PeerConnection));
  if (!pc) {
    return NULL;
  }

  memcpy(&pc->config, config, sizeof(PeerConfiguration));

  if (agent_create(&pc->agent) < 0) {
    free(pc);
    return NULL;
  }

  rtp_nack_cache_init(&pc->nack_cache);
  pc->rtx_seq_number = 1;

  memset(&pc->sctp, 0, sizeof(pc->sctp));

  if (pc->config.audio_codec) {
    rtp_encoder_init(&pc->artp_encoder, pc->config.audio_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->artp_decoder, pc->config.audio_codec,
                     pc->config.onaudiotrack, pc->config.user_data);
  }

  if (pc->config.video_codec) {
    rtp_encoder_init(&pc->vrtp_encoder, pc->config.video_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->vrtp_decoder, pc->config.video_codec,
                     pc->config.onvideotrack, pc->config.user_data);
  }

  return pc;
}

void peer_connection_destroy(PeerConnection* pc) {
  if (pc) {
    rtp_nack_cache_deinit(&pc->nack_cache);
    sctp_destroy_association(&pc->sctp);
    dtls_srtp_deinit(&pc->dtls_srtp);
    agent_destroy(&pc->agent);
    free(pc);
    pc = NULL;
  }
}

void peer_connection_close(PeerConnection* pc) {
  pc->state = PEER_CONNECTION_CLOSED;
}

int peer_connection_send_audio(PeerConnection* pc, const uint8_t* buf, size_t len) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
  return rtp_encoder_encode(&pc->artp_encoder, buf, len);
}

static uint32_t peer_connection_pts_us_to_rtp90k(uint32_t pts_us) {
  return (uint32_t)(((uint64_t)pts_us * 9ULL) / 100ULL);
}

static int peer_connection_annexb_has_idr_nal(const uint8_t* buf, size_t len) {
  size_t off = 0;
  while (off + 3 < len) {
    size_t sc_len = 0;
    if (buf[off] == 0 && buf[off + 1] == 0 && buf[off + 2] == 1) {
      sc_len = 3;
    } else if (off + 4 <= len && buf[off] == 0 && buf[off + 1] == 0 && buf[off + 2] == 0 && buf[off + 3] == 1) {
      sc_len = 4;
    } else {
      off++;
      continue;
    }
    size_t nal = off + sc_len;
    if (nal >= len) {
      break;
    }
    if ((buf[nal] & 0x1fu) == 5u) {
      return 1;
    }
    off = nal + 1;
  }
  return 0;
}

void peer_connection_set_nack_discard_pre_idr(PeerConnection* pc, int enable) {
  if (!pc) {
    return;
  }
  rtp_nack_cache_set_discard_pre_idr(&pc->nack_cache, enable);
}

int peer_connection_send_video(PeerConnection* pc, const uint8_t* buf, size_t len, uint32_t pts_us) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
  if (pc->nack_cache.discard_pre_idr && peer_connection_annexb_has_idr_nal(buf, len)) {
    rtp_nack_cache_set_resend_floor(&pc->nack_cache, pc->vrtp_encoder.seq_number);
    LOGD("nack: IDR AU — resend floor seq=%u", (unsigned)pc->vrtp_encoder.seq_number);
  }
  if (pts_us > 0) {
    uint32_t ts_abs = peer_connection_pts_us_to_rtp90k(pts_us);
    if (!pc->rtp_ts_origin_set) {
      pc->rtp_ts_origin_90k = ts_abs;
      pc->rtp_ts_origin_set = 1;
      pc->last_pts_us = pts_us;
    }
    /* Session-relative 90 kHz clock (not uptime since boot) — keeps browser
     * playout aligned after ICE/DTLS connect. */
    uint32_t ts = ts_abs - pc->rtp_ts_origin_90k;
    if (ts <= pc->vrtp_encoder.timestamp) {
      uint32_t delta = 0;
      if (pts_us > pc->last_pts_us) {
        delta = peer_connection_pts_us_to_rtp90k(pts_us - pc->last_pts_us);
      }
      if (delta == 0) {
        delta = pc->vrtp_encoder.timestamp_increment;
      }
      ts = pc->vrtp_encoder.timestamp + delta;
      if (ts == pc->vrtp_encoder.timestamp) {
        ts++;
      }
    }
    pc->last_pts_us = pts_us;
    rtp_encoder_set_timestamp(&pc->vrtp_encoder, ts);
  } else {
    pc->vrtp_encoder.timestamp += pc->vrtp_encoder.timestamp_increment;
  }
  return rtp_encoder_encode(&pc->vrtp_encoder, buf, len);
}

int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len) {
  return peer_connection_datachannel_send_sid(pc, message, len, 0);
}

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return -1;
  }
  if (pc->config.datachannel == DATA_CHANNEL_STRING)
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  else
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
}

int peer_connection_create_datachannel(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol) {
  return peer_connection_create_datachannel_sid(pc, channel_type, priority, reliability_parameter, label, protocol, 0);
}

int peer_connection_create_datachannel_sid(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol, uint16_t sid) {
  int rtrn = -1;

  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return rtrn;
  }

  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Message Type |  Channel Type |            Priority           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                    Reliability Parameter                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Label Length          |       Protocol Length         |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                             Label                             |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                            Protocol                           |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  int msg_size = 12 + strlen(label) + strlen(protocol);
  uint16_t priority_big_endian = htons(priority);
  uint32_t reliability_big_endian = ntohl(reliability_parameter);
  uint16_t label_length = htons(strlen(label));
  uint16_t protocol_length = htons(strlen(protocol));
  char* msg = calloc(1, msg_size);
  if (!msg) {
    return rtrn;
  }

  msg[0] = DATA_CHANNEL_OPEN;
  memcpy(msg + 2, &priority_big_endian, sizeof(uint16_t));
  memcpy(msg + 4, &reliability_big_endian, sizeof(uint32_t));
  memcpy(msg + 8, &label_length, sizeof(uint16_t));
  memcpy(msg + 10, &protocol_length, sizeof(uint16_t));
  memcpy(msg + 12, label, strlen(label));
  memcpy(msg + 12 + strlen(label), protocol, strlen(protocol));

  rtrn = sctp_outgoing_data(&pc->sctp, msg, msg_size, PPID_CONTROL, sid);
  free(msg);
  return rtrn;
}

static char* peer_connection_dtls_role_setup_value(DtlsSrtpRole d) {
  return d == DTLS_SRTP_ROLE_SERVER ? "a=setup:passive" : "a=setup:active";
}

int peer_connection_loop(PeerConnection* pc) {
  uint32_t ssrc = 0;
  memset(pc->agent_buf, 0, sizeof(pc->agent_buf));
  pc->agent_ret = -1;

  switch (pc->state) {
    case PEER_CONNECTION_NEW:
      break;

    case PEER_CONNECTION_CHECKING:
      if (agent_select_candidate_pair(&pc->agent) < 0) {
        agent_log_ice_diagnostics(&pc->agent, "select_pair -> FAILED (no usable ICE pair)");
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      } else if (agent_connectivity_check(&pc->agent) == 0) {
        LOGI("peer_conn: ICE nominated pair succeeded — starting DTLS-SRTP");
        STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
      }
      break;

    case PEER_CONNECTION_CONNECTED:

      if (dtls_srtp_handshake(&pc->dtls_srtp, NULL) == 0) {
        LOGI("peer_conn: DTLS-SRTP handshake done — media path ready");

        if (pc->config.datachannel) {
          LOGI("SCTP create socket");
          sctp_create_association(&pc->sctp, &pc->dtls_srtp);
          pc->sctp.userdata = pc->config.user_data;
        }

        STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
      }
      break;
    case PEER_CONNECTION_COMPLETED:
      if ((pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf))) > 0) {
        LOGD("agent_recv %d", pc->agent_ret);

        if (rtcp_probe(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTCP packet");
          dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);
          peer_connection_incoming_rtcp(pc, pc->agent_buf, pc->agent_ret);

        } else if (dtls_srtp_probe(pc->agent_buf)) {
          int ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
          LOGD("Got DTLS data %d", ret);

          if (ret > 0) {
            sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
          }

        } else if (rtp_packet_validate(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTP packet");

          dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);

          ssrc = rtp_get_ssrc(pc->agent_buf);
          if (ssrc == pc->remote_assrc) {
            rtp_decoder_decode(&pc->artp_decoder, pc->agent_buf, pc->agent_ret);
          } else if (ssrc == pc->remote_vssrc) {
            rtp_decoder_decode(&pc->vrtp_decoder, pc->agent_buf, pc->agent_ret);
          }

        } else {
          LOGW("Unknown data");
        }
      }

      if (CONFIG_KEEPALIVE_TIMEOUT > 0 && (ports_get_epoch_time() - pc->agent.binding_request_time) > CONFIG_KEEPALIVE_TIMEOUT) {
        LOGI("binding request timeout");
        STATE_CHANGED(pc, PEER_CONNECTION_CLOSED);
      }

      break;
    case PEER_CONNECTION_FAILED:
      break;
    case PEER_CONNECTION_DISCONNECTED:
      break;
    case PEER_CONNECTION_CLOSED:
      break;
    default:
      break;
  }

  return 0;
}

void peer_connection_set_remote_description(PeerConnection* pc, const char* sdp, SdpType type) {
  const char* p = sdp;
  char buf[256];
  char* val_start = NULL;
  uint32_t* ssrc = NULL;
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;
  int is_update = 0;
  Agent* agent = &pc->agent;
  char saved_remote_fingerprint[sizeof(pc->dtls_srtp.remote_fingerprint)];

  memcpy(saved_remote_fingerprint, pc->dtls_srtp.remote_fingerprint, sizeof(saved_remote_fingerprint));
  memset(pc->dtls_srtp.remote_fingerprint, 0, sizeof(pc->dtls_srtp.remote_fingerprint));

  /* Browsers often emit LF-only SDP; libpeer used to require CRLF and skipped fingerprint/setup. */
  while (*p) {
    const char* eol = strchr(p, '\n');
    size_t raw_len = eol ? (size_t)(eol - p) : strlen(p);
    size_t line_len = raw_len;
    if (line_len > 0 && p[line_len - 1] == '\r') {
      line_len--;
    }
    if (line_len >= sizeof(buf)) {
      line_len = sizeof(buf) - 1;
    }
    memcpy(buf, p, line_len);
    buf[line_len] = '\0';

    if (strstr(buf, "a=setup:passive")) {
      role = DTLS_SRTP_ROLE_CLIENT;
    }

    if (strncmp(buf, "a=fingerprint:", 14) == 0) {
      const char* sp = strchr(buf + 14, ' ');
      if (sp) {
        sp++;
        size_t i = 0;
        while (sp[i] && i < DTLS_SRTP_FINGERPRINT_LENGTH - 1) {
          pc->dtls_srtp.remote_fingerprint[i] = sp[i];
          i++;
        }
        pc->dtls_srtp.remote_fingerprint[i] = '\0';
      }
    }

    if (strstr(buf, "a=ice-ufrag") &&
        strlen(agent->remote_ufrag) != 0 &&
        (strncmp(buf + strlen("a=ice-ufrag:"), agent->remote_ufrag, strlen(agent->remote_ufrag)) == 0)) {
      is_update = 1;
    }

    if (strstr(buf, "m=video")) {
      ssrc = &pc->remote_vssrc;
    } else if (strstr(buf, "m=audio")) {
      ssrc = &pc->remote_assrc;
    }

    if ((val_start = strstr(buf, "a=ssrc:")) && ssrc) {
      *ssrc = strtoul(val_start + 7, NULL, 10);
      LOGD("SSRC: %" PRIu32, *ssrc);
    }

    if (!eol) {
      break;
    }
    p = eol + 1;
  }

  (void)role;

  {
    size_t fp_len = strlen(pc->dtls_srtp.remote_fingerprint);
    LOGI("set_remote_descr type=%d remote_fp_len=%u head=\"%.32s\"", (int)type, (unsigned)fp_len,
         pc->dtls_srtp.remote_fingerprint);
  }

  if (is_update) {
    if (strlen(pc->dtls_srtp.remote_fingerprint) == 0 && strlen(saved_remote_fingerprint) > 0) {
      memcpy(pc->dtls_srtp.remote_fingerprint, saved_remote_fingerprint,
             sizeof(pc->dtls_srtp.remote_fingerprint));
    }
    return;
  }

  if (type == SDP_TYPE_OFFER) {
    if (sdp_parse_remote_offer_layout(sdp, &pc->remote_offer_layout) == 0) {
      pc->have_remote_offer_layout = 1;
      if (pc->remote_offer_layout.h264_payload_type >= 96 &&
          pc->remote_offer_layout.h264_payload_type <= 127) {
        rtp_encoder_set_payload_type(&pc->vrtp_encoder,
                                       (uint8_t)pc->remote_offer_layout.h264_payload_type);
      }
    } else {
      pc->have_remote_offer_layout = 0;
    }
  }

  agent_set_remote_description(&pc->agent, (char*)sdp);
  if (type == SDP_TYPE_OFFER) {
    LOGI(
        "peer_conn: remote offer parsed — remotes=%d ice_ufrag=%s",
        pc->agent.remote_candidates_count,
        pc->agent.remote_ufrag[0] ? "yes" : "NO");
  }
  if (type == SDP_TYPE_ANSWER) {
    agent_update_candidate_pairs(&pc->agent);
    STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  }
}

/* JSEP: attributes after the last m= line belong to that media only. We used to append
 * all a=candidate lines after m=application, so browsers scoped them to the wrong mid and
 * never completed ICE for the bundled video transport. Insert after the first m=video block. */
static void peer_connection_insert_local_ice_candidates(PeerConnection* pc, const char* candidates) {
  char* sdp = pc->sdp;
  size_t sdp_cap = sizeof(pc->sdp);

  if (!candidates || !candidates[0]) {
    return;
  }

  char* video = strstr(sdp, "m=video");
  char* insert_at = NULL;
  if (video) {
    char* mux = strstr(video, "a=rtcp-mux");
    if (mux) {
      mux += strlen("a=rtcp-mux");
      if (*mux == '\r') {
        mux++;
      }
      if (*mux == '\n') {
        mux++;
      }
      insert_at = mux;
    }
  }

  if (!insert_at) {
    sdp_append(sdp, "%s", candidates);
    return;
  }

  size_t pos = (size_t)(insert_at - sdp);
  size_t cand_len = strlen(candidates);
  size_t tail_len = strlen(sdp + pos);
  if (pos + cand_len + tail_len + 1 > sdp_cap) {
    sdp_append(sdp, "%s", candidates);
    return;
  }

  memmove(sdp + pos + cand_len, sdp + pos, tail_len + 1);
  memcpy(sdp + pos, candidates, cand_len);
}

static void peer_connection_trickle_one_line(char *line, void *userdata) {
  PeerConnection *pc = (PeerConnection *)userdata;
  if (pc->onicecandidate) {
    pc->onicecandidate(line, pc->config.user_data);
  }
}

static const char* peer_connection_create_sdp(PeerConnection* pc, SdpType sdp_type) {
  char* description = (char*)pc->temp_buf;

  memset(pc->temp_buf, 0, sizeof(pc->temp_buf));
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;

  pc->sctp.connected = 0;

  switch (sdp_type) {
    case SDP_TYPE_OFFER:
      role = DTLS_SRTP_ROLE_SERVER;
      agent_clear_candidates(&pc->agent);
      pc->agent.mode = AGENT_MODE_CONTROLLING;
      break;
    case SDP_TYPE_ANSWER:
      role = DTLS_SRTP_ROLE_CLIENT;
      pc->agent.mode = AGENT_MODE_CONTROLLED;
      break;
    default:
      break;
  }

  dtls_srtp_reset_session(&pc->dtls_srtp);
  dtls_srtp_init(&pc->dtls_srtp, role, pc);
  pc->dtls_srtp.udp_recv = peer_connection_dtls_srtp_recv;
  pc->dtls_srtp.udp_send = peer_connection_dtls_srtp_send;

  memset(pc->sdp, 0, sizeof(pc->sdp));

  if (sdp_type == SDP_TYPE_ANSWER && pc->have_remote_offer_layout) {
    sdp_append_answer_session_bundle(pc->sdp, &pc->remote_offer_layout);
  } else {
    // TODO: check if we have video or audio codecs
    sdp_create(pc->sdp,
               pc->config.video_codec != CODEC_NONE,
               pc->config.audio_codec != CODEC_NONE,
               pc->config.datachannel);

    if (pc->config.video_codec == CODEC_H264) {
      sdp_append_h264(pc->sdp);
    }

    switch (pc->config.audio_codec) {
      case CODEC_PCMA:
        sdp_append_pcma(pc->sdp);
        break;
      case CODEC_PCMU:
        sdp_append_pcmu(pc->sdp);
        break;
      case CODEC_OPUS:
        sdp_append_opus(pc->sdp);
      default:
        break;
    }

    if (pc->config.datachannel) {
      sdp_append_datachannel(pc->sdp);
    }
  }

  agent_create_ice_credential(&pc->agent);

  const int answer_with_layout = (sdp_type == SDP_TYPE_ANSWER && pc->have_remote_offer_layout);
  sdp_bundle_transport_attrs_t bundle_attrs;
  const sdp_bundle_transport_attrs_t* bundle_ptr = NULL;
  if (answer_with_layout) {
    bundle_attrs.ice_ufrag = pc->agent.local_ufrag;
    bundle_attrs.ice_pwd = pc->agent.local_upwd;
    bundle_attrs.fingerprint_sha256 = pc->dtls_srtp.local_fingerprint;
    bundle_attrs.setup_line = peer_connection_dtls_role_setup_value(role);
    bundle_ptr = &bundle_attrs;
  } else {
    sdp_append(pc->sdp, "a=ice-ufrag:%s", pc->agent.local_ufrag);
    sdp_append(pc->sdp, "a=ice-pwd:%s", pc->agent.local_upwd);
    sdp_append(pc->sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
    sdp_append(pc->sdp, peer_connection_dtls_role_setup_value(role));
  }

  if (answer_with_layout) {
    sdp_append_answer_media_from_remote(pc->sdp,
                                        &pc->remote_offer_layout,
                                        pc->config.video_codec == CODEC_H264,
                                        (int)pc->config.audio_codec,
                                        pc->config.datachannel != DATA_CHANNEL_NONE,
                                        bundle_ptr);
  }

  pc->b_local_description_created = 1;

#if !CONFIG_ICE_RELAY_ONLY
  agent_gather_candidate(&pc->agent, NULL, NULL, NULL);
#endif

  if (sdp_type == SDP_TYPE_ANSWER) {
    /* Emit the answer immediately with host candidates only; STUN/TURN round-trips
     * run afterward and are trickled so the browser is not stuck waiting seconds
     * on rtc_sig before it receives type=answer (avoids duplicate offers / WS churn). */
    memset(description, 0, sizeof(pc->temp_buf));
    agent_get_local_description(&pc->agent, description, sizeof(pc->temp_buf));
    peer_connection_insert_local_ice_candidates(pc, description);
    if (pc->onicecandidate) {
      pc->onicecandidate(pc->sdp, pc->config.user_data);
    }
    int prev_count = pc->agent.local_candidates_count;
    for (int i = 0; i < (int)(sizeof(pc->config.ice_servers) / sizeof(pc->config.ice_servers[0])); ++i) {
      if (pc->config.ice_servers[i].urls) {
        LOGI("ice server: %s", pc->config.ice_servers[i].urls);
        agent_gather_candidate(&pc->agent, pc->config.ice_servers[i].urls, pc->config.ice_servers[i].username,
                               pc->config.ice_servers[i].credential);
        agent_report_new_local_candidates_trickle(&pc->agent, prev_count, peer_connection_trickle_one_line, pc);
        prev_count = pc->agent.local_candidates_count;
      }
    }
  } else {
    for (int i = 0; i < (int)(sizeof(pc->config.ice_servers) / sizeof(pc->config.ice_servers[0])); ++i) {
      if (pc->config.ice_servers[i].urls) {
        LOGI("ice server: %s", pc->config.ice_servers[i].urls);
        agent_gather_candidate(&pc->agent, pc->config.ice_servers[i].urls, pc->config.ice_servers[i].username,
                               pc->config.ice_servers[i].credential);
      }
    }
    memset(description, 0, sizeof(pc->temp_buf));
    agent_get_local_description(&pc->agent, description, sizeof(pc->temp_buf));
    peer_connection_insert_local_ice_candidates(pc, description);
    if (pc->onicecandidate) {
      pc->onicecandidate(pc->sdp, pc->config.user_data);
    }
  }

  return pc->sdp;
}

const char* peer_connection_create_offer(PeerConnection* pc) {
  return peer_connection_create_sdp(pc, SDP_TYPE_OFFER);
}

const char* peer_connection_create_answer(PeerConnection* pc) {
  const char* sdp = peer_connection_create_sdp(pc, SDP_TYPE_ANSWER);
  agent_update_candidate_pairs(&pc->agent);
  LOGI(
      "peer_conn: post-answer ICE locals=%d remotes=%d pairs=%d turn_alloc=%d",
      pc->agent.local_candidates_count,
      pc->agent.remote_candidates_count,
      pc->agent.candidate_pairs_num,
      pc->agent.turn_allocated);
  STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  return sdp;
}

int peer_connection_send_rtcp_pil(PeerConnection* pc, uint32_t ssrc) {
  int ret = -1;
  uint8_t plibuf[128];
  rtcp_get_pli(plibuf, 12, ssrc);

  // TODO: encrypt rtcp packet
  // guint size = 12;
  // dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  // ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  return ret;
}

// callbacks
void peer_connection_on_connected(PeerConnection* pc, void (*on_connected)(void* userdata)) {
  pc->on_connected = on_connected;
}

void peer_connection_on_receiver_packet_loss(PeerConnection* pc,
                                             void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* userdata)) {
  pc->on_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_onicecandidate(PeerConnection* pc, void (*onicecandidate)(char* sdp, void* userdata)) {
  pc->onicecandidate = onicecandidate;
}

void peer_connection_oniceconnectionstatechange(PeerConnection* pc,
                                                void (*oniceconnectionstatechange)(PeerConnectionState state, void* userdata)) {
  pc->oniceconnectionstatechange = oniceconnectionstatechange;
}

void peer_connection_ondatachannel(PeerConnection* pc,
                                   void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid),
                                   void (*onopen)(void* userdata),
                                   void (*onclose)(void* userdata)) {
  if (pc) {
    sctp_onopen(&pc->sctp, onopen);
    sctp_onclose(&pc->sctp, onclose);
    sctp_onmessage(&pc->sctp, onmessage);
  }
}

int peer_connection_lookup_sid(PeerConnection* pc, const char* label, uint16_t* sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (strncmp(pc->sctp.stream_table[i].label, label, sizeof(pc->sctp.stream_table[i].label)) == 0) {
      *sid = pc->sctp.stream_table[i].sid;
      return 0;
    }
  }
  return -1;  // Not found
}

char* peer_connection_lookup_sid_label(PeerConnection* pc, uint16_t sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (pc->sctp.stream_table[i].sid == sid) {
      return pc->sctp.stream_table[i].label;
    }
  }
  return NULL;  // Not found
}

int peer_connection_add_ice_candidate(PeerConnection* pc, char* candidate) {
  Agent* agent = &pc->agent;
  IceCandidate parsed;
  int i;

  if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
    LOGW("remote candidate pool full (%d) — drop", AGENT_MAX_CANDIDATES);
    return -1;
  }
  if (ice_candidate_from_description(&parsed, candidate, candidate + strlen(candidate)) != 0) {
    return -1;
  }
  /* Chrome sends the same foundation on every BUNDLE m-line; storing each
   * copy wastes remote slots and previously triggered full pair rebuilds
   * that reset connectivity checks on every trickle. */
  for (i = 0; i < agent->remote_candidates_count; i++) {
    if (strcmp(agent->remote_candidates[i].foundation, parsed.foundation) == 0) {
      return 0;
    }
  }
  i = agent->remote_candidates_count;
  agent->remote_candidates[i] = parsed;
  agent->remote_candidates_count++;
  LOGD("Add candidate: %s", candidate);
  agent_add_pairs_for_remote(agent, i);
  return 0;
}
