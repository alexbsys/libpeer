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

/* TEMP freeze-hunt: phase tracker. g_pcl_seq increments once per loop entry;
 * g_pcl_phase is set to a checkpoint id before/after each potentially-blocking
 * call. An independent lock-free heartbeat task (esp_peer_libpeer_default.c)
 * prints these via esp_rom_printf, so if peer_connection_loop() ever stops
 * returning, the last phase pinpoints the exact call that hung. Remove once fixed. */
volatile uint32_t g_pcl_seq = 0;
volatile uint32_t g_pcl_phase = 0;
#define PCL(p) do { g_pcl_phase = (uint32_t)(p); } while (0)

/* TEMP freeze-hunt: lock-free UART print (bypasses wedged stdout lock). */
extern int esp_rom_printf(const char* fmt, ...);

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
  void (*on_remb_bitrate)(uint32_t bitrate_bps, void* user_data);

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

  /* Outbound RTCP Sender Report (RFC 3550 §6.4.1) for the video SSRC. Counts are
   * accumulated in the outgoing RTP callback; the report is emitted periodically
   * from the COMPLETED loop so the browser gets NTP<->RTP anchoring (A/V sync,
   * accurate getStats) and can echo LSR/DLSR for RTT. */
  uint32_t vsr_packet_count;
  uint32_t vsr_octet_count;
  uint32_t vsr_last_rtp_ts;
  uint32_t vsr_last_send_ms;

  /* Wall-clock (ms) of the last inbound RTCP packet. A media-path liveness
   * signal: when we are actively sending video but stop receiving RTCP
   * (RR/REMB/PLI) the downstream path is likely throttled/dead even if ICE
   * consent still passes. 0 = no RTCP seen yet. */
  uint32_t last_rtcp_in_ms;
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
  /* Tally the video stream for its Sender Report (shared callback also serves
   * audio, so filter by SSRC). Counts are pre-encryption: packet count and
   * payload octets (RFC 3550 excludes the 12-byte RTP header), plus the latest
   * RTP timestamp to anchor the SR's NTP/RTP pair. */
  if (size >= 12) {
    const RtpHeader* h = (const RtpHeader*)data;
    if (ntohl(h->ssrc) == pc->vrtp_encoder.ssrc) {
      pc->vsr_packet_count++;
      pc->vsr_octet_count += (uint32_t)(size - 12);
      pc->vsr_last_rtp_ts = ntohl(h->timestamp);
    }
  }
  rtp_nack_cache_store(&pc->nack_cache, data, (int)size);
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  agent_send(&pc->agent, data, size);
}

/* Emit an RTCP Sender Report for the outbound video SSRC. Cheap: one ~28 B packet
 * (+SRTCP tag) at PC_SR_INTERVAL_MS. The NTP field uses the monotonic ms clock —
 * its absolute value need not be real wall time for a single stream; the receiver
 * echoes the middle 32 bits back via RR for RTT and uses NTP<->RTP to anchor
 * playout. */
#define PC_SR_INTERVAL_MS 1000
static void peer_connection_send_video_sr(PeerConnection* pc) {
  uint8_t pkt[64];
  uint32_t now_ms;
  uint32_t ntp_sec;
  uint32_t ntp_frac;
  int len;

  if (pc->state != PEER_CONNECTION_COMPLETED || pc->vsr_packet_count == 0) {
    return;
  }

  now_ms = (uint32_t)ports_get_epoch_time();
  ntp_sec = now_ms / 1000u;
  ntp_frac = (uint32_t)(((uint64_t)(now_ms % 1000u) << 32) / 1000u);

  pkt[0] = 0x80;                 /* V=2, P=0, RC=0 */
  pkt[1] = (uint8_t)RTCP_SR;     /* 200 */
  pkt[2] = 0x00;                 /* length = 6 (28 bytes / 4 - 1) */
  pkt[3] = 0x06;
  *(uint32_t*)(pkt + 4) = htonl(pc->vrtp_encoder.ssrc);
  *(uint32_t*)(pkt + 8) = htonl(ntp_sec);
  *(uint32_t*)(pkt + 12) = htonl(ntp_frac);
  *(uint32_t*)(pkt + 16) = htonl(pc->vsr_last_rtp_ts);
  *(uint32_t*)(pkt + 20) = htonl(pc->vsr_packet_count);
  *(uint32_t*)(pkt + 24) = htonl(pc->vsr_octet_count);
  len = 28;

  dtls_srtp_encrypt_rctp_packet(&pc->dtls_srtp, pkt, &len);
  if (len > 0) {
    agent_send(&pc->agent, pkt, len);
  }
}

/* RTP/RTCP use version 2 in the top two bits (RFC 3550). Those must not be fed to mbedTLS
 * during DTLS handshake — on low-latency LAN paths they can arrive on the same ICE socket
 * before DTLS completes and cause MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE / CONN_EOF. */
static int peer_connection_looks_like_rtp_or_rtcp(const uint8_t* buf, int n) {
  return n >= 1 && (buf[0] & 0xC0) == 0x80;
}

static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  const int handshake_phase = dtls_srtp->handshaking;
  /* Wall-clock bound for one DTLS read. This callback runs synchronously inside
   * peer_connection_loop() while the per-peer lock is held, so it must return
   * promptly to keep the lock free for video/UI/signaling. During the handshake
   * we return MBEDTLS_ERR_SSL_WANT_READ on timeout (NOT 0 — mbedTLS reads 0 as
   * connection EOF and aborts): mbedTLS preserves handshake state, the loop
   * releases the lock, and the next iteration resumes the same handshake so a
   * multi-datagram flight (e.g. the server flight over a TURN relay) is
   * accumulated across iterations instead of being reset every timeout. Outside
   * the handshake (datachannel reads) we keep the original return so callers that
   * loop on WANT_READ don't spin. */
  const uint32_t deadline_ms = 200;
  uint32_t start = (uint32_t)ports_get_epoch_time();
  int iters = 0;

  if (handshake_phase) {
    esp_rom_printf("DTLSRXenter len=%u\n", (unsigned)len);
  }

  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  while (pc->state == PEER_CONNECTION_CONNECTED &&
         (uint32_t)((uint32_t)ports_get_epoch_time() - start) < deadline_ms) {
    ret = agent_recv(&pc->agent, buf, len);
    iters++;

    if (ret > 0) {
      if (handshake_phase && peer_connection_looks_like_rtp_or_rtcp(buf, ret)) {
        LOGD("skip RTP/RTCP (%d B) during DTLS handshake", ret);
        ret = -1;
      } else {
        if (handshake_phase) {
          esp_rom_printf("DTLSRX got %d B after %d iters\n", ret, iters);
        }
        break;
      }
    }
    /* Yield periodically: a STUN/connectivity flood on this socket makes
     * agent_recv() return immediately every time (no select() wait), which
     * would CPU-starve video/UI/signaling for the whole deadline. */
    if ((iters & 0x1f) == 0) {
      ports_sleep_ms(1);
    }
  }
  if (handshake_phase && ret <= 0) {
    esp_rom_printf("DTLSRX timeout iters=%d\n", iters);
    /* No data this window: tell mbedTLS to wait (and let it drive retransmission
     * via the timer cb) rather than signalling EOF. */
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return ret;
}

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  // LOGD("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len);
  int sret = agent_send(&pc->agent, buf, len);
  if (pc->dtls_srtp.handshaking) {
    esp_rom_printf("DTLSTX sret=%d len=%u ct=%u\n", sret, (unsigned)len,
                   (len > 0) ? (unsigned)buf[0] : 0u);
  }
  /* mbedTLS's BIO send callback must report the number of *payload* bytes
   * accepted, not the wire bytes. agent_send() over a TURN relay returns the
   * framed size (payload + ChannelData/Send header), which is > len; mbedTLS
   * treats a return > len as a fault and aborts the handshake. Clamp success to
   * len (datagram sends are atomic, so sret > 0 means the whole flight went). */
  if (sret > 0) {
    return (int)len;
  }
  return sret;
}

static void peer_connection_incoming_rtcp(PeerConnection* pc, uint8_t* buf, size_t len) {
  RtcpHeader* rtcp_header;
  size_t pos = 0;

  pc->last_rtcp_in_ms = (uint32_t)ports_get_epoch_time();

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
        } else if (fmt == 15 && pc->on_remb_bitrate) {
          /* RFC draft "goog-remb": PSFB (PT=206) with FMT=15. The FCI
             (offset 12 = 4 hdr + 4 sender SSRC + 4 media SSRC) is:
               'R','E','M','B'  (4 bytes, unique id)
               num_ssrc         (1 byte)
               exp:6 | mantissa:18  (3 bytes, big-endian bitfield)
               feedback SSRC[]  (4 bytes each)
             Estimated max bitrate (bps) = mantissa << exp. */
          size_t block_bytes = 4 * ((size_t)ntohs(rtcp_header->length) + 1u);
          if (pos + block_bytes <= len && block_bytes >= 12u + 8u) {
            const uint8_t* fci = buf + pos + 12;
            if (fci[0] == 'R' && fci[1] == 'E' && fci[2] == 'M' && fci[3] == 'B') {
              uint8_t exp = (uint8_t)(fci[5] >> 2);
              uint32_t mantissa = ((uint32_t)(fci[5] & 0x03) << 16) | ((uint32_t)fci[6] << 8) | (uint32_t)fci[7];
              uint64_t bitrate = (uint64_t)mantissa << exp;
              if (bitrate > 0xFFFFFFFFull) {
                bitrate = 0xFFFFFFFFull;
              }
              pc->on_remb_bitrate((uint32_t)bitrate, pc->config.user_data);
            }
          }
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

static const char* peer_ice_candidate_type_str(int type) {
  switch (type) {
    case ICE_CANDIDATE_TYPE_HOST:
      return "host";
    case ICE_CANDIDATE_TYPE_SRFLX:
      return "srflx";
    case ICE_CANDIDATE_TYPE_PRFLX:
      return "prflx";
    case ICE_CANDIDATE_TYPE_RELAY:
      return "relay";
    default:
      return "?";
  }
}

static void peer_ice_format_addr(const Address* addr, char* out, size_t out_len) {
  char ip[ADDRSTRLEN];
  if (!addr) {
    snprintf(out, out_len, "-");
    return;
  }
  addr_to_string(addr, ip, sizeof(ip));
  snprintf(out, out_len, "%s:%d", ip, addr->port);
}

int peer_connection_get_ice_info(PeerConnection* pc, PeerIceInfo* info) {
  if (!pc || !info) {
    return -1;
  }
  memset(info, 0, sizeof(*info));
  info->state = pc->state;
  info->ms_since_rtcp_in = pc->last_rtcp_in_ms
                               ? (int)((uint32_t)ports_get_epoch_time() - pc->last_rtcp_in_ms)
                               : -1;
  info->controlling = (pc->agent.mode == AGENT_MODE_CONTROLLING) ? 1 : 0;
  info->turn_allocated = pc->agent.turn_allocated ? 1 : 0;
  info->relay_over_tcp = pc->agent.turn_use_tcp ? 1 : 0;
  info->local_type_str = "-";
  info->remote_type_str = "-";
  info->transport_str = "none";
  snprintf(info->local_addr, sizeof(info->local_addr), "-");
  snprintf(info->remote_addr, sizeof(info->remote_addr), "-");

  IceCandidatePair* pair = pc->agent.nominated_pair;
  if (!pair) {
    pair = pc->agent.selected_pair;
  }
  if (pair && pair->local && pair->remote) {
    info->connected = 1;
    info->local_type = pair->local->type;
    info->remote_type = pair->remote->type;
    info->local_type_str = peer_ice_candidate_type_str(pair->local->type);
    info->remote_type_str = peer_ice_candidate_type_str(pair->remote->type);
    info->via_relay = (pair->local->type == ICE_CANDIDATE_TYPE_RELAY ||
                       pair->remote->type == ICE_CANDIDATE_TYPE_RELAY)
                          ? 1
                          : 0;
    peer_ice_format_addr(&pair->local->addr, info->local_addr, sizeof(info->local_addr));
    peer_ice_format_addr(&pair->remote->addr, info->remote_addr, sizeof(info->remote_addr));
    if (info->via_relay) {
      info->transport_str = info->relay_over_tcp ? "relay-tcp" : "relay-udp";
    } else {
      info->transport_str = "udp";
    }
  }
  return 0;
}

/* Log the selected ICE path. Reads the pair directly with no large locals so
 * it adds negligible stack to the (stack-tight) peer_connection_loop() frame
 * that runs the SDP/gather path. The full address detail stays available via
 * peer_connection_get_ice_info() for programmatic callers. */
static void peer_connection_log_selected_ice(PeerConnection* pc) {
  IceCandidatePair* pair = pc->agent.nominated_pair;
  if (!pair) {
    pair = pc->agent.selected_pair;
  }
  if (!pair || !pair->local || !pair->remote) {
    return;
  }
  int relay = (pair->local->type == ICE_CANDIDATE_TYPE_RELAY ||
               pair->remote->type == ICE_CANDIDATE_TYPE_RELAY);
  LOGI("ICE selected: transport=%s local=%s remote=%s role=%s turn_alloc=%d",
       relay ? (pc->agent.turn_use_tcp ? "relay-tcp" : "relay-udp") : "udp",
       peer_ice_candidate_type_str(pair->local->type),
       peer_ice_candidate_type_str(pair->remote->type),
       pc->agent.mode == AGENT_MODE_CONTROLLING ? "controlling" : "controlled",
       pc->agent.turn_allocated);
  /* TEMP freeze-hunt: lock-free mirror, survives a wedged stdout lock. */
  uint32_t lip = (uint32_t)pair->local->addr.sin.sin_addr.s_addr;
  uint32_t rip = (uint32_t)pair->remote->addr.sin.sin_addr.s_addr;
  esp_rom_printf(
      "DTLSPATH selected transport=%s local=%s(%u.%u.%u.%u:%u) "
      "remote=%s(%u.%u.%u.%u:%u) role=%s turn=%d remote_nom=%d\n",
      relay ? (pc->agent.turn_use_tcp ? "relay-tcp" : "relay-udp") : "udp",
      peer_ice_candidate_type_str(pair->local->type),
      lip & 0xff, (lip >> 8) & 0xff, (lip >> 16) & 0xff, (lip >> 24) & 0xff, pair->local->addr.port,
      peer_ice_candidate_type_str(pair->remote->type),
      rip & 0xff, (rip >> 8) & 0xff, (rip >> 16) & 0xff, (rip >> 24) & 0xff, pair->remote->addr.port,
      pc->agent.mode == AGENT_MODE_CONTROLLING ? "controlling" : "controlled",
      pc->agent.turn_allocated, pc->agent.remote_nominated);
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

  /* Propagate ICE behavior policy (relay-only / relay transport) to the agent
   * so gathering and pairing honor it. */
  pc->agent.ice_transport_policy = (int)pc->config.ice_transport_policy;
  pc->agent.ice_relay_protocol = (int)pc->config.ice_relay_protocol;
  if (pc->agent.ice_transport_policy == AGENT_ICE_POLICY_RELAY ||
      pc->agent.ice_relay_protocol != AGENT_ICE_RELAY_ANY) {
    LOGI("ICE policy: transport=%s relay_proto=%s",
         pc->agent.ice_transport_policy == AGENT_ICE_POLICY_RELAY ? "relay-only" : "all",
         pc->agent.ice_relay_protocol == AGENT_ICE_RELAY_UDP   ? "udp"
         : pc->agent.ice_relay_protocol == AGENT_ICE_RELAY_TCP ? "tcp"
                                                               : "any");
  }

  rtp_nack_cache_init(&pc->nack_cache);
  pc->rtx_seq_number = 1;
  pc->vsr_packet_count = 0;
  pc->vsr_octet_count = 0;
  pc->vsr_last_rtp_ts = 0;
  pc->vsr_last_send_ms = 0;
  pc->last_rtcp_in_ms = 0;

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
  g_pcl_seq++;
  PCL(1);
  memset(pc->agent_buf, 0, sizeof(pc->agent_buf));
  pc->agent_ret = -1;

  switch (pc->state) {
    case PEER_CONNECTION_NEW:
      break;

    case PEER_CONNECTION_CHECKING:
      PCL(10);
      if (agent_select_candidate_pair(&pc->agent) < 0) {
        PCL(11);
        agent_log_ice_diagnostics(&pc->agent, "select_pair -> FAILED (no usable ICE pair)");
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      } else {
        PCL(12);
        if (agent_connectivity_check(&pc->agent) == 0 &&
            agent_ready_to_finalize(&pc->agent)) {
          PCL(13);
          LOGI("peer_conn: ICE nominated pair succeeded — starting DTLS-SRTP");
          /* Keep the large PeerIceInfo off this (stack-tight) loop frame — see
           * peer_connection_log_selected_ice(). */
          peer_connection_log_selected_ice(pc);
          STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
        }
      }
      PCL(14);
      break;

    case PEER_CONNECTION_CONNECTED:

      PCL(20);
      {
        int _hs = dtls_srtp_handshake(&pc->dtls_srtp, NULL);
        if (_hs != 1) { /* skip in-progress spam; log only done(0)/fatal(-1) */
          esp_rom_printf("DTLSHS ret=%d state=%d role=%d\n", _hs, (int)pc->dtls_srtp.state,
                         (int)pc->dtls_srtp.role);
        }
        if (_hs != 0) {
          PCL(22);
          break;
        }
      }
      {
        PCL(21);
        LOGI("peer_conn: DTLS-SRTP handshake done — media path ready");

        /* Test-only: arm UDP fault injection now that media is flowing, so the
         * simulated throttle hits the established stream rather than the
         * handshake (see LIBPEER_FAULT_INJECT in agent.c). No-op otherwise. */
        pc->agent.fault_armed = 1;

        if (pc->config.datachannel) {
          LOGI("SCTP create socket");
          sctp_create_association(&pc->sctp, &pc->dtls_srtp);
          pc->sctp.userdata = pc->config.user_data;
        }

        STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
      }
      PCL(22);
      break;
    case PEER_CONNECTION_COMPLETED:
      PCL(30);
      if ((pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf))) > 0) {
        PCL(31);
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

      if ((uint32_t)((uint32_t)ports_get_epoch_time() - pc->vsr_last_send_ms) >= PC_SR_INTERVAL_MS) {
        pc->vsr_last_send_ms = (uint32_t)ports_get_epoch_time();
        peer_connection_send_video_sr(pc);
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

  PCL(99);
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

void peer_connection_on_remb(PeerConnection* pc,
                             void (*on_remb_bitrate)(uint32_t bitrate_bps, void* userdata)) {
  pc->on_remb_bitrate = on_remb_bitrate;
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
