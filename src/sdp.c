#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sdp.h"
#include "rtp.h"

/* MediaCodec from peer_connection.h — keep in sync (audio starts at OPUS). */
enum {
  SDP_CODEC_OPUS = 4,
  SDP_CODEC_PCMA = 5,
  SDP_CODEC_PCMU = 6,
};

int sdp_append(char* sdp, const char* format, ...) {
  va_list argptr;

  va_start(argptr, format);

  if (sdp[0] == '\0') {
    vsnprintf(sdp, CONFIG_SDP_BUFFER_SIZE, format, argptr);
  } else {
    vsnprintf(sdp + strlen(sdp), CONFIG_SDP_BUFFER_SIZE - strlen(sdp), format, argptr);
  }

  if (sdp[strlen(sdp) - 1] != '\n') {
    strcat(sdp, "\r\n");
  }

  va_end(argptr);
  return 0;
}

void sdp_reset(char* sdp) {
  memset(sdp, 0, CONFIG_SDP_BUFFER_SIZE);
}

static void sdp_append_bundle_transport_after_c_line(char* sdp,
                                                     const sdp_bundle_transport_attrs_t* b) {
  if (!b || !b->ice_ufrag || !b->ice_pwd || !b->fingerprint_sha256 || !b->setup_line) {
    return;
  }
  sdp_append(sdp, "a=ice-ufrag:%s", b->ice_ufrag);
  sdp_append(sdp, "a=ice-pwd:%s", b->ice_pwd);
  sdp_append(sdp, "a=fingerprint:sha-256 %s", b->fingerprint_sha256);
  sdp_append(sdp, "%s", b->setup_line);
}

void sdp_append_h264_mid(char* sdp,
                         const char* mid,
                         const char* direction_or_null,
                         int h264_pt,
                         const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  const char* d = direction_or_null ? direction_or_null : "sendrecv";
  int pt = (h264_pt >= 96 && h264_pt <= 127) ? h264_pt : 96;
  const int rtx_pt = PT_H264_RTX;
  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF %d %d", pt, rtx_pt);
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtcp-fb:%d nack", pt);
  sdp_append(sdp, "a=rtcp-fb:%d nack pli", pt);
  sdp_append(sdp, "a=rtcp-fb:%d goog-remb", pt);
  sdp_append(sdp,
             "a=fmtp:%d profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1",
             pt);
  sdp_append(sdp, "a=rtpmap:%d H264/90000", pt);
  sdp_append(sdp, "a=rtpmap:%d rtx/90000", rtx_pt);
  sdp_append(sdp, "a=fmtp:%d apt=%d", rtx_pt, pt);
  sdp_append(sdp, "a=ssrc-group:FID %d %d", (int)SSRC_H264, (int)SSRC_H264_RTX);
  sdp_append(sdp, "a=ssrc:%d cname:webrtc-h264", (int)SSRC_H264);
  sdp_append(sdp, "a=ssrc:%d cname:webrtc-h264-rtx", (int)SSRC_H264_RTX);
  sdp_append(sdp, "a=%s", d);
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_h264(char* sdp) {
  sdp_append_h264_mid(sdp, "video", NULL, 0, NULL);
}

static void sdp_append_rejected_video_mid(char* sdp,
                                          const char* mid,
                                          int h264_pt,
                                          const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  int pt = (h264_pt >= 96 && h264_pt <= 127) ? h264_pt : 96;
  sdp_append(sdp, "m=video 0 UDP/TLS/RTP/SAVPF %d", pt);
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtpmap:%d H264/90000", pt);
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=inactive");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcma_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 8");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtpmap:8 PCMA/8000");
  sdp_append(sdp, "a=ssrc:4 cname:webrtc-pcma");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcma(char* sdp) {
  sdp_append_pcma_mid(sdp, "audio", NULL);
}

void sdp_append_pcmu_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 0");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtpmap:0 PCMU/8000");
  sdp_append(sdp, "a=ssrc:5 cname:webrtc-pcmu");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcmu(char* sdp) {
  sdp_append_pcmu_mid(sdp, "audio", NULL);
}

void sdp_append_opus_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 111");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtpmap:111 opus/48000/2");
  sdp_append(sdp, "a=ssrc:6 cname:webrtc-opus");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_opus(char* sdp) {
  sdp_append_opus_mid(sdp, "audio", NULL);
}

static void sdp_append_rejected_audio_mid(char* sdp,
                                          const char* mid,
                                          const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=audio 0 UDP/TLS/RTP/SAVPF 111");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=rtpmap:111 opus/48000/2");
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=inactive");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_datachannel_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=application 50712 UDP/DTLS/SCTP webrtc-datachannel");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=sctp-port:5000");
  sdp_append(sdp, "a=max-message-size:262144");
}

void sdp_append_datachannel(char* sdp) {
  sdp_append_datachannel_mid(sdp, "datachannel", NULL);
}

static void sdp_append_rejected_application_mid(char* sdp,
                                                const char* mid,
                                                const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  sdp_append(sdp, "m=application 0 UDP/DTLS/SCTP webrtc-datachannel");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append_bundle_transport_after_c_line(sdp, bundle_transport_or_null);
  sdp_append(sdp, "a=mid:%s", mid);
  sdp_append(sdp, "a=sctp-port:5000");
  sdp_append(sdp, "a=max-message-size:262144");
  sdp_append(sdp, "a=inactive");
}

void sdp_create(char* sdp, int b_video, int b_audio, int b_datachannel) {
  char bundle[64];
  sdp_append(sdp, "v=0");
  sdp_append(sdp, "o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
  sdp_append(sdp, "s=-");
  sdp_append(sdp, "t=0 0");
  sdp_append(sdp, "a=msid-semantic: iot");
#if ICE_LITE
  sdp_append(sdp, "a=ice-lite");
#endif
  memset(bundle, 0, sizeof(bundle));

  strcat(bundle, "a=group:BUNDLE");

  if (b_video) {
    strcat(bundle, " video");
  }

  if (b_audio) {
    strcat(bundle, " audio");
  }

  if (b_datachannel) {
    strcat(bundle, " datachannel");
  }

  sdp_append(sdp, bundle);
}

int sdp_parse_remote_offer_layout(const char* sdp, sdp_remote_offer_layout_t* out) {
  int cur = -1;

  memset(out, 0, sizeof(*out));

  if (!sdp) {
    return -1;
  }

  const char* p = sdp;
  while (*p) {
    const char* eol = strchr(p, '\n');
    size_t raw_len = eol ? (size_t)(eol - p) : strlen(p);
    size_t line_len = raw_len;
    if (line_len > 0 && p[line_len - 1] == '\r') {
      line_len--;
    }

    char line[256];
    if (line_len >= sizeof(line)) {
      line_len = sizeof(line) - 1;
    }
    memcpy(line, p, line_len);
    line[line_len] = '\0';

    if (strncmp(line, "m=video", 7) == 0) {
      if (out->count >= SDP_MAX_MLINES) {
        return -1;
      }
      cur = out->count++;
      out->kind[cur] = SDP_MLINE_VIDEO;
      out->mid[cur][0] = '\0';
    } else if (strncmp(line, "m=audio", 7) == 0) {
      if (out->count >= SDP_MAX_MLINES) {
        return -1;
      }
      cur = out->count++;
      out->kind[cur] = SDP_MLINE_AUDIO;
      out->mid[cur][0] = '\0';
    } else if (strncmp(line, "m=application", 13) == 0) {
      if (out->count >= SDP_MAX_MLINES) {
        return -1;
      }
      cur = out->count++;
      out->kind[cur] = SDP_MLINE_APPLICATION;
      out->mid[cur][0] = '\0';
    } else if (cur >= 0 && strncmp(line, "a=mid:", 6) == 0) {
      const char* val = line + 6;
      strncpy(out->mid[cur], val, sizeof(out->mid[cur]) - 1);
      out->mid[cur][sizeof(out->mid[cur]) - 1] = '\0';
    } else if (cur >= 0 && out->kind[cur] == SDP_MLINE_VIDEO && out->h264_payload_type == 0 &&
               strncmp(line, "a=rtpmap:", 9) == 0) {
      int pt = atoi(line + 9);
      if (pt >= 96 && pt <= 127 && strstr(line, "H264/90000") != NULL) {
        out->h264_payload_type = pt;
      }
    } else if (cur >= 0 && strcmp(line, "a=sendrecv") == 0) {
      out->dir[cur] = SDP_MEDIA_DIR_SENDRECV;
    } else if (cur >= 0 && strcmp(line, "a=sendonly") == 0) {
      out->dir[cur] = SDP_MEDIA_DIR_SENDONLY;
    } else if (cur >= 0 && strcmp(line, "a=recvonly") == 0) {
      out->dir[cur] = SDP_MEDIA_DIR_RECVONLY;
    } else if (cur >= 0 && strcmp(line, "a=inactive") == 0) {
      out->dir[cur] = SDP_MEDIA_DIR_INACTIVE;
    }

    if (!eol) {
      break;
    }
    p = eol + 1;
  }

  for (int i = 0; i < out->count; i++) {
    if (out->mid[i][0] == '\0') {
      snprintf(out->mid[i], sizeof(out->mid[i]), "%d", i);
    }
  }

  return out->count > 0 ? 0 : -1;
}

void sdp_append_answer_session_bundle(char* sdp, const sdp_remote_offer_layout_t* lo) {
  char bundle[512];
  char midbuf[64];

  sdp_append(sdp, "v=0");
  sdp_append(sdp, "o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
  sdp_append(sdp, "s=-");
  sdp_append(sdp, "t=0 0");
  sdp_append(sdp, "a=msid-semantic: iot");
#if ICE_LITE
  sdp_append(sdp, "a=ice-lite");
#endif

  memset(bundle, 0, sizeof(bundle));
  strcat(bundle, "a=group:BUNDLE");
  for (int i = 0; i < lo->count; i++) {
    const char* mid = lo->mid[i];
    if (!mid || mid[0] == '\0') {
      snprintf(midbuf, sizeof(midbuf), "%d", i);
      mid = midbuf;
    }
    size_t bl = strlen(bundle);
    snprintf(bundle + bl, sizeof(bundle) - bl, " %s", mid);
  }
  sdp_append(sdp, "%s", bundle);
}

/* JSEP: if remote will only receive our RTP, answer sendonly; if remote only sends, we cannot answer sendrecv. */
static const char* sdp_h264_answer_direction(sdp_media_direction_t offer_dir) {
  switch (offer_dir) {
    case SDP_MEDIA_DIR_RECVONLY:
      return "sendonly";
    case SDP_MEDIA_DIR_SENDRECV:
      return "sendonly";
    case SDP_MEDIA_DIR_SENDONLY:
      return "inactive";
    case SDP_MEDIA_DIR_INACTIVE:
      return "inactive";
    default:
      /* Unspecified in offer: viewers almost always use recvonly for remote video. */
      return "sendonly";
  }
}

void sdp_append_answer_media_from_remote(char* sdp,
                                         const sdp_remote_offer_layout_t* lo,
                                         int want_h264,
                                         int audio_codec,
                                         int want_datachannel,
                                         const sdp_bundle_transport_attrs_t* bundle_transport_or_null) {
  char midbuf[64];

  for (int i = 0; i < lo->count; i++) {
    const char* mid = lo->mid[i];
    if (!mid || mid[0] == '\0') {
      snprintf(midbuf, sizeof(midbuf), "%d", i);
      mid = midbuf;
    }

    switch (lo->kind[i]) {
      case SDP_MLINE_VIDEO:
        if (want_h264) {
          sdp_append_h264_mid(sdp,
                              mid,
                              sdp_h264_answer_direction(lo->dir[i]),
                              lo->h264_payload_type,
                              bundle_transport_or_null);
        } else {
          sdp_append_rejected_video_mid(sdp, mid, lo->h264_payload_type, bundle_transport_or_null);
        }
        break;
      case SDP_MLINE_AUDIO:
        if (audio_codec == SDP_CODEC_OPUS) {
          sdp_append_opus_mid(sdp, mid, bundle_transport_or_null);
        } else if (audio_codec == SDP_CODEC_PCMA) {
          sdp_append_pcma_mid(sdp, mid, bundle_transport_or_null);
        } else if (audio_codec == SDP_CODEC_PCMU) {
          sdp_append_pcmu_mid(sdp, mid, bundle_transport_or_null);
        } else {
          sdp_append_rejected_audio_mid(sdp, mid, bundle_transport_or_null);
        }
        break;
      case SDP_MLINE_APPLICATION:
        if (want_datachannel) {
          sdp_append_datachannel_mid(sdp, mid, bundle_transport_or_null);
        } else {
          sdp_append_rejected_application_mid(sdp, mid, bundle_transport_or_null);
        }
        break;
      default:
        break;
    }
  }
}
