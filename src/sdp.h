#ifndef SDP_H_
#define SDP_H_

#include <string.h>
#include "config.h"

#define SDP_ATTR_LENGTH 128

#define SDP_MAX_MLINES 8

#ifndef ICE_LITE
#define ICE_LITE 0
#endif

typedef enum {
  SDP_MLINE_VIDEO = 0,
  SDP_MLINE_AUDIO,
  SDP_MLINE_APPLICATION,
} sdp_mline_kind_t;

/** Parsed a=sendrecv / sendonly / recvonly / inactive on each m= block (UNSPEC if omitted). */
typedef enum {
  SDP_MEDIA_DIR_UNSPEC = 0,
  SDP_MEDIA_DIR_SENDRECV,
  SDP_MEDIA_DIR_SENDONLY,
  SDP_MEDIA_DIR_RECVONLY,
  SDP_MEDIA_DIR_INACTIVE,
} sdp_media_direction_t;

typedef struct {
  int count;
  sdp_mline_kind_t kind[SDP_MAX_MLINES];
  char mid[SDP_MAX_MLINES][64];
  sdp_media_direction_t dir[SDP_MAX_MLINES];
  /** First H264/90000 rtpmap PT in the video m= section; 0 = answer with default 96. */
  int h264_payload_type;
} sdp_remote_offer_layout_t;

/** If non-NULL, append these lines right after each bundled m= section's c= line (Chrome/JSEP). */
typedef struct {
  const char* ice_ufrag;
  const char* ice_pwd;
  const char* fingerprint_sha256;
  /** Full line without trailing CRLF, e.g. "a=setup:active". */
  const char* setup_line;
} sdp_bundle_transport_attrs_t;

void sdp_append_h264(char* sdp);

/**
 * @param direction_or_null RTP direction attribute without "a=" prefix; NULL defaults to sendrecv.
 * @param h264_pt dynamic payload type for H264 (96–127); 0 defaults to 96.
 * @param bundle_transport_or_null optional per-mid ICE+DTLS (BUNDLE answer to browsers).
 */
void sdp_append_h264_mid(char* sdp,
                         const char* mid,
                         const char* direction_or_null,
                         int h264_pt,
                         const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

void sdp_append_pcma(char* sdp);

void sdp_append_pcma_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

void sdp_append_pcmu(char* sdp);

void sdp_append_pcmu_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

void sdp_append_opus(char* sdp);

void sdp_append_opus_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

void sdp_append_datachannel(char* sdp);

void sdp_append_datachannel_mid(char* sdp, const char* mid, const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

void sdp_create(char* sdp, int b_video, int b_audio, int b_datachannel);

/**
 * Parse remote SDP (typically a browser offer) for m-line order and mids.
 * @return 0 if at least one m= line was found, -1 otherwise.
 */
int sdp_parse_remote_offer_layout(const char* sdp, sdp_remote_offer_layout_t* out);

/** v= / o= / … / a=group:BUNDLE &lt;mids&gt; — must come before ICE/DTLS and before any m= line. */
void sdp_append_answer_session_bundle(char* sdp, const sdp_remote_offer_layout_t* lo);

/**
 * All m= sections in remote offer order (call after session ICE + fingerprint lines).
 * @param audio_codec MediaCodec value (CODEC_NONE / CODEC_OPUS / CODEC_PCMA / CODEC_PCMU).
 * @param bundle_transport_or_null ICE+DTLS lines repeated under each m= (NULL = omit).
 */
void sdp_append_answer_media_from_remote(char* sdp,
                                         const sdp_remote_offer_layout_t* lo,
                                         int want_h264,
                                         int audio_codec,
                                         int want_datachannel,
                                         const sdp_bundle_transport_attrs_t* bundle_transport_or_null);

int sdp_append(char* sdp, const char* format, ...);

void sdp_reset(char* sdp);

#endif  // SDP_H_
