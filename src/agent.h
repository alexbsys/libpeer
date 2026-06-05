#ifndef AGENT_H_
#define AGENT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "ice.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

#ifndef AGENT_MAX_DESCRIPTION
#define AGENT_MAX_DESCRIPTION 40960
#endif

#ifndef AGENT_MAX_CANDIDATES
/* Default 10 is too small for modern browser offers (many a=candidate lines).
 * Match the headroom we used with esp_peer_default (max_candidates=32). */
#define AGENT_MAX_CANDIDATES 64
#endif

#ifndef AGENT_MAX_CANDIDATE_PAIRS
#define AGENT_MAX_CANDIDATE_PAIRS 100
#endif

typedef enum AgentState {

  AGENT_STATE_GATHERING_ENDED = 0,
  AGENT_STATE_GATHERING_STARTED,
  AGENT_STATE_GATHERING_COMPLETED,

} AgentState;

typedef enum AgentMode {

  AGENT_MODE_CONTROLLED = 0,
  AGENT_MODE_CONTROLLING

} AgentMode;

/* Mirror of peer_connection.h IceTransportPolicy / IceRelayProtocol. Kept as
 * plain macros so the low-level agent does not depend on the public header. */
#define AGENT_ICE_POLICY_ALL 0
#define AGENT_ICE_POLICY_RELAY 1
#define AGENT_ICE_RELAY_ANY 0
#define AGENT_ICE_RELAY_UDP 1
#define AGENT_ICE_RELAY_TCP 2

typedef struct Agent Agent;

struct Agent {
  char remote_ufrag[ICE_UFRAG_LENGTH + 1];
  char remote_upwd[ICE_UPWD_LENGTH + 1];

  char local_ufrag[ICE_UFRAG_LENGTH + 1];
  char local_upwd[ICE_UPWD_LENGTH + 1];

  IceCandidate local_candidates[AGENT_MAX_CANDIDATES];
  IceCandidate remote_candidates[AGENT_MAX_CANDIDATES];

  int local_candidates_count;
  int remote_candidates_count;

  UdpSocket udp_sockets[2];

  Address host_addr;
  int b_host_addr;
  uint64_t binding_request_time;
  AgentState state;

  AgentMode mode;

  IceCandidatePair candidate_pairs[AGENT_MAX_CANDIDATE_PAIRS];
  IceCandidatePair* selected_pair;
  IceCandidatePair* nominated_pair;

  int candidate_pairs_num;
  int use_candidate;
  /* Controlled agent: set once the controlling peer (browser) sends a Binding
   * request with USE-CANDIDATE. Until then a controlled agent must NOT finalize
   * the selected pair from its own rank-based pick, or it can commit to a pair
   * (e.g. host<->host that succeeds first) the peer later abandons for a relay,
   * leaving DTLS waiting forever on a path the peer never sends to. */
  int remote_nominated;
  /* Controlled agent fallback: epoch-ms deadline after which we stop waiting for
   * USE-CANDIDATE and accept our own self-selected pair (so a peer that never
   * trickles a clean nomination still connects). 0 = not armed yet. */
  uint32_t controlled_nom_deadline;
  uint32_t transaction_id[3];

  /* TURN allocation state — ICE checks to relay addrs need Send/Permission. */
  int turn_use_tcp;
  TcpSocket turn_tcp;
  Address turn_server;
  char turn_username[128];
  char turn_password[128];
  char turn_realm[64];
  char turn_nonce[64];
  Address turn_relay_addr;
  int turn_allocated;
  Address turn_permissions[16];
  int turn_permissions_count;

  /* TURN/TCP uses ChannelBind + ChannelData (coturn does not relay Send over TCP). */
#define AGENT_TURN_MAX_CHANNELS 16
  struct {
    Address peer;
    uint16_t number;
    int bound;
    int use_send;
  } turn_channels[AGENT_TURN_MAX_CHANNELS];
  int turn_channels_count;
  uint16_t turn_next_channel;

  /* Scratch buffer for framing/deframing a full relay datagram (payload up to the
   * 1400-byte bound + 4-byte ChannelData header + 4-byte padding). Kept off the
   * task stack: these paths run from the webrtc_bus video-send task (only ~6 KB
   * stack) and a 1.4 KB stack array there overflowed it (stack protection fault).
   * Access is serialized by the per-peer lock that already guards agent_send/recv
   * (required anyway for TURN-TCP stream integrity). UDP-send and TCP-recv never
   * run in the same session (turn_use_tcp), so one buffer is sufficient. */
  uint8_t turn_chan_frame[1400 + 4 + 4];

  /* CreatePermission reply can arrive while we wait, or be read first by agent_recv (same UDP). */
  uint8_t turn_cp_tid[12];
  Address turn_cp_peer;
  int turn_cp_pending;

  /* ChannelBind reply may be read by agent_recv while ICE loop drains TURN/TCP. */
  uint8_t turn_cb_tid[12];
  uint16_t turn_cb_channel;
  int turn_cb_pending;
  int turn_cb_ok;

  /* Consent freshness (RFC 7675): keep sending periodic Binding requests on the
   * selected pair after it succeeds, so the peer can still complete its own check
   * (relay: first packets may be dropped before the peer installs its permission). */
  int consent_ticks;

  /* TURN lifetime management: refresh the allocation, permissions and channel binds
   * before they expire so long sessions survive (RFC 8656 §3.9/§9). */
  uint32_t turn_alloc_lifetime; /* granted allocation lifetime (s); 0 = unknown/600 */
  uint32_t turn_alloc_time;     /* epoch (s) of last successful Allocate/Refresh */
  uint32_t turn_perm_time;      /* epoch (s) of last permission/channel (re)bind */

  /* Relayed media delivery: agent_recv points these at the caller's buffer so the
   * TURN receive path can hand non-STUN payloads (DTLS/SRTP) back to the app. */
  uint8_t* media_out;
  int media_out_cap;
  int media_out_len;

  /* ICE behavior policy (mirrors peer_connection.h IceTransportPolicy /
   * IceRelayProtocol; stored as int to avoid pulling the public header here).
   *   ice_transport_policy: 0 = ALL, 1 = RELAY-only
   *   ice_relay_protocol:   0 = ANY, 1 = UDP-only, 2 = TCP-only */
  int ice_transport_policy;
  int ice_relay_protocol;

  /* Re-entrancy guard for the TURN send path. agent_turn_send() can be reached
   * again from inside agent_turn_wait_response() (a relayed Binding request is
   * dispatched while we wait for a ChannelBind/Refresh reply, and we answer it
   * via the relay). Without this guard that nests blocking ChannelBind/wait
   * handshakes and overflows the task stack under connectivity-check bursts.
   * Depth > 0 means "re-entrant": send best-effort without a blocking handshake. */
  int turn_send_depth;
};

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential);

void agent_create_ice_credential(Agent* agent);

void agent_get_local_description(Agent* agent, char* description, int length);

/** For each local candidate with index >= first_new_idx, format one SDP line and invoke fn. */
typedef void (*AgentTrickleLineFn)(char* line, void* userdata);
void agent_report_new_local_candidates_trickle(Agent* agent, int first_new_idx,
                                                AgentTrickleLineFn fn, void* userdata);

int agent_send(Agent* agent, const uint8_t* buf, int len);

int agent_recv(Agent* agent, uint8_t* buf, int len);

void agent_set_remote_description(Agent* agent, char* description);

int agent_select_candidate_pair(Agent* agent);

int agent_connectivity_check(Agent* agent);

/** Controlled agent: 1 once it is allowed to finalize the selected pair (the
 * controlling peer sent USE-CANDIDATE, or the fallback grace period elapsed).
 * Controlling agents are always ready. */
int agent_ready_to_finalize(Agent* agent);

void agent_clear_candidates(Agent* agent);

int agent_create(Agent* agent);

void agent_destroy(Agent* agent);

void agent_update_candidate_pairs(Agent* agent);

void agent_add_pairs_for_remote(Agent* agent, int remote_idx);

/** Verbose ICE snapshot for UART debugging (locals/remotes/pairs, pair states). */
void agent_log_ice_diagnostics(const Agent* agent, const char* reason);

/** Drain TURN/TCP and UDP without sending connectivity checks (late responses, tests). */
void agent_pump(Agent* agent, int rounds);

/** One-line progress for relay ICE tests (pair state, conncheck, TURN channels). */
void agent_log_ice_progress(const Agent* agent, const char* tag);

#endif  // AGENT_H_
