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
  uint32_t transaction_id[3];

  /* TURN allocation state — ICE checks to relay addrs need Send/Permission. */
  Address turn_server;
  char turn_username[128];
  char turn_password[128];
  char turn_realm[64];
  char turn_nonce[64];
  Address turn_relay_addr;
  int turn_allocated;
  Address turn_permissions[16];
  int turn_permissions_count;

  /* CreatePermission reply can arrive while we wait, or be read first by agent_recv (same UDP). */
  uint8_t turn_cp_tid[12];
  Address turn_cp_peer;
  int turn_cp_pending;
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

void agent_clear_candidates(Agent* agent);

int agent_create(Agent* agent);

void agent_destroy(Agent* agent);

void agent_update_candidate_pairs(Agent* agent);

void agent_add_pairs_for_remote(Agent* agent, int remote_idx);

/** Verbose ICE snapshot for UART debugging (locals/remotes/pairs, pair states). */
void agent_log_ice_diagnostics(const Agent* agent, const char* reason);

#endif  // AGENT_H_
