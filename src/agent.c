#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "agent.h"
#include "base64.h"
#include "ice.h"
#include "ports.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

#define AGENT_POLL_TIMEOUT 1
#define AGENT_CONNCHECK_MAX 150
#define AGENT_CONNCHECK_PERIOD 2
#define AGENT_TURN_MAX_PERMISSIONS 16
/* ICE may multiplex Binding requests on the TURN socket; drain until the
 * CreatePermission *response* for our transaction_id (not the first STUN). */
#define AGENT_TURN_CP_MAX_DRAIN 16
/* Each attempt waits AGENT_POLL_TIMEOUT ms on select(); on ESP-IDF/lwIP the
 * effective minimum is often ~20 ms, so 1000 tries ≈ 20 s per STUN/TURN
 * round-trip — observed blocking ICE gather for 40+ s across servers. */
#define AGENT_STUN_RECV_MAXTIMES 25

static void agent_process_inbound_stun(Agent* agent, StunMessage* stun_msg, Address* addr);

/* RFC 8489: STUN password is the pwd of the ufrag that appears first in USERNAME. */
static const char* agent_stun_password_for_msg(Agent* agent, const StunMessage* stun_msg) {
  if (stun_msg->username[0] != '\0') {
    const char* colon = strchr(stun_msg->username, ':');
    if (colon) {
      size_t first_len = (size_t)(colon - stun_msg->username);
      if (first_len == strlen(agent->remote_ufrag) &&
          strncmp(stun_msg->username, agent->remote_ufrag, first_len) == 0) {
        return agent->remote_upwd;
      }
      if (first_len == strlen(agent->local_ufrag) &&
          strncmp(stun_msg->username, agent->local_ufrag, first_len) == 0) {
        return agent->local_upwd;
      }
    }
  }
  /* Binding success response to our connectivity check (no USERNAME attr). */
  return agent->remote_upwd;
}

void agent_clear_candidates(Agent* agent) {
  agent->local_candidates_count = 0;
  agent->remote_candidates_count = 0;
  agent->candidate_pairs_num = 0;
  agent->turn_allocated = 0;
  agent->turn_permissions_count = 0;
  agent->turn_cp_pending = 0;
  memset(agent->turn_cp_tid, 0, sizeof(agent->turn_cp_tid));
  memset(&agent->turn_server, 0, sizeof(agent->turn_server));
  memset(&agent->turn_relay_addr, 0, sizeof(agent->turn_relay_addr));
}

int agent_create(Agent* agent) {
  int ret;
  agent->udp_sockets[0].fd = -1;
#if CONFIG_IPV6
  agent->udp_sockets[1].fd = -1;
#endif
  if ((ret = udp_socket_open(&agent->udp_sockets[0], AF_INET, 0)) < 0) {
    LOGE("Failed to create UDP socket.");
    return ret;
  }
  LOGI("create IPv4 UDP socket: %d", agent->udp_sockets[0].fd);

#if CONFIG_IPV6
  if ((ret = udp_socket_open(&agent->udp_sockets[1], AF_INET6, 0)) < 0) {
    LOGE("Failed to create IPv6 UDP socket.");
    return ret;
  }
  LOGI("create IPv6 UDP socket: %d", agent->udp_sockets[1].fd);
#endif

  agent_clear_candidates(agent);
  memset(agent->remote_ufrag, 0, sizeof(agent->remote_ufrag));
  memset(agent->remote_upwd, 0, sizeof(agent->remote_upwd));
  return 0;
}

void agent_destroy(Agent* agent) {
  if (agent->udp_sockets[0].fd >= 0) {
    udp_socket_close(&agent->udp_sockets[0]);
  }

#if CONFIG_IPV6
  if (agent->udp_sockets[1].fd >= 0) {
    udp_socket_close(&agent->udp_sockets[1]);
  }
#endif
}

static int agent_socket_recv(Agent* agent, Address* addr, uint8_t* buf, int len) {
  int ret = -1;
  int i = 0;
  int maxfd = -1;
  fd_set rfds;
  struct timeval tv;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  tv.tv_sec = 0;
  tv.tv_usec = AGENT_POLL_TIMEOUT * 1000;
  FD_ZERO(&rfds);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (agent->udp_sockets[i].fd > maxfd) {
      maxfd = agent->udp_sockets[i].fd;
    }
    if (agent->udp_sockets[i].fd >= 0) {
      FD_SET(agent->udp_sockets[i].fd, &rfds);
    }
  }

  ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
  if (ret < 0) {
    LOGE("select error");
  } else if (ret == 0) {
    // timeout
  } else {
    for (i = 0; i < 2; i++) {
      if (FD_ISSET(agent->udp_sockets[i].fd, &rfds)) {
        memset(buf, 0, len);
        ret = udp_socket_recvfrom(&agent->udp_sockets[i], addr, buf, len);
        break;
      }
    }
  }

  return ret;
}

static int agent_socket_recv_attempts(Agent* agent, Address* addr, uint8_t* buf, int len, int maxtimes) {
  int ret = -1;
  int i = 0;
  for (i = 0; i < maxtimes; i++) {
    if ((ret = agent_socket_recv(agent, addr, buf, len)) != 0) {
      break;
    }
  }
  return ret;
}

static int agent_socket_send(Agent* agent, Address* addr, const uint8_t* buf, int len) {
  switch (addr->family) {
    case AF_INET6:
      return udp_socket_sendto(&agent->udp_sockets[1], addr, buf, len);
    case AF_INET:
    default:
      return udp_socket_sendto(&agent->udp_sockets[0], addr, buf, len);
  }
  return -1;
}

static int agent_addr_same(const Address* a, const Address* b) {
  char sa[ADDRSTRLEN];
  char sb[ADDRSTRLEN];
  if (!a || !b || a->family != b->family || a->port != b->port) {
    return 0;
  }
  addr_to_string(a, sa, sizeof(sa));
  addr_to_string(b, sb, sizeof(sb));
  return strcmp(sa, sb) == 0;
}

static int agent_pair_needs_turn(const IceCandidatePair* pair) {
  if (!pair || !pair->local || !pair->remote) {
    return 0;
  }
  return pair->local->type == ICE_CANDIDATE_TYPE_RELAY ||
         pair->remote->type == ICE_CANDIDATE_TYPE_RELAY;
}

static int agent_ipv4_is_site_local(const Address* addr) {
  if (!addr || addr->family != AF_INET) {
    return 0;
  }
  uint32_t ip = ntohl(addr->sin.sin_addr.s_addr);
  if ((ip >> 24) == 10) {
    return 1;
  }
  if ((ip >> 16) == 0xC0A8) {
    return 1;
  }
  if ((ip >> 12) >= 0xAC10 && (ip >> 12) <= 0xAC1F) {
    return 1;
  }
  return 0;
}

/* Same broadcast domain as ESP (e.g. 192.168.60.x + 192.168.61.x with mask 255.255.254.0). */
static int agent_ipv4_same_lan23(uint32_t a, uint32_t b) {
  return (a & 0xFFFFFE00u) == (b & 0xFFFFFE00u);
}

/* Drop remote RFC1918 host on another LAN segment (VMware 192.168.56.x, etc.). */
static int agent_remote_candidate_viable(const Agent* agent, const IceCandidate* remote) {
  int i;
  if (!remote) {
    return 0;
  }
  if (remote->type != ICE_CANDIDATE_TYPE_HOST || !agent_ipv4_is_site_local(&remote->addr)) {
    return 1;
  }
  if (!agent) {
    return 0;
  }
  for (i = 0; i < agent->local_candidates_count; i++) {
    const IceCandidate* local = &agent->local_candidates[i];
    if (local->type != ICE_CANDIDATE_TYPE_HOST || local->addr.family != AF_INET) {
      continue;
    }
    uint32_t lip = ntohl(local->addr.sin.sin_addr.s_addr);
    uint32_t rip = ntohl(remote->addr.sin.sin_addr.s_addr);
    if (agent_ipv4_same_lan23(lip, rip)) {
      return 1;
    }
  }
  return 0;
}

static int agent_turn_has_permission(Agent* agent, const Address* peer) {
  int i;
  for (i = 0; i < agent->turn_permissions_count; i++) {
    if (agent_addr_same(&agent->turn_permissions[i], peer)) {
      return 1;
    }
  }
  return 0;
}

static int agent_turn_write_xor_peer(char* out, Address* peer, StunHeader* hdr) {
  uint8_t mask[16];
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, hdr->transaction_id, sizeof(hdr->transaction_id));
  return stun_set_mapped_address(out, mask, peer);
}

/* CreatePermission response may be read here or later by agent_recv — same UDP socket. */
static void agent_turn_cp_try_finish_from_response(Agent* agent, StunMessage* stun_msg) {
  if (!agent->turn_cp_pending || stun_msg->stunmethod != STUN_METHOD_CREATE_PERMISSION) {
    return;
  }
  StunHeader* h = (StunHeader*)stun_msg->buf;
  if (memcmp(h->transaction_id, agent->turn_cp_tid, 12) != 0) {
    return;
  }
  if (stun_msg->stunclass == STUN_CLASS_ERROR) {
    agent->turn_cp_pending = 0;
    LOGW("TURN CreatePermission STUN error");
    return;
  }
  if (stun_msg->stunclass != STUN_CLASS_RESPONSE) {
    return;
  }
  agent->turn_cp_pending = 0;
  if (!agent_turn_has_permission(agent, &agent->turn_cp_peer) &&
      agent->turn_permissions_count < AGENT_TURN_MAX_PERMISSIONS) {
    agent->turn_permissions[agent->turn_permissions_count++] = agent->turn_cp_peer;
  }
  char addr_string[ADDRSTRLEN];
  addr_to_string(&agent->turn_cp_peer, addr_string, sizeof(addr_string));
  LOGI("TURN permission for %s:%d", addr_string, agent->turn_cp_peer.port);
}

static int agent_turn_create_permission(Agent* agent, Address* peer) {
  StunMessage send_msg;
  StunMessage recv_msg;
  char xor_peer[32];
  char addr_string[ADDRSTRLEN];
  int xor_len;
  int ret;

  if (!agent->turn_allocated || !peer) {
    return -1;
  }
  if (agent_turn_has_permission(agent, peer)) {
    return 0;
  }

  memset(&send_msg, 0, sizeof(send_msg));
  memset(&recv_msg, 0, sizeof(recv_msg));
  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_CREATE_PERMISSION);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(agent->turn_username),
                      agent->turn_username);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(agent->turn_nonce), agent->turn_nonce);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(agent->turn_realm), agent->turn_realm);
  xor_len = agent_turn_write_xor_peer(xor_peer, peer, (StunHeader*)send_msg.buf);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_XOR_PEER_ADDRESS, xor_len, xor_peer);
  stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, agent->turn_password,
                  strlen(agent->turn_password));

  const StunHeader* sh_out = (const StunHeader*)send_msg.buf;
  memcpy(agent->turn_cp_tid, sh_out->transaction_id, sizeof(agent->turn_cp_tid));
  agent->turn_cp_peer = *peer;
  agent->turn_cp_pending = 1;

  ret = agent_socket_send(agent, &agent->turn_server, send_msg.buf, send_msg.size);
  if (ret < 0) {
    agent->turn_cp_pending = 0;
    return -1;
  }

  /* Do not block the ICE loop waiting for CreatePermission on the shared UDP
   * socket (responses are often muxed with Binding; long drain starves checks).
   * Grant permission optimistically; brief drain processes any immediate reply. */
  if (!agent_turn_has_permission(agent, peer) && agent->turn_permissions_count < AGENT_TURN_MAX_PERMISSIONS) {
    agent->turn_permissions[agent->turn_permissions_count++] = *peer;
  }
  addr_to_string(peer, addr_string, sizeof(addr_string));
  LOGI("TURN permission (optimistic) for %s:%d", addr_string, peer->port);

  Address raddr;
  for (int drain = 0; drain < 4; drain++) {
    memset(&recv_msg, 0, sizeof(recv_msg));
    ret = agent_socket_recv_attempts(agent, &raddr, recv_msg.buf, sizeof(recv_msg.buf), 3);
    if (ret <= 0) {
      break;
    }
    if (!stun_probe(recv_msg.buf, (size_t)ret)) {
      continue;
    }
    recv_msg.size = (size_t)ret;
    stun_parse_msg_buf(&recv_msg);
    agent_turn_cp_try_finish_from_response(agent, &recv_msg);
    agent_process_inbound_stun(agent, &recv_msg, &raddr);
  }
  agent->turn_cp_pending = 0;
  return 0;
}

static int agent_turn_send(Agent* agent, Address* peer, const uint8_t* data, int len) {
  StunMessage send_msg;
  char xor_peer[32];
  int xor_len;

  if (!agent->turn_allocated || !peer || !data || len <= 0) {
    return -1;
  }
  if (agent_turn_create_permission(agent, peer) != 0) {
    return -1;
  }

  memset(&send_msg, 0, sizeof(send_msg));
  stun_msg_create(&send_msg, STUN_CLASS_INDICATION | STUN_METHOD_SEND);
  xor_len = agent_turn_write_xor_peer(xor_peer, peer, (StunHeader*)send_msg.buf);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_XOR_PEER_ADDRESS, xor_len, xor_peer);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_DATA, len, (char*)data);
  return agent_socket_send(agent, &agent->turn_server, send_msg.buf, send_msg.size);
}

static int agent_pair_rank(const IceCandidatePair* pair) {
  int rank = (int)pair->priority;
  if (pair->local->type == ICE_CANDIDATE_TYPE_RELAY || pair->remote->type == ICE_CANDIDATE_TYPE_RELAY) {
    rank += 2000000000;
  } else if (pair->local->type == ICE_CANDIDATE_TYPE_SRFLX ||
             pair->remote->type == ICE_CANDIDATE_TYPE_SRFLX) {
    rank += 1000000000;
  }
  return rank;
}

static void agent_adopt_inbound_remote(Agent* agent, Address* addr) {
  int i;

  for (i = 0; i < agent->remote_candidates_count; i++) {
    if (agent_addr_same(&agent->remote_candidates[i].addr, addr)) {
      return;
    }
  }
  if (!agent_ipv4_is_site_local(addr)) {
    return;
  }
  if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
    char raddr[ADDRSTRLEN];
    addr_to_string(addr, raddr, sizeof(raddr));
    LOGW("remote candidate pool full — cannot adopt inbound %s:%d", raddr, addr->port);
    return;
  }
  i = agent->remote_candidates_count;
  ice_candidate_create(&agent->remote_candidates[i], 9000 + i, ICE_CANDIDATE_TYPE_HOST, addr);
  agent->remote_candidates_count++;
  char raddr[ADDRSTRLEN];
  addr_to_string(addr, raddr, sizeof(raddr));
  LOGI("ICE adopt inbound remote host %s:%d (not in SDP)", raddr, addr->port);
  agent_add_pairs_for_remote(agent, i);
}

static void agent_note_inbound_binding(Agent* agent, Address* addr) {
  IceCandidatePair* best = NULL;
  int best_rank = -1;
  int i;

  agent_adopt_inbound_remote(agent, addr);

  for (i = 0; i < agent->candidate_pairs_num; i++) {
    IceCandidatePair* pair = &agent->candidate_pairs[i];
    int match = 0;
    if (!pair->remote || !pair->local) {
      continue;
    }
    if (agent_addr_same(&pair->remote->addr, addr)) {
      match = 1;
    } else if (pair->remote->type == ICE_CANDIDATE_TYPE_HOST && pair->remote->addr.family == AF_INET &&
               addr->family == AF_INET) {
      uint32_t rip = ntohl(pair->remote->addr.sin.sin_addr.s_addr);
      uint32_t aip = ntohl(addr->sin.sin_addr.s_addr);
      if (agent_ipv4_same_lan23(rip, aip) && pair->remote->addr.port == addr->port) {
        match = 1;
      }
    }
    if (!match) {
      continue;
    }
    if (!agent_addr_same(&pair->remote->addr, addr)) {
      char want[ADDRSTRLEN];
      char had[ADDRSTRLEN];
      addr_to_string(addr, want, sizeof(want));
      addr_to_string(&pair->remote->addr, had, sizeof(had));
      LOGI("ICE learn remote addr %s:%d (was %s)", want, addr->port, had);
      memcpy(&pair->remote->addr, addr, sizeof(Address));
    }
    pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
    int rank = agent_pair_rank(pair);
    if (rank > best_rank) {
      best_rank = rank;
      best = pair;
    }
  }
  if (best) {
    agent->nominated_pair = best;
    agent->selected_pair = best;
    char raddr[ADDRSTRLEN];
    addr_to_string(addr, raddr, sizeof(raddr));
    LOGI("ICE inbound Binding OK — nominated %s:%d", raddr, addr->port);
  }
}

static IceCandidatePair* agent_find_pair_for_addr(Agent* agent, Address* addr) {
  int i;
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    IceCandidatePair* pair = &agent->candidate_pairs[i];
    if (pair->remote && agent_addr_same(&pair->remote->addr, addr)) {
      return pair;
    }
  }
  return NULL;
}

static int agent_create_host_addr(Agent* agent) {
  int i, j;
  const char* iface_prefx[] = {CONFIG_IFACE_PREFIX};
  IceCandidate* ice_candidate;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    for (j = 0; j < sizeof(iface_prefx) / sizeof(iface_prefx[0]); j++) {
      ice_candidate = agent->local_candidates + agent->local_candidates_count;
      // only copy port and family to addr of ice candidate
      ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_HOST,
                           &agent->udp_sockets[i].bind_addr);
      // if resolve host addr, add to local candidate
      if (ports_get_host_addr(&ice_candidate->addr, iface_prefx[j])) {
        agent->local_candidates_count++;
      }
    }
  }

  return 0;
}

static int agent_create_stun_addr(Agent* agent, Address* serv_addr) {
  int ret = -1;
  Address bind_addr;
  StunMessage send_msg;
  StunMessage recv_msg;
  memset(&send_msg, 0, sizeof(send_msg));
  memset(&recv_msg, 0, sizeof(recv_msg));

  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);

  ret = agent_socket_send(agent, serv_addr, send_msg.buf, send_msg.size);

  if (ret == -1) {
    LOGE("Failed to send STUN Binding Request.");
    return ret;
  }

  ret = agent_socket_recv_attempts(agent, NULL, recv_msg.buf, sizeof(recv_msg.buf), AGENT_STUN_RECV_MAXTIMES);
  if (ret <= 0) {
    LOGD("Failed to receive STUN Binding Response.");
    return ret;
  }

  stun_parse_msg_buf(&recv_msg);
  memcpy(&bind_addr, &recv_msg.mapped_addr, sizeof(Address));
  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_SRFLX, &bind_addr);
  return ret;
}

static int agent_create_turn_addr(Agent* agent, Address* serv_addr, const char* username, const char* credential) {
  int ret = -1;
  uint32_t attr = ntohl(0x11000000);
  Address turn_addr;
  StunMessage send_msg;
  StunMessage recv_msg;
  char addr_string[ADDRSTRLEN];

  if (!username || !credential) {
    LOGE("TURN missing username/credential");
    return -1;
  }
  memcpy(&agent->turn_server, serv_addr, sizeof(Address));
  strncpy(agent->turn_username, username, sizeof(agent->turn_username) - 1);
  strncpy(agent->turn_password, credential, sizeof(agent->turn_password) - 1);

  memset(&recv_msg, 0, sizeof(recv_msg));
  memset(&send_msg, 0, sizeof(send_msg));
  stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);

  ret = agent_socket_send(agent, serv_addr, send_msg.buf, send_msg.size);
  if (ret == -1) {
    LOGE("Failed to send TURN Binding Request.");
    return -1;
  }

  ret = agent_socket_recv_attempts(agent, NULL, recv_msg.buf, sizeof(recv_msg.buf), AGENT_STUN_RECV_MAXTIMES);
  if (ret <= 0) {
    LOGD("Failed to receive STUN Binding Response.");
    return ret;
  }

  stun_parse_msg_buf(&recv_msg);

  if (recv_msg.stunclass == STUN_CLASS_ERROR && recv_msg.stunmethod == STUN_METHOD_ALLOCATE) {
    memset(&send_msg, 0, sizeof(send_msg));
    stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(recv_msg.nonce), recv_msg.nonce);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(recv_msg.realm), recv_msg.realm);
    stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, credential, strlen(credential));
  } else {
    LOGE("Invalid TURN Binding Response.");
    return -1;
  }

  ret = agent_socket_send(agent, serv_addr, send_msg.buf, send_msg.size);
  if (ret < 0) {
    LOGE("Failed to send TURN Binding Request.");
    return -1;
  }

  ret = agent_socket_recv_attempts(agent, NULL, recv_msg.buf, sizeof(recv_msg.buf), AGENT_STUN_RECV_MAXTIMES);
  if (ret <= 0) {
    LOGD("Failed to receive TURN Allocate success.");
    return ret;
  }

  stun_parse_msg_buf(&recv_msg);
  if (recv_msg.stunclass != STUN_CLASS_RESPONSE) {
    LOGE("TURN Allocate failed");
    return -1;
  }
  memcpy(&turn_addr, &recv_msg.relayed_addr, sizeof(Address));
  strncpy(agent->turn_realm, recv_msg.realm, sizeof(agent->turn_realm) - 1);
  strncpy(agent->turn_nonce, recv_msg.nonce, sizeof(agent->turn_nonce) - 1);
  agent->turn_allocated = 1;
  agent->turn_permissions_count = 0;
  memcpy(&agent->turn_relay_addr, &turn_addr, sizeof(Address));
  addr_to_string(&turn_addr, addr_string, sizeof(addr_string));
  LOGI("TURN relay allocated %s:%d", addr_string, turn_addr.port);

  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_RELAY, &turn_addr);
  return 0;
}

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential) {
  char* pos;
  int port;
  char hostname[64];
  char addr_string[ADDRSTRLEN];
  int i;
  int addr_type[1] = {AF_INET};  // ipv6 no need stun
  Address resolved_addr;
  memset(hostname, 0, sizeof(hostname));

  if (urls == NULL) {
    agent_create_host_addr(agent);
    return;
  }

  if ((pos = strstr(urls + 5, ":")) == NULL) {
    LOGE("Invalid URL");
    return;
  }

  port = atoi(pos + 1);
  if (port <= 0) {
    LOGE("Cannot parse port");
    return;
  }

  snprintf(hostname, pos - urls - 5 + 1, "%s", urls + 5);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (ports_resolve_addr(hostname, &resolved_addr) == 0) {
      addr_set_port(&resolved_addr, port);
      addr_to_string(&resolved_addr, addr_string, sizeof(addr_string));
      LOGI("Resolved stun/turn server %s:%d", addr_string, port);

      if (strncmp(urls, "stun:", 5) == 0) {
        LOGD("Create stun addr");
        agent_create_stun_addr(agent, &resolved_addr);
      } else if (strncmp(urls, "turn:", 5) == 0) {
        LOGD("Create turn addr");
        agent_create_turn_addr(agent, &resolved_addr, username, credential);
      }
    }
  }
}

void agent_create_ice_credential(Agent* agent) {
  memset(agent->local_ufrag, 0, sizeof(agent->local_ufrag));
  memset(agent->local_upwd, 0, sizeof(agent->local_upwd));

  utils_random_string(agent->local_ufrag, 4);
  utils_random_string(agent->local_upwd, 24);
}

void agent_get_local_description(Agent* agent, char* description, int length) {
  for (int i = 0; i < agent->local_candidates_count; i++) {
    ice_candidate_to_description(&agent->local_candidates[i], description + strlen(description), length - strlen(description));
  }

  // remove last \n
  description[strlen(description)] = '\0';
  LOGD("local description:\n%s", description);
}

void agent_report_new_local_candidates_trickle(Agent* agent, int first_new_idx,
                                               AgentTrickleLineFn fn, void* userdata) {
  if (!fn || first_new_idx < 0) {
    return;
  }
  char line[512];
  for (int i = first_new_idx; i < agent->local_candidates_count; i++) {
    line[0] = '\0';
    ice_candidate_to_description(&agent->local_candidates[i], line, (int)sizeof(line));
    if (line[0] == '\0') {
      continue;
    }
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
      line[--n] = '\0';
    }
    if (n > 0) {
      fn(line, userdata);
    }
  }
}

int agent_send(Agent* agent, const uint8_t* buf, int len) {
  if (!agent->nominated_pair) {
    return -1;
  }
  if (agent_pair_needs_turn(agent->nominated_pair) && agent->turn_allocated) {
    return agent_turn_send(agent, &agent->nominated_pair->remote->addr, buf, len);
  }
  return agent_socket_send(agent, &agent->nominated_pair->remote->addr, buf, len);
}

static void agent_create_binding_response(Agent* agent, StunMessage* msg, Address* addr) {
  int size = 0;
  char username[584];
  char mapped_address[32];
  uint8_t mask[16];
  StunHeader* header;
  stun_msg_create(msg, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
  header = (StunHeader*)msg->buf;
  memcpy(header->transaction_id, agent->transaction_id, sizeof(header->transaction_id));
  /* Offerer checks use USERNAME=<answerer>:<offerer>; respond with the same (RFC 8489). */
  snprintf(username, sizeof(username), "%s:%s", agent->local_ufrag, agent->remote_ufrag);
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, agent->transaction_id, sizeof(agent->transaction_id));
  size = stun_set_mapped_address(mapped_address, mask, addr);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, size, mapped_address);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->local_upwd, strlen(agent->local_upwd));
}

static void agent_create_binding_request(Agent* agent, StunMessage* msg) {
  uint64_t tie_breaker = 0;  // always be controlled
  // send binding request
  stun_msg_create(msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);
  char username[584];
  memset(username, 0, sizeof(username));
  snprintf(username, sizeof(username), "%s:%s", agent->remote_ufrag, agent->local_ufrag);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_PRIORITY, 4, (char*)&agent->nominated_pair->priority);
  if (agent->mode == AGENT_MODE_CONTROLLING) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USE_CANDIDATE, 0, NULL);
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLING, 8, (char*)&tie_breaker);
  } else {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLED, 8, (char*)&tie_breaker);
  }
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->remote_upwd, strlen(agent->remote_upwd));
}

void agent_process_stun_request(Agent* agent, StunMessage* stun_msg, Address* addr) {
  StunMessage msg;
  StunHeader* header;
  IceCandidatePair* pair;
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      const char* req_pwd = agent_stun_password_for_msg(agent, stun_msg);
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, (char*)req_pwd) == 0) {
        char req_from[ADDRSTRLEN];
        addr_to_string(addr, req_from, sizeof(req_from));
        LOGI("ICE STUN Binding request from %s:%d", req_from, addr->port);
        header = (StunHeader*)stun_msg->buf;
        memcpy(agent->transaction_id, header->transaction_id, sizeof(header->transaction_id));
        agent_note_inbound_binding(agent, addr);
        pair = agent_find_pair_for_addr(agent, addr);
        if (stun_msg->use_candidate && pair) {
          pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
          agent->nominated_pair = pair;
          agent->selected_pair = pair;
          LOGI("ICE nominated by remote USE-CANDIDATE");
        }
        agent_create_binding_response(agent, &msg, addr);
        if (pair && agent_pair_needs_turn(pair) && agent->turn_allocated) {
          agent_turn_send(agent, addr, msg.buf, msg.size);
        } else {
          agent_socket_send(agent, addr, msg.buf, msg.size);
        }
        LOGI("ICE STUN Binding response sent to %s:%d (%u B)", req_from, addr->port, (unsigned)msg.size);
        agent->binding_request_time = ports_get_epoch_time();
      }
      break;
    default:
      break;
  }
}

void agent_process_stun_response(Agent* agent, StunMessage* stun_msg) {
  agent_turn_cp_try_finish_from_response(agent, stun_msg);
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      LOGI("ICE STUN Binding response (class=%d)", (int)stun_msg->stunclass);
      if (!agent->nominated_pair) {
        break;
      }
      const char* rsp_pwd = agent_stun_password_for_msg(agent, stun_msg);
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, (char*)rsp_pwd) == 0) {
        agent->nominated_pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
        LOGI("ICE binding response OK — pair succeeded");
      } else if (rsp_pwd != agent->local_upwd &&
                 stun_msg_is_valid(stun_msg->buf, stun_msg->size, (char*)agent->local_upwd) == 0) {
        agent->nominated_pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
        LOGI("ICE binding response OK (local pwd fallback) — pair succeeded");
      } else {
        LOGW("ICE binding response auth failed (remote_pwd_len=%u has_username=%d fp=%d)",
             (unsigned)strlen(agent->remote_upwd), stun_msg->username[0] != '\0', (int)stun_msg->has_fingerprint);
      }
      break;
    default:
      break;
  }
}

static void agent_process_inbound_stun(Agent* agent, StunMessage* stun_msg, Address* addr) {
  switch (stun_msg->stunclass) {
    case STUN_CLASS_REQUEST:
      agent_process_stun_request(agent, stun_msg, addr);
      break;
    case STUN_CLASS_RESPONSE:
      agent_process_stun_response(agent, stun_msg);
      break;
    case STUN_CLASS_INDICATION:
      if (stun_msg->stunmethod == STUN_METHOD_SEND && stun_msg->data_len > 0 &&
          stun_probe(stun_msg->data, (size_t)stun_msg->data_len) == 0) {
        StunMessage inner;
        memset(&inner, 0, sizeof(inner));
        memcpy(inner.buf, stun_msg->data, (size_t)stun_msg->data_len);
        inner.size = (size_t)stun_msg->data_len;
        stun_parse_msg_buf(&inner);
        agent_process_inbound_stun(agent, &inner, &stun_msg->peer_addr);
      }
      break;
    default:
      break;
  }
}

int agent_recv(Agent* agent, uint8_t* buf, int len) {
  int ret = -1;
  StunMessage stun_msg;
  Address addr;
  if ((ret = agent_socket_recv(agent, &addr, buf, len)) > 0 && stun_probe(buf, len) == 0) {
    memset(&stun_msg, 0, sizeof(stun_msg));
    memcpy(stun_msg.buf, buf, ret);
    stun_msg.size = ret;
    stun_parse_msg_buf(&stun_msg);
    agent_process_inbound_stun(agent, &stun_msg, &addr);
    ret = 0;
  }
  return ret;
}

static void agent_copy_sdp_field(char* dst, size_t dst_len, const char* src, int src_len) {
  if (src_len <= 0) {
    dst[0] = '\0';
    return;
  }
  if (src_len >= (int)dst_len) {
    src_len = (int)dst_len - 1;
  }
  memcpy(dst, src, (size_t)src_len);
  dst[src_len] = '\0';
}

void agent_set_remote_description(Agent* agent, char* description) {
  int i;
  char line[512];

  LOGD("Set remote description:\n%s", description);

  memset(agent->remote_ufrag, 0, sizeof(agent->remote_ufrag));
  memset(agent->remote_upwd, 0, sizeof(agent->remote_upwd));

  const char* p = description;
  while (*p) {
    const char* eol = strchr(p, '\n');
    size_t raw_len = eol ? (size_t)(eol - p) : strlen(p);
    size_t line_len = raw_len;
    if (line_len > 0 && p[line_len - 1] == '\r') {
      line_len--;
    }
    if (line_len >= sizeof(line)) {
      line_len = sizeof(line) - 1;
    }
    memcpy(line, p, line_len);
    line[line_len] = '\0';

    if (strncmp(line, "a=ice-ufrag:", strlen("a=ice-ufrag:")) == 0) {
      agent_copy_sdp_field(agent->remote_ufrag, sizeof(agent->remote_ufrag), line + strlen("a=ice-ufrag:"),
                           (int)(line_len - strlen("a=ice-ufrag:")));
    } else if (strncmp(line, "a=ice-pwd:", strlen("a=ice-pwd:")) == 0) {
      agent_copy_sdp_field(agent->remote_upwd, sizeof(agent->remote_upwd), line + strlen("a=ice-pwd:"),
                           (int)(line_len - strlen("a=ice-pwd:")));
    } else if (strncmp(line, "a=candidate:", strlen("a=candidate:")) == 0) {
      if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
        LOGW("remote candidate pool full (%d) in SDP — skip rest", AGENT_MAX_CANDIDATES);
        break;
      }
      if (ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count], line,
                                         line + line_len) == 0) {
        for (i = 0; i < agent->remote_candidates_count; i++) {
          if (strcmp(agent->remote_candidates[i].foundation,
                     agent->remote_candidates[agent->remote_candidates_count].foundation) == 0) {
            break;
          }
        }
        if (i == agent->remote_candidates_count) {
          agent->remote_candidates_count++;
        }
      }
    }

    if (!eol) {
      break;
    }
    p = eol + 1;
  }

  LOGI("ICE remote creds parsed ufrag_len=%u pwd_len=%u remotes=%d",
       (unsigned)strlen(agent->remote_ufrag), (unsigned)strlen(agent->remote_upwd),
       agent->remote_candidates_count);
  LOGD("remote ufrag: %s", agent->remote_ufrag);
  LOGD("remote upwd: %s", agent->remote_upwd);
}

void agent_update_candidate_pairs(Agent* agent) {
  int i, j;
  /* Rebuild from scratch — trickle ICE calls this repeatedly; appending
   * without reset overflows candidate_pairs[] and corrupts nominated_pair. */
  agent->candidate_pairs_num = 0;
  agent->nominated_pair = NULL;
  agent->selected_pair = NULL;
  for (i = 0; i < agent->local_candidates_count; i++) {
    for (j = 0; j < agent->remote_candidates_count; j++) {
      if (!agent_remote_candidate_viable(agent, &agent->remote_candidates[j])) {
        continue;
      }
      if (agent->local_candidates[i].addr.family == agent->remote_candidates[j].addr.family) {
        if (agent->candidate_pairs_num >= AGENT_MAX_CANDIDATE_PAIRS) {
          LOGW("candidate pair pool full (%d) — skip rest", AGENT_MAX_CANDIDATE_PAIRS);
          goto done;
        }
        agent->candidate_pairs[agent->candidate_pairs_num].local = &agent->local_candidates[i];
        agent->candidate_pairs[agent->candidate_pairs_num].remote = &agent->remote_candidates[j];
        agent->candidate_pairs[agent->candidate_pairs_num].priority = agent->local_candidates[i].priority + agent->remote_candidates[j].priority;
        agent->candidate_pairs[agent->candidate_pairs_num].state = ICE_CANDIDATE_STATE_FROZEN;
        agent->candidate_pairs[agent->candidate_pairs_num].conncheck = 0;
        agent->candidate_pairs_num++;
      }
    }
  }
done:
  LOGD("candidate pairs num: %d", agent->candidate_pairs_num);
}

void agent_add_pairs_for_remote(Agent* agent, int remote_idx) {
  int i;
  if (remote_idx < 0 || remote_idx >= agent->remote_candidates_count) {
    return;
  }
  IceCandidate* remote = &agent->remote_candidates[remote_idx];
  if (!agent_remote_candidate_viable(agent, remote)) {
    return;
  }
  for (i = 0; i < agent->local_candidates_count; i++) {
    IceCandidate* local = &agent->local_candidates[i];
    if (local->addr.family != remote->addr.family) {
      continue;
    }
    int p;
    for (p = 0; p < agent->candidate_pairs_num; p++) {
      if (agent->candidate_pairs[p].local == local &&
          agent->candidate_pairs[p].remote == remote) {
        break;
      }
    }
    if (p < agent->candidate_pairs_num) {
      continue;
    }
    if (agent->candidate_pairs_num >= AGENT_MAX_CANDIDATE_PAIRS) {
      LOGW("candidate pair pool full (%d) — skip trickle pair", AGENT_MAX_CANDIDATE_PAIRS);
      return;
    }
    agent->candidate_pairs[agent->candidate_pairs_num].local = local;
    agent->candidate_pairs[agent->candidate_pairs_num].remote = remote;
    agent->candidate_pairs[agent->candidate_pairs_num].priority = local->priority + remote->priority;
    agent->candidate_pairs[agent->candidate_pairs_num].state = ICE_CANDIDATE_STATE_FROZEN;
    agent->candidate_pairs[agent->candidate_pairs_num].conncheck = 0;
    agent->candidate_pairs_num++;
  }
  LOGD("trickle pair add remote[%d]: pairs=%d", remote_idx, agent->candidate_pairs_num);
}

int agent_connectivity_check(Agent* agent) {
  char addr_string[ADDRSTRLEN];
  uint8_t buf[1400];
  StunMessage msg;

  if (agent->selected_pair && agent->selected_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    return 0;
  }

  if (!agent->nominated_pair || agent->nominated_pair->state != ICE_CANDIDATE_STATE_INPROGRESS) {
    return -1;
  }

  memset(&msg, 0, sizeof(msg));

  if (agent->nominated_pair->conncheck % AGENT_CONNCHECK_PERIOD == 0) {
    addr_to_string(&agent->nominated_pair->remote->addr, addr_string, sizeof(addr_string));
    if (agent->nominated_pair->conncheck == 0 || agent->nominated_pair->conncheck == AGENT_CONNCHECK_PERIOD) {
      LOGI("ICE check #%d -> %s:%d turn=%d", agent->nominated_pair->conncheck, addr_string,
           agent->nominated_pair->remote->addr.port,
           agent_pair_needs_turn(agent->nominated_pair) ? 1 : 0);
    } else {
      LOGD("send binding request to remote ip: %s, port: %d", addr_string, agent->nominated_pair->remote->addr.port);
    }
    agent_create_binding_request(agent, &msg);
    if (agent_pair_needs_turn(agent->nominated_pair) && agent->turn_allocated) {
      agent_turn_send(agent, &agent->nominated_pair->remote->addr, msg.buf, msg.size);
    } else {
      agent_socket_send(agent, &agent->nominated_pair->remote->addr, msg.buf, msg.size);
    }
  }

  for (int drain = 0; drain < 12; drain++) {
    agent_recv(agent, buf, sizeof(buf));
    if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      break;
    }
  }

  if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent->selected_pair = agent->nominated_pair;
    return 0;
  }

  return -1;
}

int agent_select_candidate_pair(Agent* agent) {
  int i;
  int best = -1;
  int best_rank = -1;

  /* Prefer pairs that already passed connectivity — do not keep nominating
   * new FROZEN pairs while SUCCEEDED ones exist (was: S=3 but selected=0). */
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      int rank = agent_pair_rank(&agent->candidate_pairs[i]);
      if (rank > best_rank) {
        best_rank = rank;
        best = i;
      }
    }
  }
  if (best >= 0) {
    agent->nominated_pair = &agent->candidate_pairs[best];
    agent->selected_pair = &agent->candidate_pairs[best];
    return 0;
  }

  best = -1;
  best_rank = -1;
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FROZEN) {
      int rank = agent_pair_rank(&agent->candidate_pairs[i]);
      if (rank > best_rank) {
        best_rank = rank;
        best = i;
      }
    }
  }
  if (best >= 0) {
    agent->nominated_pair = &agent->candidate_pairs[best];
    agent->candidate_pairs[best].conncheck = 0;
    agent->candidate_pairs[best].state = ICE_CANDIDATE_STATE_INPROGRESS;
    return 0;
  }
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS) {
      agent->nominated_pair = &agent->candidate_pairs[i];
      agent->candidate_pairs[i].conncheck++;
      if (agent->candidate_pairs[i].conncheck < AGENT_CONNCHECK_MAX) {
        return 0;
      }
      agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_FAILED;
    }
  }
  return -1;
}

void agent_log_ice_diagnostics(const Agent* agent, const char* reason) {
  int nf = 0, nw = 0, ni = 0, ns = 0, nfail = 0;
  int nominated_idx = -1;
  int i;

  if (!agent) {
    LOGW("ICE diag (%s): null agent", reason ? reason : "?");
    return;
  }

  for (i = 0; i < agent->candidate_pairs_num; i++) {
    switch (agent->candidate_pairs[i].state) {
      case ICE_CANDIDATE_STATE_FROZEN:
        nf++;
        break;
      case ICE_CANDIDATE_STATE_WAITING:
        nw++;
        break;
      case ICE_CANDIDATE_STATE_INPROGRESS:
        ni++;
        break;
      case ICE_CANDIDATE_STATE_SUCCEEDED:
        ns++;
        break;
      case ICE_CANDIDATE_STATE_FAILED:
        nfail++;
        break;
      default:
        break;
    }
    if (agent->nominated_pair == &agent->candidate_pairs[i]) {
      nominated_idx = i;
    }
  }

  LOGW(
      "ICE diag (%s): locals=%d remotes=%d pairs=%d turn_alloc=%d "
      "pair_states F/W/I/S/X=%d/%d/%d/%d/%d nominated_idx=%d selected=%p",
      reason ? reason : "?",
      agent->local_candidates_count,
      agent->remote_candidates_count,
      agent->candidate_pairs_num,
      agent->turn_allocated,
      nf,
      nw,
      ni,
      ns,
      nfail,
      nominated_idx,
      (void*)agent->selected_pair);

  if (agent->nominated_pair && agent->nominated_pair->local && agent->nominated_pair->remote) {
    char la[ADDRSTRLEN];
    char ra[ADDRSTRLEN];
    addr_to_string(&agent->nominated_pair->local->addr, la, sizeof(la));
    addr_to_string(&agent->nominated_pair->remote->addr, ra, sizeof(ra));
    LOGW(
        "ICE diag nominated: local=%s remote=%s pair_state=%d conncheck=%d/%d "
        "local_typ=%d remote_typ=%d",
        la,
        ra,
        (int)agent->nominated_pair->state,
        agent->nominated_pair->conncheck,
        AGENT_CONNCHECK_MAX,
        (int)agent->nominated_pair->local->type,
        (int)agent->nominated_pair->remote->type);
  }
}
