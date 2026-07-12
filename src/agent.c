#include <errno.h>
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
#include "stun_tcp.h"
#include "utils.h"

/* TEMP freeze-hunt: shared phase tracker (defined in peer_connection.c). */
extern volatile uint32_t g_pcl_phase;
#define PCL(p) do { g_pcl_phase = (uint32_t)(p); } while (0)
/* Lock-free raw diagnostics; PEER_LOG_RAW is resolved per-platform in peer_log.h
 * (esp_rom_printf on ESP, printf elsewhere) — see utils.h include above. */

/* Controlled agent grace period (ms) to wait for the controlling peer's
 * USE-CANDIDATE before falling back to our own self-selected pair. */
#define AGENT_CONTROLLED_NOM_WAIT_MS 4000

#define AGENT_POLL_TIMEOUT 1
#define AGENT_CONNCHECK_MAX 400
/* Outbound connectivity-check spacing (peer_connection_loop ticks between sends).
 * Was 2 (~20 ms with 10 ms loop); 6 ≈ 60 ms — enough on LAN, less CPU during CHECKING. */
#define AGENT_CONNCHECK_PERIOD 6
#define AGENT_TURN_MAX_PERMISSIONS 16
/* ICE may multiplex Binding requests on the TURN socket; drain until the
 * CreatePermission *response* for our transaction_id (not the first STUN). */
#define AGENT_TURN_CP_MAX_DRAIN 16
/* Each attempt waits AGENT_POLL_TIMEOUT ms on select(); on ESP-IDF/lwIP the
 * effective minimum is often ~20 ms, so 1000 tries ≈ 20 s per STUN/TURN
 * round-trip — observed blocking ICE gather for 40+ s across servers. */
#define AGENT_STUN_RECV_MAXTIMES 25
#define AGENT_TURN_TCP_RECV_MAXTIMES 80
#define AGENT_TURN_CB_RECV_MS 200
#define AGENT_TURN_CB_WAIT_MS 800

/* ===========================================================================
 *  TEST-ONLY fault injection (compile-time). Simulates a mobile-carrier
 *  DPI/TSPU "soft block": ICE connectivity (STUN consent) keeps passing so the
 *  path *looks* alive, but media + RTCP over UDP are throttled to zero after a
 *  handful of packets. The per-agent counter is NOT reset across reconnects'
 *  sake by design — each fresh session re-establishes, flows ~N packets, then
 *  dies again, exactly like a real TSPU choke. TCP relay is never affected, so
 *  failover to TURN-TCP is the only escape — which is what we want to exercise.
 *
 *  Enable by building with -DLIBPEER_FAULT_INJECT=1 (optionally override the
 *  kill threshold with -DLIBPEER_FAULT_UDP_KILL_AFTER=<n>). Off by default. */
#ifndef LIBPEER_FAULT_INJECT
#define LIBPEER_FAULT_INJECT 0
#endif
#if LIBPEER_FAULT_INJECT
#ifndef LIBPEER_FAULT_UDP_KILL_AFTER
#define LIBPEER_FAULT_UDP_KILL_AFTER 120
#endif
/* Returns 1 when the (UDP) media/RTCP packet should be dropped to simulate the
 * throttle. STUN consent never routes through here, so ICE stays "connected".
 * TCP relay (turn_use_tcp) is exempt. */
static int agent_fault_drop_udp_media(Agent* agent) {
  if (!agent || agent->turn_use_tcp || !agent->fault_armed) {
    return 0; /* TCP relay or pre-COMPLETED handshake: never throttle */
  }
  if (agent->fault_udp_pkts < LIBPEER_FAULT_UDP_KILL_AFTER) {
    agent->fault_udp_pkts++;
    if (agent->fault_udp_pkts == LIBPEER_FAULT_UDP_KILL_AFTER) {
      PEER_LOG_RAW("FAULTINJECT: UDP media/RTCP throttled to zero after %d pkts\n",
                     (int)LIBPEER_FAULT_UDP_KILL_AFTER);
    }
    return 0;
  }
  return 1;
}
#endif /* LIBPEER_FAULT_INJECT */

static void agent_process_inbound_stun(Agent* agent, StunMessage* stun_msg, Address* addr);
static int agent_turn_channel_to_peer(Agent* agent, uint16_t channel, Address* peer);
static void agent_turn_cb_try_finish_from_response(Agent* agent, StunMessage* stun_msg);
static int agent_turn_process_udp_datagram(Agent* agent, Address* addr, uint8_t* buf, int len);
static int agent_turn_tcp_poll_recv(Agent* agent, StunMessage* stun_msg);
static void agent_turn_tcp_drain_media(Agent* agent, int wait_ms);
static void agent_turn_drain_udp(Agent* agent);
static void agent_turn_deallocate(Agent* agent);
static int agent_turn_refresh(Agent* agent, uint32_t lifetime);
static void agent_turn_refresh_maybe(Agent* agent);
static int agent_turn_create_permission(Agent* agent, Address* peer);
static int agent_turn_channel_bind_req(Agent* agent, Address* peer, uint16_t channel);
static int agent_turn_control_recv_attempts(Agent* agent, StunMessage* recv_msg, int maxtimes);
static int agent_turn_dispatch_stun_msg(Agent* agent, StunMessage* stun_msg, Address* addr);

/* Default TURN lifetimes (RFC 8656 defaults). Refresh well before expiry. */
#define AGENT_TURN_DEFAULT_LIFETIME 600u
#define AGENT_TURN_PERMISSION_LIFETIME 300u

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
  agent->consent_ticks = 0;
  if (agent->turn_allocated) {
    agent_turn_deallocate(agent);
    return;
  }
  if (agent->turn_tcp.fd >= 0) {
    tcp_socket_close(&agent->turn_tcp);
  }
  agent->local_candidates_count = 0;
  agent->remote_candidates_count = 0;
  agent->candidate_pairs_num = 0;
  agent->nominated_pair = NULL;
  agent->selected_pair = NULL;
  agent->remote_nominated = 0;
  agent->controlled_nom_deadline = 0;
  agent->turn_allocated = 0;
  agent->turn_use_tcp = 0;
  agent->turn_tcp.fd = -1;
  agent->turn_permissions_count = 0;
  agent->turn_channels_count = 0;
  agent->turn_next_channel = STUN_CHANNEL_NUMBER_MIN;
  agent->turn_cp_pending = 0;
  agent->turn_cb_pending = 0;
  agent->turn_cb_ok = 0;
  agent->turn_pending_media_len = 0;
  memset(agent->turn_cp_tid, 0, sizeof(agent->turn_cp_tid));
  memset(agent->turn_cb_tid, 0, sizeof(agent->turn_cb_tid));
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
  agent->turn_tcp.fd = -1;
  agent->turn_use_tcp = 0;
  agent->turn_send_depth = 0;
  memset(agent->remote_ufrag, 0, sizeof(agent->remote_ufrag));
  memset(agent->remote_upwd, 0, sizeof(agent->remote_upwd));
  return 0;
}

void agent_destroy(Agent* agent) {
  agent_turn_deallocate(agent);
  if (agent->turn_tcp.fd >= 0) {
    tcp_socket_close(&agent->turn_tcp);
    agent->turn_tcp.fd = -1;
  }
  agent->turn_use_tcp = 0;
  if (agent->udp_sockets[0].fd >= 0) {
    udp_socket_close(&agent->udp_sockets[0]);
    agent->udp_sockets[0].fd = -1;
  }

#if CONFIG_IPV6
  if (agent->udp_sockets[1].fd >= 0) {
    udp_socket_close(&agent->udp_sockets[1]);
    agent->udp_sockets[1].fd = -1;
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

  PCL(3041); /* freeze-hunt: about to select() */
  ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
  PCL(3042); /* freeze-hunt: select() returned */
  if (ret < 0) {
    LOGE("select error");
  } else if (ret == 0) {
    // timeout
  } else {
    for (i = 0; i < 2; i++) {
      if (FD_ISSET(agent->udp_sockets[i].fd, &rfds)) {
        memset(buf, 0, len);
        PCL(3043); /* freeze-hunt: about to recvfrom() */
        ret = udp_socket_recvfrom(&agent->udp_sockets[i], addr, buf, len);
        PCL(3044); /* freeze-hunt: recvfrom() returned */
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

static int agent_turn_control_send(Agent* agent, const uint8_t* buf, int len) {
  if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
    return stun_tcp_send(&agent->turn_tcp, buf, len);
  }
  return agent_socket_send(agent, &agent->turn_server, buf, len);
}

static void agent_turn_deallocate(Agent* agent) {
  StunMessage send_msg;
  uint32_t lifetime_zero;

  if (!agent->turn_allocated || !agent->turn_server.port) {
    return;
  }
  memset(&send_msg, 0, sizeof(send_msg));
  lifetime_zero = htonl(0);
  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_REFRESH);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_LIFETIME, sizeof(lifetime_zero), (char*)&lifetime_zero);
  if (agent->turn_username[0]) {
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(agent->turn_username),
                        agent->turn_username);
  }
  if (agent->turn_nonce[0]) {
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(agent->turn_nonce), agent->turn_nonce);
  }
  if (agent->turn_realm[0]) {
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(agent->turn_realm), agent->turn_realm);
  }
  stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, agent->turn_password, strlen(agent->turn_password));
  if (agent_turn_control_send(agent, send_msg.buf, send_msg.size) >= 0) {
    LOGI("TURN Refresh lifetime=0 (deallocate) sent");
#if CONFIG_TURN_TCP
    if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
      agent_turn_tcp_drain_media(agent, 200);
    }
#endif
    if (!agent->turn_use_tcp) {
      agent_turn_drain_udp(agent);
    }
  }
  if (agent->turn_tcp.fd >= 0) {
    tcp_socket_close(&agent->turn_tcp);
    agent->turn_tcp.fd = -1;
  }
  agent->local_candidates_count = 0;
  agent->remote_candidates_count = 0;
  agent->candidate_pairs_num = 0;
  agent->nominated_pair = NULL;
  agent->selected_pair = NULL;
  agent->remote_nominated = 0;
  agent->controlled_nom_deadline = 0;
  agent->turn_allocated = 0;
  agent->turn_use_tcp = 0;
  agent->turn_permissions_count = 0;
  agent->turn_channels_count = 0;
  agent->turn_next_channel = STUN_CHANNEL_NUMBER_MIN;
  agent->turn_cp_pending = 0;
  agent->turn_cb_pending = 0;
  agent->turn_cb_ok = 0;
  agent->turn_alloc_lifetime = 0;
  agent->turn_alloc_time = 0;
  agent->turn_perm_time = 0;
  memset(agent->turn_cp_tid, 0, sizeof(agent->turn_cp_tid));
  memset(agent->turn_cb_tid, 0, sizeof(agent->turn_cb_tid));
  memset(&agent->turn_server, 0, sizeof(agent->turn_server));
  memset(&agent->turn_relay_addr, 0, sizeof(agent->turn_relay_addr));
}

/* Build a TURN Refresh request with the given lifetime + current credentials. */
static void agent_turn_build_refresh(Agent* agent, StunMessage* msg, uint32_t lifetime) {
  uint32_t lt = htonl(lifetime);
  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_REQUEST | STUN_METHOD_REFRESH);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_LIFETIME, sizeof(lt), (char*)&lt);
  if (agent->turn_username[0]) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(agent->turn_username), agent->turn_username);
  }
  if (agent->turn_nonce[0]) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_NONCE, strlen(agent->turn_nonce), agent->turn_nonce);
  }
  if (agent->turn_realm[0]) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_REALM, strlen(agent->turn_realm), agent->turn_realm);
  }
  stun_msg_finish(msg, STUN_CREDENTIAL_LONG_TERM, agent->turn_password, strlen(agent->turn_password));
}

/* Drain the control connection looking for a response to transaction `tid`.
 * Returns 1 and fills `out` if found within the wait window, else 0. */
static int agent_turn_wait_response(Agent* agent, const uint8_t* tid, StunMessage* out, int wait_ms) {
  /* Bound the wait by WALL-CLOCK, not just the idle (sleep) branch. Under an ICE
   * connectivity-check flood the relay socket always has a packet ready, so the
   * old `continue`-without-sleeping path never advanced the counter and never
   * yielded — rtc_loop would spin at prio 5, starving the watchdog/LCD/video and
   * appearing to freeze the whole device until the peer stopped flooding. We now
   * stop at the deadline regardless of traffic and yield periodically. */
  uint32_t start = (uint32_t)ports_get_epoch_time(); /* ms */
  int processed = 0;
  for (;;) {
    StunMessage rx;
    int ret;
    if ((uint32_t)((uint32_t)ports_get_epoch_time() - start) >= (uint32_t)wait_ms) {
      break;
    }
    memset(&rx, 0, sizeof(rx));
    ret = agent_turn_control_recv_attempts(agent, &rx, 1);
    if (ret > 0) {
      /* Only STUN can be our response; ChannelData media never matches a txn id. */
      if (stun_probe(rx.buf, (size_t)ret) == 0) {
        rx.size = (size_t)ret;
        stun_parse_msg_buf(&rx);
        if (memcmp(((StunHeader*)rx.buf)->transaction_id, tid, 12) == 0 &&
            (rx.stunclass == STUN_CLASS_RESPONSE || rx.stunclass == STUN_CLASS_ERROR)) {
          memcpy(out, &rx, sizeof(rx));
          return 1;
        }
      }
      /* Not our response — route through the normal path so muxed ICE/STUN is handled
       * and relayed media (ChannelData/Data indication) is still delivered to the app. */
      if (!agent->turn_use_tcp) {
        agent_turn_process_udp_datagram(agent, &agent->turn_server, rx.buf, ret);
      } else if (stun_probe(rx.buf, (size_t)ret) == 0) {
        rx.size = (size_t)ret;
        stun_parse_msg_buf(&rx);
        agent_turn_dispatch_stun_msg(agent, &rx, &agent->turn_server);
      }
      /* Keep draining queued packets fast, but yield every few so a sustained
       * flood can never monopolise the CPU (deadline above is the hard stop). */
      if ((++processed & 0x0f) == 0) {
        ports_sleep_ms(1);
      }
      continue;
    }
    ports_sleep_ms(10);
  }
  return 0;
}

/* TURN Refresh with stale-nonce (438) retry. lifetime=0 deallocates. Returns 0 on success. */
static int agent_turn_refresh(Agent* agent, uint32_t lifetime) {
  StunMessage send_msg;
  StunMessage resp;
  int attempt;

  if (!agent->turn_allocated || !agent->turn_server.port) {
    return -1;
  }
  for (attempt = 0; attempt < 2; attempt++) {
    agent_turn_build_refresh(agent, &send_msg, lifetime);
    uint8_t tid[12];
    memcpy(tid, ((StunHeader*)send_msg.buf)->transaction_id, sizeof(tid));
    if (agent_turn_control_send(agent, send_msg.buf, send_msg.size) < 0) {
      return -1;
    }
    memset(&resp, 0, sizeof(resp));
    if (!agent_turn_wait_response(agent, tid, &resp, agent->turn_use_tcp ? 600 : 400)) {
      /* No reply (lifetime=0 best-effort, or transient). Treat non-fatal. */
      return lifetime == 0 ? 0 : -1;
    }
    if (resp.stunclass == STUN_CLASS_RESPONSE) {
      if (lifetime > 0) {
        /* Tests pin a short lifetime via AGENT_TURN_REQUEST_LIFETIME so the periodic
         * Refresh keeps firing (coturn clamps the actual allocation up to its 600 s
         * minimum and echoes that back). */
        const char* ov = getenv("AGENT_TURN_REQUEST_LIFETIME");
        uint32_t pin = (ov && ov[0]) ? (uint32_t)atoi(ov) : 0;
        agent->turn_alloc_lifetime = pin ? pin : (resp.lifetime ? resp.lifetime : lifetime);
        agent->turn_alloc_time = ports_get_epoch_time();
        LOGI("TURN Refresh OK lifetime=%u s (echoed=%u)", agent->turn_alloc_lifetime, resp.lifetime);
      }
      return 0;
    }
    if (resp.stunclass == STUN_CLASS_ERROR && resp.error_code == 438 && resp.nonce[0]) {
      /* Stale nonce: adopt the server's fresh nonce/realm and retry once. */
      strncpy(agent->turn_nonce, resp.nonce, sizeof(agent->turn_nonce) - 1);
      agent->turn_nonce[sizeof(agent->turn_nonce) - 1] = '\0';
      if (resp.realm[0]) {
        strncpy(agent->turn_realm, resp.realm, sizeof(agent->turn_realm) - 1);
        agent->turn_realm[sizeof(agent->turn_realm) - 1] = '\0';
      }
      LOGI("TURN Refresh 438 stale nonce — retrying with fresh nonce");
      continue;
    }
    LOGW("TURN Refresh failed class=0x%x err=%d", resp.stunclass, resp.error_code);
    return -1;
  }
  return -1;
}

/* Refresh allocation + permissions/channels before they expire. Cheap time-gated. */
static void agent_turn_refresh_maybe(Agent* agent) {
  uint32_t now;
  uint32_t half;
  const char* disable;

  if (!agent->turn_allocated) {
    return;
  }
  /* Test hook: AGENT_TURN_DISABLE_REFRESH=1 lets the allocation expire (negative case). */
  disable = getenv("AGENT_TURN_DISABLE_REFRESH");
  if (disable && disable[0] == '1') {
    return;
  }
  /* ports_get_epoch_time() returns milliseconds; lifetimes are in seconds. */
  now = ports_get_epoch_time();
  half = (agent->turn_alloc_lifetime ? agent->turn_alloc_lifetime : AGENT_TURN_DEFAULT_LIFETIME) * 1000u / 2u;
  if (half < 5000u) {
    half = 5000u;
  }
  if (now - agent->turn_alloc_time >= half) {
    agent_turn_refresh(agent, agent->turn_alloc_lifetime ? agent->turn_alloc_lifetime
                                                          : AGENT_TURN_DEFAULT_LIFETIME);
  }
  /* Permissions expire after ~300 s; channel binds after ~600 s. Re-issue both at
   * half the permission lifetime so inbound relay keeps flowing. ChannelBind also
   * refreshes the underlying permission. AGENT_TURN_PERM_REFRESH_MS overrides the
   * interval (tests use short coturn channel/permission lifetimes). */
  uint32_t perm_interval = AGENT_TURN_PERMISSION_LIFETIME * 1000u / 2u;
  {
    const char* pe = getenv("AGENT_TURN_PERM_REFRESH_MS");
    if (pe && pe[0]) {
      int v = atoi(pe);
      if (v > 0) {
        perm_interval = (uint32_t)v;
      }
    }
  }
  if (now - agent->turn_perm_time >= perm_interval) {
    int i;
    int n = agent->turn_channels_count;
    for (i = 0; i < n; i++) {
      Address peer = agent->turn_channels[i].peer;
      uint16_t ch = agent->turn_channels[i].number;
      if (agent->turn_channels[i].bound && ch >= STUN_CHANNEL_NUMBER_MIN) {
        agent_turn_channel_bind_req(agent, &peer, ch);
      } else {
        agent_turn_create_permission(agent, &peer);
      }
    }
    for (i = 0; i < agent->turn_permissions_count; i++) {
      agent_turn_create_permission(agent, &agent->turn_permissions[i]);
    }
    agent->turn_perm_time = ports_get_epoch_time();
  }
}

static int agent_turn_control_recv_attempts(Agent* agent, StunMessage* recv_msg, int maxtimes) {
  int ret = -1;
  int i;
  if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
    int tcp_max = (maxtimes > 0) ? maxtimes : AGENT_TURN_TCP_RECV_MAXTIMES;
    if (tcp_max > AGENT_TURN_TCP_RECV_MAXTIMES) {
      tcp_max = AGENT_TURN_TCP_RECV_MAXTIMES;
    }
    for (i = 0; i < tcp_max; i++) {
      ret = stun_tcp_recv_packet(&agent->turn_tcp, recv_msg->buf, (int)sizeof(recv_msg->buf));
      if (ret > 0) {
        recv_msg->size = ret;
        return ret;
      }
      if (ret < 0) {
        return ret;
      }
      if (i + 1 < tcp_max) {
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(agent->turn_tcp.fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        (void)select(agent->turn_tcp.fd + 1, &rfds, NULL, NULL, &tv);
      }
    }
    return 0;
  }
  return agent_socket_recv_attempts(agent, NULL, recv_msg->buf, (int)sizeof(recv_msg->buf), maxtimes);
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
  /* We must use OUR TURN allocation (Send indication / ChannelData) only when
   * OUR local candidate is the relay. When the remote is a relay but our local
   * is host/srflx, the remote's relayed transport address is a routable public
   * address we send to directly — routing it back through our own TURN server
   * would be an incorrect (and fragile) double-relay. */
  return pair->local->type == ICE_CANDIDATE_TYPE_RELAY;
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

/** True when media ICE pair is already up and this Binding is from the same remote. */
static int agent_inbound_from_selected_pair(const Agent* agent, const Address* addr) {
  const IceCandidatePair* sel = agent->selected_pair;
  if (!sel || sel->state != ICE_CANDIDATE_STATE_SUCCEEDED || !sel->remote || !addr) {
    return 0;
  }
  if (agent_addr_same(&sel->remote->addr, addr)) {
    return 1;
  }
  if (sel->remote->type == ICE_CANDIDATE_TYPE_HOST && sel->remote->addr.family == AF_INET &&
      addr->family == AF_INET) {
    uint32_t rip = ntohl(sel->remote->addr.sin.sin_addr.s_addr);
    uint32_t aip = ntohl(addr->sin.sin_addr.s_addr);
    if (agent_ipv4_same_lan23(rip, aip) && sel->remote->addr.port == addr->port) {
      return 1;
    }
  }
  return 0;
}

/* Drop remote RFC1918 host on another LAN segment (VMware 192.168.56.x, etc.). */
static int agent_remote_candidate_viable(const Agent* agent, const IceCandidate* remote) {
  int i;
  if (!remote) {
    return 0;
  }
  /* Relay-only policy is enforced on the *local* side: we gather only our
   * TURN relay candidate, so every pair egresses through the relay regardless
   * of the remote candidate type. Remote host/srflx are still acceptable
   * targets to relay to, so they are not filtered here. */
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
    if (stun_msg->error_code == 438 && stun_msg->nonce[0]) {
      strncpy(agent->turn_nonce, stun_msg->nonce, sizeof(agent->turn_nonce) - 1);
      agent->turn_nonce[sizeof(agent->turn_nonce) - 1] = '\0';
      if (stun_msg->realm[0]) {
        strncpy(agent->turn_realm, stun_msg->realm, sizeof(agent->turn_realm) - 1);
        agent->turn_realm[sizeof(agent->turn_realm) - 1] = '\0';
      }
      LOGI("TURN CreatePermission 438 — refreshed nonce (retry next cycle)");
      return;
    }
    LOGW("TURN CreatePermission STUN error (code=%d)", stun_msg->error_code);
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

  ret = agent_turn_control_send(agent, send_msg.buf, send_msg.size);
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

  uint8_t drain_buf[1400];
  for (int drain = 0; drain < 4; drain++) {
    if (agent_recv(agent, drain_buf, sizeof(drain_buf)) != 0) {
      break;
    }
  }
  agent->turn_cp_pending = 0;
  return 0;
}

static int agent_addr_is_turn_server(const Agent* agent, const Address* addr) {
  char sa[ADDRSTRLEN];
  char sb[ADDRSTRLEN];
  if (!agent->turn_allocated || !addr) {
    return 0;
  }
  if (addr->port != agent->turn_server.port) {
    return 0;
  }
  addr_to_string(addr, sa, sizeof(sa));
  addr_to_string(&agent->turn_server, sb, sizeof(sb));
  return strcmp(sa, sb) == 0;
}

static int agent_media_stash(Agent* agent, const uint8_t* payload, int plen) {
  if (!agent || !payload || plen <= 0) {
    return -1;
  }
  if (agent->turn_pending_media_len > 0 || plen > (int)sizeof(agent->turn_pending_media)) {
    return -1;
  }
  memmove(agent->turn_pending_media, payload, (size_t)plen);
  agent->turn_pending_media_len = plen;
  return 0;
}

static void agent_turn_process_channel_payload(Agent* agent, uint16_t channel, const uint8_t* payload,
                                               int plen) {
  Address peer;
  char peer_str[ADDRSTRLEN];

  if (!agent_turn_channel_to_peer(agent, channel, &peer)) {
    if (!agent->selected_pair) {
      PEER_LOG_RAW("CHPL unknown ch=0x%04x plen=%d\n", (unsigned)channel, plen);
    }
    LOGW("TURN ChannelData unknown ch=0x%04x (%d B)", (unsigned)channel, plen);
    return;
  }
  addr_to_string(&peer, peer_str, sizeof(peer_str));
  if (plen > 0 && stun_probe((uint8_t*)payload, (size_t)plen) == 0) {
    StunMessage inner;
    LOGI("TURN ChannelData %d B STUN from peer %s:%d (ch=0x%04x)", plen, peer_str, peer.port,
         (unsigned)channel);
    memset(&inner, 0, sizeof(inner));
    memcpy(inner.buf, payload, (size_t)plen);
    inner.size = (size_t)plen;
    stun_parse_msg_buf(&inner);
    if (!agent->selected_pair) {
      PEER_LOG_RAW("CHPL stun cls=%d mth=%d uc=%d peer=%u:%u\n", (int)inner.stunclass,
                     (int)inner.stunmethod, (int)inner.use_candidate,
                     (unsigned)((uint32_t)peer.sin.sin_addr.s_addr & 0xff), peer.port);
    }
    agent_process_inbound_stun(agent, &inner, &peer);
    return;
  }
  /* Non-STUN payload = relayed application media (DTLS/SRTP). Hand it to the caller. */
  if (plen > 0 && agent->media_out && agent->media_out_len == 0 && plen <= agent->media_out_cap) {
    /* payload may alias the caller buffer (buf+4 -> buf), so memmove. */
    memmove(agent->media_out, payload, (size_t)plen);
    agent->media_out_len = plen;
    LOGD("TURN ChannelData %d B media from peer %s:%d -> app", plen, peer_str, peer.port);
  } else if (plen > 0 && agent_media_stash(agent, payload, plen) == 0) {
    LOGD("TURN ChannelData %d B media stashed (no app buffer)", plen);
  } else if (plen > 0) {
    LOGW("TURN ChannelData %d B media dropped (no app buffer / overflow)", plen);
  }
}

static void agent_turn_drain_udp(Agent* agent) {
  uint8_t buf[1400];
  Address addr;
  int i;
  int ret;

  if (agent->turn_use_tcp || !agent->turn_allocated) {
    return;
  }
  for (i = 0; i < 24; i++) {
    ret = agent_socket_recv(agent, &addr, buf, (int)sizeof(buf));
    if (ret <= 0) {
      break;
    }
    if (agent_turn_process_udp_datagram(agent, &addr, buf, ret)) {
      /* Consumed as TURN traffic (and may have surfaced relayed media into
       * agent->media_out). Stop if we now have media to hand back. */
      if (agent->media_out_len > 0) {
        break;
      }
      continue;
    }
    /* udp_sockets[] is shared between TURN control and direct (host/srflx) ICE.
     * A non-TURN datagram read here must NOT be dropped: route ICE STUN to the
     * inbound handler (binding requests/USE-CANDIDATE/keepalives) and hand direct
     * media (e.g. a DTLS flight on a host pair) back to the caller via media_out. */
    if (stun_probe(buf, (size_t)ret) == 0) {
      StunMessage sm;
      memset(&sm, 0, sizeof(sm));
      memcpy(sm.buf, buf, (size_t)ret);
      sm.size = (size_t)ret;
      stun_parse_msg_buf(&sm);
      agent_process_inbound_stun(agent, &sm, &addr);
    } else if (agent->media_out && agent->media_out_len == 0 && ret <= agent->media_out_cap) {
      memcpy(agent->media_out, buf, (size_t)ret);
      agent->media_out_len = ret;
      break;
    }
  }
}

static int agent_turn_udp_send_channel_data(Agent* agent, uint16_t channel, const uint8_t* data, int len) {
  /* Frame buffer must hold a full relay datagram (payload + 4-byte ChannelData
   * header + padding). STUN_ATTR_BUF_SIZE (512) was far too small: a DTLS
   * handshake flight carrying our certificate is ~760 B, so stun_pack_channel_data()
   * returned -1 and agent_send() reported a send failure to mbedTLS. mbedTLS then
   * reset the session (regenerating client_random); the peer's already-sent flight,
   * signed over the old random, failed signature verification on the retry —
   * surfacing as the relay-only ECP_VERIFY_FAILED (-0x4e00). Uses the off-stack
   * agent->turn_chan_frame (see agent.h) to keep the webrtc_bus stack small. */
  int total;

  total = stun_pack_channel_data(agent->turn_chan_frame, (int)sizeof(agent->turn_chan_frame),
                                 channel, data, len);
  if (total < 0) {
    return -1;
  }
  return agent_socket_send(agent, &agent->turn_server, agent->turn_chan_frame, total);
}

static int agent_turn_dispatch_stun_msg(Agent* agent, StunMessage* stun_msg, Address* addr) {
  agent_turn_cb_try_finish_from_response(agent, stun_msg);
  agent_turn_cp_try_finish_from_response(agent, stun_msg);
  if (!agent->turn_cb_pending || stun_msg->stunmethod != STUN_METHOD_CHANNEL_BIND ||
      stun_msg->stunclass != STUN_CLASS_RESPONSE) {
    agent_process_inbound_stun(agent, stun_msg, addr);
  }
  return 1;
}

static int agent_turn_process_udp_datagram(Agent* agent, Address* addr, uint8_t* buf, int len) {
  uint16_t channel;
  int plen;

  if (!agent->turn_allocated) {
    return 0;
  }
  if (stun_is_channel_data_prefix(buf, len, &channel, &plen)) {
    agent_turn_process_channel_payload(agent, channel, buf + 4, plen);
    return 1;
  }
  if (stun_probe(buf, (size_t)len) != 0) {
    return 0;
  }
  if (!agent_addr_is_turn_server(agent, addr)) {
    return 0;
  }
  {
    StunMessage stun_msg;
    memset(&stun_msg, 0, sizeof(stun_msg));
    memcpy(stun_msg.buf, buf, (size_t)len);
    stun_msg.size = (size_t)len;
    stun_parse_msg_buf(&stun_msg);
    return agent_turn_dispatch_stun_msg(agent, &stun_msg, addr);
  }
}

static int agent_turn_channel_to_peer(Agent* agent, uint16_t channel, Address* peer) {
  int i;
  for (i = 0; i < agent->turn_channels_count; i++) {
    if (agent->turn_channels[i].number == channel) {
      *peer = agent->turn_channels[i].peer;
      return 1;
    }
  }
  return 0;
}

static void agent_turn_cb_try_finish_from_response(Agent* agent, StunMessage* stun_msg) {
  int i;

  if (stun_msg->stunmethod != STUN_METHOD_CHANNEL_BIND) {
    return;
  }
  if (!agent->turn_cb_pending) {
    StunHeader* lh;
    if (stun_msg->stunclass != STUN_CLASS_RESPONSE) {
      return;
    }
    lh = (StunHeader*)stun_msg->buf;
    if (memcmp(lh->transaction_id, agent->turn_cb_tid, sizeof(agent->turn_cb_tid)) != 0) {
      return;
    }
    for (i = 0; i < agent->turn_channels_count; i++) {
      if (agent->turn_channels[i].number == agent->turn_cb_channel) {
        agent->turn_channels[i].bound = 1;
        LOGI("TURN ChannelBind late OK ch=0x%04x", (unsigned)agent->turn_channels[i].number);
        return;
      }
    }
    return;
  }
  StunHeader* h = (StunHeader*)stun_msg->buf;
  if (memcmp(h->transaction_id, agent->turn_cb_tid, sizeof(agent->turn_cb_tid)) != 0) {
    return;
  }
  agent->turn_cb_pending = 0;
  if (stun_msg->stunclass == STUN_CLASS_ERROR) {
    agent->turn_cb_ok = -1;
    if (stun_msg->error_code == 438 && stun_msg->nonce[0]) {
      strncpy(agent->turn_nonce, stun_msg->nonce, sizeof(agent->turn_nonce) - 1);
      agent->turn_nonce[sizeof(agent->turn_nonce) - 1] = '\0';
      if (stun_msg->realm[0]) {
        strncpy(agent->turn_realm, stun_msg->realm, sizeof(agent->turn_realm) - 1);
        agent->turn_realm[sizeof(agent->turn_realm) - 1] = '\0';
      }
      LOGI("TURN ChannelBind 438 — refreshed nonce (retry next cycle)");
      return;
    }
    if (stun_msg->error_code != 0) {
      LOGW("TURN ChannelBind STUN error %d %s", stun_msg->error_code, stun_msg->error_reason);
    } else {
      LOGW("TURN ChannelBind STUN error");
    }
    return;
  }
  if (stun_msg->stunclass != STUN_CLASS_RESPONSE) {
    agent->turn_cb_ok = -1;
    return;
  }
  agent->turn_cb_ok = 1;
  for (i = 0; i < agent->turn_channels_count; i++) {
    if (agent->turn_channels[i].number == agent->turn_cb_channel) {
      Address* p = &agent->turn_channels[i].peer;
      agent->turn_channels[i].bound = 1;
      if (!agent_turn_has_permission(agent, p) &&
          agent->turn_permissions_count < AGENT_TURN_MAX_PERMISSIONS) {
        agent->turn_permissions[agent->turn_permissions_count++] = *p;
      }
      char addr_string[ADDRSTRLEN];
      addr_to_string(p, addr_string, sizeof(addr_string));
      LOGI("TURN ChannelBind 0x%04x for %s:%d", (unsigned)agent->turn_cb_channel, addr_string, p->port);
      return;
    }
  }
}

static int agent_turn_channel_bind_req(Agent* agent, Address* peer, uint16_t channel) {
  StunMessage send_msg;
  StunMessage recv_msg;
  char xor_peer[32];
  uint16_t ch_fields[2];
  int xor_len;
  int ret;
  int i;

  if (agent_turn_create_permission(agent, peer) != 0) {
    return -1;
  }

  memset(&send_msg, 0, sizeof(send_msg));
  memset(&recv_msg, 0, sizeof(recv_msg));
  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_CHANNEL_BIND);
  /* coturn stun_attr_add_channel_number_str: 4-byte value, channel in first uint16 (BE). */
  ch_fields[0] = htons(channel);
  ch_fields[1] = 0;
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_CHANNEL_NUMBER, sizeof(ch_fields), (char*)ch_fields);
  xor_len = agent_turn_write_xor_peer(xor_peer, peer, (StunHeader*)send_msg.buf);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_XOR_PEER_ADDRESS, xor_len, xor_peer);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(agent->turn_username),
                      agent->turn_username);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(agent->turn_realm), agent->turn_realm);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(agent->turn_nonce), agent->turn_nonce);
  stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, agent->turn_password,
                  strlen(agent->turn_password));

  memcpy(agent->turn_cb_tid, ((StunHeader*)send_msg.buf)->transaction_id, sizeof(agent->turn_cb_tid));
  agent->turn_cb_channel = channel;
  agent->turn_cb_pending = 1;
  agent->turn_cb_ok = 0;

  ret = agent_turn_control_send(agent, send_msg.buf, send_msg.size);
  if (ret < 0) {
    agent->turn_cb_pending = 0;
    return -1;
  }

#if CONFIG_TURN_TCP
  if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
    tcp_socket_set_recv_timeout_ms(&agent->turn_tcp, AGENT_TURN_CB_RECV_MS);
  }
#endif
  {
    const int wait_ms = agent->turn_use_tcp ? AGENT_TURN_CB_WAIT_MS : 800;
    for (i = 0; agent->turn_cb_pending && i * 50 < wait_ms; i++) {
#if CONFIG_TURN_TCP
      if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(agent->turn_tcp.fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        if (select(agent->turn_tcp.fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
          continue;
        }
      } else
#endif
      {
        ports_sleep_ms(50);
      }
      for (int pass = 0; agent->turn_cb_pending && pass < 12; pass++) {
        memset(&recv_msg, 0, sizeof(recv_msg));
        ret = agent_turn_control_recv_attempts(agent, &recv_msg, 1);
        if (ret <= 0) {
          break;
        }
        recv_msg.size = (size_t)ret;
        stun_parse_msg_buf(&recv_msg);
        {
          Address from = agent->turn_server;
          agent_turn_dispatch_stun_msg(agent, &recv_msg, &from);
        }
      }
      if (!agent->turn_use_tcp) {
        agent_turn_drain_udp(agent);
      }
    }
  }
#if CONFIG_TURN_TCP
  if (agent->turn_use_tcp && agent->turn_tcp.fd >= 0) {
    tcp_socket_set_recv_timeout_ms(&agent->turn_tcp, 50);
  }
#endif
  if (!agent->turn_cb_pending) {
    return agent->turn_cb_ok == 1 ? 0 : -1;
  }
  if (agent->turn_cb_ok == -1) {
    agent->turn_cb_pending = 0;
    return -1;
  }
  /* Coturn may accept the bind but the success STUN reply can arrive after the wait window. */
  agent->turn_cb_pending = 0;
  for (i = 0; i < agent->turn_channels_count; i++) {
    if (agent->turn_channels[i].number == channel) {
      agent->turn_channels[i].bound = 1;
      break;
    }
  }
  if (!agent_turn_has_permission(agent, peer) &&
      agent->turn_permissions_count < AGENT_TURN_MAX_PERMISSIONS) {
    agent->turn_permissions[agent->turn_permissions_count++] = *peer;
  }
  char addr_string[ADDRSTRLEN];
  addr_to_string(peer, addr_string, sizeof(addr_string));
  LOGD("TURN ChannelBind assumed OK ch=0x%04x for %s:%d", (unsigned)channel, addr_string, peer->port);
  return 0;
}

static int agent_turn_peer_prefers_send(Agent* agent, Address* peer) {
  int i;
  for (i = 0; i < agent->turn_channels_count; i++) {
    if (agent_addr_same(&agent->turn_channels[i].peer, peer)) {
      return agent->turn_channels[i].use_send;
    }
  }
  return 0;
}

static int agent_turn_get_or_bind_channel(Agent* agent, Address* peer, uint16_t* out_ch) {
  int i;

  if (agent_turn_peer_prefers_send(agent, peer)) {
    return -1;
  }
  for (i = 0; i < agent->turn_channels_count; i++) {
    if (agent_addr_same(&agent->turn_channels[i].peer, peer)) {
      if (agent->turn_channels[i].use_send) {
        return -1;
      }
      if (!agent->turn_channels[i].bound) {
        if (agent_turn_channel_bind_req(agent, peer, agent->turn_channels[i].number) != 0) {
          return -1;
        }
        agent->turn_channels[i].bound = 1;
      }
      *out_ch = agent->turn_channels[i].number;
      return 0;
    }
  }
  if (agent->turn_channels_count >= AGENT_TURN_MAX_CHANNELS) {
    return -1;
  }
  i = agent->turn_channels_count++;
  agent->turn_channels[i].peer = *peer;
  agent->turn_channels[i].number = agent->turn_next_channel++;
  if (agent->turn_next_channel > STUN_CHANNEL_NUMBER_MAX) {
    agent->turn_next_channel = STUN_CHANNEL_NUMBER_MIN;
  }
  agent->turn_channels[i].bound = 0;
  agent->turn_channels[i].use_send = 0;
  if (agent_turn_channel_bind_req(agent, peer, agent->turn_channels[i].number) != 0) {
    agent->turn_channels[i].use_send = 1;
    return -1;
  }
  agent->turn_channels[i].bound = 1;
  *out_ch = agent->turn_channels[i].number;
  return 0;
}

/* ChannelData (4-byte header) is the efficient relay path and is the default. The
 * earlier "one-way ChannelData" failures were a STUN XOR-address parse bug (now fixed),
 * not a ChannelData problem. Set AGENT_TURN_USE_INDICATIONS=1 to fall back to the
 * larger Send/Data indications (debugging / interop). */
static int agent_turn_channeldata_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char* e = getenv("AGENT_TURN_USE_INDICATIONS");
    cached = (e && e[0] == '1') ? 0 : 1;
  }
  return cached;
}

/* Best-effort relayed send used when agent_turn_send() is re-entered from inside
 * a TURN wait/dispatch (Agent.turn_send_depth > 0). It NEVER starts a blocking
 * ChannelBind/CreatePermission handshake — that is exactly what recursed through
 * agent_turn_wait_response() and overflowed the task stack under connectivity-
 * check bursts. It uses an already-bound channel if one exists, otherwise a
 * stateless Send indication. A response sent this way may be dropped by the
 * server if no permission exists yet; that is harmless because the peer
 * retransmits its Binding request and the depth-0 path answers it properly. */
static int agent_turn_send_reentrant(Agent* agent, Address* peer, const uint8_t* data, int len) {
  StunMessage ind;
  char xor_peer[32];
  int xor_len;
  int i;

  if (agent_turn_channeldata_enabled()) {
    for (i = 0; i < agent->turn_channels_count; i++) {
      if (agent->turn_channels[i].bound && !agent->turn_channels[i].use_send &&
          agent_addr_same(&agent->turn_channels[i].peer, peer)) {
        if (agent->turn_use_tcp) {
          return stun_tcp_send_channel_data(&agent->turn_tcp, agent->turn_channels[i].number, data, len);
        }
        return agent_turn_udp_send_channel_data(agent, agent->turn_channels[i].number, data, len);
      }
    }
  }
  memset(&ind, 0, sizeof(ind));
  stun_msg_create(&ind, STUN_CLASS_INDICATION | STUN_METHOD_SEND);
  xor_len = agent_turn_write_xor_peer(xor_peer, peer, (StunHeader*)ind.buf);
  stun_msg_write_attr(&ind, STUN_ATTR_TYPE_XOR_PEER_ADDRESS, xor_len, xor_peer);
  stun_msg_write_attr(&ind, STUN_ATTR_TYPE_DATA, len, (char*)data);
  return agent_turn_control_send(agent, ind.buf, ind.size);
}

static int agent_turn_send_inner(Agent* agent, Address* peer, const uint8_t* data, int len) {
  StunMessage send_msg;
  char xor_peer[32];
  int xor_len;
  int ret;
  uint16_t channel;

  if (!agent->turn_allocated || !peer || !data || len <= 0) {
    return -1;
  }

  /* ChannelData is the default efficient relay path (see agent_turn_channeldata_enabled).
   * Set AGENT_TURN_USE_INDICATIONS=1 to fall back to Send/Data indications. */
  if (agent_turn_channeldata_enabled())
  {
  if (!agent_turn_peer_prefers_send(agent, peer)) {
    if (agent_turn_get_or_bind_channel(agent, peer, &channel) == 0) {
      char ps[ADDRSTRLEN];
      addr_to_string(peer, ps, sizeof(ps));
      LOGI("TURN ChannelData %d B -> %s:%d ch=0x%04x", len, ps, peer->port, (unsigned)channel);
      if (agent->turn_use_tcp) {
        ret = stun_tcp_send_channel_data(&agent->turn_tcp, channel, data, len);
        /* Flush any partial TX tail only — do NOT drain inbound ChannelData here.
         * This runs inside mbedTLS's send callback; agent->media_out is unset, so
         * reading inbound relayed media would drop SCTP/datachannel frames (see the
         * UDP ChannelData path below). agent_recv() picks up inbound media. */
        (void)tcp_socket_tx_flush(&agent->turn_tcp);
        return ret;
      }
      ret = agent_turn_udp_send_channel_data(agent, channel, data, len);
      /* Do NOT drain here: this runs inside mbedTLS's send callback during the
       * DTLS handshake (and later for every media write). agent->media_out is
       * unset in the send context, so draining would read the peer's relayed
       * response (server flight / media) off the shared socket and drop it,
       * leaving mbedTLS's f_recv to stall on an incomplete flight (observed as
       * ECP_VERIFY_FAILED). The dedicated recv path (agent_recv) reads it. */
      return ret;
    }
  }
  }

  if (agent_turn_create_permission(agent, peer) != 0) {
    return -1;
  }

  memset(&send_msg, 0, sizeof(send_msg));
  stun_msg_create(&send_msg, STUN_CLASS_INDICATION | STUN_METHOD_SEND);
  xor_len = agent_turn_write_xor_peer(xor_peer, peer, (StunHeader*)send_msg.buf);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_XOR_PEER_ADDRESS, xor_len, xor_peer);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_DATA, len, (char*)data);
  ret = agent_turn_control_send(agent, send_msg.buf, send_msg.size);
#if CONFIG_TURN_TCP
  if (agent->turn_use_tcp) {
    agent_turn_tcp_drain_media(agent, 80);
  }
#endif
  /* UDP: do not drain here (send-callback context, media_out unset) — see the
   * ChannelData path above. The recv path picks up relayed responses. */
  return ret;
}

/* Re-entrancy guard around the TURN send path. At depth 0 this is the normal
 * (working) blocking send. If reached again while a TURN wait/dispatch is in
 * progress (a relayed Binding request answered mid-handshake), it falls back to
 * a non-blocking best-effort send so the ChannelBind/wait chain cannot recurse
 * into itself and overflow the stack. See Agent.turn_send_depth. */
static int agent_turn_send(Agent* agent, Address* peer, const uint8_t* data, int len) {
  int ret;

  if (!agent->turn_allocated || !peer || !data || len <= 0) {
    return -1;
  }
  if (agent->turn_send_depth > 0) {
    return agent_turn_send_reentrant(agent, peer, data, len);
  }
  agent->turn_send_depth++;
  ret = agent_turn_send_inner(agent, peer, data, len);
  agent->turn_send_depth--;
  return ret;
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
    const int same_as_selected =
        (agent->selected_pair && agent->selected_pair == best &&
         agent->selected_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED);
    agent->nominated_pair = best;
    agent->selected_pair = best;
    if (!same_as_selected) {
      char raddr[ADDRSTRLEN];
      addr_to_string(addr, raddr, sizeof(raddr));
      LOGI("ICE inbound Binding OK — nominated %s:%d", raddr, addr->port);
    } else {
      LOGD("ICE keepalive binding from selected pair");
    }
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

static int agent_parse_ice_server_url(const char* urls, char* hostname, size_t hlen, int* port,
                                      int* use_tcp) {
  const char* rest;
  char tmp[256];
  char* q;
  char* colon;

  if (!urls || !hostname || !port || !use_tcp) {
    return -1;
  }
  *use_tcp = 0;
  if (strncmp(urls, "stun:", 5) == 0) {
    rest = urls + 5;
  } else if (strncmp(urls, "turn:", 5) == 0) {
    rest = urls + 5;
  } else {
    return -1;
  }
  strncpy(tmp, rest, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = '\0';
  q = strchr(tmp, '?');
  if (q) {
#if CONFIG_TURN_TCP
    if (strstr(q, "transport=tcp") != NULL) {
      *use_tcp = 1;
    }
#endif
    *q = '\0';
  }
  colon = strrchr(tmp, ':');
  if (!colon) {
    return -1;
  }
  *port = atoi(colon + 1);
  if (*port <= 0) {
    return -1;
  }
  *colon = '\0';
  strncpy(hostname, tmp, hlen - 1);
  hostname[hlen - 1] = '\0';
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

static int agent_create_turn_addr(Agent* agent, Address* serv_addr, const char* username,
                                  const char* credential, int use_tcp) {
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

#if CONFIG_TURN_TCP
  agent->turn_use_tcp = 0;
  if (use_tcp) {
    uint32_t sip = (uint32_t)serv_addr->sin.sin_addr.s_addr;
    PEER_LOG_RAW("TURNTCP connect -> %u.%u.%u.%u:%u\n", sip & 0xff, (sip >> 8) & 0xff,
                   (sip >> 16) & 0xff, (sip >> 24) & 0xff, serv_addr->port);
    agent->turn_tcp.fd = -1;
    if (tcp_socket_open(&agent->turn_tcp, serv_addr->family) < 0) {
      PEER_LOG_RAW("TURNTCP open FAILED\n");
      LOGE("TURN/TCP socket open failed");
      return -1;
    }
    if (tcp_socket_connect(&agent->turn_tcp, serv_addr) < 0) {
      PEER_LOG_RAW("TURNTCP connect FAILED\n");
      tcp_socket_close(&agent->turn_tcp);
      return -1;
    }
    agent->turn_use_tcp = 1;
    PEER_LOG_RAW("TURNTCP connected ok\n");
    LOGI("TURN control transport: TCP");
  } else
#endif
  {
    LOGI("TURN control transport: UDP");
  }

  memset(&recv_msg, 0, sizeof(recv_msg));
  memset(&send_msg, 0, sizeof(send_msg));
  stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);

  ret = agent_turn_control_send(agent, send_msg.buf, send_msg.size);
  if (ret == -1) {
    LOGE("Failed to send TURN Allocate.");
    goto fail;
  }

  ret = agent_turn_control_recv_attempts(agent, &recv_msg,
                                         agent->turn_use_tcp ? AGENT_TURN_TCP_RECV_MAXTIMES
                                                             : AGENT_STUN_RECV_MAXTIMES);
  PEER_LOG_RAW("TURNTCP alloc1 ret=%d\n", ret);
  if (ret <= 0) {
    LOGE("Failed to receive TURN Allocate response (ret=%d).", ret);
    goto fail;
  }

  stun_parse_msg_buf(&recv_msg);
  LOGD("TURN Allocate challenge class=0x%x method=0x%x", recv_msg.stunclass, recv_msg.stunmethod);

  if (recv_msg.stunclass == STUN_CLASS_ERROR && recv_msg.stunmethod == STUN_METHOD_ALLOCATE) {
    if (recv_msg.realm[0]) {
      strncpy(agent->turn_realm, recv_msg.realm, sizeof(agent->turn_realm) - 1);
      agent->turn_realm[sizeof(agent->turn_realm) - 1] = '\0';
    }
    if (recv_msg.nonce[0]) {
      strncpy(agent->turn_nonce, recv_msg.nonce, sizeof(agent->turn_nonce) - 1);
      agent->turn_nonce[sizeof(agent->turn_nonce) - 1] = '\0';
    }
    memset(&send_msg, 0, sizeof(send_msg));
    stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(recv_msg.nonce), recv_msg.nonce);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(recv_msg.realm), recv_msg.realm);
    {
      /* Test hook: request a short allocation lifetime so expiry/refresh can be
       * exercised quickly (coturn's max-allocate-lifetime does not cap the default). */
      const char* req_lt = getenv("AGENT_TURN_REQUEST_LIFETIME");
      if (req_lt && req_lt[0]) {
        uint32_t lt = htonl((uint32_t)atoi(req_lt));
        stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_LIFETIME, sizeof(lt), (char*)&lt);
      }
    }
    stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, credential, strlen(credential));
  } else if (recv_msg.stunclass == STUN_CLASS_ERROR) {
    LOGE("TURN Allocate unexpected error class=0x%x method=0x%x", recv_msg.stunclass, recv_msg.stunmethod);
    goto fail;
  } else {
    LOGE("Invalid TURN Allocate challenge class=0x%x method=0x%x size=%d", recv_msg.stunclass,
         recv_msg.stunmethod, (int)recv_msg.size);
    goto fail;
  }

  ret = agent_turn_control_send(agent, send_msg.buf, send_msg.size);
  if (ret < 0) {
    LOGE("Failed to send authenticated TURN Allocate.");
    goto fail;
  }

  memset(&recv_msg, 0, sizeof(recv_msg));
  ret = agent_turn_control_recv_attempts(agent, &recv_msg,
                                         agent->turn_use_tcp ? AGENT_TURN_TCP_RECV_MAXTIMES
                                                             : AGENT_STUN_RECV_MAXTIMES);
  PEER_LOG_RAW("TURNTCP alloc2 ret=%d\n", ret);
  if (ret <= 0) {
    LOGD("Failed to receive TURN Allocate success.");
    goto fail;
  }

  stun_parse_msg_buf(&recv_msg);
  if (recv_msg.stunclass != STUN_CLASS_RESPONSE) {
    PEER_LOG_RAW("TURNTCP alloc2 class=0x%x (not response)\n", recv_msg.stunclass);
    LOGE("TURN Allocate failed class=0x%x", recv_msg.stunclass);
    goto fail;
  }
  memcpy(&turn_addr, &recv_msg.relayed_addr, sizeof(Address));
  if (recv_msg.realm[0]) {
    strncpy(agent->turn_realm, recv_msg.realm, sizeof(agent->turn_realm) - 1);
  }
  if (recv_msg.nonce[0]) {
    strncpy(agent->turn_nonce, recv_msg.nonce, sizeof(agent->turn_nonce) - 1);
  }
  agent->turn_allocated = 1;
  agent->turn_permissions_count = 0;
  agent->turn_channels_count = 0;
  agent->turn_next_channel = STUN_CHANNEL_NUMBER_MIN;
  agent->turn_alloc_lifetime = recv_msg.lifetime ? recv_msg.lifetime : AGENT_TURN_DEFAULT_LIFETIME;
  {
    /* Test hook: coturn ignores LIFETIME in Allocate (always grants 600 s) but honours
     * it in Refresh. Override the effective lifetime so the periodic Refresh requests
     * (and the refresh cadence) use the short value — lets expiry tests run in ~30 s. */
    const char* req_lt = getenv("AGENT_TURN_REQUEST_LIFETIME");
    if (req_lt && req_lt[0]) {
      agent->turn_alloc_lifetime = (uint32_t)atoi(req_lt);
    }
  }
  agent->turn_alloc_time = ports_get_epoch_time();
  agent->turn_perm_time = agent->turn_alloc_time;
  memcpy(&agent->turn_relay_addr, &turn_addr, sizeof(Address));
  addr_to_string(&turn_addr, addr_string, sizeof(addr_string));
  {
    uint32_t rip = (uint32_t)turn_addr.sin.sin_addr.s_addr;
    PEER_LOG_RAW("TURNTCP allocated relay %u.%u.%u.%u:%u tcp=%d\n", rip & 0xff, (rip >> 8) & 0xff,
                   (rip >> 16) & 0xff, (rip >> 24) & 0xff, turn_addr.port, (int)agent->turn_use_tcp);
  }
  LOGI("TURN relay allocated %s:%d (control=%s) lifetime=%u s", addr_string, turn_addr.port,
       agent->turn_use_tcp ? "tcp" : "udp", agent->turn_alloc_lifetime);

  {
    /* Test hook: coturn ignores the LIFETIME in Allocate (always grants its default),
     * but honors it in Refresh. Shrink the allocation immediately so expiry/refresh
     * behavior can be exercised on a 20-30 s timescale. */
    const char* req_lt = getenv("AGENT_TURN_REQUEST_LIFETIME");
    if (req_lt && req_lt[0]) {
      uint32_t want = (uint32_t)atoi(req_lt);
      if (want > 0) {
        agent->turn_alloc_lifetime = want;
        agent_turn_refresh(agent, want);
      }
    }
  }

  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_RELAY, &turn_addr);
  return 0;

fail:
#if CONFIG_TURN_TCP
  if (agent->turn_use_tcp) {
    tcp_socket_close(&agent->turn_tcp);
    agent->turn_use_tcp = 0;
  }
#endif
  return -1;
}

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential) {
  int port;
  int use_tcp = 0;
  char hostname[64];
  char addr_string[ADDRSTRLEN];
  int i;
  int addr_type[1] = {AF_INET};
  Address resolved_addr;

  if (urls == NULL) {
    /* Relay-only policy: do not gather host candidates — every packet must
     * traverse a TURN relay (ESP32 test mode / forced-relay deployments). */
    if (agent->ice_transport_policy == AGENT_ICE_POLICY_RELAY) {
      LOGI("ICE relay-only: skipping host candidate gathering");
      return;
    }
    agent_create_host_addr(agent);
    return;
  }

  if (agent_parse_ice_server_url(urls, hostname, sizeof(hostname), &port, &use_tcp) != 0) {
    LOGE("Invalid ICE server URL: %s", urls);
    return;
  }

  /* Relay-only policy: STUN yields server-reflexive (non-relay) candidates,
   * which we must not use — skip STUN servers entirely. */
  if (strncmp(urls, "stun:", 5) == 0 &&
      agent->ice_transport_policy == AGENT_ICE_POLICY_RELAY) {
    LOGI("ICE relay-only: skipping STUN server %s", urls);
    return;
  }

  /* Relay-protocol restriction: drop TURN servers whose transport does not
   * match the configured protocol (force UDP-only or TCP-only relays). */
  if (strncmp(urls, "turn:", 5) == 0) {
    if (agent->ice_relay_protocol == AGENT_ICE_RELAY_UDP && use_tcp) {
      LOGI("ICE relay UDP-only: skipping TCP TURN server %s", urls);
      return;
    }
    if (agent->ice_relay_protocol == AGENT_ICE_RELAY_TCP && !use_tcp) {
      LOGI("ICE relay TCP-only: skipping UDP TURN server %s", urls);
      return;
    }
  }

  for (i = 0; i < (int)(sizeof(addr_type) / sizeof(addr_type[0])); i++) {
    if (ports_resolve_addr(hostname, &resolved_addr) != 0) {
      continue;
    }
    addr_set_port(&resolved_addr, port);
    addr_to_string(&resolved_addr, addr_string, sizeof(addr_string));
    LOGI("Resolved ICE server %s:%d tcp=%d", addr_string, port, use_tcp);

    if (strncmp(urls, "stun:", 5) == 0) {
      agent_create_stun_addr(agent, &resolved_addr);
    } else if (strncmp(urls, "turn:", 5) == 0) {
      agent_create_turn_addr(agent, &resolved_addr, username, credential, use_tcp);
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
#if LIBPEER_FAULT_INJECT
  if (agent_fault_drop_udp_media(agent)) {
    return len; /* pretend the send succeeded; the packet is silently dropped */
  }
#endif
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
      int _valid = (stun_msg_is_valid(stun_msg->buf, stun_msg->size, (char*)req_pwd) == 0);
      if (!agent->selected_pair) {
        PEER_LOG_RAW("STUNREQ valid=%d uc=%d turn=%d user=%s\n", _valid,
                       (int)stun_msg->use_candidate, (int)agent->turn_allocated,
                       stun_msg->username[0] ? stun_msg->username : "(none)");
      }
      if (_valid) {
        char req_from[ADDRSTRLEN];
        const int settled = agent_inbound_from_selected_pair(agent, addr);
        addr_to_string(addr, req_from, sizeof(req_from));
        if (!settled) {
          LOGI("ICE STUN Binding request from %s:%d", req_from, addr->port);
        } else {
          LOGD("ICE STUN Binding keepalive from %s:%d", req_from, addr->port);
        }
        header = (StunHeader*)stun_msg->buf;
        memcpy(agent->transaction_id, header->transaction_id, sizeof(header->transaction_id));
        if (!settled) {
          agent_note_inbound_binding(agent, addr);
        }
        pair = agent_find_pair_for_addr(agent, addr);
        if (stun_msg->use_candidate && pair) {
          pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
          agent->nominated_pair = pair;
          agent->selected_pair = pair;
          if (!agent->remote_nominated) {
            uint32_t nip = (uint32_t)addr->sin.sin_addr.s_addr;
            PEER_LOG_RAW("ICEUSECAND remote=%u.%u.%u.%u:%u lt=%d rt=%d\n",
                           nip & 0xff, (nip >> 8) & 0xff, (nip >> 16) & 0xff,
                           (nip >> 24) & 0xff, addr->port,
                           pair->local ? (int)pair->local->type : -1,
                           pair->remote ? (int)pair->remote->type : -1);
          }
          agent->remote_nominated = 1;
          if (!settled) {
            LOGI("ICE nominated by remote USE-CANDIDATE");
          }
        }
        agent_create_binding_response(agent, &msg, addr);
        if (agent->turn_allocated) {
          agent_turn_send(agent, addr, msg.buf, msg.size);
        } else {
          agent_socket_send(agent, addr, msg.buf, msg.size);
        }
        if (!settled) {
          LOGI("ICE STUN Binding response sent to %s:%d (%u B)", req_from, addr->port, (unsigned)msg.size);
        }
        agent->binding_request_time = ports_get_epoch_time();
      } else {
        char req_from[ADDRSTRLEN];
        addr_to_string(addr, req_from, sizeof(req_from));
        LOGW("ICE Binding request auth failed from %s:%d", req_from, addr->port);
      }
      break;
    default:
      break;
  }
}

void agent_process_stun_response(Agent* agent, StunMessage* stun_msg) {
  agent_turn_cb_try_finish_from_response(agent, stun_msg);
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
      if ((stun_msg->stunmethod == STUN_METHOD_SEND || stun_msg->stunmethod == STUN_METHOD_DATA) &&
          stun_msg->data_len > 0) {
        char peer_str[ADDRSTRLEN];
        addr_to_string(&stun_msg->peer_addr, peer_str, sizeof(peer_str));
        LOGI("TURN %s indication %d B from peer %s:%d", stun_msg->stunmethod == STUN_METHOD_DATA ? "Data" : "Send",
             stun_msg->data_len, peer_str, stun_msg->peer_addr.port);
        if (stun_probe(stun_msg->data, (size_t)stun_msg->data_len) == 0) {
          StunMessage inner;
          memset(&inner, 0, sizeof(inner));
          memcpy(inner.buf, stun_msg->data, (size_t)stun_msg->data_len);
          inner.size = (size_t)stun_msg->data_len;
          stun_parse_msg_buf(&inner);
          agent_process_inbound_stun(agent, &inner, &stun_msg->peer_addr);
        } else if (agent->media_out && agent->media_out_len == 0 &&
                   stun_msg->data_len <= agent->media_out_cap) {
          /* Relayed application media carried in a Data indication. */
          memcpy(agent->media_out, stun_msg->data, (size_t)stun_msg->data_len);
          agent->media_out_len = stun_msg->data_len;
          LOGD("TURN Data indication %d B media -> app", stun_msg->data_len);
        } else if (agent_media_stash(agent, stun_msg->data, stun_msg->data_len) == 0) {
          LOGD("TURN Data indication %d B media stashed (no app buffer)", stun_msg->data_len);
        } else {
          LOGW("TURN indication media dropped (%d bytes, no app buffer/overflow)", stun_msg->data_len);
        }
      }
      break;
    default:
      break;
  }
}

static int agent_turn_tcp_poll_recv(Agent* agent, StunMessage* stun_msg) {
  fd_set rfds;
  struct timeval tv;
  int ret;
  int is_channel = 0;
  uint16_t channel = 0;
  int got = 0;
  /* Frames on the TURN-TCP stream can be ChannelData carrying a full relay
   * datagram (e.g. a ~760 B DTLS handshake flight with our certificate), which
   * is far larger than a STUN control message. Read into a datagram-sized buffer:
   * StunMessage.buf is only STUN_ATTR_BUF_SIZE (512) B, so reading directly into
   * it made stun_tcp_recv_turn_frame() reject any larger frame (total > bufsize),
   * silently dropping the relayed DTLS flight and stalling the handshake over the
   * TCP relay (no video). Uses the off-stack agent->turn_chan_frame (see agent.h)
   * to avoid a 1.4 KB stack array on the loop/recv path. */
  uint8_t* frame = agent->turn_chan_frame;
  const int frame_cap = (int)sizeof(agent->turn_chan_frame);

  if (!agent->turn_use_tcp || agent->turn_tcp.fd < 0) {
    return 0;
  }
  /* Drain any partially-written outbound frame first. tcp_socket_send() never
   * blocks: under TX backpressure it stashes a frame's unsent tail and returns,
   * so the tail must be pushed out as the socket drains. This runs in the ICE
   * loop's TURN drain (under c->mu), exactly when the kernel TX buffer is freeing
   * up, keeping the ChannelData stream byte-aligned without ever blocking. */
  (void)tcp_socket_tx_flush(&agent->turn_tcp);
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(agent->turn_tcp.fd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (select(agent->turn_tcp.fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
      break;
    }
    ret = stun_tcp_recv_turn_frame(&agent->turn_tcp, frame, frame_cap, &is_channel, &channel);
    if (ret <= 0) {
      break;
    }
    got = 1;
    if (is_channel) {
      int plen = (int)(((uint16_t)frame[2] << 8) | frame[3]);
      if (!agent->selected_pair) {
        int looks_stun = (plen >= 8 && stun_probe(frame + 4, (size_t)plen) == 0) ? 1 : 0;
        PEER_LOG_RAW("TCPRX ch=0x%04x plen=%d stun=%d\n", channel, plen, looks_stun);
      }
      agent_turn_process_channel_payload(agent, channel, frame + 4, plen);
      /* media_out holds ONE relayed payload. Several ChannelData frames (e.g.
       * batched RTCP — RR/REMB/NACK) routinely arrive in a single TCP segment;
       * if we kept reading, the next frame would be dropped at "no app buffer /
       * overflow", starving inbound RTCP and tripping a false media stall. Hand
       * this payload back now — the remaining frames stay in the TCP stream and
       * are picked up by the caller's next poll (peer_connection COMPLETED drains
       * in a loop). STUN control frames carry no media, so keep draining those. */
      if (agent->media_out && agent->media_out_len > 0) {
        break;
      }
      continue;
    }
    /* STUN control message: parse out of the (512 B) StunMessage buffer. */
    if (!agent->selected_pair) {
      PEER_LOG_RAW("TCPRX stun ret=%d\n", ret);
    }
    if (ret > (int)sizeof(stun_msg->buf)) {
      continue;
    }
    memcpy(stun_msg->buf, frame, (size_t)ret);
    stun_msg->size = (size_t)ret;
    stun_parse_msg_buf(stun_msg);
    agent_turn_dispatch_stun_msg(agent, stun_msg, &stun_msg->peer_addr);
  }
  return got;
}

static void agent_turn_tcp_drain_media(Agent* agent, int wait_ms) {
  StunMessage stun_msg;
  /* Wall-clock bound (see agent_turn_wait_response): the old elapsed counter only
   * advanced on the idle branch, so a steady TCP relay stream could spin here
   * forever and starve the system. */
  uint32_t start = (uint32_t)ports_get_epoch_time();
  /* wait_ms is a MAX, not a fixed dwell. Stop early once the relay has been idle
   * for a short grace period: spinning out the full 120-200 ms on every empty
   * poll made each peer_connection_loop() pass take ~320 ms, which starved the
   * connected state (slow to answer connectivity checks / RTCP -> browser
   * re-offers). A frame that lands just after we bail is still picked up on the
   * next loop iteration (the main loop polls this socket every pass), and the
   * idle counter resets whenever data arrives so active bursts still drain. */
  const int idle_break_ms = 30;
  int idle_ms = 0;

  if (!agent->turn_use_tcp || agent->turn_tcp.fd < 0 || wait_ms <= 0) {
    return;
  }
  memset(&stun_msg, 0, sizeof(stun_msg));
  while ((uint32_t)((uint32_t)ports_get_epoch_time() - start) < (uint32_t)wait_ms) {
    if (agent->nominated_pair && agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      break;
    }
    if (agent_turn_tcp_poll_recv(agent, &stun_msg)) {
      idle_ms = 0;
      memset(&stun_msg, 0, sizeof(stun_msg));
      continue;
    }
    if (idle_ms >= idle_break_ms) {
      break;
    }
    ports_sleep_ms(10);
    idle_ms += 10;
  }
}

int agent_recv(Agent* agent, uint8_t* buf, int len) {
  int ret = -1;
  StunMessage stun_msg;
  Address addr;

  if (agent->turn_pending_media_len > 0 && len >= agent->turn_pending_media_len) {
    memmove(buf, agent->turn_pending_media, (size_t)agent->turn_pending_media_len);
    ret = agent->turn_pending_media_len;
    agent->turn_pending_media_len = 0;
    goto done;
  }

  /* Expose the caller buffer to the TURN receive path so relayed non-STUN media
   * (ChannelData / Data indication) can be delivered back to the application. */
  agent->media_out = buf;
  agent->media_out_cap = len;
  agent->media_out_len = 0;

  /* Keep the TURN allocation / permissions / channels alive on long sessions. The
   * refresh path drains the control socket and may surface relayed media into buf. */
  PCL(300);
  agent_turn_refresh_maybe(agent);
  if (agent->media_out_len > 0) {
    ret = agent->media_out_len;
    goto done;
  }

  PCL(301);
  memset(&stun_msg, 0, sizeof(stun_msg));
  while (agent_turn_tcp_poll_recv(agent, &stun_msg)) {
    PCL(302);
    if (agent->media_out_len > 0) {
      ret = agent->media_out_len;
      goto done;
    }
    memset(&stun_msg, 0, sizeof(stun_msg));
  }
  PCL(303);
  /* Note: do NOT early-return when our pair is SUCCEEDED. We must keep reading the
   * socket to (a) respond to the peer's ongoing connectivity checks so its side can
   * complete ICE, and (b) deliver media to the caller (peer_connection COMPLETED). */
  PCL(304);
  if ((ret = agent_socket_recv(agent, &addr, buf, len)) > 0) {
    PCL(305);
    if (agent_turn_process_udp_datagram(agent, &addr, buf, ret)) {
      ret = agent->media_out_len; /* >0 if relayed media was delivered into buf */
      goto done;
    }
    if (stun_probe(buf, (size_t)len) == 0) {
      memset(&stun_msg, 0, sizeof(stun_msg));
      memcpy(stun_msg.buf, buf, (size_t)ret);
      stun_msg.size = (size_t)ret;
      stun_parse_msg_buf(&stun_msg);
      if (agent->turn_allocated && agent_addr_is_turn_server(agent, &addr)) {
        agent_turn_dispatch_stun_msg(agent, &stun_msg, &addr);
      } else {
        agent_process_inbound_stun(agent, &stun_msg, &addr);
      }
      ret = 0;
    }
    /* else: a direct (non-relay) media datagram is already in buf; return its length. */
  }

done:
  agent->media_out = NULL;
  agent->media_out_cap = 0;
#if LIBPEER_FAULT_INJECT
  /* Drop inbound media/RTCP (STUN was already handled above and set ret=0, so
   * consent keeps flowing). Mimics the bidirectional UDP throttle. */
  if (ret > 0 && agent_fault_drop_udp_media(agent)) {
    ret = 0;
  }
#endif
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
  agent->remote_nominated = 0;
  agent->controlled_nom_deadline = 0;
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

void agent_pump(Agent* agent, int rounds) {
  uint8_t buf[1400];
  int i;

  if (!agent || rounds <= 0) {
    return;
  }
  for (i = 0; i < rounds; i++) {
    memset(buf, 0, sizeof(buf));
    agent_recv(agent, buf, (int)sizeof(buf));
    agent_turn_drain_udp(agent);
    if (agent->nominated_pair && agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      agent->selected_pair = agent->nominated_pair;
    }
  }
}

void agent_log_ice_progress(const Agent* agent, const char* tag) {
  char la[ADDRSTRLEN];
  char ra[ADDRSTRLEN];
  const IceCandidatePair* p;
  int ch = 0;

  if (!agent) {
    return;
  }
  p = agent->nominated_pair;
  if (!p || !p->local || !p->remote) {
    LOGI("ICE progress (%s): no nominated pair (pairs=%d turn=%d)", tag ? tag : "?", agent->candidate_pairs_num,
         agent->turn_allocated);
    return;
  }
  addr_to_string(&p->local->addr, la, sizeof(la));
  addr_to_string(&p->remote->addr, ra, sizeof(ra));
  for (int i = 0; i < agent->turn_channels_count; i++) {
    if (agent->turn_channels[i].bound) {
      ch++;
    }
  }
  LOGI(
      "ICE progress (%s): pair_state=%d conncheck=%d/%d local=%s:%d remote=%s:%d turn=%d ch_bound=%d/%d "
      "mode=%s",
      tag ? tag : "?",
      (int)p->state,
      p->conncheck,
      AGENT_CONNCHECK_MAX,
      la,
      p->local->addr.port,
      ra,
      p->remote->addr.port,
      agent->turn_allocated,
      ch,
      agent->turn_channels_count,
      agent->mode == AGENT_MODE_CONTROLLING ? "ctrl" : "controlled");
}

/* Consent freshness (RFC 7675). After a pair succeeds, keep sending Binding requests
 * to the peer at a low rate so its own check can still complete — important over a
 * relay, where the peer may drop our first packets until it installs its permission. */
#define AGENT_CONSENT_PERIOD 8
static void agent_connectivity_consent_keepalive(Agent* agent, IceCandidatePair* pair) {
  StunMessage msg;

  if (!pair || !pair->remote) {
    return;
  }
  if ((agent->consent_ticks++ % AGENT_CONSENT_PERIOD) != 0) {
    return;
  }
  memset(&msg, 0, sizeof(msg));
  agent->nominated_pair = pair;
  agent_create_binding_request(agent, &msg);
  if (agent_pair_needs_turn(pair) && agent->turn_allocated) {
    agent_turn_send(agent, &pair->remote->addr, msg.buf, msg.size);
  } else {
    agent_socket_send(agent, &pair->remote->addr, msg.buf, msg.size);
  }
}

int agent_connectivity_check(Agent* agent) {
  char addr_string[ADDRSTRLEN];
  uint8_t buf[1400];
  StunMessage msg;

  if (agent->selected_pair && agent->selected_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent_connectivity_consent_keepalive(agent, agent->selected_pair);
    return 0;
  }

  if (!agent->nominated_pair) {
    return -1;
  }

  if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent->selected_pair = agent->nominated_pair;
    agent_connectivity_consent_keepalive(agent, agent->selected_pair);
    return 0;
  }

  if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_FAILED) {
    agent_pump(agent, 48);
    if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      agent->selected_pair = agent->nominated_pair;
      LOGI("ICE pair recovered to SUCCEEDED after FAILED (late binding response)");
      return 0;
    }
    /* Keep checking — peer may have succeeded first; late responses still valid. */
    agent->nominated_pair->state = ICE_CANDIDATE_STATE_INPROGRESS;
    agent->nominated_pair->conncheck = 0;
  }

  if (agent->nominated_pair->state != ICE_CANDIDATE_STATE_INPROGRESS) {
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
      PCL(120);
      agent_turn_send(agent, &agent->nominated_pair->remote->addr, msg.buf, msg.size);
#if CONFIG_TURN_TCP
      if (agent->turn_use_tcp) {
        PCL(121);
        agent_turn_tcp_drain_media(agent, 120);
      } else
#endif
      {
        for (int u = 0; u < 20; u++) {
          PCL(122);
          agent_turn_drain_udp(agent);
          if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
            break;
          }
          ports_sleep_ms(5);
        }
      }
    } else {
      PCL(123);
      agent_socket_send(agent, &agent->nominated_pair->remote->addr, msg.buf, msg.size);
    }
  }

  for (int drain = 0; drain < 16; drain++) {
    PCL(124);
    agent_recv(agent, buf, sizeof(buf));
    PCL(125);
    agent_turn_drain_udp(agent);
    if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      break;
    }
  }
  PCL(126);

  if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent->selected_pair = agent->nominated_pair;
    return 0;
  }

  agent->nominated_pair->conncheck++;
  if (agent->nominated_pair->conncheck >= AGENT_CONNCHECK_MAX) {
    LOGW("ICE pair conncheck budget exhausted (%d)", agent->nominated_pair->conncheck);
    if (agent->turn_allocated) {
#if CONFIG_TURN_TCP
      if (agent->turn_use_tcp) {
        agent_turn_tcp_drain_media(agent, 150);
      }
#endif
      agent_pump(agent, 16);
    }
    if (agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      agent->selected_pair = agent->nominated_pair;
      LOGI("ICE pair succeeded on final drain before FAILED");
      return 0;
    }
    agent->nominated_pair->state = ICE_CANDIDATE_STATE_FAILED;
  }

  return -1;
}

int agent_ready_to_finalize(Agent* agent) {
  if (!agent) {
    return 1;
  }
  if (agent->mode == AGENT_MODE_CONTROLLING) {
    return 1;
  }
  if (agent->remote_nominated) {
    return 1;
  }
  /* Controlled and the peer has not nominated yet: hold off committing so we
   * don't latch a pair (e.g. the fast host<->host one) the peer will abandon.
   * Arm a grace deadline so a peer that never trickles USE-CANDIDATE still
   * connects on our own self-selected pair. */
  uint32_t now = (uint32_t)ports_get_epoch_time();
  if (agent->controlled_nom_deadline == 0) {
    agent->controlled_nom_deadline = now + AGENT_CONTROLLED_NOM_WAIT_MS;
    return 0;
  }
  return (int32_t)(now - agent->controlled_nom_deadline) >= 0;
}

int agent_select_candidate_pair(Agent* agent) {
  int i;
  int best = -1;
  int best_rank = -1;

  /* Once the controlling peer has nominated a pair (USE-CANDIDATE), a controlled
   * agent must use exactly that pair — re-ranking here could pick a different
   * (e.g. relay-preferred) pair than the one the peer actually sends media on,
   * which strands the DTLS handshake. */
  if (agent->mode == AGENT_MODE_CONTROLLED && agent->remote_nominated &&
      agent->nominated_pair &&
      agent->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) {
    agent->selected_pair = agent->nominated_pair;
    return 0;
  }

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
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS ||
        agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FAILED) {
      agent->nominated_pair = &agent->candidate_pairs[i];
      return 0;
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
