#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

extern "C" {
#include "agent.h"
#include "ice.h"
}

#include "test_env.h"

static bool line_is_relay(const char* line) {
  return line && strstr(line, " typ relay ") != nullptr;
}

static void gather_turn_relay(Agent* agent, const char* url, const char* user, const char* pass) {
  agent_gather_candidate(agent, url, user, pass);
}

static int relay_count(const Agent* a) {
  int n = 0;
  for (int i = 0; i < a->local_candidates_count; ++i) {
    if (a->local_candidates[i].type == ICE_CANDIDATE_TYPE_RELAY) {
      n++;
    }
  }
  return n;
}

static void exchange_relay_candidates(Agent* a, Agent* b) {
  char desc[4096];
  for (int round = 0; round < 2; ++round) {
    Agent* src = (round == 0) ? a : b;
    Agent* dst = (round == 0) ? b : a;
    memset(desc, 0, sizeof(desc));
    agent_get_local_description(src, desc, (int)sizeof(desc));
    char* save = nullptr;
    char* line = strtok_r(desc, "\r\n", &save);
    for (; line != nullptr; line = strtok_r(nullptr, "\r\n", &save)) {
      if (line[0] == '\0' || !line_is_relay(line)) {
        continue;
      }
      char cand[512];
      snprintf(cand, sizeof(cand), "a=%s", line);
      if (ice_candidate_from_description(&dst->remote_candidates[dst->remote_candidates_count], cand,
                                         cand + strlen(cand)) == 0) {
        dst->remote_candidates_count++;
      }
    }
  }
}

static int agent_succeeded_bit(const Agent* a) {
  return (a->nominated_pair && a->nominated_pair->state == ICE_CANDIDATE_STATE_SUCCEEDED) ? 1 : 0;
}

/* Forward decl (full ICE loop defined below). */
static int run_relay_connectivity_loop(Agent* a, Agent* b, const char* tag, int max_iters, int sleep_us,
                                       int recovery_iters);

/** Establish a relay-only ICE pair over `url`. Returns the success bitmask (3 == both). */
static int establish_relay_pair(Agent* a, Agent* b, const char* url, const char* user, const char* pass,
                                const char* tag) {
  gather_turn_relay(a, url, user, pass);
  gather_turn_relay(b, url, user, pass);
  if (relay_count(a) < 1 || relay_count(b) < 1) {
    return 0;
  }
  exchange_relay_candidates(a, b);
  agent_update_candidate_pairs(a);
  agent_update_candidate_pairs(b);
  return run_relay_connectivity_loop(a, b, tag, 600, 12000, 300);
}

/** Send one application payload src->dst over the relay and confirm dst receives it.
 *  Retries because the first relay packets may be dropped until permissions settle, and
 *  keeps both agents serviced (consent keepalive + TURN refresh) while waiting. */
static bool relay_deliver(Agent* src, Agent* dst, const char* tag, int timeout_ms) {
  static const char kMsg[] = "LIBPEER-RELAY-MEDIA-TEST-PAYLOAD-0123456789-abcdef";
  const int plen = (int)sizeof(kMsg) - 1;
  uint8_t rbuf[1500];
  int waited = 0;

  while (waited < timeout_ms) {
    agent_send(src, (const uint8_t*)kMsg, plen);
    for (int k = 0; k < 12; ++k) {
      int r = agent_recv(dst, rbuf, (int)sizeof(rbuf));
      if (r == plen && memcmp(rbuf, kMsg, (size_t)plen) == 0) {
        fprintf(stderr, "[ice-test] %s media delivered after %d ms\n", tag, waited);
        return true;
      }
    }
    agent_recv(src, rbuf, (int)sizeof(rbuf)); /* service ACKs / keepalives on the sender */
    usleep(50000);
    waited += 50;
  }
  fprintf(stderr, "[ice-test] %s media NOT delivered within %d ms\n", tag, timeout_ms);
  return false;
}

/** Run ICE connectivity loop with pumps and progress logs. Returns bitmask: 1=A, 2=B. */
static int run_relay_connectivity_loop(Agent* a, Agent* b, const char* tag, int max_iters, int sleep_us,
                                       int recovery_iters) {
  int succeeded = 0;
  const int progress_step = 40;

  fprintf(stderr, "[ice-test] %s start max_iters=%d recovery=%d sleep_us=%d\n", tag, max_iters,
          recovery_iters, sleep_us);

  for (int i = 0; i < max_iters; ++i) {
    if (agent_select_candidate_pair(a) == 0) {
      agent_connectivity_check(a);
    }
    if (agent_select_candidate_pair(b) == 0) {
      agent_connectivity_check(b);
    }
    agent_pump(a, 6);
    agent_pump(b, 6);

    succeeded = agent_succeeded_bit(a) | (agent_succeeded_bit(b) << 1);
    if (succeeded == 3) {
      fprintf(stderr, "[ice-test] %s OK at iter=%d\n", tag, i);
      return succeeded;
    }

    if (i % progress_step == 0) {
      agent_log_ice_progress(a, tag);
      agent_log_ice_progress(b, tag);
      fprintf(stderr, "[ice-test] %s iter=%d/%d succeeded=0x%x\n", tag, i, max_iters, succeeded);
    }
    if (i == 120 && succeeded == 0) {
      fprintf(stderr,
              "[ice-test] %s WARNING: no ICE success by iter 120 — check coturn on TURN_PORT "
              "(allow-loopback-peers, single instance)\n",
              tag);
    }
    usleep((useconds_t)sleep_us);
  }

  if (succeeded == 1 || succeeded == 2) {
    Agent* lag = (succeeded & 1) ? b : a;
    Agent* up = (succeeded & 1) ? a : b;
    fprintf(stderr, "[ice-test] %s one-sided OK (0x%x) — extra pump on lagging agent\n", tag, succeeded);
    for (int k = 0; k < 200; ++k) {
      agent_pump(lag, 16);
      agent_pump(up, 4);
      if (agent_select_candidate_pair(lag) == 0) {
        agent_connectivity_check(lag);
      }
      succeeded = agent_succeeded_bit(a) | (agent_succeeded_bit(b) << 1);
      if (succeeded == 3) {
        fprintf(stderr, "[ice-test] %s OK after one-sided recovery at %d\n", tag, k);
        return succeeded;
      }
      usleep(5000);
    }
  }

  fprintf(stderr, "[ice-test] %s recovery phase (%d iters)\n", tag, recovery_iters);
  for (int i = 0; i < recovery_iters; ++i) {
    agent_pump(a, 12);
    agent_pump(b, 12);
    if (agent_select_candidate_pair(a) == 0) {
      agent_connectivity_check(a);
    }
    if (agent_select_candidate_pair(b) == 0) {
      agent_connectivity_check(b);
    }
    succeeded = agent_succeeded_bit(a) | (agent_succeeded_bit(b) << 1);
    if (succeeded == 3) {
      fprintf(stderr, "[ice-test] %s OK in recovery at %d\n", tag, i);
      return succeeded;
    }
    usleep((useconds_t)sleep_us);
  }

  fprintf(stderr, "[ice-test] %s FAIL succeeded=0x%x\n", tag, succeeded);
  return succeeded;
}

class IceRelayPair : public ::testing::Test {
 protected:
  void SetUp() override {
    env_ = load_turn_env();
    if (!env_.ok) {
      GTEST_SKIP() << "TURN env not configured";
    }
    if (!turn_server_udp_reachable(env_)) {
      GTEST_SKIP() << "TURN server not reachable on UDP (start coturn on TURN_PORT, see run_tests.sh)";
    }
    /* Coturn relay thread may need a moment after process start. */
    usleep(300000);
    ASSERT_EQ(agent_create(&a_), 0);
    ASSERT_EQ(agent_create(&b_), 0);
    /* Loopback: both sides send USE-CANDIDATE so each can complete on inbound Binding
     * (gives both directions an independent path to completion over the relay). */
    a_.mode = AGENT_MODE_CONTROLLING;
    b_.mode = AGENT_MODE_CONTROLLING;
    agent_create_ice_credential(&a_);
    agent_create_ice_credential(&b_);
    snprintf(a_.remote_ufrag, sizeof(a_.remote_ufrag), "%s", b_.local_ufrag);
    snprintf(a_.remote_upwd, sizeof(a_.remote_upwd), "%s", b_.local_upwd);
    snprintf(b_.remote_ufrag, sizeof(b_.remote_ufrag), "%s", a_.local_ufrag);
    snprintf(b_.remote_upwd, sizeof(b_.remote_upwd), "%s", a_.local_upwd);
  }
  void TearDown() override {
    agent_destroy(&a_);
    agent_destroy(&b_);
    /* Let coturn reap closed relay sessions before the next test method. */
    usleep(500000);
  }

  TurnEnv env_;
  Agent a_{};
  Agent b_{};
};

TEST_F(IceRelayPair, UdpTurnRelayPairConnectivity) {
  gather_turn_relay(&a_, env_.turn_url_udp.c_str(), env_.username.c_str(), env_.password.c_str());
  gather_turn_relay(&b_, env_.turn_url_udp.c_str(), env_.username.c_str(), env_.password.c_str());
  ASSERT_GE(relay_count(&a_), 1);
  ASSERT_GE(relay_count(&b_), 1);

  exchange_relay_candidates(&a_, &b_);
  agent_update_candidate_pairs(&a_);
  agent_update_candidate_pairs(&b_);

  const int succeeded = run_relay_connectivity_loop(&a_, &b_, "udp-relay", 600, 12000, 300);
  if (succeeded != 3) {
    agent_log_ice_diagnostics(&a_, "IceRelayPair.UdpTurnRelayPairConnectivity");
    agent_log_ice_diagnostics(&b_, "IceRelayPair.UdpTurnRelayPairConnectivity");
  }
  EXPECT_EQ(succeeded, 3) << "both agents should complete ICE over relay (UDP TURN control)";
}

TEST_F(IceRelayPair, TcpRelayPairConnectivity) {
  gather_turn_relay(&a_, env_.turn_url_tcp.c_str(), env_.username.c_str(), env_.password.c_str());
  gather_turn_relay(&b_, env_.turn_url_tcp.c_str(), env_.username.c_str(), env_.password.c_str());
  ASSERT_GE(relay_count(&a_), 1);
  ASSERT_GE(relay_count(&b_), 1);

  exchange_relay_candidates(&a_, &b_);
  agent_update_candidate_pairs(&a_);
  agent_update_candidate_pairs(&b_);

  const int succeeded = run_relay_connectivity_loop(&a_, &b_, "tcp-relay", 600, 12000, 300);
  if (succeeded != 3) {
    agent_log_ice_diagnostics(&a_, "IceRelayPair.TcpRelayPairConnectivity");
    agent_log_ice_diagnostics(&b_, "IceRelayPair.TcpRelayPairConnectivity");
  }
  EXPECT_EQ(succeeded, 3) << "both agents should complete ICE over relay";
}

/** Repeated TCP+UDP runs in one process — catches coturn/session races. */
TEST_F(IceRelayPair, RelayConnectivityStress) {
  const char* rounds_env = std::getenv("ICE_STRESS_ROUNDS");
  int rounds = rounds_env ? atoi(rounds_env) : 10;
  if (rounds < 1) {
    rounds = 1;
  }
  if (rounds > 20) {
    rounds = 20;
  }

  fprintf(stderr, "[ice-test] stress rounds=%d\n", rounds);

  for (int r = 0; r < rounds; ++r) {
    char tag[64];
    if (r > 0) {
      agent_clear_candidates(&a_);
      agent_clear_candidates(&b_);
      usleep(500000);
    }
    a_.mode = AGENT_MODE_CONTROLLING;
    b_.mode = AGENT_MODE_CONTROLLING;

    snprintf(tag, sizeof(tag), "stress-r%d-udp", r);
    gather_turn_relay(&a_, env_.turn_url_udp.c_str(), env_.username.c_str(), env_.password.c_str());
    gather_turn_relay(&b_, env_.turn_url_udp.c_str(), env_.username.c_str(), env_.password.c_str());
    ASSERT_GE(relay_count(&a_), 1) << "round " << r << " UDP gather A";
    ASSERT_GE(relay_count(&b_), 1) << "round " << r << " UDP gather B";
    exchange_relay_candidates(&a_, &b_);
    agent_update_candidate_pairs(&a_);
    agent_update_candidate_pairs(&b_);
    int     ok = run_relay_connectivity_loop(&a_, &b_, tag, 600, 12000, 300);
    ASSERT_EQ(ok, 3) << "UDP stress round " << r;
    usleep(800000);

    agent_clear_candidates(&a_);
    agent_clear_candidates(&b_);
    usleep(500000);
    a_.mode = AGENT_MODE_CONTROLLING;
    b_.mode = AGENT_MODE_CONTROLLING;

    snprintf(tag, sizeof(tag), "stress-r%d-tcp", r);
    gather_turn_relay(&a_, env_.turn_url_tcp.c_str(), env_.username.c_str(), env_.password.c_str());
    gather_turn_relay(&b_, env_.turn_url_tcp.c_str(), env_.username.c_str(), env_.password.c_str());
    ASSERT_GE(relay_count(&a_), 1) << "round " << r << " TCP gather A";
    ASSERT_GE(relay_count(&b_), 1) << "round " << r << " TCP gather B";
    exchange_relay_candidates(&a_, &b_);
    agent_update_candidate_pairs(&a_);
    agent_update_candidate_pairs(&b_);
    ok = run_relay_connectivity_loop(&a_, &b_, tag, 600, 12000, 300);
    ASSERT_EQ(ok, 3) << "TCP stress round " << r;
    usleep(800000);
  }
}

/* ---------------------------------------------------------------------------
 * Media forwarding over the relay
 * Establish ICE over TURN, then push application payloads both directions and
 * verify each side receives them via agent_recv (ChannelData/Data-indication).
 * ------------------------------------------------------------------------- */

TEST_F(IceRelayPair, RelayMediaForwardingUdp) {
  ASSERT_EQ(establish_relay_pair(&a_, &b_, env_.turn_url_udp.c_str(), env_.username.c_str(),
                                 env_.password.c_str(), "media-udp"),
            3)
      << "ICE over UDP relay must complete before media test";
  EXPECT_TRUE(relay_deliver(&a_, &b_, "media-udp A->B", 5000)) << "A->B relayed media";
  EXPECT_TRUE(relay_deliver(&b_, &a_, "media-udp B->A", 5000)) << "B->A relayed media";
}

TEST_F(IceRelayPair, RelayMediaForwardingTcp) {
  ASSERT_EQ(establish_relay_pair(&a_, &b_, env_.turn_url_tcp.c_str(), env_.username.c_str(),
                                 env_.password.c_str(), "media-tcp"),
            3)
      << "ICE over TCP relay must complete before media test";
  EXPECT_TRUE(relay_deliver(&a_, &b_, "media-tcp A->B", 5000)) << "A->B relayed media";
  EXPECT_TRUE(relay_deliver(&b_, &a_, "media-tcp B->A", 5000)) << "B->A relayed media";
}

/* ---------------------------------------------------------------------------
 * TURN refresh / expiry
 *
 * coturn enforces a ~600 s minimum on the *allocation* lifetime (it ignores a
 * smaller requested LIFETIME), so a sub-minute allocation-expiry case is not
 * possible against coturn. The relay sub-resource that actually governs media
 * delivery on a short timescale is the channel binding / permission, whose
 * lifetimes coturn *does* honor (--channel-lifetime / --permission-lifetime).
 *
 * These tests therefore use a short channel/permission lifetime:
 *   positive = periodic refresh re-binds the channel/permission and media keeps
 *              flowing past the lifetime (also exercises stale-nonce 438 recovery
 *              since coturn --stale-nonce is short);
 *   negative = with refresh disabled the binding/permission expires and the
 *              relay stops delivering media.
 *
 * run_tests.sh starts a coturn with a short channel/permission lifetime and
 * exports TURN_SHORT_LIFETIME with that value; without it the tests are skipped.
 * ------------------------------------------------------------------------- */

static int short_lifetime_or_skip() {
  const char* lt = std::getenv("TURN_SHORT_LIFETIME");
  return (lt && lt[0]) ? atoi(lt) : 0;
}

/* Pump both agents for `seconds`, servicing sockets (and, when enabled, refreshing
 * the TURN allocation / channel binds through agent_recv). */
static void pump_both_for(Agent* a, Agent* b, int seconds) {
  const int ticks = seconds * 10;
  for (int t = 0; t < ticks; ++t) {
    agent_pump(a, 2);
    agent_pump(b, 2);
    usleep(100000);
  }
}

/* Positive: with periodic refresh enabled, the channel binding / permission is
 * re-issued before it expires, so relayed media keeps flowing past the lifetime.
 * Also exercises the allocation Refresh path and stale-nonce (438) recovery. */
TEST_F(IceRelayPair, RelayRefreshKeepsRelayAlive) {
  const int lifetime = short_lifetime_or_skip();
  if (lifetime <= 0) {
    GTEST_SKIP() << "needs short-lived coturn (set TURN_SHORT_LIFETIME, see run_tests.sh)";
  }
  unsetenv("AGENT_TURN_DISABLE_REFRESH"); /* refresh ON for this case */
  /* Re-bind well inside the channel/permission lifetime, and keep the allocation
   * Refresh firing on the same short cadence (pinned via AGENT_TURN_REQUEST_LIFETIME). */
  setenv("AGENT_TURN_PERM_REFRESH_MS", std::to_string(lifetime * 1000 / 3).c_str(), 1);
  setenv("AGENT_TURN_REQUEST_LIFETIME", std::to_string(lifetime).c_str(), 1);

  ASSERT_EQ(establish_relay_pair(&a_, &b_, env_.turn_url_udp.c_str(), env_.username.c_str(),
                                 env_.password.c_str(), "refresh-pos"),
            3);
  ASSERT_TRUE(relay_deliver(&a_, &b_, "refresh-pos initial", 5000))
      << "media must work right after ICE";

  const int wait_s = lifetime + 12; /* outlive the channel/permission lifetime */
  fprintf(stderr, "[ice-test] refresh-pos waiting %d s (lifetime=%d) with refresh ON\n", wait_s, lifetime);
  pump_both_for(&a_, &b_, wait_s);

  EXPECT_TRUE(relay_deliver(&a_, &b_, "refresh-pos after-expiry-window", 6000))
      << "relay should stay alive: periodic refresh re-binds the channel/permission";

  unsetenv("AGENT_TURN_PERM_REFRESH_MS");
  unsetenv("AGENT_TURN_REQUEST_LIFETIME");
}

/* Negative: with refresh disabled, the channel binding / permission expires after
 * its lifetime and the relay stops delivering media. The receiver (b) does not send
 * during the wait, so its inbound permission/channel is not implicitly kept alive. */
TEST_F(IceRelayPair, RelayExpiresWithoutRefresh) {
  const int lifetime = short_lifetime_or_skip();
  if (lifetime <= 0) {
    GTEST_SKIP() << "needs short-lived coturn (set TURN_SHORT_LIFETIME, see run_tests.sh)";
  }
  setenv("AGENT_TURN_DISABLE_REFRESH", "1", 1); /* refresh OFF */

  const int succeeded = establish_relay_pair(&a_, &b_, env_.turn_url_udp.c_str(), env_.username.c_str(),
                                             env_.password.c_str(), "refresh-neg");
  ASSERT_EQ(succeeded, 3);
  ASSERT_TRUE(relay_deliver(&a_, &b_, "refresh-neg initial", 5000))
      << "media must work right after ICE";

  const int wait_s = lifetime + 15; /* well past the channel/permission lifetime */
  fprintf(stderr, "[ice-test] refresh-neg waiting %d s (lifetime=%d) with refresh OFF\n", wait_s, lifetime);
  pump_both_for(&a_, &b_, wait_s);

  EXPECT_FALSE(relay_deliver(&a_, &b_, "refresh-neg after-expiry", 4000))
      << "without refresh the channel/permission expires and the relay must stop";

  unsetenv("AGENT_TURN_DISABLE_REFRESH");
}
