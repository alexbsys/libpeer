#include <gtest/gtest.h>

#include <cstring>

extern "C" {
#include "agent.h"
#include "ice.h"
}

#include "test_env.h"

static int count_relay_candidates(const Agent* agent) {
  int n = 0;
  for (int i = 0; i < agent->local_candidates_count; ++i) {
    if (agent->local_candidates[i].type == ICE_CANDIDATE_TYPE_RELAY) {
      n++;
    }
  }
  return n;
}

class TurnTcpAllocate : public ::testing::Test {
 protected:
  void SetUp() override {
    env_ = load_turn_env();
    if (!env_.ok) {
      GTEST_SKIP() << "TURN env not configured";
    }
    ASSERT_EQ(agent_create(&agent_), 0);
  }
  void TearDown() override { agent_destroy(&agent_); }

  TurnEnv env_;
  Agent agent_{};
};

TEST_F(TurnTcpAllocate, UdpBaseline) {
  agent_gather_candidate(&agent_, env_.turn_url_udp.c_str(), env_.username.c_str(),
                         env_.password.c_str());
  EXPECT_GE(count_relay_candidates(&agent_), 1);
  EXPECT_TRUE(agent_.turn_allocated);
  EXPECT_EQ(agent_.turn_use_tcp, 0);
}

TEST_F(TurnTcpAllocate, TcpControl) {
  agent_gather_candidate(&agent_, env_.turn_url_tcp.c_str(), env_.username.c_str(),
                         env_.password.c_str());
  EXPECT_GE(count_relay_candidates(&agent_), 1) << "TURN/TCP Allocate failed";
  EXPECT_TRUE(agent_.turn_allocated);
  EXPECT_EQ(agent_.turn_use_tcp, 1);
  EXPECT_GE(agent_.turn_tcp.fd, 0);
}
