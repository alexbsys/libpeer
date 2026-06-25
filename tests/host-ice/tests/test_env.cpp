#include "test_env.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static const char* env_or(const char* key, const char* def) {
  const char* v = std::getenv(key);
  return (v && v[0]) ? v : def;
}

TurnEnv load_turn_env() {
  TurnEnv e{};
  const char* host = env_or("TURN_HOST", "127.0.0.1");
  const char* port = env_or("TURN_PORT", "3480");
  e.username = env_or("TURN_USER", "testuser");
  e.password = env_or("TURN_PASS", "testpass");

  char udp_buf[256];
  char tcp_buf[256];
  std::snprintf(udp_buf, sizeof(udp_buf), "turn:%s:%s", host, port);
  std::snprintf(tcp_buf, sizeof(tcp_buf), "turn:%s:%s?transport=tcp", host, port);
  e.turn_url_udp = udp_buf;
  e.turn_url_tcp = tcp_buf;

  e.ok = !e.username.empty() && !e.password.empty();
  return e;
}

bool turn_server_udp_reachable(const TurnEnv& env) {
  const char* host = std::getenv("TURN_HOST");
  const char* port = std::getenv("TURN_PORT");
  if (!host || !host[0]) {
    host = "127.0.0.1";
  }
  if (!port || !port[0]) {
    port = "3480";
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  if (fd <= 2) {
    int dupfd = fcntl(fd, F_DUPFD, 3);
    if (dupfd >= 0) {
      close(fd);
      fd = dupfd;
    }
  }

  struct sockaddr_in sa {};
  sa.sin_family = AF_INET;
  sa.sin_port = htons((uint16_t)atoi(port));
  if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
    close(fd);
    return false;
  }

  const uint8_t probe[20] = {0};
  const ssize_t sent = sendto(fd, probe, sizeof(probe), 0, (struct sockaddr*)&sa, sizeof(sa));
  close(fd);
  return sent == (ssize_t)sizeof(probe);
}

namespace {

class CoturnWarmupEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    TurnEnv env = load_turn_env();
    if (!env.ok || !turn_server_udp_reachable(env)) {
      return;
    }
    fprintf(stderr, "[ice-test] coturn warmup 500ms (TURN_PORT=%s)\n",
            std::getenv("TURN_PORT") ? std::getenv("TURN_PORT") : "3480");
    usleep(500000);
  }
};

const int kRegisterWarmup = []() {
  ::testing::AddGlobalTestEnvironment(new CoturnWarmupEnvironment());
  return 0;
}();

}  // namespace
