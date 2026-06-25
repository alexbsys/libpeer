#pragma once

#include <string>

struct TurnEnv {
  std::string turn_url_udp;
  std::string turn_url_tcp;
  std::string username;
  std::string password;
  bool ok;
};

TurnEnv load_turn_env();

/** Returns true if UDP port accepts a datagram (coturn likely up). */
bool turn_server_udp_reachable(const TurnEnv& env);
