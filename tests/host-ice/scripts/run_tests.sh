#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
COTURN_DIR="$ROOT/docker/coturn"

export TURN_HOST="${TURN_HOST:-127.0.0.1}"
# Lab coturn on 3480 — avoids conflict with apt/system coturn on 3478/3479.
export TURN_PORT="${TURN_PORT:-3480}"
export TURN_USER="${TURN_USER:-testuser}"
export TURN_PASS="${TURN_PASS:-testpass}"

use_docker=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  use_docker=1
fi

stop_local_coturn() {
  if [ -f /tmp/libpeer-ice-turn.pid ]; then
    kill "$(cat /tmp/libpeer-ice-turn.pid)" 2>/dev/null || true
    rm -f /tmp/libpeer-ice-turn.pid
  fi
  if command -v pgrep >/dev/null 2>&1; then
    for pid in $(pgrep -f "turnserver.*listening-port=${TURN_PORT}" 2>/dev/null || true); do
      kill -9 "$pid" 2>/dev/null || true
    done
  fi
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${TURN_PORT}/tcp" "${TURN_PORT}/udp" 2>/dev/null || true
  fi
  sleep 2
}

start_local_coturn() {
  stop_local_coturn
  echo "==> Starting coturn (local turnserver on port ${TURN_PORT}) extra: $*"
  turnserver -c "$COTURN_DIR/turnserver.conf" \
    --listening-port="${TURN_PORT}" \
    --listening-ip="${TURN_HOST}" \
    --relay-ip="${TURN_HOST}" \
    --allow-loopback-peers \
    --relay-threads=1 \
    "$@" \
    --pidfile=/tmp/libpeer-ice-turn.pid -f >/dev/null 2>&1 &
  for _w in 1 2 3 4 5 6 7 8 9 10; do
    if ss -lun 2>/dev/null | grep -q ":${TURN_PORT} "; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: coturn not listening on UDP ${TURN_PORT}"
  exit 1
}

if [ "$use_docker" = "1" ]; then
  echo "==> Starting coturn (docker, host network)..."
  docker compose -f "$COTURN_DIR/docker-compose.yml" up -d
  sleep 2
  cleanup() {
    docker compose -f "$COTURN_DIR/docker-compose.yml" down || true
  }
  trap cleanup EXIT
  RUN_COTURN_PER_TEST=0
elif command -v turnserver >/dev/null 2>&1; then
  RUN_COTURN_PER_TEST=1
  cleanup() {
    stop_local_coturn
  }
  trap cleanup EXIT
else
  echo "WARN: no docker/turnserver — tests need coturn on ${TURN_HOST}:${TURN_PORT}"
  RUN_COTURN_PER_TEST=0
fi

export LIBPEER_DIST_LIB="$BUILD/dist/lib"

echo "==> Configuring libpeer-ice..."
cmake -S "$ROOT" -B "$BUILD" -G Ninja \
  -DLIBPEER_ICE_RELAY_ONLY=OFF \
  -DCMAKE_BUILD_TYPE=Debug

echo "==> Building (first run downloads mbedtls/gtest; may take several minutes)..."
cmake --build "$BUILD" -j"$(nproc)"

echo "==> Running tests..."
cd "$BUILD"
export LD_LIBRARY_PATH="${BUILD}/libpeer_build/src:${LIBPEER_DIST_LIB:-$BUILD/dist/lib}:${LD_LIBRARY_PATH:-}"
# Set ICE_STRESS_ROUNDS=10 (or similar) to include RelayConnectivityStress.
export ICE_STRESS_ROUNDS="${ICE_STRESS_ROUNDS:-0}"

# Each ICE test gets a fresh coturn — avoids leaked allocations on loopback relay.
ICE_CTEST_NAMES=(
  "TurnTcpAllocate.UdpBaseline"
  "TurnTcpAllocate.TcpControl"
  "IceRelayPair.UdpTurnRelayPairConnectivity"
  "IceRelayPair.TcpRelayPairConnectivity"
  "IceRelayPair.RelayMediaForwardingUdp"
  "IceRelayPair.RelayMediaForwardingTcp"
)
# Long stress run (optional): ICE_STRESS_ROUNDS=10 ./scripts/run_tests.sh
if [ "${ICE_STRESS_ROUNDS:-0}" -gt 0 ]; then
  ICE_CTEST_NAMES+=("IceRelayPair.RelayConnectivityStress")
fi

fail=0
for name in "${ICE_CTEST_NAMES[@]}"; do
  if [ "${RUN_COTURN_PER_TEST:-0}" = "1" ]; then
    start_local_coturn
  fi
  echo "==> ctest -R ${name}"
  if ! ctest --output-on-failure -V -j1 -R "^${name}$"; then
    fail=1
  fi
  if [ "${RUN_COTURN_PER_TEST:-0}" = "1" ]; then
    stop_local_coturn
  fi
done

# TURN refresh / expiry tests: coturn enforces a ~600 s minimum allocation lifetime,
# so we exercise expiry on the channel-binding / permission lifetime instead (coturn
# honors --channel-lifetime / --permission-lifetime). stale-nonce is short too so the
# refresh path exercises 438 recovery. Only on the local-turnserver path.
TURN_REFRESH_LIFETIME="${TURN_REFRESH_LIFETIME:-20}"
TURN_REFRESH_STALE_NONCE="${TURN_REFRESH_STALE_NONCE:-25}"
REFRESH_CTEST_NAMES=(
  "IceRelayPair.RelayRefreshKeepsRelayAlive"
  "IceRelayPair.RelayExpiresWithoutRefresh"
)
if [ "${RUN_COTURN_PER_TEST:-0}" = "1" ]; then
  for name in "${REFRESH_CTEST_NAMES[@]}"; do
    start_local_coturn \
      --channel-lifetime="${TURN_REFRESH_LIFETIME}" \
      --permission-lifetime="${TURN_REFRESH_LIFETIME}" \
      --stale-nonce="${TURN_REFRESH_STALE_NONCE}"
    echo "==> ctest -R ${name} (short-lived coturn: channel/perm=${TURN_REFRESH_LIFETIME}s nonce=${TURN_REFRESH_STALE_NONCE}s)"
    if ! TURN_SHORT_LIFETIME="${TURN_REFRESH_LIFETIME}" \
         ctest --output-on-failure -V -j1 -R "^${name}$"; then
      fail=1
    fi
    stop_local_coturn
  done
else
  echo "==> Skipping TURN refresh/expiry tests (need local turnserver for short-lived coturn)."
fi

if [ "$fail" -ne 0 ]; then
  echo "==> Some tests failed."
  exit 1
fi

echo "==> Done."
