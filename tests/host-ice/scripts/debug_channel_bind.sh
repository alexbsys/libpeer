#!/usr/bin/env bash
# Capture TURN/TCP (ChannelBind / ChannelData) while running IceRelayPair test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
PORT="${TURN_PORT:-3480}"
PCAP="${PCAP:-/tmp/libpeer_ice_channelbind.pcap}"

export TURN_HOST="${TURN_HOST:-127.0.0.1}"
export TURN_PORT="$PORT"
export TURN_USER="${TURN_USER:-testuser}"
export TURN_PASS="${TURN_PASS:-testpass}"

cleanup() {
  if [ -n "${TCPDUMP_PID:-}" ]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
  fi
  if [ -f /tmp/libpeer-ice-turn.pid ]; then
    kill "$(cat /tmp/libpeer-ice-turn.pid)" 2>/dev/null || true
    rm -f /tmp/libpeer-ice-turn.pid
  fi
}
trap cleanup EXIT

fuser -k "${PORT}/tcp" "${PORT}/udp" 2>/dev/null || true
pkill -9 -f "turnserver.*listening-port=${PORT}" 2>/dev/null || true
sleep 1

echo "==> coturn on ${TURN_HOST}:${PORT} (isolated lab port)"
turnserver -c "$ROOT/docker/coturn/turnserver.conf" \
  --listening-port="${PORT}" \
  --listening-ip="${TURN_HOST}" \
  --relay-ip="${TURN_HOST}" \
  --allow-loopback-peers \
  --log-file=/tmp/libpeer_ice_coturn.log \
  --verbose \
  --pidfile=/tmp/libpeer-ice-turn.pid -f &
sleep 3

if ! ss -lun | grep -q ":${PORT} "; then
  echo "ERROR: coturn not listening on UDP ${PORT}"
  exit 1
fi

echo "==> tcpdump -> ${PCAP}"
if sudo -n true 2>/dev/null; then
  sudo tcpdump -i lo -s 0 -w "$PCAP" "host ${TURN_HOST} and port ${PORT}" >/dev/null 2>&1 &
else
  tcpdump -i lo -s 0 -w "$PCAP" "host ${TURN_HOST} and port ${PORT}" >/dev/null 2>&1 &
fi
TCPDUMP_PID=$!
sleep 1

export LD_LIBRARY_PATH="${BUILD}/dist/lib:${LD_LIBRARY_PATH:-}"
echo "==> IceRelayPair.TcpRelayPairConnectivity"
"$BUILD/tests/test_ice_relay_pair" \
  --gtest_filter=IceRelayPair.TcpRelayPairConnectivity 2>&1 | tee /tmp/libpeer_ice_test.log || true

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

echo ""
echo "==> STUN/TCP message types (client -> server, first bytes after TCP payload)"
tcpdump -r "$PCAP" -n -xx 2>/dev/null | grep -E "0x0009|0x0109|0x4000|0x4010|length" | head -40 || true

echo ""
echo "==> coturn log (channel/bind)"
grep -iE "channel|bind|permission|error" /tmp/libpeer_ice_coturn.log 2>/dev/null | tail -30 || true

echo ""
echo "==> test log (ChannelBind / ChannelData / binding)"
grep -iE "ChannelBind|ChannelData|binding|succeeded|FAILED" /tmp/libpeer_ice_test.log | tail -30 || true

echo ""
echo "PCAP: $PCAP"
