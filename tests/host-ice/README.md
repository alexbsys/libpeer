# libpeer host ICE/TURN integration tests

Desktop (host) integration tests for libpeer's **ICE + TURN relay** stack,
including **TURN over TCP**. They run libpeer's real agent against a live
[coturn](https://github.com/coturn/coturn) server, so they validate actual
on-the-wire behaviour — not mocks.

They are **not** part of the normal libpeer build (embedded or standalone): this
is a self-contained CMake project that consumes libpeer via `add_subdirectory`.
Build it explicitly when you want to exercise the relay paths on a PC.

Runs on **Ubuntu** (native) and on **Windows via WSL2 (Ubuntu)**.

See the top-level [`README.md`](../../README.md) ("Host integration tests") for
the full description: what each case proves, how to read the output, and the
tuning knobs. Quick reference below.

## Prerequisites

```bash
sudo apt install -y build-essential cmake ninja-build
# coturn provides the TURN server (the script also accepts docker):
sudo apt install -y coturn        # or: sudo apt install -y docker.io
```

`scripts/install_deps_wsl.sh` installs the same set on a fresh WSL2 Ubuntu.

## Build & run

```bash
cd firmware/master/third_party/libpeer/tests/host-ice
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh            # configures, builds, starts coturn, runs ctest
```

The first build downloads GoogleTest and compiles libpeer's vendored mbedTLS /
libsrtp / usrsctp — expect a few minutes. Subsequent runs are fast.

Optional environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `TURN_HOST` | `127.0.0.1` | TURN server address |
| `TURN_PORT` | `3480` | TURN listening port (3480 avoids a system coturn on 3478) |
| `TURN_USER` | `testuser` | TURN long-term credential user |
| `TURN_PASS` | `testpass` | TURN long-term credential password |
| `ICE_STRESS_ROUNDS` | `0` | >0 enables the repeated UDP+TCP stress case |

## Test cases

| Test | What it proves |
|------|----------------|
| `TurnTcpAllocate.UdpBaseline` | TURN `Allocate` over a UDP control channel |
| `TurnTcpAllocate.TcpControl` | TURN `Allocate` over a **TCP** control channel (`?transport=tcp`) |
| `IceRelayPair.UdpTurnRelayPairConnectivity` | Two agents complete ICE over a UDP relay |
| `IceRelayPair.TcpRelayPairConnectivity` | Two agents complete ICE over a **TCP** relay |
| `IceRelayPair.RelayMediaForwardingUdp` / `...Tcp` | Application payloads actually flow both directions over the relay |
| `IceRelayPair.RelayRefreshKeepsRelayAlive` | Periodic TURN refresh keeps the channel/permission alive past its lifetime |
| `IceRelayPair.RelayExpiresWithoutRefresh` | Without refresh the relay stops delivering (negative control) |
| `IceRelayPair.RelayConnectivityStress` | Repeated UDP+TCP rounds (set `ICE_STRESS_ROUNDS>0`) |

## Manual coturn

```bash
docker compose -f docker/coturn/docker-compose.yml up
turnutils_uclient -v -u testuser -w testpass 127.0.0.1
```
