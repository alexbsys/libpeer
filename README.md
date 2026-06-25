# libpeer (embedded WebRTC) — feature overview & usage

A small, dependency-light WebRTC stack in C for microcontrollers (ESP32 family
and similar). It implements just enough of the standards to push real-time
media and data over the public Internet through NATs, while staying inside the
RAM/CPU budget of an embedded SoC. This document describes the library as a
**general-purpose embedded WebRTC building block** — not tied to any particular
application.

> This is a modified/extended fork of the original `libpeer`. The capability
> table below reflects *this* fork.

## What it can and cannot do

| Area | Status | Notes |
|------|--------|-------|
| **ICE — host candidates** | ✅ | Local interface addresses. |
| **ICE — server-reflexive (STUN)** | ✅ | `stun:` servers for NAT discovery. |
| **ICE — TURN relay over UDP** | ✅ | `turn:host?transport=udp`. |
| **ICE — TURN relay over TCP** | ✅ | `turn:host?transport=tcp` (TURN control channel over TCP, RFC 6062-style ChannelData framing). |
| **Trickle ICE** | ✅ | Candidates can be added incrementally via `peer_connection_add_ice_candidate()`. |
| **Transport policy `all` / `relay`** | ✅ | Force relay-only, or allow host+srflx+relay. |
| **Relay-protocol pinning (UDP-only / TCP-only / any)** | ✅ | Restrict which TURN transport is allocated. |
| **Consent freshness (RFC 7675)** | ⚠️ Partial | Periodic STUN Binding keepalive on the selected pair; no consent-failure-driven re-nomination. |
| **mDNS (`.local`) remote candidates** | ⛔ Skipped | Intentionally ignored — resolving `.local` blocks the event loop and these candidates are never reachable from outside the LAN anyway. |
| **DTLS 1.2 + SRTP key export** | ✅ | mbedTLS-based; client or server role. |
| **SRTP/SRTCP encrypt/decrypt** | ✅ | AES-128 CM + HMAC-SHA1. |
| **RTP send (H.264)** | ✅ | Single-NAL and FU-A fragmentation, 90 kHz clock, optional capture-PTS mapping. |
| **RTP receive / depacketize** | ✅ | Audio + video track callbacks. |
| **RTX retransmission (RFC 4588)** | ✅ | Separate RTX SSRC + payload type, `apt`/`ssrc-group:FID` in SDP, driven by inbound NACK. |
| **RTCP NACK (RFC 4585)** | ✅ | Inbound Generic NACK triggers RTX resends from a sequence-number cache. |
| **RTCP PLI / FIR** | ✅ | Inbound PLI/FIR surfaced as a "send a keyframe" callback. |
| **RTCP Receiver Report (loss)** | ✅ | Inbound RR `fraction_lost` / cumulative loss surfaced via callback. |
| **RTCP Sender Report (SR)** | ✅ | Outbound SR emitted periodically for A/V sync + receiver stats. |
| **RTCP REMB (`goog-remb`)** | ✅ | Advertised in SDP; inbound REMB surfaced via callback for bandwidth estimation. |
| **rtcp-mux** | ✅ | RTP and RTCP share one transport (required by modern browsers). |
| **BUNDLE** | ✅ | Single transport for the media session. |
| **SCTP data channels** | ✅ | DCEP, reliable/partial-reliable. |
| **TWCC (transport-wide congestion control)** | ⛔ Not implemented | See "Why not" below. |
| **FEC (FlexFEC / ULPFEC)** | ⛔ Not implemented | See "Why not" below. |
| **Simulcast / SVC** | ⛔ Not implemented | One encoding per track. |
| **Mid-session ICE failover / ICE restart** | ⛔ Not implemented | See "Why not" below. |
| **Audio codecs (Opus/G.711) transcode** | ➖ Passthrough | Library forwards RTP; encoding/decoding is the application's job. |

### Why some features are intentionally left out

- **TWCC** requires the *sender* to maintain per-packet transport-wide sequence
  numbers and run a delay-based congestion controller (GCC) over the receiver's
  feedback. On a CPU already saturated by capture/encode work, the per-packet
  bookkeeping and the GCC filter are expensive for marginal benefit. **REMB**
  (receiver-side estimate, a few bytes per second of feedback) gives most of the
  bandwidth-adaptation value at a tiny fraction of the cost, so it is preferred.

- **FEC** trades bandwidth for redundancy to mask loss without a round trip. For
  low-latency, single-viewer embedded links, **NACK + RTX** recovers loss with
  far less constant overhead and is already implemented. FEC mainly pays off for
  large fan-out / high-RTT scenarios that embedded senders rarely serve.

- **Simulcast / SVC** assume one source feeding many heterogeneous receivers
  through an SFU. An embedded sender typically produces a single stream; adaptive
  quality is handled by reconfiguring the one encoder from REMB/RR feedback.

- **Mid-session ICE failover / ICE restart** is omitted to keep the agent simple
  and deterministic. Path *selection* across host/srflx/relay-UDP/relay-TCP
  happens once, at connection setup, by ICE priority. If the chosen path later
  dies, the connection times out and recovery is a fresh negotiation driven by
  the application/signaling layer (during which the best currently-working path
  is re-selected). This is simpler and more predictable than maintaining
  multiple live paths and consent state machines on a constrained device.

## ICE: automatic selection vs. switching

It is important to be precise about *when* path selection happens:

- **At connection setup (automatic, yes).** With transport policy `all` and
  relay protocol `any`, the agent gathers every candidate type it can (host,
  server-reflexive, TURN-UDP, TURN-TCP) and selects the highest-priority pair
  that passes connectivity checks. If direct UDP is reachable it wins; if UDP is
  blocked, the UDP pairs fail their checks and a TURN (UDP, then TCP) pair is
  selected instead. So the *initial* choice between direct-UDP / relay-UDP /
  relay-TCP is automatic.

- **Mid-session (no seamless switch).** Once a pair is selected and media is
  flowing, the library does **not** re-nominate a different pair or hop from UDP
  to TCP on the fly. If the active path degrades or is blocked, the connection
  eventually times out; the *application* must renegotiate (ICE restart /
  reconnect), after which selection runs again and lands on whatever path works
  now. Practically: "we were on direct UDP, the path broke" recovers by
  reconnecting onto TURN — not by a glitch-free in-session handover.

If you need to *force* a path (e.g. lock everything to a TURN TCP relay for a
hostile-network test), pin it with the transport-policy / relay-protocol knobs
shown below; then no other candidate type is gathered at all.

## Configuring the transport: UDP-only / TCP-only / everything

```c
#include "peer_connection.h"

PeerConfiguration cfg = {0}; /* zero-init = policy ALL + relay protocol ANY */

cfg.ice_servers[0] = (IceServer){ .urls = "stun:stun.example.org:3478" };
cfg.ice_servers[1] = (IceServer){
    .urls = "turn:turn.example.org:3478?transport=udp",
    .username = "user", .credential = "pass" };
cfg.ice_servers[2] = (IceServer){
    .urls = "turn:turn.example.org:3478?transport=tcp",
    .username = "user", .credential = "pass" };

/* (1) Everything (default): host + srflx + relay, UDP and TCP relays. */
cfg.ice_transport_policy = ICE_TRANSPORT_POLICY_ALL;
cfg.ice_relay_protocol   = ICE_RELAY_PROTOCOL_ANY;

/* (2) Relay only, but allow either relay transport. */
cfg.ice_transport_policy = ICE_TRANSPORT_POLICY_RELAY;
cfg.ice_relay_protocol   = ICE_RELAY_PROTOCOL_ANY;

/* (3) TURN over UDP only (no host/srflx, no TCP relay). */
cfg.ice_transport_policy = ICE_TRANSPORT_POLICY_RELAY;
cfg.ice_relay_protocol   = ICE_RELAY_PROTOCOL_UDP;

/* (4) TURN over TCP only — survives networks that block UDP entirely. */
cfg.ice_transport_policy = ICE_TRANSPORT_POLICY_RELAY;
cfg.ice_relay_protocol   = ICE_RELAY_PROTOCOL_TCP;

PeerConnection* pc = peer_connection_create(&cfg);
```

To inspect which path actually won at runtime:

```c
PeerIceInfo info;
if (peer_connection_get_ice_info(pc, &info) == 0 && info.connected) {
    printf("path=%s relay=%d tcp=%d local=%s remote=%s\n",
           info.transport_str,   /* "udp" / "relay-udp" / "relay-tcp" */
           info.via_relay, info.relay_over_tcp,
           info.local_addr, info.remote_addr);
}
```

## Reacting to PLI / FIR (remote asks for a keyframe)

When the viewer loses sync it sends RTCP PLI/FIR. The library surfaces this as a
single "please produce an intra frame" callback — wire it to your encoder's
force-IDR request.

```c
static void on_request_keyframe(void* userdata) {
    Encoder* enc = userdata;
    encoder_force_idr(enc);   /* next encoded frame will be a keyframe */
}

cfg.on_request_keyframe = on_request_keyframe;
cfg.user_data           = my_encoder;
/* ...then peer_connection_create(&cfg); */
```

## Learning about packet loss (RTCP Receiver Report)

Inbound RR carries the receiver's `fraction_lost` (0..255, i.e. /256) and the
cumulative number of lost packets. Use it as a congestion/quality signal.

```c
static void on_loss(float fraction_loss, uint32_t total_loss, void* userdata) {
    /* fraction_loss is 0.0 .. ~1.0; total_loss is cumulative packets. */
    if (fraction_loss > 0.05f) {
        bitrate_controller_note_loss(userdata, fraction_loss);
    }
}

peer_connection_on_receiver_packet_loss(pc, on_loss);
```

## Bandwidth estimation with REMB (`goog-remb`)

The SDP offer advertises `a=rtcp-fb:<pt> goog-remb`, so a compatible peer
(e.g. Chrome) will periodically send back its estimate of the available
downlink bitrate. Register a callback to receive it in **bits per second**:

```c
static void on_remb(uint32_t bitrate_bps, void* userdata) {
    /* The receiver's view of how much bandwidth the path can carry. */
    encoder_set_target_bitrate(userdata, bitrate_bps);
}

peer_connection_on_remb(pc, on_remb);
```

A robust controller treats REMB as the **primary** target while it arrives
frequently, and falls back to a local heuristic (e.g. RTT/loss probing) when
REMB is sparse or absent:

```c
/* sketch of the freshness gate */
static uint32_t last_remb_bps;
static int64_t  last_remb_us;

static void on_remb(uint32_t bps, void* u) {
    last_remb_bps = bps;
    last_remb_us  = now_us();
}

/* once per second in your control loop: */
if (now_us() - last_remb_us <= 5 * 1000 * 1000 && last_remb_bps > 0) {
    target = clamp(last_remb_bps, min_bps, max_bps);   /* trust REMB */
} else {
    target = heuristic_estimate();                      /* fall back to ping/loss */
}
```

## NACK and retransmissions (RFC 4585 + RFC 4588)

Retransmission is automatic and requires no application code:

1. The SDP offers H.264 plus a separate **RTX** payload type and SSRC
   (`a=rtpmap:<rtx_pt> rtx/90000`, `a=fmtp:<rtx_pt> apt=<pt>`,
   `a=ssrc-group:FID <media_ssrc> <rtx_ssrc>`) and `a=rtcp-fb:<pt> nack`.
2. Every outbound media packet is retained in a sequence-number-indexed cache.
3. When the peer reports loss with an RTCP **Generic NACK** (RTPFB fmt=1), the
   library looks up the requested sequence numbers and resends them as **RTX**
   packets on the RTX SSRC.
4. Optionally, resends for packets older than the most recent IDR can be
   dropped (they would arrive too late to be useful):

```c
/* esp_peer layer exposes this as a config flag; at the libpeer level: */
peer_connection_set_nack_discard_pre_idr(pc, 1);
```

You normally do not observe individual NACKs directly — they are consumed
inside the RTCP handler. The *effect* of loss is visible through the RR loss
callback and through REMB shrinking.

### Tuning the retransmit buffer depth (runtime)

The resend cache holds the **last N outbound RTP packets** so a NACK can be
answered with an RTX copy. A deeper buffer recovers *older* losses (useful on
lossy/jittery links where loss reports arrive late), at a RAM cost of
`N * (CONFIG_MTU + 128)` bytes — on ESP32 this allocation prefers PSRAM. The
default depth is `RTP_NACK_RING_DEFAULT` (512 packets ≈ 0.5–1 s of history); it
is clamped to `RTP_NACK_RING_MAX`.

All knobs are **runtime functions** (no recompile needed) — the compile-time
defaults are unchanged:

```c
/* (A) Process-wide default, applied to PeerConnections created afterwards.
 *     Call this once at startup, before bringing up sessions. */
peer_connection_set_default_nack_buffer_size(1024);       /* deeper history   */
peer_connection_set_default_nack_resend_per_sec(800);     /* allow more RTX/s */

/* (B) Live, per-connection — resize the buffer of an already-created pc.
 *     Resizing drops the currently buffered history (next packets refill it).
 *     Call from the same task that drives peer_connection_loop(). */
peer_connection_set_nack_buffer_size(pc, 2048);           /* 0 = back to default */
peer_connection_set_nack_resend_per_sec(pc, 1000);

/* Inspect the current depth. */
unsigned depth = peer_connection_get_nack_buffer_size(pc);
```

Guidance: increase the **depth** when losses come in bursts or feedback is
delayed (high RTT); increase the **resend-per-second** cap when a single drop
needs many packets resent faster than the 500/s default allows. Both trade
uplink/RAM for recovery, so raise them only as far as a problematic link needs.

## Outbound Sender Reports (SR)

Once media is flowing, the library periodically emits an RTCP **Sender Report**
for the video stream (NTP + RTP timestamp mapping, packet/octet counts). This
lets the receiver compute inter-stream sync and round-trip time. No application
action is required.

## Minimal media-send loop

```c
PeerConnection* pc = peer_connection_create(&cfg);

peer_connection_oniceconnectionstatechange(pc, on_state);
peer_connection_onicecandidate(pc, on_local_candidate);  /* trickle out */

/* signaling: exchange offer/answer + candidates with the remote peer ... */
const char* offer = peer_connection_create_offer(pc);
/* send `offer`, receive `answer`: */
peer_connection_set_remote_description(pc, answer_sdp, SDP_TYPE_ANSWER);
peer_connection_add_ice_candidate(pc, remote_candidate_line);

/* drive the state machine + I/O from one task: */
for (;;) {
    peer_connection_loop(pc);
    if (peer_connection_get_state(pc) == PEER_CONNECTION_COMPLETED) {
        /* pts_us = capture timestamp; 0 lets the library use a fixed tick */
        peer_connection_send_video(pc, h264_au, h264_len, capture_pts_us);
    }
}
```

## Threading note

`peer_connection_loop()` performs all socket I/O, ICE checks, DTLS, and RTCP
handling. Run it from a single dedicated task and call the `send` functions from
that same task (or serialize access). The callbacks above are invoked from
inside the loop, so they must not block.
