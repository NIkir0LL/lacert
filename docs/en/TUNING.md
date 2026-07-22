> **Language:** English · [Русский](../ru/TUNING.md)

# Tunable parameters (for a test bench)

> This document explains **why** the values are what they are and how to choose
> them. The complete list of `.env` variables with defaults is in
> [`CONFIG.md`](CONFIG.md).

Every timing parameter in the system can be overridden through the gateway's
environment variables (`cmd/gatewayd`) — no code changes and no rebuild. That
makes it easy to tune values on a bench before moving to a production setup with
real ESP32 devices.

**Note:** if a variable is not set, the default (production) value applies, so
for production you can simply set nothing.

## Parameter table

| Environment variable | Default | What it controls |
|---|---|---|
| `LACERT_ROTATION_INTERVAL` | `300s` | How often to rotate the key by time |
| `LACERT_ROTATION_PACKET_LIMIT` | `300` | Rotate after N transmitted packets |
| `LACERT_ROTATION_ACK_TIMEOUT` | `5s` | How long to wait for a rotation acknowledgement (ACK) before treating it as failed |
| `LACERT_ROTATION_CHECK_PERIOD` | `5s` | How often the scheduler polls devices |
| `LACERT_MAX_ROTATION_FAILURES` | `3` | How many consecutive failed rotations before a device is revoked |
| `LACERT_FIRMWARE_INTERVAL` | `1h` | How often to check firmware integrity |
| `LACERT_FIRMWARE_VALIDITY` | `15s` | Validity window for a challenge response (later responses are rejected as stale) |
| `LACERT_FIRMWARE_CHALLENGE_TIMEOUT` | `25s` | Pause before issuing another challenge to the same device |
| `LACERT_PENDING_HANDSHAKE_TIMEOUT` | `20s` | Expiry of an incomplete handshake |
| `LACERT_NONCE_TTL` | `5m` | How long nonces are remembered for replay protection |

## Where these defaults come from

The defaults are tuned for the "ECDSA + local network" combination actually used
on the boards — see the analysis conclusion: ECDSA rather than SLH-DSA. The
timeouts leave headroom over the cost of the operations on the device itself: an
ECDSA signature takes 22 ms on the ESP32-C6 and 170 ms on the ESP32-S3, that is,
a fraction of a second even in the worst case.

- **`LACERT_ROTATION_ACK_TIMEOUT` = 5s.** Ample: a rotation on the ESP32 fits
  into single-digit milliseconds including the network round trip.
- **`LACERT_FIRMWARE_VALIDITY` = 15s.** The window within which the device must
  answer a challenge. A shorter window leaves less room for replaying an old
  response.
- **`LACERT_PENDING_HANDSHAKE_TIMEOUT` = 20s.** Keeps incomplete handshakes from
  lingering in the gateway's memory.
- **`LACERT_ROTATION_INTERVAL` = 300s.** Can be shortened to 60–120 s: more
  frequent rotation means less data under a single key. The limiting factor is
  the overhead on the device itself. Measured on hardware, one rotation
  (ML-KEM decapsulation plus BLAKE3 key derivation) costs **18–23 ms** — about
  18 ms on the ESP32-C6 and about 23 ms on the ESP32-S3. At a one-minute
  interval that is a fraction of a per cent of CPU time.

  (Earlier revisions of this document quoted ≈61 µs here — that was a rotation
  on an x86-64 server. On a microcontroller it is three orders of magnitude more
  expensive, and the interval has to be planned from the hardware figures. See
  the table in `FIRMWARE.md`.)

If you switch to **SLH-DSA**, these windows need to grow: on a server its
signing takes ≈336 ms against ≈0.35 ms for ECDSA, and on a microcontroller the
gap is wider still — ECDSA alone already costs 22 ms (C6) and 170 ms (S3).
Reasonable starting points: `ROTATION_ACK_TIMEOUT` up to 30 s,
`FIRMWARE_VALIDITY` up to 90 s, `PENDING_HANDSHAKE_TIMEOUT` up to 60 s.

`RotationPacketLimit`, `MaxRotationFailures` and `NonceTTL` can usually be left
alone.

## Example: test bench with short intervals

```bash
LACERT_ROTATION_INTERVAL=60s \
LACERT_ROTATION_ACK_TIMEOUT=8s \
LACERT_FIRMWARE_INTERVAL=30m \
LACERT_FIRMWARE_VALIDITY=15s \
LACERT_PENDING_HANDSHAKE_TIMEOUT=20s \
./gatewayd
```

## Example: demo mode for the live stress test (very short intervals)

Used by `deploy/run-live-stress.sh` so that all scenarios complete in about
20 seconds. NOT for production:

```bash
LACERT_ROTATION_INTERVAL=6s \
LACERT_ROTATION_ACK_TIMEOUT=4s \
LACERT_FIRMWARE_INTERVAL=2s \
LACERT_FIRMWARE_VALIDITY=1s \
./gatewayd
```

## Finding the optimum on a bench

1. Start the gateway with emulation (`LACERT_EMULATE_DEVICES=3`) and different
   values.
2. Watch the "metrics" tab on the dashboard: if `rotations_failed` or
   `firmware_checks_rejected` grow while the devices are healthy, the timeout is
   too short — increase it.
3. When you move to real ESP32 devices, start from "safe" values close to the
   defaults and shorten them gradually, checking that no failures appear.

## Live stress test: the D4 delay

Scenario D4 (stale firmware challenge) answers a challenge deliberately late so
that the gateway rejects the response. The delay must EXCEED the gateway's
`LACERT_FIRMWARE_VALIDITY`. The default delay is 20 s, comfortably above the
15 s window. If you widen the validity window, widen the delay too:

  LACERT_STRESS_D4_DELAY=35s go run ./cmd/stresstest   # if validity=30s
