> **Language:** English · [Русский](../ru/OVERVIEW.md)

# LACERT — project overview

The single entry point into the documentation: what this is, what it consists
of, how to build and run each part, and where to look for details.

LACERT (Lightweight Autonomous Continuous Encryption with Refreshment Tokens)
is a fully local — cloud-free — system for connecting IoT devices to a corporate
network with post-quantum cryptography. It has two parts:

- **the gateway** — a network service written in Go (`cmd/gatewayd`)
- **the firmware** — a protocol client written in C for the ESP32 (`firmware/`).

Both implement the same protocol and have been verified working against each
other on real hardware: XIAO ESP32-C6 (RISC-V), XIAO ESP32-S3 and
ESP32-S3-DevKitC-1 (Xtensa).

---

## Documentation index

| Document | About |
|----------|-------|
| `OVERVIEW.md` (this file) | overview, building, running |
| `PROTOCOL_SPEC.md` | byte-level protocol specification |
| `GATEWAY.md` | gateway architecture and API |
| `CONFIG.md` | **full reference of `.env` variables** |
| `MEASUREMENTS.md` | **measurement methodology and results** (how every figure was obtained and how to reproduce it) |
| `ECC_ACCELERATOR.md` | verified by measurement: what creates the signing-speed gap between the C6 and the S3 |
| `FIRMWARE.md` | how the ESP32 firmware is built internally |
| `TUNING.md` | timing parameters via environment variables |
| `FIRMWARE_BUILD.md` | step-by-step build and flashing |
| `LINUX_DEBUG.md` | debugging the protocol on Linux without hardware |
| `QUICKSTART.md` | getting the gateway running quickly |
| `ROBUSTNESS.md` | robustness: weak points found and how they were closed |
| `DEPLOY.md` | server deployment |
| `BOARD_MEASUREMENTS.md` | how on-board measurements are taken |
| `HISTORY.md` | development journal: what was built at each stage and why |

---

## What the system does

1. **Enrollment.** The device generates two key pairs (ECDSA P-256 for
   signatures and ML-KEM-1024 for key exchange), computes a checksum of its own
   firmware and enrolls with the gateway over REST. Keys are stored on the
   device (NVS/efuse) and survive a reboot.
2. **Handshake.** Post-quantum: key exchange over ML-KEM-1024, session key
   derivation through BLAKE3, authentication by an ECDSA signature. Unlike TLS,
   no public-key infrastructure is required — identity is bound to the device
   itself.
3. **Data transfer.** Telemetry is encrypted with ChaCha20-Poly1305.
4. **Continuous key rotation.** Roughly every 5 minutes (configurable) the
   session key is refreshed with a fresh ML-KEM secret mixed in. This provides
   forward secrecy (PFS) and post-compromise security (PCS).
5. **Firmware integrity checks.** The gateway periodically sends a challenge
   the device signs `challenge || SHA-256(firmware image)`, which lets the
   gateway confirm that the device is still running the firmware it enrolled
   with.

Each step, along with frame and field layouts, is described in
`PROTOCOL_SPEC.md`.

---

## Key research result

The hypothesis that a post-quantum signature (SLH-DSA) would pay off was not
confirmed: its signing is roughly 9,300× slower than ECDSA (hundreds of
milliseconds against tens of microseconds, see MEASUREMENTS) and its signatures are about 110× larger (7,856 bytes against 71).
The conclusion: **post-quantum strength is placed on key exchange (ML-KEM-1024),
while the signature stays with ECDSA P-256.** The system supports both signature
algorithms (switchable through `SigAlgorithm`), but ECDSA is the default and is
what runs on the device.

**Measurements on real boards support this conclusion.** Even ECDSA is expensive
on a microcontroller: 22 ms on the ESP32-C6 and 170 ms on the ESP32-S3 (against
0.35 ms on the server). SLH-DSA, being orders of magnitude heavier, is simply not
viable on chips of this class. ML-KEM itself, meanwhile, remains moderate —
16–23 ms — and barely depends on the platform.

Compared against DTLS 1.2 at comparable guarantees, LACERT establishes a session
3.2× faster, and the post-quantum ML-KEM key exchange costs 11× less than
classical ECDHE on a server and 13–15× less on the ESP32 boards. Details are in
`MEASUREMENTS.md`, section 3.5.

A separate finding: **ECDSA runs 7.7× faster on the ESP32-C6 than on the
ESP32-S3**, even though the C6 is the weaker chip (160 MHz against 240, one core
against two). On every other operation the two boards are on par, so the cause
is specifically the hardware elliptic-curve accelerator, which the C6 has and
the S3 does not. For cryptography on a microcontroller, a dedicated accelerator
matters more than clock speed. The full table is in `FIRMWARE.md`.

---

## Scope and threat model

The system is a prototype for an isolated segment of a corporate network, and it
is worth stating its assumptions plainly.

**Authentication is one-way.** The device proves its identity to the gateway with
a signature bound to an efuse key. The gateway presents no signature in return,
so its authenticity is not established by the protocol — trust in it comes from
the deployment conditions rather than from cryptography. On a network where an
active man-in-the-middle is possible, that is not enough.

**Control frames carry no signature.** The key-rotation and error frames
(types 8, 9 and 10) are protected only by travelling over an already encrypted
channel. They have no signature or MAC of their own.

**The embedded MQTT broker carries decrypted telemetry.** Connecting to it
requires a username and password, a subscriber may only read device topics, and
the channel is wrapped in TLS when a certificate and key are configured. Without
credentials the broker does not start. Channel encryption is off by default
though, and turning it on is a deliberate step — otherwise the data leaves the
machine in the clear.

**Debug mode exposes session keys.** The `LACERT_LOG_SESSION_KEYS` variable makes
the gateway write session keys to its log. That exists for examining handshakes
on the bench and must stay off everywhere except the lab.

**The device registry does not handle key replacement.** Device keys live in NVS
and stand in for efuse: if that memory is erased, the device generates fresh keys
while the registry still holds the old record, and the handshake fails. There is
no supported way to re-register a device yet.

These limits are neither hidden nor glossed over: they mark the area in which the
results hold, and they set the direction for further work.

## Repository layout

```
lacert/
├── cmd/                      applications (main packages)
│   ├── gatewayd/             the production gateway
│   ├── devicesim/            device simulator (for testing without hardware)
│   ├── demo/                 protocol demonstration with tracing
│   └── stresstest/           live attacker (exercises the defenses)
├── internal/                 gateway-internal packages (not importable outside)
│   ├── crypto/               primitives (ML-KEM, ECDSA, BLAKE3, ChaCha20)
│   ├── gateway/              gateway logic: sessions, rotation, integrity checks
│   ├── wire/                 binary framing of the protocol
│   ├── transport/            TCP server and TCP client
│   ├── api/                  REST API (chi)
│   ├── webui/                web dashboard (HTML/CSS/JS, embedded via go:embed)
│   ├── store/                storage (memstore + pgstore for PostgreSQL)
│   ├── scheduler/            background scheduler for rotations and checks
│   ├── telemetry/            telemetry parsing and storage
│   ├── mqttbridge/           embedded MQTT broker
│   ├── device/               device model
│   ├── emulator/             built-in device emulation
│   └── regtool/              enrollment utility
├── firmware/                 ESP32 firmware (C, ESP-IDF)
│   ├── main/                 protocol client + entry point
│   ├── component-overlay/    ESP32 component glue (RNG, CMakeLists)
│   ├── components/           ML-KEM (PQClean) and BLAKE3 — downloaded by fetch-components.sh
│   └── linux-debug/          the same client built for Linux, for debugging
├── deploy/                   deployment (bare-metal install.sh, tuning)
└── docs/                     documentation
```

---

## Building and running the gateway

Requirements: Go 1.22+. For production storage, PostgreSQL — without it the
gateway runs in memory.

```bash
# build
go build -o gatewayd ./cmd/gatewayd

# run (in-memory, no database) — handy for a quick check
LACERT_HTTP_ADDR=:8080 LACERT_TCP_ADDR=:7700 ./gatewayd

# open the dashboard
xdg-open http://localhost:8080
```

Production deployment in a single command (systemd, /opt/lacert, PostgreSQL):

```bash
sudo bash deploy/bare-metal/install.sh
```

The script is idempotent and does not overwrite an existing
`/etc/lacert/gatewayd.env`. Details are in `GATEWAY.md`.

---

## Building and flashing the firmware

Requirements: ESP-IDF v5.4.x (**a release tag**, not an intermediate branch
commit — ESP-IDF builds can fail on raw commits). XIAO ESP32-C6 (RISC-V), XIAO
ESP32-S3 and ESP32-S3-DevKitC-1 (Xtensa) are supported. **All three boards have
been verified on real hardware** and complete the full protocol against the
gateway.

```bash
cd firmware
# fill in the settings in main/main.c (Wi-Fi, gateway IP, device_id, token)
idf.py set-target esp32s3      # or esp32c6
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

The complete instructions, test-bench setup and a walkthrough of common problems
are in `FIRMWARE_BUILD.md`. The internals of the firmware are covered in
`FIRMWARE.md`.

---

## Debugging without hardware

The same client code (`firmware/main/lacert_wire.c` and `lacert_client.c`) also
builds for Linux under `firmware/linux-debug/`, with cryptography provided by
OpenSSL. This makes it possible to run the entire protocol against the gateway
without a board. See `LINUX_DEBUG.md`.

---

## Checks and tests

```bash
go build ./...        # build everything
go vet ./...          # static analysis
go test ./...         # unit tests (14 packages)
go test -race ./...   # race detector
```

An end-to-end stress test of five defense mechanisms (forged signature, replay,
stale challenge, wrong key, corrupted frame) lives in
`internal/gateway/stress_test.go` and `cmd/stresstest/`.
