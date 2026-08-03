> **Language:** English · [Русский](../ru/HISTORY.md)

# Development journal

A stage-by-stage chronicle of the work on LACERT: what was built, what problems
surfaced and how they were solved. This document answers the question "why is
the system built this way", whereas how it works today is described in
[`OVERVIEW.md`](OVERVIEW.md), [`GATEWAY.md`](GATEWAY.md) and
[`FIRMWARE.md`](FIRMWARE.md).

Every item is completed and verified work rather than intent: the defects listed
were reproduced by a test or a live run before being fixed.

---

## Stage 1. The cryptographic core

The protocol's basic primitives were implemented and verified:

- **ML-KEM-1024 (Kyber)** — post-quantum key exchange through
  `github.com/cloudflare/circl`. The sizes match the specification: the public
  key and the ciphertext are 1,568 bytes each.
- **Device signature** — two variants, both implemented and comparable:
  `ECDSA P-256` (the primary one) and `SLH-DSA-SHA2-128s` (FIPS 205).
- **BLAKE3** — derivation of the session key K0 and the rotation step
  `Ki+1 = BLAKE3(Ki || Mi || "rotate_v1")`.
- **ChaCha20-Poly1305** — data encryption, payloads up to 380 bytes.
- **Continuous rotation** every 300 packets or 300 seconds, wiping the old key.
- **Firmware integrity checks** — challenge/response with a signature and a
  SHA-256 comparison, revoking the device automatically on a mismatch.
- **Offline enrollment** — parameters printed over the serial port with a
  checksum that guards against typos during manual transfer.

---

## Stage 2. The transport layer

The gateway and the device were separated into **distinct processes** genuinely
communicating over the network, rather than calling functions inside a single
program.

**`cmd/gatewayd`** — the gateway process:

- a TCP server (`:7700`) speaking the LACERT protocol: binary framing
  (`internal/wire`), handshake, data, rotation, firmware integrity checks
- a REST API (`:8080`, built on `chi`) — device enrollment, listing and status,
  event log, revocation, and issuing the gateway's public key
- an embedded MQTT broker (`:1883`, built on `mochi-mqtt`) — decrypted telemetry
  is published to `devices/{id}/telemetry`, events to `devices/{id}/events`
- a background scheduler (`internal/scheduler`) — walks active connections and
  initiates rotations on a timer along with periodic firmware checks
- storage — PostgreSQL through gorm, falling back to memory automatically if the
  database is unavailable.

**`cmd/devicesim`** — the device process: generates keys, enrolls over REST,
establishes a secure channel over TCP, sends telemetry and answers rotations and
firmware checks.

Verified by running both processes with real sockets and a real database,
including a telemetry subscription through `mosquitto_sub` and calls to the REST
API.

---

## Stage 3. Gateway and protocol hardening

Before adding the web interface, gaps were closed that would otherwise have
surfaced in production.

**A race on concurrent writes to a TCP connection.** The scheduler and the
session handler wrote to the same `net.Conn` without synchronization, so
simultaneous calls could interleave frames. Worse, even without byte-level
corruption, concurrent `InitiateRotation` calls for one device could compute the
rotation step in one order and send the frames in another: the two sides ended
up with different keys without a single corrupted byte on the wire. Fixed — the
operation "compute the protocol step and send the frame" is now atomic at the
connection level (`connEntry.ioMu`). Test: `TestTCPConcurrentServerWrites`.

**Lost addressing when a device reconnected.** If a device reconnected, the old
goroutine could remove the registry entry for the **new** connection once the
old socket finally closed — leaving the gateway unable to address the device.
Fixed: the old connection is closed immediately, and the entry is removed only
if it still belongs to that particular session (compared by pointer). Test:
`TestTCPDeviceReconnectDoesNotLoseAddressing`.

**Silent replacement of an unanswered challenge.** Calling
`IssueFirmwareChallenge` again before a response arrived silently replaced the
challenge — a device answering the first request would have been wrongly
rejected. Fixed: a repeat call within `firmwareChallengeTimeout` returns an
explicit error instead of overwriting the state.

**No keepalive or idle timeout.** A hung connection (a device switched off
without closing TCP cleanly) held a goroutine and a registry slot indefinitely.
TCP keepalive and a read timeout were added — set well above the rotation
interval so that live but temporarily idle channels are not closed.

**No graceful shutdown.** `Server.Shutdown(ctx)` now closes the listener and all
active connections and waits for the serving goroutines. It is wired into
`cmd/gatewayd` for SIGTERM/SIGINT. Test:
`TestTCPServerShutdownClosesConnections`.

**REST API without authentication or CORS.** Bearer authentication was added for
the admin endpoints through `LACERT_ADMIN_TOKEN`. If no token is set,
authentication is disabled with an explicit warning in the log. `/healthz` and
`/api/v1/gateway` remain open at all times — the latter is needed by a device
for provisioning before any authentication exists. CORS is configured through
`LACERT_CORS_ORIGINS`. `GET /api/v1/devices/{id}` began returning `online`,
`remote_addr` and `last_seen`.

Every fix is covered by tests, including a full run under the race detector.

---

## Stage 4. Web interface, a single binary, detachable emulation

**Backend and frontend ship as one file.** The administration page
(`internal/webui`) is plain HTML/CSS/JS with no build step and no calls to
external CDNs (the project targets isolated networks, where pulling fonts from a
third-party service would be out of place). It is embedded into the binary via
`go:embed` and served by the same HTTP server and port as the REST API. It
starts with a single command, with everything inside: the TCP protocol, REST,
MQTT, the web page and the scheduler.

The page can: list devices with real-time online status. Enroll a device
(including pasting a whole line from the serial port in one action — the fields
are parsed automatically, see `regtool.Parse`). Show an event log. Revoke a
device.

The styling is deliberately console-like: monospaced type, a dark panel, an
amber accent. What it displays is essentially the device's own output —
hexadecimal keys, identifiers, checksums — so the monospaced font is not a
decorative flourish but literally what the administrator reads from a terminal.

**ESP32 emulation was moved into a reusable package**, `internal/emulator`.
Previously `cmd/devicesim` was a standalone `main.go`. It is now a thin wrapper
around `internal/emulator.Run(ctx, cfg)`.

**Emulation can be switched on inside `gatewayd`** with
`LACERT_EMULATE_DEVICES=N` — the gateway spins up N software devices that
connect over the same TCP port a real board would use. Crucially, neither the
gateway nor the protocol distinguishes an emulated device from a real one: both
speak the same `internal/wire` protocol through `internal/transport`. Moving to
trials with real boards therefore amounts to not setting
`LACERT_EMULATE_DEVICES`. The server side needs no rewriting.

Along the way an unrealistic aspect of enrollment was fixed: previously the
**entire firmware image** was sent to the gateway so it could compute the
reference hash, which is both unrealistic for an embedded device and
unnecessary. The device now computes the SHA-256 of its own firmware and sends
only the hash — exactly as it does during subsequent periodic checks. The field
joined the single output line
(`DeviceID=… IdentityPub=… KEMPub=… FirmwareHash=… Checksum=…`), and the
checksum covers it as well.

---

## Stage 5. Monitoring dashboard, telemetry in the database, rotation log

Until this point decrypted telemetry went to MQTT and vanished — there was no
way to review history or plot a chart.

**Storing telemetry.** `internal/gateway.HandleData` now not only decrypts a
packet but also stores it (the raw data plus the numeric fields parsed by
`internal/telemetry.ParseKV`) in the `telemetry_readings` table. The payload
format is a plain `key=value;key2=value2`: this avoids requiring a serialization
library on a device with limited flash.

**Rotation log.** The `key_rotations` table: every rotation attempt, successful
or not, is recorded with its time, initiator, status and error text. Full key
values reach the log **only** when the test mode is explicitly enabled
(`LACERT_LOG_SESSION_KEYS=true`, off by default). In production session keys are
not written to the database at all, rather than merely hidden in the interface.

**The REST API** gained `GET /api/v1/telemetry` (filters `device_id`,
`since`/`until` or the relative `range=1h`, and `limit`) and
`GET /api/v1/rotations`. `GET /api/v1/gateway` began returning
`log_session_keys` so the frontend can display the correct mode banner.

**The dashboard** gained a "Monitoring" section (charts of numeric telemetry
fields, an overview across all devices or a specific one, periods from 30
minutes to a day or a custom range, plus a table of packet history) and a
"Rotation log" section. The charts are written from scratch in plain SVG, with
no external libraries or CDNs — for the same reason as system fonts rather than
downloaded ones: everything has to work without internet access.

**How this was verified.** The chart mathematics (axis scaling, finding the
nearest point for a tooltip) was first exercised as pure functions with explicit
assertions — 28 of them, all passing. Then a real browser test was run through
Playwright against a live gateway: signing in with a token, opening a device
card, moving into monitoring, hovering over a chart, switching the range, and
viewing the rotation log in both modes. This uncovered two visual defects before
they could reach a user: an uncontrolled `text-transform: uppercase` on the
device identifier inside headings, and a broken layout in the test-mode banner.
Both were fixed and re-verified by the same test.

---

## Stage 6. Devices stopped hanging offline; sensor profiles

A real defect found during trials on a server with PostgreSQL: after **any**
restart of `gatewayd` with built-in emulation enabled, every emulated device
stayed offline forever.

The cause: each process start generates new keys for the emulated devices while
reusing the same identifiers (`emulated-esp32-1`…`-N`). With persistent storage
the old enrollment survives a restart, and re-enrolling under the same
identifier with different keys was rejected as `ErrDeviceExists` — the device
never reached the handshake. With in-memory storage the problem did not appear.

Fixed by adding `DeviceStore.Delete`, which cascades through telemetry, the
event log and the rotation log (implemented in both storage backends, each with
tests, including a check against a real database: delete → re-enroll with
different keys → success), and `internal/emulator.ResetDevices`, which is called
for the reserved identifiers before the emulators start. Real devices are
unaffected. Verified live: three consecutive restarts with ten emulated devices
gave 10 out of 10 online on every start, whereas before the fix the second and
later starts consistently produced ten errors.

A related gap was closed at the same time: previously every emulated device sent
identical values from one formula, so the charts looked like a single line
copied N times. `internal/emulator/profiles.go` now defines five sensor
profiles:

| Profile | Fields |
|---------|--------|
| `climate` | `temperature`, `humidity` |
| `power` | `voltage`, `current_a`, `power_w` |
| `pressure` | `pressure_kpa`, `temperature` |
| `fuel` | `level_percent` (decreasing monotonically), `temperature` |
| `motor` | `rpm`, `vibration_mm_s`, `temperature` |

Each device gets its own profile (assigned round-robin) along with its own base
level, amplitude and phase, all derived deterministically from the identifier:
the same identifier always yields the same instrument "character" across
restarts, while different devices look different on the chart. `cmd/devicesim`
supports choosing manually through `LACERT_PROFILE`.

---

## Stage 7. Full audit for defects and vulnerabilities

A deliberate manual audit of the entire codebase — serialization, concurrency,
the REST API, storage, transport — with the test suite extended to cover what it
found. Every item was reproduced by a test or a live run before being fixed.

**[Denial of service] A `uint16` overflow while parsing frames.**
`internal/wire.takeFramed` computed `2+n`, where `n` is a `uint16` length read
from someone else's TCP stream. When `n` approached the maximum, the addition
overflowed the 16-bit type **before** the conversion to `int`, which made the
bounds check trivially false and sent the code past the end of the buffer — a
panic. Since the connection handler was not wrapped in `recover()`, such a panic
killed **the entire gateway process** along with every connected device. One
corrupted packet on port 7700 was enough. Traffic of exactly this kind — a
network scanner probing the port with an HTTP request — had already been
observed in operation. Fixed by converting to `int` before the addition
`recover()` was added as defense in depth, so a panic now takes down only one
connection. Covered by tests with pathological input for all seven parsing
functions and by an end-to-end test that hammers the server with garbage
traffic, including an exact copy of a line from a real log.

**[Logic error] Revoking a device did not tear down its channel.** The
`POST /devices/{id}/revoke` endpoint called only `Store.Revoke` — a device with
an established secure channel kept sending data and rotating keys indefinitely.
The revocation feature therefore did not work for the very case it is pressed
for. Fixed: `Gateway.RevokeDevice` closes and removes the active session, and
`tcpserver.Server.Disconnect` tears down the socket with an explicit reason
frame.

**[Vulnerability] `device_id` was not validated and went straight into MQTT
topics.** The field from the enrollment request was unconstrained in its
character set and used as-is in `devices/{deviceID}/telemetry`. A device with an
identifier such as `a/#` would have broken the broker's topic structure, since
`#` and `+` are reserved wildcards, and could have intersected unpredictably
with other subscriptions. Fixed: a single validation in
`Gateway.RegisterDevice` — letters, digits, dot, underscore and hyphen, 1 to 128
characters.

**[Robustness] The KEM key was not validated on enrollment.** A device with a
wrongly sized key (a truncated string during manual entry) enrolled
successfully, and the error only surfaced at the first handshake — much later
and with a far less comprehensible message. The format is now checked
immediately.

**[Memory leak] `scheduler.lastFirmwareCheck` grew without bound.** The map
gained an entry for every identifier it saw, but entries for disconnected
devices were never removed. Cleanup was added on every scheduler tick.

**[Usability] Typos in environment variables were silently ignored.** Values
such as `LACERT_EMULATE_DEVICES=5x` were quietly treated as "off" without a
single line in the log. The gateway now warns explicitly about which variable
failed to apply and why.

**[Denial of service, minor] There was no upper bound on `limit`** in
`/api/v1/telemetry` and `/api/v1/rotations`. An inflated value was not
rejected — it is now clamped to a sensible ceiling.

A coverage gap was also closed: `internal/scheduler` had no tests at all — tests
were added for scheduled rotation, scheduled firmware checks and the memory leak
itself.

---

## Stage 8. Three monitoring-dashboard defects

Found during real use of the interface. All three were reproduced and diagnosed
through Playwright before being fixed.

**The page jumped to the top on every auto-refresh.** The cause:
`renderMonitoring` read `container.clientWidth` inside `renderLineChart`, which
forces a synchronous layout recalculation. That recalculation happened at a
moment when the old cards had already been removed and the new ones were not yet
fully added, so the document's total height temporarily shrank. If the scroll
position exceeded that reduced height, the browser immediately pulled it up and
did not restore it once the cards were finished. Fixed in two ways: the build
was split into two passes (all card containers are inserted into the DOM
atomically first, then a chart is added to each), and `.chart-card` was given a
`min-height` so it occupies its final place in the layout in advance. Verified by
a test: the scroll position before and after an auto-refresh now matches,
whereas it previously reset to zero.

**Period filters visibly did not apply.** The cause was a race: the periodic
poll and a click on a range button fire requests almost simultaneously, and the
responses are not guaranteed to arrive in the order they were sent. A response
to a stale request arriving later overwrote the chart with wider data on top of
the filter that had just been applied. The server had been filtering correctly
all along — verified by direct API calls before any frontend changes. Fixed with
a request sequence counter: a response superseded by a newer request is
discarded. The same technique was applied to the rotation log, which was subject
to the same race. Verified live: records "from the past" were deliberately
inserted into the database, and selecting a one-hour range correctly excludes
them.

**The first chart appeared squashed** — its numbers and timestamps became
illegibly small while the others rendered normally. The same underlying layout
recalculation produced this effect too: the grid uses
`grid-template-columns: repeat(auto-fit, minmax(420px, 1fr))`, and when the
width was read for the very first card in the single-pass code, the others had
not yet been added to the DOM. The grid saw a single element and stretched it
across the full width. When the rest were added later the real column width
shrank, but the `viewBox` had already been computed for the wide one. Resolved
by the same two-pass build: the width is read only once the grid holds the
complete set of cards.

---

## Stage 9. The ESP32 firmware

The firmware is implemented, lives in `firmware/` and has been verified on real
boards.

- **Cryptography on the device:** ML-KEM-1024 — PQClean
  (`firmware/components/ml_kem`, rather than liboqs as originally assumed)
  BLAKE3 — a separate component, while ECDSA P-256, ChaCha20-Poly1305 and SHA-256 —
  mbedTLS from the ESP-IDF distribution. Randomness comes from the hardware
  generator (`esp_random`).
- **Code shared with the debug bench:** `lacert_wire.c` and `lacert_client.c`
  are the same files that build for Linux (`firmware/linux-debug/`), which is
  what made it possible to debug the protocol before hardware arrived.
- **Device keys** are generated on first power-up and stored in NVS (modelling
  efuse), so they survive a reboot.
- **Verified on three boards:** XIAO ESP32-C6 (RISC-V), XIAO ESP32-S3 and
  ESP32-S3-DevKitC-1 (Xtensa) all complete the full protocol against the
  gateway. Around 253 KB of free heap remains on the S3 and 303 KB on the C6.
- **Cryptographic measurements were taken on the chips themselves** (the
  `LACERT_BENCH` mode). The headline result: ECDSA runs 7.7× faster on the
  ESP32-C6 than on the ESP32-S3 (22 ms against 170 ms) — even though the C6 is
  the weaker chip in clock speed and core count. The cause is the C6's hardware
  elliptic-curve accelerator, which the S3 lacks. The full table and conclusions
  are in [`FIRMWARE.md`](FIRMWARE.md).

---

## Engineering clarifications to the protocol specification

The protocol description at the sequence-diagram level is not fully detailed in
a few places. The following concrete decisions were made to get the protocol
working.

**1. Both sides hold KEM keys.** For the gateway to encapsulate in Msg2 it needs
the device's ML-KEM-1024 public key — so the device generates its pair during
preparation and hands over the public part at offline enrollment. Likewise the
gateway has its own pair, known to the device at provisioning. This yields
**symmetric rotation**: either side can initiate it, and `Ki+1` is computed
independently on both.

**2. An explicit key-confirmation scheme in Msg3.** The device signs not the
mere fact of decapsulation but the value
`BLAKE3(transcript || "confirm" || K0)`. This provides mutual key confirmation
in a single return trip: if K0 differs between the device and the gateway the
signature will not verify, so the gateway establishes both the device's
authenticity and the correctness of the shared key with one message.

**3. SLH-DSA: measured values, not just theory.** SLH-DSA's advantage in
avoiding elliptic-curve operations is not free:

| Parameter set | Key size | Signature size | Sign | Verify |
|---------------|----------|----------------|------|--------|
| ECDSA P-256 | 65 bytes | 71 bytes | ~30 µs | ~87 µs |
| SLH-DSA-SHA2-128s | 32 bytes | 7,856 bytes | **~915 ms** | ~0.9 ms |
| SLH-DSA-SHA2-128f | 32 bytes | ~17 KB | ~44 ms | ~2.7 ms |

The "s" variant is more compact in signature size, but signs so slowly that on a
microcontroller it would become a practical bottleneck for every rotation and
firmware check. The "f" variant is faster, but a signature of about 17 KB is
itself a burden on transmission. This is a measured trade-off rather than a
declarative claim about reducing load.

The values above were obtained on a server processor. The absolute figures on a
microcontroller will differ, but the relative relationship between the
algorithms holds. Current measurements are in
[`MEASUREMENTS.md`](MEASUREMENTS.md), sections 3.2 and 3.3.

**4. The ML-KEM-1024 sizes are confirmed by the code:** public key — 1,568
bytes, ciphertext — 1,568 bytes, shared secret — 32 bytes.

---

## Directions for further development

Recorded as plans. Not being implemented at this stage.

- **Monitoring through Prometheus and Grafana.** Indicators: process health
  (TCP, MQTT, REST), data throughput, CPU and memory load on the gateway and, in
  time, telemetry from the devices themselves on the same measure. Latency to
  devices, the frequency of rotations and firmware checks, and the number of
  revoked devices. Technically this is added as a `/metrics` endpoint
  (`prometheus/client_golang`) plus a Grafana dashboard on top of it. There is no
  need to design for it in advance — it layers on without reworking the existing
  code.
- **A web page for device enrollment** — an interface over the existing REST API
  (`internal/api`), replacing manual `curl` calls or the `internal/regtool`
  console utility with an administrator form.
