> **Language:** English · [Русский](../ru/ROBUSTNESS.md)

# Improvements: robustness, security, observability

A summary of the changes made to the cryptographic core, the protocol and the
gateway beyond the original version. Each item follows the pattern
"threat/problem → solution → tests".

## 1. Replay protection for the handshake

**Problem.** The `Nonce` field in the first handshake message (Msg1) was not
checked by the gateway — a recorded legitimate Msg1 could be replayed.

**Solution.** The `ReplayGuard` component (`internal/crypto/replay.go`): the
gateway remembers `(DeviceID, Nonce)` pairs and rejects repeats. Entries have a
time-to-live (TTL, 5 minutes by default) with lazy cleanup, so memory does not
grow without bound.

**Tests.** `internal/crypto/replay_test.go`,
`TestHandleMsg1RejectsReplayedNonce` in `internal/gateway`.

## 2. Atomic key rotation with acknowledgment (ACK) and an iteration number

**Problem.** The original rotation updated the initiator's key immediately and
overwrote the old one. Losing a rotation message on the network left the two
sides with different keys and broke the link with no way to recover.

**Solution** (`internal/crypto/rotation_atomic.go`):
- the initiator computes `Ki+1` but keeps encrypting under the current key until
  an ACK arrives (`BeginRotate` / `CommitRotate` / `AbortRotate`)
- every rotation message carries an iteration number cryptographically bound to
  the new key: `Ki+1 = BLAKE3(Ki || Mi || iteration || "rotate_v1")`. This
  protects rotation against replay and detects desynchronization.

Carried through every layer: `wire` (the `TypeRotationV2` and `TypeRotationAck`
types), `device`, `gateway`, `tcpclient`, `tcpserver`.

**Tests.** `internal/crypto/rotation_atomic_test.go` (including
`TestNonAtomicRotationBreaksOnPacketLoss`, which demonstrates the original
problem), end-to-end tests in `internal/transport/tcpserver`.

## 3. Timeout and automatic retry of an unfinished rotation

**Problem.** If no ACK arrived, the session stayed in a "transitional" state
forever and could never rotate again.

**Solution.** `Session.AbortIfStale(timeout)` rolls the rotation back if no ACK
arrives within `RotationAckTimeout` (5 s). The scheduler
(`internal/scheduler`) rolls back a stuck rotation and starts it over. A failed
attempt is written to the log.

**Tests.** `TestAbortIfStale*` in crypto, `TestSchedulerRollsBackStaleRotation`.

## 4. Timeout on the firmware integrity response

**Problem.** A challenge response was accepted regardless of its age — a window
for replaying a pre-prepared (challenge, response) pair.

**Solution.** A validity window, `firmwareResponseValidity` (15 s): a response to
a stale challenge is rejected (the device is not revoked in this case, since the
response itself is correct — only its timing is wrong).

**Tests.** `TestFirmwareChallengeExpires*` in `internal/gateway`.

## 5. Timeout on an unfinished handshake

**Problem.** An unfinished handshake held secret material (`sharedSecret`) in
memory indefinitely.

**Solution.** `pendingHandshakeTimeout` (20 s): a late Msg3 is rejected, and
stale entries are cleaned up on a new Msg1, with the secret wiped.

**Tests.** `TestPendingHandshake*` in `internal/gateway`.

## 6. Aggregated metrics (observability)

The `Metrics` component (`internal/gateway/metrics.go`) provides thread-safe
counters: handshakes (completed/rejected), replays blocked, rotations
(succeeded/failed), firmware checks (passed/failed/rejected), devices revoked.
Available through `GET /api/v1/metrics`.

**Tests.** `TestMetrics*` in `internal/gateway`.

## 7. Graceful shutdown with key wiping

**Problem.** When the gateway stopped, active sessions with their keys remained
in memory.

**Solution.** `Gateway.Shutdown()` closes every session (wiping the keys) and
clears unfinished state. It is called from `cmd/gatewayd` after the network
listeners are closed. In addition, `Session.Close()` now also wipes the "pending"
key of an unfinished rotation.

**Tests.** `TestGatewayShutdownClosesSessionsAndZeroizes`.

---

## Testing summary

- All packages build and `go vet` reports nothing.
- All unit and integration tests pass.
- The data-race detector (`go test -race`) is clean across every package.
- An end-to-end live run of the gateway with emulated devices was carried out:
  handshake, telemetry, atomic rotation, firmware check with revocation, replay
  protection and graceful shutdown were all confirmed.

---

## Code audit: problems found and fixed

A complete audit of the code (backend and frontend) was carried out after all
the improvements.

### 1. The emulator was using the obsolete (non-atomic) rotation
**Problem.** The scheduler and all the rest of the code had moved to atomic
rotation with ACKs, but the device emulator kept calling the old
`RotateIfNeeded()` (non-atomic, vulnerable to packet loss). As a result the
emulated devices were not exercising the new, safe path.
**Fix.** The emulator was moved to `RotateIfNeededAtomic()`. Verified by a live
run: rotation completes with an ACK and the iteration number increases.

### 2. Duplicated `device_id` field in structured logs
**Problem.** The client's base logger already carried `device_id` (the emulator
created it via `.With("device_id", ...)`), while individual log calls added the
field again — the output read `device_id=X device_id=X`.
**Fix.** `device_id` is now set once, in `tcpclient.Dial`. The repeated additions
were removed. The duplication in the logs is gone.

### 3. Buffer overflow in the firmware when parsing the ML-KEM ciphertext

**Problem.** In `lacert_client.c` the length of the ML-KEM ciphertext was taken
from the frame and never checked against `LACERT_KEM_CIPHERTEXT_SIZE` (1568
bytes). The length field is 16-bit and the frame is capped only at 64 KiB, so a
single Msg2 produced two defects at once:

- `build_msg2_bytes` wrote `2 + length + 32` bytes into the stack buffer `m2`,
  sized `8 + 1568 + 32` = 1608 bytes — a stack overflow of up to ~64 KiB
- `lacert_kem_decapsulate` reads exactly 1568 bytes regardless of the declared
  length, so a shorter field made it read past the end of the received buffer.

The same oversight was present in rotation handling (`handle_rotation_v2`) —
without the write there, but with the same out-of-bounds read.

Notably, the device does not authenticate the gateway (see `PROTOCOL_SPEC.md`,
section 3), so such a frame can be sent by anyone who can reach the network, not
only by the genuine gateway.

**Fix.** Both places now check `kem_ct_len != LACERT_KEM_CIPHERTEXT_SIZE` and
return `LACERT_ERR_DECODE`. Confirmed under AddressSanitizer: before the fix,
writing 60,034 bytes into a 1608-byte buffer was reported as an overflow. After
it, the frame is rejected with no out-of-bounds access. Absence of regression was
checked as well: the client completes the handshake, sends telemetry and answers
the firmware integrity challenge.

**Why the gateway is unaffected.** In Go the same parsing is guarded by
`len(ciphertext) != mlkem1024.CiphertextSize` (`internal/crypto/identity.go`),
and a slice bounds violation would raise a panic rather than corrupt memory. The
defect class is specific to C: where Go is safe by construction, the firmware
needs an explicit check — and one of the three was missing (the challenge parser
had it from the start).

### Reviewed and found correct
- **The dashboard's time filters (30 min / 1 / 6 / 12 / 24 h)** work through the
  whole chain: button → JS state → the `since`/`until` query parameters →
  parsing in the API → filtering in storage. Confirmed by a dedicated test
  (30 min → 2 points, 1 h → 3, no filter → 4) and by a live run.
- **Race protection for telemetry/rotation requests** (`monRequestSeq`,
  `rotRequestSeq`) is correct — stale responses are discarded.
- **Tab switching and polling** create no extra load, since only the active tab is
  refreshed.
- **`cmd/demo`** deliberately uses non-atomic rotation as a simple illustration
  of the UML sequence. It is a documented teaching artifact, not a production
  path.

### Metrics surfaced on the web dashboard
- A "metrics" tab was added to the dashboard: cards with counters for
  handshakes, rotations, firmware checks, blocked replays and device
  revocations, grouped into sections. They refresh automatically on polling and
  on demand via a button. The "alarming" counters (replays, failed checks,
  revocations) are highlighted when non-zero. The data comes from
  `GET /api/v1/metrics`.

---

## Visual polish and responsiveness of the dashboard

The web dashboard was refined visually and made responsive (sizing itself to the
window) while keeping the original "console/control panel" concept: monospaced
type, amber accents, a dark theme and no external CDNs.

### Visual refinement
- Subtle depth on panels and cards (soft shadows in the spirit of an instrument
  console).
- Smooth hover effects on metric cards and charts (a slight lift, a highlighted
  border).
- An amber top rule on "alarming" metric cards when their value is non-zero.
- Tidy focus states (`:focus-visible`) for keyboard navigation.
- Respect for `prefers-reduced-motion` (animations are disabled per the OS
  setting).

### Responsiveness (automatic sizing)
- The container is fluid: padding via `clamp()`, maximum width raised to 1440 px
  (less wasted space on wide monitors).
- Breakpoints (`@media`): tablet (≤900 px), phone (≤560 px), very narrow screens
  (≤380 px).
- On narrow screens: the navigation moves to its own scrollable row, charts
  stack into a single column, the range panel and the metrics reflow, and
  secondary header elements are hidden.
- Tables are wrapped in a horizontally scrollable container, so they do not
  stretch the page on a phone.

Verified by rendering in a browser (headless Chromium) at three sizes — desktop
1440 px, tablet 820 px, phone 380 px: every tab (devices, monitoring, rotations,
metrics) adapts correctly and stays readable.

---

## Fixes from server-side feedback

### 1. The "refresh" button on monitoring did not reset the range
**Problem.** After a custom date range was chosen, the ↻ button simply reloaded
the data for the same range without clearing the search.
**Fix.** The refresh button now clears the `since`/`until` date fields, returns
the selection to the default period (1 hour) if a custom range was set, and
reloads the data.

### 2. Metric values were pushed to the left
**Problem.** The numbers and labels in the metric cards were left-aligned.
**Fix.** The contents of the metric cards are now centered both horizontally and
vertically, and the cards were given a minimum height for consistency.

### 3. Monitoring showed only about 25 minutes of data regardless of the period
**Problem (the main one).** Whichever period was selected (30 min / 1 / 6 / 12 /
24 h), the chart showed only the last ~25 minutes. The cause: the telemetry
query was truncated by the NUMBER of records (a 5,000 limit) before it was
truncated by TIME. With several devices and frequent telemetry, 5,000 records
covered only ~25–33 minutes, so older data within the selected period simply
never made it in.
**Fix.** The upper bound of the query was raised from 5,000 to 50,000 (both in
the API and in storage), which covers a 24-hour range for several devices. The
limit is now applied as a safety net AFTER filtering by time, so the chart shows
the whole selected period. Confirmed by a test: 5,490 records over an hour are
returned in full, with the oldest point exactly 60 minutes back.

---

## Second round of fixes from server-side feedback

### 1. The page jumped to the top on auto-refresh when scrolled down
**Problem.** During auto-refresh (every 3 s) redrawing the tables through
`innerHTML` briefly reduced the document height, and the browser pulled the
scroll position up without restoring it.
**Fix.** The scroll position (`scrollY`) is captured before the refresh cycle and
restored after the DOM is redrawn (on the next frame). Verified in a browser:
after scrolling down and two auto-refreshes the position is preserved with no
shift.

### 2. The time filter (30 min / 1 h / …) did not apply on a server with a non-UTC timezone
**Problem (the main one).** On a server in a timezone other than UTC (for
example UTC+3), querying telemetry by period returned almost nothing: telemetry
was stored in the server's local time while the range boundaries arrived from
the frontend in UTC, so the time comparison was offset by the timezone. The
charts therefore did not change when the period changed (although searching by a
specific date did work, because there the user entered the time manually).
**Fix.** All telemetry timestamps are now stored in UTC (`time.Now().UTC()` in
the gateway and in the stores), and the range boundaries (`since`/`until`) are
explicitly converted to UTC in the API and in `pgstore`. The filter now behaves
identically regardless of the server's timezone. Verified by a live run under
`TZ=Europe/Moscow` (UTC+3): a "last 30 minutes" query returned every recent
point, as expected.

### 3. CRITICAL: failed rotations accumulated indefinitely without revoking the device
**Problem.** 54 consecutive failed rotations were observed while data kept
flowing under the old key and the device was not revoked. Two causes:
  (a) **a duel of initiators** — both the emulator (the device) and the scheduler
      (the gateway) started rotations on their own timers at nearly the same
      moment. The opposing rotation could not begin (the session was already in
      the pending state), no ACK arrived, and the attempts were rolled back on
      timeout indefinitely
  (b) **no threshold** — failed rotations had no counter after which the device
      would be revoked.
**Fix.**
  (a) Rotation is now initiated ONLY by the gateway (through the scheduler), so
      there is a single initiator. The device merely responds to the gateway's
      rotation.
  (b) The scheduler counts consecutive failed rotations per device and, after
      `MaxConsecutiveRotationFailures` (=3), revokes the device (closing the
      session and wiping the keys). The counter resets on a successful rotation.
Verified by a test: after 3 unacknowledged rotations in a row the device is
revoked and the `devices_revoked` metric increases.

---

## Comprehensive stress test of every defense mechanism (5 devices)

An integration test, `TestStressAllDefenseMechanisms`
(`internal/gateway/stress_test.go`), was added. It exercises every defense
mechanism simultaneously across five devices, each reproducing its own failure
scenario. Time is controlled manually, so the test is deterministic.

Scenarios and the metrics they check:
  D1 — intermittent rotation failures (2 in a row, below the ban threshold of 3):
       verifies that `rotations_failed` grows but the device is NOT revoked, and
       that it then rotates successfully (`rotations_succeeded`).
  D2 — replay attacks on the handshake: `replays_blocked` +
       `handshakes_rejected`.
  D3 — handshake with a corrupted Msg3 signature: `handshakes_rejected`.
  D4 — a late response to a firmware check (the challenge has expired):
       `firmware_checks_rejected`.
  D5 — passes 2 firmware checks, then the firmware is swapped → failure →
       revocation: `firmware_checks_passed`, `firmware_checks_failed`,
       `devices_revoked`.

Final metrics for the run: `handshakes_completed=3`, `handshakes_rejected=4`,
`replays_blocked=3`, `rotations_succeeded=1`, `rotations_failed=2`,
`firmware_checks_passed=2`, `firmware_checks_failed=1`,
`firmware_checks_rejected=1`, `devices_revoked=1`. Every assertion holds: the
mechanisms work correctly and do not interfere with one another. To run:
`go test -run TestStressAllDefenseMechanisms -v ./internal/gateway/`

---

## Live stress test against a running gateway (`cmd/stresstest`)

In addition to the in-process `TestStressAllDefenseMechanisms`, the
`cmd/stresstest` tool was added — a "live" stress test that connects over a REAL
NETWORK to a running `cmd/gatewayd`, enrolls 5 devices through REST and
reproduces its own failure scenario on each (the same D1–D5). Before and after
the run it reads the gateway's metrics through `/api/v1/metrics` and shows the
changes. The same values are visible in real time on the dashboard's "metrics"
tab.

To let the demonstration finish quickly, the scheduler intervals were made
configurable through the gateway's environment variables (production uses the
defaults):
  `LACERT_ROTATION_INTERVAL`     — rotation interval by time (default 300 s)
  `LACERT_ROTATION_ACK_TIMEOUT`  — how long to wait for a rotation ACK (default 5 s)
  `LACERT_ROTATION_CHECK_PERIOD` — the scheduler's polling period (default 5 s)
  `LACERT_FIRMWARE_INTERVAL`     — how often to check firmware (default 1 h)
  `LACERT_FIRMWARE_VALIDITY`     — validity window for a challenge response (default 15 s)

Run it in a single command (starts the gateway in demo mode and runs the attack):
  `bash deploy/run-live-stress.sh`

Verified by a live run: all 9 metrics genuinely change on a running gateway —
handshakes (completed/rejected), replays blocked, rotations failed, firmware
checks (passed/failed/rejected-as-stale) and device revocations.

---

## Every timing parameter made configurable through the environment (bench tuning)

To make it possible to find optimal values on a test bench before moving to a
production system with ESP32 devices, all of the system's timing parameters can
now be overridden through the gateway's environment variables, without changing
code. If a variable is not set, the production default applies.

Configurable parameters (the full table and recommendations are in `TUNING.md`):
  `LACERT_ROTATION_INTERVAL` (300 s), `LACERT_ROTATION_PACKET_LIMIT` (300),
  `LACERT_ROTATION_ACK_TIMEOUT` (5 s), `LACERT_ROTATION_CHECK_PERIOD` (5 s),
  `LACERT_MAX_ROTATION_FAILURES` (3), `LACERT_FIRMWARE_INTERVAL` (1 h),
  `LACERT_FIRMWARE_VALIDITY` (15 s), `LACERT_FIRMWARE_CHALLENGE_TIMEOUT` (25 s),
  `LACERT_PENDING_HANDSHAKE_TIMEOUT` (20 s), `LACERT_NONCE_TTL` (5 m).

Verified: the gateway logs every applied override at startup.

---

## Updated default timeouts + a template in `.env`

Following the bench tuning, the STATIC defaults in the code were updated (they
apply when a parameter is not set in `/etc/lacert/gatewayd.env`):
  `RotationAckTimeout`:       30 s → 5 s
  `firmwareResponseValidity`: 90 s → 15 s
  `firmwareChallengeTimeout`: 2 m  → 25 s
  `pendingHandshakeTimeout`:  60 s → 20 s
The remaining defaults are unchanged (`RotationInterval` 300 s,
`FirmwareCheckInterval` 1 h, `DefaultNonceTTL` 5 m,
`MaxConsecutiveRotationFailures` 3, `RotationCheckPeriod` 5 s,
`RotationPacketLimit` 300).

The `/etc/lacert/gatewayd.env` generated by `install.sh` gained a block listing
ALL the timing parameters, commented out (`#`), with an explanation and the stock
value for each. While a line stays commented the default from the code applies
uncommenting it overrides that. This puts the complete list of configurable
timeouts in front of the administrator.

## Code and documentation audit: findings and fixes

What follows are the results of a full review of the code and documentation,
carried out after all of the work described above.

### 1. Data packets had no replay protection
**Problem.** `ReplayGuard` only covered the handshake (the Msg1 nonce). Data
packets were not checked at all: ChaCha20-Poly1305 proves a packet is authentic
and unmodified, but says nothing about whether it has been seen before. A
captured telemetry packet decrypted just fine on every replay and was stored as
a fresh reading each time — data forgery without a single corrupted byte.
**Fix.** A per-session window of accepted nonces
(`internal/crypto/replay_data.go`): the nonce is unique per key by
construction, so remembering the ones accepted under the current Ki is enough.
Rotation clears the window, whose size is bounded. The frame format is
unchanged, so the ESP32 firmware needs no modification. Blocked replays are
exposed as the `data_replays_blocked` metric.
**Tests.** `internal/crypto/replay_data_test.go`,
`TestHandleDataRejectsReplayedPacket` in `internal/gateway`.

### 2. Sessions were not released when a connection ended
**Problem.** `tcpserver` only removed the connection entry, while
`Gateway.sessions` kept the session key of every device that had ever connected
until revocation or process shutdown — contradicting the very PFS hygiene that
`Session.Close()` exists for.
**Fix.** `Gateway.CloseSessionInstance(deviceID, session)` is called when a
connection is done being served. It compares the session pointer rather than
just the device ID: the device may have reconnected, and an old goroutine
finishing up must not tear down the new connection's channel.
**Tests.** `TestSessionIsClosedWhenConnectionEnds`,
`TestReconnectKeepsExactlyOneLiveSession` in `internal/transport/tcpserver`.

### 3. A fast reconnect broke BOTH connections
**Problem.** Pending handshakes were keyed by `deviceID` alone. If a device
opened a second connection before the gateway had finalized the first (a board
reboot or Wi-Fi flap — routine for ESP32), the second Msg1 overwrote the first's
state. The first connection's Msg3 was then verified against the wrong
transcript and rejected as an invalid signature, and the second connection's
Msg3 no longer found its own entry. The device was left with no channel and
looked like a source of failed handshakes in the log.
**Fix.** Each handshake attempt now carries an identifier
(`HandleMsg1Tracked` / `HandleMsg3Tracked`). A superseded connection gets
`ErrHandshakeSuperseded` and closes without taking the newer state with it.
**Tests.** `TestRapidReconnectStillEstablishesChannel` in `internal/transport/tcpserver`.

### 4. Socket writes without a deadline stalled the scheduler
**Problem.** Frame writes never set `SetWriteDeadline`. A device that stopped
reading its socket (full receive buffer, TCP zero window) blocked the write
forever. Since rotation and firmware checks are issued under `ioMu` by the
scheduler, which walks devices sequentially in a single goroutine, one stuck
device halted key rotation for ALL the others.
**Fix.** `tcpserver.WriteTimeout` (15 s) on every frame write.

### 5. Other audit findings
- The obsolete non-atomic rotation (type 4) is no longer accepted: the frame is
  not authenticated in any way, and `Session.Rotate()` does not advance the
  iteration counter, so a single such frame would desynchronize atomic rotation.
- `ApplyRotationAck` checks and commits under a single mutex acquisition
  (previously there was a window between the two).
- After revoking a device, the scheduler now drops its TCP connection (only the
  REST revoke handler did so before) and prunes all of its state maps, not just
  `lastFirmwareCheck`.
- `putFramed` explicitly rejects fields longer than 65535 bytes instead of
  silently truncating the length to `uint16`.
- REST: the registration request body is size-limited, and a revoked device is
  recognized via `errors.Is` rather than `==` comparison.
- The installer creates the env file with mode 600 before writing secrets to it.
