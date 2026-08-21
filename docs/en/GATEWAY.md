> **Language:** English · [Русский](../ru/GATEWAY.md)

# The LACERT gateway — architecture and API

The gateway (`cmd/gatewayd`) is a self-contained network service written in Go.
It accepts device connections over TCP, runs the LACERT protocol with them,
stores devices and telemetry, serves a REST API and a web dashboard, and
publishes data to MQTT.

## Layers

```
                    ┌─────────────────────────────────────┐
   devices ──TCP──► │ transport/tcpserver → gateway        │
   (ESP32)   :7700  │   handshake, data, rotation,         │
                    │   firmware integrity checks          │
                    ├─────────────────────────────────────┤
   browser ─HTTP──► │ api (REST) + webui (dashboard) :8080 │
   admin/scripts    ├─────────────────────────────────────┤
   subscribers ───► │ mqttbridge (broker)            :1883 │
                    ├─────────────────────────────────────┤
                    │ scheduler — background rotations     │
                    ├─────────────────────────────────────┤
                    │ store — memstore | pgstore (Postgres)│
                    └─────────────────────────────────────┘
```

Packages:

- **`internal/gateway`** — the core: session state, initiating rotations,
  issuing and verifying firmware challenges, handling ACKs, revoking devices.
- **`internal/transport/tcpserver`** — accepting TCP connections, reading and
  writing frames, passing them to the gateway.
- **`internal/wire`** — binary framing (see [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md)).
- **`internal/crypto`** — ML-KEM-1024, ECDSA P-256, BLAKE3, ChaCha20-Poly1305,
  key derivation and rotation.
- **`internal/api`** — REST built on `chi`, Bearer-token authentication.
- **`internal/webui`** — the dashboard (HTML/CSS/JS, embedded into the binary
  via go:embed).
- **`internal/store`** — the storage interface. There is `memstore` (in memory) and
  `pgstore` (PostgreSQL through gorm, tables `devices`, `telemetry_readings`,
  `key_rotations`, `session_events`).
- **`internal/scheduler`** — walks active sessions on a timer and triggers key
  rotations and firmware checks.
- **`internal/mqttbridge`** — the embedded MQTT broker (`mochi-mqtt`)
  decrypted telemetry goes to `devices/{id}/telemetry`, events to
  `devices/{id}/events`.
- **`internal/telemetry`** — parsing payloads and recording readings.

## Ports (defaults)

| Port | Purpose | Variable |
|------|---------|----------|
| `:7700` | device TCP protocol | `LACERT_TCP_ADDR` |
| `:8080` | REST API + dashboard | `LACERT_HTTP_ADDR` |
| `:1883` | MQTT broker | `LACERT_MQTT_ADDR` |

For devices on the local network to connect, the listeners must bind all
interfaces (`:7700`, not `127.0.0.1:7700`).

## REST API

Base path `/api/v1`, JSON throughout.

### Public (no token)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | liveness probe, returns `ok` |
| GET | `/api/v1/gateway` | the gateway's public ML-KEM key |

`/api/v1/gateway` is intentionally open: the firmware requests it at startup,
before the first handshake, when it has no token yet. The key itself is public,
so there is nothing to hide. Operational fields of the response (such as
`log_session_keys`, which tells whether the gateway writes session keys to its
log) are returned only with a valid token — an outsider has no business knowing
how the gateway is configured.

Note that in the current scheme the shared secret is encapsulated under the
**device's** public key (see [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md), section 3.2), so the gateway's
own public key takes no part in the handshake: the firmware retrieves it but
never uses it.

### Counters at `/api/v1/metrics`

Metrics live in process memory and reset when the gateway restarts. They are
shown on the dashboard's "Metrics" tab.

| Field | What it counts |
|-------|----------------|
| `handshakes_completed` | successfully completed handshakes |
| `handshakes_rejected` | rejected handshakes (bad signature, unknown or revoked device) |
| `replays_blocked` | blocked replays: a frame with an already-used nonce |
| `rotations_succeeded` | key rotations acknowledged by the device (ACK received) |
| `rotations_failed` | failed rotation attempts — bad tag, stale iteration, or ACK timeout |
| `rotation_timeouts` | rollbacks on ACK timeout, when no ACK arrived in time (also included in `rotations_failed`) |
| `firmware_checks_passed` | firmware integrity checks that passed |
| `firmware_checks_failed` | checks that failed (signature mismatch or firmware hash mismatch) |
| `firmware_checks_rejected` | responses rejected as stale (later than `LACERT_FIRMWARE_VALIDITY`) |
| `devices_revoked` | revoked devices |
| `data_replays_blocked` | data packets rejected as replays (nonce already seen under the current key) |
| `telemetry_dropped` | accepted readings that could not be written to storage |

The `telemetry_dropped` counter deserves separate attention: it grows when a
packet was received and decrypted successfully but the write to storage failed
(for example, the database is unavailable). Packet processing is not interrupted
in that case — tearing down the session because of a storage problem would turn
a database failure into a loss of connectivity. The readings, however, are lost
for good, so a non-zero value calls for investigating the database rather than
merely being watched.

The distinction between `failed` and `rejected` for firmware checks matters:
**failed** means the device answered but the answer did not match — a sign of
firmware tampering, which leads to revocation. **rejected** means the answer
arrived too late, usually due to a slow network, and does not lead to
revocation.

### Protected (Bearer token)

If `LACERT_ADMIN_TOKEN` is set, these routes require the header
`Authorization: Bearer <token>`. If no token is set, authentication is disabled
— convenient for local development, **not for production**.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/devices` | list devices and their status |
| POST | `/api/v1/devices` | enroll a device |
| GET | `/api/v1/devices/{id}` | device details |
| GET | `/api/v1/devices/{id}/events` | device event log |
| PUT | `/api/v1/devices/{id}` | re-enrol: replace the keys of an existing device |
| DELETE | `/api/v1/devices/{id}` | remove the record entirely, history included |
| POST | `/api/v1/devices/{id}/revoke` | revoke a device |
| GET | `/api/v1/telemetry` | telemetry readings |
| GET | `/api/v1/rotations` | key-rotation log |
| GET | `/api/v1/firmware-checks` | firmware integrity check log (`?device_id=`, `?limit=`) |
| GET | `/api/v1/metrics` | gateway counters (see below) |

### Re-enrolment and deletion

Three actions on a device record mean different things, and they are worth
keeping apart.

**Revocation** is a decision about trust. The record stays in the registry along
with the reason, the device remains visible to the operator, and it no longer
completes a handshake. This is what happens when a firmware integrity check
fails or a device goes missing.

**Re-enrolment** replaces the keys of a device that lost them: the board's
memory was erased, the board was swapped while keeping its identifier, or the
firmware was reflashed and generated a fresh pair. History is preserved — the
event log, the accumulated telemetry and the date of first enrolment all stay.
An active session is closed, since it runs on the old key.

A revoked device cannot be re-enrolled. Replacing keys does not lift a
revocation, and silently returning a board revoked on suspicion of firmware
tampering would be wrong. If that is genuinely intended, the record is deleted
first.

**Deletion** is housekeeping. The record disappears together with its log and
telemetry, and the identifier becomes free again. This is for records created by
mistake or made for testing. For a device that has been in service, revocation is
usually the better fit: it leaves a trace.
### Enrolling a device (POST /devices body)

```json
{
  "device_id": "xiao-esp32-1",
  "identity_pub_hex": "04....",        // ECDSA P-256, 65 bytes
  "kem_pub_hex": "....",               // ML-KEM-1024 pub, 1568 bytes
  "firmware_hash_hex": "....",         // SHA-256 of the firmware image, 32 bytes
  "checksum": "....",                  // hex(BLAKE3(id||idPub||kemPub||fwHash))[:8]
  "sig_algorithm": "ecdsa-p256"
}
```

Re-enrolling the same `device_id` with the same keys returns 400/409, and that
is **expected** — the device is simply already known. Enrolling the same
`device_id` with **different** keys, however, is rejected, and such a device
will fail the handshake. This is the protection against impersonation. Every
physical board must therefore have a unique `device_id`.

## Configuration

Everything is set through environment variables. **The full reference of all 25
variables with their defaults is in [`CONFIG.md`](CONFIG.md)**. The reasoning
behind the timings and advice on choosing them is in [`TUNING.md`](TUNING.md).
The key ones:

| Variable | Purpose |
|----------|---------|
| `LACERT_HTTP_ADDR`, `LACERT_TCP_ADDR`, `LACERT_MQTT_ADDR` | listen addresses |
| `LACERT_ADMIN_TOKEN` | token for protected REST routes |
| `LACERT_PG_DSN` | PostgreSQL connection string (without it, memory is used) |
| `LACERT_ROTATION_INTERVAL` | key rotation period (300 s by default) |
| `LACERT_FIRMWARE_INTERVAL` | firmware check period (1 h by default) |
| `LACERT_CORS_ORIGINS` | allowed origins for the dashboard |

Diagnostic variables (`LACERT_LOG_SESSION_KEYS`, `LACERT_EMULATE_DEVICES` and
so on) are meant for debugging and **must be switched off in production**.

## Variables for the helper utilities

These belong to the tools under `cmd/` rather than to the gateway itself, and
are useful when testing without real boards:

| Variable | Utility | Purpose |
|----------|---------|---------|
| `LACERT_GATEWAY_HTTP` | `devicesim`, `stresstest` | gateway REST address (default `http://localhost:8080`) |
| `LACERT_GATEWAY_TCP` | `devicesim`, `stresstest` | gateway TCP address (default `localhost:7700`) |
| `LACERT_DEVICE_ID` | `devicesim` | identifier of the simulated device |
| `LACERT_PROFILE` | `devicesim` | sensor profile (which telemetry fields to send) |
| `LACERT_STRESS_WAIT` | `stresstest` | pause before the scenarios start |
| `LACERT_STRESS_D4_DELAY` | `stresstest` | response delay in scenario D4 (checks that a stale challenge is refused) |
| `LACERT_TEST_PG_DSN` | `pgstore` tests | connection to a test database. Without it the PostgreSQL tests are skipped |

## Robustness and resource limits

**HTTP timeouts.** The server sets `ReadHeaderTimeout` (10 s), `ReadTimeout`
(30 s), `WriteTimeout` (60 s), `IdleTimeout` (120 s) and a header size limit
(1 MB). Without them a slow or hostile client could hold connections open
indefinitely and exhaust resources (slowloris) — Go's `http.Server` sets no
timeouts by default.

**TCP timeouts.** Device connections carry read deadlines, and incomplete
handshakes expire after `LACERT_PENDING_HANDSHAKE_TIMEOUT`.

**Memory limits without a database.** When `LACERT_PG_DSN` is unset the gateway
keeps everything in memory. Those logs are bounded (100k telemetry records,
50k events and 50k rotations) with the oldest entries evicted: without this,
ten devices reporting every 2 s would grow the process by about 80 MB per day
and it would run out of memory within a week. Use PostgreSQL for real history.

**Indexes.** The dashboard's main queries ("the last N records for a device")
rely on composite indexes `(device_id, created_at DESC)` on telemetry,
rotations and events, plus a separate index on `event_type` for the firmware
check tab. With separate indexes PostgreSQL had to select every record for the
device and sort them. With composite ones it reads exactly the rows it needs in
the right order (0.25 ms instead of 1.0 ms at 300k records, and the gap widens
as history grows). The indexes are created automatically during migration.

**Recovery from failures.** A panic in one connection handler is caught and does
not bring the gateway down. Shutdown on `SIGTERM`/`SIGINT` is graceful: the
server waits for in-flight requests and closes sessions.

## Behavior under load (measured)

Load test against a real PostgreSQL, on **a single CPU core**, with emulated
devices sending telemetry every 2 s, rotating keys every 30 s and running
firmware checks every minute — noticeably harsher than the production defaults
of 300 s and 1 h:

| Devices | CPU | Memory | `/devices` latency | Failures |
|---------|-----|--------|--------------------|----------|
| 10 | 0.4 % | 20 MB | 3 ms | 0 |
| 100 | 3.3 % | 34 MB | 13 ms | 0 |
| 250 | 7.7 % | 57 MB | 12 ms | 0 |
| 500 | 12.4 % | 93 MB | 26 ms | 0 |

Every device comes online, and rotations and integrity checks complete without a
single failure. Resource use grows linearly: roughly **0.025 % CPU and 0.15 MB
of memory per device**.

Cryptography is not the bottleneck: on the server a handshake takes a fraction
of a millisecond and a rotation tens of microseconds. It is expensive only on
the microcontroller itself — see [`FIRMWARE.md`](FIRMWARE.md). What limits the system is the
database and the network, not computation.

Two problems were found and fixed as a result of these measurements:

- **The device list issued N+1 queries.** `/api/v1/devices` fetched the latest
  telemetry separately for every device, which meant 500 SQL queries for a
  single dashboard load at 500 devices. It is now a single query
  (`DISTINCT ON`) for all of them, and latency dropped from 180 ms to 26 ms.
- **The database connection pool was unbounded.** With a thousand devices
  connecting at once the gateway kept opening connections until PostgreSQL
  started replying "too many clients" (its limit is 100), and some devices could
  not complete the handshake. The pool is now capped, and queries wait for a free
  connection instead of failing.

## Deployment

```bash
sudo bash deploy/bare-metal/install.sh
```

This installs the binaries into `/opt/lacert/bin/` (`gatewayd`, `devicesim`),
the configuration into `/etc/lacert/gatewayd.env`, and sets up the
`lacert-gatewayd` systemd service. The script is idempotent and does not
overwrite an existing `.env`. Management:

```bash
systemctl status lacert-gatewayd
sudo systemctl restart lacert-gatewayd
journalctl -u lacert-gatewayd -f
```

## Working with devices (PostgreSQL)

List them:
```bash
psql "$LACERT_PG_DSN" -c "SELECT device_id, status FROM devices;"
```

Delete a device — for example after erasing NVS, to reuse the id:
```bash
psql "$LACERT_PG_DSN" -c "DELETE FROM devices WHERE device_id='xiao-esp32-1';"
```

## Production build

For production it is worth building the gateway without the diagnostic parts:
exclude `cmd/demo`, `cmd/stresstest`, `cmd/devicesim` and `internal/emulator`,
switch off `LACERT_EMULATE_DEVICES` and `LACERT_LOG_SESSION_KEYS`, set
`LACERT_ADMIN_TOKEN`, and configure `LACERT_CORS_ORIGINS` for your domain.
