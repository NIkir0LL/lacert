> **Language:** English · [Русский](../ru/CONFIG.md)

# Gateway configuration — the complete `.env` reference

The gateway is configured exclusively through environment variables. In a
production deployment they live in **`/etc/lacert/gatewayd.env`** and are picked
up by the systemd service (`lacert-gatewayd`).

> **Important.** If you launch the binary by hand (`./gatewayd`), the variables
> from `/etc/lacert/gatewayd.env` are **not** loaded — the gateway starts with
> its defaults, meaning no database (in-memory) and no authorization. To run it
> manually:
> ```bash
> sudo bash -c 'set -a; source /etc/lacert/gatewayd.env; set +a; /opt/lacert/bin/gatewayd'
> ```

The reasoning behind the timing values and advice on choosing them is in
[`TUNING.md`](TUNING.md). This document is the complete list.

---

## Network

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_TCP_ADDR` | `:7700` | address of the device TCP protocol |
| `LACERT_HTTP_ADDR` | `:8080` | address of the REST API and dashboard |
| `LACERT_MQTT_ADDR` | `:1883` | address of the embedded MQTT broker |
| `LACERT_CORS_ORIGINS` | unset | allowed external origins for browser requests (e.g. `https://lacert.example.com`). When unset, cross-origin requests are not permitted: the built-in dashboard is served from the same address and does not need them. Setting `*` opens the API to any site — use it deliberately |

For boards on the local network to connect, the address must bind all
interfaces (`:7700`), not `127.0.0.1:7700`.

## Storage

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_PG_DSN` | unset | PostgreSQL connection string |

**If `LACERT_PG_DSN` is unset the gateway runs in memory** and loses every
device and all telemetry on restart. A warning appears in the log at startup.
For production use it must be set:

```
LACERT_PG_DSN=host=localhost user=lacert password=... dbname=lacert port=5432 sslmode=disable
```

## Security

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_ADMIN_TOKEN` | unset | token for protected REST routes (`Authorization: Bearer <token>`) |
| `LACERT_NONCE_TTL` | `5m` | lifetime of a nonce in replay protection |

If no token is set, **REST authorization is disabled** — suitable only for local
development. The same token goes into the board's firmware
(`LACERT_ADMIN_TOKEN` in `main.c`), which presents it during enrollment.

## Key rotation

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_ROTATION_INTERVAL` | `300s` | how often to rotate the session key |
| `LACERT_ROTATION_PACKET_LIMIT` | `300` | also rotate after this many packets under one key |
| `LACERT_ROTATION_ACK_TIMEOUT` | `5s` | how long to wait for the device's rotation acknowledgment (ACK) |
| `LACERT_ROTATION_CHECK_PERIOD` | `5s` | how often the scheduler walks the sessions |
| `LACERT_MAX_ROTATION_FAILURES` | `3` | how many consecutive failed rotations before a device is revoked |

### How the time before a retry is calculated

The scheduler runs in ticks of `ROTATION_CHECK_PERIOD`. On each tick it first
checks whether a rotation already sent has been hanging longer than
`ROTATION_ACK_TIMEOUT`, and only then decides whether to start a new one.

So if a device **does not answer**:

```
t = 0                      gateway sent the rotation, waiting for the ACK
t < ACK_TIMEOUT            ticks pass, the rotation is not yet counted as failed
first tick after
ACK_TIMEOUT                the hung rotation is rolled back, failure #1 recorded
next tick                  a new rotation attempt
```

**Time before a retry ≈ `ACK_TIMEOUT` + up to 2 × `CHECK_PERIOD`.**

Example (a common demonstration setup: `ACK_TIMEOUT=5s`, `CHECK_PERIOD=2s`):
rollback around second 6, retry around second 8 — that is, a new attempt roughly
**every 8–10 seconds**.

After `MAX_ROTATION_FAILURES` consecutive failures (3 by default, so about
25–30 s in this example) the gateway **revokes the device**: continuing to
exchange data when the key cannot be changed is unsafe. The failure counter is
**reset by the first successful rotation**, so isolated connectivity glitches do
not accumulate into a revocation.

For reference: a rotation on the board itself (ML-KEM decapsulation plus BLAKE3
key derivation) takes 18–26 ms, so a 5-second timeout leaves a two-hundred-fold
margin. If rotations are failing, the cause is lost connectivity rather than
insufficient performance.

## Firmware integrity checks

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_FIRMWARE_INTERVAL` | `1h` | how often to check a device's firmware |
| `LACERT_FIRMWARE_VALIDITY` | `15s` | window during which a challenge response counts as fresh |
| `LACERT_FIRMWARE_CHALLENGE_TIMEOUT` | `25s` | pause before issuing another challenge to the same device |

A failed check — a signature that does not verify, or a firmware hash that does
not match the enrolled one — causes **immediate revocation** of the device.
That is the protection against firmware tampering.

> During development this gets in the way: reflashing modified firmware changes
> its SHA-256, while the gateway still holds the old one, so the device is
> revoked at the very first check. The fix is to delete the device record before
> reflashing:
> ```bash
> psql "$LACERT_PG_DSN" -c "DELETE FROM devices WHERE device_id='xiao-s3';"
> ```

## Handshake

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_PENDING_HANDSHAKE_TIMEOUT` | `20s` | when an incomplete handshake expires |

## Debugging and demonstration

These variables **must not be enabled in production**.

| Variable | Default | Purpose |
|----------|---------|---------|
| `LACERT_EMULATE_DEVICES` | `0` | how many software devices to spin up inside the gateway |
| `LACERT_EMULATE_INTERVAL` | `2s` | how often emulated devices send telemetry |
| `LACERT_LOG_SESSION_KEYS` | `false` | print session keys in the rotation log in clear text |

> **Emulation wipes its own data on every gateway restart.** Emulated devices
> generate new keys at startup, so the gateway deletes the previous
> `emulated-esp32-N` records along with their telemetry and rotations. It looks
> like "the data disappeared". **Records of real boards are untouched.**

## Utilities and tests

These belong to the helper programs under `cmd/` rather than to the gateway.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `LACERT_GATEWAY_HTTP` | `devicesim`, `stresstest` | gateway REST address (default `http://localhost:8080`) |
| `LACERT_GATEWAY_TCP` | `devicesim`, `stresstest` | gateway TCP address (default `localhost:7700`) |
| `LACERT_DEVICE_ID` | `devicesim` | identifier of the simulated device |
| `LACERT_PROFILE` | `devicesim` | sensor profile: `climate`, `power`, `pressure`, `fuel`, `motor`. If unset, chosen deterministically from `LACERT_DEVICE_ID` |
| `LACERT_STRESS_WAIT` | `stresstest` | pause before the attack scenarios begin |
| `LACERT_STRESS_D4_DELAY` | `stresstest` | response delay in scenario D4 (verifies that a stale challenge is refused) |
| `LACERT_TEST_PG_DSN` | `pgstore` tests | connection to a test database; without it the PostgreSQL tests are skipped |

Profiles determine which telemetry fields a simulated device sends:

| Profile | Fields |
|---------|--------|
| `climate` | `temperature`, `humidity` |
| `power` | `voltage`, `current_a`, `power_w` |
| `pressure` | `pressure`, `temperature` |
| `fuel` | fuel level and related readings |
| `motor` | `rpm`, `vibration_mm_s`, `temperature` |

The gateway parses telemetry as arbitrary `key=value` pairs, so any field lands
in the database and on the charts automatically — including the measurements a
real board reports (`heap_free`, `handshake_us` and so on).

---

## Ready-made configurations

### Production

```bash
LACERT_TCP_ADDR=:7700
LACERT_HTTP_ADDR=:8080
LACERT_MQTT_ADDR=:1883
LACERT_PG_DSN=host=localhost user=lacert password=SECRET dbname=lacert port=5432 sslmode=disable
LACERT_ADMIN_TOKEN=LONG_RANDOM_TOKEN
LACERT_CORS_ORIGINS=https://lacert.example.com
# emulation and key logging are off (simply unset)
```

### Demonstration (fast rotations, everything visible in real time)

```bash
LACERT_PG_DSN=...
LACERT_ADMIN_TOKEN=...
LACERT_ROTATION_INTERVAL=20s
LACERT_ROTATION_CHECK_PERIOD=2s
LACERT_FIRMWARE_INTERVAL=20s
LACERT_EMULATE_DEVICES=0          # real boards only
LACERT_LOG_SESSION_KEYS=false
```

To check which variables the **running** process actually sees:

```bash
sudo cat /proc/$(pgrep -x gatewayd)/environ | tr '\0' '\n' | grep LACERT
```
