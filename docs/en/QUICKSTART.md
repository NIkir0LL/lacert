> **Language:** English · [Русский](../ru/QUICKSTART.md)

# LACERT — quick start

A short guide to building, testing and running the system. The architecture and
the protocol are described in full in `OVERVIEW.md` and `PROTOCOL_SPEC.md`.

## Requirements

- **Go 1.22** or newer (check with `go version`)
- OS: Linux, macOS or Windows
- Dependencies are already vendored under `vendor/`, so **no internet access is
  needed** to build

## 1. Build

```bash
# from the project root (the lacert5 directory)
go build ./...
```

If dependency downloads cause trouble, build offline — everything is already in
`vendor/`:

```bash
go build -mod=vendor ./...
```

## 2. Run the tests

```bash
go test ./...                       # normal run
go test -mod=vendor ./...           # offline, from vendor
go test -race ./...                 # with the data-race detector (slower)
go test ./... -cover                # with coverage
```

Expected result: all 14 packages report `ok`; there should be no `FAIL`.

## 3. Run the gateway with emulated devices (no ESP32 hardware)

The simplest way to see the system working is to start the gateway with several
emulated ESP32 devices built in:

```bash
go build -o gatewayd ./cmd/gatewayd

LACERT_EMULATE_DEVICES=3 \
LACERT_EMULATE_INTERVAL=1s \
LACERT_LOG_SESSION_KEYS=true \
./gatewayd
```

Once it is running:
- **Web dashboard**: http://localhost:8080
- The devices enroll themselves, perform the post-quantum handshake and start
  sending telemetry.

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `LACERT_EMULATE_DEVICES` | How many ESP32 devices to emulate (0 = no emulation) | `0` |
| `LACERT_EMULATE_INTERVAL` | How often the emulator sends telemetry | `2s` |
| `LACERT_LOG_SESSION_KEYS` | Print full keys in the rotation log (TESTING ONLY) | `false` |
| `LACERT_HTTP_ADDR` | Address of the web UI and REST API | `:8080` |
| `LACERT_TCP_ADDR` | TCP port for devices | `:7700` |
| `LACERT_MQTT_ADDR` | Port of the embedded MQTT broker | `:1883` |
| `LACERT_ADMIN_TOKEN` | Bearer token for protected REST endpoints (empty = no authorization) | empty |
| `LACERT_PG_DSN` | PostgreSQL DSN (empty = in-memory storage) | empty |
| `LACERT_CORS_ORIGINS` | Allowed CORS origins | empty |

> **Important when moving to real ESP32 devices.** Emulation is switched on
> solely by `LACERT_EMULATE_DEVICES`. The server-side logic is decoupled from the
> emulator: moving to real boards requires no rewriting — just drop that
> variable and point real devices at `LACERT_TCP_ADDR`.

## 4. Main REST endpoints (for manual checks)

With the gateway running (on :8080 by default):

```bash
curl http://localhost:8080/healthz                       # liveness
curl http://localhost:8080/api/v1/devices                # device list
curl "http://localhost:8080/api/v1/telemetry?range=1h&limit=50"  # telemetry
curl http://localhost:8080/api/v1/rotations              # key-rotation log
curl http://localhost:8080/api/v1/metrics                # aggregated metrics
curl http://localhost:8080/api/v1/gateway                # gateway public KEM key
```

## 5. What to exercise when testing

The main mechanisms worth running through:

1. **Post-quantum handshake** — devices switch to `online` on the dashboard.
2. **Telemetry** — numeric values move and change on the charts.
3. **Key rotation** — entries appear in the rotation log
   (`/api/v1/rotations`); in test mode both the old and the new key are visible.
4. **Firmware integrity check** — once an hour (or immediately, on the
   scheduler's first tick) the device answers a challenge.
5. **Metrics** (`/api/v1/metrics`) — counters for handshakes, rotations,
   firmware checks and rejected replays.

## If something goes wrong

When reporting a problem, please include:
- your Go version (`go version`) and OS;
- the exact command you ran;
- the full error output;
- if a test fails, the test name from the `go test` output.
