> **Language:** English · [Русский](../ru/DEPLOY.md)

# Server deployment (bare metal, no Docker)

## The quick path: the automated script

Unpack the archive on the server and run this from its root (where `go.mod`
lives):

```bash
sudo bash deploy/bare-metal/install.sh
```

The script is idempotent (safe to re-run) and does the following:
1. Checks that Go ≥ 1.22 is installed.
2. Installs PostgreSQL if it is missing (through `apt-get` — for RHEL/CentOS
   replace this with `dnf`/`yum` by hand before running. Nothing else changes).
3. Creates the `lacert` role and database in PostgreSQL with a random password.
4. Builds `gatewayd` and `devicesim` and places them in `/opt/lacert/bin/`.
5. Creates the system user `lacert` (no shell, no home directory).
6. Generates `/etc/lacert/gatewayd.env` with a random `LACERT_ADMIN_TOKEN`
   (mode `600`, readable only by the `lacert` user) — **if the file already
   exists the script does not overwrite it**, so that the token and password are
   not lost on a repeat run.
7. Installs and starts the `lacert-gatewayd` systemd service.

At the end the script prints the commands for verification and reminds you to
open the ports in the firewall.

## Verification after installation

```bash
# Service status and logs
systemctl status lacert-gatewayd
journalctl -u lacert-gatewayd -f

# Liveness
curl -s http://localhost:8080/healthz

# The gateway's public key (always open, no token — needed for device provisioning)
curl -s http://localhost:8080/api/v1/gateway

# View the admin token and the database connection settings
cat /etc/lacert/gatewayd.env

# List devices (requires the token from the file above)
curl -s -H "Authorization: Bearer <YOUR_TOKEN>" http://localhost:8080/api/v1/devices
```

### Web interface

Open `http://<server_address>:8080/` in a browser. The page (HTML/CSS/JS) is
embedded directly into the `gatewayd` binary and served by it on the same port
as the REST API: there is no separate frontend to build or deploy. If the REST
API is protected (that is, `LACERT_ADMIN_TOKEN` is set), the page itself shows a
banner asking for the token — it is stored only in the browser (localStorage)
and is never sent anywhere except in the `Authorization` header of requests to
this same gateway.

What the page offers: a device list with real-time online status and a short
preview of the latest message. Enrollment of a new device (you can paste an
entire line from the serial port and the fields fill themselves in). A device
card with the full latest message and an event log. A **"Monitoring" section** —
charts of numeric telemetry fields over time (an overview across all devices or
a specific device, over 30 min / 1 / 6 / 12 / 24 hours or a custom range) plus a
history of received packets. A **"Rotation log" section** — every key-change
attempt, successful or not.

### The monitoring dashboard and rotation log

- **Monitoring**: with no device selected, an overview (one chart per metric with
  every device as a separate line). With a device selected, charts for that
  device only, plus a table of received packets over the same period.
- **Rotation log**: the old and new keys are shown in full only if
  `LACERT_LOG_SESSION_KEYS=true` is enabled on the gateway (the variable is
  commented out by default in `gatewayd.env` — see below). Leave it off in
  production. The page will show a banner explaining that the values are hidden.
- **Firmware checks**: a summary (how many integrity checks passed and how many
  were rejected) and a table across all devices. The gateway periodically sends
  the device a challenge, and the device answers with a signature over
  `challenge || SHA-256(firmware image)` — confirming that the board is running
  the same firmware it enrolled with.

### A trial run without real hardware (built-in emulation)

If you want to see "live" devices in the interface straight away, without
waiting for real ESP32 boards, uncomment this in `/etc/lacert/gatewayd.env`:
```
LACERT_EMULATE_DEVICES=2
LACERT_EMULATE_INTERVAL=2s
# optional, for debugging only — see the note about the rotation log above:
# LACERT_LOG_SESSION_KEYS=true
```
and restart the service: `sudo systemctl restart lacert-gatewayd`. The gateway
will spin up the requested number of software devices, which enroll themselves,
perform the handshake and start sending telemetry — over exactly the same
TCP/REST protocol as a real board. **When you move on to testing with real ESP32
devices, simply make sure `LACERT_EMULATE_DEVICES` is unset (or 0)** and connect
the boards to port 7700: neither the gateway nor the protocol needs changing —
to them an emulated and a real device are indistinguishable.

> **Important: the emulators wipe their own data every time the gateway
> restarts.** An emulated device generates new keys when the process starts, so
> before launching emulation the gateway deletes the previous
> `emulated-esp32-N` records along with their telemetry, rotations and events
> (otherwise enrollment under the same ID would be rejected and the devices
> would stay offline forever). This looks like "the data disappeared after a
> restart": the database counters drop sharply. **Records belonging to real
> boards are not touched.** If you need to accumulate data, switch emulation off
> (`LACERT_EMULATE_DEVICES=0`).

### A full end-to-end test (device simulator against a real gateway)

```bash
TOKEN=$(grep LACERT_ADMIN_TOKEN /etc/lacert/gatewayd.env | cut -d= -f2)
LACERT_ADMIN_TOKEN="$TOKEN" LACERT_DEVICE_ID="test-device-1" /opt/lacert/bin/devicesim
```

You should see, in order: key preparation → enrollment over REST → handshake →
periodic telemetry. Stop it with `Ctrl+C`.

Check that the device shows as "online" in the REST API (in a separate terminal,
while `devicesim` is running):
```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/devices/test-device-1
```

Check telemetry delivery to MQTT (if `mosquitto-clients` is installed:
`sudo apt-get install -y mosquitto-clients`):
```bash
mosquitto_sub -h localhost -p 1883 -t 'devices/+/telemetry' -v \\
  -u "$(sudo grep -oP '(?<=^LACERT_MQTT_USER=).+' /etc/lacert/gatewayd.env)" \\
  -P "$(sudo grep -oP '(?<=^LACERT_MQTT_PASSWORD=).+' /etc/lacert/gatewayd.env)"
```

## Connecting real ESP32 boards

The firmware lives in `firmware/`. No additional configuration is needed on the
server side — the boards connect to the same ports as the emulators.

What you will need to fill into the firmware (`firmware/main/main.c`):

- **the server's IP** on the local network (`hostname -I | awk '{print $1}'`)
- **the admin token** (`sudo grep LACERT_ADMIN_TOKEN /etc/lacert/gatewayd.env`)
- **a unique `LACERT_DEVICE_ID` for every board** — the gateway keeps one set of
  keys per ID, so a second board with the same ID will not complete the
  handshake
- the Wi-Fi settings (2.4 GHz only — the ESP32 cannot see 5 GHz networks).

After that the board handles everything itself: it generates keys on first
power-up (storing them in NVS), computes the SHA-256 of its own firmware,
enrolls over REST and performs the handshake. There is no need to "extract keys"
or "compute the hash" by hand.

Check that the ports are reachable from the local network (see the next section)
and that the gateway listens on all interfaces (`:7700`, not `127.0.0.1:7700`).

Building and flashing, along with a walkthrough of common problems, are covered
in [`FIRMWARE_BUILD.md`](FIRMWARE_BUILD.md). The internals of the firmware are in [`FIRMWARE.md`](FIRMWARE.md).

## The complete settings reference

Every gateway environment variable with its default is described in
[`CONFIG.md`](CONFIG.md), together with ready-made production and demonstration
configurations.

## Opening ports in the firewall

If devices or the web page will connect from **outside** the server:
```bash
sudo ufw allow 7700/tcp   # the LACERT TCP protocol (devices)
sudo ufw allow 8080/tcp   # REST API
sudo ufw allow 1883/tcp   # MQTT
```
If everything (gateway, devices and web page) will run on the server itself or
within one private network behind NAT/VPN, there is no need to open ports to the
public internet.

## Manual installation (if the automated script does not suit you)

```bash
# 1. PostgreSQL
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE ROLE lacert WITH LOGIN PASSWORD 'YOUR_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE lacert OWNER lacert;"

# 2. Build
go build -o gatewayd ./cmd/gatewayd
go build -o devicesim ./cmd/devicesim
sudo install -m 0755 gatewayd /opt/lacert/bin/gatewayd
sudo install -m 0755 devicesim /opt/lacert/bin/devicesim

# 3. Configuration
sudo mkdir -p /etc/lacert
sudo tee /etc/lacert/gatewayd.env <<'EOF'
LACERT_PG_DSN=host=localhost user=lacert password=YOUR_PASSWORD dbname=lacert port=5432 sslmode=disable
LACERT_TCP_ADDR=:7700
LACERT_HTTP_ADDR=:8080
LACERT_MQTT_ADDR=:1883
LACERT_ADMIN_TOKEN=generate_with_openssl_rand_-hex_32
# Cross-origin requests are not permitted by default: the dashboard is served by
# the same process from the same address and does not need them. Uncomment this
# only if a third-party web page calls the REST API, and name it explicitly
# instead of using "*".
# LACERT_CORS_ORIGINS=https://lacert.example.com
EOF
sudo chmod 600 /etc/lacert/gatewayd.env

# 4. systemd
sudo cp deploy/systemd/lacert-gatewayd.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lacert
sudo chown -R lacert:lacert /opt/lacert /etc/lacert/gatewayd.env
sudo systemctl daemon-reload
sudo systemctl enable --now lacert-gatewayd
```

## Common problems

**`go.mod` contains `replace golang.org/x/... => github.com/...` lines — this is
normal.** They appeared during development in an isolated sandbox with no access
to domains such as `golang.org`/`gorm.io`/`go.uber.org`. On your server with
ordinary internet access they cause no trouble — `go build` simply takes the
code of the same libraries from their GitHub mirrors. Leave them alone.

**`go build` fails with an error about the Go version.** Go ≥ 1.22.2 is
required — check `go version` and upgrade if necessary (for example from
https://go.dev/dl/ — the standard tarball installation into `/usr/local/go`).

**PostgreSQL: `password authentication failed`.** This usually means the
password in `/etc/lacert/gatewayd.env` does not match the one set for the role
in PostgreSQL. Check or reset the role's password:
```bash
sudo -u postgres psql -c "ALTER ROLE lacert WITH PASSWORD 'NEW_PASSWORD';"
```
then update `LACERT_PG_DSN` in the env file accordingly and run
`sudo systemctl restart lacert-gatewayd`.

**The service will not start / crashes immediately.** Look at the details:
```bash
journalctl -u lacert-gatewayd -n 50 --no-pager
```
The most common causes: a port is already taken (`lsof -i :8080` /
`lsof -i :7700` / `lsof -i :1883`), an incorrect DSN, or the `lacert` user
lacking read permission on the env file.

**I upgraded the version — the dashboard is empty / data is "not coming" from
the database.** Three usual causes, in descending order of frequency:

1. **Browser cache.** The dashboard (HTML/CSS/JS) is baked into the binary
   through `go:embed`, and after an upgrade the browser may still serve the old
   files. Press `Ctrl+Shift+R` (a hard refresh) or open a private window.
2. **The period filter.** The "Monitoring" tab defaults to "1 hour". If the
   boards have not sent fresh telemetry since the restart, the charts will be
   empty even though the database holds a day's history. Switch to "24 hours".
3. **The gateway was started without its environment variables.** If you launch
   the binary by hand (`./gatewayd`), the variables from
   `/etc/lacert/gatewayd.env` **are not loaded**, `LACERT_PG_DSN` ends up empty,
   and the gateway silently falls back to in-memory storage — it will not read
   the database at all. The startup log contains a line about in-memory storage.
   The correct way to upgrade is to unpack the new archive and run the same
   install script from its root:

```bash
sudo bash deploy/bare-metal/install.sh
```

   The script is idempotent: the database password and admin token are taken
   from the existing `/etc/lacert/gatewayd.env`, the data in PostgreSQL is left
   untouched, and the service is restarted on the new binary.

   Alternatively, by hand if you build separately:

```bash
go build -o gatewayd ./cmd/gatewayd
sudo systemctl stop lacert-gatewayd
sudo cp gatewayd /opt/lacert/bin/gatewayd
sudo systemctl start lacert-gatewayd
```

   If you do need to run it by hand for debugging, load the environment
   explicitly:

```bash
sudo bash -c 'set -a; source /etc/lacert/gatewayd.env; set +a; /opt/lacert/bin/gatewayd'
```

To check which environment the running process actually sees:

```bash
sudo cat /proc/$(pgrep -x gatewayd)/environ | tr '\0' '\n' | grep LACERT
```

**The number of telemetry records dropped sharply after a restart.** Most likely
emulation is enabled (`LACERT_EMULATE_DEVICES`): its devices are recreated every
time the gateway starts and their previous data is deleted. Records of real
boards are unaffected. See the section on built-in emulation above.

**I want to reset and start over.** The script is safe to re-run. For a complete
reset (including the database and the token):
```bash
sudo systemctl stop lacert-gatewayd
sudo -u postgres psql -c "DROP DATABASE IF EXISTS lacert;"
sudo -u postgres psql -c "DROP ROLE IF EXISTS lacert;"
sudo rm -rf /etc/lacert /opt/lacert
sudo bash deploy/bare-metal/install.sh
```
