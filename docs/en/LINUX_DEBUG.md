> **Language:** English · [Русский](../ru/LINUX_DEBUG.md)

# Debugging the LACERT C client on Linux

This builds a **Linux version** of the firmware's C client, so that the protocol
can be debugged against a running Go gateway **without ESP32 hardware**. It
speeds development up considerably: rebuilds take seconds, and you get a normal
gdb session and memory sanitizers.

The client uses the **same** `../main/lacert_wire.c` and
`../main/lacert_client.c` as the ESP32 firmware, so what you exercise is exactly
the protocol logic that will ship to the board. Only the crypto layer differs:
here it is OpenSSL (`lacert_crypto_linux.c`) instead of mbedTLS, but the
primitives are the same (ECDSA P-256, ChaCha20-Poly1305, SHA-256, ML-KEM-1024,
BLAKE3).

## Verified compatibility

The key cryptographic libraries have been verified to match the Go gateway's
implementation **exactly** — otherwise the handshake would not succeed:

- **ML-KEM-1024**: PQClean (C) produces the same shared secret as circl (Go).
- **BLAKE3**: the official C implementation produces the same hash as
  zeebo/blake3 (Go).
- **ChaCha20-Poly1305 / ECDSA**: compatible — telemetry encrypted in C is
  decrypted by the gateway, and the handshake signature is accepted.

The end-to-end test passes: the C client enrolls, completes the handshake and
sends telemetry, and the gateway receives and decrypts all of it correctly.

## Installing dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
git clone https://github.com/BLAKE3-team/BLAKE3 ~/BLAKE3
git clone https://github.com/PQClean/PQClean ~/PQClean
```

## Building

```bash
cd firmware/linux-debug
bash build_linux.sh
```

(if the libraries live elsewhere: `BLAKE3_DIR=... PQCLEAN_DIR=... bash build_linux.sh`)

## Running against the gateway

The gateway must already be running. Then:

```bash
LACERT_ADMIN_TOKEN=<your-token> LACERT_DEVICE_ID=linux-test-1 \
  ./lacert-client <host> <http_port> <tcp_port>
```

For example, against a local gateway:

```bash
LACERT_ADMIN_TOKEN=41b1751e... ./lacert-client 127.0.0.1 8080 7700
```

The client will:
1. generate ECDSA and ML-KEM keys;
2. enroll over REST (POST /api/v1/devices);
3. fetch the gateway's ML-KEM public key;
4. perform the handshake;
5. send five telemetry packets.

A successful run ends with a line reporting that the protocol works. The
decrypted telemetry can be seen on the dashboard or through
`GET /api/v1/telemetry?device_id=<id>`.

## Files

- `lacert_crypto_linux.c` — crypto on OpenSSL + PQClean + BLAKE3 (Linux only).
- `main_linux.c` — entry point: key generation, enrollment, handshake, sending
  data.
- `build_linux.sh` — the build script.
- `esp_random.h` — a host stub for the ESP32 random-number API. It is needed only
  by `bench_host`, which compiles `../main/lacert_crypto.c` directly; randomness
  comes from `getrandom(2)` or `/dev/urandom`. The firmware uses the real header
  from the ESP-IDF distribution.

These files are NOT used on the ESP32, which uses `../main/lacert_crypto.c`
(mbedTLS) and `../main/main.c` instead.

## Exercising rotation and firmware checks (the full protocol)

The client stays alive for `LACERT_RUN_SECONDS` seconds (60 by default),
listening to the gateway and answering the key rotations and firmware checks it
initiates, while sending telemetry in parallel. To see a rotation or a firmware
check quickly, start the gateway with accelerated intervals:

```bash
# on the gateway side:
LACERT_ROTATION_INTERVAL=6s LACERT_FIRMWARE_INTERVAL=5s LACERT_ROTATION_CHECK_PERIOD=1s ./gatewayd
# on the client side:
LACERT_RUN_SECONDS=25 ./lacert-client 127.0.0.1 8080 7700
```

The client's output will show lines reporting that a new key was applied and
that a challenge was answered, followed by a summary. This confirms that the C
implementation of rotation (deriving the next key through BLAKE3) and of the
firmware check (an ECDSA signature over challenge||hash) is compatible with the
gateway.

## How close this is to the real firmware

`main_linux.c` is written to model the behaviour of a real device:

1. **Persistent keys.** On the first run the keys (ECDSA + ML-KEM) are generated
   and saved to a file (`lacert_device.keys` by default, overridable with
   `LACERT_KEYFILE`). On later runs they are loaded, so the gateway recognises
   "the same device" after a restart — the equivalent of NVS/efuse on the ESP32.
   Re-enrolling with the same keys is ignored by the gateway, which is expected.
2. **A real firmware hash.** `firmware_hash` is the SHA-256 of the binary itself
   (on the ESP32 it is the SHA-256 of the firmware image). It stays the same
   across runs.
3. **Reconnection.** If the connection drops, the client waits 2 s and
   reconnects, fetching the gateway's public key again and repeating the
   handshake — just as a real device does after losing the network.

What remains Linux-specific, and is replaced on the ESP32: crypto on OpenSSL →
mbedTLS plus components; file-based key storage → NVS/efuse; POSIX sockets →
Wi-Fi with lwIP (the socket API itself is the same).

### Example: running twice means the same device

```bash
# first run — enrolls:
LACERT_KEYFILE=dev1.keys ./lacert-client 127.0.0.1 8080 7700
# second run — recognised by the same keys:
LACERT_KEYFILE=dev1.keys ./lacert-client 127.0.0.1 8080 7700
```
