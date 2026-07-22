> **Language:** English · [Русский](../ru/FIRMWARE.md)

# ESP32 firmware — how it works inside

The LACERT protocol client written in C for ESP-IDF. A single project builds for
three boards: XIAO ESP32-C6 (RISC-V), XIAO ESP32-S3 and ESP32-S3-DevKitC-1
(Xtensa). Step-by-step building and flashing is covered in `FIRMWARE_BUILD.md`;
this document describes how the code is organised.

## Files

| File | Purpose | Platform |
|------|---------|----------|
| `main/lacert_proto.h` | protocol constants: message types, field sizes, error codes | shared |
| `main/lacert_wire.{c,h}` | framing: reading and writing frames, packing fields | shared |
| `main/lacert_client.{c,h}` | protocol logic: handshake, data, rotation, firmware checks | shared |
| `main/lacert_crypto.{c,h}` | primitives via mbedTLS plus components | ESP32 |
| `main/main.c` | entry point: Wi-Fi, keys in NVS, enrollment, main loop, reconnection | ESP32 |
| `components/ml_kem/` | ML-KEM-1024 (PQClean) + the ESP32 randomness source | ESP32 |
| `components/blake3/` | BLAKE3 (portable implementation) | ESP32 |

**Important:** `lacert_wire.c` and `lacert_client.c` are platform-independent.
Exactly the same files build for Linux (`firmware/linux-debug/`) and are tested
against the gateway without hardware. Only the crypto layer (mbedTLS on the
ESP32 versus OpenSSL on Linux) and the entry point differ.

## Cryptographic layer

`lacert_crypto.c` implements everything through libraries available on the
ESP32:

- **SHA-256, ECDSA P-256, ChaCha20-Poly1305** — mbedTLS (bundled with ESP-IDF,
  partly hardware-accelerated on the S3/C6);
- **ML-KEM-1024** — the `components/ml_kem` component (PQClean), with the
  ESP32 hardware RNG (`esp_random`) as the randomness source;
- **BLAKE3** — the `components/blake3` component (portable implementation; the
  SIMD versions are x86-only, so Xtensa/RISC-V use the baseline one).

Every function returns `lacert_err_t` and checks the libraries' return codes.
Secret material — the ML-KEM shared secret, the next rotation key — is wiped
with `memset` immediately after use. mbedTLS contexts are released on all exit
paths (via `goto done`).

## Error codes

All protocol functions return `lacert_err_t` (`main/lacert_proto.h`):

| Code | Meaning | When it occurs |
|------|---------|----------------|
| `LACERT_OK` (0) | success | — |
| `LACERT_ERR_IO` (−1) | network/socket error | connection dropped, gateway unreachable, could not allocate a frame buffer |
| `LACERT_ERR_DECODE` (−2) | malformed frame | the frame does not parse, a field runs past the boundary, the size exceeds the limit |
| `LACERT_ERR_CRYPTO` (−3) | cryptographic failure | an mbedTLS/PQClean failure, for example decryption not matching |
| `LACERT_ERR_AUTH` (−4) | access denied | signature mismatch, replay detected, device revoked by the gateway |
| `LACERT_ERR_STATE` (−5) | wrong state | a frame arrived that does not fit the current phase, e.g. a rotation with no established session |

`LACERT_ERR_AUTH` during normal operation means the gateway rejected the
device: the firmware closes the session and moves on to reconnecting, blinking
red.

## Execution flow (main.c)

```
app_main
  ├─ nvs_flash_init            initialise storage
  ├─ led_init                  LED (mode 1 — plain, mode 2 — RGB WS2812)
  ├─ wifi_init_sta             connect to Wi-Fi (wait for an IP)
  ├─ keys_load / generate      keys from NVS, or create them on first boot
  ├─ firmware_hash             SHA-256 of the running firmware partition
  ├─ register_device           REST enrollment with the gateway (idempotent)
  ├─ fetch_gateway_key         fetch the gateway's ML-KEM public key
  └─ loop:
       run_session
         ├─ tcp_connect
         ├─ lacert_do_handshake         handshake → session_key
         └─ while the link is alive:
              ├─ select() on the socket
              ├─ lacert_handle_incoming  rotation / firmware check
              └─ every 2 s: lacert_send_data (telemetry)
       on a drop — pause and reconnect (the gateway key is fetched again)
```

## Key storage (NVS)

On first power-up the device generates ECDSA and ML-KEM keys and saves them to
NVS (namespace `lacert`). On later boots the keys are loaded, which is why the
gateway recognises "the same device" after a reboot. This models the binding to
efuse on a production device.

If NVS is erased (`idf.py erase-flash`), the device generates new keys. The
gateway will then still hold the previous key for that `device_id`, and the
handshake will fail. The fix is to change `LACERT_DEVICE_ID` or delete the
record on the gateway (see `GATEWAY.md`).

## Firmware hash

`firmware_hash()` takes the SHA-256 of the running partition through
`esp_partition_get_sha256`. This value is sent during enrollment and used in
responses to firmware challenges. If you reflash modified firmware without
clearing the record on the gateway, its hash changes and integrity checks start
failing — which is the correct behaviour (protection against tampering), but it
gets in the way during active development; raising `LACERT_FIRMWARE_INTERVAL`
on the gateway helps temporarily.

## LED indication

The mode is chosen by the `LACERT_LED_MODE` macro at the top of `main.c`:

- **1** — a plain single-colour LED (XIAO). Pin `LACERT_LED_GPIO`
  (S3 = 21, C6 = 15), active-low (`LACERT_LED_ACTIVE_LOW = 1`).
- **2** — an addressable RGB WS2812 (DevKitC-1) driven over RMT. Pin
  `LACERT_RGB_GPIO` (48 by default; 38 on early board revisions). Brightness is
  `LACERT_RGB_BRIGHTNESS` (0–255, default 24; above 40 it is usually blinding).
  The WS2812 is driven by a pulse protocol, so a plain `gpio_set_level` will not
  light it — hence the separate RMT backend.

Events: handshake — 3 flashes (green on RGB), transmission — 1 (blue), rotation
— 2 (purple), firmware check — 1 (cyan), error — one long flash (red).

## Memory

ML-KEM-1024 needs a noticeable amount of stack (a 3,168-byte private key plus
working buffers), so `sdkconfig.defaults` raises the main task's stack to 24 KB.
On real boards around 240–250 KB of free heap remains, which is a comfortable
margin. The ESP32-C6 has less memory than the S3; if it runs short, PSRAM can be
enabled on the S3-N8R2.

## Bench settings

At the top of `main.c`:

```c
#define LACERT_WIFI_SSID      "..."          // 2.4 GHz only
#define LACERT_WIFI_PASS      "..."
#define LACERT_GW_HOST        "192.168.1.10"  // IP of the machine running the gateway
#define LACERT_GW_HTTP_PORT   8080
#define LACERT_GW_TCP_PORT    7700
#define LACERT_DEVICE_ID      "xiao-esp32-1"  // UNIQUE per board
#define LACERT_ADMIN_TOKEN    "..."           // gateway token, if enabled
#define LACERT_LED_MODE       1               // 1 — plain LED, 2 — RGB
```

## Compatibility testing

The crypto module is compiled on the host against the real mbedTLS 3.6 headers —
the same version ESP-IDF ships — and exercised against a live Go gateway.
Verified: BLAKE3 matches the reference, ML-KEM decapsulation matches the
gateway's implementation (circl), ECDSA produces valid DER, and the full
protocol (handshake, rotation, firmware check) completes. On real hardware all
three boards (C6, XIAO S3, DevKitC-1) run the whole protocol.

## Behaviour when the gateway is unavailable

The device does not give up if the gateway is down or restarting:

- **Gateway unavailable at board boot** — a common case after a general power
  cut, since the board comes up in seconds while the server takes a minute. The
  board retries enrollment and key retrieval every 5 seconds until the gateway
  answers. The LED blinks red meanwhile.
- **Gateway restarted mid-session.** The connection drops and the board
  reconnects. On every attempt it re-fetches the gateway's public key, which
  matters because the gateway generates **a new key pair on every start**, and a
  handshake with the old key would be guaranteed to fail.
- **Gateway forgot the device** — it was running without PostgreSQL and
  restarted, or the record was deleted from the database. The handshake then
  fails even though HTTP responds. After three consecutive failures the board
  tries to **enroll again**; enrollment is idempotent, so if the device really is
  known the gateway simply answers 400/409 and nothing breaks.

Verified live: the gateway was killed mid-session and brought back up with new
keys and an empty database — the device re-enrolled by itself and restored the
secure channel.

## Measurements on the board itself

The figures reported in the original work were taken on an x86-64 server, and
that was the main limitation: it was unknown how the operations behave on a
microcontroller. The firmware can measure them **on the board directly** — this
is controlled by the `LACERT_MEASURE` macro at the top of `main.c` (enabled by
default; `0` turns it off).

What is measured:

| Field | Meaning |
|-------|---------|
| `handshake_us` | the complete handshake Msg1 → Msg2 → Msg3 (µs) |
| `rotation_us` | handling one key rotation: ML-KEM decapsulation + BLAKE3 key derivation (µs) |
| `fw_sign_us` | answering an integrity check: SHA-256 + ECDSA signature (µs) |
| `heap_free` | free heap at the moment of sending (bytes) |
| `heap_min` | minimum free heap over the whole run (bytes) |

These fields travel **together with ordinary telemetry**, so the gateway parses
them as regular metrics: they land in the database and appear on the dashboard
charts automatically (the "Monitoring" tab). No separate export mechanism is
needed — the data can be taken from the database or through
`GET /api/v1/telemetry`.

The `heap_min` value is useful in its own right: if it keeps falling over time
there is a memory leak. In stable operation it quickly reaches a plateau.

### Important: the measurements depend on build settings

By default ESP-IDF builds a project with **`-Og`** (a debug build, no
optimisation) and **without hardware acceleration** of cryptography. In such a
build an ECDSA signature takes **hundreds of milliseconds** — that is not a
property of the algorithm but an artefact of the debug configuration, and
quoting such figures as a characteristic of the protocol would be wrong.

`sdkconfig.defaults` enables:

| Option | Why |
|--------|-----|
| `CONFIG_COMPILER_OPTIMIZATION_SIZE` | build with `-Os` instead of `-Og`: smaller and noticeably faster code |
| `CONFIG_MBEDTLS_HARDWARE_MPI` | the hardware big-number unit — the key accelerator for ECDSA |
| `CONFIG_MBEDTLS_HARDWARE_SHA` | hardware SHA-256 |
| `CONFIG_MBEDTLS_ECP_NIST_OPTIM` | optimised arithmetic for P-256 |

**If you change `sdkconfig.defaults`, an existing `sdkconfig` will not pick the
changes up** — it has to be deleted and regenerated:

```bash
rm -f sdkconfig && idf.py set-target esp32s3 && idf.py build
```

Measurements for a report should be taken from the optimised build, and the
configuration they were obtained under must always be stated.

**Comparing architectures.** Exactly the same measurements are taken by the
Linux debug client (`firmware/linux-debug/`), built from the same protocol code.
For reference, on an x86-64 server (these figures **include the network
exchange** over localhost): handshake ≈1.2 ms, rotation ≈0.6 ms, firmware check
response ≈0.5 ms.

Note that `handshake_us` and similar values include network delays — on the
board, three exchanges over Wi-Fi, adding tens of milliseconds of noise — so
**comparing platforms by them is not valid**. For architectural comparison there
is a separate microbenchmark without networking; see the next section.

## Cryptographic microbenchmark

`LACERT_BENCH` in `main.c` (enabled by default) runs each operation
`LACERT_BENCH_ITERS` times (20) **without networking** and prints the average.
This is the right tool for comparing platforms: the `handshake_us` figures from
telemetry include three Wi-Fi exchanges and are therefore noisy by tens of
milliseconds.

The same set of operations, run by the same code, is executed on the host by
`firmware/linux-debug/bench_host.c`. One implementation (mbedTLS + PQClean +
BLAKE3) across all platforms, so the differences cannot be attributed to
different libraries.

**Methodology.** Operations of different cost are measured differently —
otherwise the result is distorted:

- **Heavy ones** (ECDSA, ML-KEM — from single-digit to hundreds of
  milliseconds): each iteration is timed separately, with `vTaskDelay(1)`
  between iterations. Without it the task holds the core longer than the
  watchdog timeout (one ECDSA signature on the ESP32-S3 is about 170 ms, so
  twenty in a row means 3.5 seconds of continuous work and `task_wdt` fires).
  The pause sits **between** measurements and is not included in the result.
- **Light ones** (BLAKE3, SHA-256, ChaCha20 — tens of microseconds): the whole
  loop is timed, over more runs (200). Timing each iteration here is not
  possible: two timer calls cost several microseconds while the operation itself
  is only tens, so the overhead would inflate the result by tens of per cent. The
  watchdog is not a concern — the entire loop finishes within single-digit
  milliseconds.

### Results (one and the same implementation)

| Operation | x86-64 | ESP32-S3 (Xtensa, 240 MHz) | ESP32-C6 (RISC-V, 160 MHz) |
|-----------|--------|----------------------------|----------------------------|
| ECDSA P-256 sign | 0.35 ms | 170.2 ms | **22.2 ms** |
| ECDSA P-256 keypair | 0.30 ms | 156.7 ms | **9.6 ms** |
| ML-KEM-1024 keypair | 0.11 ms | 16.7 ms | 15.1 ms |
| ML-KEM-1024 encapsulate | 0.11 ms | 18.4 ms | 16.0 ms |
| ML-KEM-1024 decapsulate | 0.12 ms | 21.1 ms | 17.8 ms |
| BLAKE3 (key derivation) | 2.0 µs | 18.0 µs | 19.8 µs |
| SHA-256 (96 bytes) | 0.7 µs | 60.1 µs | 41.7 µs |
| ChaCha20-Poly1305 seal | 12.4 µs | 150.5 µs | 210.6 µs |
| Free heap | — | ~252 KB | ~295 KB |

The measurements were taken with `LACERT_SHARED_CRYPTO_CTX = 1` (the shared
cryptographic context). The comparison against the original version, along with
the memory cost of the optimisation, is in `MEASUREMENTS.md`, section 3.4.

**Main conclusion.** ECDSA runs **7.7× faster** on the ESP32-C6 than on the
ESP32-S3, even though the C6 is the weaker chip (160 MHz against 240, one core
against two). On every other operation the boards are on par (ML-KEM 17.8 against
21.1 ms; on BLAKE3 and ChaCha20 the C6 is even slower). The difference therefore
lies not in core performance but in the **hardware elliptic-curve accelerator**,
which the C6 has and the S3 does not. For cryptography on a microcontroller, a
dedicated accelerator matters more than clock speed.

**Second conclusion.** ML-KEM barely depends on the platform: these chips have
no accelerators for lattice cryptography, so everything runs in software. Put
differently, post-quantum key exchange costs roughly the same everywhere, while
the signature is what should be chosen with the specific chip in mind.
