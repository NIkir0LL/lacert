# On-board firmware performance measurements

Methodology for measuring LACERT cryptographic operations on real ESP32 devices
and for checking the effect of the ECDSA-context optimization. A full build for
esp32c6 has been verified from a clean clone of the repository; on-board numbers
are collected with the steps below.

Russian version: [`ЗАМЕРЫ_НА_ПЛАТАХ.md`](ЗАМЕРЫ_НА_ПЛАТАХ.md).

## Verified before on-board measurements

Independently of the target board:

- **The crypto module compiles against mbedTLS 3.6.3** — the same version
  shipped in ESP-IDF v5.4. The library was built from source, and
  `main/lacert_crypto.c` was compiled together with ML-KEM (PQClean) and BLAKE3,
  with no errors or warnings.
- **Both switch branches produce valid signatures** — 50 signatures each with
  two different keys, every one verified with an independent context (the way
  the gateway does it). No mismatches.
- **The full protocol works** — the debug client from `linux-debug/` (the same
  `lacert_wire.c` and `lacert_client.c` that go on the board) ran against the
  Go gateway: enrollment, handshake, telemetry, key rotation, firmware-integrity
  responses — with no errors.

On-board measurements are needed to observe behavior under Xtensa/RISC-V and the
ESP32 hardware RNG, which differ from the host platform.

---

## ECDSA optimization switch

At the top of `main/lacert_crypto.c`:

```c
#define LACERT_SHARED_CRYPTO_CTX 1
```

- **1** — the random number generator and the P-256 curve parameters are created
  once and reused (optimization);
- **0** — original behavior: the context is recreated for every signature.

Both branches live in the same firmware and are toggled by a single digit, so
they can be measured on one board under identical conditions — otherwise the
difference could come from different builds rather than the optimization itself.

### Context

On mbedTLS 2.28 the optimization gave a 2.6× speedup. On mbedTLS 3.6 (in
ESP-IDF v5.4) there is no difference: 348.2 µs versus 347.4 µs by the median of
fifteen runs on x86-64. On ESP32 the entropy source differs — a hardware
generator instead of the OS subsystem — so the result may differ, and that can
only be checked on the board.

---

## Measurement procedure

For each board (**XIAO ESP32-C6** and **XIAO ESP32-S3** — they differ in whether
a hardware ECC accelerator is present).

### 1. Preparation

```bash
cd firmware
# fill in main/main.c: Wi-Fi, gateway IP, LACERT_DEVICE_ID (unique!)
rm -rf build sdkconfig
idf.py set-target esp32c6        # or esp32s3
idf.py build
```

Check that the optimized configuration was applied:

```bash
grep -E 'COMPILER_OPTIMIZATION|MBEDTLS_HARDWARE' sdkconfig
```

If it shows `-Og` instead of `-Os`, the measurements are meaningless: a debug
build is an order of magnitude slower.

### 2. Measurement with optimization (value 1)

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

Capture the whole table from the "CRYPTOGRAPHY MICROBENCHMARK" block. One run is
enough: the operations are in the millisecond range and noise has little effect.

### 3. Measurement without optimization

Change the value to `0` in `main/lacert_crypto.c`, then rebuild and flash (a
clean rebuild is not needed — one file changes):

```bash
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

### 4. Repeat for the second board

---

## Result format

Four microbenchmark tables are collected: C6 with value 1, C6 with value 0, S3
with value 1, S3 with value 0. A block looks like:

```
==================================================
CRYPTOGRAPHY MICROBENCHMARK (no network)
board: ESP32-C6 (RISC-V, 160 MHz)
--------------------------------------------------
  ECDSA P-256 keypair             12.25 ms   (5 runs)
  ECDSA P-256 sign                25.76 ms   (20 runs)
  ...
==================================================
```

They let you assess the effect of the optimization on each board.

---

## Important reminders

**A unique `LACERT_DEVICE_ID` per board.** The gateway keeps one key set per
identifier; a second board with the same name will fail the handshake.

**Reflashing changes the image SHA-256.** The gateway holds the reference hash
from enrollment, so after reflashing the integrity check fails and the device is
revoked — correct behavior, but inconvenient during frequent reflashing. Before
reflashing, remove the device record:

```bash
psql "$LACERT_PG_DSN" -c "DELETE FROM devices WHERE device_id='xiao-c6';"
```

Or, if the gateway runs without a database, restart it.

**Ports:** XIAO — `/dev/ttyACM0`, ESP32-S3-DevKitC-1 — `/dev/ttyUSB0`.

**When changing target** (`esp32c6` ↔ `esp32s3`), always `rm -rf build sdkconfig`,
otherwise the build picks up settings from the previous board.

---

## Note on `bench_host`

Building the host benchmark (`MEASUREMENTS.md`, section 6.2) needs the `-I.`
flag, otherwise the build fails on a missing `esp_random.h`. The `linux-debug/`
directory provides an `esp_random.h` stub (randomness from `getrandom(2)`,
falling back to `/dev/urandom`) that reproduces the measurements on the host.
