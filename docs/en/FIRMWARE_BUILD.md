> **Language:** English · [Русский](../ru/FIRMWARE_BUILD.md)

# LACERT — ESP32 firmware (the protocol client)

The LACERT protocol client written in C for ESP-IDF. **A single project builds
for all three boards**: XIAO ESP32-C6 (RISC-V), XIAO ESP32-S3 and ESP32-S3-N8R2
(Xtensa). The architectural differences are hidden inside ESP-IDF, so no
board-specific code is needed.

The wire format follows `PROTOCOL_SPEC.md` byte for byte.

## Status: READY TO FLASH

Every part is implemented; no stubs remain:

| File | What it does | Status |
|------|--------------|--------|
| `main/lacert_wire.c` | protocol frames and fields | done |
| `main/lacert_client.c` | handshake, data, rotation, firmware checks | done |
| `main/lacert_crypto.c` | ECDSA, ChaCha20, SHA-256 (mbedTLS) + ML-KEM, BLAKE3 | done |
| `main/main.c` | Wi-Fi, keys in NVS, enrollment, main loop, reconnection | done |
| `component-overlay/` | ESP32 component glue: RNG (`randombytes_esp.c`), `CMakeLists.txt` for ml_kem and blake3 | in repo |
| `components/ml_kem/`, `components/blake3/` | ML-KEM-1024 (PQClean) and BLAKE3 — **downloaded** by `fetch-components.sh`, not stored in the repo | see "Building" |

### Verified before flashing

The ESP32 crypto module (`lacert_crypto.c` plus both components) was compiled on
the host against the real mbedTLS 3.6 headers — the same version ESP-IDF ships —
and exercised against a **live Go gateway**. The result: enrollment, handshake,
telemetry, **3 key rotations** and **5 firmware integrity checks** were all
accepted by the gateway. So the cryptography and the protocol are compatible;
what remains on the board is the surrounding plumbing (Wi-Fi/NVS), which is also
written.

Additionally: a full `idf.py build` for esp32c6 has been verified from a clean
clone of the repository (after `fetch-components.sh`) — `lacert_firmware.bin` is
produced and fits into the application partition.

## Before building: configure the bench

Fill these in at the top of `main/main.c`:

```c
#define LACERT_WIFI_SSID      "your_network_name"
#define LACERT_WIFI_PASS      "password"
#define LACERT_GW_HOST        "192.168.1.10"   // gateway IP on the local network
#define LACERT_GW_HTTP_PORT   8080
#define LACERT_GW_TCP_PORT    7700
#define LACERT_DEVICE_ID      "xiao-esp32-1"   // unique per board!
#define LACERT_ADMIN_TOKEN    ""               // gateway token, if enabled

#define LACERT_LED_MODE       1    // 1 = plain LED (XIAO)
                                   // 2 = addressable RGB WS2812 (ESP32-S3-DevKitC-1)
```

**About the LED.** The XIAO has a plain single-colour LED (mode 1); the
ESP32-S3-DevKitC-1 has an addressable RGB WS2812 (mode 2), which is driven by a
pulse protocol and will not light up from a plain `gpio_set_level`. Set the mode
that matches your board. The pins (`LACERT_LED_GPIO` for the XIAO,
`LACERT_RGB_GPIO` for the DevKitC-1) are defined in the same place and can be
changed if needed.

What the LED indicates:

| Event | XIAO (single colour) | DevKitC-1 (RGB) |
|-------|----------------------|-----------------|
| secure channel established | 3 flashes | green ×3 |
| telemetry sent | 1 short flash | blue ×1 |
| key rotation | 2 flashes | purple ×2 |
| firmware integrity check | 1 flash | cyan ×1 |
| error / gateway unreachable | one long flash | red |

**Important:** every board must have its own `LACERT_DEVICE_ID`, otherwise they
will collide on the gateway.

## Building and flashing

Third-party cryptography (ML-KEM from PQClean, BLAKE3) is not stored in the
repository — it has to be downloaded once. The script clones them at pinned
versions, keeps only the files that build on ESP32 (SIMD implementations for
x86/ARM are dropped), and overlays the local glue from `component-overlay/`
(hardware RNG and `CMakeLists.txt`).

The commands below are written for the `lacert` monorepo, where the firmware
lives in the `firmware/` subdirectory. When building from the
`lacert-crypto-esp32` repository the firmware sits at the repository root —
skip the `cd firmware` step, everything else is the same.

```bash
cd firmware

# 1. download third-party components (once; needs git and network access)
./scripts/fetch-components.sh

# 2. select the board (once):
idf.py set-target esp32c6      # XIAO ESP32-C6
#   or
idf.py set-target esp32s3      # XIAO ESP32-S3 / ESP32-S3-N8R2

# 3. build and flash
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor    # the port on your system
```

The PQClean and BLAKE3 versions are pinned in `scripts/fetch-components.sh`
(the `PQCLEAN_REF`, `BLAKE3_REF` variables) — the build is reproducible. Update
them deliberately, changing these values and re-checking the build.

## What happens on first power-up

1. Wi-Fi comes up.
2. No keys are found in NVS → ECDSA P-256 and ML-KEM-1024 keys are generated and
   saved (the equivalent of efuse: subsequent boots reuse them).
3. The SHA-256 of the firmware image is computed.
4. The device enrolls with the gateway over REST (re-enrolling with the same
   keys is not an error — the gateway simply recognises the device).
5. The gateway's public ML-KEM key is fetched.
6. TCP connection, handshake, then the main loop: telemetry every 2 seconds,
   answers to key rotations and firmware checks. On a drop, it reconnects.

Expected monitor output:

```
I (…) lacert: WiFi connected, IP: 192.168.1.55
I (…) lacert: first boot: generating keys (ECDSA + ML-KEM-1024)...
I (…) lacert: keys generated and stored in NVS
I (…) lacert: enrollment: new device (201)
I (…) lacert: gateway public ML-KEM key received
I (…) lacert: === secure channel established ===
I (…) lacert: sent: temperature=20.5; seq=0
I (…) lacert: [firmware] answered the integrity check
I (…) lacert: [rotation] new key, iteration=1
```

## Debugging without a board

The `linux-debug/` directory builds the same client for Linux (crypto on
OpenSSL) so the protocol can be exercised against the gateway without hardware —
handy while making changes.

## Memory

ML-KEM-1024 needs a noticeable amount of stack (a 3,168-byte key plus working
buffers). In `sdkconfig.defaults` the main task's stack is raised to 24 KB. The
ESP32-C6 has less memory than the S3 — if allocation failures appear, enable
PSRAM on the S3-N8R2 or reduce the buffers.

## Signature

**ECDSA P-256** is used, following the analysis (SLH-DSA is impractical on the
ESP32: signing takes hundreds of milliseconds and produces 7,856 bytes).

A hardware elliptic-curve accelerator is present **only on the ESP32-C6**, where
signing takes 22.2 ms. The ESP32-S3 has no such block, so the same operation
runs in software and takes 170.2 ms — a difference of 7.7×. This is worth
keeping in mind when choosing a board if handshakes happen frequently.

## Common build and flashing problems

Collected from real deployment experience on Manjaro/Arch.

**`idf.py: command not found`.** The ESP-IDF environment has not been activated.
In every new terminal session:

```bash
. ~/esp/esp-idf/export.sh
```

**The target list (`set-target`) is empty.** ESP-IDF is not installed, or the
VS Code extension does not know where it lives. Check `echo $IDF_PATH`.

**The port will not open (`Permission denied`).** On Arch/Manjaro the group for
serial ports is `uucp` (not `dialout` as on Ubuntu):

```bash
sudo usermod -aG uucp $USER    # then log out and back in
```

**Which port belongs to the board.** The XIAO uses the chip's native USB and
appears as `/dev/ttyACM0`. The ESP32-S3-DevKitC-1 has an external USB-UART
bridge, so it appears as `/dev/ttyUSB0`. If esptool cannot find the port, check
both.

**The board does not respond / the port vanished / `error -71`.** The XIAO's
native USB can get stuck after a failed reset attempt. To enter the bootloader
manually: unplug USB → press and hold **BOOT** → plug USB back in → release
BOOT. Then `idf.py -p /dev/ttyACM0 flash`, followed by RESET.

**`build.ninja: expected build command name`.** The build directory was
corrupted by an interrupted build. Cured by `rm -rf build`.

**The build fails inside ESP-IDF (internal compiler error, `corrupted size`).**
A sign of a damaged cache or an unstable IDF branch state. Check that you are on
a release tag rather than an intermediate commit:

```bash
cd ~/esp/esp-idf && git describe --tags      # should read e.g. v5.4.4
```

If you see a tail like `v5.4.4-813-g...`, switch to the tag:
`git checkout v5.4.4 && git submodule update --init --recursive && ./install.sh esp32s3,esp32c6`.
`ccache -C` and a single-threaded build (`idf.py -j1 build`) also help.

**`undefined reference to mbedtls_chachapoly_*`.** ChaCha20-Poly1305 is not
enabled in `sdkconfig`. The `CHACHAPOLY` option depends on `POLY1305`, which in
turn depends on `CHACHA20`, so all three are required (they are present in
`sdkconfig.defaults`). If `sdkconfig` already exists it will not pick up changes
made to the defaults — delete it and regenerate:
`rm -f sdkconfig && idf.py set-target esp32s3`.

**Leaving the monitor** — `Ctrl+]`. To rebuild and reflash without leaving the
monitor: `Ctrl+T`, then `Ctrl+F`.

## Partition table

The firmware does not fit the stock 1 MB application partition: ML-KEM + BLAKE3 +
mbedTLS + Wi-Fi come to roughly 1.0–1.1 MB. The project therefore carries its own
table (`partitions.csv`) with a **2 MB** application partition; it is wired in
through `sdkconfig.defaults` and applied automatically.

Board flash sizes: XIAO ESP32-C6 — 4 MB; XIAO ESP32-S3 and ESP32-S3-DevKitC-1 —
8 MB. The `CONFIG_ESPTOOLPY_FLASHSIZE_4MB` setting suits all of them (on the
8 MB boards the remainder simply goes unused).

## Performance measurements on the board

`main/main.c` provides two independent mechanisms (both enabled by default):

**`LACERT_MEASURE`** — measures the real protocol operations (handshake,
rotation, firmware-check response) and sends the results along with telemetry.
They land in the database and on the dashboard charts. Useful for monitoring
operation and for spotting memory leaks (the `heap_free` and `heap_min` fields).

Important: these figures **include the network exchange** over Wi-Fi, so they are
not suitable for comparing platforms.

**`LACERT_BENCH`** — a microbenchmark: at startup, before joining Wi-Fi, it runs
each cryptographic operation 20 times **without networking** and prints the
averages:

```
==================================================
CRYPTOGRAPHY MICROBENCHMARK (no networking)
board: ESP32-C6 (RISC-V, 160 MHz)
--------------------------------------------------
  ECDSA P-256 keypair              9.63 ms   (5 runs)
  ECDSA P-256 sign                22.20 ms   (20 runs)
  ML-KEM-1024 keypair             15.06 ms   (5 runs)
  ML-KEM-1024 encapsulate         15.99 ms   (20 runs)
  ML-KEM-1024 decapsulate         17.78 ms   (20 runs)
  BLAKE3 (key derivation)          19.8 µs   (200 runs)
  SHA-256 (96 bytes)               41.7 µs   (200 runs)
  ChaCha20-Poly1305 seal          210.6 µs   (200 runs)
==================================================
```

This is the correct instrument for comparing architectures. The same set of
operations, run by the same code, is executed on the host by
`linux-debug/bench_host.c`.

Results for all boards, and the conclusions drawn from them, are in
`FIRMWARE.md`.

**The measurements depend on build settings.** By default ESP-IDF builds with
`-Og` (no optimisation), and on such a build cryptography runs several times
slower. `sdkconfig.defaults` enables `-Os` and the hardware accelerators (MPI,
SHA, and ECC on the C6). To confirm they were applied:

```bash
grep -E 'COMPILER_OPTIMIZATION|MBEDTLS_HARDWARE' sdkconfig
```

If you edited `sdkconfig.defaults`, an existing `sdkconfig` will not pick the
changes up — it has to be deleted:
`rm -f sdkconfig && idf.py set-target esp32s3`.
