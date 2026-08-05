# The contribution of the hardware ECC accelerator: verified by measurement

> **Language:** English · [Русский](../ru/ECC_ACCELERATOR.md)

ECDSA P-256 signing takes 22.2 ms on the ESP32-C6 against 170.2 ms on the
ESP32-S3 — a 7.7x gap, in favour of the board that runs at the lower clock
(160 MHz against 240 MHz). This document tests where that gap comes from and
separates what is confirmed by measurement from what is taken on the strength of
vendor documentation.

## The question

The original explanation was that the C6 has a hardware elliptic-curve
accelerator and the S3 does not. Plausible, but resting on the manufacturer's
documentation rather than on a measurement of our own. Other causes are
conceivable: differences between the Xtensa and RISC-V toolchains, differences
in how mbedTLS is implemented for each architecture, differing cache sizes.

The claim under test: **the gap is created by the hardware ECC block**. If so, a
C6 build with the accelerator disabled should sign in a time consistent with a
purely software computation.

## Two different blocks that are easy to conflate

Discussion of this result (see Acknowledgements) showed that the confusion comes
from not distinguishing two separate peripherals:

| Block | What it does | C6 | S3 | found on |
|-------|--------------|----|-----|----------|
| **ECC Accelerator** | speeds up elliptic-curve arithmetic | **yes** | **no** | some of the family |
| **ECDSA_DS** (signing) | performs the whole signature, key held in eFuse | no | no | H2, C5, C61, P4 and others |

The list of chips carrying the signing peripheral is deliberately left
incomplete: it grows with every generation, and any list written into prose will
go stale. The dependable way to check is ESP-IDF's own capability headers, which
declare `SOC_ECC_SUPPORTED` and `SOC_ECDSA_SUPPORTED` (see below). For the four
named above, the presence of the block was checked against the official ESP-IDF
documentation pages devoted to it.

Which has consequences worth keeping in mind:

- on the C6 signing is accelerated, but **no eFuse-protected key storage comes
  with it** — that requires ECDSA_DS, which the C6 does not have
- an "ECC (HW) ✓" mark in a comparison table does not imply comparable
  performance across chip generations
- the absence of ECDSA_DS on both C6 and S3 does **not** mean both fall back on
  the same general block: the C6 has a dedicated ECC accelerator, the S3 has
  nothing beyond its bignum accelerator.

### Sources

Chapter listings in the technical reference manuals. On the C6, "ECC
Accelerator (ECC)" and "RSA Digital Signature Peripheral (RSA_DS)" are separate
chapters standing next to each other. On the S3, the same section holds only
RSA, HMAC, Digital Signature, XTS_AES, Clock Glitch Detection and the random
number generator. There is no ECC chapter.

- [ESP32-C6 Technical Reference Manual](https://documentation.espressif.com/esp32-c6_technical_reference_manual_en.pdf)
- [ESP32-C6 Datasheet](https://documentation.espressif.com/esp32-c6_datasheet_en.pdf) — description of the block
- [mbedTLS in ESP-IDF for the C6](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/protocols/mbedtls.html) — `CONFIG_MBEDTLS_HARDWARE_ECC` present
- [mbedTLS in ESP-IDF for the S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/protocols/mbedtls.html) — only `CONFIG_MBEDTLS_HARDWARE_MPI`

The machine-readable source, and the one that actually gates these options:
`SOC_ECC_SUPPORTED` and `SOC_ECDSA_SUPPORTED` in
`components/soc/<target>/include/soc/soc_caps.h` in the ESP-IDF tree. One
command settles it:

```bash
grep -H "SOC_ECC_SUPPORTED\|SOC_ECDSA_SUPPORTED" \
  $IDF_PATH/components/soc/esp32s3/include/soc/soc_caps.h \
  $IDF_PATH/components/soc/esp32c6/include/soc/soc_caps.h \
  $IDF_PATH/components/soc/esp32c5/include/soc/soc_caps.h
```

A caveat on documentation versions: the ESP-IDF v6.0 pages show a generic preset
listing that includes `HARDWARE_ECC` even for the original ESP32, which has no
such block. Use the 5.x pages, which are tied to a specific build target.

### Indirect confirmation from an independent source

The distinction between the two blocks is confirmed by more than a reading of the
reference manuals. Espressif's security advisory AR2026-006 reports a flaw in
signature verification during secure boot and lists the affected chips: H2, C5,
C61 and P4. The vulnerability concerns ECDSA-based boot, that is, the operation
of the dedicated signing peripheral.

Neither the C6 nor the C2 appears on that list. Both have an elliptic-curve
accelerator but no signing peripheral, so the vulnerable path does not exist on
them. The list of affected chips turns out to be, in effect, a list of those
whose dedicated signing is implemented in hardware, and the C6's absence from it
confirms the distinction between the blocks from a direction independent of
reading capability tables.

### Why the accelerator does not help X25519

The ESP32-C2 datasheet describes the block's capabilities in more detail than the
C6 description does, and the list explains the measurement: the block supports
**two curves, P-192 and P-256**, across seven working modes — base point
verification and multiplication, Jacobian point verification and multiplication.

Curve25519 is not on that list and could not be: it is a Montgomery curve, while
the block is built for NIST curves in Weierstrass form. Hence the measured
result — 121.37 ms against 119.33 with the accelerator on and off, that is, no
difference at all.

## Method

Measurements are taken with the firmware's built-in microbenchmark
(`LACERT_BENCH`) — the same one that produced every other figure in this work:
twenty runs per operation, each iteration timed separately, pauses between
iterations excluded from the result. Exactly one build parameter differs between
the two runs.

**Control group.** Only elliptic-curve operations go through the ECC
accelerator. ML-KEM, BLAKE3, SHA-256 and ChaCha20 do not use it, so their timings
must not change between the two builds. If they do, the difference is not
confined to one parameter and the measurement is void.

### Run 0: re-verifying the published figures

Before comparing anything, the original figures have to reproduce. The
measurements in this work were taken earlier. Both the firmware and the build
environment have changed since, and if 22.2 ms does not come back today there is
nothing to compare the second run against.

Both boards are run in their current configuration, without a single edit.

```bash
cd firmware

# C6
rm -f sdkconfig
idf.py set-target esp32c6
idf.py build flash monitor        # exit with Ctrl+]

# S3
rm -f sdkconfig
idf.py fullclean
idf.py set-target esp32s3
idf.py build flash monitor
```

Deleting `sdkconfig` before switching targets is required: without it
`set-target` does not always overwrite an existing configuration, and you can end
up building for the previous chip without noticing. Confirm the target actually
changed:

```bash
grep -m1 "^CONFIG_IDF_TARGET=" sdkconfig
```

The results are then set against the published ones. A few percent of difference
is normal — clock and cache state vary. A difference of several times over means
something substantial has changed, and that is what needs looking into before
moving on to the main experiment.

| Operation | Published | Re-measured | Difference |
|-----------|-----------|-------------|------------|
| C6, ECDSA sign | 22.2 ms | 21.90 ms | −1.4 % |
| C6, ECDSA keygen | 9.6 ms | 8.85 ms | −7.8 % |
| C6, ML-KEM-1024 encapsulate | 16.0 ms | 15.97 ms | −0.2 % |
| C6, ML-KEM-1024 decapsulate | 17.8 ms | 17.70 ms | −0.6 % |
| S3, ECDSA sign | 170.2 ms | 167.97 ms | −1.3 % |
| S3, ECDSA keygen | 156.7 ms | 154.47 ms | −1.4 % |
| S3, ML-KEM-1024 encapsulate | 18.4 ms | 17.89 ms | −2.8 % |
| S3, ML-KEM-1024 decapsulate | 21.1 ms | 20.37 ms | −3.5 % |

The figures reproduced: differences of a few percent, around one percent for the
key operations. They were taken with a different firmware, built separately,
which makes the agreement more meaningful.

Repeatability across board instances was checked separately: two different
ESP32-S3 boards (XIAO and DevKitC-1) gave 167.97 and 167.97 ms for signing,
154.47 and 154.34 ms for key generation. Variation between instances of the same
model is negligible.

**Two corrections found during the cross-check.**

BLAKE3 key derivation diverged more than anything else: 17.5 µs against the
published 19.8 on the C6, and 16.4 against 18.0 on the S3. The roughly ten
percent gap comes from an extra call layer in the production firmware, where the
operation goes through a protocol wrapper. Here it is called directly.

ChaCha20-Poly1305 diverged threefold, and the cause was not the measurement. The
original benchmark runs on a 96-byte message (the size of `msg` in the firmware),
whereas this one uses an actual kilobyte. The project documentation gives no size
for that row at all, but a public write-up of the results labelled it "1 KB" —
that label is wrong and needs correcting. Comparable figures: 96 bytes takes
210.6 µs, 1024 bytes takes 715.0 µs on the C6.

### Run 1: accelerator enabled

```bash
cd firmware
grep -n MBEDTLS_HARDWARE_ECC sdkconfig.defaults.esp32c6   # expect =y
rm -f sdkconfig
idf.py set-target esp32c6
idf.py build flash monitor
```

Record the `ECDSA P-256 sign` and `ECDSA P-256 keypair` lines, along with the
control group figures.

### Run 2: accelerator disabled

```bash
sed -i 's/^CONFIG_MBEDTLS_HARDWARE_ECC=y/# CONFIG_MBEDTLS_HARDWARE_ECC is not set/' \
  sdkconfig.defaults.esp32c6
rm -f sdkconfig
idf.py fullclean
idf.py set-target esp32c6
idf.py build flash monitor
```

Deleting `sdkconfig` is required: `idf.py fullclean` clears the build directory
but leaves the configuration file alone, and without removing it the edit to
`sdkconfig.defaults` has no effect.

Afterwards, restore the setting:

```bash
sed -i 's/^# CONFIG_MBEDTLS_HARDWARE_ECC is not set/CONFIG_MBEDTLS_HARDWARE_ECC=y/' \
  sdkconfig.defaults.esp32c6
rm -f sdkconfig
```

## Prediction, recorded before measuring

Written down in advance so the result cannot be fitted to the expectation.

If the accelerator is what creates the gap, signing on the C6 with the block
disabled should become **slower than on the S3**: a software computation at
160 MHz should lose to a software computation at 240 MHz by roughly half again.
So the expected figure is on the order of 250 ms against the S3's 170.2 ms.

If instead the time stays near 22 ms, the explanation is wrong and the cause
lies elsewhere — in differences between the mbedTLS implementations for the two
architectures, for instance.

## Results

The runs were made with the firmware in `bench/`, twenty iterations per
operation. Exactly one build parameter differs between the first and second run.

### What the accelerator contributes: one board against itself

| Operation | Accelerator on | Off | Factor |
|-----------|----------------|-----|--------|
| ECDSA, keygen | 8.85 ms | 145.15 ms | **16.4** |
| ECDSA, sign | 21.90 ms | 158.05 ms | **7.2** |
| ECDSA, verify | 41.58 ms | 313.10 ms | **7.5** |
| ECDH P-256, keygen | 8.77 ms | 145.01 ms | **16.5** |
| ECDH P-256, point multiply | 8.60 ms | 144.80 ms | **16.8** |
| X25519, keygen | 120.41 ms | 119.33 ms | 1.0 |
| X25519, point multiply | 121.37 ms | 123.79 ms | 1.0 |

### Control group

Operations that do not go through the accelerator and therefore must not change:

| Operation | Run 1 | Run 2 | Difference |
|-----------|-------|-------|------------|
| ML-KEM-1024, keygen | 15.11 ms | 15.15 ms | 0.26 % |
| ML-KEM-1024, encapsulate | 15.97 ms | 15.99 ms | 0.13 % |
| ML-KEM-1024, decapsulate | 17.70 ms | 17.72 ms | 0.11 % |
| SHA-256, 1 KB | 49.9 µs | 49.9 µs | 0 % |
| BLAKE3, 1 KB | 164.9 µs | 164.9 µs | 0 % |
| SLH-DSA-128s, keygen | 13,295.00 ms | 13,295.00 ms | 0 % |
| SLH-DSA-128s, sign | 101,057.49 ms | 101,057.48 ms | 0.00001 % |

The SLH-DSA signature matching to hundredths of a millisecond over a hundred
seconds is the strictest check available: it rules out even accidental
agreement. agreement to hundredths of a percent confirms that exactly one parameter changed
between builds, and that the difference seen in curve operations is down to it.

### Between the boards

| Operation | C6 with accelerator | C6 without | S3 |
|-----------|---------------------|------------|-----|
| ECDSA, sign | 21.90 ms | 158.05 ms | 167.97 ms |
| ECDSA, verify | 41.58 ms | 313.10 ms | 330.93 ms |
| ECDH P-256, point multiply | 8.60 ms | 144.80 ms | 154.41 ms |
| X25519, point multiply | 121.37 ms | 123.79 ms | 127.77 ms |

## Conclusions

**The claim holds.** The gap in curve-operation speed is created by the hardware
ECC block. Turning off a single setting, on the same chip and in the same
firmware, slows signing by 7.2x and operations that rely solely on point
multiplication by 16.5x. The control group did not move.

**The prediction was wrong about magnitude.** The expectation was that the C6
without its accelerator would come out roughly half as fast as the S3, following
the clock ratio of 160 MHz against 240. In fact the C6 without the accelerator is
slightly **faster**: 158.05 against 167.97 ms for signing. The same ratio of
about 1.06 repeats across every software operation, X25519 included, which the
accelerator never touches.

So on equal terms, with no hardware assistance, the C6 gets more done per clock.
Nothing here explains why: it could be differences in the bignum implementation
for the two architectures, in cache behaviour, or in the bignum accelerator
itself, which is enabled on both boards. These numbers raise the question rather
than answer it.

What matters is that the error in the prediction does not touch the main
conclusion, which rests on comparing one board against itself, where everything
else is identical down to the build.

**The accelerator covers NIST curves but not Curve25519.** X25519 came out at
120.41 against 119.33 ms — no difference at all. The block works with P-256 and
sits out for Curve25519, which is computed in software on both boards.

That matters for choosing a scheme. The German BSI TR-02102 standard recommends a
hybrid of X25519 and ML-KEM rather than a clean switch to a post-quantum scheme.
On the ESP32-C6 the classical half of such a hybrid costs 120 ms — more than the
entire ML-KEM-1024 encapsulation (15.97 ms), and fourteen times more than P-256
agreement with the accelerator (8.60 ms). The BSI recommendation was not written
for microcontrollers, and on this chip its price turns out to be substantial.

## A claim overturned: ECDH is accelerated

This work stated that ECDH key agreement differs between the boards by only
1.05x, and concluded from that the accelerator is not engaged on that path.
**That is wrong.**

Direct measurement gives:

| | C6 | S3 | Ratio |
|---|---|---|---|
| ECDH P-256, point multiply | 8.60 ms | 154.41 ms | **18.0** |

Not 1.05 but eighteen. And disabling the accelerator on the C6 slows the same
operation by 16.8x, which leaves no doubt about the cause.

The error was in how the figure was obtained. The earlier value was inferred
indirectly, from a DTLS-ECDHE-PSK handshake time, on the assumption that the
symmetric part was small beside it. The assumption did not hold: something else
dominated that handshake, and the difference in key agreement simply vanished
inside it.

This is precisely the case flagged in the write-up as indirect and the weakest
link in the numbers. The weak link is what gave way.

The practical lesson: a value obtained by subtracting from a composite timing
needs a direct measurement to back it before anything is built on top of it.

## Stack usage

The firmware reports actual usage after each group. Measurement confirmed the
estimate made beforehand with `-fstack-usage`:

| Algorithm | Estimated in advance | Measured on hardware |
|-----------|----------------------|----------------------|
| ML-DSA-87 | 121 KB | 119.9 KB |
| ML-DSA-65 | 78 KB | 77.9 KB |
| ML-DSA-44 | 51 KB | 50.9 KB |
| ML-KEM-1024 (and lower levels) | — | 20.3 KB |
| Classical primitives | — | 6.0 KB |

Hence a practical conclusion for embedded work: with post-quantum signatures the
binding constraint is stack, not time. A single ML-DSA-87 call needs 120 KB —
more than many tasks are given in total, and an order of magnitude more than all
the classical cryptography in the protocol. SLH-DSA, meanwhile, spends under a
kilobyte and pays in time instead.

## A security note on the signing peripheral

Espressif advisory **AR2026-006** concerns that very peripheral: on four chips —
H2, C5, C61 and P4 — the ROM-level signature check can accept an invalid
signature as valid. An attacker able to replace the firmware image in flash can
thereby bypass Secure Boot.

The advisory has no bearing on this work, and it is worth saying so plainly so
that no false connection is drawn:

- the flaw sits in the bootloader's signature check in ROM, not in the
  application-level verification the protocol performs
- neither the ESP32-C6 nor the ESP32-S3, on which every measurement here was
  taken, appears among the affected chips
- anyone using RSA rather than ECDSA for Secure Boot is unaffected entirely,
  while on the C61 there is no RSA fallback, since ECDSA is the only scheme it
  supports

It is mentioned here because this work is about device authenticity, and a reader
may reasonably expect known weaknesses in the corresponding hardware blocks to be
named.

## Acknowledgements

The distinction between the ECC accelerator and the ECDSA_DS signing peripheral
entered this document through a discussion with
[`artkeller-42`](https://github.com/artkeller), who maintains a capability matrix
for the ESP32 family —
[ESP32Features](https://github.com/artkeller/ESP32Features). He checked the
reference manuals and established that a dedicated ECDSA_DS signing peripheral
belongs to other chips in the family rather than to the C6 or the S3, while the
C6's own signing peripheral is RSA-flavoured.
That correction sharpened the explanation: the cause is not the signing
peripheral, which neither chip has, but the ECC accelerator, which the C6 has and
the S3 does not.

He also pointed out that the original list of chips carrying the signing
peripheral was incomplete: there are not two but at least six, and the single gap
in his own table turned out to be the P4. The list here has been replaced with a
pointer to the machine-readable source, which will not go stale.

The same discussion also brought the AR2026-006 advisory to light, whose list of
affected chips yields the indirect confirmation described above. The X25519
measurement from this work has in turn been cited in his capability table.

From the same discussion came a pointer to the German BSI TR-02102 standard,
which sets 2030 as the deadline for data in the high-protection category — a
stricter date than the 2035 figure this work originally cited — and to advisory
AR2026-006, discussed above.
