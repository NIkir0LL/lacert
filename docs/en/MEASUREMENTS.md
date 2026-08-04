> **Language:** English · [Русский](../ru/MEASUREMENTS.md)

# Measurement methodology and results

This section describes how every numerical value quoted in the project was
obtained. All measurements were carried out on our own test bench. Not a single
figure is taken from the literature or from vendor documentation. The
description given here is sufficient to reproduce any of the measurements.

---

## 1. Test bench

### 1.1. Hardware

| Label | Device | Core | Clock | Flash | Notes |
|-------|--------|------|-------|-------|-------|
| C6 | Seeed XIAO ESP32-C6 (ESP32-C6FH4, rev. v0.2) | RISC-V, 1 core + LP | 160 MHz | 4 MB | has a hardware ECC accelerator |
| S3 | Seeed XIAO ESP32-S3 | Xtensa LX7, 2 cores | 240 MHz | 8 MB | no ECC accelerator |
| S3-DK | Espressif ESP32-S3-DevKitC-1 | Xtensa LX7, 2 cores | 240 MHz | 8 MB | no ECC accelerator |
| Server | PC running the gateway (x86-64) | — | — | — | comparison baseline |

The board characteristics were read from the chips themselves
(`esptool.py flash_id`) rather than taken from datasheets.

### 1.2. Software

| Component | Version / source |
|-----------|------------------|
| ESP-IDF | v5.4.4 (release tag) |
| Device compiler | riscv32-esp-elf / xtensa-esp32s3-elf from the ESP-IDF distribution |
| Host compiler | GCC 13.3.0 |
| Gateway | Go 1.22 |
| ML-KEM-1024 | PQClean (reference implementation, compiled from source as part of the firmware) |
| BLAKE3 | reference portable implementation |
| ECDSA P-256, SHA-256, ChaCha20-Poly1305 | mbedTLS from the ESP-IDF distribution |
| Database | PostgreSQL 16 |

### 1.3. Firmware build configuration

Build settings materially affect the result, so they are stated explicitly (the
file `firmware/sdkconfig.defaults`):

```
CONFIG_COMPILER_OPTIMIZATION_SIZE=y     # -Os (rather than the default debug -Og)
CONFIG_MBEDTLS_HARDWARE_MPI=y           # hardware big-number unit
CONFIG_MBEDTLS_HARDWARE_SHA=y           # hardware SHA-256
CONFIG_MBEDTLS_ECP_NIST_OPTIM=y         # optimized arithmetic for P-256
CONFIG_MBEDTLS_HARDWARE_ECC=y           # ESP32-C6 only: the ECC accelerator
```

**Rationale.** ESP-IDF builds a project with `-Og` (a debug build) by default. In
such a build cryptographic operations run several times slower than in real
firmware, and the resulting figures would characterize the debug mode rather
than the algorithm. Every measurement reported here was taken from an optimized
build. Both boards were built with identical settings, so the architectural
comparison is valid.

---

## 2. Methodology for measuring cryptographic operations

### 2.1. What is measured

What is measured is the execution time of individual cryptographic primitives
**without any network exchange**. This is essential: a full handshake involves
three packet exchanges over Wi-Fi whose latency amounts to tens of milliseconds,
fluctuates, and does not depend on the chip. Comparing architectures by that
figure would not be valid.

The instrument is the `LACERT_BENCH` mode in the firmware
(`firmware/main/main.c`). It runs automatically when the board powers up, before
it joins the network, and prints its results to the serial port.

### 2.2. Measurement procedure

The operations are split into two groups, because their costs differ by four
orders of magnitude:

**Heavy operations** (ECDSA, ML-KEM — from single-digit to hundreds of
milliseconds). Each iteration is timed separately. The results are summed and
divided by the number of iterations (20, or 5 for key-pair generation). A
`vTaskDelay(1)` is executed between iterations: without it the task holds the
CPU core longer than the watchdog timeout (a single ECDSA signature on the
ESP32-S3 takes about 170 ms, so twenty in a row means 3.5 s) and the device
resets. The pause sits **between** measurements and is not part of the measured
interval.

**Light operations** (BLAKE3, SHA-256, ChaCha20-Poly1305 — tens of
microseconds). The whole loop is timed (200 iterations) with a single timer read
for the entire loop. Per-iteration timing is not admissible here: two calls to
the time function cost several microseconds, which — for an operation lasting
tens of microseconds — inflates the result by tens of per cent. Verified
experimentally: BLAKE3 timed per iteration reported 42.9 µs, timed as a whole
loop 17.9 µs.

The time source on the board is `esp_timer_get_time()` (a hardware timer with
1 µs resolution).

### 2.3. Comparability with the baseline

The x86-64 figures were obtained with **the same implementation and the same
methodology**: the program `firmware/linux-debug/bench_host.c` is built from the
same cryptographic-core sources (`lacert_crypto.c`, PQClean, BLAKE3) as the
firmware. Because of this, the divergence between platforms cannot be explained
by differing libraries — the very same code is being compared.

---

## 3. Results: cryptographic operations

Average time for a single operation. Every value is a mean over 20 runs (5 for
key-pair generation, 200 for the light operations).

| Operation | x86-64 | ESP32-S3 (Xtensa, 240 MHz) | ESP32-C6 (RISC-V, 160 MHz) |
|-----------|--------|----------------------------|----------------------------|
| ECDSA P-256, sign | 0.35 ms | 170.2 ms | **22.2 ms** |
| ECDSA P-256, key-pair generation | 0.30 ms | 156.7 ms | **9.6 ms** |
| ML-KEM-1024, key-pair generation | 0.11 ms | 16.7 ms | 15.1 ms |
| ML-KEM-1024, encapsulation | 0.11 ms | 18.4 ms | 16.0 ms |
| ML-KEM-1024, decapsulation | 0.12 ms | 21.1 ms | 17.8 ms |
| BLAKE3, key derivation | 2.0 µs | 18.0 µs | 19.8 µs |
| SHA-256 (96 bytes) | 0.7 µs | 60.1 µs | 41.7 µs |
| ChaCha20-Poly1305, encryption | 12.4 µs | 150.5 µs | 210.6 µs |
| Free memory after initialization | — | 252 KB | 295 KB |

The board figures were taken with `LACERT_SHARED_CRYPTO_CTX = 1` (the shared
cryptographic context, see section 3.4).

The size of an ECDSA P-256 signature in DER encoding is variable, 69–72 bytes,
depending on the leading zeros in the signature components.

### 3.1. Principal observations

**1. Signing with ECDSA runs 7.7× faster on the ESP32-C6 than on the ESP32-S3**,
even though the C6 is the weaker chip in computational terms (one core against
two, 160 MHz against 240).

The cause is not core performance, as the remaining rows of the table confirm:
on ML-KEM operations the boards are comparable (17.8 against 21.1 ms), while on
BLAKE3 and ChaCha20 the ESP32-C6 is in fact **slower** than the ESP32-S3 — as
one would expect at a lower clock speed. The speed-up appears exclusively on
elliptic-curve operations, for which the ESP32-C6 has a hardware accelerator
that the ESP32-S3 lacks.

**Conclusion:** when choosing a microcontroller for cryptography-intensive work,
the presence of a dedicated hardware accelerator matters more than clock speed
or core count.

**2. ML-KEM-1024 performance depends only weakly on the platform** (16–21 ms on
both boards). Neither chip has a hardware accelerator for lattice cryptography,
so the operations run entirely in software. It follows that moving to
post-quantum key exchange costs roughly the same on any chip of this class,
whereas the cost of the signature depends substantially on the specific model.

**3. The ratio between microcontroller and server cost differs between
primitives.** ECDSA signing on the ESP32-S3 is about 490× slower than on the
server, while ML-KEM operations are about 170× slower. In other words, on a
microcontroller post-quantum key exchange becomes relatively "cheaper" than the
classical signature, which further supports the chosen architecture
(post-quantum KEM + ECDSA).

### 3.2. Comparing signature algorithms on the server platform

A separate series of measurements compares the three signature schemes as
implemented in the gateway (Go). Unlike section 3, which compared platforms,
this compares **algorithms against one another** on a single machine.

**Bench and methodology.** AMD Ryzen 7 5700X, Windows, Go 1.22, the standard
benchmark mechanism (`go test -bench`). The fast operations were measured by
time (`-benchtime=2s`, on the order of 10⁵ iterations) and repeated three times
(`-count=3`). The spread between repeats did not exceed 1.5 %. SLH-DSA was
measured by iteration count (`-benchtime=10x`), since a single signature takes
about a quarter of a second.

| Algorithm | Quantum resistance | Sign | Verify | Key-pair generation | Memory per signature |
|-----------|--------------------|------|--------|---------------------|----------------------|
| ECDSA P-256 | no (discrete logarithm) | 25.2 µs | 56.7 µs | 11.2 µs | 6,336 B / 67 allocations |
| Ed25519 | no (discrete logarithm) | **19.5 µs** | **45.1 µs** | 16.0 µs | **64 B / 1 allocation** |
| SLH-DSA-SHA2-128s | **yes** (hash-function security) | 234.3 ms | 232.5 µs | — | 15,670 B / 37 allocations |

The resistance column is essential for interpreting the others: ECDSA and
Ed25519 rest on the same problem — the discrete logarithm in the group of points
of an elliptic curve — and Shor's algorithm solves it in polynomial time,
invalidating both schemes equally. The difference in curves (P-256 versus
edwards25519) does not affect this. Among the signature schemes considered, only
SLH-DSA provides post-quantum security.

Supporting protocol operations on the same machine: ML-KEM-1024 key-pair
generation — 36.5 µs, encapsulation — 12.9 µs, decapsulation — 19.4 µs, a key
rotation step — 34.7 µs, packet encryption — 0.83 µs.

**Observation 1. With SLH-DSA only signing is expensive.** Verification takes
232.5 µs and is merely four times slower than ECDSA, whereas signing takes
234.3 ms — 9,300× more expensive than ECDSA and **a thousand times more
expensive than its own verification**.

For the architecture under consideration this asymmetry is unfavorable: the
signature is produced by the device (a microcontroller) and verified by the
gateway (a server). The entire cost of the algorithm therefore falls on the
least capable node in the system.

**Observation 2. Ed25519 beats ECDSA moderately on time and dramatically on
memory.** Signing is 23 % faster and verification 20 % faster, but the amount of
memory allocated differs by a factor of 99, and the number of calls to the
allocator by a factor of 67 (one against sixty-seven). Ed25519 key-pair
generation, conversely, is 44 % slower, which is of no practical consequence: it
happens once in the lifetime of a device.

On a server platform the memory advantage is immaterial. On a microcontroller
with a constrained heap, however, it determines how predictable the behavior
is — less fragmentation and less risk of an allocation failure.

An important caveat: **Ed25519 is not a post-quantum scheme**. The comparison
above is an engineering one — it answers the question of what a classical
signature costs, not of resistance to a quantum adversary. Replacing ECDSA with
Ed25519 would not have brought the system closer to post-quantum protection:
both schemes rest on the same problem and are equally vulnerable to Shor's
algorithm. The final choice of signature scheme and the reasons for rejecting
Ed25519 are set out in [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md), section 9.

### 3.3. The cost of the signature choice at protocol level

The figures above characterize isolated operations. The practical question is
what the choice of algorithm costs **the protocol as a whole**. To answer it,
the complete handshake (three messages, including the ML-KEM exchange, key
derivation and confirmation) was measured in two variants:

| Handshake variant | Time | Memory | Allocations |
|-------------------|------|--------|-------------|
| with ECDSA P-256 | 122.8 µs | 13,704 B | 108 |
| with SLH-DSA-SHA2-128s | 235.2 ms | 28,228 B | 92 |

Switching to SLH-DSA makes the protocol **1,914× more expensive**. That ratio is
substantially lower than the 9,300 measured for the isolated signature, and it
reflects the practical consequences of the choice more accurately.

Notably, SLH-DSA requires twice the memory but fewer allocations (92 against
108): the signature is carried as a single 7,856-byte block, whereas ECDSA
spreads its work across many small allocations.

**Composition of the ECDSA handshake.** Breaking the total time down by
operation:

| Operation | Time | Share |
|-----------|------|-------|
| Signature verification (gateway) | 56.7 µs | 46 % |
| Signature generation (device) | 25.2 µs | 20 % |
| ML-KEM decapsulation | 19.4 µs | 16 % |
| ML-KEM encapsulation | 12.9 µs | 10 % |
| BLAKE3, framing, other | 8.8 µs | 7 % |

**Observation 3.** Signature operations account for 67 % of handshake time and
post-quantum key exchange for 26 %. The bottleneck of the protocol is therefore
the classical signature rather than the post-quantum part — and this already
holds on the server platform, not only on the microcontroller, where the same
effect is more pronounced (see observation 1 in section 3.1).

This result supports the chosen architecture: moving post-quantum strength to
the key-exchange layer creates no computational bottleneck, and further
optimization of the protocol should be directed at the signature operations.

### 3.4. The cost of preparing the cryptographic context

In the original firmware implementation, the random number generator (CTR-DRBG)
and the P-256 curve parameters were created afresh on every call to sign. The
hypothesis tested was that moving them into a shared context, created once,
would reduce the time of the operation.

The `LACERT_SHARED_CRYPTO_CTX` switch in `firmware/main/lacert_crypto.c` builds
either version from the same source, which makes it possible to measure both on
one board under identical conditions.

| Board | Operation | Context per call | Shared context | Gain |
|-------|-----------|------------------|----------------|------|
| ESP32-C6 | sign | 25.70 ms | 22.20 ms | 13.6 % |
| ESP32-C6 | key-pair generation | 12.40 ms | 9.63 ms | 22.3 % |
| ESP32-S3 | sign | 172.48 ms | 170.23 ms | 1.3 % |
| ESP32-S3 | key-pair generation | 158.04 ms | 156.67 ms | 0.9 % |

**Observation 4. The saving is a fixed quantity, while its relative weight
depends on how fast cryptography runs on the chip.** In absolute terms preparing
the context costs 1.4–3.5 ms on both boards, which is natural: that work does
not depend on the speed of the computation that follows. On the ESP32-C6, where
signing takes 22 ms thanks to the hardware accelerator, those milliseconds are a
noticeable share. On the ESP32-S3, with its 170 ms, they disappear into the
total.

The 1.3 % difference on the ESP32-S3 is comparable to the measurement error:
control operations untouched by the change diverged between runs by as much as
6.5 % (SHA-256), while the rest stayed within 0.6 %. For the ESP32-C6 the gains
of 13.6 % and 22.3 % lie well above the noise floor.

**The price of the optimization.** The shared context permanently occupies heap:
608 bytes on the ESP32-C6 and 448 bytes on the ESP32-S3. Against 250–300 KB of
free memory this is immaterial.

The optimization is left enabled by default. The switch remains in the code, so
the decision is reversible and open to re-verification.

**A separate note on the server platform.** On x86-64, built against mbedTLS
3.6, there is no difference between the two versions: 348.2 µs against 347.4 µs
by the median of fifteen runs. The gain appears only on the microcontroller,
where entropy comes from a hardware generator rather than from the operating
system. This illustrates that optimizations measured on a server platform do not
transfer to an embedded one automatically, nor the other way round.

### 3.5. Comparison with DTLS 1.2

The figures above characterize LACERT on its own. The practical question is what
a standard solution to the same problem costs. DTLS 1.2 as implemented in
mbedTLS was taken as the baseline: it targets the same scenarios (protecting
datagrams from embedded devices) and ships with ESP-IDF, so it adds no
dependencies.

**Conditions for comparability.** Both sides of each protocol run in a single
process and exchange data through in-memory buffers: the network is excluded,
since otherwise the channel latency would be what is measured. Both programs are
built with the same compiler and linked against the same build of mbedTLS 3.6.3.

That last point matters. The LACERT handshake was also measured in the Go
gateway implementation (section 3.3, 122.8 µs), but that figure cannot be
compared against DTLS: in Go, P-256 signing uses an assembly implementation and
takes 25 µs, whereas the same operation in mbedTLS takes 365 µs. A 14-fold
difference would reflect the choice of library rather than the properties of the
protocols. A separate bench was therefore written that reproduces the
cryptographic path of the LACERT handshake in C against the same mbedTLS.

**Choice of DTLS modes.** Three were used, since they provide different
guarantees:

- **DTLS-PSK** — a pre-shared secret. The lower bound on cost, but there is no
  authentication based on an individual device key, and revoking one device
  requires changing the key on all of them.
- **DTLS-ECDHE-PSK** — the same plus an ephemeral key exchange.
- **DTLS-ECDHE-ECDSA with mutual certificate verification** — the closest
  analogue of LACERT in its properties: both sides prove their identity and the
  session key is fresh.

The cipher suites are set explicitly. Without that, mbedTLS selects ECDHE-PSK for
"PSK" on its own, and the measurement stops being a lower bound.

#### Results (x86-64, mbedTLS 3.6.3, median of five runs)

| Protocol | Session establishment | Handshake traffic |
|----------|-----------------------|-------------------|
| DTLS-PSK | 89.9 µs | 408 bytes |
| **LACERT** | **1,846 µs** | **1,800 bytes** |
| DTLS-ECDHE-PSK | 2,816 µs | 538 bytes |
| DTLS-ECDHE-ECDSA (mutual) | 5,964 µs | 1,649 bytes |

Spread between runs: 3–10 %.

**Observation 5. At comparable guarantees, LACERT establishes a session 3.2×
faster than DTLS.** The comparison is legitimate precisely against the
ECDHE-ECDSA variant with mutual verification: only that one, like LACERT,
authenticates the device by its own key and derives a fresh session key.

The reason for the advantage is visible in the breakdown of the LACERT
handshake:

| Operation | Time | Share |
|-----------|------|-------|
| ECDSA signature verification (gateway) | 1,220.4 µs | 66 % |
| ECDSA signature generation (device) | 366.7 µs | 20 % |
| ML-KEM-1024 decapsulation (device) | 131.3 µs | 7 % |
| ML-KEM-1024 encapsulation (gateway) | 112.9 µs | 6 % |
| BLAKE3 key derivation | 60.8 µs | 3 % |

**Observation 6. The post-quantum key exchange is cheaper than the classical
one.** ML-KEM accounts for 13 % of the handshake, whereas ECDHE in DTLS costs
roughly 2,700 µs — which follows from the difference between DTLS-PSK and
DTLS-ECDHE-PSK. Replacing ECDHE with ML-KEM-1024 therefore not only provides
post-quantum strength but also saves time.

The difference in total cost is explained by DTLS-ECDHE-ECDSA performing both an
ephemeral elliptic-curve exchange and two signatures with certificate parsing,
while LACERT does one signature and one encapsulation.

#### Traffic volume — not in LACERT's favor

The LACERT handshake takes 1,800 bytes against 538 for DTLS-ECDHE-PSK. The cause
is the 1,568-byte ML-KEM-1024 ciphertext, an unavoidable property of the scheme.

| Message | Size | Contents |
|---------|------|----------|
| Msg1 | 113 bytes | identifier, 32-byte nonce, 65-byte ECDSA public key |
| Msg2 | 1,602 bytes | 1,568-byte ML-KEM ciphertext, 32-byte nonce |
| Msg3 | 73 bytes | ECDSA signature |
| Frame headers | 12 bytes | type and length, three messages |

For a battery-powered device this may outweigh the saving in time: radio
transmission is usually more expensive than computation. A mitigating factor is
that the handshake happens once per session, while subsequent key rotation
proceeds without a new ML-KEM exchange and adds only 32 bytes per step.

#### Verification on hardware: ESP32-S3 and ESP32-C6

The same bench was run on both boards, where client and server execute on one
chip. The boards differ in having a hardware accelerator for elliptic curves:
the ESP32-C6 has one, the ESP32-S3 does not. That makes the comparison
particularly telling — the accelerator works in favor of DTLS, since neither
board provides hardware support for ML-KEM operations.

| Protocol | ESP32-S3 | ESP32-C6 |
|----------|----------|----------|
| DTLS-ECDHE-PSK | 530.8 ms (407 B) | 505.9 ms (407 B) |
| DTLS-ECDHE-ECDSA (mutual) | 1,555.0 ms (1,455 B) | 649.1 ms (1,452 B) |

The DTLS-PSK mode is unavailable in the mbedTLS build shipped with ESP-IDF, so
the lower bound was not measured. Traffic differs from the x86 figures (538 and
1,649 bytes): the ESP-IDF build enables a different set of TLS extensions.

**Observation 7. The post-quantum key exchange is cheaper than the classical one
on both boards, and more so on the board with the hardware accelerator.** The
cost of ECDHE is estimated by the DTLS-ECDHE-PSK figure, since the symmetric part
of the handshake is negligible against it.

| | ESP32-S3 | ESP32-C6 | x86-64 |
|---|---|---|---|
| ECDHE (classical exchange) | 530.8 ms | 505.9 ms | ~2,726 µs |
| ML-KEM-1024 (encapsulation + decapsulation) | 39.6 ms | 33.8 ms | 244 µs |
| **ratio** | **13.4 : 1** | **15.0 : 1** | **11.2 : 1** |

The result is robust: the advantage of ML-KEM holds even where the hardware
favors its competitor.

**Observation 8 — REFUTED by a later direct measurement.** The original reasoning
is kept below along with an account of where it went wrong: the mistake here is
more instructive than the result was.

The original inference, from decomposing the handshake across two modes, was that
the accelerator speeds up ECDSA but not the key exchange:

| Component | ESP32-S3 | ESP32-C6 | "Speed-up" |
|-----------|----------|----------|------------|
| Standalone ECDSA signature | 170.2 ms | 22.1 ms | 7.7 × |
| ECDSA part of the handshake (difference of modes) | 1,024.2 ms | 143.2 ms | 7.2 × |
| ECDHE exchange (subtracted from handshake time) | 530.8 ms | 505.9 ms | 1.05 × |

From which it was explained that ESP-IDF supposedly provides hardware ECDSA
signing but not the general elliptic-curve point multiplication that key exchange
relies on.

**Measuring the operation directly showed the opposite:**

| Component | ESP32-S3 | ESP32-C6 | Speed-up |
|-----------|----------|----------|----------|
| ECDH P-256, point multiplication | 154.41 ms | 8.60 ms | **18.0 ×** |

What is more, disabling the accelerator on the C6 itself slows the same operation
by 16.8x — so the hardware block serves point multiplication even better than it
serves signing (7.2x), rather than ignoring it.

**Where the error was.** The 505.9 ms figure was not measured but subtracted: an
estimated share of the signature was taken out of a DTLS-ECDHE-PSK handshake time
and the remainder attributed to key exchange. The assumption that everything else
in that remainder was negligible did not hold — something else dominated the
handshake, and an eighteenfold difference in key exchange simply vanished inside
it.

The explanation about how the accelerator is built falls with it: hardware point
multiplication for NIST curves does exist, and key exchange uses it. What does not
use it is X25519 — the block works with NIST curves, not Curve25519 (121.37 ms
against 119.33 with the accelerator on and off, i.e. no difference at all).

A full account with the methodology is in [`ECC_ACCELERATOR.md`](ECC_ACCELERATOR.md).

**The methodological lesson.** A value obtained by subtracting from a composite
timing is not a measurement. Before building an explanation of how a chip works
on such a value, it has to be confirmed by measuring the operation itself.

The practical consequence for design: **the cost of ML-KEM is predictable and
depends little on the chip** (39.6 against 33.8 ms — a factor of 1.17), whereas
the cost of ECDSA varies by a factor of 7.7 depending on the presence of an
accelerator. A timing budget computed for an ML-KEM-based scheme transfers
between platforms. One for a classical elliptic-curve scheme does not.

**A limitation of these measurements, since partly lifted.** Originally the full
LACERT handshake could not be compared against DTLS on the boards: the cost of
signature verification on the chip itself was missing, since in the protocol the
gateway verifies signatures rather than the device, and the firmware's
microbenchmark had no such operation.

The benchmark firmware in `bench/` measures it: ECDSA P-256 verification takes
41.58 ms on the ESP32-C6 and 330.93 ms on the ESP32-S3. Notably, verification
costs more than signing (21.90 ms on the C6) — it needs two point multiplications
instead of one.

A full protocol-level comparison on the boards has not yet been built on these
figures: it would also need the cost of frame parsing and assembly, which the
microbenchmark does not isolate. But the main missing term is no longer missing.

#### What the comparison does not cover

The figures above compare only session establishment and encryption. Beyond them
lie mechanisms that DTLS does not have at all:

- **continuous key rotation** — DTLS 1.2 provides no way to change the key
  within a session. Doing so requires a fresh handshake with its full cost
- **firmware integrity checking** — absent from DTLS as a concept
- **revoking an individual device** without affecting the others — impossible in
  principle in PSK mode.

The conclusion is therefore best stated as: at comparable guarantees of
authentication and key freshness, LACERT establishes a session faster and
additionally provides mechanisms absent from DTLS, at the cost of a larger
handshake.

#### Reproduction

The sources of both benches are `dtls_bench.c` and `lacert_hs_bench.c`. The
build commands are in the file comments. Certificates for the ECDHE-ECDSA mode
are created beforehand:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out srv.key
openssl req -new -x509 -key srv.key -out srv.crt -days 365 \
  -subj "/CN=lacert-dtls-bench" -sha256
openssl ecparam -name prime256v1 -genkey -noout -out cli.key
openssl req -new -x509 -key cli.key -out cli.crt -days 365 \
  -subj "/CN=lacert-device-1" -sha256
```


---

## 4. Methodology for measuring gateway performance

Load testing was carried out on a single CPU core against a real PostgreSQL 16
instance. The load was generated by the built-in device emulator
(`LACERT_EMULATE_DEVICES`), which implements the same network protocol as the
physical boards.

The load parameters were deliberately set harsher than the production defaults:

| Parameter | Under test | Default |
|-----------|-----------|---------|
| Telemetry interval | 2 s | 2 s |
| Key rotation interval | 30 s | 300 s |
| Firmware check interval | 60 s | 1 h |

Measured: CPU load and resident memory of the gateway process (`ps`), REST API
response time (`curl`), the number of successful handshakes, rotations and
integrity checks (the `/api/v1/metrics` counters), and the number of database
records.

## 5. Results: gateway performance

| Devices | CPU load | Memory | `/api/v1/devices` response time | Failures |
|---------|----------|--------|--------------------------------|----------|
| 10 | 0.4 % | 20 MB | 3 ms | 0 |
| 100 | 3.3 % | 34 MB | 13 ms | 0 |
| 250 | 7.7 % | 57 MB | 12 ms | 0 |
| 500 | 12.4 % | 93 MB | 26 ms | 0 |

In every trial all devices established a secure connection successfully. Key
rotations and firmware integrity checks completed without a single failure.

Resource consumption grows linearly: approximately 0.025 % of a CPU core and
0.15 MB of memory per device. Cryptographic computation is not the limiting
factor for the gateway — a handshake on the server platform takes a fraction of
a millisecond. The limits are set by the storage subsystem and the network.

---

## 6. Reproducing the results

### 6.1. Cryptographic measurements on a board

```bash
cd firmware
# set the network parameters and LACERT_DEVICE_ID in main/main.c
rm -rf build sdkconfig
idf.py set-target esp32c6          # or esp32s3
idf.py build

# confirm that the optimized configuration was applied:
grep -E 'COMPILER_OPTIMIZATION|MBEDTLS_HARDWARE' sdkconfig

idf.py -p /dev/ttyACM0 flash monitor
```

The results are printed to the serial port immediately after initialization,
before the board joins the network (the "CRYPTOGRAPHY MICROBENCHMARK" block).

### 6.2. Measurements on the baseline platform (x86-64)

```bash
cd firmware/linux-debug
gcc -O2 -std=c11 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 \
    -DBLAKE3_NO_AVX512 -I. -I../main -I../components/ml_kem -I../components/blake3 \
    bench_host.c ../main/lacert_crypto.c ../components/ml_kem/*.c \
    ../components/blake3/blake3.c ../components/blake3/blake3_dispatch.c \
    ../components/blake3/blake3_portable.c -lmbedcrypto -o bench_host
./bench_host
```

### 6.3. Gateway load testing

```bash
export LACERT_PG_DSN="postgresql://lacert:PASSWORD@localhost/lacert?sslmode=disable"
export LACERT_ADMIN_TOKEN=TOKEN
export LACERT_EMULATE_DEVICES=500
export LACERT_EMULATE_INTERVAL=2s
export LACERT_ROTATION_INTERVAL=30s
export LACERT_FIRMWARE_INTERVAL=60s
./gatewayd

# in another terminal, after about a minute:
ps -p $(pgrep -x gatewayd) -o %cpu=,rss=
curl -s -o /dev/null -w "%{time_total}\n" -H "Authorization: Bearer TOKEN" \
     http://localhost:8080/api/v1/devices
curl -s -H "Authorization: Bearer TOKEN" http://localhost:8080/api/v1/metrics
```

---

## 7. Primary data

The benchmark output is preserved in the serial-port log. The measurement
records for each board are given in the appendix. Telemetry values covering
handshake time, rotation time and free memory are additionally stored in the
database (fields `handshake_us`, `rotation_us`, `fw_sign_us`, `heap_free`,
`heap_min`) and are available through `GET /api/v1/telemetry`, which makes it
possible to verify the reported figures independently.

## On-chip algorithm comparison (the `bench/` firmware)

Measured with the separate firmware in `bench/`, twenty iterations per operation,
built with `-Os`. No network is brought up and no protocol runs — computation
only, so radio-induced variance is excluded.

### Key exchange: what a security level costs

| Level | Keygen | Encapsulate | Decapsulate | Public key | Ciphertext |
|-------|--------|-------------|-------------|------------|------------|
| ML-KEM-512 | 6.48 ms | 6.69 ms | 7.51 ms | 800 B | 768 B |
| ML-KEM-768 | 10.04 ms | 10.68 ms | 11.94 ms | 1184 B | 1088 B |
| **ML-KEM-1024** | **15.11 ms** | **15.97 ms** | **17.70 ms** | **1568 B** | **1568 B** |

Figures for the ESP32-C6. Moving from the lowest level to the highest costs about
2.3x the time and twice the traffic. The protocol uses 1024: against the total
handshake duration a difference of ten milliseconds is not decisive, and the
larger security margin is preferable for devices that stay in the field ten to
fifteen years.

### Signatures: post-quantum schemes

| Scheme | Keygen | Sign | Verify | Signature | Public key |
|--------|--------|------|--------|-----------|------------|
| ML-DSA-44 | 17.46 ms | 71.89 ms | 17.95 ms | 2420 B | 1312 B |
| ML-DSA-65 | 30.07 ms | 111.48 ms | 30.07 ms | 3309 B | 1952 B |
| ML-DSA-87 | 50.46 ms | 122.51 ms | 51.10 ms | 4627 B | 2592 B |
| SLH-DSA-128s | 13,295 ms | **101,057 ms** | 99.2 ms | 7856 B | 32 B |
| ECDSA P-256 *(for reference)* | 8.85 ms | 21.90 ms | 41.58 ms | ~71 B | 65 B |

Figures for the ESP32-C6 with its ECC accelerator enabled.

This closes a gap noted in the work: ML-DSA had never been measured on the chip.
The verdict is that ML-DSA is usable. Signing takes between 72 and 123
milliseconds, comparable to ECDSA without hardware assistance (158 ms) and
acceptable for a device reporting every few seconds.

SLH-DSA is not merely slow by comparison but unusable: **one signature takes 101
seconds** on the ESP32-C6 and 114 seconds on the ESP32-S3. Key generation takes
thirteen and fifteen seconds respectively. A device signing a single message
would spend nearly two minutes computing.

How far that is from everything else:

| Against | Times slower |
|---------|--------------|
| ECDSA P-256 with the accelerator (21.90 ms) | 4614 |
| ML-DSA-44 (71.89 ms) | 1406 |
| ML-DSA-87 (122.51 ms) | 825 |

The earlier estimate in this work — 234.3 ms per signature — was taken on a
server with a different implementation (Go, the circl library). The 431-fold gap
against the chip comes from two causes at once: a different processor and a
different implementation. The figures cannot be set directly against each other,
but they point to the same conclusion.

Verification, by contrast, is cheap — around 100 ms, comparable to ECDSA without
the accelerator. Only signing is expensive.

The measurement doubles as another control: with the ECC accelerator on and off,
the SLH-DSA figures matched to hundredths of a millisecond (101,057.49 and
101,057.48 ms), confirming that this scheme is independent of the elliptic-curve
block.

**ML-DSA signing time varies between runs.** ML-DSA-65 gave 100.04 and 133.12 ms
on two S3 boards, ML-DSA-87 gave 131.52 and 112.41 ms. This is a property of the
scheme itself: signing works by rejection sampling, and the number of loop
repetitions differs from signature to signature. For operations without rejection
(keygen, verify) the spread between board instances is negligible.

### The stack constraint

| Algorithm | Stack used |
|-----------|------------|
| ML-DSA-87 | 119.9 KB |
| ML-DSA-65 | 77.9 KB |
| ML-DSA-44 | 50.9 KB |
| ML-KEM (any level) | 20.3 KB |
| SLH-DSA-128s | 3.8 KB |
| Classical primitives | 6.0 KB |

For embedded work this often matters more than time. A single ML-DSA-87 call
needs 120 KB of stack — more than many tasks are given in total. In PQClean's
reference implementation the expanded structures live on the stack, and the
usage cannot be reduced without reworking the library.

SLH-DSA is the opposite case: 3.8 KB of stack, thirty times less than ML-DSA-87,
paid for in time — and the price is prohibitive.

### Classical primitives

| Operation | ESP32-C6 | ESP32-S3 |
|-----------|----------|----------|
| ECDSA P-256, sign | 21.90 ms | 167.97 ms |
| ECDSA P-256, verify | 41.58 ms | 330.93 ms |
| ECDH P-256, point multiply | 8.60 ms | 154.41 ms |
| X25519, point multiply | 121.37 ms | 127.77 ms |
| SHA-256, 1 KB | 49.9 µs | 66.2 µs |
| BLAKE3, 1 KB | 164.9 µs | 158.4 µs |
| BLAKE3, key derivation | 17.5 µs | 16.4 µs |
| ChaCha20-Poly1305, 1 KB | 715.0 µs | 710.0 µs |

The gap in curve operations comes from the hardware ECC accelerator, which the C6
has and the S3 does not. Verified by direct experiment — see
[`ECC_ACCELERATOR.md`](ECC_ACCELERATOR.md).

X25519 does not go through the accelerator on either board: the block works with
NIST curves. Hence a practical point for hybrid schemes — the classical half of
an X25519 + ML-KEM hybrid costs more on the C6 than the entire post-quantum part.
