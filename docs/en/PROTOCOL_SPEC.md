> **Language:** English · [Русский](../ru/PROTOCOL_SPEC.md)

# LACERT — protocol specification (for implementing the ESP32 client)

This document describes the LACERT wire format **byte by byte**, so that the C
client (the ESP32 firmware) matches the Go gateway implementation exactly. A
mismatch in even a single byte — field order, endianness, a separator string —
will cause the handshake or the signature check to fail.

The source of truth is the gateway code in `internal/wire` and
`internal/crypto`; everything here is derived from it.

---

## 0. General conventions

- **Endianness:** all integer lengths and counters are **big-endian (BE)**.
- **Primitives:**
  - Key exchange: **ML-KEM-1024** (Kyber, NIST final).
  - Device signature: **ECDSA P-256** (recommended; see the note on SLH-DSA below).
  - Hashing / key derivation: **BLAKE3** (32-byte output).
  - Data encryption: **ChaCha20-Poly1305**.
  - Firmware hash: **SHA-256**.
- **Sizes (bytes):**
  - ML-KEM-1024 public key: **1568**
  - ML-KEM-1024 ciphertext: **1568**
  - ML-KEM-1024 shared secret: **32**
  - Session key (BLAKE3 output): **32**
  - ECDSA P-256 public key (uncompressed): **65** (`0x04 || X(32) || Y(32)`)
  - ECDSA P-256 signature: **ASN.1 DER** (variable length, ~70–72 bytes) —
    **not** the raw r‖s form!
  - ChaCha20-Poly1305 nonce: **12**, authentication tag: **16**
  - SHA-256 hash: **32**
  - Handshake nonce (Msg1/Msg2): **32**
  - Firmware challenge: **64**

> **Important note on the ECDSA signature.** Go signs via `ecdsa.SignASN1`, so
> the result is an ASN.1 DER structure (`SEQUENCE { INTEGER r, INTEGER s }`),
> *not* the concatenation r‖s. On the ESP32, mbedTLS also produces ASN.1 DER by
> default (`mbedtls_ecdsa_write_signature`), so the formats match. Do not use
> "raw" mode.

---

## 1. Frame format (transport over TCP)

Every message is wrapped in a frame:

```
+-----------------+--------+------------------+
| payload length  | type   | payload          |
| 4 bytes BE      | 1 byte | N bytes          |
+-----------------+--------+------------------+
```

- Payload length is a BE `uint32` and does not include the 5-byte header.
- Maximum frame size: **65536** bytes (protection against garbage input).

**Message types (1 byte):**

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| `TypeHandshakeMsg1` | 1 | device → gateway | start of the handshake |
| `TypeHandshakeMsg2` | 2 | gateway → device | handshake response |
| `TypeHandshakeMsg3` | 3 | device → gateway | confirmation (signature) |
| `TypeRotation` | 4 | — | (legacy non-atomic rotation, unused) |
| `TypeData` | 5 | device → gateway | encrypted telemetry |
| `TypeFirmwareChallenge` | 6 | gateway → device | firmware integrity challenge |
| `TypeFirmwareResponse` | 7 | device → gateway | firmware integrity response |
| `TypeError` | 8 | gateway → device | text error before disconnecting |
| `TypeRotationV2` | 9 | gateway → device | atomic key rotation |
| `TypeRotationAck` | 10 | device → gateway | rotation acknowledgement |

### Framing of fields inside the payload

Variable-length fields inside a payload are prefixed with a 2-byte BE length:

```
putFramed(data): [uint16 BE: len(data)][data...]
```

Fixed-length fields (a 32-byte nonce and the like) are written as-is, with no
prefix.

---

## 2. Offline enrollment (before connecting)

Before its first connection, a device must be enrolled with the gateway — the
equivalent of "burning the efuse" in a real system. Enrollment goes over REST,
not over the TCP protocol. Request body for `POST /api/v1/devices`:

```json
{
  "device_id":         "<string>",
  "identity_pub_hex":  "<hex ECDSA P-256 pub, 65 bytes → 130 hex chars>",
  "kem_pub_hex":       "<hex ML-KEM-1024 pub, 1568 bytes>",
  "firmware_hash_hex": "<hex SHA-256 of the firmware, 32 bytes>",
  "checksum":          "<serial-number checksum>",
  "sig_algorithm":     "ecdsa-p256"
}
```

Header: `Authorization: Bearer <admin-token>` (if the gateway is token-protected).

The device stores: its own ML-KEM-1024 private key, its ECDSA private key (the
"efuse"), and the gateway's ML-KEM-1024 public key (obtained from
`GET /api/v1/gateway`, field `kem_pub_hex`).

---

## 3. Handshake (Noise_XX-like, three messages)

### 3.1 Msg1 (device → gateway), type 1

Payload:

```
putFramed(device_id)          // [uint16 len][device_id string]
nonce                         // 32 random bytes
putFramed(identity_pub)       // [uint16 len][ECDSA pub, 65 bytes]
```

The device generates a random 32-byte `nonce` and keeps the whole of Msg1 — it
will be needed for the transcript.

### 3.2 Msg2 (gateway → device), type 2

Payload:

```
putFramed(kem_ciphertext)     // [uint16 len][ML-KEM ciphertext, 1568 bytes]
gateway_nonce                 // 32 bytes
```

The gateway has encapsulated a shared secret under the **device's** ML-KEM
public key. The device **decapsulates** it with its own ML-KEM private key:

```
shared_secret = ML-KEM-1024.Decapsulate(dev_kem_priv, kem_ciphertext)  // 32 bytes
```

### 3.3 Deriving the session key K0

Both sides compute this identically. First the **transcript** — BLAKE3 over the
canonical bytes of Msg1 and Msg2:

```
msg1_bytes = putFramed(device_id) || nonce || putFramed(identity_pub)
msg2_bytes = putFramed(kem_ciphertext) || gateway_nonce

transcript = BLAKE3( msg1_bytes || msg2_bytes )        // 32 bytes
```

> Note: `msg1_bytes` / `msg2_bytes` used for the transcript carry the same
> 2-byte `putFramed` framing as on the wire, and the field order is exactly as
> shown.

Then K0:

```
K0 = BLAKE3( shared_secret || transcript || "lacert_handshake_v1" )   // 32 bytes
```

The separator string is ASCII `lacert_handshake_v1`, with no trailing NUL.

### 3.4 Msg3 (device → gateway), type 3

The device proves possession of its signing private key and that its K0 matches.
First the "confirmation value":

```
confirm = BLAKE3( transcript || "confirm" || K0 )      // 32 bytes
```

The separator string is ASCII `confirm`. The device then signs `confirm`:

```
signature = ECDSA_P256_sign( dev_identity_priv, confirm )
```

where `ECDSA_P256_sign(m)` = `ASN1( SignASN1( SHA-256(m) ) )`, that is:
1. `digest = SHA-256(confirm)` (32 bytes),
2. sign `digest` with the ECDSA key; the result is in **ASN.1 DER** form.

Msg3 payload:

```
putFramed(signature)          // [uint16 len][ECDSA DER signature]
```

The gateway verifies the signature with the device's enrolled public key. If it
is valid the session is established, and the current key is K0.

---

> **Type 4 (deprecated, unused).** In an early scheme type 4 denoted
> non-atomic key rotation. It was found insecure (the frame is unauthenticated
> and does not advance the iteration counter) and removed from the protocol. The
> gateway still recognizes type 4 on input but **rejects** it; regular devices
> and the emulator never send such a frame. Current rotation is atomic, types 9
> and 10 (see section 5). The value 4 is reserved and not reused.

## 4. Data transfer (telemetry)

### 4.1 Data (device → gateway), type 5

The payload is encrypted with the current session key Ki:

```
nonce (12 bytes) = random(8) || uint32_BE(seq_num)
ciphertext = ChaCha20Poly1305_seal(Ki, nonce, plaintext)   // includes the 16-byte tag
```

- The high 8 bytes of the nonce are random, the low 4 bytes are the packet
  counter `seq_num` (BE). This guarantees nonce uniqueness under a single key.
- `plaintext` is a telemetry string, for example `temperature=25.3; seq=42`.

Payload:

```
putFramed(nonce)              // [uint16=12][12-byte nonce]
putFramed(ciphertext)         // [uint16 len][ciphertext + tag]
```

The maximum plaintext size is bounded — see `MaxPayloadSize` in the code.

---

## 5. Key rotation (atomic, initiated by the GATEWAY)

Rotation is initiated **only by the gateway**; the device has no rotation timer
of its own and only responds. The device receives `TypeRotationV2`, applies the
new key and answers with `TypeRotationAck`.

### 5.1 RotationV2 (gateway → device), type 9

Payload:

```
iteration                     // 8 bytes, uint64 BE (number of the new iteration)
putFramed(kem_ciphertext)     // [uint16 len][ML-KEM ciphertext, 1568 bytes]
```

The device decapsulates a fresh secret `mi` with its ML-KEM private key:

```
mi = ML-KEM-1024.Decapsulate(dev_kem_priv, kem_ciphertext)   // 32 bytes
```

### 5.2 Deriving the next key

```
next_key = BLAKE3( current_key(32) || mi(32) || uint64_BE(iteration) || "rotate_v1" )
```

- `current_key` is the session key in force (32 bytes).
- The separator string is ASCII `rotate_v1`.
- The iteration is the same `iteration` from the message (8 bytes BE).

The device adopts `next_key` as its new current key.

### 5.3 RotationAck (device → gateway), type 10

Payload:

```
iteration                     // 8 bytes, uint64 BE (the same iteration)
```

On receiving an ACK with the correct iteration number, the gateway commits the
new key on its side. If no ACK arrives within `RotationAckTimeout` (5 s by
default) the gateway rolls the rotation back; after several consecutive failures
the device is revoked.

> **Checking the iteration number.** The device must accept only
> `iteration == current_iteration + 1`. A lower or equal value is a
> repeat/replay and must be rejected. A higher value with a gap indicates
> desynchronization and must also be rejected.

---

## 6. Firmware integrity check

The gateway periodically verifies that the device's firmware has not been
replaced.

### 6.1 FirmwareChallenge (gateway → device), type 6

Payload:

```
putFramed(challenge)          // [uint16=64][64 random bytes]
```

### 6.2 FirmwareResponse (device → gateway), type 7

The device computes the SHA-256 of its own firmware image and signs
`challenge || firmware_hash`:

```
firmware_hash = SHA-256(firmware_image)                      // 32 bytes
to_sign = challenge(64) || firmware_hash(32)                 // 96 bytes
signature = ECDSA_P256_sign( dev_identity_priv, to_sign )
          = ASN1( SignASN1( SHA-256(to_sign) ) )
```

Payload:

```
firmware_hash                 // 32 bytes (no putFramed — fixed size!)
putFramed(signature)          // [uint16 len][ECDSA DER signature]
```

> Note: `firmware_hash` is written as a fixed 32 bytes **without** the 2-byte
> length prefix, at the very start of the payload. The signature does carry a
> prefix.

The gateway compares `firmware_hash` against the reference value from enrollment
and verifies the signature. The response must arrive within
`firmwareResponseValidity` (15 s by default), otherwise the challenge is
considered stale and is rejected.

---

## 7. Errors (gateway → device), type 8

The payload is simply a UTF-8 string with the error text, for example
`device revoked`. It is sent just before the connection is closed. There is no
field framing — the whole payload is the string.

---

## 8. Device workflow (summary)

```
1. (once) Enroll over REST and fetch the gateway's ML-KEM public key.
2. Connect to the gateway over TCP (port 7700 by default).
3. Send Msg1 → receive Msg2 → decapsulate → compute K0 → send Msg3.
   The session is established.
4. In a loop:
   - send Data (telemetry), encrypted with the current key;
   - listen for incoming frames:
       * RotationV2        → apply the new key, answer with RotationAck;
       * FirmwareChallenge → answer with FirmwareResponse;
       * Error             → log it and reconnect or stop.
```

---

## 9. On the choice of signature scheme

The system supports both schemes (`sig_algorithm`: `ecdsa-p256` or `slh-dsa`),
but for the ESP32 **ECDSA P-256 is strongly recommended**:

- **ECDSA P-256**: signing takes 22.2 ms on the ESP32-C6 and 170.2 ms on the
  ESP32-S3; signatures are ~70 bytes. The difference between the boards comes
  from the hardware elliptic-curve accelerator: the ESP32-C6 has one and the
  ESP32-S3 does not, so on the S3 the operation runs entirely in software
  (mbedTLS).
- **SLH-DSA**: signing takes hundreds of milliseconds even on a server — roughly
  11,000× slower than ECDSA — and signatures are 7,856 bytes. On the ESP32 this
  is unacceptable in both time and memory.

This is confirmed by measurements (see `MEASUREMENTS.md`). ML-KEM provides
post-quantum strength at the key-exchange layer; the signature remains classical.

Worth keeping in mind: on the ESP32-S3 the signature turns out to be the most
expensive operation in the protocol — more expensive than a post-quantum ML-KEM
decapsulation (170.2 ms against 21.1 ms).

### Why the signature remained classical

Of the two schemes considered, only SLH-DSA provides post-quantum security: it
rests on properties of hash functions, which Shor's algorithm does not affect.
ECDSA rests on the discrete-logarithm problem and is broken by a quantum
adversary. Measurements showed the cost of a post-quantum signature to be
unacceptable for the ESP32, so a deliberate split was adopted:

- **key exchange — post-quantum** (ML-KEM-1024);
- **signature — classical** (ECDSA P-256).

The practical consequence: an adversary with a quantum computer will not be able
to recover session keys from intercepted traffic, but will be able to forge a
device signature. For a scenario where the primary concern is the
confidentiality of long-lived data ("harvest now, decrypt later"), this split is
justified; for one where unforgeability of the signature is critical, a scheme
of the SLH-DSA class — and correspondingly more capable hardware — is required.

### The alternative considered: Ed25519

Ed25519 was evaluated during the work as a replacement for ECDSA. The scheme was
not implemented from scratch — Go's standard library (`crypto/ed25519`) was used,
so the correctness of the algorithm itself rests with its authors. What this
project verified is the integration: signing and verification on a generated key
pair, rejection of a tampered message, and completion of a full handshake
(`TestEd25519RoundTrip` and `TestHandshakeEd25519` in `internal/crypto`).
Measurements on the server platform showed a noticeable gain — signing 23 %
faster and 99× less memory allocated (see `MEASUREMENTS.md`, section 3.2).

The replacement was nevertheless rejected:

1. **It adds no post-quantum security.** Ed25519 rests on the same
   discrete-logarithm problem as ECDSA and is equally vulnerable to Shor's
   algorithm. It does not address the central question of this work.
2. **It requires a fourth external dependency.** ECDSA is part of mbedTLS and is
   therefore already present in ESP-IDF (see section 10), whereas Ed25519 would
   have to be pulled in as a separate library.
3. **On the ESP32-C6 it would make things worse.** That board's hardware
   accelerator speeds up ECDSA operations by roughly 7.7× (`MEASUREMENTS.md`,
   observation 8); there is no hardware support for Ed25519.

The Ed25519 implementation is retained in the gateway core (`internal/crypto`)
as a tool for comparative measurements, but is not used in the firmware or in
the protocol.

---

## 10. C cryptographic libraries for the ESP32 (reference)

| Primitive | Where to get it |
|-----------|-----------------|
| ECDSA P-256 | mbedTLS (bundled with ESP-IDF; hardware acceleration on the ESP32-C6 only) |
| ChaCha20-Poly1305 | mbedTLS (bundled) |
| SHA-256 | mbedTLS / ROM (hardware) |
| ML-KEM-1024 | PQClean — wired in as the `firmware/components/ml_kem` component |
| BLAKE3 | the official C implementation from BLAKE3-team/BLAKE3 |

Only ML-KEM-1024 and BLAKE3 have to be added from outside; everything else
already ships with ESP-IDF.
