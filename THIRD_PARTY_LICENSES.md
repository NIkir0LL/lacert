# Third-Party Licenses

This project depends on the third-party libraries listed below. Unlike the
published repositories, this working copy **bundles** them: Go dependencies are
vendored under `vendor/`, and the firmware components live under
`firmware/components/`. Their licenses apply to the respective components.

## Go dependencies (`vendor/`)

| Library | License | Notes |
|---------|---------|-------|
| github.com/cloudflare/circl | BSD-3-Clause | post-quantum & classical crypto |
| github.com/zeebo/blake3 | CC0-1.0 (public domain) | BLAKE3 hashing |
| golang.org/x/crypto | BSD-3-Clause | ChaCha20-Poly1305 |
| github.com/go-chi/chi/v5 | MIT | HTTP router |
| github.com/go-chi/cors | MIT | CORS middleware |
| github.com/mochi-mqtt/server/v2 | MIT | embedded MQTT broker |
| github.com/jackc/pgx/v5 | MIT | PostgreSQL driver |
| **github.com/eclipse/paho.mqtt.golang** | **EPL-2.0 / EDL-1.0** | MQTT client — see note below |

## Firmware components (`firmware/components/`)

| Component | Source | License |
|-----------|--------|---------|
| `ml_kem` | [PQClean](https://github.com/PQClean/PQClean) | public domain (CC0-1.0) |
| `blake3` | [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) | CC0-1.0 / Apache-2.0 |

mbedTLS, used for ECDSA P-256, SHA-256 and ChaCha20-Poly1305 on the device, is
part of the ESP-IDF distribution (Apache-2.0) and is not bundled here.

## Note on Eclipse Paho (EPL-2.0)

`paho.mqtt.golang` is distributed under the Eclipse Public License 2.0 with a
secondary Eclipse Distribution License 1.0 (BSD-3-Clause). It is used here as an
**unmodified dependency**. The EPL is a weak/file-level copyleft: it does not
affect the MIT license of this project's own source code. If you modify the Paho
library itself, you must make those modifications available under the EPL.

Full license texts are available in each library's own repository.
