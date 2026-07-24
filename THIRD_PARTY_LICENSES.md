# Third-Party Licenses

This project depends on the following third-party libraries, fetched via Go
modules (not bundled in this repository). Their licenses apply to the
respective components.

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

## Note on Eclipse Paho (EPL-2.0)

`paho.mqtt.golang` is distributed under the Eclipse Public License 2.0 with a
secondary Eclipse Distribution License 1.0 (BSD-3-Clause). It is used here as an
**unmodified dependency**. The EPL is a weak/file-level copyleft: it does not
affect the MIT license of this project's own source code. If you modify the Paho
library itself, you must make those modifications available under the EPL.

Full license texts are available in each library's own repository.
