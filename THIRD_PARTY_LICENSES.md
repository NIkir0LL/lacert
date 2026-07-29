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
| gorm.io/gorm | MIT | ORM used by the PostgreSQL store |
| gorm.io/driver/postgres | MIT | GORM driver for PostgreSQL |
| github.com/jackc/pgx/v5 | MIT | PostgreSQL driver (used through the GORM driver) |
| **github.com/eclipse/paho.mqtt.golang** | **EPL-2.0 / EDL-1.0** | MQTT client — see note below |

## Note on Eclipse Paho (EPL-2.0)

`paho.mqtt.golang` is distributed under the Eclipse Public License 2.0 with a
secondary Eclipse Distribution License 1.0 (BSD-3-Clause). It is used here as an
**unmodified dependency**. The EPL is a weak/file-level copyleft: it does not
affect the MIT license of this project's own source code. If you modify the Paho
library itself, you must make those modifications available under the EPL.

Full license texts are available in each library's own repository.

## Transitive dependencies

The libraries above pull in the following modules. They are not imported by this
project directly, but they end up in the compiled binary, so their licenses are
listed here as well.

| Library | License | Pulled in by |
|---------|---------|--------------|
| github.com/gorilla/websocket | BSD-2-Clause | mochi-mqtt, paho.mqtt.golang |
| github.com/jackc/pgpassfile | MIT | pgx |
| github.com/jackc/pgservicefile | MIT | pgx |
| github.com/jackc/puddle/v2 | MIT | pgx |
| github.com/jinzhu/inflection | MIT | gorm |
| github.com/jinzhu/now | MIT | gorm |
| github.com/klauspost/cpuid/v2 | MIT | zeebo/blake3 |
| github.com/rs/xid | MIT | mochi-mqtt |
| golang.org/x/net | BSD-3-Clause | paho.mqtt.golang |
| golang.org/x/sync | BSD-3-Clause | pgx |
| golang.org/x/sys | BSD-3-Clause | golang.org/x/crypto |
| golang.org/x/text | BSD-3-Clause | pgx |
| gopkg.in/yaml.v3 | MIT | mochi-mqtt |

All of them are permissive licenses (MIT and BSD), compatible with the MIT
license of this project.

## A note on the `replace` directives in go.mod

`go.mod` redirects the canonical module paths (`golang.org/x/...`, `gorm.io/...`)
to their GitHub mirrors — for example `golang.org/x/crypto` to
`github.com/golang/crypto`. This is a workaround for networks where the Go
module proxy is unreachable while GitHub is not: without it `go mod download`
fails.

The mirrors are the upstream repositories themselves, so the code and the
licenses are the same. If your network reaches `proxy.golang.org`, the
directives can be removed and the build will resolve the modules normally.
