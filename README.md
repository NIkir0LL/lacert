# LACERT

[English](#english) · [Русский](#русский)

**LACERT** — a fully local, cloud-free system for connecting IoT devices to
corporate networks with **post-quantum** security. Gateway, monitoring, REST
API and dashboard included.

---

## English

### What it is

LACERT connects constrained IoT devices (ESP32) to a corporate network without
any cloud dependency. Everything runs on your own gateway. The protocol
combines:

- **Post-quantum key exchange** (ML-KEM-1024) so traffic stays safe against a
  future quantum adversary;
- a **Noise_XX-style handshake** in which the device authenticates itself to
  the gateway with an efuse-bound signing key (the gateway is trusted by
  provisioning: the device is given its public key offline, and does not verify
  a gateway signature — see `docs/en/PROTOCOL_SPEC.md`, section 3);
- **continuous key rotation** for forward secrecy and post-compromise security;
- **remote firmware-integrity checks** (ECDSA challenge-response);
- **ChaCha20-Poly1305** for the encrypted data channel.

This repository is the **full working system**: gateway daemon, device registry,
telemetry storage (PostgreSQL), embedded MQTT broker, REST API and a monitoring
dashboard.

### Related repositories

| Repository | What |
|------------|------|
| [lacert-crypto-go](https://github.com/NIkir0LL/lacert-crypto-go) | reusable Go crypto core (Apache-2.0) |
| [lacert-crypto-esp32](https://github.com/NIkir0LL/lacert-crypto-esp32) | ESP32 device firmware (Apache-2.0) |
| **lacert** (this repo) | full gateway + monitoring stack (MIT) |

### Layout

| Path | What |
|------|------|
| `cmd/gatewayd` | the gateway daemon |
| `cmd/demo`, `cmd/devicesim`, `cmd/stresstest` | demos & load testing |
| `internal/gateway`, `internal/api` | protocol server and REST API |
| `internal/store` | PostgreSQL persistence |
| `internal/scheduler`, `internal/telemetry` | rotation scheduling & telemetry |
| `internal/mqttbridge` | embedded MQTT broker bridge |
| `internal/webui` | monitoring dashboard |
| `firmware/` | ESP32 firmware (ESP-IDF) + Linux debug build |
| `benchmarks/` | DTLS comparison benchmarks |
| `deploy/` | bare-metal & systemd deployment |
| `docs/en/`, `docs/ru/` | full documentation in English and Russian |

### Quick start

```bash
# build the gateway
go build ./cmd/gatewayd

# see docs/en/DEPLOY.md for a full setup with PostgreSQL
```

Dependencies are fetched by Go modules — no third-party code is stored in this
repository. A local working copy may additionally vendor them under `vendor/`
for offline builds (see `THIRD_PARTY_LICENSES.md`); that directory is
deliberately not published.

Documentation is available in both languages — [English](docs/en/OVERVIEW.md) ·
[Русский](docs/ru/OVERVIEW.md). Start with
[OVERVIEW](docs/en/OVERVIEW.md) for the project tour,
[QUICKSTART](docs/en/QUICKSTART.md) to get running fast, or
[PROTOCOL_SPEC](docs/en/PROTOCOL_SPEC.md) for the byte-level protocol.

### License

MIT - see [LICENSE](LICENSE). Third-party dependencies keep their own licenses;
see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) (note: the MQTT client
Eclipse Paho is under EPL-2.0).

---

## Русский

### Что это

LACERT подключает IoT-устройства с ограниченными ресурсами (ESP32) к
корпоративной сети без какой-либо зависимости от облака. Всё работает на вашем
собственном шлюзе. Протокол объединяет:

- **постквантовый обмен ключами** (ML-KEM-1024), чтобы трафик был защищён от
  будущего квантового противника;
- **рукопожатие по образцу Noise_XX**, в котором устройство аутентифицирует
  себя перед шлюзом efuse-привязанным ключом подписи (шлюз доверенный по
  провижинингу: его публичный ключ передаётся устройству офлайн, встречной
  подписи шлюза протокол не проверяет — см. `docs/ru/PROTOCOL_SPEC.md`, раздел 3);
- **непрерывную ротацию ключей** для прямой секретности и восстановления
  стойкости после компрометации;
- **удалённую проверку целостности прошивки** (ECDSA, «запрос-ответ»);
- **ChaCha20-Poly1305** для зашифрованного канала данных.

Этот репозиторий — **полная рабочая система**: демон шлюза, реестр устройств,
хранилище телеметрии (PostgreSQL), встроенный MQTT-брокер, REST API и дашборд
мониторинга.

### Связанные репозитории

| Репозиторий | Что |
|-------------|-----|
| [lacert-crypto-go](https://github.com/NIkir0LL/lacert-crypto-go) | переиспользуемое криптоядро на Go (Apache-2.0) |
| [lacert-crypto-esp32](https://github.com/NIkir0LL/lacert-crypto-esp32) | прошивка устройства для ESP32 (Apache-2.0) |
| **lacert** (этот репозиторий) | полный шлюз + мониторинг (MIT) |

### Структура

| Путь | Что |
|------|-----|
| `cmd/gatewayd` | демон шлюза |
| `cmd/demo`, `cmd/devicesim`, `cmd/stresstest` | демонстрации и нагрузочные тесты |
| `internal/gateway`, `internal/api` | сервер протокола и REST API |
| `internal/store` | хранение в PostgreSQL |
| `internal/scheduler`, `internal/telemetry` | планировщик ротаций и телеметрия |
| `internal/mqttbridge` | мост встроенного MQTT-брокера |
| `internal/webui` | дашборд мониторинга |
| `firmware/` | прошивка ESP32 (ESP-IDF) и её Linux-сборка для отладки |
| `benchmarks/` | бенчмарки для сравнения с DTLS |
| `deploy/` | развёртывание на «голом железе» и через systemd |
| `docs/ru/`, `docs/en/` | полная документация на русском и английском |

### Быстрый старт

```bash
# собрать шлюз
go build ./cmd/gatewayd

# полная установка с PostgreSQL описана в docs/ru/DEPLOY.md
```

Зависимости подтягиваются менеджером модулей Go — чужой код в этом репозитории
не хранится. В локальной рабочей копии они дополнительно могут лежать в
`vendor/` для сборки без интернета (см. `THIRD_PARTY_LICENSES.md`); этот каталог
намеренно не публикуется.

Документация есть на двух языках — [Русский](docs/ru/OVERVIEW.md) ·
[English](docs/en/OVERVIEW.md). Начать стоит с
[OVERVIEW](docs/ru/OVERVIEW.md) — обзор проекта,
[QUICKSTART](docs/ru/QUICKSTART.md) — быстрый запуск,
[PROTOCOL_SPEC](docs/ru/PROTOCOL_SPEC.md) — протокол побайтно.

### Лицензия

MIT — см. [LICENSE](LICENSE). Внешние зависимости сохраняют свои лицензии, см.
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) (обратите внимание:
MQTT-клиент Eclipse Paho распространяется под EPL-2.0).
