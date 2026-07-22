#!/usr/bin/env bash
# Живой стресс-тест защитных механизмов LACERT против РАБОТАЮЩЕГО шлюза.
#
# Скрипт поднимает шлюз в «демо-режиме» (ускоренные интервалы ротации и
# проверки прошивки), затем запускает cmd/stresstest, который по реальной сети
# регистрирует 5 устройств и воспроизводит на каждом свой сценарий сбоя.
# Метрики видны и в выводе инструмента, и на вкладке «метрики» веб-дашборда
# (http://localhost:8080).
#
# Запуск из корня проекта:
#   bash deploy/run-live-stress.sh
#
# Остановить шлюз после демонстрации: Ctrl+C.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# --- Демо-режим: короткие интервалы, чтобы всё отработало за ~20 секунд. ---
# ВНИМАНИЕ: это ТЕСТОВЫЕ значения. В проде используются значения по умолчанию
# (ротация 300с, проверка прошивки 1ч, тайм-аут ACK 30с, окно прошивки 90с).
export LACERT_ROTATION_INTERVAL="${LACERT_ROTATION_INTERVAL:-6s}"
export LACERT_ROTATION_ACK_TIMEOUT="${LACERT_ROTATION_ACK_TIMEOUT:-4s}"
export LACERT_ROTATION_CHECK_PERIOD="${LACERT_ROTATION_CHECK_PERIOD:-1s}"
export LACERT_FIRMWARE_INTERVAL="${LACERT_FIRMWARE_INTERVAL:-2s}"
export LACERT_FIRMWARE_VALIDITY="${LACERT_FIRMWARE_VALIDITY:-1s}"

export LACERT_HTTP_ADDR="${LACERT_HTTP_ADDR:-:8080}"
export LACERT_TCP_ADDR="${LACERT_TCP_ADDR:-:7700}"
export LACERT_MQTT_ADDR="${LACERT_MQTT_ADDR:-:1883}"

GOFLAGS="${GOFLAGS:--mod=vendor}"
export GOFLAGS

echo ">>> Собираю gatewayd…"
go build -o /tmp/lacert-gatewayd-demo ./cmd/gatewayd

echo ">>> Запускаю шлюз в демо-режиме (лог: /tmp/lacert-demo-gw.log)…"
/tmp/lacert-gatewayd-demo > /tmp/lacert-demo-gw.log 2>&1 &
GW_PID=$!
trap 'echo; echo ">>> Останавливаю шлюз (pid=$GW_PID)…"; kill "$GW_PID" 2>/dev/null || true' EXIT

sleep 3
echo ">>> Дашборд: http://localhost${LACERT_HTTP_ADDR}  (откройте вкладку «метрики»)"
echo ">>> Запускаю живой стресс-тест…"
echo

LACERT_GATEWAY_HTTP="http://localhost${LACERT_HTTP_ADDR}" \
LACERT_GATEWAY_TCP="localhost${LACERT_TCP_ADDR}" \
LACERT_STRESS_WAIT="${LACERT_STRESS_WAIT:-18s}" \
  go run ./cmd/stresstest

echo
echo ">>> Готово. Шлюз ещё работает — откройте дашборд, чтобы посмотреть метрики."
echo ">>> Нажмите Enter, чтобы остановить шлюз и выйти."
read -r _
