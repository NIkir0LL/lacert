#!/usr/bin/env bash
# Автоматическая установка LACERT gatewayd на bare-metal Linux-сервер
# (без Docker). Рассчитан на Debian/Ubuntu (apt-get); для RHEL/CentOS/Fedora
# замените команды установки PostgreSQL на dnf/yum — остальное не изменится.
#
# Запускать с правами root (или через sudo) из корня распакованного архива:
#   sudo bash deploy/bare-metal/install.sh
set -euo pipefail

LACERT_USER="lacert"
INSTALL_DIR="/opt/lacert"
BIN_DIR="$INSTALL_DIR/bin"
ENV_DIR="/etc/lacert"
ENV_FILE="$ENV_DIR/gatewayd.env"
PG_DB="lacert"
PG_USER="lacert"

log() { echo -e "\n>>> $1"; }

if [[ "$EUID" -ne 0 ]]; then
  echo "Этот скрипт нужно запускать с правами root (sudo bash $0)" >&2
  exit 1
fi

# Идемпотентность при повторном запуске: если env-файл уже существует,
# переиспользуем записанные в нём пароль БД и admin-токен, а не генерируем
# новые — иначе при повторном прогоне скрипта пароль роли в PostgreSQL
# обновился бы, а в уже существующем env-файле остался бы старый, и шлюз
# перестал бы подключаться к базе после, казалось бы, безобидного повтора.
if [[ -f "$ENV_FILE" ]]; then
  PG_PASSWORD="$(grep -oP '(?<=password=)[^ ]+' "$ENV_FILE" | head -1)"
  ADMIN_TOKEN="$(grep -oP '(?<=^LACERT_ADMIN_TOKEN=).+' "$ENV_FILE" | head -1)"
  ENV_FILE_EXISTS=1
  # Установки до версии 1.1.0 записывали в env-файл LACERT_CORS_ORIGINS=*, то
  # есть разрешали обращаться к REST API любому сайту. Сам файл мы не правим —
  # это конфигурация оператора — но предупредим об этом в конце установки.
  CORS_WILDCARD=0
  if grep -qE '^LACERT_CORS_ORIGINS=\*[[:space:]]*$' "$ENV_FILE"; then
    CORS_WILDCARD=1
  fi
else
  PG_PASSWORD="$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | xxd -p)"
  ADMIN_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | xxd -p)"
  ENV_FILE_EXISTS=0
  CORS_WILDCARD=0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

log "Проверка версии Go"
if ! command -v go >/dev/null 2>&1; then
  echo "Go не найден в PATH. Установите Go 1.22+ и повторите запуск." >&2
  exit 1
fi
go version
GO_MINOR=$(go version | grep -oP 'go1\.\K[0-9]+' || echo 0)
if [[ "$GO_MINOR" -lt 22 ]]; then
  echo "Внимание: обнаружен Go старее 1.22 — сборка может не пройти (go.mod требует go 1.22.2)." >&2
fi

log "Проверка/установка PostgreSQL"
if ! command -v psql >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-contrib
  else
    echo "apt-get не найден. Установите PostgreSQL вручную и повторите запуск." >&2
    exit 1
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now postgresql
else
  service postgresql start || true
fi

log "Настройка базы данных и пользователя PostgreSQL"
# Идемпотентно: создаём роль/БД только если их ещё нет. Используем `su`,
# а не `sudo`, так как скрипт уже требует root — не хотим тащить лишнюю
# зависимость от пакета sudo на минимальных серверных образах.
ROLE_EXISTS=$(su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'\"")
if [[ "$ROLE_EXISTS" != *1* ]]; then
  su postgres -c "psql -c \"CREATE ROLE ${PG_USER} WITH LOGIN PASSWORD '${PG_PASSWORD}';\""
else
  su postgres -c "psql -c \"ALTER ROLE ${PG_USER} WITH PASSWORD '${PG_PASSWORD}';\"" >/dev/null
fi
DB_EXISTS=$(su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${PG_DB}'\"")
if [[ "$DB_EXISTS" != *1* ]]; then
  su postgres -c "psql -c \"CREATE DATABASE ${PG_DB} OWNER ${PG_USER};\""
fi

log "Сборка gatewayd и devicesim"
go build -o /tmp/lacert-gatewayd ./cmd/gatewayd
go build -o /tmp/lacert-devicesim ./cmd/devicesim
mkdir -p "$BIN_DIR"
install -m 0755 /tmp/lacert-gatewayd "$BIN_DIR/gatewayd"
install -m 0755 /tmp/lacert-devicesim "$BIN_DIR/devicesim"

log "Создание системного пользователя $LACERT_USER (без shell, без home)"
id -u "$LACERT_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$LACERT_USER"

log "Генерация конфигурации сервиса"
mkdir -p "$ENV_DIR"
if [[ "$ENV_FILE_EXISTS" -eq 1 ]]; then
  echo "Файл $ENV_FILE уже существует — переиспользую сохранённые в нём пароль БД и admin-токен."
else
  # Файл создаётся СРАЗУ с правами 600, до записи в него секретов. Раньше
  # chmod стоял после heredoc: между созданием файла (под текущим umask,
  # обычно 0644) и сменой прав существовало окно, в котором пароль БД и
  # admin-токен были доступны на чтение любому локальному пользователю.
  install -m 600 /dev/null "$ENV_FILE"
  cat > "$ENV_FILE" <<EOF
LACERT_PG_DSN=host=localhost user=${PG_USER} password=${PG_PASSWORD} dbname=${PG_DB} port=5432 sslmode=disable
LACERT_TCP_ADDR=:7700
LACERT_HTTP_ADDR=:8080
LACERT_MQTT_ADDR=:1883
LACERT_ADMIN_TOKEN=${ADMIN_TOKEN}
# Кросс-доменные запросы по умолчанию не разрешены, и это нормально: дашборд
# отдаётся тем же процессом на порту 8080, то есть с того же origin, и в
# CORS-разрешениях не нуждается. Раскомментируйте и перечислите адреса только
# если к REST API будет обращаться СТОРОННЯЯ веб-страница с другого адреса.
# Значение "*" открывает API любому сайту в браузере пользователя — не ставьте
# его на сервере, доступном не только из доверенной сети.
# LACERT_CORS_ORIGINS=https://lacert.example.com
# Раскомментируйте, чтобы шлюз сам поднял N программных ESP32 для
# демонстрации/тестов без реального железа (см. internal/emulator):
# LACERT_EMULATE_DEVICES=2
# LACERT_EMULATE_INTERVAL=2s
# Раскомментируйте ТОЛЬКО в тестовой среде: журнал ротаций ключей
# (раздел "Журнал ротаций" в веб-интерфейсе) будет показывать полные
# значения старого/нового сеансового ключа. Никогда не включайте в проде —
# это чувствительный криптографический материал.
# LACERT_LOG_SESSION_KEYS=true
#
# ====================================================================
# Временные параметры (тайм-ауты и интервалы).
# Ниже перечислены ВСЕ настраиваемые временные параметры со СТОКОВЫМИ
# значениями (как в коде). Строки закомментированы (#) — пока стоит #,
# применяется значение по умолчанию из кода. Раскомментируйте строку,
# чтобы переопределить параметр своим значением.
# Формат длительности: s (секунды), m (минуты), h (часы). Пример: 90s, 2m, 1h.
# --------------------------------------------------------------------
#
# Как часто ротировать сеансовый ключ ПО ВРЕМЕНИ (даже при малом трафике).
# Чаще = меньше данных под одним ключом (безопаснее), но выше накладные расходы.
# LACERT_ROTATION_INTERVAL=300s
#
# Ротация ключа после N переданных пакетов (второй триггер, что наступит раньше).
# LACERT_ROTATION_PACKET_LIMIT=300
#
# Сколько ждать подтверждения (ACK) ротации, прежде чем считать её неуспешной и
# откатить. Защита от потери пакета. Для ECDSA на локальной сети хватает 5-10s.
# LACERT_ROTATION_ACK_TIMEOUT=5s
#
# Как часто планировщик опрашивает устройства ("не пора ли ротировать/проверять").
# Это НЕ сама ротация, а лишь частота опроса.
# LACERT_ROTATION_CHECK_PERIOD=5s
#
# Сколько неуспешных ротаций ПОДРЯД допускается, прежде чем устройство отзывают.
# LACERT_MAX_ROTATION_FAILURES=3
#
# Как часто проверять целостность прошивки каждого устройства.
# LACERT_FIRMWARE_INTERVAL=1h
#
# Окно, в которое устройство должно ответить на проверку прошивки (challenge).
# Ответ позже — отклоняется как устаревший (защита от replay заготовленного ответа).
# LACERT_FIRMWARE_VALIDITY=15s
#
# Пауза, после которой шлюз разрешает выдать НОВЫЙ challenge, если на прошлый не
# ответили (например, после потери пакета).
# LACERT_FIRMWARE_CHALLENGE_TIMEOUT=25s
#
# Через сколько протухает незавершённое рукопожатие (Msg2 отправлен, Msg3 не
# пришёл) — освобождает секретный материал из памяти.
# LACERT_PENDING_HANDSHAKE_TIMEOUT=20s
#
# Как долго помнить nonce рукопожатия для защиты от повтора (replay).
# LACERT_NONCE_TTL=5m
# ====================================================================
EOF
  chmod 600 "$ENV_FILE"
  chown "$LACERT_USER":"$LACERT_USER" "$ENV_FILE"
fi
chown -R "$LACERT_USER":"$LACERT_USER" "$INSTALL_DIR"

log "Установка systemd-сервиса"
cp "$REPO_ROOT/deploy/systemd/lacert-gatewayd.service" /etc/systemd/system/lacert-gatewayd.service
systemctl daemon-reload
systemctl enable lacert-gatewayd

# Именно restart, а не "enable --now": последнее запускает службу только если она
# ещё не работает. При повторном прогоне скрипта поверх работающей установки
# (обновление на новую версию) новый двоичный файл лёг бы в $BIN_DIR, но в
# памяти продолжил бы работать старый, и обновление выглядело бы успешным, не
# будучи таковым. restart корректен в обоих случаях: запускает остановленную
# службу и перезапускает работающую.
systemctl restart lacert-gatewayd

sleep 2
log "Статус сервиса"
systemctl --no-pager status lacert-gatewayd || true

echo
echo "=================================================================="
echo "Готово. Веб-интерфейс администрирования: http://<адрес_сервера>:8080/"
echo "(admin-токен для входа — см. $ENV_FILE)"
echo
echo "Обновление на новую версию: распакуйте новый архив и выполните этот же"
echo "скрипт из его корня. Пароль БД и admin-токен сохранятся, база не тронется,"
echo "служба перезапустится на новом двоичном файле."
echo
echo "Полезные команды:"
echo "  journalctl -u lacert-gatewayd -f          # логи в реальном времени"
echo "  curl -s http://localhost:8080/healthz     # проверка живости"
echo "  cat $ENV_FILE                              # пароль БД и admin-токен"
echo "  systemctl restart lacert-gatewayd         # перезапуск"
echo "  systemctl stop lacert-gatewayd            # остановка"
echo
if [[ "${CORS_WILDCARD:-0}" == "1" ]]; then
  echo
  echo "ВНИМАНИЕ: в $ENV_FILE осталась строка LACERT_CORS_ORIGINS=* от прежней"
  echo "установки. Она разрешает обращаться к REST API шлюза любому сайту,"
  echo "открытому в браузере администратора. Дашборд отдаётся с того же адреса"
  echo "и в этом разрешении не нуждается — строку можно удалить:"
  echo "  sed -i '/^LACERT_CORS_ORIGINS=\*$/d' $ENV_FILE && systemctl restart lacert-gatewayd"
  echo "Если к API обращается сторонняя веб-страница, вместо удаления перечислите"
  echo "её адрес явно: LACERT_CORS_ORIGINS=https://ваш-адрес"
fi
echo
echo "Не забудьте открыть в файрволе порты 7700 (TCP/LACERT), 8080 (REST + веб-страница),"
echo "1883 (MQTT), если устройства/веб-страница будут подключаться извне:"
echo "  ufw allow 7700/tcp; ufw allow 8080/tcp; ufw allow 1883/tcp"
echo "=================================================================="
