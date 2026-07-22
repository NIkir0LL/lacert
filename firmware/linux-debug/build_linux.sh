#!/usr/bin/env bash
# build_linux.sh — собрать Linux-версию C-клиента LACERT для отладки протокола
# против работающего Go-шлюза (БЕЗ железа ESP32).
#
# Зачем: отладить C-реализацию протокола на большом компьютере (быстрые циклы,
# gdb, санитайзеры), прежде чем заливать на ESP32. Использует те же
# lacert_wire.c и lacert_client.c, что и прошивка; крипто — на OpenSSL (вместо
# mbedTLS), ML-KEM — PQClean, BLAKE3 — официальная C-реализация.
#
# ПРЕДВАРИТЕЛЬНО (один раз) на Ubuntu/Debian:
#   sudo apt-get update
#   sudo apt-get install -y build-essential libssl-dev
#
# Затем скачать крипто-библиотеки (см. переменные ниже) и запустить этот скрипт.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Каталоги с исходниками прошивки (общие с ESP32) и Linux-специфичные.
FW_MAIN="../main"
LINUX_DIR="."

# Пути к скачанным библиотекам (поменяйте под своё расположение).
BLAKE3_DIR="${BLAKE3_DIR:-$HOME/BLAKE3/c}"
PQCLEAN_DIR="${PQCLEAN_DIR:-$HOME/PQClean}"
KEM_DIR="$PQCLEAN_DIR/crypto_kem/ml-kem-1024/clean"

if [ ! -d "$BLAKE3_DIR" ]; then
  echo "ОШИБКА: не найден BLAKE3 в $BLAKE3_DIR"
  echo "Скачайте: git clone https://github.com/BLAKE3-team/BLAKE3 ~/BLAKE3"
  exit 1
fi
if [ ! -d "$KEM_DIR" ]; then
  echo "ОШИБКА: не найден PQClean ML-KEM в $KEM_DIR"
  echo "Скачайте: git clone https://github.com/PQClean/PQClean ~/PQClean"
  exit 1
fi

echo ">>> Сборка Linux-клиента..."
# -Wno-deprecated-declarations: OpenSSL 3.0 помечает EC_KEY_* устаревшими, но
# они работают корректно. Для отладочного инструмента переписывать на новый
# EVP_PKEY API смысла нет — подавляем шум предупреждений.
gcc -O2 -std=c11 -Wall -Wno-deprecated-declarations \
  -I"$FW_MAIN" -I"$KEM_DIR" -I"$PQCLEAN_DIR/common" -I"$BLAKE3_DIR" \
  -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 \
  "$FW_MAIN/lacert_wire.c" \
  "$FW_MAIN/lacert_client.c" \
  "$LINUX_DIR/lacert_crypto_linux.c" \
  "$LINUX_DIR/main_linux.c" \
  "$KEM_DIR"/*.c \
  "$PQCLEAN_DIR/common/fips202.c" \
  "$BLAKE3_DIR/blake3.c" \
  "$BLAKE3_DIR/blake3_dispatch.c" \
  "$BLAKE3_DIR/blake3_portable.c" \
  -lcrypto \
  -o lacert-client

echo ">>> Готово: ./lacert-client"
echo ""
echo "Запуск против работающего шлюза:"
echo "  LACERT_ADMIN_TOKEN=<токен> LACERT_DEVICE_ID=linux-1 \\"
echo "    ./lacert-client <host> <http_port> <tcp_port>"
echo "например:"
echo "  LACERT_ADMIN_TOKEN=... ./lacert-client 127.0.0.1 8080 7700"
