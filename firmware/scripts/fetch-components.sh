#!/usr/bin/env bash
#
# fetch-components.sh — подтягивает сторонние крипто-компоненты (чужой код,
# не хранится в этом репозитории) и накладывает поверх локальную обвязку под
# ESP32 из component-overlay/.
#
# Что делает:
#   • клонирует PQClean и BLAKE3 на зафиксированных версиях (*_REF ниже);
#   • берёт только файлы, нужные на ESP32, отбрасывая SIMD-реализации под
#     x86/ARM и примеры с собственным main();
#   • накладывает component-overlay/ — источник случайности (esp_fill_random),
#     заголовки и готовые CMakeLists.txt. Эти файлы НЕ из upstream, они
#     обязательны для сборки и поставляются в репозитории.
#
# После:  idf.py set-target esp32c6  &&  idf.py build
#
set -euo pipefail

# --- Зафиксированные версии. ВНИМАНИЕ: это заготовки; подставьте конкретные
# коммит PQClean и тег BLAKE3, проверенные вашей сборкой idf.py build. ------
PQCLEAN_REF="202a8f96315f9ed219387a50f7e40d04af037ea8"  # зафиксировано, проверено сборкой idf.py build под esp32c6
BLAKE3_REF="1.5.4"       # тег релиза BLAKE3

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OVERLAY="$ROOT/component-overlay"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[ -d "$OVERLAY" ] || { echo "ОШИБКА: нет $OVERLAY — в репозитории должна быть обвязка компонентов (randombytes_esp.c, CMakeLists и т.д.)" >&2; exit 1; }

clone_at() { # url ref dest
  git clone --quiet "$1" "$3"
  ( cd "$3" && git checkout --quiet "$2" ) || {
    echo "ОШИБКА: нет ревизии $2 в $1 (upstream мог переписать историю)" >&2; exit 1; }
}

# --- ML-KEM-1024 (PQClean) ---------------------------------------------
echo "==> ML-KEM-1024 (PQClean @ $PQCLEAN_REF)"
clone_at https://github.com/PQClean/PQClean "$PQCLEAN_REF" "$TMP/pqclean"
MLKEM_SRC="$TMP/pqclean/crypto_kem/ml-kem-1024/clean"
[ -d "$MLKEM_SRC" ] || { echo "ОШИБКА: нет $MLKEM_SRC — структура PQClean изменилась" >&2; exit 1; }

rm -rf "$ROOT/components/ml_kem"; mkdir -p "$ROOT/components/ml_kem"
cp "$MLKEM_SRC/"*.c "$MLKEM_SRC/"*.h "$ROOT/components/ml_kem/"
cp "$TMP/pqclean/common/fips202.c" "$TMP/pqclean/common/fips202.h" "$ROOT/components/ml_kem/"
# накладываем локальную обвязку ml_kem (randombytes_esp.c, randombytes.h,
# compat.h, рабочий CMakeLists.txt) — она перекрывает/дополняет upstream
cp "$OVERLAY/ml_kem/"* "$ROOT/components/ml_kem/"
echo "    ml_kem: upstream + overlay ($(ls "$ROOT/components/ml_kem/"*.c | wc -l | tr -d ' ') .c)"

# --- BLAKE3 ------------------------------------------------------------
echo "==> BLAKE3 (@ $BLAKE3_REF)"
clone_at https://github.com/BLAKE3-team/BLAKE3 "$BLAKE3_REF" "$TMP/blake3"
BLAKE3_SRC="$TMP/blake3/c"
[ -d "$BLAKE3_SRC" ] || { echo "ОШИБКА: нет $BLAKE3_SRC — структура BLAKE3 изменилась" >&2; exit 1; }

rm -rf "$ROOT/components/blake3"; mkdir -p "$ROOT/components/blake3"
# только переносимая реализация: SIMD (avx/sse/neon) под x86/ARM на ESP32
# (RISC-V/Xtensa) не компилируется; example*/main несут свой main().
for f in blake3.c blake3_dispatch.c blake3_portable.c blake3.h blake3_impl.h; do
  cp "$BLAKE3_SRC/$f" "$ROOT/components/blake3/" || { echo "ОШИБКА: нет $f в BLAKE3" >&2; exit 1; }
done
# рабочий CMakeLists из overlay (с BLAKE3_NO_* дефайнами)
cp "$OVERLAY/blake3/CMakeLists.txt" "$ROOT/components/blake3/"
echo "    blake3: 3 .c (portable) + overlay CMakeLists"

echo "==> Готово. components/ собран (upstream + overlay)."
echo "    Дальше:  idf.py set-target esp32c6   (или esp32s3)"
echo "             idf.py build"
