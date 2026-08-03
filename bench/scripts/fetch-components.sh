#!/usr/bin/env bash
#
# fetch-components.sh — скачивает сторонние криптографические реализации для
# прошивки замеров и раскладывает их компонентами ESP-IDF.
#
# Чужой код в репозитории не хранится: он берётся из первоисточника по
# зафиксированным версиям. Запускать один раз перед первой сборкой:
#
#   ./scripts/fetch-components.sh
#
# Общие для PQClean файлы (SHA-3, SHA-2, источник случайности) выносятся в
# отдельный компонент pqclean_common. Иначе они попали бы в каждый алгоритм
# по отдельности, и линковка упала бы на повторяющихся символах: PQClean
# разделяет по пространствам имён сами алгоритмы, но не общие функции.

set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
COMPONENTS="$HERE/components"
OVERLAY="$HERE/component-overlay"

# Версии зафиксированы: криптографическая реализация должна быть воспроизводимой,
# а замеры — сопоставимыми между прогонами.
PQCLEAN_REF="202a8f96315f9ed219387a50f7e40d04af037ea8"
BLAKE3_REF="1.5.4"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say()  { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }

clone_at() {
    local url="$1" ref="$2" dst="$3"
    git clone -q --filter=blob:none --no-checkout "$url" "$dst"
    git -C "$dst" fetch -q --depth 1 origin "$ref" 2>/dev/null || git -C "$dst" fetch -q origin
    git -C "$dst" checkout -q "$ref"
}

say "PQClean @ $PQCLEAN_REF"
clone_at https://github.com/PQClean/PQClean "$PQCLEAN_REF" "$TMP/pqclean"

# ─── Общий компонент ────────────────────────────────────────────────────────
say "общие файлы PQClean → pqclean_common"
mkdir -p "$COMPONENTS/pqclean_common"
for f in fips202.c fips202.h sha2.c sha2.h randombytes.h compat.h; do
    cp "$TMP/pqclean/common/$f" "$COMPONENTS/pqclean_common/"
done
ok "SHA-3 (fips202), SHA-2 (sha2), заголовки"

# ─── Алгоритмы ──────────────────────────────────────────────────────────────
# Каждый алгоритм — свой компонент. Имя заголовка-обёртки делаем коротким,
# чтобы прошивка не зависела от расположения файлов внутри PQClean.
add_algo() {
    local src="$1" comp="$2" header="$3"
    local dst="$COMPONENTS/$comp"
    mkdir -p "$dst"

    # Только переносимая реализация ("clean"): оптимизированные варианты
    # PQClean написаны под AVX2 и на ESP32 не соберутся.
    find "$TMP/pqclean/$src/clean" -maxdepth 1 -name '*.c' -o -maxdepth 1 -name '*.h' \
        | while read -r f; do cp "$f" "$dst/"; done

    # Обёртка: прошивке достаточно включить один заголовок на алгоритм.
    cp "$dst/api.h" "$dst/$header"

    local srcs
    srcs="$(cd "$dst" && ls *.c | sed 's/^/        "/; s/$/"/')"
    cat > "$dst/CMakeLists.txt" <<EOF
# $comp — сгенерировано scripts/fetch-components.sh, править вручную не нужно.
idf_component_register(
    SRCS
$srcs
    INCLUDE_DIRS "."
    REQUIRES pqclean_common esp_hw_support
)
EOF
    ok "$comp"
}

say "алгоритмы"
add_algo crypto_kem/ml-kem-512               mlkem512    mlkem512.h
add_algo crypto_kem/ml-kem-768               mlkem768    mlkem768.h
add_algo crypto_kem/ml-kem-1024              mlkem1024   mlkem1024.h
add_algo crypto_sign/ml-dsa-44               mldsa44     mldsa44.h
add_algo crypto_sign/ml-dsa-65               mldsa65     mldsa65.h
add_algo crypto_sign/ml-dsa-87               mldsa87     mldsa87.h
add_algo crypto_sign/sphincs-sha2-128s-simple slhdsa128s slhdsa128s.h

# ─── BLAKE3 ─────────────────────────────────────────────────────────────────
say "BLAKE3 @ $BLAKE3_REF"
clone_at https://github.com/BLAKE3-team/BLAKE3 "$BLAKE3_REF" "$TMP/blake3"
mkdir -p "$COMPONENTS/blake3"
# Только переносимая реализация: остальные файлы — под SIMD x86 и ARM, на
# ESP32 они не нужны и не собираются.
for f in blake3.c blake3.h blake3_dispatch.c blake3_impl.h blake3_portable.c; do
    cp "$TMP/blake3/c/$f" "$COMPONENTS/blake3/"
done
ok "переносимая реализация"

# ─── Наложение обвязки ──────────────────────────────────────────────────────
# Файлы, которых в первоисточниках нет: источник случайности на аппаратном
# генераторе ESP32 и сборочные файлы, которые не генерируются автоматически.
if [ -d "$OVERLAY" ]; then
    say "обвязка из component-overlay"
    ( cd "$OVERLAY" && find . -type f -print0 ) | while IFS= read -r -d '' rel; do
        mkdir -p "$COMPONENTS/$(dirname "$rel")"
        cp "$OVERLAY/$rel" "$COMPONENTS/$rel"
        ok "${rel#./}"
    done
fi

echo
say "готово. Дальше:"
echo "    idf.py set-target esp32c6     (или esp32s3)"
echo "    idf.py build flash monitor"
