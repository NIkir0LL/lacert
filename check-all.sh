#!/usr/bin/env bash
#
# check-all.sh — полная проверка проекта LACERT.
# Запускать из корня проекта (там, где go.mod).
#
#   bash check-all.sh
#
set -u
cd "$(dirname "$0")" 2>/dev/null || true

ok(){ printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
bad(){ printf '  \033[1;31m✗\033[0m %s\n' "$1"; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$1"; }
inf(){ printf '    \033[0;37m%s\033[0m\n' "$1"; }
say(){ printf '\n\033[1;36m━━━ %s ━━━\033[0m\n' "$1"; }

FAILED=0

# ─────────────────────────────────────────────────────────────
say "1. Окружение"
if command -v go >/dev/null; then
  ok "Go: $(go version | awk '{print $3, $4}')"
else
  bad "Go не найден"; exit 1
fi

# ─────────────────────────────────────────────────────────────
say "2. Сборка"
if out=$(go build ./... 2>&1); then
  ok "go build ./... — без ошибок"
else
  bad "go build упал:"; printf '%s\n' "$out" | head -10 | sed 's/^/      /'; FAILED=1
fi

# ─────────────────────────────────────────────────────────────
say "3. Статический анализ"
if out=$(go vet ./... 2>&1); then
  ok "go vet ./... — замечаний нет"
else
  bad "go vet нашёл проблемы:"; printf '%s\n' "$out" | head -10 | sed 's/^/      /'; FAILED=1
fi

# ─────────────────────────────────────────────────────────────
say "4. Тесты"
tout=$(go test ./... -count=1 2>&1)
passed=$(printf '%s\n' "$tout" | grep -c '^ok')
failed=$(printf '%s\n' "$tout" | grep -c '^FAIL')
if [ "$failed" = "0" ]; then
  ok "все пакеты прошли ($passed шт.)"
else
  bad "провалено пакетов: $failed"
  printf '%s\n' "$tout" | grep -A3 '^--- FAIL' | head -20 | sed 's/^/      /'; FAILED=1
fi

# Тесты PostgreSQL пропускаются без LACERT_TEST_PG_DSN. Без этого предупреждения
# отчёт «все пакеты прошли» вводил бы в заблуждение: хранилище остаётся
# непроверенным, а именно оно отвечает за сохранность данных между перезапусками.
skipped=$(printf '%s\n' "$tout" | grep -c '^--- SKIP' || true)
if [ "${LACERT_TEST_PG_DSN:-}" = "" ]; then
  warn "тесты PostgreSQL пропущены (LACERT_TEST_PG_DSN не задана)"
  printf '      задайте её, чтобы проверить хранилище:\n'
  printf '      LACERT_TEST_PG_DSN="host=localhost user=lacert password=... dbname=lacert sslmode=disable"\n'
elif [ "$skipped" != "0" ]; then
  warn "часть тестов пропущена ($skipped шт.)"
else
  ok "тесты PostgreSQL выполнены"
fi

# ─────────────────────────────────────────────────────────────
say "5. Детектор гонок данных"
if out=$(go test -race ./internal/... -count=1 2>&1); then
  ok "go test -race — гонок не обнаружено"
else
  if printf '%s\n' "$out" | grep -q 'DATA RACE'; then
    bad "обнаружена гонка данных:"
    printf '%s\n' "$out" | grep -A8 'DATA RACE' | head -15 | sed 's/^/      /'; FAILED=1
  else
    bad "тесты с -race не прошли"; printf '%s\n' "$out" | grep '^FAIL' | head -5 | sed 's/^/      /'; FAILED=1
  fi
fi

# ─────────────────────────────────────────────────────────────
say "6. Покрытие тестами"
go test ./internal/... -cover -count=1 2>/dev/null \
  | grep -E 'coverage:' | sed 's/^/    /' | head -15

# ─────────────────────────────────────────────────────────────
say "7. Бенчмарки подписи"
inf "(это главные цифры для сравнения алгоритмов)"
go test ./internal/crypto/ -bench 'BenchmarkSign|BenchmarkVerify|BenchmarkGenerateIdentity' \
  -benchtime=10x -benchmem -run '^$' -count=1 2>&1 \
  | grep -E '^Benchmark' | sed 's/-[0-9]*\s\+/  /' | sed 's/^/    /'

# ─────────────────────────────────────────────────────────────
say "8. Бенчмарки ML-KEM, шифрования и ротации"
go test ./internal/crypto/ -bench 'GenerateKEMKeyPair|Encapsulate|Decapsulate|EncryptPacket|RotationStep' \
  -benchtime=50x -run '^$' -count=1 2>&1 \
  | grep -E '^Benchmark' | sed 's/-[0-9]*\s\+/  /' | sed 's/^/    /'

say "9. Бенчмарки полного рукопожатия"
inf "(ECDSA против SLH-DSA — весь протокол целиком)"
go test ./internal/crypto/ -bench 'FullHandshake' \
  -benchtime=5x -run '^$' -count=1 2>&1 \
  | grep -E '^Benchmark' | sed 's/-[0-9]*\s\+/  /' | sed 's/^/    /' 

# ─────────────────────────────────────────────────────────────
say "10. Документация"
ru=$(ls docs/ru/*.md 2>/dev/null | wc -l)
en=$(ls docs/en/*.md 2>/dev/null | wc -l)
[ "$ru" = "$en" ] && [ "$ru" -gt 0 ] \
  && ok "docs/ru и docs/en синхронны ($ru файлов)" \
  || { bad "рассинхрон: ru=$ru en=$en"; FAILED=1; }

# битые ссылки
python3 - <<'PY' 2>/dev/null || echo "    (python3 не найден — проверка ссылок пропущена)"
import os,re
bad=tot=0
for lang in ('ru','en'):
    d=os.path.join('docs',lang)
    if not os.path.isdir(d): continue
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('.md'): continue
        s=open(os.path.join(d,fn),encoding='utf-8').read()
        for m in re.finditer(r'\]\(([^)#]+\.md)[^)]*\)', s):
            link=m.group(1); tot+=1
            if link.startswith('http'): continue
            if not os.path.exists(os.path.normpath(os.path.join(d,link))):
                print(f"    \033[1;31m✗\033[0m битая ссылка: {lang}/{fn} → {link}"); bad+=1
print(f"  \033[1;32m✓\033[0m ссылок проверено {tot}, битых {bad}" if bad==0
      else f"  \033[1;31m✗\033[0m битых ссылок: {bad}")
PY

# ─────────────────────────────────────────────────────────────
say "11. Гигиена репозитория"
n=$(grep -rniE 'диплом|магистр|отчёт по практике' --include='*.md' --include='*.go' --include='*.c' . 2>/dev/null \
    | grep -v vendor | grep -v 'firmware/components' | wc -l)
[ "$n" = "0" ] && ok "учебных упоминаний нет" || { bad "учебных упоминаний: $n"; }

n=$(grep -rniE '(token|password|secret)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9+/]{16,}' \
    --include='*.go' . 2>/dev/null | grep -v vendor | grep -v _test | wc -l)
[ "$n" = "0" ] && ok "жёстко заданных секретов не найдено" || bad "возможные секреты: $n"

# ─────────────────────────────────────────────────────────────
say "ИТОГ"
if [ "$FAILED" = "0" ]; then
  printf '  \033[1;32mвсе проверки пройдены\033[0m\n\n'
else
  printf '  \033[1;31mесть проблемы — см. выше\033[0m\n\n'
  exit 1
fi
