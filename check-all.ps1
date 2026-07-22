# check-all.ps1 — полная проверка проекта LACERT под Windows/PowerShell.
# Запускать из корня проекта (там, где go.mod):
#
#   .\check-all.ps1
#
# Если PowerShell не разрешает запуск скриптов, выполните один раз:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$ErrorActionPreference = "Continue"
$failed = 0

function Say($t)  { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [OK] $t" -ForegroundColor Green }
function Bad($t)  { Write-Host "  [!!] $t" -ForegroundColor Red }
function Warn($t) { Write-Host "  [~~] $t" -ForegroundColor Yellow }
function Inf($t)  { Write-Host "    $t" -ForegroundColor DarkGray }

# ─────────────────────────────────────────────────────────────
Say "1. Окружение"
$v = go version
if ($LASTEXITCODE -eq 0) { Ok $v } else { Bad "Go не найден"; exit 1 }

# ─────────────────────────────────────────────────────────────
Say "2. Сборка"
$out = go build ./... 2>&1
if ($LASTEXITCODE -eq 0) { Ok "go build ./... — без ошибок" }
else { Bad "go build упал:"; $out | Select-Object -First 10 | ForEach-Object { Inf $_ }; $failed = 1 }

# ─────────────────────────────────────────────────────────────
Say "3. Статический анализ"
$out = go vet ./... 2>&1
if ($LASTEXITCODE -eq 0) { Ok "go vet ./... — замечаний нет" }
else { Bad "go vet нашёл проблемы:"; $out | Select-Object -First 10 | ForEach-Object { Inf $_ }; $failed = 1 }

# ─────────────────────────────────────────────────────────────
Say "4. Тесты"
$out = go test ./... -count=1 2>&1
$passed = ($out | Select-String -Pattern '^ok' ).Count
$fail   = ($out | Select-String -Pattern '^FAIL').Count
if ($fail -eq 0) { Ok "все пакеты прошли ($passed шт.)" }
else {
  Bad "провалено пакетов: $fail"
  $out | Select-String -Pattern '^(FAIL|--- FAIL)' | Select-Object -First 10 | ForEach-Object { Inf $_ }
  $failed = 1
}

# Тесты PostgreSQL пропускаются без LACERT_TEST_PG_DSN. Без предупреждения отчёт
# «все пакеты прошли» вводил бы в заблуждение: хранилище остаётся непроверенным,
# а именно оно отвечает за сохранность данных между запусками.
$skipped = ($out | Select-String -Pattern '^--- SKIP').Count
if (-not $env:LACERT_TEST_PG_DSN) {
  Warn "тесты PostgreSQL пропущены (LACERT_TEST_PG_DSN не задана)"
  Inf 'задайте её, чтобы проверить хранилище, например:'
  Inf '$env:LACERT_TEST_PG_DSN = "host=localhost user=lacert password=... dbname=lacert sslmode=disable"'
} elseif ($skipped -ne 0) {
  Warn "часть тестов пропущена ($skipped шт.)"
} else {
  Ok "тесты PostgreSQL выполнены"
}

# ─────────────────────────────────────────────────────────────
Say "5. Детектор гонок данных"
Inf "(требует gcc; если его нет — секция пропустится)"
$out = go test -race ./internal/... -count=1 2>&1
if ($LASTEXITCODE -eq 0) { Ok "go test -race — гонок не обнаружено" }
elseif ($out -match 'requires cgo|gcc') { Inf "пропущено: нужен компилятор C (gcc)" }
elseif ($out -match 'DATA RACE') {
  Bad "обнаружена гонка данных:"
  $out | Select-String -Pattern 'DATA RACE' -Context 0,6 | Select-Object -First 1 | ForEach-Object { Inf $_ }
  $failed = 1
}
else { Bad "тесты с -race не прошли"; $out | Select-String '^FAIL' | Select-Object -First 5 | ForEach-Object { Inf $_ } }

# ─────────────────────────────────────────────────────────────
Say "6. Покрытие тестами"
go test ./internal/... -cover -count=1 2>&1 |
  Select-String -Pattern 'coverage:' | ForEach-Object { Inf $_ }

# ─────────────────────────────────────────────────────────────
Say "7. Бенчмарки подписи (главные цифры)"
go test ./internal/crypto/ -bench 'BenchmarkSign|BenchmarkVerify|BenchmarkGenerateIdentity' `
  -benchtime=10x -benchmem -run '^$' -count=1 2>&1 |
  Select-String -Pattern '^Benchmark' | ForEach-Object { Inf $_ }

# ─────────────────────────────────────────────────────────────
Say "8. Бенчмарки ML-KEM, шифрования и ротации"
go test ./internal/crypto/ -bench 'GenerateKEMKeyPair|Encapsulate|Decapsulate|EncryptPacket|RotationStep' `
  -benchtime=50x -run '^$' -count=1 2>&1 |
  Select-String -Pattern '^Benchmark' | ForEach-Object { Inf $_ }

# ─────────────────────────────────────────────────────────────
Say "9. Бенчмарки полного рукопожатия"
Inf "(весь протокол целиком: ECDSA против SLH-DSA)"
go test ./internal/crypto/ -bench 'FullHandshake' `
  -benchtime=5x -run '^$' -count=1 2>&1 |
  Select-String -Pattern '^Benchmark' | ForEach-Object { Inf $_ }

# ─────────────────────────────────────────────────────────────
Say "10. Документация"
$ru = @(Get-ChildItem -Path "docs\ru\*.md" -ErrorAction SilentlyContinue).Count
$en = @(Get-ChildItem -Path "docs\en\*.md" -ErrorAction SilentlyContinue).Count
if ($ru -eq $en -and $ru -gt 0) { Ok "docs/ru и docs/en синхронны ($ru файлов)" }
else { Bad "рассинхрон: ru=$ru en=$en"; $failed = 1 }

# битые ссылки внутри документации
$broken = 0; $total = 0
foreach ($lang in @("ru","en")) {
  $dir = "docs\$lang"
  if (-not (Test-Path $dir)) { continue }
  foreach ($f in Get-ChildItem "$dir\*.md") {
    $text = Get-Content $f.FullName -Raw
    foreach ($m in [regex]::Matches($text, '\]\(([^)#]+\.md)')) {
      $link = $m.Groups[1].Value
      if ($link -like "http*") { continue }
      $total++
      $target = Join-Path $dir $link
      if (-not (Test-Path $target)) { Bad "битая ссылка: $lang/$($f.Name) -> $link"; $broken++ }
    }
  }
}
if ($broken -eq 0) { Ok "ссылок проверено $total, битых 0" } else { $failed = 1 }

# ─────────────────────────────────────────────────────────────
Say "11. Гигиена репозитория"
$acad = Select-String -Path "*.md","docs\ru\*.md","docs\en\*.md","internal\**\*.go" `
        -Pattern 'диплом|магистр|отчёт по практике' -ErrorAction SilentlyContinue
if (-not $acad) { Ok "учебных упоминаний нет" } else { Bad "учебных упоминаний: $($acad.Count)" }

# ─────────────────────────────────────────────────────────────
Say "ИТОГ"
if ($failed -eq 0) { Write-Host "  все проверки пройдены" -ForegroundColor Green }
else { Write-Host "  есть проблемы — см. выше" -ForegroundColor Red }
Write-Host ""
