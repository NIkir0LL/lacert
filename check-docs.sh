#!/usr/bin/env bash
#
# check-docs.sh — сверка документации с кодом.
#
# Отвечает на один вопрос: не разошлось ли написанное в документах с тем, что
# на самом деле делает программа. Проверки подобраны по ошибкам, которые уже
# случались в этом проекте, а не по общим соображениям:
#
#   • один и тот же замер приводился в двух документах с разными значениями
#   • предел из кода был назван в спецификации другим термином
#   • документ ссылался на раздел, переехавший в другой файл
#   • новая переменная окружения появлялась в коде раньше, чем в справочнике
#
# Запускать из корня проекта:
#
#     bash check-docs.sh
#
# Возвращает ненулевой код, если найдено расхождение, поэтому годится для
# включения в автоматические проверки.

set -u
cd "$(dirname "$0")" 2>/dev/null || true

ok(){   printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
bad(){  printf '  \033[1;31m✗\033[0m %s\n' "$1"; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$1"; }
say(){  printf '\n\033[1;36m━━━ %s ━━━\033[0m\n' "$1"; }
inf(){  printf '    \033[0;37m%s\033[0m\n' "$1"; }

FAILED=0

if ! command -v python3 >/dev/null; then
  bad "python3 не найден, сверка невозможна"
  exit 1
fi

# Без этой проверки запуск из чужого каталога дал бы невнятный перечень мнимых
# расхождений вместо понятного сообщения о том, что искать нечего.
if [ ! -f go.mod ] || [ ! -d docs/ru ]; then
  bad "это не корень проекта LACERT: не найдены go.mod или docs/ru"
  inf "запускать из каталога, где лежит go.mod"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
say "1. Переменные окружения"
# Ловит случай: переменную добавили в код и забыли описать, или наоборот —
# описали и удалили из кода, оставив запись в справочнике.
python3 - <<'PY' || FAILED=1
import re, os, sys

def read(p):
    try: return open(p, encoding="utf-8").read()
    except OSError: return ""

used = set()
for root, _, files in os.walk("."):
    if "vendor" in root or "/.git" in root: continue
    for f in files:
        if not f.endswith(".go"): continue
        s = read(os.path.join(root, f))
        # и прямой вызов, и обёртка getenv(key, default)
        used |= set(re.findall(r'(?:os\.Getenv|getenv)\(\s*"(LACERT_[A-Z_0-9]+)"', s))

# прошивка задаёт свои макросами, справочник их тоже описывает
firmware = set(re.findall(r'#define\s+(LACERT_[A-Z_0-9]+)', read("firmware/main/main.c")))

documented = set(re.findall(r'`(LACERT_[A-Z_0-9]+)`', read("docs/ru/CONFIG.md")))

known = used | firmware
missing = sorted(documented - known)   # описаны, но нигде не встречаются
undocumented = sorted(used - documented)

if undocumented:
    for v in undocumented:
        print(f"  \033[1;31m✗\033[0m {v} читается кодом, но не описана в CONFIG.md")
if missing:
    for v in missing:
        print(f"  \033[1;33m!\033[0m {v} описана, но в коде и прошивке не встречается")
if not undocumented and not missing:
    print(f"  \033[1;32m✓\033[0m {len(documented)} переменных, расхождений нет")

sys.exit(1 if undocumented else 0)
PY

# ─────────────────────────────────────────────────────────────────────────────
say "2. Коды кадров протокола"
# Три источника должны совпадать: реализация на Go, заголовок прошивки,
# спецификация. Рассинхрон здесь означает, что устройство и шлюз поймут
# разное, а документ опишет третье.
python3 - <<'PY' || FAILED=1
import re, sys

def read(p):
    try: return open(p, encoding="utf-8").read()
    except OSError: return ""

go   = dict(re.findall(r'(Type\w+)\s+byte\s*=\s*(\d+)', read("internal/wire/wire.go")))
c    = dict(re.findall(r'#define\s+LACERT_MSG_(\w+)\s+(\d+)', read("firmware/main/lacert_proto.h")))
doc  = dict(re.findall(r'\|\s*`(Type\w+)`\s*\|\s*(\d+)\s*\|', read("docs/ru/PROTOCOL_SPEC.md")))

problems = 0
for name, val in sorted(go.items(), key=lambda x: int(x[1])):
    if doc.get(name) != val:
        print(f"  \033[1;31m✗\033[0m {name}={val} в коде, в спецификации {doc.get(name, 'отсутствует')}")
        problems += 1

# прошивка называет типы иначе, поэтому сверяем только набор значений
if sorted(map(int, go.values())) != sorted(map(int, c.values())):
    print(f"  \033[1;31m✗\033[0m набор кодов в прошивке отличается от кода на Go")
    problems += 1

if problems == 0:
    print(f"  \033[1;32m✓\033[0m {len(go)} кодов совпадают в трёх источниках")
sys.exit(1 if problems else 0)
PY

# ─────────────────────────────────────────────────────────────────────────────
say "3. Пределы и постоянные величины"
# Ловит случай: значение поменяли в коде, а в документе осталось прежнее.
python3 - <<'PY' || FAILED=1
import re, sys

def read(p):
    try: return open(p, encoding="utf-8").read()
    except OSError: return ""

# что ищем в коде → где должно быть упомянуто в документации
checks = [
    ("MaxPayloadSize",  r'MaxPayloadSize\s*=\s*(\d+)',      "internal/crypto/aead.go",  ["docs/ru/PROTOCOL_SPEC.md"]),
    ("ChallengeSize",   r'ChallengeSize\s*=\s*(\d+)',       "internal/crypto/firmware.go", ["docs/ru/PROTOCOL_SPEC.md"]),
    ("MaxConnections",  r'MaxConnections\s*=\s*(\d+)',      "internal/transport/tcpserver/server.go", ["docs/ru/CONFIG.md"]),
]
problems = 0
for name, pat, src, docs in checks:
    m = re.search(pat, read(src))
    if not m:
        print(f"  \033[1;33m!\033[0m {name}: не найдена в {src}, проверка пропущена")
        continue
    val = m.group(1)
    found_in = [d for d in docs if re.search(rf'\b{val}\b', read(d))]
    if found_in:
        print(f"  \033[1;32m✓\033[0m {name} = {val}, упомянута в {', '.join(found_in)}")
    else:
        print(f"  \033[1;31m✗\033[0m {name} = {val} в коде, но значение не встречается в {', '.join(docs)}")
        problems += 1
sys.exit(1 if problems else 0)
PY

# ─────────────────────────────────────────────────────────────────────────────
say "4. Опорные замеры"
# Ловит случай, найденный внешним разбором: подпись ECDSA приводилась как 22,1
# в одном месте и 22,2 в шести других. Отличие в одном знаке, соотношение в той
# же строке сходилось при обоих значениях, и три вычитки подряд его пропустили.
#
# Проверка идёт от списка опорных значений. Разбирать таблицы не выходит:
# в строке вида «| подпись | 170,2 мс | 22,1 мс |» плата не названа, она стоит
# в заголовке столбца, поэтому привязать число к плате по тексту строки нельзя.
# Вместо этого каждое число сверяется с набором значений, допустимых для этой
# операции.
python3 - <<'PYEOF' || FAILED=1
import re, os, sys

# Опорные значения, сгруппированные по операции. Каждое число, встреченное в
# строке про эту операцию, должно совпасть с одним из них — с точностью до
# округления. Список ведётся вручную намеренно: меняя замер, приходится
# править эту строку, а значит задумываться, где ещё число встречается.
#
# Источник — docs/ru/MEASUREMENTS.md, основная таблица.
CANON = {
    ("ecdsa", "sign"):    {"опорные": [22.2, 170.2, 0.35],
                           "иные": [21.90, 167.97, 158.05, 313.10, 21.9]},
    ("ecdsa", "keygen"):  {"опорные": [9.6, 156.7, 0.30],
                           "иные": [8.85, 154.47, 154.34, 145.15, 145.01]},
    ("ml-kem", "encaps"): {"опорные": [16.0, 18.4, 0.11],
                           "иные": [15.97, 15.99, 17.89, 6.69, 10.68, 7.40, 11.92]},
    ("ml-kem", "decaps"): {"опорные": [17.8, 21.1, 0.12],
                           "иные": [17.70, 17.72, 20.37, 7.51, 11.94, 8.84, 13.83]},
}
# «иные» — числа, законно встречающиеся рядом с опорными: повторные замеры
# прошивкой из bench/, значения для младших уровней стойкости, замеры на
# сервере. Они не ошибка, но и не опорные, поэтому перечислены явно.

def parse(num):
    s = num.replace("\u00a0", " ").replace(" ", "")
    s = s.replace(",", "") if ("," in s and "." in s) else s.replace(",", ".")
    try: return float(s)
    except ValueError: return None

def precision(num):
    s = num.replace(",", ".")
    return len(s.split(".")[1]) if "." in s else 0

def canon_precision(t):
    st = ("%g" % t)
    return len(st.split(".")[1]) if "." in st else 0

def matches(v, p, target):
    """Совпадает ли с учётом округления.

    Сравнение идёт по МЕНЬШЕЙ из двух точностей. Это существенно в обе стороны:
    «около 170 мс» в обзоре и 170,2 в таблице — одно число, и 9,63 в образце
    вывода прошивки против округлённого 9,6 в таблице — тоже одно."""
    d = min(p, canon_precision(target))
    return round(v, d) == round(target, d)

NUM = re.compile(r"([\d]+(?:[.,][\d]+)?)\s*(мс|ms)\b")
OPS = {"sign":   ("подпись", "sign"),
       "keygen": ("генерация ключ", "keygen", "keypair"),
       "encaps": ("инкапс", "encaps"),
       "decaps": ("декапс", "decaps")}

problems = 0
checked = 0

for lang in ("ru", "en"):
    d = os.path.join("docs", lang)
    if not os.path.isdir(d): continue
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md"): continue
        for i, line in enumerate(open(os.path.join(d, fn), encoding="utf-8"), 1):
            low = line.lower()
            for (alg, op), sets in CANON.items():
                if alg not in low: continue
                if not any(w in low for w in OPS[op]): continue
                nums = [(parse(n), precision(n), n) for n, _ in NUM.findall(line)]
                nums = [(v, p, raw) for v, p, raw in nums if v is not None]
                if not nums: continue
                checked += 1
                allowed = sets["опорные"] + sets["иные"]
                for v, p, raw in nums:
                    if any(matches(v, p, t) for t in allowed):
                        continue
                    # не совпало ни с чем — близко ли к опорному?
                    near = [t for t in sets["опорные"] if t and abs(v - t) / t < 0.05]
                    if near:
                        print("  \033[1;31m\u2717\033[0m %s %s: встречено %s, ожидалось %g \u2014 %s/%s:%d"
                              % (alg.upper(), op, raw, near[0], lang, fn, i))
                        problems += 1

if problems == 0:
    print("  \033[1;32m\u2713\033[0m %d строк с опорными замерами, отклонений нет" % checked)
sys.exit(1 if problems else 0)
PYEOF

say "5. Числовой паритет двух локалей"
# Ловит случай: замер обновили в русской версии и забыли в английской.
#
# Разделители в двух языках разные, и без приведения к общему виду проверка
# тонет в мнимых расхождениях. В русском тексте тысячи разделяются пробелом
# (101 057), дробная часть запятой (22,2). В английском наоборот: тысячи
# запятой (101,057), дробная часть точкой (22.2).
python3 - <<'PYEOF' || FAILED=1
import re, os, sys

# Число целиком. Сначала пробуется вид с разделителем тысяч (группы ровно по
# три цифры), затем обычный. Запрет цифры следом обязателен: без него «0,00001»
# разбиралось бы как «0,000» и «01», приняв дробную часть за тысячи.
# Набор знаков внутри одного шаблона брать нельзя — «3.3, 122,8» слиплось бы
# в одно число.
NUM = re.compile(r"\d{1,3}(?:[\u00a0 ,]\d{3})+(?:[.,]\d+)?(?!\d)|\d+(?:[.,]\d+)?")

def norm(raw):
    """Приводит число к единому виду независимо от языка.

    Разделитель тысяч распознаётся по строению всего числа, а не по соседнему
    знаку: группы ровно по три цифры, а целая часть не начинается с нуля.
    Поэтому 60 034 и 60,034 дают одно значение, а 0,025 остаётся дробью."""
    s = raw.replace("\u00a0", " ").strip()
    if re.fullmatch(r"[1-9]\d{0,2}(?: \d{3})+", s):        # русский вид
        return "%g" % float(s.replace(" ", ""))
    if re.fullmatch(r"[1-9]\d{0,2}(?:,\d{3})+", s):        # английский вид
        return "%g" % float(s.replace(",", ""))
    s = s.replace(" ", "")
    if "," in s and "." in s:
        # присутствуют оба знака: 13,295.00 — запятая здесь разделяет тысячи
        s = s.replace(",", "")
    else:
        s = s.replace(",", ".")
    try:
        return "%g" % float(s)
    except ValueError:
        return None

def numbers(path):
    if not os.path.exists(path): return []
    out, incode = [], False
    for line in open(path, encoding="utf-8"):
        if line.startswith("```"): incode = not incode; continue
        if incode: continue
        for raw in NUM.findall(line):
            v = norm(raw)
            if v is not None: out.append(v)
    return sorted(out)

problems = 0
for fn in sorted(os.listdir("docs/ru")):
    if not fn.endswith(".md"): continue
    ru, en = set(numbers("docs/ru/" + fn)), set(numbers("docs/en/" + fn))
    only_ru, only_en = sorted(ru - en)[:6], sorted(en - ru)[:6]
    if only_ru or only_en:
        print("  \033[1;31m\u2717\033[0m %s: только в русской %s, только в английской %s"
              % (fn, only_ru, only_en))
        problems += 1

if problems == 0:
    print("  \033[1;32m\u2713\033[0m числа во всех парах документов совпадают")
sys.exit(1 if problems else 0)
PYEOF

say "6. Упоминания файлов"
# Ловит случай: файл переименовали или удалили, а ссылка на него осталась.
#
# Отсеиваются два вида упоминаний, которые файлами не являются: ссылки на
# функции вида `internal/wire.takeFramed` (точка после имени пакета) и
# каталоги, которые в репозитории не хранятся, а скачиваются при сборке
# (`firmware/components/`, `bench/components/`).
python3 - <<'PYEOF' || FAILED=1
import re, os, sys

# каталоги, которых в репозитории нет намеренно
GENERATED = ("firmware/components", "bench/components", "firmware/build", "bench/build")

problems = checked = 0
for lang in ("ru", "en"):
    d = os.path.join("docs", lang)
    if not os.path.isdir(d): continue
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md"): continue
        for i, line in enumerate(open(os.path.join(d, fn), encoding="utf-8"), 1):
            for path in re.findall(r"`((?:internal|cmd|firmware|bench|deploy|docs)/[\w./-]+)`", line):
                p = path.rstrip("/")
                if any(p.startswith(g) for g in GENERATED): continue
                # ссылка на функцию: имя пакета, точка, имя с заглавной или строчной
                if re.search(r"/[\w-]+\.[A-Za-z]\w*$", p) and not re.search(r"\.(go|c|h|md|sh|css|js|html|yml|csv)$", p):
                    continue
                checked += 1
                if not os.path.exists(p):
                    print("  \033[1;31m\u2717\033[0m %s/%s:%d упоминает несуществующий путь %s"
                          % (lang, fn, i, path))
                    problems += 1
if problems == 0:
    print("  \033[1;32m\u2713\033[0m %d упоминаний путей, все существуют" % checked)
sys.exit(1 if problems else 0)
PYEOF

say "7. Мусор в дереве"
# Ловит случай, найденный при разборе дерева: в репозитории лежали два файла
# нулевого размера с двойным расширением, ни на что не ссылающиеся. Заодно
# ловит сохранённый в корень вывод команд и прочее, чему в выпуске не место.
python3 - <<'PYEOF' || FAILED=1
import os, sys

SKIP = ("./.git", "./vendor", "./firmware/build", "./bench/build",
        "./firmware/components", "./bench/components", "./firmware/sdkconfig",
        "./bench/sdkconfig")
STRAY = (".log", ".bak", ".tmp", ".old", ".orig", ".swp", ".rej")

empty, stray = [], []
for root, dirs, files in os.walk("."):
    if any(root.startswith(s) for s in SKIP):
        dirs[:] = []
        continue
    dirs[:] = [d for d in dirs if not os.path.join(root, d).startswith(SKIP)]
    for f in files:
        p = os.path.join(root, f)
        if any(p.startswith(s) for s in SKIP): continue
        if os.path.getsize(p) == 0:
            empty.append(p)
        if f.endswith(STRAY) or f.endswith("~"):
            stray.append(p)

for p in empty:
    print("  \033[1;31m\u2717\033[0m файл нулевого размера: %s" % p)
for p in stray:
    print("  \033[1;31m\u2717\033[0m посторонний файл: %s" % p)

# В корне проекта состав файлов известен наперёд. Всё прочее там — либо
# случайно сохранённый вывод команды, либо забытый черновик. Именно так в
# рабочее дерево однажды попал файл с выводом tree.
ROOT_OK = (".md", ".sh", ".ps1", ".mod", ".sum", ".gitignore")
ROOT_NAMES = ("LICENSE", "go.mod", "go.sum", ".gitignore")
unexpected = []
for f in sorted(os.listdir(".")):
    if os.path.isdir(f): continue
    if f in ROOT_NAMES: continue
    if any(f.endswith(e) for e in ROOT_OK): continue
    unexpected.append(f)
for f in unexpected:
    print("  \033[1;31m\u2717\033[0m в корне проекта посторонний файл: %s" % f)

if not empty and not stray and not unexpected:
    print("  \033[1;32m\u2713\033[0m пустых и посторонних файлов нет")
sys.exit(1 if (empty or stray or unexpected) else 0)
PYEOF

printf '\n\033[1;36m━━━ ИТОГ ━━━\033[0m\n'
if [ "$FAILED" = "0" ]; then
  ok "документация сходится с кодом"
  exit 0
else
  bad "найдены расхождения, см. выше"
  exit 1
fi
