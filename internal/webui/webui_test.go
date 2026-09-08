package webui

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Пакет отдаёт встроенную статику, и сломаться тут можно тремя способами:
// файл не попал в сборку, отдаётся с неверным типом, или страница ссылается
// на ресурс, которого нет. Каждый случай проверяется отдельно.

// Четыре файла интерфейса обязаны быть встроены в бинарник. Если один
// пропадёт из каталога static, go:embed молча соберётся без него, а дашборд
// откроется пустым — этот тест ловит пропажу раньше.
func TestEmbeddedFilesPresent(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "app.css", "favicon.svg"} {
		data, err := fs.ReadFile(FS(), name)
		if err != nil {
			t.Fatalf("файл %s не встроен: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("файл %s встроен пустым", name)
		}
	}
}

// Всё, на что ссылается index.html внутри страницы, должно существовать среди
// встроенных файлов. Иначе браузер получит 404 на скрипт или стили, и панель
// покажется, но работать не будет.
func TestIndexReferencesResolve(t *testing.T) {
	index, err := fs.ReadFile(FS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(string(index), -1)
	if len(refs) == 0 {
		t.Fatal("в index.html не найдено ни одной ссылки на ресурс")
	}
	for _, m := range refs {
		ref := m[1]
		if strings.HasPrefix(ref, "http") || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "data:") {
			continue
		}
		if _, err := fs.Stat(FS(), strings.TrimPrefix(ref, "/")); err != nil {
			t.Errorf("index.html ссылается на %q, а такого файла нет: %v", ref, err)
		}
	}
}

// Mount вешает файлы на роутер с корня: главная страница по «/», остальные по
// имени, каждый со своим типом содержимого. Проверяется через настоящий
// роутер chi, тот же, что в cmd/gatewayd.
func TestMountServesFilesWithTypes(t *testing.T) {
	r := chi.NewRouter()
	Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	cases := []struct {
		path, ctype, marker string
	}{
		{"/", "text/html", "<title>LACERT"},
		{"/index.html", "text/html", "<title>LACERT"},
		{"/app.js", "javascript", "METRIC_KEYS"},
		{"/app.css", "text/css", "{"},
		{"/favicon.svg", "image/svg+xml", "<svg"},
	}
	for _, c := range cases {
		resp, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: ожидался 200, получен %d", c.path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, c.ctype) {
			t.Errorf("%s: тип содержимого %q, ожидался с %q", c.path, ct, c.ctype)
		}
		if !strings.Contains(string(body), c.marker) {
			t.Errorf("%s: в ответе нет ожидаемого фрагмента %q", c.path, c.marker)
		}
	}
}

// Несуществующий путь должен давать 404, а не главную страницу и не листинг
// каталога — иначе опечатка в адресе выглядит как рабочая панель.
func TestMountUnknownPathIs404(t *testing.T) {
	r := chi.NewRouter()
	Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/нет-такого.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ожидался 404, получен %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "<title>LACERT") {
		t.Fatal("на несуществующий путь отдана главная страница")
	}
}

// Ключи метрик в app.js и карточки в index.html должны совпадать один в один:
// ключ без карточки — значение, которое некуда вывести, карточка без ключа —
// вечный прочерк. Эта пара уже расходилась однажды, потому проверяется здесь.
func TestMetricKeysMatchCards(t *testing.T) {
	js, _ := fs.ReadFile(FS(), "app.js")
	html, _ := fs.ReadFile(FS(), "index.html")

	block := regexp.MustCompile(`(?s)const METRIC_KEYS = \[(.*?)\];`).FindStringSubmatch(string(js))
	if block == nil {
		t.Fatal("в app.js не найден список METRIC_KEYS")
	}
	keys := regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(block[1], -1)
	cards := regexp.MustCompile(`id="m-([a-z_]+)"`).FindAllStringSubmatch(string(html), -1)

	keySet := map[string]bool{}
	for _, k := range keys {
		keySet[k[1]] = true
	}
	cardSet := map[string]bool{}
	for _, c := range cards {
		cardSet[c[1]] = true
	}
	for k := range keySet {
		if !cardSet[k] {
			t.Errorf("ключ %q есть в app.js, а карточки m-%s в index.html нет", k, k)
		}
	}
	for c := range cardSet {
		if !keySet[c] {
			t.Errorf("карточка m-%s есть в index.html, а ключа в app.js нет", c)
		}
	}
	if len(keySet) == 0 {
		t.Fatal("список ключей метрик пуст")
	}
}
