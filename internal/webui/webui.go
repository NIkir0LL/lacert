// Package webui встраивает веб-страницу администрирования (регистрация
// устройств, список/статус, журнал событий) прямо в бинарник cmd/gatewayd
// через go:embed — отдельно собирать или раздавать фронтенд не нужно: один
// процесс, один порт, REST API и веб-страница на одном HTTP-сервере.
//
// Сознательно без сборочного шага (никакого npm/webpack/vite): чистые
// HTML/CSS/JS, без внешних зависимостей и без обращений к CDN — проект по
// постановке задачи предназначен для изолированных корпоративных сетей без
// доступа в интернет, и было бы странно сделать админ-панель, которая не
// загрузится без Google Fonts.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var embedded embed.FS

// FS — встроенные файлы веб-интерфейса (поддерево "static" из embed.FS).
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		// Не должно произойти: "static" всегда присутствует в сборке.
		panic(err)
	}
	return sub
}

// Mount регистрирует веб-интерфейс на роутере по указанному префиксу
// ("" или "/" — обслуживать с корня). REST-эндпоинты (/api/v1/..., /healthz)
// регистрируются отдельно и не конфликтуют со статикой.
func Mount(mux interface {
	Handle(pattern string, h http.Handler)
}) {
	fileServer := http.FileServer(http.FS(FS()))
	mux.Handle("/*", fileServer)
}
