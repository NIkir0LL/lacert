module lacert

// Нижняя граница версии набора инструментов, а не «версия, которой собираем».
// Здесь она намеренно низкая: код не использует ничего, появившегося после
// 1.22, а самая требовательная зависимость (cloudflare/circl) объявляет ровно
// 1.22.0. Подъём границы отсёк бы сборку на более старых наборах, ничего не
// дав взамен: набор новее собирает этот код и так.
//
// Проверено опытом: с границей 1.26 набор 1.22 пытается скачать недостающую
// версию и падает с «toolchain not available».
go 1.22.2

require (
	github.com/cloudflare/circl v1.6.3
	github.com/eclipse/paho.mqtt.golang v1.4.3
	github.com/go-chi/chi/v5 v5.1.0
	github.com/go-chi/cors v1.2.2
	github.com/mochi-mqtt/server/v2 v2.7.9
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.31.0
	gorm.io/driver/postgres v0.0.0-00010101000000-000000000000
	gorm.io/gorm v1.25.10
)

require (
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/rs/xid v1.4.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/crypto => github.com/golang/crypto v0.31.0

replace golang.org/x/sys => github.com/golang/sys v0.28.0

replace gorm.io/gorm => github.com/go-gorm/gorm v1.25.12

replace gorm.io/driver/postgres => github.com/go-gorm/postgres v1.5.9

replace go.uber.org/zap => github.com/uber-go/zap v1.27.0

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml v3.0.1+incompatible

replace golang.org/x/text => github.com/golang/text v0.21.0

replace golang.org/x/sync => github.com/golang/sync v0.10.0

replace go.uber.org/multierr => github.com/uber-go/multierr v1.11.0

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20180628173108-788fd7840127

replace golang.org/x/net => github.com/golang/net v0.33.0
