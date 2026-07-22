// Package telemetry разбирает полезную нагрузку, расшифрованную шлюзом из
// пакетов данных устройства (см. internal/gateway.HandleData), в числовые
// поля — для построения графиков на дашборде.
//
// Формат payload — простой "key=value;key2=value2" (именно его шлёт
// internal/emulator и, по аналогии, будет слать прошивка ESP32: компактнее
// JSON, не требует библиотеки сериализации на embedded-устройстве с
// ограниченной Flash-памятью — то же соображение, что и в protocol-уровне
// internal/wire). Поля, которые не удаётся разобрать как число (например,
// строковые статусы), просто не попадают в числовую карту — RawPayload
// сохраняется целиком в любом случае, так что данные не теряются.
package telemetry

import (
	"strconv"
	"strings"
)

// ParseKV разбирает payload вида "temperature=23.5;humidity=41;seq=3" в
// map числовых значений. Нечисловые и пустые поля пропускаются молча —
// это нормальная ситуация (например, поле "status=ok"), а не ошибка.
func ParseKV(payload string) map[string]float64 {
	out := make(map[string]float64)
	for _, field := range strings.Split(payload, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		out[key] = f
	}
	return out
}
