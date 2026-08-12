package store

import (
	"fmt"
	"testing"
	"time"
)

func TestMemStore_TelemetryRecordAndQuery(t *testing.T) {
	s := New()

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		err := s.RecordTelemetry(TelemetryReading{
			DeviceID:   "dev-1",
			RawPayload: "temperature=20;humidity=40",
			Parsed:     map[string]float64{"temperature": 20 + float64(i), "humidity": 40},
			ReceivedAt: base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("record telemetry %d: %v", i, err)
		}
	}
	// Запись для другого устройства — не должна попадать в фильтр по dev-1.
	if err := s.RecordTelemetry(TelemetryReading{DeviceID: "dev-2", RawPayload: "x=1", ReceivedAt: base}); err != nil {
		t.Fatalf("record telemetry dev-2: %v", err)
	}

	all, err := s.QueryTelemetry(TelemetryFilter{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("query telemetry: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 readings for dev-1, got %d", len(all))
	}
	// Должны быть в хронологическом порядке (старые -> новые).
	for i := 0; i < len(all)-1; i++ {
		if all[i].ReceivedAt.After(all[i+1].ReceivedAt) {
			t.Fatalf("readings not in chronological order at index %d", i)
		}
	}
	if all[0].Parsed["temperature"] != 20 {
		t.Fatalf("expected first reading temperature=20, got %v", all[0].Parsed["temperature"])
	}

	// Фильтр по времени: только последние 2 минуты диапазона.
	since := base.Add(3 * time.Minute)
	filtered, err := s.QueryTelemetry(TelemetryFilter{DeviceID: "dev-1", Since: since})
	if err != nil {
		t.Fatalf("query telemetry filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 readings after %v, got %d", since, len(filtered))
	}

	limited, err := s.QueryTelemetry(TelemetryFilter{DeviceID: "dev-1", Limit: 2})
	if err != nil {
		t.Fatalf("query telemetry limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected limit=2 to return 2 readings, got %d", len(limited))
	}
	// limit должен оставлять самые НОВЫЕ записи (а не самые старые).
	if limited[len(limited)-1].Parsed["temperature"] != 24 {
		t.Fatalf("expected most recent reading to be the last of the limited set, got %v", limited[len(limited)-1].Parsed)
	}
}

func TestMemStore_LatestTelemetry(t *testing.T) {
	s := New()

	if got, err := s.LatestTelemetry("ghost"); err != nil || got != nil {
		t.Fatalf("expected nil,nil for device with no telemetry, got %v, %v", got, err)
	}

	must := func(err error) {
		if err != nil {
			t.Fatalf("record telemetry: %v", err)
		}
	}
	must(s.RecordTelemetry(TelemetryReading{DeviceID: "dev-1", RawPayload: "seq=1", ReceivedAt: time.Now().Add(-time.Minute)}))
	must(s.RecordTelemetry(TelemetryReading{DeviceID: "dev-1", RawPayload: "seq=2", ReceivedAt: time.Now()}))

	latest, err := s.LatestTelemetry("dev-1")
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if latest == nil || latest.RawPayload != "seq=2" {
		t.Fatalf("expected latest reading to be seq=2, got %+v", latest)
	}
}

func TestMemStore_Delete(t *testing.T) {
	s := New()

	rec := &DeviceRecord{DeviceID: "dev-del-1", IdentityPub: []byte{1}, KEMPub: []byte{2}, FirmwareHash: make([]byte, 32)}
	if err := s.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.LogEvent("dev-del-1", "registered", "test"); err != nil {
		t.Fatalf("log event: %v", err)
	}
	if err := s.RecordTelemetry(TelemetryReading{DeviceID: "dev-del-1", RawPayload: "x=1"}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.LogRotation(RotationLogEntry{DeviceID: "dev-del-1", Initiator: "device", Success: true}); err != nil {
		t.Fatalf("log rotation: %v", err)
	}
	// Контрольное устройство, которое НЕ должно пострадать от удаления dev-del-1.
	if err := s.Register(&DeviceRecord{DeviceID: "dev-keep", IdentityPub: []byte{9}, KEMPub: []byte{9}, FirmwareHash: make([]byte, 32)}); err != nil {
		t.Fatalf("register dev-keep: %v", err)
	}
	if err := s.RecordTelemetry(TelemetryReading{DeviceID: "dev-keep", RawPayload: "y=1"}); err != nil {
		t.Fatalf("record telemetry dev-keep: %v", err)
	}

	if err := s.Delete("dev-del-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.Get("dev-del-1"); err != ErrDeviceNotFound {
		t.Fatalf("expected ErrDeviceNotFound after delete, got %v", err)
	}
	events, err := s.RecentEvents("dev-del-1", 0)
	if err != nil || len(events) != 0 {
		t.Fatalf("expected events to be cascade-deleted, got %v, err=%v", events, err)
	}
	tel, err := s.QueryTelemetry(TelemetryFilter{DeviceID: "dev-del-1"})
	if err != nil || len(tel) != 0 {
		t.Fatalf("expected telemetry to be cascade-deleted, got %v, err=%v", tel, err)
	}
	rot, err := s.RotationHistory("dev-del-1", 0)
	if err != nil || len(rot) != 0 {
		t.Fatalf("expected rotation history to be cascade-deleted, got %v, err=%v", rot, err)
	}

	// Контрольное устройство не задето.
	if _, err := s.Get("dev-keep"); err != nil {
		t.Fatalf("dev-keep should be unaffected by deleting dev-del-1: %v", err)
	}
	keepTel, err := s.QueryTelemetry(TelemetryFilter{DeviceID: "dev-keep"})
	if err != nil || len(keepTel) != 1 {
		t.Fatalf("dev-keep telemetry should be unaffected, got %v, err=%v", keepTel, err)
	}

	// Идемпотентность: повторное удаление несуществующего устройства не ошибка.
	if err := s.Delete("dev-del-1"); err != nil {
		t.Fatalf("delete of already-deleted device should be idempotent, got %v", err)
	}
	if err := s.Delete("never-existed"); err != nil {
		t.Fatalf("delete of never-registered device should be idempotent, got %v", err)
	}
}

func TestMemStore_RotationLog(t *testing.T) {
	s := New()

	must := func(err error) {
		if err != nil {
			t.Fatalf("log rotation: %v", err)
		}
	}
	must(s.LogRotation(RotationLogEntry{DeviceID: "dev-1", Initiator: "device", Success: true, RotationCount: 1}))
	must(s.LogRotation(RotationLogEntry{DeviceID: "dev-1", Initiator: "gateway", Success: false, ErrorText: "decapsulate failed", RotationCount: 2}))
	must(s.LogRotation(RotationLogEntry{DeviceID: "dev-2", Initiator: "device", Success: true, RotationCount: 1}))

	history, err := s.RotationHistory("dev-1", 0)
	if err != nil {
		t.Fatalf("rotation history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 rotation entries for dev-1, got %d", len(history))
	}
	// Самая свежая запись должна быть первой.
	if history[0].RotationCount != 2 || history[0].Success {
		t.Fatalf("expected most recent (failed) rotation first, got %+v", history[0])
	}

	all, err := s.RotationHistory("", 0)
	if err != nil {
		t.Fatalf("rotation history (all devices): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rotation entries across all devices, got %d", len(all))
	}

	limited, err := s.RotationHistory("", 1)
	if err != nil {
		t.Fatalf("rotation history limited: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected limit=1 to return 1 entry, got %d", len(limited))
	}
}

// TestEventsByType проверяет выборку событий по типу — она питает сводную
// панель проверок целостности прошивки в дашборде.
func TestEventsByType(t *testing.T) {
	s := New()
	// два устройства, разные типы событий
	_ = s.LogEvent("dev-a", "handshake", "рукопожатие")
	_ = s.LogEvent("dev-a", "firmware_check", "пройдена")
	_ = s.LogEvent("dev-b", "firmware_check", "пройдена")
	_ = s.LogEvent("dev-a", "firmware_check_rejected", "устаревший challenge")
	_ = s.LogEvent("dev-b", "rotation", "ротация")

	types := []string{"firmware_check", "firmware_check_rejected"}

	// по всем устройствам: должно быть ровно 3 события проверки прошивки
	all, err := s.EventsByType(types, "", 0)
	if err != nil {
		t.Fatalf("EventsByType: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ожидалось 3 события проверки прошивки, получено %d", len(all))
	}
	for _, e := range all {
		if e.EventType != "firmware_check" && e.EventType != "firmware_check_rejected" {
			t.Fatalf("в выборку попал посторонний тип: %s", e.EventType)
		}
	}

	// новые события идут первыми
	if all[0].EventType != "firmware_check_rejected" {
		t.Fatalf("ожидалось, что первым будет самое новое событие, получено: %s", all[0].EventType)
	}

	// фильтр по устройству
	onlyA, err := s.EventsByType(types, "dev-a", 0)
	if err != nil {
		t.Fatalf("EventsByType(dev-a): %v", err)
	}
	if len(onlyA) != 2 {
		t.Fatalf("для dev-a ожидалось 2 события, получено %d", len(onlyA))
	}
	for _, e := range onlyA {
		if e.DeviceID != "dev-a" {
			t.Fatalf("в выборку по dev-a попало устройство %s", e.DeviceID)
		}
	}

	// лимит
	limited, err := s.EventsByType(types, "", 1)
	if err != nil {
		t.Fatalf("EventsByType(limit=1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("лимит не сработал: получено %d записей вместо 1", len(limited))
	}
}

// TestMemStoreTrimming проверяет, что журналы в памяти не растут бесконечно.
// Без ограничения шлюз, запущенный без PostgreSQL, за неделю съедал бы сотни
// мегабайт и падал по нехватке памяти.
func TestMemStoreTrimming(t *testing.T) {
	s := New()
	rec := &DeviceRecord{DeviceID: "trim-dev", IdentityPub: []byte("p"), KEMPub: []byte("k")}
	if err := s.Register(rec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Пишем заведомо больше лимита.
	over := maxTelemetryInMemory + 6000 // больше лимита И больше запаса (slack)
	for i := 0; i < over; i++ {
		if err := s.RecordTelemetry(TelemetryReading{
			DeviceID:   "trim-dev",
			RawPayload: fmt.Sprintf("seq=%d", i),
			ReceivedAt: time.Now(),
		}); err != nil {
			t.Fatalf("RecordTelemetry(%d): %v", i, err)
		}
	}

	s.mu.RLock()
	got := len(s.telemetry)
	oldest := s.telemetry[0].RawPayload
	newest := s.telemetry[len(s.telemetry)-1].RawPayload
	s.mu.RUnlock()

	// Обрезка идёт пачками, поэтому длина колеблется в пределах [max, max+slack].
	// Главное — что она ОГРАНИЧЕНА и не растёт линейно с числом записей.
	if got > maxTelemetryInMemory+8192 {
		t.Fatalf("телеметрия не обрезана: %d записей (лимит %d)", got, maxTelemetryInMemory)
	}
	if got >= over {
		t.Fatalf("вытеснения не произошло: хранится %d из %d записей", got, over)
	}
	// Старые вытеснены, свежие на месте.
	if oldest == "seq=0" {
		t.Fatal("самая старая запись не вытеснена")
	}
	if newest != fmt.Sprintf("seq=%d", over-1) {
		t.Fatalf("последняя запись потеряна: %q", newest)
	}

	// Свежие данные по-прежнему доступны через обычный запрос.
	latest, err := s.LatestTelemetry("trim-dev")
	if err != nil {
		t.Fatalf("LatestTelemetry: %v", err)
	}
	if latest == nil || latest.RawPayload != fmt.Sprintf("seq=%d", over-1) {
		t.Fatalf("LatestTelemetry вернул не последнюю запись: %+v", latest)
	}
}

// Reregister заменяет ключи, сохраняя историю и дату первой регистрации.
func TestMemStore_ReregisterKeepsHistory(t *testing.T) {
	s := New()
	original := time.Now().Add(-24 * time.Hour)
	rec := &DeviceRecord{
		DeviceID:     "dev-re",
		IdentityPub:  []byte("старый ключ подписи"),
		KEMPub:       []byte("старый ключ обмена"),
		FirmwareHash: []byte("старый хеш"),
		CreatedAt:    original,
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("регистрация: %v", err)
	}
	if err := s.LogEvent("dev-re", "проверка", "событие до замены"); err != nil {
		t.Fatalf("запись события: %v", err)
	}

	err := s.Reregister(&DeviceRecord{
		DeviceID:     "dev-re",
		IdentityPub:  []byte("новый ключ подписи"),
		KEMPub:       []byte("новый ключ обмена"),
		FirmwareHash: []byte("новый хеш"),
	})
	if err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	got, err := s.Get("dev-re")
	if err != nil {
		t.Fatalf("получение: %v", err)
	}
	if string(got.IdentityPub) != "новый ключ подписи" {
		t.Errorf("ключ подписи не сменился: %q", got.IdentityPub)
	}
	if string(got.KEMPub) != "новый ключ обмена" {
		t.Errorf("ключ обмена не сменился: %q", got.KEMPub)
	}
	if !got.CreatedAt.Equal(original) {
		t.Errorf("дата первой регистрации должна сохраняться: было %v, стало %v", original, got.CreatedAt)
	}

	events, err := s.RecentEvents("dev-re", 0)
	if err != nil {
		t.Fatalf("чтение журнала: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Detail == "событие до замены" {
			found = true
		}
	}
	if !found {
		t.Error("журнал событий должен сохраняться при замене ключей")
	}
}

// Состояние отзыва при замене ключей переносится: иначе отозванное за
// неудачную проверку прошивки устройство молча вернулось бы в строй.
func TestMemStore_ReregisterKeepsRevocation(t *testing.T) {
	s := New()
	if err := s.Register(&DeviceRecord{DeviceID: "dev-rev", IdentityPub: []byte("к")}); err != nil {
		t.Fatalf("регистрация: %v", err)
	}
	if err := s.Revoke("dev-rev", "подмена прошивки"); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	if err := s.Reregister(&DeviceRecord{DeviceID: "dev-rev", IdentityPub: []byte("новый")}); err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	// Get отдаёт запись отозванного устройства вместе с ошибкой.
	got, err := s.Get("dev-rev")
	if !errorsIsRevoked(err) {
		t.Fatalf("устройство должно остаться отозванным, получено: %v", err)
	}
	if !got.Revoked || got.RevokedReason != "подмена прошивки" {
		t.Errorf("причина отзыва должна сохраняться: %+v", got)
	}
}

// Перерегистрация неизвестного устройства — ошибка, а не скрытое создание.
func TestMemStore_ReregisterUnknownFails(t *testing.T) {
	s := New()
	err := s.Reregister(&DeviceRecord{DeviceID: "нет такого", IdentityPub: []byte("к")})
	if err != ErrDeviceNotFound {
		t.Fatalf("ожидалась ошибка отсутствия устройства, получено: %v", err)
	}
}

func errorsIsRevoked(err error) bool { return err == ErrDeviceRevoked }
