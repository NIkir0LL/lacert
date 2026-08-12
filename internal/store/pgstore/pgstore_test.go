package pgstore

import (
	"os"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/store"
)

func testDSN() string {
	if dsn := os.Getenv("LACERT_TEST_PG_DSN"); dsn != "" {
		return dsn
	}
	return "host=localhost user=postgres password=lacert dbname=lacert port=5432 sslmode=disable"
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(testDSN())
	if err != nil {
		t.Skipf("postgres unavailable, skipping pgstore tests: %v", err)
	}
	// Чистим таблицы перед каждым тестом, чтобы тесты были независимы.
	s.db.Exec("TRUNCATE TABLE session_events, devices, telemetry_readings, key_rotations")
	return s
}

func TestPGStore_RegisterGetRevoke(t *testing.T) {
	s := openTestStore(t)

	rec := &store.DeviceRecord{
		DeviceID:     "pg-device-001",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{1, 2, 3, 4},
		KEMPub:       []byte{5, 6, 7, 8},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := s.Register(rec); err != store.ErrDeviceExists {
		t.Fatalf("expected ErrDeviceExists on duplicate registration, got %v", err)
	}

	got, err := s.Get(rec.DeviceID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DeviceID != rec.DeviceID || got.SigAlgorithm != rec.SigAlgorithm {
		t.Fatalf("unexpected record: %+v", got)
	}

	if err := s.Revoke(rec.DeviceID, "test revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = s.Get(rec.DeviceID)
	if err != store.ErrDeviceRevoked {
		t.Fatalf("expected ErrDeviceRevoked, got %v", err)
	}

	if _, err := s.Get("does-not-exist"); err != store.ErrDeviceNotFound {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestPGStore_EventLog(t *testing.T) {
	s := openTestStore(t)

	rec := &store.DeviceRecord{
		DeviceID:     "pg-device-002",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{1},
		KEMPub:       []byte{2},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}

	for _, evt := range []string{"handshake", "rotation", "firmware_check"} {
		if err := s.LogEvent(rec.DeviceID, evt, "detail-"+evt); err != nil {
			t.Fatalf("log event %s: %v", evt, err)
		}
	}

	events, err := s.RecentEvents(rec.DeviceID, 2)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (limit applied), got %d", len(events))
	}
	// Самое свежее событие должно быть первым (ORDER BY created_at DESC).
	if events[0].EventType != "firmware_check" {
		t.Fatalf("expected most recent event first, got %s", events[0].EventType)
	}
}

func TestPGStore_List(t *testing.T) {
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		rec := &store.DeviceRecord{
			DeviceID:     "pg-list-device-" + string(rune('A'+i)),
			SigAlgorithm: crypto.SigECDSAP256,
			IdentityPub:  []byte{byte(i)},
			KEMPub:       []byte{byte(i)},
			FirmwareHash: make([]byte, crypto.FirmwareHashSize),
		}
		if err := s.Register(rec); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}

	all, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(all))
	}
}

func TestPGStore_TelemetryRecordAndQuery(t *testing.T) {
	s := openTestStore(t)

	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < 5; i++ {
		err := s.RecordTelemetry(store.TelemetryReading{
			DeviceID:   "pg-tel-device-1",
			RawPayload: "temperature=20;humidity=40",
			Parsed:     map[string]float64{"temperature": 20 + float64(i), "humidity": 40},
			ReceivedAt: base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("record telemetry %d: %v", i, err)
		}
	}
	if err := s.RecordTelemetry(store.TelemetryReading{DeviceID: "pg-tel-device-2", RawPayload: "x=1", ReceivedAt: base}); err != nil {
		t.Fatalf("record telemetry device-2: %v", err)
	}

	all, err := s.QueryTelemetry(store.TelemetryFilter{DeviceID: "pg-tel-device-1"})
	if err != nil {
		t.Fatalf("query telemetry: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 readings, got %d", len(all))
	}
	for i := 0; i < len(all)-1; i++ {
		if all[i].ReceivedAt.After(all[i+1].ReceivedAt) {
			t.Fatalf("readings not in chronological order at index %d", i)
		}
	}
	if all[0].Parsed["temperature"] != 20 {
		t.Fatalf("expected first reading temperature=20, got %v", all[0].Parsed)
	}
	if all[len(all)-1].Parsed["temperature"] != 24 {
		t.Fatalf("expected last reading temperature=24, got %v", all[len(all)-1].Parsed)
	}

	since := base.Add(3 * time.Minute)
	filtered, err := s.QueryTelemetry(store.TelemetryFilter{DeviceID: "pg-tel-device-1", Since: since})
	if err != nil {
		t.Fatalf("query telemetry filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 readings after %v, got %d", since, len(filtered))
	}

	limited, err := s.QueryTelemetry(store.TelemetryFilter{DeviceID: "pg-tel-device-1", Limit: 2})
	if err != nil {
		t.Fatalf("query telemetry limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected limit=2 to return 2 readings, got %d", len(limited))
	}

	latest, err := s.LatestTelemetry("pg-tel-device-1")
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if latest == nil || latest.Parsed["temperature"] != 24 {
		t.Fatalf("expected latest reading temperature=24, got %+v", latest)
	}

	if got, err := s.LatestTelemetry("ghost-device"); err != nil || got != nil {
		t.Fatalf("expected nil,nil for device with no telemetry, got %v, %v", got, err)
	}
}

func TestPGStore_RotationLog(t *testing.T) {
	s := openTestStore(t)

	must := func(err error) {
		if err != nil {
			t.Fatalf("log rotation: %v", err)
		}
	}
	must(s.LogRotation(store.RotationLogEntry{DeviceID: "pg-rot-device-1", Initiator: "device", Success: true, RotationCount: 1, NewKeyHex: "aabbcc"}))
	must(s.LogRotation(store.RotationLogEntry{DeviceID: "pg-rot-device-1", Initiator: "gateway", Success: false, ErrorText: "decapsulate failed", RotationCount: 2}))
	must(s.LogRotation(store.RotationLogEntry{DeviceID: "pg-rot-device-2", Initiator: "device", Success: true, RotationCount: 1}))

	history, err := s.RotationHistory("pg-rot-device-1", 0)
	if err != nil {
		t.Fatalf("rotation history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(history))
	}
	if history[0].Success {
		t.Fatalf("expected most recent (failed) rotation first, got %+v", history[0])
	}
	if history[1].NewKeyHex != "aabbcc" {
		t.Fatalf("expected NewKeyHex to round-trip, got %q", history[1].NewKeyHex)
	}

	all, err := s.RotationHistory("", 0)
	if err != nil {
		t.Fatalf("rotation history (all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries across all devices, got %d", len(all))
	}
}

func TestPGStore_Delete(t *testing.T) {
	s := openTestStore(t)

	rec := &store.DeviceRecord{
		DeviceID:     "pg-del-device-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{1},
		KEMPub:       []byte{2},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.LogEvent("pg-del-device-1", "registered", "test"); err != nil {
		t.Fatalf("log event: %v", err)
	}
	if err := s.RecordTelemetry(store.TelemetryReading{DeviceID: "pg-del-device-1", RawPayload: "x=1"}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
	if err := s.LogRotation(store.RotationLogEntry{DeviceID: "pg-del-device-1", Initiator: "device", Success: true}); err != nil {
		t.Fatalf("log rotation: %v", err)
	}

	keepRec := &store.DeviceRecord{
		DeviceID:     "pg-keep-device-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{9},
		KEMPub:       []byte{9},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(keepRec); err != nil {
		t.Fatalf("register keep device: %v", err)
	}
	if err := s.RecordTelemetry(store.TelemetryReading{DeviceID: "pg-keep-device-1", RawPayload: "y=1"}); err != nil {
		t.Fatalf("record telemetry keep device: %v", err)
	}

	if err := s.Delete("pg-del-device-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.Get("pg-del-device-1"); err != store.ErrDeviceNotFound {
		t.Fatalf("expected ErrDeviceNotFound after delete, got %v", err)
	}
	events, err := s.RecentEvents("pg-del-device-1", 0)
	if err != nil || len(events) != 0 {
		t.Fatalf("expected events to be cascade-deleted, got %v, err=%v", events, err)
	}
	tel, err := s.QueryTelemetry(store.TelemetryFilter{DeviceID: "pg-del-device-1"})
	if err != nil || len(tel) != 0 {
		t.Fatalf("expected telemetry to be cascade-deleted, got %v, err=%v", tel, err)
	}
	rot, err := s.RotationHistory("pg-del-device-1", 0)
	if err != nil || len(rot) != 0 {
		t.Fatalf("expected rotation history to be cascade-deleted, got %v, err=%v", rot, err)
	}

	// Контрольное устройство не задето.
	if _, err := s.Get("pg-keep-device-1"); err != nil {
		t.Fatalf("keep device should be unaffected: %v", err)
	}
	keepTel, err := s.QueryTelemetry(store.TelemetryFilter{DeviceID: "pg-keep-device-1"})
	if err != nil || len(keepTel) != 1 {
		t.Fatalf("keep device telemetry should be unaffected, got %v, err=%v", keepTel, err)
	}

	// Идемпотентность.
	if err := s.Delete("pg-del-device-1"); err != nil {
		t.Fatalf("delete of already-deleted device should be idempotent, got %v", err)
	}

	// После удаления регистрация под тем же DeviceID с НОВЫМИ ключами должна
	// проходить успешно — это и есть сценарий перезапуска эмулятора,
	// который мы чиним.
	newRec := &store.DeviceRecord{
		DeviceID:     "pg-del-device-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{111, 112, 113}, // другие ключи, как после рестарта эмулятора
		KEMPub:       []byte{114, 115, 116},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(newRec); err != nil {
		t.Fatalf("re-register after delete should succeed (this is the bug being fixed), got %v", err)
	}
}

// TestPGStore_EventsByType проверяет выборку событий по типу в БОЕВОМ
// хранилище (PostgreSQL). Этот метод питает вкладку «Проверки прошивки»
// в дашборде, а в бою работает именно pgstore, а не memstore.
func TestPGStore_EventsByType(t *testing.T) {
	s := openTestStore(t)

	for _, id := range []string{"pg-fw-a", "pg-fw-b"} {
		rec := &store.DeviceRecord{
			DeviceID:     id,
			SigAlgorithm: crypto.SigECDSAP256,
			IdentityPub:  []byte("pub"),
			KEMPub:       []byte("kem"),
			FirmwareHash: []byte("hash"),
		}
		if err := s.Register(rec); err != nil {
			t.Fatalf("Register(%s): %v", id, err)
		}
	}

	// разные типы событий у двух устройств
	mustLog := func(dev, typ, detail string) {
		t.Helper()
		if err := s.LogEvent(dev, typ, detail); err != nil {
			t.Fatalf("LogEvent(%s,%s): %v", dev, typ, err)
		}
	}
	mustLog("pg-fw-a", "handshake", "рукопожатие")
	mustLog("pg-fw-a", "firmware_check", "пройдена")
	mustLog("pg-fw-b", "firmware_check", "пройдена")
	mustLog("pg-fw-a", "firmware_check_rejected", "устаревший challenge")
	mustLog("pg-fw-b", "rotation", "ротация")

	types := []string{"firmware_check", "firmware_check_rejected"}

	// по всем устройствам — только проверки прошивки, посторонние типы не попадают
	all, err := s.EventsByType(types, "", 0)
	if err != nil {
		t.Fatalf("EventsByType: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ожидалось 3 события проверки прошивки, получено %d", len(all))
	}
	for _, e := range all {
		if e.EventType != "firmware_check" && e.EventType != "firmware_check_rejected" {
			t.Fatalf("посторонний тип в выборке: %s", e.EventType)
		}
	}

	// самое новое событие идёт первым (ORDER BY created_at DESC)
	if all[0].EventType != "firmware_check_rejected" {
		t.Fatalf("ожидалось самое новое событие первым, получено %s", all[0].EventType)
	}

	// фильтр по устройству
	onlyA, err := s.EventsByType(types, "pg-fw-a", 0)
	if err != nil {
		t.Fatalf("EventsByType(pg-fw-a): %v", err)
	}
	if len(onlyA) != 2 {
		t.Fatalf("для pg-fw-a ожидалось 2 события, получено %d", len(onlyA))
	}

	// лимит
	limited, err := s.EventsByType(types, "", 1)
	if err != nil {
		t.Fatalf("EventsByType(limit=1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("лимит не сработал: %d записей вместо 1", len(limited))
	}
}

// Reregister заменяет ключи, сохраняя историю и состояние отзыва.
//
// Реализация для PostgreSQL сложнее, чем для памяти: обновление идёт по
// перечню полей, а не сохранением записи целиком. Иначе GORM затёр бы
// состояние отзыва нулевыми значениями из переданной записи, и отозванное
// устройство молча вернулось бы в строй.
func TestPGStore_Reregister(t *testing.T) {
	s := openTestStore(t)

	rec := &store.DeviceRecord{
		DeviceID:     "pg-re-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte("старый ключ подписи"),
		KEMPub:       []byte("старый ключ обмена"),
		FirmwareHash: []byte("старый хеш"),
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("регистрация: %v", err)
	}
	if err := s.LogEvent("pg-re-1", "проверка", "событие до замены"); err != nil {
		t.Fatalf("запись события: %v", err)
	}
	before, err := s.Get("pg-re-1")
	if err != nil {
		t.Fatalf("получение: %v", err)
	}

	err = s.Reregister(&store.DeviceRecord{
		DeviceID:     "pg-re-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte("новый ключ подписи"),
		KEMPub:       []byte("новый ключ обмена"),
		FirmwareHash: []byte("новый хеш"),
	})
	if err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	after, err := s.Get("pg-re-1")
	if err != nil {
		t.Fatalf("получение после замены: %v", err)
	}
	if string(after.IdentityPub) != "новый ключ подписи" {
		t.Errorf("ключ подписи не сменился: %q", after.IdentityPub)
	}
	if string(after.KEMPub) != "новый ключ обмена" {
		t.Errorf("ключ обмена не сменился: %q", after.KEMPub)
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("дата первой регистрации должна сохраняться: было %v, стало %v",
			before.CreatedAt, after.CreatedAt)
	}

	events, err := s.RecentEvents("pg-re-1", 0)
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

// Состояние отзыва при замене ключей не должно затираться.
func TestPGStore_ReregisterKeepsRevocation(t *testing.T) {
	s := openTestStore(t)

	if err := s.Register(&store.DeviceRecord{
		DeviceID:     "pg-re-rev",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte("ключ"),
		KEMPub:       []byte("ключ"),
		FirmwareHash: []byte("хеш"),
	}); err != nil {
		t.Fatalf("регистрация: %v", err)
	}
	if err := s.Revoke("pg-re-rev", "подмена прошивки"); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	if err := s.Reregister(&store.DeviceRecord{
		DeviceID:     "pg-re-rev",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte("новый"),
		KEMPub:       []byte("новый"),
		FirmwareHash: []byte("новый"),
	}); err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	got, err := s.Get("pg-re-rev")
	if err != store.ErrDeviceRevoked {
		t.Fatalf("устройство должно остаться отозванным, получено: %v", err)
	}
	if !got.Revoked || got.RevokedReason != "подмена прошивки" {
		t.Errorf("причина отзыва должна сохраняться: revoked=%v reason=%q",
			got.Revoked, got.RevokedReason)
	}
}

// Перерегистрация неизвестного устройства — ошибка, а не скрытое создание.
func TestPGStore_ReregisterUnknownFails(t *testing.T) {
	s := openTestStore(t)
	err := s.Reregister(&store.DeviceRecord{
		DeviceID:    "pg-never-existed",
		IdentityPub: []byte("ключ"),
	})
	if err != store.ErrDeviceNotFound {
		t.Fatalf("ожидалась ошибка отсутствия устройства, получено: %v", err)
	}
}
