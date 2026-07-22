// Package pgstore реализует store.DeviceStore поверх PostgreSQL через gorm —
// именно то хранилище, которое описано в работе ("gorm — библиотека для
// работы с базой данных PostgreSQL, где будут храниться записи о
// зарегистрированных устройствах, логи сессий и история смены ключей").
package pgstore

import (
	"encoding/json"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/store"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// deviceRow —gorm-модель таблицы devices. Отдельная от store.DeviceRecord
// структура, чтобы крипто-агностичный пакет store не зависел от
// специфичных для gorm тегов (изоляция слоя хранения, по аналогии с
// изоляцией криптографического модуля шлюза, описанной в работе).
type deviceRow struct {
	DeviceID      string `gorm:"primaryKey;column:device_id"`
	SigAlgorithm  int    `gorm:"column:sig_algorithm"`
	IdentityPub   []byte `gorm:"column:identity_pub"`
	KEMPub        []byte `gorm:"column:kem_pub"`
	FirmwareHash  []byte `gorm:"column:firmware_hash"`
	Revoked       bool   `gorm:"column:revoked"`
	RevokedReason string `gorm:"column:revoked_reason"`
	CreatedAt     time.Time
}

func (deviceRow) TableName() string { return "devices" }

func (r deviceRow) toRecord() store.DeviceRecord {
	return store.DeviceRecord{
		DeviceID:      r.DeviceID,
		SigAlgorithm:  crypto.SigAlgorithm(r.SigAlgorithm),
		IdentityPub:   r.IdentityPub,
		KEMPub:        r.KEMPub,
		FirmwareHash:  r.FirmwareHash,
		Revoked:       r.Revoked,
		RevokedReason: r.RevokedReason,
		CreatedAt:     r.CreatedAt,
	}
}

// eventRow — gorm-модель таблицы session_events (журнал рукопожатий,
// ротаций, проверок прошивки и отзывов).
type eventRow struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	DeviceID string `gorm:"column:device_id;index;index:idx_events_device_time,priority:1"`
	// event_type индексируется отдельно: вкладка «Проверки прошивки» выбирает
	// события по типу (firmware_check / firmware_check_rejected) сразу по всем
	// устройствам — без индекса это полный скан журнала.
	EventType string `gorm:"column:event_type;index"`
	Detail    string `gorm:"column:detail"`
	// Составной (device_id, created_at) — под запрос «последние события
	// устройства»; отдельный по created_at — под выборки по типу с сортировкой.
	CreatedAt time.Time `gorm:"index;index:idx_events_device_time,priority:2,sort:desc"`
}

func (eventRow) TableName() string { return "session_events" }

// telemetryRow — gorm-модель таблицы telemetry_readings: каждый принятый и
// расшифрованный пакет данных устройства. ParsedJSON хранит результат
// internal/telemetry.ParseKV как JSON-объект (а не нативный jsonb-тип
// средствами gorm) — так конвертация в/из store.TelemetryReading.Parsed
// остаётся простым encoding/json без дополнительных Scanner/Valuer обвязок.
type telemetryRow struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	DeviceID   string `gorm:"column:device_id;index;index:idx_telemetry_device_time,priority:1"`
	RawPayload string `gorm:"column:raw_payload"`
	ParsedJSON []byte `gorm:"column:parsed_json;type:jsonb"`
	// Составной индекс (device_id, received_at) — под основной запрос дашборда:
	// «последние N показаний устройства». С раздельными индексами PostgreSQL
	// вынужден отбирать все записи устройства и сортировать их (top-N heapsort);
	// с составным — сразу читает нужные строки в правильном порядке. На 300 тыс.
	// записей это 0,25 мс вместо 1,0 мс, и разрыв растёт с объёмом истории.
	ReceivedAt time.Time `gorm:"index;index:idx_telemetry_device_time,priority:2,sort:desc"`
}

func (telemetryRow) TableName() string { return "telemetry_readings" }

func telemetryRowFrom(r store.TelemetryReading) (telemetryRow, error) {
	var parsedJSON []byte
	if len(r.Parsed) > 0 {
		b, err := json.Marshal(r.Parsed)
		if err != nil {
			return telemetryRow{}, err
		}
		parsedJSON = b
	}
	return telemetryRow{
		DeviceID:   r.DeviceID,
		RawPayload: r.RawPayload,
		ParsedJSON: parsedJSON,
		ReceivedAt: r.ReceivedAt,
	}, nil
}

func (row telemetryRow) toRecord() (store.TelemetryReading, error) {
	out := store.TelemetryReading{
		ID:         row.ID,
		DeviceID:   row.DeviceID,
		RawPayload: row.RawPayload,
		ReceivedAt: row.ReceivedAt,
	}
	if len(row.ParsedJSON) > 0 {
		if err := json.Unmarshal(row.ParsedJSON, &out.Parsed); err != nil {
			return store.TelemetryReading{}, err
		}
	}
	return out, nil
}

// rotationRow — gorm-модель таблицы key_rotations (журнал попыток ротации
// ключа, успешных и неудачных). См. комментарий к store.RotationLogEntry
// насчёт того, когда OldKeyHex/NewKeyHex реально заполняются.
type rotationRow struct {
	ID            uint      `gorm:"primaryKey;autoIncrement"`
	DeviceID      string    `gorm:"column:device_id;index;index:idx_rotations_device_time,priority:1"`
	Initiator     string    `gorm:"column:initiator"`
	Success       bool      `gorm:"column:success"`
	ErrorText     string    `gorm:"column:error_text"`
	OldKeyHex     string    `gorm:"column:old_key_hex"`
	NewKeyHex     string    `gorm:"column:new_key_hex"`
	RotationCount int       `gorm:"column:rotation_count"`
	CreatedAt     time.Time `gorm:"index;index:idx_rotations_device_time,priority:2,sort:desc"`
}

func (rotationRow) TableName() string { return "key_rotations" }

func rotationRowFrom(e store.RotationLogEntry) rotationRow {
	return rotationRow{
		DeviceID:      e.DeviceID,
		Initiator:     e.Initiator,
		Success:       e.Success,
		ErrorText:     e.ErrorText,
		OldKeyHex:     e.OldKeyHex,
		NewKeyHex:     e.NewKeyHex,
		RotationCount: e.RotationCount,
	}
}

func (row rotationRow) toRecord() store.RotationLogEntry {
	return store.RotationLogEntry{
		ID:            row.ID,
		DeviceID:      row.DeviceID,
		Initiator:     row.Initiator,
		Success:       row.Success,
		ErrorText:     row.ErrorText,
		OldKeyHex:     row.OldKeyHex,
		NewKeyHex:     row.NewKeyHex,
		RotationCount: row.RotationCount,
		CreatedAt:     row.CreatedAt,
	}
}

// Store — реализация store.DeviceStore поверх PostgreSQL.
type Store struct {
	db *gorm.DB
}

// Open подключается к PostgreSQL по DSN (например,
// "host=localhost user=postgres password=lacert dbname=lacert port=5432 sslmode=disable")
// и выполняет автомиграцию таблиц devices и session_events.
func Open(dsn string) (*Store, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	// Пул соединений. Без явной настройки database/sql не ограничивает число
	// открытых соединений, и под нагрузкой шлюз открывает их столько, сколько
	// одновременных запросов к нему пришло. PostgreSQL по умолчанию принимает не
	// больше 100 клиентов и начинает отвечать «sorry, too many clients already»
	// (SQLSTATE 53300) — а для шлюза это выглядит как отказ в рукопожатии
	// устройствам. Проверено нагрузочным тестом: при тысяче устройств,
	// подключающихся одновременно, соединения кончались и часть плат не могла
	// установить сессию.
	//
	// Ограничиваем пул: лишние запросы теперь ждут свободного соединения в
	// очереди (это доли миллисекунды), а не падают с ошибкой.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(25)                  // с запасом под лимит PostgreSQL
	sqlDB.SetMaxIdleConns(10)                  // держим тёплые соединения
	sqlDB.SetConnMaxLifetime(30 * time.Minute) // переоткрываем, чтобы не копить мусор
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	if err := db.AutoMigrate(&deviceRow{}, &eventRow{}, &telemetryRow{}, &rotationRow{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Register(rec *store.DeviceRecord) error {
	row := deviceRow{
		DeviceID:     rec.DeviceID,
		SigAlgorithm: int(rec.SigAlgorithm),
		IdentityPub:  rec.IdentityPub,
		KEMPub:       rec.KEMPub,
		FirmwareHash: rec.FirmwareHash,
	}
	var existing deviceRow
	if err := s.db.Where("device_id = ?", rec.DeviceID).First(&existing).Error; err == nil {
		return store.ErrDeviceExists
	}
	return s.db.Create(&row).Error
}

func (s *Store) Get(deviceID string) (*store.DeviceRecord, error) {
	var row deviceRow
	if err := s.db.Where("device_id = ?", deviceID).First(&row).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, store.ErrDeviceNotFound
		}
		return nil, err
	}
	rec := row.toRecord()
	if rec.Revoked {
		return &rec, store.ErrDeviceRevoked
	}
	return &rec, nil
}

func (s *Store) Revoke(deviceID, reason string) error {
	res := s.db.Model(&deviceRow{}).Where("device_id = ?", deviceID).
		Updates(map[string]any{"revoked": true, "revoked_reason": reason})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return store.ErrDeviceNotFound
	}
	return nil
}

// Delete удаляет запись устройства и все связанные с ним строки (журнал
// событий, телеметрию, журнал ротаций) одной транзакцией. Идемпотентна.
// См. комментарий к store.DeviceStore.Delete о назначении.
func (s *Store) Delete(deviceID string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("device_id = ?", deviceID).Delete(&deviceRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("device_id = ?", deviceID).Delete(&eventRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("device_id = ?", deviceID).Delete(&telemetryRow{}).Error; err != nil {
			return err
		}
		if err := tx.Where("device_id = ?", deviceID).Delete(&rotationRow{}).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) List() ([]store.DeviceRecord, error) {
	var rows []deviceRow
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]store.DeviceRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toRecord())
	}
	return out, nil
}

func (s *Store) LogEvent(deviceID, eventType, detail string) error {
	return s.db.Create(&eventRow{DeviceID: deviceID, EventType: eventType, Detail: detail}).Error
}

// EventsByType — выборка событий заданных типов (по всем устройствам либо по
// одному). Используется сводной панелью проверок целостности прошивки.
func (s *Store) EventsByType(eventTypes []string, deviceID string, limit int) ([]store.SessionEvent, error) {
	q := s.db.Model(&eventRow{}).Order("created_at DESC")
	if len(eventTypes) > 0 {
		q = q.Where("event_type IN ?", eventTypes)
	}
	if deviceID != "" {
		q = q.Where("device_id = ?", deviceID)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []eventRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]store.SessionEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.SessionEvent{
			ID:        r.ID,
			DeviceID:  r.DeviceID,
			EventType: r.EventType,
			Detail:    r.Detail,
			CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (s *Store) RecentEvents(deviceID string, limit int) ([]store.SessionEvent, error) {
	q := s.db.Where("device_id = ?", deviceID).Order("created_at DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []eventRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]store.SessionEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.SessionEvent{
			ID:        r.ID,
			DeviceID:  r.DeviceID,
			EventType: r.EventType,
			Detail:    r.Detail,
			CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

var _ store.DeviceStore = (*Store)(nil)

func (s *Store) RecordTelemetry(reading store.TelemetryReading) error {
	row, err := telemetryRowFrom(reading)
	if err != nil {
		return err
	}
	if row.ReceivedAt.IsZero() {
		row.ReceivedAt = time.Now().UTC()
	}
	return s.db.Create(&row).Error
}

func (s *Store) QueryTelemetry(filter store.TelemetryFilter) ([]store.TelemetryReading, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50000
	}

	q := s.db.Model(&telemetryRow{}).Order("received_at DESC").Limit(limit)
	if filter.DeviceID != "" {
		q = q.Where("device_id = ?", filter.DeviceID)
	}
	// Сравнения по времени приводим к UTC явно, чтобы фильтр не зависел от
	// часового пояса сервера: телеметрия сохраняется в UTC, поэтому и границы
	// диапазона сравниваем в UTC (иначе на сервере с ненулевым смещением TZ
	// выборка «за последние 30 минут» отсекала бы почти все свежие данные).
	if !filter.Since.IsZero() {
		q = q.Where("received_at >= ?", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		q = q.Where("received_at <= ?", filter.Until.UTC())
	}

	var rows []telemetryRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]store.TelemetryReading, len(rows))
	for i, row := range rows {
		rec, err := row.toRecord()
		if err != nil {
			return nil, err
		}
		out[i] = rec
	}
	// rows пришли DESC (новые -> старые); разворачиваем в хронологический
	// порядок — так удобнее строить графики на фронтенде.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// LatestTelemetryAll — последнее показание каждого устройства ОДНИМ запросом.
//
// Раньше список устройств в дашборде вызывал LatestTelemetry в цикле: при 500
// устройствах это 500 отдельных SQL-запросов на каждое открытие страницы
// (проблема N+1), и ответ занимал сотни миллисекунд. DISTINCT ON — специфичная
// для PostgreSQL конструкция, которая берёт по одной строке на каждое значение
// device_id; вместе с составным индексом (device_id, received_at DESC) она
// читает ровно нужные строки без сортировки всей таблицы.
func (s *Store) LatestTelemetryAll() (map[string]store.TelemetryReading, error) {
	var rows []telemetryRow
	err := s.db.Raw(`
		SELECT DISTINCT ON (device_id) *
		FROM telemetry_readings
		ORDER BY device_id, received_at DESC
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]store.TelemetryReading, len(rows))
	for _, r := range rows {
		reading, err := r.toRecord()
		if err != nil {
			return nil, err
		}
		out[r.DeviceID] = reading
	}
	return out, nil
}

func (s *Store) LatestTelemetry(deviceID string) (*store.TelemetryReading, error) {
	var row telemetryRow
	err := s.db.Where("device_id = ?", deviceID).Order("received_at DESC").Limit(1).Find(&row).Error
	if err != nil {
		return nil, err
	}
	if row.ID == 0 {
		return nil, nil // нет ни одного пакета от устройства
	}
	rec, err := row.toRecord()
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) LogRotation(entry store.RotationLogEntry) error {
	row := rotationRowFrom(entry)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	return s.db.Create(&row).Error
}

func (s *Store) RotationHistory(deviceID string, limit int) ([]store.RotationLogEntry, error) {
	q := s.db.Model(&rotationRow{}).Order("created_at DESC")
	if deviceID != "" {
		q = q.Where("device_id = ?", deviceID)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []rotationRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]store.RotationLogEntry, len(rows))
	for i, row := range rows {
		out[i] = row.toRecord()
	}
	return out, nil
}
