// Package store определяет абстракцию хранилища зарегистрированных
// устройств шлюза и журнала событий (логи сессий и история смены ключей —
// см. раздел работы про gorm/PostgreSQL). Есть две реализации интерфейса
// DeviceStore:
//
//   - MemStore (этот пакет) — потокобезопасная map в памяти процесса.
//     Используется в unit-тестах и как fallback, если PostgreSQL недоступен.
//   - pgstore.Store (internal/store/pgstore) — реализация поверх PostgreSQL
//     через gorm, для реального развёртывания шлюза.
//
// Шлюз (internal/gateway) работает с любой реализацией через интерфейс
// DeviceStore — это позволяет тестировать логику протокола без поднятия
// настоящей БД и при необходимости легко заменить хранилище.
package store

import (
	"errors"
	"time"

	"lacert/internal/crypto"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// DeviceRecord — запись об устройстве, как она появляется в реестре шлюза
// после успешной офлайн-регистрации.
type DeviceRecord struct {
	DeviceID      string
	SigAlgorithm  crypto.SigAlgorithm
	IdentityPub   []byte // efuse-привязанный публичный ключ подписи
	KEMPub        []byte // публичный ключ ML-KEM-1024 (сериализованный)
	FirmwareHash  []byte // эталонный SHA-256 хеш прошивки (32 байта), зафиксированный при регистрации
	Revoked       bool
	RevokedReason string
	CreatedAt     time.Time
}

// KEMPublicKey десериализует публичный ключ ML-KEM-1024 устройства.
func (d *DeviceRecord) KEMPublicKey() (*mlkem1024.PublicKey, error) {
	return crypto.UnpackKEMPublicKey(d.KEMPub)
}

// FirmwareHashArray конвертирует хранимый хеш прошивки в фиксированный
// массив байт, как того требуют функции пакета crypto.
func (d *DeviceRecord) FirmwareHashArray() ([crypto.FirmwareHashSize]byte, error) {
	var out [crypto.FirmwareHashSize]byte
	if len(d.FirmwareHash) != crypto.FirmwareHashSize {
		return out, errors.New("stored firmware hash has unexpected length")
	}
	copy(out[:], d.FirmwareHash)
	return out, nil
}

// SessionEvent — запись в журнале событий (рукопожатие, ротация, проверка
// прошивки, отзыв) — соответствует "логам сессий и истории смены ключей",
// упомянутым в работе как часть назначения таблиц PostgreSQL.
type SessionEvent struct {
	ID        uint      `json:"id"`
	DeviceID  string    `json:"device_id"`
	EventType string    `json:"event_type"` // "handshake" | "rotation" | "firmware_check" | "revoked" | "data"
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// TelemetryReading — один принятый и расшифрованный пакет данных от
// устройства. RawPayload хранится всегда (как пришло после расшифровки);
// Parsed — числовые поля, извлечённые из RawPayload (см. internal/telemetry),
// для построения графиков. Если payload не в формате "key=value;...", Parsed
// будет пустым, но RawPayload всё равно сохранится — потеря парсинга не
// должна означать потерю данных.
type TelemetryReading struct {
	ID         uint               `json:"id"`
	DeviceID   string             `json:"device_id"`
	RawPayload string             `json:"raw_payload"`
	Parsed     map[string]float64 `json:"parsed,omitempty"`
	ReceivedAt time.Time          `json:"received_at"`
}

// RotationLogEntry — запись о попытке ротации ключа (успешной или неудачной).
// OldKeyHex/NewKeyHex заполняются ПОЛНОСТЬЮ только если на шлюзе явно включён
// тестовый режим (LACERT_LOG_SESSION_KEYS=true, см. cmd/gatewayd) — иначе
// остаются пустыми. Хранить ключи сессий в БД по умолчанию выключено
// намеренно: это чувствительный материал, и даже в журнале он не должен
// накапливаться без явного запроса в тестовой среде.
type RotationLogEntry struct {
	ID            uint      `json:"id"`
	DeviceID      string    `json:"device_id"`
	Initiator     string    `json:"initiator"` // "device" | "gateway"
	Success       bool      `json:"success"`
	ErrorText     string    `json:"error_text,omitempty"`
	OldKeyHex     string    `json:"old_key_hex,omitempty"`
	NewKeyHex     string    `json:"new_key_hex,omitempty"`
	RotationCount int       `json:"rotation_count"`
	CreatedAt     time.Time `json:"created_at"`
}

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrDeviceExists   = errors.New("device already registered")
	ErrDeviceRevoked  = errors.New("device is revoked")
)

// TelemetryFilter — параметры запроса истории телеметрии.
type TelemetryFilter struct {
	DeviceID string // пусто — все устройства
	Since    time.Time
	Until    time.Time
	Limit    int // <=0 — использовать разумный дефолт реализации
}

// DeviceStore — абстракция реестра устройств и журнала событий, через
// которую шлюз (internal/gateway) работает с хранилищем, независимо от
// конкретной реализации (in-memory или PostgreSQL).
type DeviceStore interface {
	// Register добавляет устройство в реестр после офлайн-регистрации.
	Register(rec *DeviceRecord) error

	// Reregister заменяет ключи и эталонный хеш прошивки у уже
	// зарегистрированного устройства, сохраняя его историю: журнал событий,
	// накопленную телеметрию и дату первой регистрации.
	//
	// Нужен, когда устройство потеряло свои ключи — очистка памяти платы,
	// замена платы с сохранением идентификатора, перепрошивка с генерацией
	// новой пары. Без этого такое устройство остаётся в реестре навсегда
	// непригодным: зарегистрировать заново нельзя, а старый ключ у него уже
	// не тот.
	//
	// Возвращает ErrDeviceNotFound, если устройства в реестре нет.
	Reregister(rec *DeviceRecord) error
	// Get возвращает запись устройства. Если устройство отозвано, возвращает
	// саму запись (для аудита) вместе с ErrDeviceRevoked.
	Get(deviceID string) (*DeviceRecord, error)
	// Revoke отзывает доверие устройству.
	Revoke(deviceID, reason string) error
	// Delete полностью удаляет запись устройства (а не просто отзывает) и
	// связанные с ним данные (журнал событий, телеметрию, журнал ротаций).
	// Идемпотентна: удаление несуществующего устройства не ошибка. Не
	// предназначена для обычного администрирования реальных устройств
	// (для этого есть Revoke) — используется internal/emulator.ResetDevices
	// для очистки устаревших регистраций встроенных эмулированных устройств
	// при перезапуске шлюза с персистентным хранилищем (PostgreSQL):
	// эмулятор генерирует новые identity/KEM ключи при каждом старте
	// процесса, и без удаления старой записи под тем же DeviceID повторная
	// регистрация будет постоянно отклоняться как ErrDeviceExists.
	Delete(deviceID string) error
	// List возвращает копии всех записей реестра.
	List() ([]DeviceRecord, error)

	// LogEvent добавляет запись в журнал событий устройства.
	//
	// Журнал вспомогательный: он наполняет ленту событий на дашборде и не
	// участвует в работе протокола. Поэтому вызывающая сторона (internal/gateway)
	// намеренно игнорирует возвращаемую ошибку — сбой записи в журнал не должен
	// обрывать рукопожатие, ротацию ключа или проверку прошивки. Цена такого
	// решения: при недоступности хранилища события молча теряются, тогда как
	// сам протокол продолжает работать.
	LogEvent(deviceID, eventType, detail string) error
	// RecentEvents возвращает последние события устройства (limit <= 0 — без ограничения).
	RecentEvents(deviceID string, limit int) ([]SessionEvent, error)
	// EventsByType возвращает последние события заданных типов по всем устройствам
	// (или по одному, если deviceID непустой). Нужен для сводных панелей вроде
	// журнала проверок целостности прошивки. limit <= 0 — без ограничения.
	EventsByType(eventTypes []string, deviceID string, limit int) ([]SessionEvent, error)

	// RecordTelemetry сохраняет один принятый пакет данных устройства.
	RecordTelemetry(reading TelemetryReading) error
	// QueryTelemetry возвращает историю телеметрии по фильтру — для графиков
	// и таблицы истории на дашборде (см. internal/api).
	QueryTelemetry(filter TelemetryFilter) ([]TelemetryReading, error)
	// LatestTelemetry возвращает последний принятый пакет устройства, если он есть.
	LatestTelemetry(deviceID string) (*TelemetryReading, error)
	// LatestTelemetryAll возвращает последний пакет КАЖДОГО устройства одним
	// запросом. Нужен списку устройств в дашборде: он показывает свежие
	// показания всех устройств сразу, и вызов LatestTelemetry в цикле давал бы
	// по запросу к БД на каждое устройство (проблема N+1). Устройства без
	// телеметрии в карту не попадают.
	LatestTelemetryAll() (map[string]TelemetryReading, error)

	// LogRotation сохраняет запись о попытке ротации ключа (успешной или нет).
	LogRotation(entry RotationLogEntry) error
	// RotationHistory возвращает журнал ротаций. deviceID="" — для всех устройств.
	RotationHistory(deviceID string, limit int) ([]RotationLogEntry, error)
}
