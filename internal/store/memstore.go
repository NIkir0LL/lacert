package store

import (
	"sync"
	"time"
)

// MemStore — потокобезопасная реализация DeviceStore в памяти процесса.
type MemStore struct {
	mu        sync.RWMutex
	devices   map[string]*DeviceRecord
	events    []SessionEvent
	telemetry []TelemetryReading
	rotations []RotationLogEntry
	nextID    uint
	nextTelID uint
	nextRotID uint
}

// New создаёт пустой in-memory реестр устройств.
// Ограничения на размер журналов в памяти. MemStore используется, когда не
// задан LACERT_PG_DSN, — и шлюз в этом режиме вполне может работать неделями.
// Без ограничения журналы растут бесконечно: при 10 устройствах с интервалом
// телеметрии 2 с это ~430 тыс. записей и ~80 МБ в сутки, то есть за неделю
// процесс съедает больше полугигабайта и в итоге падает по нехватке памяти.
// Поэтому храним только последние записи, вытесняя самые старые (кольцевая
// логика). Для боевого хранения истории есть PostgreSQL.
const (
	maxTelemetryInMemory = 100_000
	maxEventsInMemory    = 50_000
	maxRotationsInMemory = 50_000
)

// trimOldest ограничивает длину журнала, вытесняя самые старые записи.
//
// Обрезка идёт ПАЧКАМИ, а не на каждой записи: наивная версия («если длина
// больше лимита — скопировать хвост») после достижения лимита копировала бы весь
// срез при каждом новом пакете телеметрии (O(n) на запись, десятки мегабайт
// копирования в секунду). Поэтому даём запас в slack элементов и переносим хвост
// только когда он превышен — тогда копирование амортизируется и в среднем стоит
// O(1) на запись. Длина журнала при этом колеблется между max и max+slack, что
// для ограничения памяти совершенно достаточно.
func trimOldest[T any](items []T, max int) []T {
	const slack = 4096
	if len(items) <= max+slack {
		return items
	}
	drop := len(items) - max
	kept := make([]T, max, max+slack)
	copy(kept, items[drop:])
	return kept
}

func New() *MemStore {
	return &MemStore{devices: make(map[string]*DeviceRecord)}
}

// Reregister заменяет ключи существующего устройства. История сохраняется:
// журнал событий и телеметрия лежат в отдельных отображениях и не трогаются,
// дата первой регистрации переносится из прежней записи.
func (s *MemStore) Reregister(rec *DeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.devices[rec.DeviceID]
	if !exists {
		return ErrDeviceNotFound
	}
	cp := *rec
	cp.CreatedAt = old.CreatedAt
	// Состояние отзыва переносится намеренно: смена ключей не должна молча
	// снимать отзыв, иначе отозванное за неудачную проверку прошивки
	// устройство возвращалось бы в строй незаметно для оператора.
	cp.Revoked = old.Revoked
	cp.RevokedReason = old.RevokedReason
	s.devices[rec.DeviceID] = &cp
	return nil
}

func (s *MemStore) Register(rec *DeviceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.devices[rec.DeviceID]; exists {
		return ErrDeviceExists
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	cp := *rec
	s.devices[rec.DeviceID] = &cp
	return nil
}

func (s *MemStore) Get(deviceID string) (*DeviceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.devices[deviceID]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	cp := *rec
	if rec.Revoked {
		return &cp, ErrDeviceRevoked
	}
	return &cp, nil
}

func (s *MemStore) Revoke(deviceID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Revoked = true
	rec.RevokedReason = reason
	return nil
}

func (s *MemStore) Delete(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, deviceID)

	filterEvents := s.events[:0:0]
	for _, e := range s.events {
		if e.DeviceID != deviceID {
			filterEvents = append(filterEvents, e)
		}
	}
	s.events = filterEvents

	filterTel := s.telemetry[:0:0]
	for _, t := range s.telemetry {
		if t.DeviceID != deviceID {
			filterTel = append(filterTel, t)
		}
	}
	s.telemetry = filterTel

	filterRot := s.rotations[:0:0]
	for _, r := range s.rotations {
		if r.DeviceID != deviceID {
			filterRot = append(filterRot, r)
		}
	}
	s.rotations = filterRot

	return nil
}

func (s *MemStore) List() ([]DeviceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DeviceRecord, 0, len(s.devices))
	for _, rec := range s.devices {
		out = append(out, *rec)
	}
	return out, nil
}

func (s *MemStore) LogEvent(deviceID, eventType, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.events = append(s.events, SessionEvent{
		ID:        s.nextID,
		DeviceID:  deviceID,
		EventType: eventType,
		Detail:    detail,
		CreatedAt: time.Now(),
	})
	s.events = trimOldest(s.events, maxEventsInMemory)
	return nil
}

func (s *MemStore) EventsByType(eventTypes []string, deviceID string, limit int) ([]SessionEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	want := make(map[string]struct{}, len(eventTypes))
	for _, t := range eventTypes {
		want[t] = struct{}{}
	}
	var out []SessionEvent
	// Идём от новых к старым.
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if deviceID != "" && e.DeviceID != deviceID {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[e.EventType]; !ok {
				continue
			}
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemStore) RecentEvents(deviceID string, limit int) ([]SessionEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SessionEvent
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].DeviceID == deviceID {
			out = append(out, s.events[i])
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

var _ DeviceStore = (*MemStore)(nil)

func (s *MemStore) RecordTelemetry(reading TelemetryReading) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextTelID++
	reading.ID = s.nextTelID
	if reading.ReceivedAt.IsZero() {
		reading.ReceivedAt = time.Now().UTC()
	}
	s.telemetry = append(s.telemetry, reading)
	s.telemetry = trimOldest(s.telemetry, maxTelemetryInMemory)
	return nil
}

func (s *MemStore) QueryTelemetry(filter TelemetryFilter) ([]TelemetryReading, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 50000
	}

	var out []TelemetryReading
	for i := len(s.telemetry) - 1; i >= 0; i-- {
		r := s.telemetry[i]
		if filter.DeviceID != "" && r.DeviceID != filter.DeviceID {
			continue
		}
		if !filter.Since.IsZero() && r.ReceivedAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && r.ReceivedAt.After(filter.Until) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	// Разворачиваем в хронологический порядок (старые -> новые) — удобнее
	// для построения графиков на фронтенде.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// LatestTelemetryAll — последнее показание каждого устройства за один проход.
func (s *MemStore) LatestTelemetryAll() (map[string]TelemetryReading, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]TelemetryReading)
	// Журнал упорядочен по времени добавления, поэтому более поздняя запись
	// просто перезаписывает более раннюю.
	for _, t := range s.telemetry {
		out[t.DeviceID] = t
	}
	return out, nil
}

func (s *MemStore) LatestTelemetry(deviceID string) (*TelemetryReading, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.telemetry) - 1; i >= 0; i-- {
		if s.telemetry[i].DeviceID == deviceID {
			cp := s.telemetry[i]
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *MemStore) LogRotation(entry RotationLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextRotID++
	entry.ID = s.nextRotID
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	s.rotations = append(s.rotations, entry)
	s.rotations = trimOldest(s.rotations, maxRotationsInMemory)
	return nil
}

func (s *MemStore) RotationHistory(deviceID string, limit int) ([]RotationLogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []RotationLogEntry
	for i := len(s.rotations) - 1; i >= 0; i-- {
		r := s.rotations[i]
		if deviceID != "" && r.DeviceID != deviceID {
			continue
		}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
