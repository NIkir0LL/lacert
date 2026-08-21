package gateway

import "sync"

// Metrics — потокобезопасные агрегированные счётчики шлюза для наблюдаемости.
// В отличие от журнала событий (store), который хранит каждую запись отдельно,
// метрики дают мгновенную сводку «сколько всего чего произошло» без обхода
// всей истории — это то, что удобно показывать на дашборде и снимать для
// оценки работы системы.
//
// Счётчики живут в памяти процесса и сбрасываются при перезапуске — это
// осознанный выбор: цель здесь оперативная сводка, а долговременная история
// уже хранится в журнале событий.
type Metrics struct {
	mu sync.Mutex

	HandshakesCompleted uint64 // успешные рукопожатия (создана сессия)
	HandshakesRejected  uint64 // отклонённые Msg1/Msg3 (replay, протухание, неверная подпись)
	ReplaysBlocked      uint64 // отбитые повторы nonce рукопожатия

	RotationsSucceeded uint64 // успешные ротации ключа (любой инициатор)
	RotationsFailed    uint64 // неуспешные попытки ротации (включая тайм-аут ACK)

	// RotationTimeouts — откаты ротации по тайм-ауту подтверждения, когда ACK
	// не пришёл в срок. Входят и в RotationsFailed, но считаются отдельно —
	// тайм-аут обычно означает живое устройство за медленной сетью, а не
	// ошибку протокола, и на дашборде эти судьбы важно различать. Растёт
	// синхронно с событием rotation_timeout в журнале устройства.
	RotationTimeouts uint64

	FirmwareChecksPassed   uint64 // пройденные проверки целостности прошивки
	FirmwareChecksFailed   uint64 // проваленные проверки (устройство отозвано)
	FirmwareChecksRejected uint64 // отклонённые ответы (устаревший challenge)

	DevicesRevoked uint64 // отзывы устройств (по любой причине)

	// TelemetryDropped — принятые и расшифрованные показания, которые не удалось
	// записать в хранилище. Ошибка записи намеренно не прерывает работу
	// протокола: устройство уже отправило пакет, и разрывать из-за этого сессию
	// значило бы превращать сбой базы в отказ всей связи. Но и терять данные
	// молча нельзя — это основная полезная нагрузка системы, а не служебный
	// журнал. Счётчик делает потерю видимой на дашборде.
	TelemetryDropped uint64

	// DataReplaysBlocked — пакеты данных, отвергнутые как повтор: nonce уже
	// принимался под текущим сеансовым ключом (см. internal/crypto/replay_data.go).
	// Считается отдельно от ReplaysBlocked (повторы рукопожатия): это разные
	// этапы протокола, и на дашборде важно видеть, где именно идёт активность.
	DataReplaysBlocked uint64
}

func (m *Metrics) incHandshakeCompleted() { m.mu.Lock(); m.HandshakesCompleted++; m.mu.Unlock() }
func (m *Metrics) incHandshakeRejected()  { m.mu.Lock(); m.HandshakesRejected++; m.mu.Unlock() }
func (m *Metrics) incReplayBlocked()      { m.mu.Lock(); m.ReplaysBlocked++; m.mu.Unlock() }

func (m *Metrics) incRotationSucceeded() { m.mu.Lock(); m.RotationsSucceeded++; m.mu.Unlock() }
func (m *Metrics) incRotationFailed()    { m.mu.Lock(); m.RotationsFailed++; m.mu.Unlock() }
func (m *Metrics) incRotationTimeout()   { m.mu.Lock(); m.RotationTimeouts++; m.mu.Unlock() }

func (m *Metrics) incFirmwarePassed()   { m.mu.Lock(); m.FirmwareChecksPassed++; m.mu.Unlock() }
func (m *Metrics) incFirmwareFailed()   { m.mu.Lock(); m.FirmwareChecksFailed++; m.mu.Unlock() }
func (m *Metrics) incFirmwareRejected() { m.mu.Lock(); m.FirmwareChecksRejected++; m.mu.Unlock() }

func (m *Metrics) incDeviceRevoked() { m.mu.Lock(); m.DevicesRevoked++; m.mu.Unlock() }

func (m *Metrics) incDataReplayBlocked() { m.mu.Lock(); m.DataReplaysBlocked++; m.mu.Unlock() }

func (m *Metrics) incTelemetryDropped() { m.mu.Lock(); m.TelemetryDropped++; m.mu.Unlock() }

// Snapshot возвращает согласованную копию всех счётчиков (под одним локом),
// пригодную для сериализации в JSON для REST/дашборда.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MetricsSnapshot{
		HandshakesCompleted:    m.HandshakesCompleted,
		HandshakesRejected:     m.HandshakesRejected,
		ReplaysBlocked:         m.ReplaysBlocked,
		RotationsSucceeded:     m.RotationsSucceeded,
		RotationsFailed:        m.RotationsFailed,
		RotationTimeouts:       m.RotationTimeouts,
		FirmwareChecksPassed:   m.FirmwareChecksPassed,
		FirmwareChecksFailed:   m.FirmwareChecksFailed,
		FirmwareChecksRejected: m.FirmwareChecksRejected,
		DevicesRevoked:         m.DevicesRevoked,
		TelemetryDropped:       m.TelemetryDropped,
		DataReplaysBlocked:     m.DataReplaysBlocked,
	}
}

// MetricsSnapshot — неизменяемый срез метрик для выдачи через REST API.
type MetricsSnapshot struct {
	HandshakesCompleted    uint64 `json:"handshakes_completed"`
	HandshakesRejected     uint64 `json:"handshakes_rejected"`
	ReplaysBlocked         uint64 `json:"replays_blocked"`
	RotationsSucceeded     uint64 `json:"rotations_succeeded"`
	RotationsFailed        uint64 `json:"rotations_failed"`
	RotationTimeouts       uint64 `json:"rotation_timeouts"`
	FirmwareChecksPassed   uint64 `json:"firmware_checks_passed"`
	FirmwareChecksFailed   uint64 `json:"firmware_checks_failed"`
	FirmwareChecksRejected uint64 `json:"firmware_checks_rejected"`
	DevicesRevoked         uint64 `json:"devices_revoked"`
	TelemetryDropped       uint64 `json:"telemetry_dropped"`
	DataReplaysBlocked     uint64 `json:"data_replays_blocked"`
}
