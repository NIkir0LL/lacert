package crypto

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// ReplayGuard защищает от повторного воспроизведения (replay) сообщений
// рукопожатия. Проблема: в Msg1 устройство передаёт случайный Nonce, но без
// проверки на стороне шлюза злоумышленник может записать корректное Msg1 и
// отправить его повторно, инициируя лишнее рукопожатие от имени устройства.
//
// Решение — шлюз запоминает недавно виденные (DeviceID, Nonce) и отвергает
// повторы. Чтобы память не росла неограниченно, записи имеют срок жизни
// (TTL): nonce старше TTL забываются, так как соответствующее Msg1 всё равно
// уже неактуально (устройство при повторном подключении присылает свежий
// nonce). TTL выбирается заметно большим типичного времени рукопожатия.
//
// Компонент потокобезопасен: шлюз обслуживает множество устройств параллельно.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[nonceKey]time.Time
	ttl  time.Duration
	now  func() time.Time // подменяется в тестах
}

type nonceKey struct {
	deviceID string
	nonce    [32]byte
}

// DefaultNonceTTL — сколько времени шлюз помнит использованный nonce.
// Пять минут значительно превышают длительность рукопожатия даже в
// нестабильной промышленной сети, но при этом ограничивают рост памяти.
// DefaultNonceTTL — сколько помнить nonce рукопожатия для replay-защиты.
// Переменная, а не константа, чтобы значение можно было подобрать на тестовом
// стенде через LACERT_NONCE_TTL (см. cmd/gatewayd). По умолчанию 5 минут.
var DefaultNonceTTL = 5 * time.Minute

// NewReplayGuard создаёт защиту с заданным TTL. При ttl <= 0 используется
// DefaultNonceTTL.
func NewReplayGuard(ttl time.Duration) *ReplayGuard {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &ReplayGuard{
		seen: make(map[nonceKey]time.Time),
		ttl:  ttl,
		now:  time.Now,
	}
}

// ErrReplayDetected возвращается, когда (DeviceID, Nonce) уже встречались.
var ErrReplayDetected = errors.New("replay detected: nonce already used for this device")

// CheckAndRemember проверяет, что nonce для данного устройства ещё не
// использовался, и запоминает его. Возвращает ErrReplayDetected, если это
// повтор. Первое появление nonce считается допустимым.
//
// Побочно вызывает ленивую очистку просроченных записей, чтобы карта не
// накапливала мусор при большом числе устройств.
func (g *ReplayGuard) CheckAndRemember(deviceID string, nonce [32]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	key := nonceKey{deviceID: deviceID, nonce: nonce}

	if seenAt, ok := g.seen[key]; ok {
		// Запись ещё жива — это replay. Просроченную запись считаем
		// отсутствующей (см. очистку ниже), поэтому сюда попадают только
		// актуальные повторы.
		if now.Sub(seenAt) < g.ttl {
			return ErrReplayDetected
		}
	}

	g.seen[key] = now
	g.evictExpiredLocked(now)
	return nil
}

// evictExpiredLocked удаляет записи старше TTL. Вызывается под уже
// захваченным mutex. Для ожидаемых объёмов (десятки–сотни устройств,
// рукопожатия нечасты) линейный проход дешёв; при масштабировании его можно
// заменить на амортизированную очистку по таймеру.
func (g *ReplayGuard) evictExpiredLocked(now time.Time) {
	for k, t := range g.seen {
		if now.Sub(t) >= g.ttl {
			delete(g.seen, k)
		}
	}
}

// Size возвращает число запомненных nonce (для тестов и метрик).
func (g *ReplayGuard) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

// --- Защита ротации от replay через монотонный счётчик итераций ---

// RotationMsgV2 расширяет RotationMsg номером итерации ротации. Это
// защищает от воспроизведения старого сообщения ротации: получатель отвергает
// сообщение, чей Iteration не превышает уже применённый. Поле сериализуется
// вместе с шифротекстом (см. wire), поэтому подмена номера ломает согласование
// ключей и обнаруживается на уровне AEAD при первом же пакете.
type RotationMsgV2 struct {
	Iteration     uint64
	KEMCiphertext []byte
}

// IterationBytes возвращает 8-байтовое big-endian представление номера
// итерации — используется как дополнительный вход при выводе нового ключа,
// чтобы номер итерации был криптографически связан с ключом, а не просто
// передавался рядом.
func (m *RotationMsgV2) IterationBytes() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], m.Iteration)
	return b[:]
}
