package crypto

import (
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

// Параметры ротации ключей — см. раздел "Механизм непрерывной ротации ключей".
const (
	rotateSeparator    = "rotate_v1"
	handshakeSeparator = "lacert_handshake_v1"
	sessionKeySize     = 32 // BLAKE3 default output size, совпадает с ChaCha20-Poly1305 key size
)

// RotationPacketLimit — после скольких переданных пакетов ротировать ключ (в
// дополнение к ротации по времени RotationInterval). Переменная, а не
// константа, чтобы значение можно было подобрать на тестовом стенде через
// LACERT_ROTATION_PACKET_LIMIT (см. cmd/gatewayd). По умолчанию 300.
var RotationPacketLimit = 300

// RotationInterval — как часто ротировать ключ по времени (в дополнение к
// лимиту по числу пакетов RotationPacketLimit). Это переменная, а не
// константа, чтобы её можно было уменьшить для тестов/демонстрации живого
// стресс-теста (см. LACERT_ROTATION_INTERVAL в cmd/gatewayd). В обычной работе
// используется значение по умолчанию — 300 секунд.
var RotationInterval = 300 * time.Second

// Session хранит текущий сеансовый ключ Ki и всё, что нужно для решения
// "пора ротировать или нет": счётчик пакетов и время последней ротации.
// Все операции потокобезопасны (mutex), так как в реальной системе шлюз
// обслуживает множество устройств параллельно (горутины).
type Session struct {
	mu sync.Mutex

	key           [sessionKeySize]byte
	packetCount   int
	lastRotatedAt time.Time
	rotationCount int
	closed        bool

	// --- Состояние атомарной ротации (вариант А+В) ---
	// iteration — монотонный номер применённой ротации (i). Начинается с 0
	// для K0 и увеличивается на каждой успешной (закоммиченной) ротации. Номер
	// связывается криптографически с новым ключом и защищает от replay
	// сообщения ротации.
	iteration uint64

	// pendingKey/pendingActive описывают «переходное» состояние: инициатор
	// уже вычислил Ki+1, но ещё не получил подтверждение (ACK). До коммита
	// данные продолжают шифроваться под текущим (старым) ключом, поэтому
	// потеря сообщения ротации не рвёт связь. pendingIteration — номер
	// итерации, к которому относится ожидаемый коммит.
	pendingKey       [sessionKeySize]byte
	pendingActive    bool
	pendingIteration uint64
	// pendingStartedAt — момент вызова BeginRotate. По нему определяется, что
	// ожидание ACK затянулось (ACK потерян в сети) и незавершённую ротацию
	// пора откатить, чтобы можно было повторить попытку (см. AbortIfStale).
	pendingStartedAt time.Time

	// --- Окно защиты пакетов данных от повтора (см. replay_data.go) ---
	// seenNonces — nonce'ы пакетов, уже принятых под ТЕКУЩИМ ключом;
	// seenOrder — тот же набор в порядке поступления, для вытеснения самых
	// старых записей при переполнении окна. Обнуляются при каждой смене
	// ключа: под новым Ki старые пакеты всё равно не расшифруются.
	seenNonces map[nonceID]struct{}
	seenOrder  []nonceID
}

// NewSession создаёт сессию с начальным ключом K0, полученным по итогам
// рукопожатия (см. handshake.go).
func NewSession(k0 []byte) (*Session, error) {
	if len(k0) != sessionKeySize {
		return nil, errors.New("k0 must be 32 bytes")
	}
	s := &Session{lastRotatedAt: time.Now()}
	copy(s.key[:], k0)
	return s, nil
}

// CurrentKey возвращает копию текущего сеансового ключа Ki для использования
// в AEAD-шифровании. Возвращается копия, а не указатель на внутренний буфер,
// чтобы вызывающий код не мог случайно изменить/затереть внутреннее состояние.
func (s *Session) CurrentKey() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return [32]byte{}, errors.New("session is closed")
	}
	return s.key, nil
}

// NeedsRotation сообщает, наступило ли время ротации — по таймеру (300 секунд)
// или по счётчику пакетов (300 пакетов), смотря что раньше.
func (s *Session) NeedsRotation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	return s.packetCount >= RotationPacketLimit || time.Since(s.lastRotatedAt) >= RotationInterval
}

// RecordPacket увеличивает счётчик пакетов, переданных под текущим ключом.
// Вызывается после каждой успешной операции шифрования/расшифровки данных.
func (s *Session) RecordPacket() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetCount++
}

// Rotate вычисляет новый ключ Ki+1 = BLAKE3(Ki || Mi || "rotate_v1") и
// немедленно затирает старый ключ Ki из памяти через sodium_memzero-аналог
// (constant-time zeroing). Mi — новый общий секрет, полученный через
// ML-KEM при данной ротации (см. RotationStep в rotation.go).
//
// Это даёт два свойства безопасности (PFS/PCS) — см. README протокола:
//   - PFS: старый Ki уничтожен, поэтому компрометация текущего ключа не
//     раскрывает прошлый трафик.
//   - PCS: новый Ki+1 зависит от свежего Mi, которого у атакующего,
//     скомпрометировавшего только Ki, нет — поэтому он теряет доступ
//     к новому трафику после следующей ротации.
func (s *Session) Rotate(mi []byte) error {
	if len(mi) != sessionKeySize {
		return errors.New("mi must be 32 bytes (ml-kem-1024 shared secret)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session is closed")
	}

	h := blake3.New()
	h.Write(s.key[:])
	h.Write(mi)
	h.Write([]byte(rotateSeparator))
	newKey := h.Sum(nil) // 32 байта по умолчанию

	// Затирание старого ключа перед заменой (имитация sodium_memzero).
	zeroize(s.key[:])

	copy(s.key[:], newKey)
	zeroize(newKey)

	s.packetCount = 0
	s.lastRotatedAt = time.Now()
	s.rotationCount++
	s.resetSeenNoncesLocked()
	return nil
}

// Close затирает текущий ключ и помечает сессию как закрытую — вызывается
// при разрыве соединения или исключении устройства из сети.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	zeroize(s.key[:])
	zeroize(s.pendingKey[:]) // затираем и «ожидающий» ключ незавершённой ротации
	s.pendingActive = false
	s.closed = true
	s.resetSeenNoncesLocked()
}

// Stats — для логирования/демонстрации текущего состояния сессии.
type Stats struct {
	PacketCount   int
	RotationCount int
	LastRotatedAt time.Time
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{PacketCount: s.packetCount, RotationCount: s.rotationCount, LastRotatedAt: s.lastRotatedAt}
}

// DeriveK0 вычисляет начальный сеансовый ключ из общего секрета, полученного
// через ML-KEM при рукопожатии, и транскрипта рукопожатия (хеш всех
// переданных сообщений) — это привязывает K0 к конкретному обмену сообщениями
// и не даёт переиспользовать секрет в другом контексте.
func DeriveK0(sharedSecret, transcript []byte) []byte {
	h := blake3.New()
	h.Write(sharedSecret)
	h.Write(transcript)
	h.Write([]byte(handshakeSeparator))
	return h.Sum(nil)
}

// timeNow — точка подмены времени в тестах атомарной ротации. В обычной
// работе указывает на time.Now.
var timeNow = time.Now

// timeDefault — исходная реализация timeNow для восстановления в тестах.
var timeDefault = time.Now

// Zeroize затирает переданный буфер (например, секретный материал
// незавершённого рукопожатия) — публичная обёртка над внутренним
// константно-временным затиранием, для использования из других пакетов.
func Zeroize(b []byte) { zeroize(b) }

// zeroize затирает буфер константным временем выполнения (аналог
// sodium_memzero из libsodium, упомянутого в работе).
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// "Использование" буфера, чтобы компилятор не удалил затирание как
	// мёртвый код при оптимизации (то, что в C решается volatile/explicit_bzero).
	subtle.ConstantTimeCompare(b, b)
}
