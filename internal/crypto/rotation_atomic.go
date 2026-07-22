package crypto

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/zeebo/blake3"
)

// Атомарная ротация ключей (варианты А + В из проектного обсуждения).
//
// Проблема исходной ротации (rotation.go): инициатор обновлял ключ сразу и
// затирал старый. Если сообщение ротации терялось в сети, инициатор
// оказывался на Ki+1, а получатель — на Ki, и связь рвалась без возможности
// восстановления (старый ключ уже уничтожен).
//
// Решение здесь построено на двух идеях:
//
//   А (атомарность через ACK). Инициатор вычисляет Ki+1, но НЕ выбрасывает
//   Ki: до получения подтверждения он продолжает шифровать данные под текущим
//   ключом. Ki+1 хранится как «ожидающий». Обе стороны переключаются на Ki+1
//   только после подтверждения. Потерянное сообщение ротации не рвёт связь:
//   стороны остаются на согласованном Ki, а ротация повторяется позже.
//
//   В (номер итерации). Каждое сообщение ротации несёт номер итерации i.
//   Получатель отвергает сообщение с номером, не превышающим уже применённый,
//   что защищает ротацию от replay и позволяет обнаружить рассинхронизацию.
//   Номер криптографически подмешивается в вывод нового ключа, поэтому его
//   нельзя незаметно подменить — расхождение сразу обнаружится на AEAD.
//
// Обмен сообщениями:
//
//   RotationMsgV2 (инициатор -> получатель): {Iteration i+1, KEM-шифротекст}
//       Инициатор: BeginRotate(Mi, i+1) — вычисляет Ki+1, держит оба ключа.
//   RotationAck  (получатель -> инициатор): {Iteration i+1}
//       Получатель применил Ki+1 и подтверждает; коммитит сразу (у него нет
//       незавершённых отправок под старым ключом — см. примечание ниже).
//       Инициатор по приёму ACK делает CommitRotate() и затирает Ki.

// RotationAck — подтверждение применения ротации получателем.
type RotationAck struct {
	Iteration uint64
}

// deriveNextKey вычисляет Ki+1 = BLAKE3(Ki || Mi || iteration || "rotate_v1").
// В отличие от исходной формулы, сюда добавлен номер итерации: он связывает
// ключ с конкретным шагом ротации и не даёт переиграть старое сообщение.
func deriveNextKey(currentKey [sessionKeySize]byte, mi []byte, iteration uint64) []byte {
	var itBuf [8]byte
	binary.BigEndian.PutUint64(itBuf[:], iteration)

	h := blake3.New()
	h.Write(currentKey[:])
	h.Write(mi)
	h.Write(itBuf[:])
	h.Write([]byte(rotateSeparator))
	return h.Sum(nil)
}

// BeginRotate вычисляет Ki+1 для заданной итерации и запоминает его как
// «ожидающий», НЕ трогая текущий ключ. Возвращает ошибку, если ротация уже в
// процессе (нельзя начать новую, не завершив предыдущую) или итерация не
// следующая по порядку.
func (s *Session) BeginRotate(mi []byte, iteration uint64) error {
	if len(mi) != sessionKeySize {
		return errors.New("mi must be 32 bytes (ml-kem-1024 shared secret)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session is closed")
	}
	if s.pendingActive {
		return errors.New("rotation already in progress (pending commit)")
	}
	if iteration != s.iteration+1 {
		return errors.New("iteration out of order")
	}

	newKey := deriveNextKey(s.key, mi, iteration)
	copy(s.pendingKey[:], newKey)
	zeroize(newKey)
	s.pendingActive = true
	s.pendingIteration = iteration
	s.pendingStartedAt = timeNow()
	return nil
}

// CommitRotate переключает сессию на ранее вычисленный Ki+1, затирает старый
// ключ Ki и завершает «переходное» состояние. Вызывается инициатором при
// получении корректного ACK и получателем сразу после применения ротации.
func (s *Session) CommitRotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitRotateLocked()
}

// commitRotateLocked — тело CommitRotate, вызывается под уже захваченным s.mu.
// Вынесено отдельно, чтобы ApplyRotationAck мог проверить состояние и
// закоммитить ротацию атомарно, не отпуская замок между двумя шагами.
func (s *Session) commitRotateLocked() error {
	if s.closed {
		return errors.New("session is closed")
	}
	if !s.pendingActive {
		return errors.New("no rotation in progress to commit")
	}

	zeroize(s.key[:]) // PFS: старый ключ уничтожается только теперь
	copy(s.key[:], s.pendingKey[:])
	zeroize(s.pendingKey[:])

	s.pendingActive = false
	s.iteration = s.pendingIteration
	s.packetCount = 0
	s.lastRotatedAt = timeNow()
	s.rotationCount++
	s.resetSeenNoncesLocked()
	return nil
}

// AbortRotate отменяет незавершённую ротацию: «ожидающий» Ki+1 затирается,
// сессия остаётся на текущем Ki. Вызывается при тайм-ауте ожидания ACK, чтобы
// можно было безопасно повторить ротацию позже.
func (s *Session) AbortRotate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	zeroize(s.pendingKey[:])
	s.pendingActive = false
	s.pendingIteration = 0
	s.pendingStartedAt = time.Time{}
}

// RotationAckTimeout — сколько инициатор ждёт ACK, прежде чем считать
// незавершённую ротацию «застрявшей» и откатить её. Значение с запасом
// превышает типичное время оборота даже в нестабильной промышленной сети, но
// не настолько велико, чтобы надолго блокировать возможность повторить ротацию.
var RotationAckTimeout = 5 * time.Second

// AbortIfStale откатывает незавершённую ротацию, если с момента её начала
// прошло больше timeout (ACK, по-видимому, потерян). Возвращает true, если
// откат был выполнен, — вызывающая сторона (планировщик) может по этому
// признаку залогировать неуспешную попытку и инициировать ротацию заново.
// При timeout <= 0 используется RotationAckTimeout.
func (s *Session) AbortIfStale(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = RotationAckTimeout
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pendingActive {
		return false
	}
	if timeNow().Sub(s.pendingStartedAt) < timeout {
		return false
	}
	zeroize(s.pendingKey[:])
	s.pendingActive = false
	s.pendingIteration = 0
	s.pendingStartedAt = time.Time{}
	return true
}

// Iteration возвращает номер последней применённой ротации.
func (s *Session) Iteration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iteration
}

// PendingRotation сообщает, есть ли незавершённая (ожидающая коммита) ротация.
func (s *Session) PendingRotation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingActive
}

// --- Протокольные операции поверх сессии ---

// InitiateRotationAtomic вызывается инициатором. Инкапсулирует свежий секрет
// под KEM-ключом собеседника, начинает (но не коммитит) ротацию на следующую
// итерацию и возвращает сообщение для отправки. Текущий ключ остаётся
// активным до получения ACK.
func InitiateRotationAtomic(session *Session, peerKEMPub *mlkem1024.PublicKey) (*RotationMsgV2, error) {
	ct, mi, err := Encapsulate(peerKEMPub)
	if err != nil {
		return nil, err
	}
	defer zeroize(mi)

	nextIter := session.Iteration() + 1
	if err := session.BeginRotate(mi, nextIter); err != nil {
		return nil, err
	}
	return &RotationMsgV2{Iteration: nextIter, KEMCiphertext: ct}, nil
}

// RespondToRotationAtomic вызывается получателем при приёме RotationMsgV2.
// Проверяет номер итерации (защита от replay/рассинхронизации), декапсулирует
// секрет, применяет ротацию (Begin+Commit сразу, т.к. получатель подтверждает
// применение) и возвращает ACK для отправки инициатору.
func RespondToRotationAtomic(session *Session, myKEMPriv *mlkem1024.PrivateKey, msg *RotationMsgV2) (*RotationAck, error) {
	expected := session.Iteration() + 1
	if msg.Iteration != expected {
		if msg.Iteration <= session.Iteration() {
			// Номер не превышает уже применённый — это повтор старого
			// сообщения ротации (replay) либо дубликат уже применённого.
			return nil, ErrRotationReplay
		}
		return nil, ErrRotationOutOfOrder
	}

	mi, err := Decapsulate(myKEMPriv, msg.KEMCiphertext)
	if err != nil {
		return nil, err
	}
	defer zeroize(mi)

	if err := session.BeginRotate(mi, msg.Iteration); err != nil {
		return nil, err
	}
	if err := session.CommitRotate(); err != nil {
		return nil, err
	}
	return &RotationAck{Iteration: msg.Iteration}, nil
}

// ApplyRotationAck вызывается инициатором при получении ACK. Проверяет, что
// подтверждение относится к ожидаемой итерации, и коммитит ротацию (переход
// на Ki+1 и затирание Ki). Некорректный или устаревший ACK игнорируется без
// изменения состояния.
// Проверка и коммит выполняются под ОДНИМ захватом mutex. Раньше замок
// отпускался между чтением pendingIteration и вызовом CommitRotate, и в это
// окно другая горутина (AbortIfStale планировщика или встречная ротация)
// успевала изменить состояние: проверка проходила по одной итерации, а
// коммитилась уже другая — либо CommitRotate падал с «no rotation in
// progress» на ротации, которая на момент проверки была валидной.
func ApplyRotationAck(session *Session, ack *RotationAck) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.pendingActive {
		return ErrNoPendingRotation
	}
	if ack.Iteration != session.pendingIteration {
		return ErrRotationOutOfOrder
	}
	return session.commitRotateLocked()
}

// Ошибки протокола ротации.
var (
	ErrRotationReplay     = errors.New("rotation replay: iteration not greater than current")
	ErrRotationOutOfOrder = errors.New("rotation iteration out of order")
	ErrNoPendingRotation  = errors.New("no pending rotation for this ack")
)
