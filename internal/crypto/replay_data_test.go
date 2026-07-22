package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// newTestSession — сессия со случайным K0 для тестов окна повторов.
func newTestSession(t *testing.T) *Session {
	t.Helper()
	k0 := bytes.Repeat([]byte{0xA5}, sessionKeySize)
	s, err := NewSession(k0)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// Основной сценарий: тот же пакет, принятый второй раз, отвергается.
func TestCheckDataNonceRejectsReplay(t *testing.T) {
	s := newTestSession(t)
	key, err := s.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}

	nonce, ct, err := EncryptPacket(key, 0, []byte("temperature=25.3"))
	if err != nil {
		t.Fatalf("EncryptPacket: %v", err)
	}

	// Первый приём — пакет валиден и нов.
	if _, err := DecryptPacket(key, nonce, ct); err != nil {
		t.Fatalf("первый приём должен расшифровываться: %v", err)
	}
	if err := s.CheckDataNonce(nonce); err != nil {
		t.Fatalf("первый приём nonce не должен считаться повтором: %v", err)
	}

	// Повтор: расшифровка по-прежнему проходит (пакет подлинный!) — именно
	// поэтому AEAD сам по себе от replay не защищает, и нужна эта проверка.
	if _, err := DecryptPacket(key, nonce, ct); err != nil {
		t.Fatalf("повторный пакет всё ещё расшифровывается, это ожидаемо: %v", err)
	}
	if err := s.CheckDataNonce(nonce); !errors.Is(err, ErrDataReplay) {
		t.Fatalf("повтор должен быть отвергнут с ErrDataReplay, получено: %v", err)
	}
}

// Разные пакеты под одним ключом принимаются все.
func TestCheckDataNonceAcceptsDistinctPackets(t *testing.T) {
	s := newTestSession(t)
	key, _ := s.CurrentKey()

	for i := 0; i < 50; i++ {
		nonce, _, err := EncryptPacket(key, uint32(i), []byte("x=1"))
		if err != nil {
			t.Fatalf("EncryptPacket %d: %v", i, err)
		}
		if err := s.CheckDataNonce(nonce); err != nil {
			t.Fatalf("пакет %d должен приниматься: %v", i, err)
		}
	}
	if got := s.SeenNonceCount(); got != 50 {
		t.Fatalf("ожидалось 50 запомненных nonce, получено %d", got)
	}
}

// Ротация ключа очищает окно: под новым Ki старые nonce'ы неактуальны,
// держать их дальше — только тратить память.
func TestRotationResetsNonceWindow(t *testing.T) {
	s := newTestSession(t)
	key, _ := s.CurrentKey()
	nonce, _, _ := EncryptPacket(key, 0, []byte("x=1"))
	if err := s.CheckDataNonce(nonce); err != nil {
		t.Fatalf("первый приём: %v", err)
	}
	if s.SeenNonceCount() == 0 {
		t.Fatal("окно должно быть непустым до ротации")
	}

	mi := bytes.Repeat([]byte{0x11}, sessionKeySize)
	if err := s.BeginRotate(mi, 1); err != nil {
		t.Fatalf("BeginRotate: %v", err)
	}
	if err := s.CommitRotate(); err != nil {
		t.Fatalf("CommitRotate: %v", err)
	}
	if got := s.SeenNonceCount(); got != 0 {
		t.Fatalf("после ротации окно должно быть пустым, в нём %d записей", got)
	}
}

// Окно ограничено сверху: если ротация надолго перестала проходить, набор
// не должен расти неограниченно.
func TestNonceWindowIsBounded(t *testing.T) {
	s := newTestSession(t)
	key, _ := s.CurrentKey()

	for i := 0; i < maxSeenNonces+500; i++ {
		nonce, _, err := EncryptPacket(key, uint32(i), []byte("x=1"))
		if err != nil {
			t.Fatalf("EncryptPacket %d: %v", i, err)
		}
		if err := s.CheckDataNonce(nonce); err != nil {
			t.Fatalf("пакет %d должен приниматься: %v", i, err)
		}
	}
	if got := s.SeenNonceCount(); got > maxSeenNonces {
		t.Fatalf("окно превысило предел: %d > %d", got, maxSeenNonces)
	}
}

// ApplyRotationAck должен проверять и коммитить атомарно. Тест фиксирует
// поведение при откате, случившемся до прихода ACK: коммита быть не должно,
// а сессия обязана остаться на старой итерации.
func TestApplyRotationAckAfterAbortDoesNotCommit(t *testing.T) {
	s := newTestSession(t)
	mi := bytes.Repeat([]byte{0x22}, sessionKeySize)
	if err := s.BeginRotate(mi, 1); err != nil {
		t.Fatalf("BeginRotate: %v", err)
	}
	keyBefore, _ := s.CurrentKey()

	s.AbortRotate() // ACK не дождались, ротация откачена

	err := ApplyRotationAck(s, &RotationAck{Iteration: 1})
	if !errors.Is(err, ErrNoPendingRotation) {
		t.Fatalf("ожидалась ErrNoPendingRotation, получено: %v", err)
	}
	keyAfter, _ := s.CurrentKey()
	if keyBefore != keyAfter {
		t.Fatal("опоздавший ACK не должен менять ключ после отката")
	}
	if s.Iteration() != 0 {
		t.Fatalf("итерация не должна была сдвинуться, получено %d", s.Iteration())
	}
}
