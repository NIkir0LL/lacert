package crypto

import (
	"bytes"
	"testing"
	"time"
)

// setupRotationPair создаёт две согласованные сессии (устройство и шлюз) с
// одинаковым K0, а также KEM-пары обеих сторон для инкапсуляции секретов
// ротации. Возвращает то, что нужно для проигрывания ротаций в тестах.
func setupRotationPair(t *testing.T) (devSess, gwSess *Session, devKEM, gwKEM *KEMKeyPair) {
	t.Helper()
	var k0 [32]byte
	for i := range k0 {
		k0[i] = byte(i)
	}
	var err error
	devSess, err = NewSession(k0[:])
	if err != nil {
		t.Fatalf("dev session: %v", err)
	}
	gwSess, err = NewSession(k0[:])
	if err != nil {
		t.Fatalf("gw session: %v", err)
	}
	devKEM, err = GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("dev kem: %v", err)
	}
	gwKEM, err = GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("gw kem: %v", err)
	}
	return devSess, gwSess, devKEM, gwKEM
}

// keysEqual проверяет, что обе сессии пришли к одному текущему ключу, шифруя и
// расшифровывая пробный пакет крест-накрест.
func keysEqual(t *testing.T, a, b *Session) bool {
	t.Helper()
	ka, err := a.CurrentKey()
	if err != nil {
		return false
	}
	kb, err := b.CurrentKey()
	if err != nil {
		return false
	}
	return ka == kb
}

// TestNonAtomicRotationBreaksOnPacketLoss демонстрирует ИСХОДНУЮ проблему:
// при старой ротации (session.Rotate сразу) потеря сообщения ротации приводит
// к расхождению ключей — инициатор ушёл вперёд, получатель остался позади, и
// связь рвётся без восстановления.
func TestNonAtomicRotationBreaksOnPacketLoss(t *testing.T) {
	devSess, gwSess, _, gwKEM := setupRotationPair(t)

	// Устройство инициирует старую (неатомарную) ротацию: инкапсулирует под
	// KEM-ключом шлюза, СРАЗУ обновляет свой ключ и «отправляет» сообщение.
	msg, err := InitiateRotation(devSess, gwKEM.Pub)
	if err != nil {
		t.Fatalf("initiate old rotation: %v", err)
	}
	_ = msg // ...которое «теряется в сети» — шлюз его не получает.

	// Теперь ключи разошлись: устройство на Ki+1, шлюз на Ki.
	if keysEqual(t, devSess, gwSess) {
		t.Fatal("expected keys to diverge after lost rotation message (demonstrating the bug)")
	}
	// Восстановиться нельзя: старый ключ устройства уже затёрт. Это и есть
	// проблема, которую решает атомарная ротация.
}

// TestAtomicRotationSurvivesLostMessage: если сообщение ротации потеряно,
// атомарная ротация НЕ рвёт связь — инициатор остаётся на старом ключе (не
// закоммитил без ACK), стороны по-прежнему согласованы.
func TestAtomicRotationSurvivesLostMessage(t *testing.T) {
	devSess, gwSess, _, gwKEM := setupRotationPair(t)

	beforeKey, _ := devSess.CurrentKey()

	// Устройство начинает атомарную ротацию, «отправляет» сообщение...
	_, err := InitiateRotationAtomic(devSess, gwKEM.Pub)
	if err != nil {
		t.Fatalf("initiate atomic rotation: %v", err)
	}
	// ...но сообщение теряется — шлюз ничего не применил, ACK не пришёл.

	// Инициатор в «переходном» состоянии, но данные всё ещё под старым ключом.
	if !devSess.PendingRotation() {
		t.Fatal("expected pending rotation on initiator")
	}
	nowKey, _ := devSess.CurrentKey()
	if nowKey != beforeKey {
		t.Fatal("initiator must keep old key until ACK (data path unbroken)")
	}
	// Стороны всё ещё согласованы — связь жива.
	if !keysEqual(t, devSess, gwSess) {
		t.Fatal("keys must stay in sync when rotation message is lost")
	}

	// По тайм-ауту инициатор отменяет ротацию и может повторить позже.
	devSess.AbortRotate()
	if devSess.PendingRotation() {
		t.Fatal("abort must clear pending state")
	}
	if !keysEqual(t, devSess, gwSess) {
		t.Fatal("keys still in sync after abort")
	}
}

// TestAtomicRotationFullRoundTrip: полный успешный цикл ротации с ACK. После
// коммита обе стороны на новом ключе, номер итерации увеличился, шифрование
// крест-накрест работает под новым ключом.
func TestAtomicRotationFullRoundTrip(t *testing.T) {
	devSess, gwSess, _, gwKEM := setupRotationPair(t)
	oldKey, _ := devSess.CurrentKey()

	// 1. Устройство инициирует.
	msg, err := InitiateRotationAtomic(devSess, gwKEM.Pub)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	// 2. Шлюз применяет и отвечает ACK.
	ack, err := RespondToRotationAtomic(gwSess, gwKEM.Priv, msg)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}

	// 3. Устройство коммитит по ACK.
	if err := ApplyRotationAck(devSess, ack); err != nil {
		t.Fatalf("apply ack: %v", err)
	}

	// Обе стороны на новом ключе.
	if !keysEqual(t, devSess, gwSess) {
		t.Fatal("keys must match after successful atomic rotation")
	}
	newKey, _ := devSess.CurrentKey()
	if newKey == oldKey {
		t.Fatal("key must actually change after rotation")
	}
	if devSess.Iteration() != 1 || gwSess.Iteration() != 1 {
		t.Fatalf("iteration must advance to 1, got dev=%d gw=%d", devSess.Iteration(), gwSess.Iteration())
	}

	// Проверяем реальный data-path под новым ключом.
	nonce, ct, err := EncryptPacket(newKey, 0, []byte("hello after rotation"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	gwKey, _ := gwSess.CurrentKey()
	pt, err := DecryptPacket(gwKey, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt under rotated key failed: %v", err)
	}
	if !bytes.Equal(pt, []byte("hello after rotation")) {
		t.Fatal("payload mismatch after rotation")
	}
}

// TestAtomicRotationRejectsReplayedMessage: повторно воспроизведённое
// сообщение ротации (тот же номер итерации) отвергается получателем.
func TestAtomicRotationRejectsReplayedMessage(t *testing.T) {
	devSess, gwSess, _, gwKEM := setupRotationPair(t)

	msg, err := InitiateRotationAtomic(devSess, gwKEM.Pub)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	ack, err := RespondToRotationAtomic(gwSess, gwKEM.Priv, msg)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	_ = ApplyRotationAck(devSess, ack)

	// Злоумышленник повторяет то же сообщение ротации (итерация 1), которую
	// шлюз уже применил. Должно быть отвергнуто как replay.
	if _, err := RespondToRotationAtomic(gwSess, gwKEM.Priv, msg); err != ErrRotationReplay {
		t.Fatalf("expected ErrRotationReplay on replayed rotation, got: %v", err)
	}
}

// TestAtomicRotationRejectsOutOfOrder: сообщение с «прыжком» номера итерации
// (например, i+2 вместо i+1) отвергается, чтобы стороны не рассинхронизировались.
func TestAtomicRotationRejectsOutOfOrder(t *testing.T) {
	_, gwSess, _, gwKEM := setupRotationPair(t)

	// Сформируем сообщение с завышенным номером итерации вручную.
	ct, _, err := Encapsulate(gwKEM.Pub)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	badMsg := &RotationMsgV2{Iteration: 5, KEMCiphertext: ct} // ожидается 1

	if _, err := RespondToRotationAtomic(gwSess, gwKEM.Priv, badMsg); err != ErrRotationOutOfOrder {
		t.Fatalf("expected ErrRotationOutOfOrder, got: %v", err)
	}
}

// TestAtomicRotationPFS: после коммита старый ключ недоступен — предыдущий
// трафик не расшифровывается новым ключом (прямая секретность сохранена, как
// и в исходной схеме, но теперь без риска рассинхронизации).
func TestAtomicRotationPFS(t *testing.T) {
	devSess, gwSess, _, gwKEM := setupRotationPair(t)

	oldKey, _ := devSess.CurrentKey()
	// Пакет, зашифрованный под старым ключом ДО ротации.
	nonce, ct, _ := EncryptPacket(oldKey, 0, []byte("secret-before-rotation"))

	msg, _ := InitiateRotationAtomic(devSess, gwKEM.Pub)
	ack, _ := RespondToRotationAtomic(gwSess, gwKEM.Priv, msg)
	_ = ApplyRotationAck(devSess, ack)

	newKey, _ := devSess.CurrentKey()
	if newKey == oldKey {
		t.Fatal("key did not change")
	}
	// Новый ключ НЕ должен расшифровать старый трафик.
	if _, err := DecryptPacket(newKey, nonce, ct); err == nil {
		t.Fatal("PFS violated: new key decrypted pre-rotation traffic")
	}
}

// TestBeginRotateRejectsConcurrentRotation: нельзя начать вторую ротацию, не
// завершив первую (защита состояния «переходного» периода).
func TestBeginRotateRejectsConcurrentRotation(t *testing.T) {
	devSess, _, _, gwKEM := setupRotationPair(t)

	if _, err := InitiateRotationAtomic(devSess, gwKEM.Pub); err != nil {
		t.Fatalf("first initiate: %v", err)
	}
	// Вторая инициация до коммита первой — ошибка.
	if _, err := InitiateRotationAtomic(devSess, gwKEM.Pub); err == nil {
		t.Fatal("expected error when starting a second rotation before commit")
	}
}

// TestAbortIfStaleRollsBackAfterTimeout: если ACK не пришёл, по истечении
// тайм-аута незавершённая ротация откатывается, и можно начать новую.
func TestAbortIfStaleRollsBackAfterTimeout(t *testing.T) {
	// Управляемое время.
	base := timeNow()
	fake := base
	timeNow = func() time.Time { return fake }
	defer func() { timeNow = timeDefault }()

	devSess, _, _, gwKEM := setupRotationPair(t)

	// Инициируем атомарную ротацию — ACK «не приходит».
	if _, err := InitiateRotationAtomic(devSess, gwKEM.Pub); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if !devSess.PendingRotation() {
		t.Fatal("expected pending rotation")
	}

	// Сразу тайм-аут ещё не наступил.
	if devSess.AbortIfStale(RotationAckTimeout) {
		t.Fatal("must not abort before timeout elapsed")
	}
	if !devSess.PendingRotation() {
		t.Fatal("rotation must still be pending before timeout")
	}

	// Прокручиваем время за тайм-аут.
	fake = base.Add(RotationAckTimeout + time.Second)
	if !devSess.AbortIfStale(RotationAckTimeout) {
		t.Fatal("expected stale rotation to be aborted after timeout")
	}
	if devSess.PendingRotation() {
		t.Fatal("pending state must be cleared after abort")
	}

	// После отката можно начать новую ротацию.
	if _, err := InitiateRotationAtomic(devSess, gwKEM.Pub); err != nil {
		t.Fatalf("must be able to re-initiate rotation after stale abort: %v", err)
	}
}

// TestAbortIfStaleNoopWhenNoPending: без незавершённой ротации метод ничего не
// делает и возвращает false.
func TestAbortIfStaleNoopWhenNoPending(t *testing.T) {
	devSess, _, _, _ := setupRotationPair(t)
	if devSess.AbortIfStale(RotationAckTimeout) {
		t.Fatal("AbortIfStale must be a no-op when nothing is pending")
	}
}

// TestAbortIfStaleKeepsRotationOnFreshPending: свежая (не устаревшая) ротация
// не откатывается — это защищает нормальный round-trip от ложного отката.
func TestAbortIfStaleKeepsRotationOnFreshPending(t *testing.T) {
	base := timeNow()
	fake := base
	timeNow = func() time.Time { return fake }
	defer func() { timeNow = timeDefault }()

	devSess, _, _, gwKEM := setupRotationPair(t)
	if _, err := InitiateRotationAtomic(devSess, gwKEM.Pub); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	// Прошло меньше тайм-аута.
	fake = base.Add(RotationAckTimeout / 2)
	if devSess.AbortIfStale(RotationAckTimeout) {
		t.Fatal("fresh pending rotation must not be aborted")
	}
}
