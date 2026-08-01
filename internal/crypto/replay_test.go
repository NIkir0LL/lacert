package crypto

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestHandshakeReplayVulnerabilityWithoutGuard документирует исходную
// проблему: без отдельной проверки nonce ничто в примитивах рукопожатия не
// мешает повторно воспроизвести Msg1. FinalizeHandshake проверяет подпись, но
// подпись у записанного Msg1/Msg3 корректна — значит, повтор целиком проходит
// верификацию. Этот тест намеренно показывает, что защита нужна на уровне
// шлюза (ReplayGuard), а не внутри отдельных сообщений.
func TestHandshakeReplayVulnerabilityWithoutGuard(t *testing.T) {
	devIdentity, _ := GenerateIdentity(SigECDSAP256)
	devIdentityPub, _ := devIdentity.PublicKeyBytes()
	devKEM, _ := GenerateKEMKeyPair()

	msg1, _ := NewHandshakeMsg1("device-001", devIdentityPub)
	msg2, gwSS, _ := BuildMsg2(devKEM.Pub)
	msg3, _, _ := BuildMsg3(devKEM.Priv, devIdentity, msg1, msg2)

	// Легитимное рукопожатие проходит.
	if _, err := FinalizeHandshake(devIdentityPub, SigECDSAP256, msg1, msg2, msg3, gwSS); err != nil {
		t.Fatalf("legitimate handshake failed: %v", err)
	}

	// Повторная финализация ТЕХ ЖЕ записанных сообщений тоже проходит —
	// это и есть replay. Проверка подписи бессильна, потому что подпись верна.
	if _, err := FinalizeHandshake(devIdentityPub, SigECDSAP256, msg1, msg2, msg3, gwSS); err != nil {
		t.Fatalf("expected replay to pass at primitive level (demonstrating the gap), got: %v", err)
	}
	// Вывод: сами по себе примитивы replay не ловят — нужен ReplayGuard.
}

// TestReplayGuardRejectsReusedNonce проверяет, что ReplayGuard отвергает
// повторное использование того же nonce тем же устройством.
func TestReplayGuardRejectsReusedNonce(t *testing.T) {
	guard := NewReplayGuard(DefaultNonceTTL)

	msg1, _ := NewHandshakeMsg1("device-001", []byte("pub"))

	if err := guard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != nil {
		t.Fatalf("first use of nonce must succeed, got: %v", err)
	}

	// Тот же nonce второй раз — replay, должен быть отвергнут.
	if err := guard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != ErrReplayDetected {
		t.Fatalf("expected ErrReplayDetected on nonce reuse, got: %v", err)
	}
}

// TestReplayGuardAllowsDistinctNonces убеждается, что разные nonce одного
// устройства и одинаковые nonce разных устройств не считаются повтором.
func TestReplayGuardAllowsDistinctNonces(t *testing.T) {
	guard := NewReplayGuard(DefaultNonceTTL)

	a, _ := NewHandshakeMsg1("device-001", nil)
	b, _ := NewHandshakeMsg1("device-001", nil) // другой случайный nonce

	if err := guard.CheckAndRemember(a.DeviceID, a.Nonce); err != nil {
		t.Fatalf("nonce A: %v", err)
	}
	if err := guard.CheckAndRemember(b.DeviceID, b.Nonce); err != nil {
		t.Fatalf("distinct nonce B for same device must pass, got: %v", err)
	}

	// Тот же nonce, что у A, но для другого устройства — не replay.
	if err := guard.CheckAndRemember("device-002", a.Nonce); err != nil {
		t.Fatalf("same nonce for different device must pass, got: %v", err)
	}
}

// TestReplayGuardExpiresOldNonces проверяет, что по истечении TTL nonce
// забывается и то же значение снова принимается (память не растёт вечно, а
// старое Msg1 всё равно неактуально).
func TestReplayGuardExpiresOldNonces(t *testing.T) {
	guard := NewReplayGuard(100 * time.Millisecond)

	// Управляемое время вместо реального сна.
	current := time.Now()
	guard.now = func() time.Time { return current }

	msg1, _ := NewHandshakeMsg1("device-001", nil)

	if err := guard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != nil {
		t.Fatalf("first use: %v", err)
	}

	// Сразу повтор — replay.
	if err := guard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != ErrReplayDetected {
		t.Fatalf("expected replay within TTL, got: %v", err)
	}

	// Прокручиваем время за пределы TTL — nonce должен «забыться».
	current = current.Add(200 * time.Millisecond)
	if err := guard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != nil {
		t.Fatalf("after TTL the nonce must be accepted again, got: %v", err)
	}
}

// TestReplayGuardEvictsExpiredEntries проверяет, что просроченные записи
// действительно удаляются из карты, а не только игнорируются при проверке.
func TestReplayGuardEvictsExpiredEntries(t *testing.T) {
	guard := NewReplayGuard(50 * time.Millisecond)
	current := time.Now()
	guard.now = func() time.Time { return current }

	// Насыпем несколько разных nonce.
	for i := 0; i < 10; i++ {
		m, _ := NewHandshakeMsg1("device-001", nil)
		_ = guard.CheckAndRemember(m.DeviceID, m.Nonce)
	}
	if guard.Size() == 0 {
		t.Fatal("expected some remembered nonces")
	}

	// Сдвигаем время далеко вперёд и добавляем ещё один nonce. Записи
	// освобождаются сменой поколений, а не поэлементно, поэтому проверяем не
	// мгновенное исчезновение, а то, что память не растёт бесконечно: после
	// двух сдвигов (каждый раз в TTL/2) прежние записи отброшены целиком.
	for i := 0; i < 3; i++ {
		current = current.Add(100 * time.Millisecond)
		m, _ := NewHandshakeMsg1("device-001", nil)
		_ = guard.CheckAndRemember(m.DeviceID, m.Nonce)
	}

	if guard.Size() > 2 {
		t.Fatalf("после смены поколений должны остаться только свежие записи, получено size=%d", guard.Size())
	}
}

// Просроченная запись не должна считаться повтором, даже если она ещё занимает
// место в предыдущем поколении: срок жизни проверяется явно.
func TestReplayGuardExpiredEntryIsNotReplay(t *testing.T) {
	guard := NewReplayGuard(50 * time.Millisecond)
	current := time.Now()
	guard.now = func() time.Time { return current }

	m, _ := NewHandshakeMsg1("device-001", nil)
	if err := guard.CheckAndRemember(m.DeviceID, m.Nonce); err != nil {
		t.Fatalf("первое появление nonce должно приниматься: %v", err)
	}

	// Ждём дольше TTL, но меньше, чем нужно для двух смен поколений, — запись
	// ещё лежит в памяти, однако уже просрочена.
	current = current.Add(60 * time.Millisecond)
	if err := guard.CheckAndRemember(m.DeviceID, m.Nonce); err != nil {
		t.Fatalf("просроченный nonce не должен считаться повтором: %v", err)
	}
}

// Стоимость вставки не должна расти с наполнением: прежняя реализация обходила
// всю карту при каждом вызове, и цена вставки увеличивалась в разы. Тест
// сравнивает время первых вставок со временем вставок в уже наполненную
// защиту.
func TestReplayGuardInsertionCostDoesNotGrow(t *testing.T) {
	if testing.Short() {
		t.Skip("замер времени, пропускается в коротком режиме")
	}
	guard := NewReplayGuard(time.Hour) // без смены поколений за время теста

	measure := func(n int, tag string) time.Duration {
		var nonce [32]byte
		start := time.Now()
		for i := 0; i < n; i++ {
			binary.BigEndian.PutUint64(nonce[:8], uint64(i))
			_ = guard.CheckAndRemember(tag, nonce)
		}
		return time.Since(start)
	}

	const batch = 20000
	first := measure(batch, "warm-up")
	last := measure(batch, "loaded")

	// Порог с большим запасом: важно поймать рост в разы, а не колебания
	// в пределах шума планировщика.
	if last > first*5 {
		t.Errorf("стоимость вставки выросла слишком сильно: первые %d заняли %v, следующие — %v",
			batch, first, last)
	}
	t.Logf("первые %d вставок: %v, следующие %d (карта наполнена): %v", batch, first, batch, last)
}
