package crypto

import (
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

	// Сдвигаем время и добавляем ещё один — очистка должна убрать старые.
	current = current.Add(100 * time.Millisecond)
	m, _ := NewHandshakeMsg1("device-001", nil)
	_ = guard.CheckAndRemember(m.DeviceID, m.Nonce)

	if guard.Size() != 1 {
		t.Fatalf("expected only the fresh nonce to remain after eviction, got size=%d", guard.Size())
	}
}
