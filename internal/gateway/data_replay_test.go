package gateway

import (
	"errors"
	"testing"

	"lacert/internal/crypto"
	"lacert/internal/store"
)

// Ровно тот же пакет, поданный шлюзу второй раз, должен быть отвергнут и не
// попасть в хранилище телеметрии. Шифрование подтверждает, что пакет
// подлинный и не изменён, но ничего не говорит о том, что он не был получен
// раньше: перехваченный из сети пакет расшифровывался повторно сколько угодно
// раз и каждый раз ложился в базу как свежее показание датчика.
func TestHandleDataRejectsReplayedPacket(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "replay-dev-1", crypto.SigECDSAP256, []byte("firmware-v1"))
	runHandshake(t, gw, dev)

	nonce, ciphertext, err := dev.SendData([]byte("pressure=4.2"))
	if err != nil {
		t.Fatalf("device send: %v", err)
	}

	// Первый приём — штатный.
	pt, err := gw.HandleData(dev.ID, nonce, ciphertext)
	if err != nil {
		t.Fatalf("первый пакет должен приниматься: %v", err)
	}
	if string(pt) != "pressure=4.2" {
		t.Fatalf("неожиданный открытый текст: %q", pt)
	}

	// Повтор тех же байт.
	if _, err := gw.HandleData(dev.ID, nonce, ciphertext); !errors.Is(err, crypto.ErrDataReplay) {
		t.Fatalf("повтор должен быть отвергнут с ErrDataReplay, получено: %v", err)
	}

	// В хранилище должна остаться ровно одна запись.
	readings, err := gw.Store.QueryTelemetry(store.TelemetryFilter{DeviceID: dev.ID})
	if err != nil {
		t.Fatalf("query telemetry: %v", err)
	}
	if len(readings) != 1 {
		t.Fatalf("ожидалась 1 запись телеметрии, получено %d — повтор попал в хранилище", len(readings))
	}

	if got := gw.Metrics.Snapshot().DataReplaysBlocked; got != 1 {
		t.Fatalf("счётчик отбитых повторов должен быть 1, получено %d", got)
	}
}

// Разные пакеты подряд принимаются как обычно — проверка на повтор не должна
// мешать нормальному потоку телеметрии.
func TestHandleDataAcceptsDistinctPackets(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "replay-dev-2", crypto.SigECDSAP256, []byte("firmware-v1"))
	runHandshake(t, gw, dev)

	for i := 0; i < 20; i++ {
		nonce, ct, err := dev.SendData([]byte("x=1"))
		if err != nil {
			t.Fatalf("device send %d: %v", i, err)
		}
		if _, err := gw.HandleData(dev.ID, nonce, ct); err != nil {
			t.Fatalf("пакет %d должен приниматься: %v", i, err)
		}
	}
	if got := gw.Metrics.Snapshot().DataReplaysBlocked; got != 0 {
		t.Fatalf("ложных срабатываний защиты от повтора быть не должно, получено %d", got)
	}
}

// CloseSession освобождает сессию и затирает ключ; повторный вызов безопасен.
func TestCloseSessionRemovesSessionAndIsIdempotent(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "close-session-dev", crypto.SigECDSAP256, []byte("firmware-v1"))
	runHandshake(t, gw, dev)

	if got := gw.ActiveSessionCount(); got != 1 {
		t.Fatalf("после рукопожатия ожидалась 1 сессия, получено %d", got)
	}
	if !gw.CloseSession(dev.ID) {
		t.Fatal("CloseSession должен сообщить, что сессия существовала")
	}
	if got := gw.ActiveSessionCount(); got != 0 {
		t.Fatalf("сессия должна быть удалена, осталось %d", got)
	}
	if gw.CloseSession(dev.ID) {
		t.Fatal("повторный CloseSession должен вернуть false, а не паниковать")
	}

	// Данные после закрытия сессии больше не принимаются.
	nonce, ct, err := dev.SendData([]byte("x=1"))
	if err != nil {
		t.Fatalf("device send: %v", err)
	}
	if _, err := gw.HandleData(dev.ID, nonce, ct); err == nil {
		t.Fatal("после закрытия сессии приём данных должен завершаться ошибкой")
	}
}
