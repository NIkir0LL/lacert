package scheduler

import (
	"testing"
	"time"

	"lacert/internal/crypto"
)

// Одна просроченная ротация должна давать ровно одно событие rotation_timeout.
// До исправления событие писали двое на один и тот же откат: шлюз в
// AbortStaleRotationIfNeeded и планировщик в maybeRotate, причём текст шлюза
// («будет повторена») описывал поведение, отменённое в 1.4.0. Проверка на
// ложный зелёный: верните LogEvent в AbortStaleRotationIfNeeded — тест обязан
// упасть с «получено 2».
func TestRotationTimeoutLoggedOnce(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "rot-timeout-once-1")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.MaxRotationFailures = 3

	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("начало ротации: %v", err)
	}

	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = 10 * time.Millisecond
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })
	time.Sleep(20 * time.Millisecond)

	sched.maybeRotate(dev.ID)

	evs, err := gw.Store.EventsByType([]string{"rotation_timeout"}, dev.ID, 0)
	if err != nil {
		t.Fatalf("чтение событий: %v", err)
	}
	for i, e := range evs {
		t.Logf("событие %d: %s — %s", i, e.EventType, e.Detail)
	}
	if len(evs) != 1 {
		t.Fatalf("ожидалось ровно одно событие rotation_timeout на один откат, получено %d", len(evs))
	}
}
