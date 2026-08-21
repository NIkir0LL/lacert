package scheduler

import (
	"testing"
	"time"

	"lacert/internal/crypto"
)

// Одна просроченная ротация должна поднять счётчик rotation_timeouts ровно на
// единицу — синхронно с единственным событием в журнале устройства. Счётчик
// узкий, откаты по тайм-ауту входят и в rotations_failed, поэтому проверяется
// и вложенность. Проверка на ложный зелёный — уберите вызов
// incRotationTimeout из AbortStaleRotationIfNeeded, тест обязан упасть.
func TestRotationTimeoutCountedInMetrics(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "rot-timeout-metric-1")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.MaxRotationFailures = 3

	before := gw.Metrics.Snapshot()
	if before.RotationTimeouts != 0 {
		t.Fatalf("счётчик не нулевой до опыта, rotation_timeouts=%d", before.RotationTimeouts)
	}

	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("начало ротации: %v", err)
	}

	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = 10 * time.Millisecond
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })
	time.Sleep(20 * time.Millisecond)

	sched.maybeRotate(dev.ID)

	after := gw.Metrics.Snapshot()
	if after.RotationTimeouts != 1 {
		t.Fatalf("ожидался ровно один тайм-аут в метриках, rotation_timeouts=%d", after.RotationTimeouts)
	}
	if after.RotationsFailed < after.RotationTimeouts {
		t.Fatalf("тайм-ауты обязаны входить в неуспешные, failed=%d timeouts=%d",
			after.RotationsFailed, after.RotationTimeouts)
	}
}
