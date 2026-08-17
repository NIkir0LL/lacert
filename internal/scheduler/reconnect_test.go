package scheduler

import (
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/transport/tcpclient"
)

// Устройство, не подтвердившее ротацию, должно получить разрыв соединения, а
// не отзыв.
//
// Причина в том, как устроен протокол: устройство применяет новый ключ до
// отправки подтверждения. Если подтверждение задержалось и шлюз откатился,
// ключи расходятся немедленно — шлюз перестаёт расшифровывать пакеты, а
// устройство об этом не знает. Повторять ротацию в таком состоянии
// бессмысленно, нужно новое рукопожатие.
func TestRotationTimeoutDisconnectsInsteadOfRevoking(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-timeout-1")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.MaxRotationFailures = 3

	// Начинаем ротацию и не подтверждаем её.
	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("начало ротации: %v", err)
	}

	// Срок ожидания подтверждения искусственно уменьшен, чтобы не ждать
	// пять секунд в тесте.
	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = 10 * time.Millisecond
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })
	time.Sleep(20 * time.Millisecond)

	sched.maybeRotate(dev.ID)

	// Устройство должно остаться в реестре: разрыв соединения не отзыв.
	rec, err := gw.Store.Get(dev.ID)
	if err != nil {
		t.Fatalf("получение записи: %v", err)
	}
	if rec.Revoked {
		t.Error("после одного пропущенного подтверждения устройство отзываться не должно")
	}

	// Соединение при этом разорвано, чтобы устройство переподключилось.
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 0 })
}

// Отзыв остаётся последней мерой: если переподключения не помогают, дело не в
// сети, и устройство действительно неисправно.
//
// Проверяется главное следствие правки: счётчик неудач переживает разрыв
// соединения. Прежде он стирался при отключении устройства, и после перехода
// на «разрыв вместо отзыва» порог оказался бы недостижим — неисправное
// устройство переподключалось бы бесконечно.
func TestFailureCountSurvivesReconnect(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-timeout-2")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.MaxRotationFailures = 2

	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = 10 * time.Millisecond
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })

	// Первая неудача: разрыв, но не отзыв.
	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("первая ротация: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	sched.maybeRotate(dev.ID)

	if rec, _ := gw.Store.Get(dev.ID); rec.Revoked {
		t.Fatal("после первой неудачи отзыва быть не должно")
	}
	if n := sched.rotationFailures[dev.ID]; n != 1 {
		t.Fatalf("счётчик должен быть 1, получено %d", n)
	}

	// Такт планировщика с отключённым устройством не должен обнулить счётчик.
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 0 })
	sched.forgetStaleFailures()
	if n := sched.rotationFailures[dev.ID]; n != 1 {
		t.Errorf("счётчик должен пережить разрыв, получено %d", n)
	}
}

// Успешная ротация обнуляет счётчик: одиночные сбои сети не должны
// накапливаться до отзыва в течение суток работы.
func TestRotationSuccessResetsFailureCount(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	_, client := registerAndConnect(t, addr, gw, "sched-timeout-3")
	defer client.Close()

	sched := New(gw, srv, quietLogger())
	sched.rotationFailures["sched-timeout-3"] = 2

	sched.noteRotationSuccess("sched-timeout-3")

	if n := sched.rotationFailures["sched-timeout-3"]; n != 0 {
		t.Errorf("после успешной ротации счётчик должен обнуляться, осталось %d", n)
	}
}

// После разрыва устройство может подключиться заново и работать дальше.
//
// Полный цикл «разрыв — переподключение той же платы — успешная ротация» в
// тесте не воспроизводится: объект устройства хранит состояние сессии, а
// пересоздать его с теми же ключами тестовое окружение не позволяет, тогда как
// прошивка при переподключении начинает с чистого листа. Поэтому здесь
// проверяется то, что проверяемо: разрыв не мешает новому подключению и не
// оставляет устройство отозванным.
//
// Полный цикл проверен на плате: устройство переподключается и продолжает
// работу, ротации проходят.
func TestDisconnectDoesNotBlockReconnection(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "cycle-1")
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.MaxRotationFailures = 3

	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = 10 * time.Millisecond
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })

	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("начало ротации: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	sched.maybeRotate(dev.ID)
	client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 0 })

	// Устройство остаётся в реестре и не отозвано.
	rec, err := gw.Store.Get(dev.ID)
	if err != nil {
		t.Fatalf("получение записи: %v", err)
	}
	if rec.Revoked {
		t.Fatal("устройство не должно отзываться после одной неудачи")
	}

	// Новое подключение принимается.
	client2, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("переподключение отвергнуто: %v", err)
	}
	defer client2.Close()
	go client2.Listen() //nolint:errcheck

	waitFor(t, 2*time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })
}

// Пока ротация ждёт подтверждения, планировщик не должен пытаться начать
// новую.
//
// Замечено на живом стенде: при частом опросе планировщик успевал тикнуть до
// истечения срока ожидания, видел, что откатывать пока нечего, и пробовал
// начать вторую ротацию. Получал отказ и записывал в журнал тревожное
// сообщение о неудавшейся ротации — там, где всё шло по плану.
func TestNoSecondRotationWhilePending(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "pending-1")
	defer client.Close()
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())

	// Начинаем ротацию и не подтверждаем её, но срок ожидания ещё не вышел.
	prev := crypto.RotationAckTimeout
	crypto.RotationAckTimeout = time.Minute
	t.Cleanup(func() { crypto.RotationAckTimeout = prev })

	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("начало ротации: %v", err)
	}
	if !gw.HasPendingRotation(dev.ID) {
		t.Fatal("ротация должна ждать подтверждения")
	}

	// Такт планировщика не должен ни откатывать, ни начинать новую.
	sched.maybeRotate(dev.ID)

	if !gw.HasPendingRotation(dev.ID) {
		t.Error("ротация не должна была откатиться: срок ожидания не вышел")
	}
	if n := sched.rotationFailures[dev.ID]; n != 0 {
		t.Errorf("неудач быть не должно, счётчик %d", n)
	}
}
