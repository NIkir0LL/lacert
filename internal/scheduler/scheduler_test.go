package scheduler

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
	"lacert/internal/store"
	"lacert/internal/transport/tcpclient"
	"lacert/internal/transport/tcpserver"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func startTestServer(t *testing.T) (addr string, gw *gateway.Gateway, srv *tcpserver.Server) {
	t.Helper()
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv = tcpserver.New(gw, quietLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	return addr, gw, srv
}

func registerAndConnect(t *testing.T, addr string, gw *gateway.Gateway, deviceID string) (*device.Device, *tcpclient.Client) {
	t.Helper()
	dev, err := device.NewDevice(deviceID, crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register device: %v", err)
	}
	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	go client.Listen() //nolint:errcheck
	return dev, client
}

// registerDeviceOnly регистрирует устройство на шлюзе, не устанавливая
// сетевого соединения (для тестов, где транспорт не нужен).
func registerDeviceOnly(t *testing.T, gw *gateway.Gateway, deviceID string) *device.Device {
	t.Helper()
	dev, err := device.NewDevice(deviceID, crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register device: %v", err)
	}
	return dev
}

// runHandshakeGW проводит рукопожатие устройство<->шлюз в процессе (без
// транспорта), чтобы у шлюза появилась активная сессия для устройства.
func runHandshakeGW(t *testing.T, gw *gateway.Gateway, dev *device.Device) {
	t.Helper()
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	msg2, err := gw.HandleMsg1(msg1)
	if err != nil {
		t.Fatalf("handle msg1: %v", err)
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("complete handshake: %v", err)
	}
	if err := gw.HandleMsg3(dev.ID, msg3); err != nil {
		t.Fatalf("handle msg3: %v", err)
	}
}

// TestSchedulerTriggersFirmwareCheckOnFirstTick проверяет, что планировщик
// сам, без вмешательства устройства или REST API, отправляет первый запрос
// проверки целостности прошивки при первом же тике для нового активного
// устройства (не ждёт целый FirmwareCheckInterval=1h перед первой проверкой).
func TestSchedulerTriggersFirmwareCheckOnFirstTick(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-esp32-001")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.RotationCheckPeriod = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	// Устройство должно ответить на присланный challenge и пройти проверку —
	// увидим это по появлению события firmware_check в журнале.
	waitFor(t, 2*time.Second, func() bool {
		events, err := gw.Store.RecentEvents(dev.ID, 0)
		if err != nil {
			return false
		}
		for _, e := range events {
			if e.EventType == "firmware_check" {
				return true
			}
		}
		return false
	})
}

// TestSchedulerTriggersRotationWhenSessionNeedsIt проверяет плановую
// ротацию по таймеру шлюза (не по инициативе устройства).
func TestSchedulerTriggersRotationWhenSessionNeedsIt(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-esp32-002")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	// Доводим до лимита пакетов, чтобы NeedsRotation() сразу вернул true —
	// не ждём реальные 300 секунд интервала по времени.
	for dev.SessionStats().PacketCount < crypto.RotationPacketLimit {
		if err := client.SendData([]byte("x")); err != nil {
			t.Fatalf("send data: %v", err)
		}
	}

	sched := New(gw, srv, quietLogger())
	sched.RotationCheckPeriod = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	waitFor(t, 2*time.Second, func() bool { return dev.SessionStats().RotationCount >= 1 })
}

// TestSchedulerPrunesFirmwareCheckStateForDisconnectedDevices —
// регрессионный тест для утечки памяти, найденной при аудите:
// lastFirmwareCheck раньше рос неограниченно, так как записи для
// отключившихся устройств никогда не удалялись.
func TestSchedulerPrunesFirmwareCheckStateForDisconnectedDevices(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-esp32-003")

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	sched := New(gw, srv, quietLogger())
	sched.tick() // ручной тик — сразу пошлём challenge и заполним lastFirmwareCheck

	if len(sched.lastFirmwareCheck) != 1 {
		t.Fatalf("expected 1 entry in lastFirmwareCheck after tick with 1 active device, got %d", len(sched.lastFirmwareCheck))
	}

	// Отключаем устройство и убеждаемся, что оно пропадает из активных.
	_ = client.Close()
	waitFor(t, 2*time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 0 })

	sched.tick() // должен подчистить lastFirmwareCheck за отключившееся устройство

	if len(sched.lastFirmwareCheck) != 0 {
		t.Fatalf("expected lastFirmwareCheck to be pruned after device disconnected, got %d entries: %v",
			len(sched.lastFirmwareCheck), sched.lastFirmwareCheck)
	}
	_ = dev
}

// TestSchedulerUsesAtomicRotation — проверяет, что плановая ротация,
// инициированная планировщиком, идёт по атомарному пути с ACK: после срабатывания
// и устройство, и шлюз переходят на следующий номер итерации.
func TestSchedulerUsesAtomicRotation(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-atomic-001")
	defer client.Close()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	// Доводим до лимита пакетов, чтобы NeedsRotation() вернул true.
	for dev.SessionStats().PacketCount < crypto.RotationPacketLimit {
		if err := client.SendData([]byte("x")); err != nil {
			t.Fatalf("send data: %v", err)
		}
	}

	sched := New(gw, srv, quietLogger())
	sched.RotationCheckPeriod = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	// Обе стороны должны перейти на итерацию 1 (атомарная ротация с ACK).
	waitFor(t, 3*time.Second, func() bool {
		return dev.SessionIteration() == 1 && gw.SessionIteration("sched-atomic-001") == 1
	})
}

// TestSchedulerRollsBackStaleRotation — проверяет, что планировщик откатывает
// застрявшую ротацию (ACK не пришёл) по тайм-ауту, после чего сессия снова
// готова к ротации. Здесь мы искусственно оставляем ротацию «висящей»,
// инициировав её напрямую на шлюзе (без доставки устройству), и прокручиваем
// управляемое время за тайм-аут.
func TestSchedulerRollsBackStaleRotation(t *testing.T) {
	base := crypto.NowForTest()
	fake := base
	crypto.SetNowForTest(func() time.Time { return fake })
	defer crypto.ResetNowForTest()

	addr, gw, srv := startTestServer(t)
	dev, client := registerAndConnect(t, addr, gw, "sched-stale-001")
	defer client.Close()
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	// Инициируем атомарную ротацию напрямую на шлюзе — ACK не придёт, потому
	// что мы не доставляем сообщение устройству. Сессия шлюза «зависает».
	if _, err := gw.InitiateAtomicRotationToDevice("sched-stale-001"); err != nil {
		t.Fatalf("initiate atomic rotation: %v", err)
	}

	sched := New(gw, srv, quietLogger())

	// До тайм-аута тик не откатывает ротацию.
	sched.tick()
	if gw.SessionIteration("sched-stale-001") != 0 {
		t.Fatal("iteration must stay 0 while rotation is pending")
	}

	// Прокручиваем время за тайм-аут и тикаем — планировщик должен откатить.
	fake = base.Add(crypto.RotationAckTimeout + time.Second)
	sched.tick()

	// После отката сессия закрывается: шлюз рвёт соединение, чтобы устройство
	// прошло рукопожатие заново.
	//
	// Прежде здесь проверялось обратное — что ротацию можно начать снова. Это
	// отражало старое поведение, при котором шлюз повторял попытку в той же
	// сессии. Но устройство применяет новый ключ до отправки подтверждения,
	// поэтому после отката ключи сторон расходятся, и повторять ротацию
	// бессмысленно: шлюз уже не может расшифровать ни одного пакета.
	if _, err := gw.InitiateAtomicRotationToDevice("sched-stale-001"); err == nil {
		t.Fatal("после отката сессия должна быть закрыта, а не готова к новой ротации")
	}
	_ = dev
}

// TestSchedulerRevokesAfterConsecutiveRotationFailures — критическая проверка:
// если устройство раз за разом не подтверждает ротацию (ACK не приходит), оно
// должно быть отозвано после MaxConsecutiveRotationFailures попыток, а не
// бесконечно накапливать «неуспешные ротации», продолжая обмен под старым
// ключом.
//
// Чтобы детерминированно смоделировать «неотвечающее» устройство, здесь
// вызывается напрямую логика счётчика провалов планировщика: сессия остаётся в
// pending-состоянии (ACK не доставляется), время прокручивается за тайм-аут, и
// на каждом такте планировщик откатывает застрявшую ротацию. Через
// MaxConsecutiveRotationFailures таких тактов устройство должно быть отозвано.
func TestSchedulerRevokesAfterConsecutiveRotationFailures(t *testing.T) {
	base := crypto.NowForTest()
	fake := base
	crypto.SetNowForTest(func() time.Time { return fake })
	defer crypto.ResetNowForTest()

	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := tcpserver.New(gw, quietLogger())
	sched := New(gw, srv, quietLogger())

	// Регистрируем устройство и вручную поднимаем ему сессию через рукопожатие
	// (без транспорта), чтобы шлюз мог инициировать ротацию.
	dev := registerDeviceOnly(t, gw, "sched-revoke-noack")
	runHandshakeGW(t, gw, dev)

	for i := 0; i < MaxConsecutiveRotationFailures; i++ {
		// Инициируем ротацию на шлюзе — «устройство» её не подтверждает.
		if _, err := gw.InitiateAtomicRotationToDevice("sched-revoke-noack"); err != nil {
			break // после отзыва инициировать уже нельзя
		}
		// Прокручиваем время за тайм-аут и вызываем логику планировщика.
		fake = fake.Add(crypto.RotationAckTimeout + time.Second)
		sched.maybeRotate("sched-revoke-noack")
	}

	// После порога подряд идущих провалов устройство должно быть отозвано.
	// Store.Get для отозванного устройства возвращает запись вместе с
	// ErrDeviceRevoked — это и есть подтверждение отзыва.
	rec, err := gw.Store.Get("sched-revoke-noack")
	revoked := (rec != nil && rec.Revoked) || err == store.ErrDeviceRevoked
	if !revoked {
		t.Fatalf("устройство должно быть отозвано после %d неуспешных ротаций подряд (err=%v)",
			MaxConsecutiveRotationFailures, err)
	}
	if gw.Metrics.Snapshot().DevicesRevoked < 1 {
		t.Fatal("счётчик отозванных устройств должен увеличиться")
	}
}
