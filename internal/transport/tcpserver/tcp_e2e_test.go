package tcpserver_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
	"lacert/internal/transport/tcpclient"
	"lacert/internal/transport/tcpserver"
)

// quietLogger — логгер без вывода в тестах (чтобы не шуметь), но реально
// используемый (можно переключить на os.Stdout для отладки).
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(quietWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type quietWriter struct{}

func (quietWriter) Write(p []byte) (int, error) { return len(p), nil }

// startTestServer поднимает TCP-сервер шлюза на случайном свободном порту
// и возвращает его адрес и сам gateway.Gateway для регистрации устройств.
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

	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() { ln.Close() })
	return addr, gw, srv
}

func registerDevice(t *testing.T, gw *gateway.Gateway, id string, firmware []byte) *device.Device {
	t.Helper()
	dev, err := device.NewDevice(id, crypto.SigECDSAP256, firmware)
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

func TestTCPHandshakeAndData(t *testing.T) {
	addr, gw, srv := startTestServer(t)

	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-001", firmware)

	var mu sync.Mutex
	var received [][]byte
	srv.OnData = func(deviceID string, plaintext []byte) {
		mu.Lock()
		received = append(received, append([]byte{}, plaintext...))
		mu.Unlock()
	}

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	go client.Listen() //nolint:errcheck // соединение закроется по завершении теста

	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("reading-%d", i))
		if err := client.SendData(payload); err != nil {
			t.Fatalf("send data %d: %v", i, err)
		}
	}

	// Даём серверной горутине время обработать кадры.
	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 3
	})

	mu.Lock()
	defer mu.Unlock()
	for i, got := range received {
		want := []byte(fmt.Sprintf("reading-%d", i))
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d: got %q want %q", i, got, want)
		}
	}
}

func TestTCPDeviceInitiatedRotation(t *testing.T) {
	addr, gw, _ := startTestServer(t)
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-002", firmware)

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	// Доводим до лимита пакетов, чтобы устройство решило, что пора ротировать.
	for dev.SessionStats().PacketCount < crypto.RotationPacketLimit-1 {
		if err := client.SendData([]byte("x")); err != nil {
			t.Fatalf("send data: %v", err)
		}
	}
	if err := client.SendData([]byte("x")); err != nil {
		t.Fatalf("send data: %v", err)
	}

	rotated, err := client.RotateIfNeeded()
	if err != nil {
		t.Fatalf("rotate if needed: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation to be triggered")
	}

	// После ротации канал должен продолжать работать.
	waitFor(t, 2*time.Second, func() bool { return dev.SessionStats().PacketCount == 0 })

	if err := client.SendData([]byte("post-rotation")); err != nil {
		t.Fatalf("send data after rotation: %v", err)
	}
}

func TestTCPGatewayInitiatedRotationAndFirmwareCheck(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-003", firmware)

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	// Шлюз сам инициирует ротацию через установленное соединение.
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })
	if err := srv.InitiateRotation(dev.ID); err != nil {
		t.Fatalf("server initiate rotation: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return dev.SessionStats().RotationCount == 1 })

	// Шлюз запрашивает проверку целостности прошивки — устройство честное.
	if err := srv.IssueFirmwareChallenge(dev.ID); err != nil {
		t.Fatalf("issue firmware challenge: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // даём обработать challenge/response в обе стороны

	if err := client.SendData([]byte("still-alive")); err != nil {
		t.Fatalf("device should still be trusted and able to send data: %v", err)
	}
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

// TestTCPDeviceReconnectDoesNotLoseAddressing — основной регрессионный тест
// для бага, исправленного в этой ревизии: если устройство переподключается
// (например, после кратковременного разрыва сети), и СТАРОЕ соединение
// после этого ещё немного "доживает" в памяти прежде чем его читающая
// горутина обнаружит закрытие сокета, шлюз не должен терять возможность
// адресовать НОВОЕ соединение (через ротацию/проверку прошивки) из-за того,
// что старая горутина удалит из карты активных соединений запись о новом.
func TestTCPDeviceReconnectDoesNotLoseAddressing(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-reconnect", firmware)

	client1, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	go client1.Listen() //nolint:errcheck

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	// Устройство "переподключается" — например, после кратковременного сбоя
	// сети, не закрыв явно старое соединение со своей стороны. Второе
	// рукопожатие на ТОМ ЖЕ device.Device (новая TCP-сессия, новый K0).
	client2, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("second dial (reconnect): %v", err)
	}
	defer client2.Close()
	go client2.Listen() //nolint:errcheck

	// Даём старой горутине время заметить закрытие старого сокета и
	// (потенциально, при наличии бага) удалить запись о новом соединении.
	time.Sleep(300 * time.Millisecond)

	if len(srv.ActiveDeviceIDs()) != 1 {
		t.Fatalf("expected exactly 1 active connection after reconnect, got %d: %v",
			len(srv.ActiveDeviceIDs()), srv.ActiveDeviceIDs())
	}

	// Шлюз должен по-прежнему быть способен адресовать устройство через
	// новое соединение (это и есть регрессия, которую мы проверяем).
	if err := srv.InitiateRotation(dev.ID); err != nil {
		t.Fatalf("gateway should still be able to address the device after reconnect: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return dev.SessionStats().RotationCount == 1 })

	if err := client2.SendData([]byte("after-reconnect")); err != nil {
		t.Fatalf("send data on new connection: %v", err)
	}

	_ = client1.Close() // старое соединение точно лишнее к этому моменту
}

// TestTCPConcurrentServerWrites — проверка, что параллельные вызовы со
// стороны шлюза (несколько попыток ротации, пересекающиеся по времени с
// одной проверкой целостности прошивки — реалистичная картина, когда
// планировщик и, в будущем, ручной запуск через REST API могут совпасть по
// времени) не повреждают кадры в TCP-потоке за счёт гонки на запись в один
// сокет. Намеренно НЕ шлём множество параллельных firmware-challenge'ей на
// одно устройство — у шлюза одновременно может быть только один неответный
// challenge на устройство (см. firmwareChallengeTimeout в gateway.go), и
// это ожидаемое ограничение, а не повреждение протокола.
func TestTCPConcurrentServerWrites(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-concurrent", firmware)

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.IssueFirmwareChallenge(dev.ID)
	}()
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Большинство вызовов закономерно вернут ошибку "сессия пока не
			// нуждается в ротации" или "ротация уже идёт" — нас интересует
			// отсутствие panic/повреждения потока на конкурентной записи в
			// сокет, а не успех каждого отдельного вызова.
			_ = srv.InitiateRotation(dev.ID)
		}()
	}
	wg.Wait()

	// Если протокольный поток был повреждён гонкой на запись, следующая
	// операция данных тоже развалится — это финальная проверка целостности.
	time.Sleep(150 * time.Millisecond)
	if err := client.SendData([]byte("still-fine")); err != nil {
		t.Fatalf("connection should still be usable after concurrent writes: %v", err)
	}
}

// TestTCPServerShutdownClosesConnections проверяет, что Shutdown закрывает
// listener и все активные соединения, и завершает все обслуживающие горутины.
func TestTCPServerShutdownClosesConnections(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := tcpserver.New(gw, quietLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(ln) }()

	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-shutdown", firmware)
	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	go client.Listen() //nolint:errcheck

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	select {
	case err := <-serveErrCh:
		if err != nil {
			t.Fatalf("Serve should return nil after graceful shutdown, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	if len(srv.ActiveDeviceIDs()) != 0 {
		t.Fatalf("expected no active connections after shutdown, got %v", srv.ActiveDeviceIDs())
	}
}

// TestTCPDisconnectClosesActiveConnectionAfterRevoke — сквозной регрессионный
// тест для бага, при котором отзыв устройства через REST API (Gateway +
// Store.Revoke) не разрывал уже установленное TCP-соединение: устройство
// продолжало нормально слать данные сколь угодно долго после отзыва. Здесь
// мы проверяем именно транспортный слой (tcpserver.Server.Disconnect),
// вызываемый так же, как это делает internal/api после Gateway.RevokeDevice.
func TestTCPDisconnectClosesActiveConnectionAfterRevoke(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-revoke", firmware)

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	listenErrCh := make(chan error, 1)
	go func() { listenErrCh <- client.Listen() }()

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	// До отзыва — данные проходят нормально.
	if err := client.SendData([]byte("before-revoke")); err != nil {
		t.Fatalf("send data before revoke: %v", err)
	}

	// Имитация того, что делает internal/api.revokeDevice: сначала Gateway
	// закрывает сессию, потом транспортный слой разрывает сам сокет.
	if err := gw.RevokeDevice(dev.ID, "test revoke"); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	disconnected := srv.Disconnect(dev.ID, "device revoked: test revoke")
	if !disconnected {
		t.Fatal("expected Disconnect to find and close the active connection")
	}

	// Соединение должно быть закрыто шлюзом — клиентская сторона должна
	// получить ошибку (закрытие сокета или явный TypeError-кадр) в Listen().
	select {
	case err := <-listenErrCh:
		if err == nil {
			t.Fatal("expected client Listen() to return an error after gateway-initiated disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not observe connection closure within timeout after revoke")
	}

	// И на стороне шлюза устройство больше не числится среди активных
	// соединений.
	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 0 })
}

// TestTCPDisconnectIsNoOpForOfflineDevice проверяет, что Disconnect
// корректно (без паники, с понятным возвратом false) обрабатывает отзыв
// устройства, которое сейчас не подключено — обычный случай в проде, когда
// администратор отзывает устройство, которое сейчас offline.
func TestTCPDisconnectIsNoOpForOfflineDevice(t *testing.T) {
	_, _, srv := startTestServer(t)
	if got := srv.Disconnect("never-connected-device", "test"); got {
		t.Fatal("expected Disconnect to return false for a device with no active connection")
	}
}

// TestTCPServerSurvivesRawGarbageOnPort — defense-in-depth регрессия: сырой
// мусорный трафик на порт (не протокол LACERT вообще, как это бывает от
// сетевых сканеров в реальной сети — подобное уже наблюдалось при тестах
// на реальном сервере) не должен приводить ни к панике всего процесса, ни
// к сбою обслуживания остальных, легитимных клиентов. Дополняет проверки
// устойчивости декодеров в internal/wire — здесь мы бьём по серверу с
// уровня целого TCP-соединения, а не по отдельной функции.
func TestTCPServerSurvivesRawGarbageOnPort(t *testing.T) {
	addr, gw, srv := startTestServer(t)

	// Открываем несколько "клиентов", шлющих откровенный не-LACERT мусор,
	// включая специально сконструированный кадр с длиной поля, вызывающей
	// переполнение uint16 (см. internal/wire.takeFramed).
	garbagePayloads := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), // именно это наблюдалось в реальном логе сервера
		bytes.Repeat([]byte{0xFF}, 200),
		{0x00, 0x00, 0x00, 0x05, byte(0x01), 0xFF, 0xFE, 0x01, 0x02}, // валидный внешний кадр (тип Msg1), но с overflow-triggering содержимым внутри
		{},
	}
	for _, payload := range garbagePayloads {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if len(payload) > 0 {
			_, _ = conn.Write(payload)
		}
		_ = conn.Close()
	}

	time.Sleep(200 * time.Millisecond) // даём серверным горутинам время обработать и отвалиться

	// Сервер должен по-прежнему быть жив и обслуживать легитимных клиентов.
	firmware := []byte("firmware-v1")
	dev := registerDevice(t, gw, "tcp-esp32-after-garbage", firmware)
	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial after garbage traffic: server should still be alive and accepting connections, got %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	if err := client.SendData([]byte("still-working-after-garbage")); err != nil {
		t.Fatalf("send data after garbage traffic: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })
}

// TestTCPDeviceInitiatedAtomicRotation — сквозная проверка атомарной ротации,
// инициированной устройством: устройство отправляет RotationMsgV2, шлюз
// применяет и отвечает RotationAck, устройство коммитит. Обе стороны должны
// перейти на итерацию 1, а канал — продолжить работать под новым ключом.
func TestTCPDeviceInitiatedAtomicRotation(t *testing.T) {
	addr, gw, _ := startTestServer(t)
	dev := registerDevice(t, gw, "tcp-esp32-atomic-dev", []byte("firmware-v1"))

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	// Отправим пару пакетов, затем инициируем атомарную ротацию.
	for i := 0; i < 3; i++ {
		if err := client.SendData([]byte("x")); err != nil {
			t.Fatalf("send data: %v", err)
		}
	}

	rotated := true
	if err := client.ForceAtomicRotation(); err != nil {
		t.Fatalf("atomic rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected atomic rotation to be initiated")
	}

	// Ждём, пока ACK долетит и обе стороны перейдут на итерацию 1.
	waitFor(t, 2*time.Second, func() bool {
		return dev.SessionIteration() == 1 && gw.SessionIteration("tcp-esp32-atomic-dev") == 1
	})
	if dev.SessionIteration() != 1 {
		t.Fatalf("device iteration = %d, want 1", dev.SessionIteration())
	}
	if gw.SessionIteration("tcp-esp32-atomic-dev") != 1 {
		t.Fatalf("gateway iteration = %d, want 1", gw.SessionIteration("tcp-esp32-atomic-dev"))
	}

	// Канал работает под новым ключом.
	if err := client.SendData([]byte("post-atomic-rotation")); err != nil {
		t.Fatalf("send after atomic rotation: %v", err)
	}
}

// TestTCPGatewayInitiatedAtomicRotation — атомарная ротация, инициированная
// шлюзом: шлюз отправляет RotationMsgV2, устройство отвечает ACK, шлюз
// коммитит. Обе стороны переходят на итерацию 1.
func TestTCPGatewayInitiatedAtomicRotation(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	dev := registerDevice(t, gw, "tcp-esp32-atomic-gw", []byte("firmware-v1"))

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	// Установим сессию, отправив один пакет (гарантирует, что соединение
	// зарегистрировано на сервере).
	if err := client.SendData([]byte("hello")); err != nil {
		t.Fatalf("send data: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		_, ok := srv.Status("tcp-esp32-atomic-gw")
		return ok
	})

	if err := srv.InitiateAtomicRotation("tcp-esp32-atomic-gw"); err != nil {
		t.Fatalf("gateway initiate atomic rotation: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return dev.SessionIteration() == 1 && gw.SessionIteration("tcp-esp32-atomic-gw") == 1
	})
	if dev.SessionIteration() != 1 || gw.SessionIteration("tcp-esp32-atomic-gw") != 1 {
		t.Fatalf("iterations not advanced: dev=%d gw=%d",
			dev.SessionIteration(), gw.SessionIteration("tcp-esp32-atomic-gw"))
	}

	// Канал продолжает работать.
	if err := client.SendData([]byte("post-gw-atomic")); err != nil {
		t.Fatalf("send after gateway atomic rotation: %v", err)
	}
}
