package tcpclient

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
	"lacert/internal/transport/tcpserver"
	"lacert/internal/wire"
)

// Тесты этого файла гоняют клиент против настоящего шлюза — того же
// tcpserver, что работает в gatewayd. Так покрываются пути, которые нельзя
// проверить подделкой: успешное рукопожатие, доставка данных, обе стороны
// атомарной ротации и проверка прошивки. Для веток с испорченными кадрами
// ниже есть «сырой» шлюз, который умеет рукопожатие, а дальше шлёт что велят.

func startGateway(t *testing.T) (addr string, gw *gateway.Gateway, srv *tcpserver.Server) {
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
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().String(), gw, srv
}

func registeredDevice(t *testing.T, gw *gateway.Gateway, id string) *device.Device {
	t.Helper()
	dev := newTestDevice(t, id)
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register: %v", err)
	}
	return dev
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
	t.Fatal("условие не выполнилось за отведённое время")
}

// received собирает расшифрованные шлюзом пакеты — единственное честное
// подтверждение доставки, ложно-зелёное здесь невозможно.
type received struct {
	mu   sync.Mutex
	data [][]byte
}

func (r *received) add(p []byte) {
	r.mu.Lock()
	r.data = append(r.data, append([]byte(nil), p...))
	r.mu.Unlock()
}

func (r *received) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data)
}

func (r *received) last() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.data) == 0 {
		return nil
	}
	return r.data[len(r.data)-1]
}

// Полное рукопожатие с настоящим шлюзом и доставка пакета, расшифрованного
// на той стороне. Покрывает успешный путь handshake и SendData целиком.
func TestDialHandshakeAndSendDataDecryptedByGateway(t *testing.T) {
	addr, gw, srv := startGateway(t)
	var got received
	srv.OnData = func(_ string, pt []byte) { got.add(pt) }

	dev := registeredDevice(t, gw, "dev-e2e")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck // фоновое чтение, обрывается закрытием соединения

	if err := client.SendData([]byte("t=21.5")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return got.count() == 1 })
	if !bytes.Equal(got.last(), []byte("t=21.5")) {
		t.Fatalf("шлюз расшифровал %q, ожидалось t=21.5", got.last())
	}
}

// Устройство инициирует ротацию, шлюз подтверждает, Listen применяет ACK.
// Доказательство — итерация выросла у обеих сторон, а пакет под новым ключом
// расшифровался на шлюзе.
func TestForceAtomicRotationAcknowledgedAndDataFlows(t *testing.T) {
	addr, gw, srv := startGateway(t)
	var got received
	srv.OnData = func(_ string, pt []byte) { got.add(pt) }

	dev := registeredDevice(t, gw, "dev-rot")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck // фоновое чтение, обрывается закрытием соединения

	before := dev.SessionIteration()
	if err := client.ForceAtomicRotation(); err != nil {
		t.Fatalf("force rotation: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return dev.SessionIteration() == before+1 })
	if gw.SessionIteration("dev-rot") != before+1 {
		t.Fatalf("итерация шлюза %d, устройства %d", gw.SessionIteration("dev-rot"), before+1)
	}
	if err := client.SendData([]byte("after-rotation")); err != nil {
		t.Fatalf("send after rotation: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return got.count() == 1 })
	if !bytes.Equal(got.last(), []byte("after-rotation")) {
		t.Fatalf("под новым ключом расшифровано %q", got.last())
	}
}

// RotateIfNeededAtomic молчит, пока политика не требует ротации, и срабатывает
// после трёхсот пакетов — порога из политики сессии.
func TestRotateIfNeededAtomicFiresOnlyWhenDue(t *testing.T) {
	addr, gw, srv := startGateway(t)
	var got received
	srv.OnData = func(_ string, pt []byte) { got.add(pt) }

	dev := registeredDevice(t, gw, "dev-due")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck // фоновое чтение, обрывается закрытием соединения

	rotated, err := client.RotateIfNeededAtomic()
	if err != nil || rotated {
		t.Fatalf("свежая сессия: rotated=%v err=%v, ожидалось false и nil", rotated, err)
	}

	for i := 0; i < 300; i++ {
		if err := client.SendData([]byte("p")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitFor(t, 5*time.Second, func() bool { return got.count() == 300 })

	before := dev.SessionIteration()
	rotated, err = client.RotateIfNeededAtomic()
	if err != nil || !rotated {
		t.Fatalf("после 300 пакетов: rotated=%v err=%v, ожидалось true", rotated, err)
	}
	waitFor(t, 2*time.Second, func() bool { return dev.SessionIteration() == before+1 })
}

// Шлюз инициирует ротацию, Listen применяет её и отвечает ACK. Проверяется
// по итерации шлюза: она сдвигается только после принятого ACK.
func TestListenAppliesGatewayInitiatedRotation(t *testing.T) {
	addr, gw, srv := startGateway(t)
	var got received
	srv.OnData = func(_ string, pt []byte) { got.add(pt) }

	dev := registeredDevice(t, gw, "dev-gwrot")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck // фоновое чтение, обрывается закрытием соединения
	waitFor(t, 2*time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	before := gw.SessionIteration("dev-gwrot")
	if err := srv.InitiateAtomicRotation("dev-gwrot"); err != nil {
		t.Fatalf("initiate from gateway: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return gw.SessionIteration("dev-gwrot") == before+1 })
	if dev.SessionIteration() != before+1 {
		t.Fatalf("устройство на итерации %d, шлюз на %d", dev.SessionIteration(), before+1)
	}
	if err := client.SendData([]byte("ok")); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return got.count() == 1 })
}

// Проверка прошивки: шлюз шлёт challenge, Listen отвечает, шлюз записывает
// событие. Затем прошивка портится, и следующая проверка кончается отзывом:
// шлюз шлёт ошибку, Listen возвращает её и зовёт обратный вызов.
func TestListenAnswersFirmwareChallengeAndReturnsOnGatewayError(t *testing.T) {
	addr, gw, srv := startGateway(t)
	dev := registeredDevice(t, gw, "dev-fw")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var failedReason string
	var mu sync.Mutex
	client.OnFirmwareCheckFailed = func(reason string) {
		mu.Lock()
		failedReason = reason
		mu.Unlock()
	}
	listenErr := make(chan error, 1)
	go func() { listenErr <- client.Listen() }()
	waitFor(t, 2*time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	if err := srv.IssueFirmwareChallenge("dev-fw"); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		events, err := gw.Store.RecentEvents("dev-fw", 0)
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

	dev.TamperFirmware([]byte("evil"))
	if err := srv.IssueFirmwareChallenge("dev-fw"); err != nil {
		t.Fatalf("challenge after tamper: %v", err)
	}
	select {
	case err := <-listenErr:
		if err == nil || !strings.Contains(err.Error(), "gateway error") {
			t.Fatalf("Listen вернул %v, ожидалась ошибка шлюза", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Listen не завершился после ошибки шлюза")
	}
	mu.Lock()
	defer mu.Unlock()
	if failedReason == "" {
		t.Fatal("обратный вызов OnFirmwareCheckFailed не сработал")
	}
}

// rawGateway — шлюз, который честно проводит рукопожатие через настоящий
// gateway, а после пишет в соединение любые кадры. Нужен для веток Listen и
// handshake, до которых через tcpserver не добраться: там кадры всегда верные.
type rawGateway struct {
	t    *testing.T
	gw   *gateway.Gateway
	ln   net.Listener
	conn net.Conn
	done chan struct{}
}

func newRawGateway(t *testing.T) *rawGateway {
	t.Helper()
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &rawGateway{t: t, gw: gw, ln: ln, done: make(chan struct{})}
	t.Cleanup(func() {
		_ = ln.Close()
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
	return r
}

// acceptAndHandshake принимает одно соединение и доводит рукопожатие до
// конца силами настоящего шлюза, после чего соединение готово к инъекциям.
func (r *rawGateway) acceptAndHandshake(deviceID string) {
	conn, err := r.ln.Accept()
	if err != nil {
		r.t.Errorf("accept: %v", err)
		close(r.done)
		return
	}
	r.conn = conn
	typ, payload, err := wire.ReadFrame(conn)
	if err != nil || typ != wire.TypeHandshakeMsg1 {
		r.t.Errorf("ожидался Msg1, получено тип %d, ошибка %v", typ, err)
		close(r.done)
		return
	}
	msg1, err := wire.DecodeMsg1(payload)
	if err != nil {
		r.t.Errorf("decode msg1: %v", err)
		close(r.done)
		return
	}
	msg2, err := r.gw.HandleMsg1(msg1)
	if err != nil {
		r.t.Errorf("handle msg1: %v", err)
		close(r.done)
		return
	}
	if err := wire.WriteFrame(conn, wire.TypeHandshakeMsg2, wire.EncodeMsg2(msg2)); err != nil {
		r.t.Errorf("write msg2: %v", err)
		close(r.done)
		return
	}
	typ, payload, err = wire.ReadFrame(conn)
	if err != nil || typ != wire.TypeHandshakeMsg3 {
		r.t.Errorf("ожидался Msg3, получено тип %d, ошибка %v", typ, err)
		close(r.done)
		return
	}
	msg3, err := wire.DecodeMsg3(payload)
	if err != nil {
		r.t.Errorf("decode msg3: %v", err)
		close(r.done)
		return
	}
	if err := r.gw.HandleMsg3(deviceID, msg3); err != nil {
		r.t.Errorf("handle msg3: %v", err)
	}
	close(r.done)
}

// Listen обязан пережить неизвестный тип кадра и три вида испорченных кадров
// (ротация, ACK, challenge), а завершиться только на явной ошибке шлюза.
func TestListenSurvivesMalformedFramesUntilGatewayError(t *testing.T) {
	r := newRawGateway(t)
	dev := registeredDevice(t, r.gw, "dev-raw")
	go r.acceptAndHandshake("dev-raw")

	client, err := Dial(r.ln.Addr().String(), dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	<-r.done

	listenErr := make(chan error, 1)
	go func() { listenErr <- client.Listen() }()

	junk := []byte("\x00\x01\x02мусор")
	frames := []struct {
		typ     uint8
		payload []byte
	}{
		{200, junk},                        // неизвестный тип
		{wire.TypeRotationV2, junk},        // ротация без метки и структуры
		{wire.TypeRotationAck, junk},       // ACK, которого никто не ждал
		{wire.TypeFirmwareChallenge, junk}, // challenge неверной длины
	}
	for _, f := range frames {
		if err := wire.WriteFrame(r.conn, f.typ, f.payload); err != nil {
			t.Fatalf("inject %d: %v", f.typ, err)
		}
	}
	select {
	case err := <-listenErr:
		t.Fatalf("Listen завершился на мусорных кадрах: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := wire.WriteFrame(r.conn, wire.TypeError, wire.EncodeErrorMsg("stop")); err != nil {
		t.Fatalf("inject error: %v", err)
	}
	select {
	case err := <-listenErr:
		if err == nil || !strings.Contains(err.Error(), "stop") {
			t.Fatalf("Listen вернул %v, ожидалась ошибка со словом stop", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Listen не завершился после кадра ошибки")
	}
}

// Msg2, который нельзя разобрать, обязан оборвать рукопожатие на устройстве.
// А вот Msg2 чужой сессии устройство по протоколу принимает: аутентификация
// односторонняя, шлюз устройству подписи не предъявляет (см. модель угроз в
// OVERVIEW). Расхождение ловит шлюз — подтверждение в Msg3 посчитано на другом
// ключе, и HandleMsg3 обязан его отвергнуть. Тест закрепляет обе половины.
func TestDialRejectsUndecodableMsg2AndGatewayRejectsForeignSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = wire.ReadFrame(conn)
		_ = wire.WriteFrame(conn, wire.TypeHandshakeMsg2, []byte("not a msg2"))
	}()
	dev := newTestDevice(t, "dev-badmsg2")
	if _, err := Dial(ln.Addr().String(), dev, quietLogger()); err == nil ||
		!strings.Contains(err.Error(), "decode msg2") {
		t.Fatalf("ожидалась ошибка decode msg2, получено %v", err)
	}

	gw, err := gateway.New()
	if err != nil {
		t.Fatal(err)
	}
	other := registeredDevice(t, gw, "dev-other")
	otherMsg1, err := other.StartHandshake()
	if err != nil {
		t.Fatal(err)
	}
	foreignMsg2, err := gw.HandleMsg1(otherMsg1)
	if err != nil {
		t.Fatal(err)
	}

	victim := registeredDevice(t, gw, "dev-victim")
	msg3FromVictim := make(chan *crypto.HandshakeMsg3, 1)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = wire.ReadFrame(conn)
		_ = wire.WriteFrame(conn, wire.TypeHandshakeMsg2, wire.EncodeMsg2(foreignMsg2))
		typ, payload, err := wire.ReadFrame(conn)
		if err != nil || typ != wire.TypeHandshakeMsg3 {
			msg3FromVictim <- nil
			return
		}
		msg3, _ := wire.DecodeMsg3(payload)
		msg3FromVictim <- msg3
	}()
	client, err := Dial(ln2.Addr().String(), victim, quietLogger())
	if err != nil {
		t.Fatalf("устройство по протоколу принимает чужой Msg2, а Dial упал: %v", err)
	}
	defer client.Close()

	select {
	case msg3 := <-msg3FromVictim:
		if msg3 == nil {
			t.Fatal("устройство не отправило Msg3")
		}
		if err := gw.HandleMsg3("dev-victim", msg3); err == nil {
			t.Fatal("шлюз принял Msg3, посчитанный на чужом секрете")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Msg3 от устройства не пришёл")
	}
}

// Отправка после разрыва соединения со стороны шлюза даёт ошибку, а Listen
// возвращает её, не зависая.
func TestListenReturnsWhenGatewayDisconnects(t *testing.T) {
	addr, gw, srv := startGateway(t)
	dev := registeredDevice(t, gw, "dev-drop")
	client, err := Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	listenErr := make(chan error, 1)
	go func() { listenErr <- client.Listen() }()
	waitFor(t, 2*time.Second, func() bool { return len(srv.ActiveDeviceIDs()) == 1 })

	if !srv.Disconnect("dev-drop", "тест разрыва") {
		t.Fatal("Disconnect не нашёл устройство")
	}
	select {
	case err := <-listenErr:
		if err == nil {
			t.Fatal("Listen вернул nil после разрыва")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Listen завис после разрыва соединения")
	}
	// Соединение закрыто шлюзом, но запись в сокет может успеть уйти в буфер
	// ядра до того, как придёт RST. Поэтому шлём несколько раз: рано или
	// поздно ядро вернёт ошибку.
	var sendErr error
	for i := 0; i < 20 && sendErr == nil; i++ {
		sendErr = client.SendData([]byte("x"))
		time.Sleep(10 * time.Millisecond)
	}
	if sendErr == nil {
		t.Fatal("отправка в разорванное соединение ни разу не вернула ошибку")
	}
}
