package tcpserver_test

import (
	"testing"
	"time"

	"lacert/internal/device"
	"lacert/internal/transport/tcpclient"
)

// sameDeviceNewSession возвращает второй объект устройства с ТЕМИ ЖЕ ключами и
// идентификатором, но с собственным состоянием сессии — так выглядит повторное
// подключение одной и той же платы. Один общий объект тут не годится:
// Client.Close() затирает сессию устройства, и закрытие старого клиента
// обрывало бы канал новому, чего с настоящим железом не происходит.
func sameDeviceNewSession(t *testing.T, src *device.Device) *device.Device {
	t.Helper()
	return &device.Device{
		ID:            src.ID,
		Identity:      src.Identity,
		KEM:           src.KEM,
		FirmwareImage: src.FirmwareImage,
	}
}

// Сессия шлюза должна освобождаться при разрыве соединения, а не жить до
// отзыва устройства или остановки процесса. Раньше tcpserver убирал запись
// только из карты соединений, и сеансовый ключ каждого когда-либо
// подключавшегося устройства оставался в памяти шлюза.
//
// Ожидание через waitFor, а не немедленная проверка: tcpclient.Dial
// возвращается, отправив Msg3, то есть ДО того, как сервер его обработал и
// создал сессию.
func TestSessionIsClosedWhenConnectionEnds(t *testing.T) {
	addr, gw, _ := startTestServer(t)
	dev := registerDevice(t, gw, "tcp-esp32-lifecycle", []byte("firmware-v1"))

	client, err := tcpclient.Dial(addr, dev, quietLogger())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return gw.ActiveSessionCount() == 1 })

	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool { return gw.ActiveSessionCount() == 0 })
	if got := gw.ActiveSessionCount(); got != 0 {
		t.Fatalf("после разрыва соединения сессий быть не должно, осталось %d", got)
	}
}

// Переподключение устройства не должно ни ломать новое соединение, ни
// оставлять лишних сессий. Оба свойства проверяются вместе, потому что они
// тянут в разные стороны: слишком ранняя очистка убивает актуальную сессию,
// слишком поздняя — копит ключи в памяти.
func TestReconnectKeepsExactlyOneLiveSession(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	devA := registerDevice(t, gw, "tcp-esp32-reconnect-2", []byte("firmware-v1"))
	devB := sameDeviceNewSession(t, devA)

	first, err := tcpclient.Dial(addr, devA, quietLogger())
	if err != nil {
		t.Fatalf("первое подключение: %v", err)
	}
	defer first.Close()
	waitFor(t, 3*time.Second, func() bool { return gw.ActiveSessionCount() == 1 })

	second, err := tcpclient.Dial(addr, devB, quietLogger())
	if err != nil {
		t.Fatalf("переподключение: %v", err)
	}
	defer second.Close()

	// Старое соединение закрывается сервером, его горутина завершается и
	// выполняет очистку — именно в этот момент раньше могла пострадать
	// актуальная сессия.
	waitFor(t, 3*time.Second, func() bool {
		_, online := srv.Status(devB.ID)
		return online && gw.ActiveSessionCount() == 1
	})
	if got := gw.ActiveSessionCount(); got != 1 {
		t.Fatalf("должна остаться ровно одна сессия, получено %d", got)
	}

	// Главная проверка: канал нового соединения работает.
	if err := second.SendData([]byte("temperature=21.0")); err != nil {
		t.Fatalf("отправка данных по актуальному соединению: %v", err)
	}
}

// Устройство начинает второе рукопожатие, не дождавшись, пока шлюз завершит
// первое (перезагрузка платы, флап Wi-Fi). Раньше это ломало ОБА соединения:
// второй Msg1 затирал состояние первого, Msg3 первого проверялся против чужого
// транскрипта и отвергался как «invalid signature», а Msg3 второго уже не
// находил своей записи. Устройство оставалось без связи и выглядело в журнале
// источником неудачных рукопожатий. См. Gateway.HandleMsg3Tracked.
func TestRapidReconnectStillEstablishesChannel(t *testing.T) {
	addr, gw, srv := startTestServer(t)
	devA := registerDevice(t, gw, "tcp-esp32-rapid", []byte("firmware-v1"))
	devB := sameDeviceNewSession(t, devA)

	first, err := tcpclient.Dial(addr, devA, quietLogger())
	if err != nil {
		t.Fatalf("первое подключение: %v", err)
	}
	defer first.Close()

	// Без waitFor: второе подключение идёт вплотную за первым, чтобы попасть
	// в то самое окно, когда сервер ещё не обработал Msg3 первого.
	second, err := tcpclient.Dial(addr, devB, quietLogger())
	if err != nil {
		t.Fatalf("переподключение: %v", err)
	}
	defer second.Close()

	waitFor(t, 3*time.Second, func() bool {
		_, online := srv.Status(devB.ID)
		return online
	})

	if err := second.SendData([]byte("pressure=1.0")); err != nil {
		t.Fatalf("канал после быстрого переподключения должен работать: %v", err)
	}
	if got := gw.ActiveSessionCount(); got != 1 {
		t.Fatalf("ожидалась ровно одна живая сессия, получено %d", got)
	}
}
