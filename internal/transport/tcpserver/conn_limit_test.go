package tcpserver_test

import (
	"net"
	"testing"
	"time"

	"lacert/internal/transport/tcpserver"
)

// Сверх предела соединения должны отклоняться, а не копиться: каждое занимает
// горутину и буферы, а разбор кадров начинается до того, как шлюз узнает,
// зарегистрировано ли устройство.
func TestServerRejectsConnectionsOverLimit(t *testing.T) {
	prev := tcpserver.MaxConnections
	tcpserver.MaxConnections = 3
	t.Cleanup(func() { tcpserver.MaxConnections = prev })

	addr, _, srv := startTestServer(t)

	// Занимаем предел. Соединения держим открытыми, ничего не отправляя:
	// сервер ждёт первый кадр, значит они остаются активными.
	held := make([]net.Conn, 0, tcpserver.MaxConnections)
	for i := 0; i < tcpserver.MaxConnections; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("подключение %d не удалось: %v", i+1, err)
		}
		held = append(held, c)
	}
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})

	// Даём серверу принять все занятые соединения, иначе счётчик может
	// отстать от клиента и следующая проверка окажется ложной.
	waitActive(t, srv, len(held))

	// Следующее подключение принимается на уровне ОС, но сервер обязан сразу
	// его закрыть. Отличаем закрытие от «сервер молчит» по чтению: закрытое
	// соединение даёт EOF, живое — упирается в таймаут.
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		// Отказ на этапе подключения — тоже корректное поведение.
		return
	}
	defer extra.Close()

	_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := extra.Read(buf); err == nil {
		t.Fatal("сверхлимитное соединение осталось открытым и приняло данные")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("сверхлимитное соединение не было закрыто: чтение упёрлось в таймаут")
	}
	// Любая другая ошибка чтения (EOF, reset) означает, что сервер закрыл
	// соединение — этого мы и добивались.
}

// Освободившееся место должно снова принимать подключения: лимит ограничивает
// одновременные соединения, а не общее их число за время работы.
func TestServerAcceptsAfterSlotFreed(t *testing.T) {
	prev := tcpserver.MaxConnections
	tcpserver.MaxConnections = 2
	t.Cleanup(func() { tcpserver.MaxConnections = prev })

	addr, _, srv := startTestServer(t)

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("первое подключение: %v", err)
	}
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("второе подключение: %v", err)
	}
	defer second.Close()
	waitActive(t, srv, 2)

	// Освобождаем одно место и ждём, пока сервер это заметит.
	_ = first.Close()
	waitActive(t, srv, 1)

	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("подключение после освобождения места: %v", err)
	}
	defer third.Close()

	_ = third.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := third.Read(buf); err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("соединение должно было остаться открытым, но закрыто: %v", err)
		}
	}
}

// waitActive ждёт, пока число активных соединений сервера не станет ожидаемым.
// Проверять сразу после Dial нельзя: клиент завершает подключение раньше, чем
// сервер успевает его учесть.
func waitActive(t *testing.T, srv *tcpserver.Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ActiveConnections() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("сервер так и не учёл %d соединений (сейчас %d)", want, srv.ActiveConnections())
}
