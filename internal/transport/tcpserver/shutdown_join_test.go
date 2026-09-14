package tcpserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"lacert/internal/gateway"
)

// Shutdown обязан возвращаться только после выхода горутины Serve — иначе её
// хвост живёт после «остановки», и код, выполняющийся следом (очистки тестов,
// затирание ключей в cmd/gatewayd), пересекается с ещё работающим сервером.
// Именно так однажды проявилась гонка данных в тесте предела соединений.
// Тест белого ящика: смотрит на serveExited изнутри пакета, потому что снаружи
// момент выхода горутины не наблюдаем. Проверка на ложный зелёный — уберите
// ожидание serveExited из Shutdown и прогоните с -count=50, тест обязан
// падать (окно вероятностное, одиночный прогон может проскочить).
func TestShutdownWaitsForServeExit(t *testing.T) {
	srv := New(nil, slog.New(slog.NewTextHandler(discard{}, nil)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	// Дожидаемся фактического старта цикла accept. Без этого Shutdown может
	// отработать по ещё не начавшемуся Serve — флаг serveStarted ложен,
	// ожидание serveExited пропускается, и строгая проверка ниже мерила бы
	// расторопность планировщика, а не присоединение. Ровно так тест и упал
	// на машине автора, где горутина стартовала позже Shutdown. Случай
	// «Shutdown до первого Serve» покрыт соседним тестом отдельно.
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		started := srv.serveStarted
		srv.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Serve не стартовал за отведённое время")
		}
		time.Sleep(time.Millisecond)
	}

	// Даём циклу accept настоящую работу — соединение принимается и сразу
	// закрывается с нашей стороны, обслуживающая горутина завершится на ошибке
	// чтения. Держать его открытым нельзя: Shutdown закрывает только
	// зарегистрированные соединения, а сырое, не дошедшее до рукопожатия,
	// заставило бы ожидание горутин упереться в контекст (замечено этим же
	// тестом, записано отдельной задачей).
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Строго без ожидания: раз Shutdown вернулся, Serve уже должен был выйти.
	select {
	case <-srv.serveExited:
	default:
		t.Fatal("Shutdown вернулся, а горутина Serve ещё не завершилась")
	}
}

// Shutdown до первого Serve не должен зависать в ожидании канала, который
// никто не закроет — флаг serveStarted это и отсекает.
func TestShutdownBeforeServeDoesNotHang(t *testing.T) {
	srv := New(nil, slog.New(slog.NewTextHandler(discard{}, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown без serve: %v", err)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Соединение, которое подключилось, но не прислало Msg1, в conns не попадает.
// Прежде Shutdown его не закрывал, и обработчик сидел в чтении до срока
// IdleTimeout — пятнадцать минут, — а остановка ждала его. Теперь остановка
// закрывает все принятые соединения и завершается сразу, а сырое соединение
// получает конец потока.
func TestShutdownClosesConnectionsWithoutHandshake(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(gw, slog.New(slog.NewTextHandler(discard{}, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Дожидаемся, чтобы сервер принял соединение и запустил обработчик.
	deadline := time.Now().Add(2 * time.Second)
	for srv.ActiveConnections() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.ActiveConnections() != 1 {
		t.Fatalf("сервер не принял сырое соединение: активных %d", srv.ActiveConnections())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown не уложился: %v (прошло %v)", err, time.Since(start))
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Shutdown занял %v — ждал соединение без рукопожатия", took)
	}

	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("сырое соединение не закрыто сервером")
	}
}

// Соединение, принятое уже после начала остановки, должно закрываться сразу,
// не порождая обработчика. Воспроизводится через очередь listener: клиент
// подключается, пока цикл приёма ещё не дошёл до Accept.
func TestConnectionAcceptedDuringShutdownIsClosed(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(gw, slog.New(slog.NewTextHandler(discard{}, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Соединение попадает в очередь ядра до старта Serve — оно будет принято
	// первым же Accept, когда Serve запустится.
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// Начинаем остановку до Serve: флаг closing уже стоит, listener закрыт.
	// Serve после этого либо не примет ничего (listener закрыт), либо примет
	// из очереди и обязан закрыть сразу. В обоих случаях активных быть не должно.
	srv.mu.Lock()
	srv.closing = true
	srv.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)
	if n := srv.ActiveConnections(); n != 0 {
		t.Fatalf("после начала остановки принято %d соединений, ожидалось 0", n)
	}
	_ = ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve не завершился после закрытия listener")
	}
}
