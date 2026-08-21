package tcpserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
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
