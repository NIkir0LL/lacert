package emulator

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"lacert/internal/api"
	"lacert/internal/gateway"
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

// startTestGateway поднимает настоящий TCP-листенер и httptest-сервер REST
// API — то есть эмулятор будет говорить с ними по реальной сети, точно так
// же, как он говорил бы с cmd/gatewayd.
func startTestGateway(t *testing.T, adminToken string) (httpURL, tcpAddr string, onDataCount func() int) {
	t.Helper()
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	tcpSrv := tcpserver.New(gw, quietLogger())
	var mu sync.Mutex
	count := 0
	tcpSrv.OnData = func(deviceID string, plaintext []byte) {
		mu.Lock()
		count++
		mu.Unlock()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = tcpSrv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })

	restSrv := api.New(gw, api.Options{TCPStatus: tcpSrv, AdminToken: adminToken})
	httpSrv := httptest.NewServer(restSrv)
	t.Cleanup(httpSrv.Close)

	return httpSrv.URL, ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

func TestRunRegistersHandshakesAndSendsTelemetry(t *testing.T) {
	httpURL, tcpAddr, onDataCount := startTestGateway(t, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(ctx, Config{
			GatewayHTTP:    httpURL,
			GatewayTCP:     tcpAddr,
			DeviceID:       "emu-test-device-1",
			SendInterval:   30 * time.Millisecond,
			Logger:         quietLogger(),
			ConnectTimeout: 5 * time.Second,
		})
	}()

	waitFor(t, 3*time.Second, func() bool { return onDataCount() >= 3 })

	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("Run should return nil after context cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit promptly after context cancellation")
	}
}

func TestRunWithAdminToken(t *testing.T) {
	httpURL, tcpAddr, onDataCount := startTestGateway(t, "secret-token-xyz")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(ctx, Config{
			GatewayHTTP:    httpURL,
			GatewayTCP:     tcpAddr,
			DeviceID:       "emu-test-device-2",
			AdminToken:     "secret-token-xyz",
			SendInterval:   30 * time.Millisecond,
			Logger:         quietLogger(),
			ConnectTimeout: 5 * time.Second,
		})
	}()

	waitFor(t, 3*time.Second, func() bool { return onDataCount() >= 2 })
	cancel()
	select {
	case <-runErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit promptly after context cancellation")
	}
}

// TestRunFailsFastWithWrongAdminToken — без верного токена регистрация
// никогда не пройдёт; Run должен сдаться по истечении ConnectTimeout, а не
// зависнуть навечно.
func TestRunFailsFastWithWrongAdminToken(t *testing.T) {
	httpURL, tcpAddr, _ := startTestGateway(t, "secret-token-xyz")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, Config{
		GatewayHTTP:    httpURL,
		GatewayTCP:     tcpAddr,
		DeviceID:       "emu-test-device-3",
		AdminToken:     "wrong-token",
		SendInterval:   30 * time.Millisecond,
		Logger:         quietLogger(),
		ConnectTimeout: 1 * time.Second, // короткий таймаут, чтобы тест не висел
	})
	if err == nil {
		t.Fatal("expected Run to fail with wrong admin token")
	}
}
