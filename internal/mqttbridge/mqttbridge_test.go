package mqttbridge

import (
	"net"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

func TestBrokerPublishSubscribe(t *testing.T) {
	addr := "127.0.0.1:18830" // нестандартный порт, чтобы не конфликтовать с реальным MQTT, если он есть в системе
	b, err := New(":18830")
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	go func() {
		_ = b.Serve()
	}()
	defer b.Close()

	// Ждём, пока листенер реально начнёт принимать соединения.
	waitForPort(t, addr, 2*time.Second)

	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("test-subscriber")
	client := paho.NewClient(opts)
	if token := client.Connect(); !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("connect subscriber: %v", token.Error())
	}
	defer client.Disconnect(250)

	received := make(chan string, 1)
	token := client.Subscribe("devices/esp32-001/telemetry", 0, func(c paho.Client, m paho.Message) {
		received <- string(m.Payload())
	})
	if !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("subscribe: %v", token.Error())
	}

	time.Sleep(100 * time.Millisecond) // даём подписке зарегистрироваться на брокере

	if err := b.PublishTelemetry("esp32-001", []byte("temperature=23.5")); err != nil {
		t.Fatalf("publish telemetry: %v", err)
	}

	select {
	case msg := <-received:
		if msg != "temperature=23.5" {
			t.Fatalf("unexpected payload: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive published telemetry within timeout")
	}
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %s did not become available within %v", addr, timeout)
}
