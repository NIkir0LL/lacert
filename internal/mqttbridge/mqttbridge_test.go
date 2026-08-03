package mqttbridge

import (
	"errors"
	"net"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

func TestBrokerPublishSubscribe(t *testing.T) {
	addr := "127.0.0.1:18830" // нестандартный порт, чтобы не конфликтовать с реальным MQTT, если он есть в системе
	b, err := New(Options{Addr: ":18830", Username: testUser, Password: testPass})
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	go func() {
		_ = b.Serve()
	}()
	defer b.Close()

	// Ждём, пока листенер реально начнёт принимать соединения.
	waitForPort(t, addr, 2*time.Second)

	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("test-subscriber").
		SetUsername(testUser).SetPassword(testPass)
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

// Учётные данные для тестов. Брокер без них не поднимается — это и проверяет
// отдельный тест ниже.
const (
	testUser = "corp-integration"
	testPass = "s3cret-for-tests"
)

// Без учётных данных брокер не должен создаваться вовсе: прежде на их месте
// работал режим «пускать всех», при котором любой, кто дотянулся до порта,
// читал расшифрованную телеметрию всех устройств.
func TestBrokerRequiresCredentials(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"без имени и пароля", Options{Addr: ":18831"}},
		{"только имя", Options{Addr: ":18831", Username: testUser}},
		{"только пароль", Options{Addr: ":18831", Password: testPass}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := New(c.opts)
			if !errors.Is(err, ErrNoCredentials) {
				t.Fatalf("ожидалась ошибка ErrNoCredentials, получено err=%v broker=%v", err, b)
			}
			if b != nil {
				t.Error("при ошибке брокер не должен возвращаться")
			}
		})
	}
}

// Подключение с неверным паролем должно отклоняться.
func TestBrokerRejectsWrongPassword(t *testing.T) {
	addr := "127.0.0.1:18832"
	b, err := New(Options{Addr: ":18832", Username: testUser, Password: testPass})
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	go func() { _ = b.Serve() }()
	defer b.Close()
	waitForPort(t, addr, 2*time.Second)

	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("intruder").
		SetUsername(testUser).SetPassword("wrong-password").SetConnectTimeout(2 * time.Second)
	client := paho.NewClient(opts)
	token := client.Connect()
	if token.WaitTimeout(3*time.Second) && token.Error() == nil {
		client.Disconnect(250)
		t.Fatal("брокер принял подключение с неверным паролем")
	}
}

// Подписчику разрешено читать топики устройств, но не публиковать: иначе тот,
// кто получил пароль на чтение, смог бы подменять показания устройств в
// системе-получателе.
func TestBrokerDeniesPublishFromSubscriber(t *testing.T) {
	addr := "127.0.0.1:18833"
	b, err := New(Options{Addr: ":18833", Username: testUser, Password: testPass})
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	go func() { _ = b.Serve() }()
	defer b.Close()
	waitForPort(t, addr, 2*time.Second)

	// Первый клиент — легальный подписчик, слушает телеметрию устройства.
	subOpts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("legit-subscriber").
		SetUsername(testUser).SetPassword(testPass)
	sub := paho.NewClient(subOpts)
	if token := sub.Connect(); !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("подключение подписчика: %v", token.Error())
	}
	defer sub.Disconnect(250)

	got := make(chan string, 1)
	if token := sub.Subscribe("devices/esp32-001/telemetry", 0, func(_ paho.Client, m paho.Message) {
		got <- string(m.Payload())
	}); !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("подписка: %v", token.Error())
	}
	time.Sleep(100 * time.Millisecond)

	// Второй клиент с теми же данными пытается опубликовать подделку.
	pubOpts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("faker").
		SetUsername(testUser).SetPassword(testPass)
	pub := paho.NewClient(pubOpts)
	if token := pub.Connect(); !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("подключение публикатора: %v", token.Error())
	}
	defer pub.Disconnect(250)

	pub.Publish("devices/esp32-001/telemetry", 0, false, []byte("temperature=999")).
		WaitTimeout(time.Second)

	select {
	case msg := <-got:
		t.Fatalf("подложное сообщение дошло до подписчика: %q", msg)
	case <-time.After(time.Second):
		// Ничего не пришло — публикация отклонена, как и задумано.
	}
}

// Подписка на посторонние топики отклоняется: подписчик должен получать только
// телеметрию и события устройств, а не всё, что окажется на брокере.
func TestBrokerDeniesForeignTopicSubscription(t *testing.T) {
	addr := "127.0.0.1:18834"
	b, err := New(Options{Addr: ":18834", Username: testUser, Password: testPass})
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	go func() { _ = b.Serve() }()
	defer b.Close()
	waitForPort(t, addr, 2*time.Second)

	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("curious").
		SetUsername(testUser).SetPassword(testPass)
	client := paho.NewClient(opts)
	if token := client.Connect(); !token.WaitTimeout(2*time.Second) || token.Error() != nil {
		t.Fatalf("подключение: %v", token.Error())
	}
	defer client.Disconnect(250)

	// Подписываемся на всё подряд. Брокер обязан отказать, но клиентская
	// библиотека сообщает об отказе не всегда явно, поэтому проверяем не код
	// возврата, а факт: доходят ли до такого подписчика реальные данные.
	got := make(chan string, 1)
	token := client.Subscribe("#", 0, func(_ paho.Client, m paho.Message) {
		got <- string(m.Payload())
	})
	token.WaitTimeout(2 * time.Second)

	if err := b.PublishTelemetry("esp32-001", []byte("temperature=23.5")); err != nil {
		t.Fatalf("публикация телеметрии: %v", err)
	}

	select {
	case msg := <-got:
		t.Fatalf("подписка на # не была отклонена, клиент получил телеметрию: %q", msg)
	case <-time.After(time.Second):
		// Данные не дошли — отказ сработал.
	}
}
