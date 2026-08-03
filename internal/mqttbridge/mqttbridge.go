// Package mqttbridge встраивает в шлюз MQTT-брокер (см. в работе: "встроенный
// MQTT-брокер для поддержки устройств, работающих по данному протоколу").
// В данной архитектуре сам защищённый канал LACERT (рукопожатие/ротация/
// данные) работает поверх TCP (internal/transport/tcpserver) — это отдельный,
// специально спроектированный протокол с постквантовой защитой. MQTT-брокер
// решает другую задачу: после того как шлюз расшифровал телеметрию,
// он публикует открытый текст в топик "devices/{id}/telemetry", откуда
// корпоративная информационная система может забрать данные привычным для
// IoT-интеграций способом (pub/sub), не имея дела с самим LACERT-протоколом.
//
// Через брокер идёт уже расшифрованная телеметрия, поэтому доступ к нему
// закрыт: подключение требует имени и пароля, подписчику разрешено только
// читать топики устройств, а канал при желании оборачивается в TLS.
package mqttbridge

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
)

// Broker — обёртка над embedded MQTT-сервером.
type Broker struct {
	srv *mqtt.Server
}

// Options — настройки брокера.
type Options struct {
	// Addr — адрес прослушивания, например ":1883".
	Addr string

	// Username и Password — учётные данные для подписчиков. Обязательны:
	// брокер отдаёт расшифрованную телеметрию, и запускать его открытым
	// нельзя. Если они пусты, New возвращает ErrNoCredentials.
	Username string
	Password string

	// TLSConfig, если задан, включает шифрование канала до подписчиков.
	// Без него телеметрия идёт по сети открытым текстом: сам протокол LACERT
	// защищает участок «устройство — шлюз», а дальше данные расшифрованы, и
	// защищать их — задача этого канала.
	TLSConfig *tls.Config

	// Logger — куда писать отказы в доступе. Если не задан, они не логируются.
	Logger *slog.Logger
}

// ErrNoCredentials возвращается, когда брокеру не заданы учётные данные.
// Прежде на его месте стоял режим «пускать всех», при котором любой, кто
// дотянулся до порта, читал всю расшифрованную телеметрию.
var ErrNoCredentials = errors.New("mqtt: не заданы имя пользователя и пароль")

// New создаёт MQTT-брокер и поднимает листенер на указанном адресе.
func New(opts Options) (*Broker, error) {
	if opts.Username == "" || opts.Password == "" {
		return nil, ErrNoCredentials
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	srv := mqtt.New(&mqtt.Options{
		InlineClient: true,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	hook := &authHook{
		username: []byte(opts.Username),
		password: []byte(opts.Password),
		logger:   logger,
	}
	if err := srv.AddHook(hook, nil); err != nil {
		return nil, fmt.Errorf("add auth hook: %w", err)
	}

	tcp := listeners.NewTCP(listeners.Config{
		ID:        "lacert-mqtt",
		Address:   opts.Addr,
		TLSConfig: opts.TLSConfig,
	})
	if err := srv.AddListener(tcp); err != nil {
		return nil, fmt.Errorf("add tcp listener: %w", err)
	}

	return &Broker{srv: srv}, nil
}

// Serve запускает брокер и блокируется до его остановки.
func (b *Broker) Serve() error {
	return b.srv.Serve()
}

// Close останавливает брокер.
func (b *Broker) Close() error {
	return b.srv.Close()
}

// PublishTelemetry публикует расшифрованную полезную нагрузку устройства в
// топик "devices/{deviceID}/telemetry". Вызывается из tcpserver.Server.OnData.
func (b *Broker) PublishTelemetry(deviceID string, payload []byte) error {
	topic := fmt.Sprintf("devices/%s/telemetry", deviceID)
	return b.srv.Publish(topic, payload, false, 0)
}

// PublishEvent публикует событие жизненного цикла устройства (рукопожатие,
// ротация, отзыв) в топик "devices/{deviceID}/events" — удобно для систем
// мониторинга, подписанных на статус устройств отдельно от самой телеметрии.
func (b *Broker) PublishEvent(deviceID, eventType, detail string) error {
	topic := fmt.Sprintf("devices/%s/events", deviceID)
	payload := fmt.Sprintf(`{"type":%q,"detail":%q}`, eventType, detail)
	return b.srv.Publish(topic, []byte(payload), false, 0)
}
