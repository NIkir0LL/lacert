// Package mqttbridge встраивает в шлюз MQTT-брокер (см. в работе: "встроенный
// MQTT-брокер для поддержки устройств, работающих по данному протоколу").
// В данной архитектуре сам защищённый канал LACERT (рукопожатие/ротация/
// данные) работает поверх TCP (internal/transport/tcpserver) — это отдельный,
// специально спроектированный протокол с постквантовой защитой. MQTT-брокер
// решает другую задачу: после того как шлюз расшифровал телеметрию,
// он публикует открытый текст в топик "devices/{id}/telemetry", откуда
// корпоративная информационная система может забрать данные привычным для
// IoT-интеграций способом (pub/sub), не имея дела с самим LACERT-протоколом.
package mqttbridge

import (
	"fmt"
	"io"
	"log/slog"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
)

// Broker — обёртка над embedded MQTT-сервером.
type Broker struct {
	srv *mqtt.Server
}

// New создаёт MQTT-брокер и поднимает TCP-листенер на addr (например, ":1883").
// auth.AllowAll используется для прототипа, так как брокер работает только в
// изолированной корпоративной сети (см. постановку задачи в работе); для
// промышленного развёртывания сюда следует подключить отдельный hook
// аутентификации по логину/паролю или mTLS.
func New(addr string) (*Broker, error) {
	srv := mqtt.New(&mqtt.Options{
		InlineClient: true,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := srv.AddHook(new(auth.AllowHook), nil); err != nil {
		return nil, fmt.Errorf("add auth hook: %w", err)
	}

	tcp := listeners.NewTCP(listeners.Config{ID: "lacert-mqtt", Address: addr})
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
