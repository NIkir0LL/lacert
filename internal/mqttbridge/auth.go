package mqttbridge

import (
	"crypto/subtle"
	"log/slog"
	"strings"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// authHook проверяет подключающихся к брокеру и решает, что им позволено.
//
// Почему собственный хук, а не готовый из библиотеки: встроенный сравнивает
// пароли обычным оператором сравнения строк, который завершается на первом
// несовпавшем байте. Здесь используется сравнение за постоянное время — по
// той же причине, по которой оно применяется для админского токена REST.
//
// Права намеренно односторонние. Брокер существует, чтобы корпоративная
// система ЗАБИРАЛА расшифрованную телеметрию, публикует в него только сам
// шлюз (внутренним вызовом, минуя сеть). Значит подключившемуся извне нужна
// лишь подписка, и разрешать ему публикацию не за чем: иначе тот, кто получил
// пароль на чтение, смог бы подменять показания устройств в системе-получателе.
type authHook struct {
	mqtt.HookBase

	username []byte
	password []byte
	logger   *slog.Logger
}

// ID — имя хука в реестре брокера.
func (h *authHook) ID() string { return "lacert-auth" }

// Provides сообщает брокеру, какие события хук обрабатывает.
func (h *authHook) Provides(b byte) bool {
	return b == mqtt.OnConnectAuthenticate || b == mqtt.OnACLCheck
}

// OnConnectAuthenticate пропускает клиента, только если совпали и имя, и
// пароль. Оба сравнения выполняются всегда, без раннего выхода: иначе по
// времени ответа можно было бы отличить «неверное имя» от «неверного пароля».
func (h *authHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	userOK := subtle.ConstantTimeCompare(cl.Properties.Username, h.username) == 1
	passOK := subtle.ConstantTimeCompare(pk.Connect.Password, h.password) == 1
	if !(userOK && passOK) {
		h.logger.Warn("отклонено подключение к MQTT-брокеру",
			"remote", cl.Net.Remote, "username", string(cl.Properties.Username))
		return false
	}
	return true
}

// OnACLCheck разрешает подписку на телеметрию и события устройств и запрещает
// всё остальное, включая любую публикацию.
func (h *authHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	if write {
		h.logger.Warn("отклонена попытка публикации в MQTT-брокер",
			"remote", cl.Net.Remote, "topic", topic)
		return false
	}
	// Подписка разрешена только на то, что шлюз действительно публикует.
	// Проверяем ровно префикс "devices/": он покрывает и конкретный топик, и
	// маски вида devices/# или devices/+/telemetry. Более широкие шаблоны
	// (в том числе "#") отклоняются намеренно — подписчик должен получать
	// только телеметрию и события, а не всё, что окажется на брокере.
	if strings.HasPrefix(topic, "devices/") {
		return true
	}
	h.logger.Warn("отклонена подписка на посторонний топик",
		"remote", cl.Net.Remote, "topic", topic)
	return false
}
