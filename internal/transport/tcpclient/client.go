// Package tcpclient реализует сетевой транспорт устройства поверх TCP —
// клиентская сторона, симметричная internal/transport/tcpserver. На реальном
// устройстве (ESP32) это будет переписано на lwIP-сокеты в среде ESP-IDF;
// сам протокол обмена кадрами (internal/wire) при этом не меняется.
package tcpclient

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"lacert/internal/device"
	"lacert/internal/wire"
)

// Client — TCP-клиент устройства с установленным защищённым каналом к шлюзу.
type Client struct {
	Dev    *device.Device
	Logger *slog.Logger

	conn net.Conn
	mu   sync.Mutex // защищает запись в conn (рукопожатие/данные пишут последовательно)

	// OnFirmwareCheckFailed вызывается, если шлюз сообщил об отказе после
	// проверки целостности прошивки (соединение в этот момент уже закрывается).
	OnFirmwareCheckFailed func(reason string)
}

// Dial подключается к шлюзу по addr и выполняет полное рукопожатие LACERT.
// После успешного возврата канал готов для SendData/ResendRotationIfNeeded.
func Dial(addr string, dev *device.Device, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	// Клиент ожидает, что device_id уже присутствует в базовом логгере
	// (вызывающая сторона передаёт logger.With("device_id", ...)). Поэтому
	// индивидуальные вызовы лога ниже его не повторяют — иначе поле
	// дублировалось бы. Если логгер без device_id — добавим его один раз здесь.
	logger = logger.With("device_id", dev.ID)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial gateway %s: %w", addr, err)
	}

	c := &Client{Dev: dev, Logger: logger, conn: conn}
	if err := c.handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return c, nil
}

func (c *Client) handshake() error {
	msg1, err := c.Dev.StartHandshake()
	if err != nil {
		return fmt.Errorf("start handshake: %w", err)
	}
	if err := wire.WriteFrame(c.conn, wire.TypeHandshakeMsg1, wire.EncodeMsg1(msg1)); err != nil {
		return fmt.Errorf("send msg1: %w", err)
	}

	msgType, payload, err := wire.ReadFrame(c.conn)
	if err != nil {
		return fmt.Errorf("read msg2: %w", err)
	}
	if msgType == wire.TypeError {
		return fmt.Errorf("gateway rejected handshake: %s", wire.DecodeErrorMsg(payload))
	}
	if msgType != wire.TypeHandshakeMsg2 {
		return fmt.Errorf("unexpected message type %d while waiting for Msg2", msgType)
	}
	msg2, err := wire.DecodeMsg2(payload)
	if err != nil {
		return fmt.Errorf("decode msg2: %w", err)
	}

	msg3, err := c.Dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		return fmt.Errorf("complete handshake: %w", err)
	}
	if err := wire.WriteFrame(c.conn, wire.TypeHandshakeMsg3, wire.EncodeMsg3(msg3)); err != nil {
		return fmt.Errorf("send msg3: %w", err)
	}

	c.Logger.Info("рукопожатие завершено, защищённый канал установлен")
	return nil
}

// SendData шифрует и отправляет один пакет прикладных данных.
func (c *Client) SendData(plaintext []byte) error {
	nonce, ciphertext, err := c.Dev.SendData(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.WriteFrame(c.conn, wire.TypeData, wire.EncodeData(nonce, ciphertext))
}

// RotateIfNeeded проверяет, не пора ли ротировать ключ (300 пакетов/300 сек),
// и если да — инициирует ротацию со стороны устройства.
func (c *Client) RotateIfNeeded() (rotated bool, err error) {
	if !c.Dev.NeedsRotation() {
		return false, nil
	}
	rotMsg, err := c.Dev.InitiateRotation()
	if err != nil {
		return false, fmt.Errorf("initiate rotation: %w", err)
	}
	c.mu.Lock()
	err = wire.WriteFrame(c.conn, wire.TypeRotation, wire.EncodeRotation(rotMsg))
	c.mu.Unlock()
	if err != nil {
		return false, fmt.Errorf("send rotation: %w", err)
	}
	c.Logger.Info("ротация ключа (инициатор: устройство) отправлена")
	return true, nil
}

// ForceAtomicRotation инициирует атомарную ротацию немедленно, без проверки
// NeedsRotation. Полезно для тестов и для ручного запуска ротации по внешнему
// событию (например, после подозрения на компрометацию).
func (c *Client) ForceAtomicRotation() error {
	rotMsg, err := c.Dev.InitiateAtomicRotation()
	if err != nil {
		return fmt.Errorf("initiate atomic rotation: %w", err)
	}
	// Ключ берётся до отправки: ротация вступит в силу только после
	// подтверждения от шлюза, и обе стороны считают метку одним ключом.
	key, err := c.Dev.ControlKey()
	if err != nil {
		return fmt.Errorf("session key for control tag: %w", err)
	}
	c.mu.Lock()
	err = wire.WriteFrame(c.conn, wire.TypeRotationV2, wire.EncodeRotationV2(rotMsg, key[:]))
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send atomic rotation: %w", err)
	}
	c.Logger.Info("атомарная ротация (инициатор: устройство, форсированная) отправлена",
		"iteration", rotMsg.Iteration)
	return nil
}

// RotateIfNeededAtomic — атомарный вариант RotateIfNeeded. Инициирует
// атомарную ротацию (с ACK): устройство отправляет RotationMsgV2 и продолжает
// слать данные под текущим ключом, пока не получит RotationAck (обрабатывается
// в Listen). Потеря сообщения ротации не рвёт связь.
func (c *Client) RotateIfNeededAtomic() (rotated bool, err error) {
	if !c.Dev.NeedsRotation() {
		return false, nil
	}
	rotMsg, err := c.Dev.InitiateAtomicRotation()
	if err != nil {
		return false, fmt.Errorf("initiate atomic rotation: %w", err)
	}
	// Ключ берётся до отправки: ротация вступит в силу только после
	// подтверждения от шлюза, и обе стороны считают метку одним ключом.
	key, err := c.Dev.ControlKey()
	if err != nil {
		return false, fmt.Errorf("session key for control tag: %w", err)
	}
	c.mu.Lock()
	err = wire.WriteFrame(c.conn, wire.TypeRotationV2, wire.EncodeRotationV2(rotMsg, key[:]))
	c.mu.Unlock()
	if err != nil {
		return false, fmt.Errorf("send atomic rotation: %w", err)
	}
	c.Logger.Info("атомарная ротация (инициатор: устройство) отправлена",
		"iteration", rotMsg.Iteration)
	return true, nil
}

// Listen блокирующе слушает входящие сообщения от шлюза: ротацию,
// инициированную шлюзом, и запросы проверки целостности прошивки. На
// реальном устройстве это выполнялось бы в отдельной задаче FreeRTOS.
// Возвращается при закрытии соединения или фатальной ошибке.
func (c *Client) Listen() error {
	for {
		msgType, payload, err := wire.ReadFrame(c.conn)
		if err != nil {
			return err
		}

		switch msgType {
		case wire.TypeRotation:
			rotMsg, err := wire.DecodeRotation(payload)
			if err != nil {
				c.Logger.Warn("не удалось декодировать сообщение ротации от шлюза", "err", err)
				continue
			}
			if err := c.Dev.HandleRotationFromGateway(rotMsg); err != nil {
				c.Logger.Warn("не удалось обработать ротацию от шлюза", "err", err)
				continue
			}
			c.Logger.Info("ротация ключа (инициатор: шлюз) применена")

		case wire.TypeRotationV2:
			// Шлюз инициировал атомарную ротацию: применяем и отвечаем ACK.
			//
			// Ключ берётся ДО применения ротации и используется дважды: для
			// проверки метки пришедшего кадра и для метки подтверждения.
			// После применения ключ станет новым, а шлюз проверит метку
			// прежним — поэтому порядок здесь существенен.
			key, err := c.Dev.ControlKey()
			if err != nil {
				c.Logger.Warn("нет сеансового ключа для проверки метки", "err", err)
				continue
			}
			rotMsg, err := wire.DecodeRotationV2(payload, key[:])
			if err != nil {
				c.Logger.Warn("не удалось декодировать атомарную ротацию от шлюза", "err", err)
				continue
			}
			ack, err := c.Dev.HandleAtomicRotationFromGateway(rotMsg)
			if err != nil {
				c.Logger.Warn("не удалось обработать атомарную ротацию от шлюза", "err", err)
				continue
			}
			c.mu.Lock()
			err = wire.WriteFrame(c.conn, wire.TypeRotationAck, wire.EncodeRotationAck(ack, key[:]))
			c.mu.Unlock()
			if err != nil {
				c.Logger.Warn("не удалось отправить ACK ротации", "err", err)
				continue
			}
			c.Logger.Info("атомарная ротация (инициатор: шлюз) применена, ACK отправлен",
				"iteration", ack.Iteration)

		case wire.TypeRotationAck:
			// Шлюз подтвердил ротацию, инициированную устройством: коммитим.
			// Ключ ещё прежний — ротация применится ниже, после проверки.
			key, err := c.Dev.ControlKey()
			if err != nil {
				c.Logger.Warn("нет сеансового ключа для проверки метки", "err", err)
				continue
			}
			ack, err := wire.DecodeRotationAck(payload, key[:])
			if err != nil {
				c.Logger.Warn("не удалось декодировать ACK ротации от шлюза", "err", err)
				continue
			}
			if err := c.Dev.ApplyRotationAckFromGateway(ack); err != nil {
				c.Logger.Warn("не удалось применить ACK ротации", "err", err)
				continue
			}
			c.Logger.Info("атомарная ротация (инициатор: устройство) подтверждена шлюзом",
				"iteration", ack.Iteration)

		case wire.TypeFirmwareChallenge:
			challenge, err := wire.DecodeFirmwareChallenge(payload)
			if err != nil {
				c.Logger.Warn("не удалось декодировать challenge", "err", err)
				continue
			}
			resp, err := c.Dev.RespondFirmwareChallenge(challenge)
			if err != nil {
				c.Logger.Warn("не удалось сформировать ответ на challenge", "err", err)
				continue
			}
			c.mu.Lock()
			err = wire.WriteFrame(c.conn, wire.TypeFirmwareResponse, wire.EncodeFirmwareResponse(resp))
			c.mu.Unlock()
			if err != nil {
				c.Logger.Warn("не удалось отправить ответ на проверку прошивки", "err", err)
			}

		case wire.TypeError:
			reason := wire.DecodeErrorMsg(payload)
			c.Logger.Warn("шлюз сообщил об ошибке", "reason", reason)
			if c.OnFirmwareCheckFailed != nil {
				c.OnFirmwareCheckFailed(reason)
			}
			return fmt.Errorf("gateway error: %s", reason)

		default:
			c.Logger.Warn("неизвестный тип сообщения от шлюза", "type", msgType)
		}
	}
}

// Close закрывает TCP-соединение и затирает ключи сессии устройства.
func (c *Client) Close() error {
	c.Dev.CloseSession()
	return c.conn.Close()
}
