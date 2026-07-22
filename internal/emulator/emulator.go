// Package emulator реализует логику программного устройства, которое
// ведёт себя по сети ТОЧНО так же, как настоящая плата ESP32 с прошивкой
// LACERT: регистрируется через REST API, устанавливает защищённый канал по
// TCP (тот же internal/wire-протокол, internal/transport/tcpclient), шлёт
// телеметрию, сама инициирует ротацию ключа по лимиту пакетов/времени и
// отвечает на ротации/проверки целостности прошивки, инициированные шлюзом.
//
// Этот пакет используется ДВУМЯ способами одним и тем же кодом:
//   - как отдельный процесс cmd/devicesim — для тестирования шлюза по
//     настоящей сети, с другой машины или в соседнем терминале;
//   - встроенно внутри cmd/gatewayd (см. LACERT_EMULATE_DEVICES) — чтобы
//     демонстрационный/тестовый стенд поднимался ОДНИМ бинарником без
//     необходимости отдельно запускать devicesim.
//
// Важно: ни шлюз, ни сам протокол НИКАК не отличают эмулированное
// устройство от настоящего ESP32 — оба говорят по одному и тому же
// TCP/REST протоколу. Поэтому при переходе на тестирование с реальными
// платами достаточно выключить эмуляцию (убрать LACERT_EMULATE_DEVICES или
// не запускать cmd/devicesim) — ни строчки в шлюзе менять не нужно.
package emulator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/transport/tcpclient"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// Config — параметры одного эмулируемого устройства.
type Config struct {
	GatewayHTTP   string              // например, "http://localhost:8080"
	GatewayTCP    string              // например, "localhost:7700"
	DeviceID      string              // уникальный идентификатор устройства
	AdminToken    string              // если REST API шлюза защищён токеном
	SendInterval  time.Duration       // период отправки телеметрии (по умолчанию 2с)
	SigAlgorithm  crypto.SigAlgorithm // по умолчанию ECDSA P-256
	FirmwareImage []byte              // "прошивка" устройства; по умолчанию — типовая заглушка
	Logger        *slog.Logger

	// Profile — тип эмулируемого датчика (климат/электросчётчик/давление/
	// топливо/мотор, см. profiles.go), определяющий набор полей телеметрии
	// и характер их изменения во времени. Если не задан, выбирается
	// детерминированно по хешу DeviceID — так что несколько эмулированных
	// устройств с разными ID автоматически получают визуально разные
	// графики, даже если вызывающий код (например, cmd/devicesim) явно
	// профиль не указал.
	Profile Profile

	// ConnectTimeout — сколько ждать поднятия шлюза (REST + TCP) перед тем,
	// как сдаться. Полезно, когда эмулятор запускается параллельно со
	// шлюзом в одном процессе (cmd/gatewayd) и стартует на долю секунды
	// раньше, чем слушатели шлюза успевают забиндить порты.
	ConnectTimeout time.Duration
}

func (c *Config) setDefaults() {
	if c.GatewayHTTP == "" {
		c.GatewayHTTP = "http://localhost:8080"
	}
	if c.GatewayTCP == "" {
		c.GatewayTCP = "localhost:7700"
	}
	if c.DeviceID == "" {
		c.DeviceID = "emulated-esp32-1"
	}
	if c.SendInterval <= 0 {
		c.SendInterval = 2 * time.Second
	}
	if len(c.FirmwareImage) == 0 {
		c.FirmwareImage = []byte("LACERT-firmware-v1.0.0-emulated-stub")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 30 * time.Second
	}
	if c.Profile == "" {
		c.Profile = profileForDeviceID(c.DeviceID)
	}
}

// Run запускает один эмулируемый прибор: подготовка ключей → провижининг →
// регистрация → рукопожатие → бесконечный цикл телеметрии/ротации. Блокируется
// до отмены ctx или фатальной ошибки канала со шлюзом.
func Run(ctx context.Context, cfg Config) error {
	cfg.setDefaults()
	logger := cfg.Logger.With("device_id", cfg.DeviceID)

	dev, err := device.NewDevice(cfg.DeviceID, cfg.SigAlgorithm, cfg.FirmwareImage)
	if err != nil {
		return fmt.Errorf("prepare device (efuse keys): %w", err)
	}
	logger.Info("устройство подготовлено (efuse-ключи сгенерированы)")

	gwKEMPub, err := fetchGatewayKEMPubWithRetry(ctx, cfg.GatewayHTTP, cfg.ConnectTimeout, logger)
	if err != nil {
		return fmt.Errorf("fetch gateway kem pubkey: %w", err)
	}
	dev.SetGatewayKEMPublicKey(gwKEMPub)

	if err := registerWithRetry(ctx, cfg.GatewayHTTP, dev, cfg.AdminToken, cfg.ConnectTimeout, logger); err != nil {
		return fmt.Errorf("register via REST: %w", err)
	}
	logger.Info("устройство зарегистрировано на шлюзе через REST API")

	// В tcpclient.Dial логгер получает device_id сам, поэтому сюда передаём
	// исходный cfg.Logger (без device_id), чтобы поле не задвоилось в логах
	// клиента.
	client, err := dialWithRetry(ctx, cfg.GatewayTCP, dev, cfg.ConnectTimeout, cfg.Logger)
	if err != nil {
		return fmt.Errorf("dial gateway TCP: %w", err)
	}
	defer client.Close()

	listenErrCh := make(chan error, 1)
	go func() { listenErrCh <- client.Listen() }()

	logger.Info("отправка телеметрии запущена", "interval", cfg.SendInterval, "profile", cfg.Profile)
	ticker := time.NewTicker(cfg.SendInterval)
	defer ticker.Stop()

	gen := newTelemetryGenerator(cfg.DeviceID, cfg.Profile)
	seq := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-listenErrCh:
			return fmt.Errorf("gateway connection closed: %w", err)
		case <-ticker.C:
			seq++
			payload := []byte(gen.Next(seq))
			if err := client.SendData(payload); err != nil {
				return fmt.Errorf("send data: %w", err)
			}
			logger.Info("телеметрия отправлена", "payload", string(payload))

			// Ротацию инициирует ТОЛЬКО шлюз (через планировщик, см.
			// internal/scheduler): у ротации должен быть единственный
			// инициатор. Если бы устройство тоже запускало ротацию по своему
			// таймеру, две ротации сталкивались бы (обе стороны почти
			// одновременно переходят в pending-состояние на одну и ту же
			// итерацию), встречная ротация не могла бы начаться, ACK не
			// приходил бы, и попытки бесконечно откатывались бы по тайм-ауту,
			// накапливая «неуспешные ротации». Поэтому устройство здесь только
			// ОТВЕЧАЕТ на ротацию, инициированную шлюзом (обрабатывается в
			// client.Listen как TypeRotationV2), а само не инициирует.
		}
	}
}

// --- сетевые операции с повторными попытками (устойчивость к тому, что
// шлюз мог ещё не успеть поднять REST/TCP слушатели) ---

const retryDelay = 300 * time.Millisecond

func fetchGatewayKEMPubWithRetry(ctx context.Context, httpBase string, timeout time.Duration, logger *slog.Logger) (*mlkem1024.PublicKey, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		pub, err := fetchGatewayKEMPub(httpBase)
		if err == nil {
			return pub, nil
		}
		lastErr = err
		logger.Debug("шлюз пока недоступен (REST), повторная попытка", "err", err)
		if !sleepOrDone(ctx, retryDelay) {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("timed out waiting for gateway REST API: %w", lastErr)
}

func fetchGatewayKEMPub(httpBase string) (*mlkem1024.PublicKey, error) {
	resp, err := http.Get(httpBase + "/api/v1/gateway")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var out struct {
		KEMPubHex string `json:"kem_pub_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(out.KEMPubHex)
	if err != nil {
		return nil, err
	}
	return crypto.UnpackKEMPublicKey(raw)
}

func registerWithRetry(ctx context.Context, httpBase string, dev *device.Device, adminToken string, timeout time.Duration, logger *slog.Logger) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		err := registerViaREST(httpBase, dev, adminToken)
		if err == nil {
			return nil
		}
		lastErr = err
		logger.Debug("регистрация пока не удалась, повторная попытка", "err", err)
		if !sleepOrDone(ctx, retryDelay) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("timed out registering device: %w", lastErr)
}

func registerViaREST(httpBase string, dev *device.Device, adminToken string) error {
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"device_id":         serial.DeviceID,
		"identity_pub_hex":  hex.EncodeToString(serial.IdentityPub),
		"kem_pub_hex":       hex.EncodeToString(serial.KEMPub),
		"firmware_hash_hex": hex.EncodeToString(serial.FirmwareHash[:]),
		"checksum":          serial.Checksum,
		// Имя схемы берётся у самого ключа, а не из конфигурации: так
		// объявленный алгоритм не может разойтись с тем, которым устройство
		// реально подписывает. Раньше здесь стояло безусловное "ecdsa-p256",
		// из-за чего поле Config.SigAlgorithm фактически не работало —
		// устройство генерировало ключ выбранной схемы, регистрировалось как
		// ECDSA, и шлюз отвергал рукопожатие с сообщением про неверный
		// открытый ключ ECDSA.
		"sig_algorithm": dev.Identity.Algorithm.APIName(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, httpBase+"/api/v1/devices", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed: status %d", resp.StatusCode)
	}
	return nil
}

func dialWithRetry(ctx context.Context, tcpAddr string, dev *device.Device, timeout time.Duration, logger *slog.Logger) (*tcpclient.Client, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := tcpclient.Dial(tcpAddr, dev, logger)
		if err == nil {
			return client, nil
		}
		lastErr = err
		logger.Debug("шлюз пока недоступен (TCP), повторная попытка", "err", err)
		if !sleepOrDone(ctx, retryDelay) {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("timed out dialing gateway TCP: %w", lastErr)
}

// sleepOrDone ждёт d или отмены ctx — возвращает false, если ctx был отменён
// раньше истечения d (вызывающий код должен немедленно прекратить попытки).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// --- Экспортированные помощники для внешних инструментов (напр. cmd/stresstest),
// которым нужно зарегистрировать устройство и получить публичный ключ шлюза,
// а затем работать с транспортом напрямую. ---

// FetchGatewayKEMPublicKey получает публичный ML-KEM ключ работающего шлюза по
// его HTTP-адресу (например "http://localhost:8080").
func FetchGatewayKEMPublicKey(httpBase string) (*mlkem1024.PublicKey, error) {
	return fetchGatewayKEMPub(httpBase)
}

// RegisterDeviceViaREST регистрирует устройство на работающем шлюзе через REST
// (эквивалент «офлайн-регистрации по серийнику»). adminToken можно оставить
// пустым, если шлюз запущен без LACERT_ADMIN_TOKEN.
func RegisterDeviceViaREST(httpBase string, dev *device.Device, adminToken string) error {
	return registerViaREST(httpBase, dev, adminToken)
}
