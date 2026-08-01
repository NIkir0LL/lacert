// cmd/gatewayd — полноценный локальный шлюз протокола LACERT: принимает
// защищённые TCP-соединения от устройств, обслуживает REST API для
// администрирования и интеграции с корпоративной системой, публикует
// расшифрованную телеметрию во встроенный MQTT-брокер и в фоне следит за
// необходимостью ротации ключей и часовой проверки целостности прошивки.
//
// Это прямая реализация архитектуры "Локальный шлюз" из текста работы —
// единственное, чего здесь по-прежнему нет, это переноса на реальные платы
// ESP32 (см. README.md, раздел "Чего здесь пока нет").
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lacert/internal/api"
	"lacert/internal/crypto"
	"lacert/internal/emulator"
	"lacert/internal/gateway"
	"lacert/internal/mqttbridge"
	"lacert/internal/scheduler"
	"lacert/internal/store"
	"lacert/internal/store/pgstore"
	"lacert/internal/transport/tcpserver"
	"lacert/internal/webui"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tcpAddr := getenv("LACERT_TCP_ADDR", ":7700")
	httpAddr := getenv("LACERT_HTTP_ADDR", ":8080")
	mqttAddr := getenv("LACERT_MQTT_ADDR", ":1883")
	pgDSN := os.Getenv("LACERT_PG_DSN")
	adminToken := os.Getenv("LACERT_ADMIN_TOKEN")
	var corsOrigins []string
	if v := os.Getenv("LACERT_CORS_ORIGINS"); v != "" {
		corsOrigins = strings.Split(v, ",")
	}

	// LACERT_EMULATE_DEVICES — см. внутренний пакет internal/emulator: при
	// значении > 0 шлюз сам поднимает указанное число программных
	// "устройств", которые подключаются к нему по тому же TCP/REST
	// протоколу, что и настоящий ESP32. Удобно для демонстрации/тестов
	// одним бинарником без отдельного запуска cmd/devicesim. При переходе
	// на тестирование с реальными платами просто не задавайте эту
	// переменную (или укажите 0) — ни шлюз, ни протокол менять не нужно.
	var emulateCount int
	if v := os.Getenv("LACERT_EMULATE_DEVICES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			logger.Warn("LACERT_EMULATE_DEVICES задан, но не является числом — эмуляция не будет запущена", "value", v, "err", err)
		} else {
			emulateCount = n
		}
	}
	emulateInterval := 2 * time.Second
	if v := os.Getenv("LACERT_EMULATE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			logger.Warn("LACERT_EMULATE_INTERVAL задан, но не распознан как длительность — используется значение по умолчанию (2s)", "value", v, "err", err)
		} else {
			emulateInterval = d
		}
	}

	var devStore store.DeviceStore
	if pgDSN != "" {
		pg, err := pgstore.Open(pgDSN)
		if err != nil {
			logger.Error("не удалось подключиться к PostgreSQL, переключаюсь на in-memory хранилище", "err", err)
			devStore = store.New()
		} else {
			logger.Info("используется хранилище PostgreSQL")
			devStore = pg
		}
	} else {
		logger.Info("LACERT_PG_DSN не задан — используется in-memory хранилище (данные не переживут перезапуск)")
		devStore = store.New()
	}

	gw, err := gateway.NewWithStore(devStore)
	if err != nil {
		logger.Error("не удалось создать шлюз", "err", err)
		os.Exit(1)
	}
	if v := os.Getenv("LACERT_LOG_SESSION_KEYS"); v != "" {
		logSessionKeys, err := strconv.ParseBool(v)
		if err != nil {
			logger.Warn("LACERT_LOG_SESSION_KEYS задан, но не распознан как true/false — тестовый режим НЕ включён", "value", v, "err", err)
		} else if logSessionKeys {
			gw.LogSessionKeys = true
			logger.Warn("LACERT_LOG_SESSION_KEYS включён — журнал ротаций будет содержать ПОЛНЫЕ значения сеансовых ключей. Используйте только в тестовой среде, никогда в проде")
		}
	}

	mqttBroker, err := mqttbridge.New(mqttAddr)
	if err != nil {
		logger.Error("не удалось создать MQTT-брокер", "err", err)
		os.Exit(1)
	}

	tcpSrv := tcpserver.New(gw, logger)
	tcpSrv.OnData = func(deviceID string, plaintext []byte) {
		if err := mqttBroker.PublishTelemetry(deviceID, plaintext); err != nil {
			logger.Warn("не удалось опубликовать телеметрию в MQTT", "device_id", deviceID, "err", err)
		}
	}

	restSrv := api.New(gw, api.Options{
		TCPStatus:      tcpSrv,
		AdminToken:     adminToken,
		AllowedOrigins: corsOrigins,
	})
	if restSrv.AuthMode() == "disabled" {
		logger.Warn("LACERT_ADMIN_TOKEN не задан — REST API администрирования доступен БЕЗ аутентификации; не используйте так в проде")
	}
	webui.Mount(restSrv.Router)
	// Тайм-ауты обязательны: без них медленный (или враждебный) клиент может
	// держать соединение сколь угодно долго, не досылая запрос, и постепенно
	// исчерпать ресурсы сервера (slowloris). http.Server по умолчанию НЕ
	// выставляет никаких тайм-аутов.
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: restSrv,
		// Сколько ждём заголовки запроса.
		ReadHeaderTimeout: 10 * time.Second,
		// Полное время на чтение запроса (заголовки + тело). Тела у нас
		// небольшие — регистрация устройства это единицы килобайт.
		ReadTimeout: 30 * time.Second,
		// Время на запись ответа. Дашборд отдаёт JSON и статику, долгих
		// потоковых ответов нет.
		WriteTimeout: 60 * time.Second,
		// Сколько держать keep-alive соединение без запросов.
		IdleTimeout: 120 * time.Second,
		// Ограничение на заголовки — защита от раздутых заголовков.
		MaxHeaderBytes: 1 << 20, // 1 МБ
	}

	sched := scheduler.New(gw, tcpSrv, logger)
	// Ускоренные интервалы для тестов/демонстрации (напр. живой стресс-тест):
	// LACERT_FIRMWARE_INTERVAL — как часто проверять прошивку (по умолч. 1ч),
	// LACERT_ROTATION_CHECK_PERIOD — частота опроса планировщика (по умолч. 5с).
	if v := os.Getenv("LACERT_ROTATION_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			crypto.RotationInterval = d
			logger.Info("интервал ротации ключа переопределён", "interval", d)
		}
	}
	if v := os.Getenv("LACERT_ROTATION_PACKET_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			crypto.RotationPacketLimit = n
			logger.Info("лимит пакетов до ротации переопределён", "limit", n)
		}
	}
	if v := os.Getenv("LACERT_NONCE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			crypto.DefaultNonceTTL = d
			logger.Info("TTL nonce replay-защиты переопределён", "ttl", d)
		}
	}
	if v := os.Getenv("LACERT_MAX_CONNECTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			tcpserver.MaxConnections = n
			logger.Info("предел одновременных соединений переопределён", "limit", n)
		}
	}
	if v := os.Getenv("LACERT_PENDING_HANDSHAKE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			gateway.SetPendingHandshakeTimeout(d)
			logger.Info("тайм-аут незавершённого рукопожатия переопределён", "timeout", d)
		}
	}
	if v := os.Getenv("LACERT_FIRMWARE_CHALLENGE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			gateway.SetFirmwareChallengeTimeout(d)
			logger.Info("тайм-аут повторной выдачи firmware-challenge переопределён", "timeout", d)
		}
	}
	if v := os.Getenv("LACERT_ROTATION_ACK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			crypto.RotationAckTimeout = d
			logger.Info("тайм-аут ACK ротации переопределён", "timeout", d)
		}
	}
	if v := os.Getenv("LACERT_FIRMWARE_VALIDITY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			gateway.SetFirmwareResponseValidity(d)
			logger.Info("окно валидности ответа на проверку прошивки переопределено", "validity", d)
		}
	}
	if v := os.Getenv("LACERT_FIRMWARE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			sched.FirmwareInterval = d
			logger.Info("интервал проверки прошивки переопределён", "interval", d)
		}
	}
	if v := os.Getenv("LACERT_ROTATION_CHECK_PERIOD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			sched.RotationCheckPeriod = d
			logger.Info("период опроса планировщика переопределён", "period", d)
		}
	}
	if v := os.Getenv("LACERT_MAX_ROTATION_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sched.MaxRotationFailures = n
			logger.Info("порог отзыва по неуспешным ротациям переопределён", "max", n)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := mqttBroker.Serve(); err != nil {
			logger.Error("mqtt broker остановлен с ошибкой", "err", err)
		}
	}()
	go func() {
		logger.Info("REST API запущен", "addr", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("REST API остановлен с ошибкой", "err", err)
		}
	}()
	go sched.Run(ctx)
	go func() {
		if err := tcpSrv.ListenAndServe(tcpAddr); err != nil {
			logger.Error("TCP-сервер шлюза остановлен с ошибкой", "err", err)
		}
	}()

	logger.Info("шлюз LACERT запущен",
		"tcp_addr", tcpAddr, "http_addr", httpAddr, "mqtt_addr", mqttAddr)

	if emulateCount > 0 {
		logger.Warn("включена встроенная эмуляция ESP32-устройств — для прода с реальными платами уберите LACERT_EMULATE_DEVICES",
			"count", emulateCount, "interval", emulateInterval)

		emulatedIDs := make([]string, 0, emulateCount)
		for i := 1; i <= emulateCount; i++ {
			emulatedIDs = append(emulatedIDs, fmt.Sprintf("emulated-esp32-%d", i))
		}
		// Эмулятор генерирует НОВЫЕ identity/KEM ключи при каждом запуске
		// процесса. При персистентном хранилище (PostgreSQL) без этой
		// очистки повторная регистрация под тем же DeviceID отклонялась бы
		// шлюзом как "устройство уже зарегистрировано", и эмулированные
		// устройства навсегда оставались бы offline после любого
		// перезапуска шлюза — см. internal/emulator.ResetDevices.
		if err := emulator.ResetDevices(gw.Store, emulatedIDs); err != nil {
			logger.Error("не удалось очистить устаревшие регистрации эмулированных устройств — они могут остаться offline", "err", err)
		}

		selfHTTP := "http://localhost" + httpAddr
		selfTCP := "localhost" + tcpAddr
		for i, deviceID := range emulatedIDs {
			cfg := emulator.Config{
				GatewayHTTP:  selfHTTP,
				GatewayTCP:   selfTCP,
				DeviceID:     deviceID,
				AdminToken:   adminToken,
				SendInterval: emulateInterval,
				Profile:      emulator.ProfileForIndex(i + 1), // циклически по типам приборов: климат/электросчётчик/давление/топливо/мотор
				Logger:       logger,
			}
			go func() {
				if err := emulator.Run(ctx, cfg); err != nil && ctx.Err() == nil {
					logger.Error("эмулятор устройства завершился с ошибкой", "device_id", cfg.DeviceID, "err", err)
				}
			}()
		}
	}

	<-ctx.Done()
	logger.Info("получен сигнал остановки, завершаем работу...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	_ = mqttBroker.Close()
	if err := tcpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("TCP-сервер не успел корректно завершиться в отведённое время", "err", err)
	}
	// После закрытия сетевых слушателей затираем ключи всех активных сессий —
	// ключевой материал не должен оставаться в памяти после остановки.
	closed := gw.Shutdown()
	logger.Info("сессии закрыты, ключи затёрты", "closed_sessions", closed)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
