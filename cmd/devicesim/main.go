// cmd/devicesim запускает симулятор IoT-устройства как ОТДЕЛЬНЫЙ процесс,
// который реально подключается по сети к работающему cmd/gatewayd. Вся
// логика — в internal/emulator; этот файл лишь читает конфигурацию из
// переменных окружения и корректно завершается по Ctrl+C/SIGTERM.
//
// Тот же internal/emulator используется и встроенно внутри cmd/gatewayd
// (см. LACERT_EMULATE_DEVICES там) — так что отдельный процесс devicesim
// нужен только тогда, когда хочется погонять эмулированное устройство с
// другой машины/контейнера, по-настоящему отдельно от шлюза.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/emulator"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := emulator.Config{
		GatewayHTTP:  getenv("LACERT_GATEWAY_HTTP", "http://localhost:8080"),
		GatewayTCP:   getenv("LACERT_GATEWAY_TCP", "localhost:7700"),
		DeviceID:     getenv("LACERT_DEVICE_ID", "xiao-esp32c6-sim-1"),
		AdminToken:   os.Getenv("LACERT_ADMIN_TOKEN"),
		SendInterval: 2 * time.Second,
		SigAlgorithm: crypto.SigECDSAP256,
		// LACERT_PROFILE: climate|power|pressure|fuel|motor. Если не задан —
		// выбирается детерминированно по хешу LACERT_DEVICE_ID (см.
		// internal/emulator.profileForDeviceID), так что отдельный запуск
		// devicesim без этой переменной всё равно получит осмысленный
		// набор полей телеметрии, а не ошибку.
		Profile: emulator.Profile(os.Getenv("LACERT_PROFILE")),
		Logger:  logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := emulator.Run(ctx, cfg); err != nil {
		logger.Error("эмулятор устройства завершился с ошибкой", "err", err)
		os.Exit(1)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
