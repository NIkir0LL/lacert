package emulator

import (
	"fmt"

	"lacert/internal/store"
)

// ResetDevices удаляет существующие регистрации для перечисленных device ID.
// Вызывается из cmd/gatewayd перед запуском встроенной эмуляции
// (LACERT_EMULATE_DEVICES) — каждый процесс-эмулятор генерирует НОВЫЕ
// identity/KEM ключи при старте, поэтому при персистентном хранилище
// (PostgreSQL) повторный запуск шлюза без этой очистки приводил бы к тому,
// что регистрация эмулированного устройства под тем же DeviceID постоянно
// отклонялась бы шлюзом как "устройство уже зарегистрировано"
// (store.ErrDeviceExists), и устройство навсегда оставалось бы offline —
// именно эта ситуация и была обнаружена и исправлена.
//
// Затрагивает только переданные ID (по умолчанию — "emulated-esp32-N"),
// то есть никак не задевает регистрации настоящих устройств.
func ResetDevices(s store.DeviceStore, deviceIDs []string) error {
	for _, id := range deviceIDs {
		if err := s.Delete(id); err != nil {
			return fmt.Errorf("reset device %q: %w", id, err)
		}
	}
	return nil
}
