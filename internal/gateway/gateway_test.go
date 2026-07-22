package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/regtool"
	"lacert/internal/store"
)

// newRegisteredDevice — вспомогательная функция: создаёт устройство,
// проходит офлайн-регистрацию на шлюзе и настраивает у устройства известный
// публичный ключ шлюза (как это было бы сделано при провижининге).
func newRegisteredDevice(t *testing.T, gw *Gateway, id string, alg crypto.SigAlgorithm, firmware []byte) *device.Device {
	t.Helper()

	dev, err := device.NewDevice(id, alg, firmware)
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())

	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	if err := gw.RegisterDevice(serial, alg); err != nil {
		t.Fatalf("register device: %v", err)
	}
	return dev
}

// runHandshake — выполняет полный обмен Msg1/Msg2/Msg3 между устройством и
// шлюзом так, как это происходило бы по сети.
func runHandshake(t *testing.T, gw *Gateway, dev *device.Device) {
	t.Helper()

	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("device start handshake: %v", err)
	}
	msg2, err := gw.HandleMsg1(msg1)
	if err != nil {
		t.Fatalf("gateway handle msg1: %v", err)
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("device complete handshake: %v", err)
	}
	if err := gw.HandleMsg3(dev.ID, msg3); err != nil {
		t.Fatalf("gateway handle msg3: %v", err)
	}
}

func TestFullLifecycle_RegistrationHandshakeDataRotation(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	firmware := []byte("firmware-image-v1.0.0")
	dev := newRegisteredDevice(t, gw, "esp32-c6-001", crypto.SigECDSAP256, firmware)

	runHandshake(t, gw, dev)

	if !dev.HasSession() {
		t.Fatal("device should have an active session after handshake")
	}

	// Передача данных в течение нескольких пакетов (без ротации).
	for i := 0; i < 5; i++ {
		plaintext := []byte("sensor-reading")
		nonce, ct, err := dev.SendData(plaintext)
		if err != nil {
			t.Fatalf("device send data: %v", err)
		}
		got, err := gw.HandleData(dev.ID, nonce, ct)
		if err != nil {
			t.Fatalf("gateway handle data: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
		}
	}

	// Доводим счётчик пакетов до лимита ротации (300) и проверяем, что
	// устройство понимает, что пора ротировать.
	for dev.SessionStats().PacketCount < crypto.RotationPacketLimit {
		_, ct, err := dev.SendData([]byte("x"))
		if err != nil {
			t.Fatalf("device send data: %v", err)
		}
		_ = ct
	}
	if !dev.NeedsRotation() {
		t.Fatal("device should need rotation after reaching packet limit")
	}

	// Устройство инициирует ротацию.
	rotMsg, err := dev.InitiateRotation()
	if err != nil {
		t.Fatalf("device initiate rotation: %v", err)
	}
	if err := gw.HandleRotationFromDevice(dev.ID, rotMsg); err != nil {
		t.Fatalf("gateway handle rotation: %v", err)
	}

	if dev.NeedsRotation() {
		t.Fatal("device should not need rotation right after rotating")
	}
	if dev.SessionStats().PacketCount != 0 {
		t.Fatalf("packet count should reset after rotation, got %d", dev.SessionStats().PacketCount)
	}

	// После ротации канал должен продолжать работать без разрыва соединения.
	plaintext := []byte("post-rotation-data")
	nonce, ct, err := dev.SendData(plaintext)
	if err != nil {
		t.Fatalf("device send data after rotation: %v", err)
	}
	got, err := gw.HandleData(dev.ID, nonce, ct)
	if err != nil {
		t.Fatalf("gateway handle data after rotation: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("post-rotation plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestGatewayInitiatedRotation(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-image-v1.0.0")
	dev := newRegisteredDevice(t, gw, "esp32-s3-002", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	rotMsg, err := gw.InitiateRotationToDevice(dev.ID)
	if err != nil {
		t.Fatalf("gateway initiate rotation: %v", err)
	}
	if err := dev.HandleRotationFromGateway(rotMsg); err != nil {
		t.Fatalf("device handle rotation from gateway: %v", err)
	}

	// Канал должен продолжать работать тем же новым ключом на обеих сторонах.
	plaintext := []byte("after-gateway-initiated-rotation")
	nonce, ct, err := dev.SendData(plaintext)
	if err != nil {
		t.Fatalf("device send data: %v", err)
	}
	got, err := gw.HandleData(dev.ID, nonce, ct)
	if err != nil {
		t.Fatalf("gateway handle data: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestFirmwareCheckPassesWhenUnmodified(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-image-v1.0.0")
	dev := newRegisteredDevice(t, gw, "esp32-c6-003", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	challenge, err := gw.IssueFirmwareChallenge(dev.ID)
	if err != nil {
		t.Fatalf("issue firmware challenge: %v", err)
	}
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("device respond to firmware challenge: %v", err)
	}
	result, err := gw.VerifyFirmwareCheck(dev.ID, resp)
	if err != nil {
		t.Fatalf("verify firmware check: %v", err)
	}
	if !result.OK() {
		t.Fatalf("expected firmware check to pass, got %+v", result)
	}

	if _, err := gw.Store.Get(dev.ID); err != nil {
		t.Fatalf("device should still be trusted after passing firmware check: %v", err)
	}
}

func TestFirmwareCheckRevokesDeviceOnTamperedFirmware(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-image-v1.0.0")
	dev := newRegisteredDevice(t, gw, "esp32-c6-004", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	// Имитация несанкционированной подмены прошивки на устройстве ПОСЛЕ
	// регистрации (например, злоумышленник перепрошил устройство).
	dev.TamperFirmware([]byte("-malicious-patch"))

	challenge, err := gw.IssueFirmwareChallenge(dev.ID)
	if err != nil {
		t.Fatalf("issue firmware challenge: %v", err)
	}
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("device respond to firmware challenge: %v", err)
	}
	result, err := gw.VerifyFirmwareCheck(dev.ID, resp)
	if err != nil {
		t.Fatalf("verify firmware check: %v", err)
	}
	if result.OK() {
		t.Fatal("expected firmware check to fail after tampering")
	}
	if !result.SignatureValid {
		t.Fatal("signature should still be valid (the device itself is honest about its current state)")
	}
	if result.HashMatches {
		t.Fatal("hash should not match the reference after tampering")
	}

	// Устройство должно быть отозвано.
	_, err = gw.Store.Get(dev.ID)
	if err != store.ErrDeviceRevoked {
		t.Fatalf("expected device to be revoked, got err=%v", err)
	}

	// Дальнейшие операции (например, новая ротация) с отозванным устройством
	// больше не должны быть возможны через активную сессию шлюза.
	if _, err := gw.InitiateRotationToDevice(dev.ID); err == nil {
		t.Fatal("expected rotation to fail for a revoked device (session should have been dropped)")
	}
}

func TestHandleDataRecordsTelemetry(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-telemetry-001", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	payload := []byte("temperature=23.5;humidity=41;status=ok")
	nonce, ct, err := dev.SendData(payload)
	if err != nil {
		t.Fatalf("device send data: %v", err)
	}
	if _, err := gw.HandleData(dev.ID, nonce, ct); err != nil {
		t.Fatalf("gateway handle data: %v", err)
	}

	latest, err := gw.Store.LatestTelemetry(dev.ID)
	if err != nil {
		t.Fatalf("latest telemetry: %v", err)
	}
	if latest == nil {
		t.Fatal("expected a telemetry reading to be recorded")
	}
	if latest.RawPayload != string(payload) {
		t.Fatalf("raw payload mismatch: got %q want %q", latest.RawPayload, payload)
	}
	if latest.Parsed["temperature"] != 23.5 || latest.Parsed["humidity"] != 41 {
		t.Fatalf("parsed values mismatch: %+v", latest.Parsed)
	}
	if _, ok := latest.Parsed["status"]; ok {
		t.Fatal("non-numeric field 'status' should not appear in parsed map")
	}
}

// failingTelemetryStore оборачивает обычное хранилище и заставляет падать
// только запись телеметрии — так проверяется поведение при недоступной базе,
// не ломая остальные операции (регистрацию, поиск устройства и т.п.).
type failingTelemetryStore struct {
	store.DeviceStore
}

func (f failingTelemetryStore) RecordTelemetry(store.TelemetryReading) error {
	return errors.New("storage unavailable")
}

// При отказе хранилища пакет всё равно должен быть обработан: устройство своё
// дело сделало, и обрывать сессию из-за проблем базы неправильно. Но потеря
// данных обязана быть заметной — иначе показания исчезали бы бесследно.
func TestHandleDataCountsDroppedTelemetry(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-drop-001", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	// Подменяем хранилище уже после регистрации и рукопожатия.
	gw.Store = failingTelemetryStore{DeviceStore: gw.Store}

	payload := []byte("temperature=23.5")
	nonce, ct, err := dev.SendData(payload)
	if err != nil {
		t.Fatalf("device send data: %v", err)
	}
	pt, err := gw.HandleData(dev.ID, nonce, ct)
	if err != nil {
		t.Fatalf("сбой хранилища не должен прерывать обработку пакета: %v", err)
	}
	if string(pt) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", pt, payload)
	}
	if got := gw.Metrics.Snapshot().TelemetryDropped; got != 1 {
		t.Fatalf("telemetry_dropped = %d, ожидалась 1", got)
	}
}

func TestRotationLoggedWithoutKeysByDefault(t *testing.T) {
	gw, err := New() // LogSessionKeys остаётся false по умолчанию
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-rotation-log-001", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	rotMsg, err := dev.InitiateRotation()
	if err != nil {
		t.Fatalf("device initiate rotation: %v", err)
	}
	if err := gw.HandleRotationFromDevice(dev.ID, rotMsg); err != nil {
		t.Fatalf("gateway handle rotation: %v", err)
	}

	history, err := gw.Store.RotationHistory(dev.ID, 0)
	if err != nil {
		t.Fatalf("rotation history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 rotation log entry, got %d", len(history))
	}
	entry := history[0]
	if !entry.Success {
		t.Fatalf("expected successful rotation, got %+v", entry)
	}
	if entry.Initiator != "device" {
		t.Fatalf("expected initiator=device, got %q", entry.Initiator)
	}
	if entry.OldKeyHex != "" || entry.NewKeyHex != "" {
		t.Fatalf("expected keys to be redacted by default (LogSessionKeys=false), got OldKeyHex=%q NewKeyHex=%q",
			entry.OldKeyHex, entry.NewKeyHex)
	}
	if entry.RotationCount != 1 {
		t.Fatalf("expected rotation_count=1, got %d", entry.RotationCount)
	}
}

func TestRotationLoggedWithFullKeysWhenEnabled(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.LogSessionKeys = true // тестовый режим, как описано в задаче

	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-rotation-log-002", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	rotMsg, err := gw.InitiateRotationToDevice(dev.ID)
	if err != nil {
		t.Fatalf("gateway initiate rotation: %v", err)
	}
	if err := dev.HandleRotationFromGateway(rotMsg); err != nil {
		t.Fatalf("device handle rotation: %v", err)
	}

	history, err := gw.Store.RotationHistory(dev.ID, 0)
	if err != nil {
		t.Fatalf("rotation history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 rotation log entry, got %d", len(history))
	}
	entry := history[0]
	if entry.Initiator != "gateway" {
		t.Fatalf("expected initiator=gateway, got %q", entry.Initiator)
	}
	if len(entry.OldKeyHex) != 64 || len(entry.NewKeyHex) != 64 {
		t.Fatalf("expected full 32-byte (64 hex char) keys when LogSessionKeys=true, got OldKeyHex=%q (%d) NewKeyHex=%q (%d)",
			entry.OldKeyHex, len(entry.OldKeyHex), entry.NewKeyHex, len(entry.NewKeyHex))
	}
	if entry.OldKeyHex == entry.NewKeyHex {
		t.Fatal("old and new key must differ after rotation")
	}
}

func TestFailedRotationIsLoggedAsUnsuccessful(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-rotation-fail-001", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	// Важно: у ML-KEM есть свойство "implicit rejection" — испорченный, но
	// правильной ДЛИНЫ шифротекст не вызывает ошибку decapsulate, а тихо
	// даёт другой (неверный) общий секрет — это намеренная защита от
	// padding-oracle-атак, а не баг. Поэтому, чтобы здесь действительно
	// получить ошибку (а не просто разойтись по ключу без видимого сбоя),
	// нужен шифротекст НЕВЕРНОЙ ДЛИНЫ.
	badMsg := &crypto.RotationMsg{KEMCiphertext: bytes.Repeat([]byte{0xFF}, 100)}
	if err := gw.HandleRotationFromDevice(dev.ID, badMsg); err == nil {
		t.Fatal("expected rotation with malformed-length ciphertext to fail")
	}

	history, err := gw.Store.RotationHistory(dev.ID, 0)
	if err != nil {
		t.Fatalf("rotation history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 rotation log entry (the failed attempt), got %d", len(history))
	}
	if history[0].Success {
		t.Fatal("expected logged rotation attempt to be marked unsuccessful")
	}
	if history[0].ErrorText == "" {
		t.Fatal("expected error text to be recorded for failed rotation")
	}
}

func TestRevokeDeviceClosesActiveSession(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	firmware := []byte("firmware-v1")
	dev := newRegisteredDevice(t, gw, "esp32-revoke-session-001", crypto.SigECDSAP256, firmware)
	runHandshake(t, gw, dev)

	// До отзыва устройство может нормально слать данные.
	nonce, ct, err := dev.SendData([]byte("before-revoke"))
	if err != nil {
		t.Fatalf("device send data before revoke: %v", err)
	}
	if _, err := gw.HandleData(dev.ID, nonce, ct); err != nil {
		t.Fatalf("gateway handle data before revoke: %v", err)
	}

	if err := gw.RevokeDevice(dev.ID, "manual test revoke"); err != nil {
		t.Fatalf("revoke device: %v", err)
	}

	// Устройство отмечено отозванным в хранилище.
	if _, err := gw.Store.Get(dev.ID); err != store.ErrDeviceRevoked {
		t.Fatalf("expected ErrDeviceRevoked after RevokeDevice, got %v", err)
	}

	// КЛЮЧЕВАЯ ПРОВЕРКА (регрессия найденного бага): активная сессия должна
	// быть закрыта — попытка расшифровать ЕЩЁ ОДИН пакет под тем же ключом
	// сессии должна провалиться, а не пройти как ни в чём не бывало. Раньше
	// RevokeDevice (точнее, прямой вызов Store.Revoke в REST-хендлере) не
	// трогал g.sessions, и устройство с уже установленным каналом
	// продолжало нормально работать сколь угодно долго после отзыва.
	nonce2, ct2, err := dev.SendData([]byte("after-revoke"))
	if err != nil {
		t.Fatalf("device-side encrypt (device doesn't know about revoke yet): %v", err)
	}
	if _, err := gw.HandleData(dev.ID, nonce2, ct2); err == nil {
		t.Fatal("expected gateway to reject data from a revoked device's now-closed session, but it succeeded")
	}

	// Попытка инициировать ротацию шлюзом для отозванного устройства тоже
	// должна проваливаться — сессии больше нет.
	if _, err := gw.InitiateRotationToDevice(dev.ID); err == nil {
		t.Fatal("expected rotation to fail for a revoked device with no active session")
	}
}

func TestRevokeDeviceIsIdempotentlyHandledForUnknownDevice(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if err := gw.RevokeDevice("never-registered", "test"); err == nil {
		t.Fatal("expected error revoking a device that was never registered")
	}
}

// TestRegisterDeviceRejectsInvalidKEMKeySize проверяет, что регистрация с
// KEM-ключом неверного размера (например, обрезанная hex-строка при ручном
// вводе через веб-форму) отклоняется СРАЗУ, с понятной ошибкой — а не
// молча создаёт "мёртвую" запись устройства, для которой первое же
// рукопожатие провалилось бы с гораздо менее очевидным сообщением.
func TestRegisterDeviceRejectsInvalidKEMKeySize(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev, err := device.NewDevice("esp32-bad-kem-key", crypto.SigECDSAP256, []byte("fw"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	// Обрезаем KEM-ключ (имитация опечатки/обрезанной строки при ручном
	// копировании в веб-форму) — валидный ML-KEM-1024 ключ должен быть
	// 1568 байт.
	serial.KEMPub = serial.KEMPub[:100]
	// Пересчитываем контрольную сумму, чтобы проверка checksum не
	// маскировала именно ту ошибку, которую мы здесь тестируем.
	serial.Checksum = regtool.ComputeChecksum(serial.DeviceID, serial.IdentityPub, serial.KEMPub, serial.FirmwareHash[:])

	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err == nil {
		t.Fatal("expected registration to fail immediately for a malformed KEM public key")
	}

	if _, err := gw.Store.Get("esp32-bad-kem-key"); err == nil {
		t.Fatal("device with invalid KEM key should not have been persisted to the store")
	}
}

// TestRegisterDeviceValidatesDeviceIDFormat — регрессия для найденной при
// аудите проблемы: device_id из REST-запроса регистрации ничем не был
// ограничен по составу символов и напрямую попадал (а) в путь REST API
// (/api/v1/devices/{deviceID}), (б) в MQTT-топик
// ("devices/{deviceID}/telemetry", см. internal/mqttbridge). Устройство с
// DeviceID вроде "a/#" реально ломало бы структуру MQTT-топиков и могло бы
// непредсказуемо взаимодействовать с чужими wildcard-подписками.
func TestRegisterDeviceValidatesDeviceIDFormat(t *testing.T) {
	badIDs := []string{
		"",                        // пусто
		"a/b",                     // '/' — разделитель уровня MQTT-топика
		"a/#",                     // '#' — MQTT multi-level wildcard
		"a/+/b",                   // '+' — MQTT single-level wildcard
		"device with spaces",      // пробелы — небезопасно в URL-путях без экранирования
		"../../etc/passwd",        // явная попытка path traversal
		string(make([]byte, 200)), // длиннее разумного предела (128 символов)
	}

	for _, badID := range badIDs {
		t.Run(fmt.Sprintf("rejects_%q", badID), func(t *testing.T) {
			gw, err := New()
			if err != nil {
				t.Fatalf("new gateway: %v", err)
			}
			dev, err := device.NewDevice(badID, crypto.SigECDSAP256, []byte("fw"))
			if err != nil {
				// device.NewDevice сам может не отказать (у него нет
				// причин на это — он ничего не знает о MQTT/REST) — тогда
				// проверяем отказ уже на RegisterDevice ниже.
				return
			}
			serial, err := dev.SerialRegistrationOutput()
			if err != nil {
				t.Fatalf("serial output: %v", err)
			}
			if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err == nil {
				t.Fatalf("expected RegisterDevice to reject device_id %q, but it succeeded", badID)
			}
		})
	}
}

func TestRegisterDeviceAcceptsLegitimateDeviceIDFormats(t *testing.T) {
	goodIDs := []string{
		"xiao-esp32c6-0001",
		"emulated-esp32-1",
		"sensor_42",
		"device.with.dots",
		"ABC123",
	}
	for _, goodID := range goodIDs {
		t.Run(goodID, func(t *testing.T) {
			gw, err := New()
			if err != nil {
				t.Fatalf("new gateway: %v", err)
			}
			dev, err := device.NewDevice(goodID, crypto.SigECDSAP256, []byte("fw"))
			if err != nil {
				t.Fatalf("new device: %v", err)
			}
			serial, err := dev.SerialRegistrationOutput()
			if err != nil {
				t.Fatalf("serial output: %v", err)
			}
			if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
				t.Fatalf("expected legitimate device_id %q to be accepted, got error: %v", goodID, err)
			}
		})
	}
}

func TestHandshakeFailsForUnregisteredDevice(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev, err := device.NewDevice("ghost-device", crypto.SigECDSAP256, []byte("fw"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1); err == nil {
		t.Fatal("expected handshake to fail for a device that was never registered")
	}
}

// TestHandleMsg1RejectsReplayedNonce — интеграционная проверка того, что
// защита от replay работает на уровне шлюза: записанное легитимное Msg1,
// отправленное повторно, отвергается, тогда как свежее рукопожатие того же
// устройства проходит. Это регрессия для найденной уязвимости (nonce из Msg1
// не проверялся).
func TestHandleMsg1RejectsReplayedNonce(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "device-replay", crypto.SigECDSAP256, []byte("fw-v1"))

	// Легитимное Msg1 — «перехваченное» злоумышленником.
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1); err != nil {
		t.Fatalf("first (legitimate) Msg1 must be accepted, got: %v", err)
	}

	// Повторная отправка того же Msg1 — replay, должна быть отвергнута.
	if _, err := gw.HandleMsg1(msg1); err == nil {
		t.Fatal("replayed Msg1 was accepted, expected rejection")
	}

	// Свежее рукопожатие того же устройства (новый nonce) снова проходит.
	msg1b, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("second start handshake: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1b); err != nil {
		t.Fatalf("fresh Msg1 with new nonce must be accepted, got: %v", err)
	}
}

// TestGatewayAbortsStaleRotationAndRetries — проверяет восстановление после
// потери ACK на уровне шлюза: если подтверждение атомарной ротации не пришло,
// по истечении тайм-аута незавершённая ротация откатывается, после чего можно
// инициировать ротацию заново. Без этого сессия навсегда застревала бы в
// «переходном» состоянии.
func TestGatewayAbortsStaleRotationAndRetries(t *testing.T) {
	// Управляемое время для детерминированного тайм-аута.
	base := crypto.NowForTest()
	fake := base
	crypto.SetNowForTest(func() time.Time { return fake })
	defer crypto.ResetNowForTest()

	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "esp32-stale-rot", crypto.SigECDSAP256, []byte("fw"))
	runHandshake(t, gw, dev)

	// Шлюз инициирует атомарную ротацию — ACK «теряется» (не применяем его).
	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("initiate atomic rotation: %v", err)
	}

	// Пока тайм-аут не наступил — откат не срабатывает, новая ротация
	// невозможна (сессия в переходном состоянии).
	if gw.AbortStaleRotationIfNeeded(dev.ID, crypto.RotationAckTimeout) {
		t.Fatal("must not abort before timeout")
	}
	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err == nil {
		t.Fatal("expected second rotation to be blocked while first is pending")
	}

	// Прокручиваем время за тайм-аут — планировщик (в лице этого вызова)
	// откатывает застрявшую ротацию.
	fake = base.Add(crypto.RotationAckTimeout + time.Second)
	if !gw.AbortStaleRotationIfNeeded(dev.ID, crypto.RotationAckTimeout) {
		t.Fatal("expected stale rotation to be aborted after timeout")
	}

	// После отката ротация снова возможна.
	if _, err := gw.InitiateAtomicRotationToDevice(dev.ID); err != nil {
		t.Fatalf("rotation must be possible again after stale abort: %v", err)
	}

	// В журнале ротаций должна появиться запись о неуспешной попытке (тайм-аут).
	logs, err := gw.Store.RotationHistory(dev.ID, 10)
	if err != nil {
		t.Fatalf("list rotations: %v", err)
	}
	var sawTimeout bool
	for _, l := range logs {
		if !l.Success {
			sawTimeout = true
		}
	}
	if !sawTimeout {
		t.Fatal("expected an unsuccessful (timeout) rotation entry in the log")
	}
}

// TestFirmwareChallengeExpiresRejectsStaleResponse — проверяет, что ответ на
// устаревший challenge отклоняется. Это закрывает окно повторного
// воспроизведения заранее заготовленной пары (challenge, response): устройство
// (или перехватчик) не может ответить на challenge спустя долгое время.
func TestFirmwareChallengeExpiresRejectsStaleResponse(t *testing.T) {
	base := time.Now()
	fake := base
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.SetNowForTest(func() time.Time { return fake })

	dev := newRegisteredDevice(t, gw, "esp32-fw-stale", crypto.SigECDSAP256, []byte("firmware-v1"))

	// Шлюз выдал challenge; устройство честно на него ответило.
	challenge, err := gw.IssueFirmwareChallenge(dev.ID)
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("respond challenge: %v", err)
	}

	// ...но ответ приходит слишком поздно — за пределами окна валидности.
	fake = base.Add(firmwareResponseValidity + time.Second)

	if _, err := gw.VerifyFirmwareCheck(dev.ID, resp); err == nil {
		t.Fatal("expected stale firmware response to be rejected")
	}

	// Устройство при этом НЕ должно быть отозвано — ведь ответ корректный,
	// проблема лишь во времени. (Отзыв — только за реальный провал проверки.)
	if _, err := gw.Store.Get(dev.ID); err != nil {
		t.Fatalf("device must not be revoked due to a stale (but valid) response: %v", err)
	}
}

// TestFirmwareChallengeFreshResponseStillPasses — регрессия: свежий ответ (в
// пределах окна валидности) по-прежнему проходит после введения тайм-аута.
func TestFirmwareChallengeFreshResponseStillPasses(t *testing.T) {
	base := time.Now()
	fake := base
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.SetNowForTest(func() time.Time { return fake })

	dev := newRegisteredDevice(t, gw, "esp32-fw-fresh", crypto.SigECDSAP256, []byte("firmware-v1"))

	challenge, err := gw.IssueFirmwareChallenge(dev.ID)
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("respond challenge: %v", err)
	}

	// Ответ приходит с небольшой задержкой, но в пределах окна.
	fake = base.Add(firmwareResponseValidity / 2)

	result, err := gw.VerifyFirmwareCheck(dev.ID, resp)
	if err != nil {
		t.Fatalf("fresh firmware response must verify: %v", err)
	}
	if !result.OK() {
		t.Fatalf("fresh firmware check must pass: %+v", result)
	}
}

// TestPendingHandshakeExpires — незавершённое рукопожатие (Msg3 не пришёл
// вовремя) протухает: поздний Msg3 отклоняется, а секретный материал не
// удерживается бесконечно. Это ограничивает накопление незавершённых
// рукопожатий и время жизни ключевого материала.
func TestPendingHandshakeExpires(t *testing.T) {
	base := time.Now()
	fake := base
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.SetNowForTest(func() time.Time { return fake })

	dev := newRegisteredDevice(t, gw, "esp32-hs-expire", crypto.SigECDSAP256, []byte("fw"))

	// Msg1 -> Msg2 (шлюз создаёт pending с текущим временем).
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	msg2, err := gw.HandleMsg1(msg1)
	if err != nil {
		t.Fatalf("handle msg1: %v", err)
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("complete handshake: %v", err)
	}

	// Msg3 приходит слишком поздно — за пределами pendingHandshakeTimeout.
	fake = base.Add(pendingHandshakeTimeout + time.Second)
	if err := gw.HandleMsg3(dev.ID, msg3); err == nil {
		t.Fatal("expected late Msg3 to be rejected after pending handshake expiry")
	}
}

// TestPendingHandshakePrunedOnNewMsg1 — протухшая запись одного устройства
// удаляется при поступлении Msg1 (в т.ч. от другого устройства), а не копится.
func TestPendingHandshakePrunedOnNewMsg1(t *testing.T) {
	base := time.Now()
	fake := base
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.SetNowForTest(func() time.Time { return fake })

	devA := newRegisteredDevice(t, gw, "esp32-hs-a", crypto.SigECDSAP256, []byte("fw"))
	devB := newRegisteredDevice(t, gw, "esp32-hs-b", crypto.SigECDSAP256, []byte("fw"))

	// devA начинает рукопожатие и «пропадает» (Msg3 не шлёт).
	msg1a, _ := devA.StartHandshake()
	if _, err := gw.HandleMsg1(msg1a); err != nil {
		t.Fatalf("handle msg1 A: %v", err)
	}
	if gw.PendingHandshakeCountForTest() != 1 {
		t.Fatalf("expected 1 pending handshake, got %d", gw.PendingHandshakeCountForTest())
	}

	// Время идёт за тайм-аут; приходит Msg1 от devB — протухший devA чистится.
	fake = base.Add(pendingHandshakeTimeout + time.Second)
	msg1b, _ := devB.StartHandshake()
	if _, err := gw.HandleMsg1(msg1b); err != nil {
		t.Fatalf("handle msg1 B: %v", err)
	}
	// Должна остаться только запись devB.
	if n := gw.PendingHandshakeCountForTest(); n != 1 {
		t.Fatalf("expected stale entry pruned, exactly 1 pending (devB) remaining, got %d", n)
	}
}

// TestMetricsCountLifecycleEvents — проверяет, что агрегированные счётчики
// корректно отражают события: успешное рукопожатие, отбитый replay, успешную
// и проваленную проверку прошивки, отзыв устройства.
func TestMetricsCountLifecycleEvents(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "esp32-metrics-1", crypto.SigECDSAP256, []byte("firmware-v1"))

	// Успешное рукопожатие.
	runHandshake(t, gw, dev)
	if got := gw.Metrics.Snapshot().HandshakesCompleted; got != 1 {
		t.Fatalf("HandshakesCompleted = %d, want 1", got)
	}

	// Replay того же Msg1 отбивается и учитывается.
	msg1, _ := dev.StartHandshake()
	if _, err := gw.HandleMsg1(msg1); err != nil {
		t.Fatalf("first msg1: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1); err == nil {
		t.Fatal("expected replay to be rejected")
	}
	snap := gw.Metrics.Snapshot()
	if snap.ReplaysBlocked != 1 {
		t.Fatalf("ReplaysBlocked = %d, want 1", snap.ReplaysBlocked)
	}
	if snap.HandshakesRejected < 1 {
		t.Fatalf("HandshakesRejected = %d, want >=1", snap.HandshakesRejected)
	}

	// Успешная проверка прошивки.
	challenge, _ := gw.IssueFirmwareChallenge(dev.ID)
	resp, _ := dev.RespondFirmwareChallenge(challenge)
	if _, err := gw.VerifyFirmwareCheck(dev.ID, resp); err != nil {
		t.Fatalf("firmware check: %v", err)
	}
	if got := gw.Metrics.Snapshot().FirmwareChecksPassed; got != 1 {
		t.Fatalf("FirmwareChecksPassed = %d, want 1", got)
	}
}

// TestMetricsCountFirmwareFailureAndRevoke — проваленная проверка прошивки
// увеличивает счётчики проваленных проверок и отзывов устройства.
func TestMetricsCountFirmwareFailureAndRevoke(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "esp32-metrics-2", crypto.SigECDSAP256, []byte("firmware-v1"))
	runHandshake(t, gw, dev)

	// Прошивку подменили после регистрации.
	dev.TamperFirmware([]byte("-malware"))
	challenge, _ := gw.IssueFirmwareChallenge(dev.ID)
	resp, _ := dev.RespondFirmwareChallenge(challenge)
	result, err := gw.VerifyFirmwareCheck(dev.ID, resp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.OK() {
		t.Fatal("tampered firmware must fail the check")
	}

	snap := gw.Metrics.Snapshot()
	if snap.FirmwareChecksFailed != 1 {
		t.Fatalf("FirmwareChecksFailed = %d, want 1", snap.FirmwareChecksFailed)
	}
	if snap.DevicesRevoked != 1 {
		t.Fatalf("DevicesRevoked = %d, want 1", snap.DevicesRevoked)
	}
}

// TestMetricsCountRotations — успешная атомарная ротация увеличивает счётчик
// успешных ротаций.
func TestMetricsCountRotations(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	dev := newRegisteredDevice(t, gw, "esp32-metrics-3", crypto.SigECDSAP256, []byte("fw"))
	runHandshake(t, gw, dev)

	// Устройство инициирует атомарную ротацию; шлюз применяет и подтверждает.
	msg, err := dev.InitiateAtomicRotation()
	if err != nil {
		t.Fatalf("device initiate: %v", err)
	}
	if _, err := gw.HandleAtomicRotationFromDevice(dev.ID, msg); err != nil {
		t.Fatalf("gateway handle rotation: %v", err)
	}
	if got := gw.Metrics.Snapshot().RotationsSucceeded; got != 1 {
		t.Fatalf("RotationsSucceeded = %d, want 1", got)
	}
}

// TestGatewayShutdownClosesSessionsAndZeroizes — при остановке шлюза все
// активные сессии закрываются (ключи затираются), а незавершённые состояния
// очищаются.
func TestGatewayShutdownClosesSessionsAndZeroizes(t *testing.T) {
	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	// Три устройства с установленными сессиями.
	for i := 0; i < 3; i++ {
		dev := newRegisteredDevice(t, gw, fmt.Sprintf("esp32-shutdown-%d", i), crypto.SigECDSAP256, []byte("fw"))
		runHandshake(t, gw, dev)
	}
	// Плюс одно незавершённое рукопожатие (держит секрет).
	devPending := newRegisteredDevice(t, gw, "esp32-shutdown-pending", crypto.SigECDSAP256, []byte("fw"))
	msg1, _ := devPending.StartHandshake()
	if _, err := gw.HandleMsg1(msg1); err != nil {
		t.Fatalf("handle msg1: %v", err)
	}

	closed := gw.Shutdown()
	if closed != 3 {
		t.Fatalf("Shutdown closed %d sessions, want 3", closed)
	}

	// После остановки не должно остаться ни сессий, ни незавершённых рукопожатий.
	if n := gw.PendingHandshakeCountForTest(); n != 0 {
		t.Fatalf("expected pending handshakes cleared, got %d", n)
	}
	// Ротация для закрытой сессии больше невозможна (сессии удалены).
	if _, err := gw.InitiateAtomicRotationToDevice("esp32-shutdown-0"); err == nil {
		t.Fatal("expected no active session after shutdown")
	}
}
