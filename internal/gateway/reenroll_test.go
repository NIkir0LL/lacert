package gateway

import (
	"bytes"
	"errors"
	"testing"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/regtool"
	"lacert/internal/store"
)

// Устройство, потерявшее ключи, должно поддаваться перерегистрации. Прежде
// такая плата оставалась в реестре навсегда непригодной: завести заново
// мешала прежняя запись, а рукопожатие не проходило, потому что ключ у платы
// уже другой.
func TestReregisterReplacesKeys(t *testing.T) {
	gw := newGatewayForTest(t)
	firmware := []byte("прошивка версии один")
	dev := newRegisteredDevice(t, gw, "esp32-reenroll", crypto.SigECDSAP256, firmware)

	before, err := gw.Store.Get(dev.ID)
	if err != nil {
		t.Fatalf("получение записи: %v", err)
	}

	// Та же плата после очистки памяти: идентификатор прежний, ключи новые.
	fresh, err := device.NewDevice(dev.ID, crypto.SigECDSAP256, firmware)
	if err != nil {
		t.Fatalf("создание устройства: %v", err)
	}
	fresh.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := fresh.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("вывод для регистрации: %v", err)
	}

	// Повторная регистрация обычным путём по-прежнему должна отвергаться:
	// иначе ключи работающего устройства затирались бы случайно.
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err == nil {
		t.Fatal("повторная регистрация тем же путём должна отвергаться")
	}

	if err := gw.ReregisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	after, err := gw.Store.Get(dev.ID)
	if err != nil {
		t.Fatalf("получение записи после перерегистрации: %v", err)
	}
	if bytes.Equal(before.IdentityPub, after.IdentityPub) {
		t.Error("ключ подписи должен был смениться")
	}
	if bytes.Equal(before.KEMPub, after.KEMPub) {
		t.Error("ключ обмена должен был смениться")
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Error("дата первой регистрации должна сохраняться")
	}
}

// История устройства при смене ключей теряться не должна: журнал событий
// показывает, что с платой происходило, и обрывать его на перерегистрации
// значило бы прятать от оператора часть картины.
func TestReregisterKeepsHistory(t *testing.T) {
	gw := newGatewayForTest(t)
	firmware := []byte("прошивка")
	dev := newRegisteredDevice(t, gw, "esp32-history", crypto.SigECDSAP256, firmware)

	if err := gw.Store.LogEvent(dev.ID, "проверка", "событие до перерегистрации"); err != nil {
		t.Fatalf("запись события: %v", err)
	}
	before, err := gw.Store.RecentEvents(dev.ID, 0)
	if err != nil {
		t.Fatalf("чтение журнала: %v", err)
	}

	fresh, _ := device.NewDevice(dev.ID, crypto.SigECDSAP256, firmware)
	fresh.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := fresh.SerialRegistrationOutput()
	if err := gw.ReregisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("перерегистрация: %v", err)
	}

	after, err := gw.Store.RecentEvents(dev.ID, 0)
	if err != nil {
		t.Fatalf("чтение журнала после: %v", err)
	}
	if len(after) <= len(before) {
		t.Errorf("журнал должен был пополниться записью о перерегистрации: было %d, стало %d",
			len(before), len(after))
	}
	found := false
	for _, e := range after {
		if e.Detail == "событие до перерегистрации" {
			found = true
		}
	}
	if !found {
		t.Error("прежние записи журнала должны сохраняться")
	}
}

// Отозванное устройство перерегистрировать нельзя. Отзыв ставится в том числе
// за неудачную проверку целостности прошивки, то есть по подозрению в
// подмене, и молча возвращать такую плату в строй опасно.
func TestReregisterRefusesRevokedDevice(t *testing.T) {
	gw := newGatewayForTest(t)
	firmware := []byte("прошивка")
	dev := newRegisteredDevice(t, gw, "esp32-revoked", crypto.SigECDSAP256, firmware)

	if err := gw.RevokeDevice(dev.ID, "не сошёлся хеш прошивки"); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	fresh, _ := device.NewDevice(dev.ID, crypto.SigECDSAP256, firmware)
	fresh.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := fresh.SerialRegistrationOutput()

	err := gw.ReregisterDevice(serial, crypto.SigECDSAP256)
	if err == nil {
		t.Fatal("перерегистрация отозванного устройства должна отвергаться")
	}

	// Ключи при отказе меняться не должны.
	rec, _ := gw.Store.Get(dev.ID)
	if !rec.Revoked {
		t.Error("отзыв должен сохраняться")
	}
}

// Перерегистрация несуществующего устройства — это ошибка, а не скрытое
// создание записи.
func TestReregisterUnknownDeviceFails(t *testing.T) {
	gw := newGatewayForTest(t)
	dev, _ := device.NewDevice("esp32-unknown", crypto.SigECDSAP256, []byte("прошивка"))
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := dev.SerialRegistrationOutput()

	err := gw.ReregisterDevice(serial, crypto.SigECDSAP256)
	if !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("ожидалась ошибка отсутствия устройства, получено: %v", err)
	}
}

// Удаление убирает устройство из реестра вместе с историей.
func TestDeleteDeviceRemovesRecord(t *testing.T) {
	gw := newGatewayForTest(t)
	dev := newRegisteredDevice(t, gw, "esp32-todelete", crypto.SigECDSAP256, []byte("прошивка"))

	if err := gw.DeleteDevice(dev.ID); err != nil {
		t.Fatalf("удаление: %v", err)
	}
	if _, err := gw.Store.Get(dev.ID); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Errorf("запись должна была исчезнуть, получено: %v", err)
	}

	// После удаления идентификатор снова свободен.
	fresh, _ := device.NewDevice("esp32-todelete", crypto.SigECDSAP256, []byte("прошивка"))
	fresh.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := fresh.SerialRegistrationOutput()
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Errorf("после удаления регистрация должна проходить: %v", err)
	}
}

// Удаление несуществующего устройства — ошибка, а не молчаливый успех.
func TestDeleteUnknownDeviceFails(t *testing.T) {
	gw := newGatewayForTest(t)
	if err := gw.DeleteDevice("esp32-never-existed"); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("ожидалась ошибка отсутствия устройства, получено: %v", err)
	}
}

// Ключ подписи должен проверяться при регистрации, а не позже. Прежде здесь
// стояла лишь проверка на непустоту, и устройство с испорченным ключом
// регистрировалось успешно, а отказывало на первом рукопожатии, где связь с
// ошибкой ввода уже не видна.
func TestRegisterRejectsMalformedIdentityKey(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"точка не на кривой": func(b []byte) []byte { return flipKeyByte(b, 40) },
		"обрезанный ключ":    func(b []byte) []byte { return b[:len(b)-1] },
		"неверный префикс":   func(b []byte) []byte { return flipKeyByte(b, 0) },
		"лишний байт":        func(b []byte) []byte { return append(append([]byte(nil), b...), 0) },
	}
	for name, damage := range cases {
		name, damage := name, damage
		t.Run(name, func(t *testing.T) {
			// Свой шлюз и свой идентификатор на каждый случай. Общий шлюз
			// давал бы ложное прохождение: первая запись регистрируется, а
			// остальные отвергаются уже за занятый идентификатор, а вовсе не
			// за испорченный ключ.
			gw := newGatewayForTest(t)
			dev, err := device.NewDevice("esp32-badkey", crypto.SigECDSAP256, []byte("прошивка"))
			if err != nil {
				t.Fatalf("создание устройства: %v", err)
			}
			dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
			serial, err := dev.SerialRegistrationOutput()
			if err != nil {
				t.Fatalf("вывод для регистрации: %v", err)
			}

			s := serial
			s.IdentityPub = damage(serial.IdentityPub)
			// Контрольная сумма пересчитывается: иначе запись отвергалась бы
			// по несовпадению суммы, и до проверки самого ключа дело бы не
			// дошло.
			s.Checksum = regtoolChecksum(t, s)

			if err := gw.RegisterDevice(s, crypto.SigECDSAP256); err == nil {
				t.Error("испорченный ключ подписи должен отвергаться при регистрации")
			}
		})
	}
}

func flipKeyByte(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0xFF
	return out
}

// newGatewayForTest создаёт шлюз в памяти. Отдельная обёртка нужна, чтобы не
// повторять обработку ошибки в каждом тесте этого файла.
func newGatewayForTest(t *testing.T) *Gateway {
	t.Helper()
	gw, err := New()
	if err != nil {
		t.Fatalf("создание шлюза: %v", err)
	}
	return gw
}

// regtoolChecksum пересчитывает контрольную сумму после подмены поля: без неё
// запись отвергалась бы по несовпадению суммы, и до проверки самого ключа
// дело бы не дошло.
func regtoolChecksum(t *testing.T, out regtool.SerialOutput) string {
	t.Helper()
	return regtool.ComputeChecksum(out.DeviceID, out.IdentityPub, out.KEMPub, out.FirmwareHash[:])
}
