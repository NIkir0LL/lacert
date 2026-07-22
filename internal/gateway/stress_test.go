package gateway

import (
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/store"
)

// TestStressAllDefenseMechanisms — комплексный стресс-тест всех защитных
// механизмов сразу, на пяти устройствах, каждое из которых воспроизводит свой
// сценарий сбоя. Цель — убедиться, что метрики и логика отзывов считаются
// правильно и механизмы не мешают друг другу.
//
// Устройства и их сценарии:
//
//	D1 — периодические сбои ротации (0..2 подряд, НЕ доводя до бана):
//	     проверяет rotations_failed без devices_revoked.
//	D2 — replay-атаки на рукопожатие:
//	     проверяет replays_blocked и handshakes_rejected.
//	D3 — отклонённые рукопожатия (неверная подпись Msg3):
//	     проверяет handshakes_rejected.
//	D4 — ответ на проверку прошивки приходит с опозданием (challenge устарел):
//	     проверяет firmware_checks_rejected.
//	D5 — проходит несколько проверок прошивки, затем подмена -> отзыв:
//	     проверяет firmware_checks_passed, firmware_checks_failed, devices_revoked.
//
// Время управляется вручную (SetNowForTest), поэтому тест детерминирован.
func TestStressAllDefenseMechanisms(t *testing.T) {
	base := time.Now()
	fake := base
	nowFn := func() time.Time { return fake }
	crypto.SetNowForTest(nowFn)
	defer crypto.ResetNowForTest()

	gw, err := New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.SetNowForTest(nowFn)

	// D1: периодические сбои ротации, не доводя до бана (порог = 3).
	d1 := setupDeviceWithSession(t, gw, "stress-d1-flaky-rotation")
	const d1FailBursts = 2
	for i := 0; i < d1FailBursts; i++ {
		if _, err := gw.InitiateAtomicRotationToDevice(d1.ID); err != nil {
			t.Fatalf("d1 initiate rotation %d: %v", i, err)
		}
		fake = fake.Add(crypto.RotationAckTimeout + time.Second)
		if !gw.AbortStaleRotationIfNeeded(d1.ID, crypto.RotationAckTimeout) {
			t.Fatalf("d1 rotation %d should have gone stale", i)
		}
	}
	rotateAtomicOK(t, gw, d1)

	// D2: replay-атака на рукопожатие.
	d2, _ := setupRegisteredDevice(t, gw, "stress-d2-replay")
	msg1, err := d2.StartHandshake()
	if err != nil {
		t.Fatalf("d2 start handshake: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1); err != nil {
		t.Fatalf("d2 first msg1: %v", err)
	}
	if _, err := gw.HandleMsg1(msg1); err == nil {
		t.Fatal("d2 replayed Msg1 must be rejected")
	}
	for i := 0; i < 2; i++ {
		_, _ = gw.HandleMsg1(msg1)
	}

	// D3: отклонённое рукопожатие (испорченная подпись Msg3).
	d3, _ := setupRegisteredDevice(t, gw, "stress-d3-bad-handshake")
	m1, _ := d3.StartHandshake()
	m2, err := gw.HandleMsg1(m1)
	if err != nil {
		t.Fatalf("d3 handle msg1: %v", err)
	}
	m3, err := d3.CompleteHandshake(m1, m2)
	if err != nil {
		t.Fatalf("d3 complete handshake: %v", err)
	}
	if len(m3.Signature) > 0 {
		m3.Signature[0] ^= 0xFF
	}
	if err := gw.HandleMsg3(d3.ID, m3); err == nil {
		t.Fatal("d3 handshake with tampered signature must be rejected")
	}

	// D4: ответ на проверку прошивки устарел -> firmware_checks_rejected.
	d4 := setupDeviceWithSession(t, gw, "stress-d4-stale-firmware")
	challenge4, err := gw.IssueFirmwareChallenge(d4.ID)
	if err != nil {
		t.Fatalf("d4 issue challenge: %v", err)
	}
	resp4, err := d4.RespondFirmwareChallenge(challenge4)
	if err != nil {
		t.Fatalf("d4 respond: %v", err)
	}
	fake = fake.Add(firmwareResponseValidity + time.Second)
	if _, err := gw.VerifyFirmwareCheck(d4.ID, resp4); err == nil {
		t.Fatal("d4 stale firmware response must be rejected")
	}

	// D5: несколько успешных проверок прошивки, затем подмена -> отзыв.
	d5 := setupDeviceWithSession(t, gw, "stress-d5-firmware-then-tamper")
	const d5GoodChecks = 2
	for i := 0; i < d5GoodChecks; i++ {
		ch, err := gw.IssueFirmwareChallenge(d5.ID)
		if err != nil {
			t.Fatalf("d5 issue challenge %d: %v", i, err)
		}
		resp, err := d5.RespondFirmwareChallenge(ch)
		if err != nil {
			t.Fatalf("d5 respond %d: %v", i, err)
		}
		res, err := gw.VerifyFirmwareCheck(d5.ID, resp)
		if err != nil {
			t.Fatalf("d5 verify %d: %v", i, err)
		}
		if !res.OK() {
			t.Fatalf("d5 check %d should pass", i)
		}
	}
	d5.TamperFirmware([]byte("-stress-rootkit"))
	ch, _ := gw.IssueFirmwareChallenge(d5.ID)
	resp, _ := d5.RespondFirmwareChallenge(ch)
	res, err := gw.VerifyFirmwareCheck(d5.ID, resp)
	if err != nil {
		t.Fatalf("d5 verify tampered: %v", err)
	}
	if res.OK() {
		t.Fatal("d5 tampered firmware must fail the check")
	}

	// === Проверка итоговых метрик ===
	m := gw.Metrics.Snapshot()
	t.Logf("ИТОГОВЫЕ МЕТРИКИ: %+v", m)
	t.Log("")
	t.Log("=== СВОДКА ПО УСТРОЙСТВАМ ===")
	t.Logf("D1 (сбои ротации, не до бана):   rotations_failed=%d, успешных=%d, отозван=НЕТ", m.RotationsFailed, m.RotationsSucceeded)
	t.Logf("D2 (replay-атаки):               replays_blocked=%d", m.ReplaysBlocked)
	t.Logf("D2+D3 (отклонено рукопожатий):   handshakes_rejected=%d", m.HandshakesRejected)
	t.Logf("D4 (устаревший challenge):       firmware_checks_rejected=%d", m.FirmwareChecksRejected)
	t.Logf("D5 (прошёл %d, потом подмена):    passed=%d, failed=%d, revoked=%d", d5GoodChecks, m.FirmwareChecksPassed, m.FirmwareChecksFailed, m.DevicesRevoked)

	if m.RotationsFailed != uint64(d1FailBursts) {
		t.Errorf("rotations_failed = %d, ожидалось %d (D1)", m.RotationsFailed, d1FailBursts)
	}
	if m.RotationsSucceeded < 1 {
		t.Errorf("rotations_succeeded = %d, ожидалось >=1 (D1)", m.RotationsSucceeded)
	}
	if _, err := gw.Store.Get(d1.ID); err == store.ErrDeviceRevoked {
		t.Error("D1 не должен быть отозван (провалов меньше порога)")
	}
	if m.ReplaysBlocked < 1 {
		t.Errorf("replays_blocked = %d, ожидалось >=1 (D2)", m.ReplaysBlocked)
	}
	if m.HandshakesRejected < 2 {
		t.Errorf("handshakes_rejected = %d, ожидалось >=2 (D2+D3)", m.HandshakesRejected)
	}
	if m.FirmwareChecksRejected < 1 {
		t.Errorf("firmware_checks_rejected = %d, ожидалось >=1 (D4)", m.FirmwareChecksRejected)
	}
	if m.FirmwareChecksPassed < uint64(d5GoodChecks) {
		t.Errorf("firmware_checks_passed = %d, ожидалось >=%d (D5)", m.FirmwareChecksPassed, d5GoodChecks)
	}
	if m.FirmwareChecksFailed < 1 {
		t.Errorf("firmware_checks_failed = %d, ожидалось >=1 (D5)", m.FirmwareChecksFailed)
	}
	if m.DevicesRevoked < 1 {
		t.Errorf("devices_revoked = %d, ожидалось >=1 (D5)", m.DevicesRevoked)
	}
	if _, err := gw.Store.Get(d5.ID); err != store.ErrDeviceRevoked {
		t.Errorf("D5 должен быть отозван после подмены прошивки (err=%v)", err)
	}
	if m.HandshakesCompleted < 3 {
		t.Errorf("handshakes_completed = %d, ожидалось >=3 (D1,D4,D5)", m.HandshakesCompleted)
	}
}

func setupRegisteredDevice(t *testing.T, gw *Gateway, id string) (*device.Device, error) {
	t.Helper()
	dev, err := device.NewDevice(id, crypto.SigECDSAP256, []byte("firmware-"+id))
	if err != nil {
		return nil, err
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		return nil, err
	}
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		return nil, err
	}
	return dev, nil
}

func setupDeviceWithSession(t *testing.T, gw *Gateway, id string) *device.Device {
	t.Helper()
	dev, err := setupRegisteredDevice(t, gw, id)
	if err != nil {
		t.Fatalf("setup %s: %v", id, err)
	}
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("%s start handshake: %v", id, err)
	}
	msg2, err := gw.HandleMsg1(msg1)
	if err != nil {
		t.Fatalf("%s handle msg1: %v", id, err)
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("%s complete handshake: %v", id, err)
	}
	if err := gw.HandleMsg3(dev.ID, msg3); err != nil {
		t.Fatalf("%s handle msg3: %v", id, err)
	}
	return dev
}

func rotateAtomicOK(t *testing.T, gw *Gateway, dev *device.Device) {
	t.Helper()
	msg, err := dev.InitiateAtomicRotation()
	if err != nil {
		t.Fatalf("%s initiate atomic rotation: %v", dev.ID, err)
	}
	if _, err := gw.HandleAtomicRotationFromDevice(dev.ID, msg); err != nil {
		t.Fatalf("%s gateway handle rotation: %v", dev.ID, err)
	}
}
