package emulator

import (
	"testing"

	"lacert/internal/crypto"
	"lacert/internal/store"
)

func TestResetDevicesAllowsIdempotentRestart(t *testing.T) {
	s := store.New()

	rec := &store.DeviceRecord{
		DeviceID:     "emulated-esp32-1",
		SigAlgorithm: crypto.SigECDSAP256,
		IdentityPub:  []byte{1, 2, 3},
		KEMPub:       []byte{4, 5, 6},
		FirmwareHash: make([]byte, crypto.FirmwareHashSize),
	}
	if err := s.Register(rec); err != nil {
		t.Fatalf("initial register: %v", err)
	}

	// Без ResetDevices повторная регистрация под тем же ID отклоняется —
	// именно это и происходило при перезапуске gatewayd с PostgreSQL.
	dup := *rec
	dup.IdentityPub = []byte{9, 9, 9} // "новые ключи после рестарта эмулятора"
	if err := s.Register(&dup); err != store.ErrDeviceExists {
		t.Fatalf("expected ErrDeviceExists before reset, got %v", err)
	}

	if err := ResetDevices(s, []string{"emulated-esp32-1", "emulated-esp32-2"}); err != nil {
		t.Fatalf("reset devices: %v", err)
	}

	// emulated-esp32-2 никогда не существовал — ResetDevices должна была
	// просто пропустить его, не вернув ошибку.
	if err := s.Register(&dup); err != nil {
		t.Fatalf("re-register after reset should succeed (this is the fixed bug), got %v", err)
	}

	got, err := s.Get("emulated-esp32-1")
	if err != nil {
		t.Fatalf("get after reset+re-register: %v", err)
	}
	if string(got.IdentityPub) != string(dup.IdentityPub) {
		t.Fatalf("expected device to carry the NEW identity pub after reset+re-register, got %x", got.IdentityPub)
	}
}

func TestResetDevicesDoesNotTouchUnlistedDevices(t *testing.T) {
	s := store.New()

	mustRegister := func(id string) {
		if err := s.Register(&store.DeviceRecord{
			DeviceID:     id,
			SigAlgorithm: crypto.SigECDSAP256,
			IdentityPub:  []byte{1},
			KEMPub:       []byte{2},
			FirmwareHash: make([]byte, crypto.FirmwareHashSize),
		}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	mustRegister("emulated-esp32-1")
	mustRegister("real-device-001")

	if err := ResetDevices(s, []string{"emulated-esp32-1"}); err != nil {
		t.Fatalf("reset devices: %v", err)
	}

	if _, err := s.Get("emulated-esp32-1"); err != store.ErrDeviceNotFound {
		t.Fatalf("expected emulated-esp32-1 to be removed, got err=%v", err)
	}
	if _, err := s.Get("real-device-001"); err != nil {
		t.Fatalf("real-device-001 must not be affected by resetting emulated devices, got err=%v", err)
	}
}
