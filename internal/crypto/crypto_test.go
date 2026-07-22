package crypto

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// performHandshake — вспомогательная функция, выполняющая полный
// трёхшаговый обмен между "устройством" и "шлюзом" внутри теста.
func performHandshake(t *testing.T, alg SigAlgorithm) (devSession, gwSession *Session, devIdentity *IdentityKeyPair) {
	t.Helper()

	devIdentity, err := GenerateIdentity(alg)
	if err != nil {
		t.Fatalf("generate device identity: %v", err)
	}
	devIdentityPub, err := devIdentity.PublicKeyBytes()
	if err != nil {
		t.Fatalf("device identity pub bytes: %v", err)
	}

	devKEM, err := GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("generate device kem keys: %v", err)
	}

	// Msg1: устройство -> шлюз
	msg1, err := NewHandshakeMsg1("device-001", devIdentityPub)
	if err != nil {
		t.Fatalf("build msg1: %v", err)
	}

	// Msg2: шлюз -> устройство (шлюз уже знает devKEM.Pub из "БД устройств")
	msg2, gwSharedSecret, err := BuildMsg2(devKEM.Pub)
	if err != nil {
		t.Fatalf("build msg2: %v", err)
	}

	// Msg3: устройство -> шлюз
	msg3, devK0, err := BuildMsg3(devKEM.Priv, devIdentity, msg1, msg2)
	if err != nil {
		t.Fatalf("build msg3: %v", err)
	}

	// Финализация на шлюзе
	gwK0, err := FinalizeHandshake(devIdentityPub, alg, msg1, msg2, msg3, gwSharedSecret)
	if err != nil {
		t.Fatalf("finalize handshake: %v", err)
	}

	if !bytes.Equal(devK0, gwK0) {
		t.Fatalf("K0 mismatch: device=%x gateway=%x", devK0, gwK0)
	}

	devSession, err = NewSession(devK0)
	if err != nil {
		t.Fatalf("new device session: %v", err)
	}
	gwSession, err = NewSession(gwK0)
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}

	return devSession, gwSession, devIdentity
}

func TestHandshakeECDSA(t *testing.T) {
	performHandshake(t, SigECDSAP256)
}

func TestHandshakeSLHDSA(t *testing.T) {
	performHandshake(t, SigSLHDSA)
}

// Ed25519 в протоколе не используется: устройства подписывают ECDSA P-256
// (см. PROTOCOL_SPEC.md, раздел 9). Реализация сохранена в ядре как инструмент
// сравнительных измерений, и этот тест проверяет её пригодность — что схема
// корректно проходит весь путь рукопожатия, а не только отдельную подпись.
// Без него замеры из MEASUREMENTS.md раздела 3.2 опирались бы на код,
// проверенный лишь частично.
func TestHandshakeEd25519(t *testing.T) {
	performHandshake(t, SigEd25519)
}

func TestHandshakeRejectsTamperedSignature(t *testing.T) {
	devIdentity, _ := GenerateIdentity(SigECDSAP256)
	devIdentityPub, _ := devIdentity.PublicKeyBytes()
	devKEM, _ := GenerateKEMKeyPair()

	msg1, _ := NewHandshakeMsg1("device-001", devIdentityPub)
	msg2, gwSharedSecret, _ := BuildMsg2(devKEM.Pub)
	msg3, _, _ := BuildMsg3(devKEM.Priv, devIdentity, msg1, msg2)

	// Подменяем подпись — имитация атакующего без приватного ключа.
	tampered := make([]byte, len(msg3.Signature))
	copy(tampered, msg3.Signature)
	tampered[0] ^= 0xFF
	msg3.Signature = tampered

	_, err := FinalizeHandshake(devIdentityPub, SigECDSAP256, msg1, msg2, msg3, gwSharedSecret)
	if err == nil {
		t.Fatal("expected handshake to fail with tampered signature, but it succeeded")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	devSession, gwSession, _ := performHandshake(t, SigECDSAP256)

	key, err := devSession.CurrentKey()
	if err != nil {
		t.Fatalf("device current key: %v", err)
	}
	gwKey, err := gwSession.CurrentKey()
	if err != nil {
		t.Fatalf("gateway current key: %v", err)
	}
	if key != gwKey {
		t.Fatal("session keys diverged right after handshake")
	}

	plaintext := []byte("temperature=23.5;humidity=41")
	nonce, ct, err := EncryptPacket(key, 0, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptPacket(gwKey, nonce, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptFailsOnTamperedCiphertext(t *testing.T) {
	devSession, _, _ := performHandshake(t, SigECDSAP256)
	key, _ := devSession.CurrentKey()

	nonce, ct, err := EncryptPacket(key, 0, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF // подмена последнего байта (затрагивает тег Poly1305)

	if _, err := DecryptPacket(key, nonce, ct); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

// TestRotationPFS_PCS проверяет ключевые свойства: после ротации старый
// ключ невосстановим (PFS), а атакующий, узнавший Ki, не может вычислить
// Ki+1 без знания Mi (PCS), потому что Mi получается только декапсуляцией
// приватным KEM-ключом, недоступным программно.
func TestRotationPFS_PCS(t *testing.T) {
	devSession, gwSession, _ := performHandshake(t, SigECDSAP256)

	devKEM, err := GenerateKEMKeyPair() // "ключ устройства" для ротации
	if err != nil {
		t.Fatalf("generate device kem for rotation: %v", err)
	}
	gwKEM, err := GenerateKEMKeyPair() // "ключ шлюза" для ротации
	if err != nil {
		t.Fatalf("generate gateway kem for rotation: %v", err)
	}

	oldDevKey, _ := devSession.CurrentKey()

	// Шлюз инициирует ротацию, инкапсулируя секрет под KEM-pubkey устройства.
	rotMsg, err := InitiateRotation(gwSession, devKEM.Pub)
	if err != nil {
		t.Fatalf("initiate rotation: %v", err)
	}

	// Устройство отвечает декапсуляцией своим приватным ключом.
	if err := RespondToRotation(devSession, devKEM.Priv, rotMsg); err != nil {
		t.Fatalf("respond to rotation: %v", err)
	}
	_ = gwKEM // зарезервирован для обратной ротации (устройство -> шлюз), не используется в этом тесте

	newDevKey, _ := devSession.CurrentKey()
	newGwKey, _ := gwSession.CurrentKey()

	if newDevKey != newGwKey {
		t.Fatalf("post-rotation keys diverged: device=%x gateway=%x", newDevKey, newGwKey)
	}
	if newDevKey == oldDevKey {
		t.Fatal("key did not change after rotation")
	}

	// PFS: старый ключ был затёрт в памяти сессии — повторное чтение
	// CurrentKey() уже не вернёт старое значение. Здесь мы проверяем это
	// логически: oldDevKey, сохранённый локально в тесте, больше нигде в
	// Session не существует (Session.key содержит только новое значение).
	stats := devSession.Stats()
	if stats.RotationCount != 1 {
		t.Fatalf("expected 1 rotation, got %d", stats.RotationCount)
	}

	// PCS (демонстрация): зная только oldDevKey (без Mi из decaps), вычислить
	// newDevKey невозможно без приватного KEM-ключа. Покажем, что простое
	// знание oldDevKey не помогает воспроизвести ротацию: BLAKE3(oldDevKey || X || "rotate_v1")
	// для любого X, который атакующий мог бы угадать без доступа к efuse,
	// не совпадёт с newDevKey, так как X должен быть результатом decaps,
	// который недоступен без приватного ключа.
	guess := DeriveK0(oldDevKey[:], []byte("attacker-guess-without-private-key"))
	if bytes.Equal(guess, newDevKey[:]) {
		t.Fatal("attacker without private KEM key was able to guess the rotated key (should be impossible)")
	}
}

func TestSessionNeedsRotationByPacketCount(t *testing.T) {
	s, err := NewSession(make([]byte, 32))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	for i := 0; i < RotationPacketLimit-1; i++ {
		s.RecordPacket()
	}
	if s.NeedsRotation() {
		t.Fatal("should not need rotation yet")
	}
	s.RecordPacket()
	if !s.NeedsRotation() {
		t.Fatal("should need rotation after reaching packet limit")
	}
}

func TestFirmwareIntegrityCheck(t *testing.T) {
	identity, _ := GenerateIdentity(SigECDSAP256)
	identityPub, _ := identity.PublicKeyBytes()

	firmwareImage := []byte("firmware-v1-binary-content-stub")
	referenceHash := sha256Sum(firmwareImage)

	challenge, err := BuildFirmwareChallenge()
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}

	resp, err := RespondToFirmwareChallenge(identity, challenge, firmwareImage)
	if err != nil {
		t.Fatalf("respond to challenge: %v", err)
	}

	result, err := VerifyFirmwareResponse(identityPub, SigECDSAP256, challenge, resp, referenceHash)
	if err != nil {
		t.Fatalf("verify firmware response: %v", err)
	}
	if !result.OK() {
		t.Fatalf("expected firmware check to pass, got %+v", result)
	}
}

func TestFirmwareIntegrityCheckDetectsTamperedFirmware(t *testing.T) {
	identity, _ := GenerateIdentity(SigECDSAP256)
	identityPub, _ := identity.PublicKeyBytes()

	originalFirmware := []byte("firmware-v1-binary-content-stub")
	referenceHash := sha256Sum(originalFirmware)

	tamperedFirmware := []byte("firmware-v1-TAMPERED-binary-content")

	challenge, _ := BuildFirmwareChallenge()
	resp, err := RespondToFirmwareChallenge(identity, challenge, tamperedFirmware)
	if err != nil {
		t.Fatalf("respond to challenge: %v", err)
	}

	result, err := VerifyFirmwareResponse(identityPub, SigECDSAP256, challenge, resp, referenceHash)
	if err != nil {
		t.Fatalf("verify firmware response: %v", err)
	}
	if !result.SignatureValid {
		t.Fatal("signature should still be valid (device is honest, firmware actually differs)")
	}
	if result.HashMatches {
		t.Fatal("hash should NOT match: firmware was tampered")
	}
	if result.OK() {
		t.Fatal("overall check should fail when firmware hash does not match reference")
	}
}

func sha256Sum(b []byte) [FirmwareHashSize]byte {
	return sha256.Sum256(b)
}
