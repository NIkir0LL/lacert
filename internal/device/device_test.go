package device

import (
	"bytes"
	"testing"

	"lacert/internal/crypto"
)

// pairWithGateway создаёт устройство и «шлюзовую» KEM-пару, проводит полное
// рукопожатие и возвращает готовое к работе устройство вместе с состоянием
// шлюза, необходимым для ответа на ротации.
//
// Здесь шлюз моделируется минимально — только тем, что нужно на стороне
// устройства: его KEM-пара и общий секрет рукопожатия. Полная интеграция со
// шлюзом проверяется в internal/gateway и internal/transport.
func newHandshookDevice(t *testing.T) (dev *Device, gwKEM *crypto.KEMKeyPair, gwSession *crypto.Session) {
	t.Helper()

	dev, err := NewDevice("dev-001", crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}

	gwKEM, err = crypto.GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("gateway kem: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gwKEM.Pub)

	// Рукопожатие: устройство <-> «шлюз».
	msg1, err := dev.StartHandshake()
	if err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	msg2, gwSS, err := crypto.BuildMsg2(dev.KEM.Pub)
	if err != nil {
		t.Fatalf("build msg2: %v", err)
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("complete handshake: %v", err)
	}
	devIdentityPub, _ := dev.Identity.PublicKeyBytes()
	gwK0, err := crypto.FinalizeHandshake(devIdentityPub, crypto.SigECDSAP256, msg1, msg2, msg3, gwSS)
	if err != nil {
		t.Fatalf("finalize handshake: %v", err)
	}
	gwSession, err = crypto.NewSession(gwK0)
	if err != nil {
		t.Fatalf("gateway session: %v", err)
	}
	return dev, gwKEM, gwSession
}

func TestNewDeviceCreatesKeys(t *testing.T) {
	dev, err := NewDevice("dev-x", crypto.SigECDSAP256, []byte("fw"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	if dev.Identity == nil || dev.KEM == nil {
		t.Fatal("device must have identity and KEM keys after creation")
	}
	if dev.HasSession() {
		t.Fatal("fresh device must not have a session before handshake")
	}
}

func TestSerialRegistrationOutputContainsIdentity(t *testing.T) {
	dev, _ := NewDevice("dev-serial", crypto.SigECDSAP256, []byte("fw"))
	out, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}
	if out.DeviceID != "dev-serial" {
		t.Fatalf("serial output device id = %q, want dev-serial", out.DeviceID)
	}
}

func TestHandshakeEstablishesSharedSession(t *testing.T) {
	dev, _, gwSession := newHandshookDevice(t)

	if !dev.HasSession() {
		t.Fatal("device must have a session after handshake")
	}
	// Ключи сторон должны совпадать: шифруем на устройстве, расшифровываем на «шлюзе».
	nonce, ct, err := dev.SendData([]byte("hello gateway"))
	if err != nil {
		t.Fatalf("send data: %v", err)
	}
	gwKey, _ := gwSession.CurrentKey()
	pt, err := crypto.DecryptPacket(gwKey, nonce, ct)
	if err != nil {
		t.Fatalf("gateway decrypt failed (key mismatch?): %v", err)
	}
	if !bytes.Equal(pt, []byte("hello gateway")) {
		t.Fatalf("payload mismatch: got %q", pt)
	}
}

func TestSendDataWithoutSessionFails(t *testing.T) {
	dev, _ := NewDevice("dev-nosess", crypto.SigECDSAP256, []byte("fw"))
	if _, _, err := dev.SendData([]byte("x")); err == nil {
		t.Fatal("expected error when sending without an active session")
	}
}

func TestReceiveDataRoundTrip(t *testing.T) {
	dev, _, gwSession := newHandshookDevice(t)

	// «Шлюз» шифрует команду, устройство её принимает.
	gwKey, _ := gwSession.CurrentKey()
	nonce, ct, err := crypto.EncryptPacket(gwKey, 0, []byte("command: reboot"))
	if err != nil {
		t.Fatalf("gateway encrypt: %v", err)
	}
	pt, err := dev.ReceiveData(nonce, ct)
	if err != nil {
		t.Fatalf("device receive: %v", err)
	}
	if !bytes.Equal(pt, []byte("command: reboot")) {
		t.Fatalf("received payload mismatch: got %q", pt)
	}
}

func TestReceiveDataWithoutSessionFails(t *testing.T) {
	dev, _ := NewDevice("dev-nosess2", crypto.SigECDSAP256, []byte("fw"))
	if _, err := dev.ReceiveData([]byte("nonce"), []byte("ct")); err == nil {
		t.Fatal("expected error receiving without session")
	}
}

func TestNeedsRotationFalseWithoutSession(t *testing.T) {
	dev, _ := NewDevice("dev-nr", crypto.SigECDSAP256, []byte("fw"))
	if dev.NeedsRotation() {
		t.Fatal("device without session must not need rotation")
	}
}

func TestInitiateRotationRequiresGatewayKey(t *testing.T) {
	dev, _ := NewDevice("dev-nogw", crypto.SigECDSAP256, []byte("fw"))
	// Есть сессия, но не задан публичный ключ шлюза.
	msg1, _ := dev.StartHandshake()
	msg2, _, _ := crypto.BuildMsg2(dev.KEM.Pub)
	if _, err := dev.CompleteHandshake(msg1, msg2); err != nil {
		t.Fatalf("complete handshake: %v", err)
	}
	if _, err := dev.InitiateAtomicRotation(); err == nil {
		t.Fatal("expected error initiating rotation without gateway KEM key")
	}
}

func TestAtomicRotationDeviceInitiatedRoundTrip(t *testing.T) {
	dev, gwKEM, gwSession := newHandshookDevice(t)

	// Устройство инициирует атомарную ротацию.
	msg, err := dev.InitiateAtomicRotation()
	if err != nil {
		t.Fatalf("initiate atomic rotation: %v", err)
	}
	// «Шлюз» применяет и отвечает ACK.
	ack, err := crypto.RespondToRotationAtomic(gwSession, gwKEM.Priv, msg)
	if err != nil {
		t.Fatalf("gateway respond: %v", err)
	}
	// Устройство коммитит по ACK.
	if err := dev.ApplyRotationAckFromGateway(ack); err != nil {
		t.Fatalf("apply ack: %v", err)
	}

	if dev.SessionIteration() != 1 {
		t.Fatalf("device iteration = %d, want 1", dev.SessionIteration())
	}
	// Канал работает под новым ключом.
	nonce, ct, err := dev.SendData([]byte("after rotation"))
	if err != nil {
		t.Fatalf("send after rotation: %v", err)
	}
	gwKey, _ := gwSession.CurrentKey()
	if _, err := crypto.DecryptPacket(gwKey, nonce, ct); err != nil {
		t.Fatalf("gateway decrypt after rotation failed: %v", err)
	}
}

func TestAtomicRotationGatewayInitiatedRoundTrip(t *testing.T) {
	dev, _, gwSession := newHandshookDevice(t)
	devKEMPub := dev.KEM.Pub

	// «Шлюз» инициирует атомарную ротацию под KEM-ключом устройства.
	msg, err := crypto.InitiateRotationAtomic(gwSession, devKEMPub)
	if err != nil {
		t.Fatalf("gateway initiate: %v", err)
	}
	// Устройство применяет и отвечает ACK.
	ack, err := dev.HandleAtomicRotationFromGateway(msg)
	if err != nil {
		t.Fatalf("device handle rotation: %v", err)
	}
	// «Шлюз» коммитит по ACK.
	if err := crypto.ApplyRotationAck(gwSession, ack); err != nil {
		t.Fatalf("gateway apply ack: %v", err)
	}

	if dev.SessionIteration() != 1 || gwSession.Iteration() != 1 {
		t.Fatalf("iterations: dev=%d gw=%d, want 1/1", dev.SessionIteration(), gwSession.Iteration())
	}
}

func TestRotationMethodsRequireSession(t *testing.T) {
	dev, _ := NewDevice("dev-nosess3", crypto.SigECDSAP256, []byte("fw"))
	if _, err := dev.InitiateAtomicRotation(); err == nil {
		t.Fatal("InitiateAtomicRotation must fail without session")
	}
	if _, err := dev.HandleAtomicRotationFromGateway(&crypto.RotationMsgV2{}); err == nil {
		t.Fatal("HandleAtomicRotationFromGateway must fail without session")
	}
	if err := dev.ApplyRotationAckFromGateway(&crypto.RotationAck{}); err == nil {
		t.Fatal("ApplyRotationAckFromGateway must fail without session")
	}
}

func TestFirmwareChallengeResponseVerifies(t *testing.T) {
	dev, _ := NewDevice("dev-fw", crypto.SigECDSAP256, []byte("firmware-v1"))
	challenge, err := crypto.BuildFirmwareChallenge()
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("respond challenge: %v", err)
	}

	devIdentityPub, _ := dev.Identity.PublicKeyBytes()
	result, err := crypto.VerifyFirmwareResponse(
		devIdentityPub, crypto.SigECDSAP256, challenge, resp, dev.FirmwareHash())
	if err != nil {
		t.Fatalf("verify firmware response: %v", err)
	}
	if !result.OK() {
		t.Fatalf("firmware check must pass for unmodified firmware: %+v", result)
	}
}

func TestTamperFirmwareIsDetected(t *testing.T) {
	dev, _ := NewDevice("dev-tamper", crypto.SigECDSAP256, []byte("firmware-v1"))
	referenceHash := dev.FirmwareHash() // эталон, сохранённый при регистрации

	// Прошивку подменили ПОСЛЕ регистрации.
	dev.TamperFirmware([]byte("malicious-payload"))

	challenge, _ := crypto.BuildFirmwareChallenge()
	resp, err := dev.RespondFirmwareChallenge(challenge)
	if err != nil {
		t.Fatalf("respond challenge: %v", err)
	}
	devIdentityPub, _ := dev.Identity.PublicKeyBytes()
	result, err := crypto.VerifyFirmwareResponse(
		devIdentityPub, crypto.SigECDSAP256, challenge, resp, referenceHash)
	if err != nil {
		t.Fatalf("verify firmware response: %v", err)
	}
	if result.OK() {
		t.Fatal("tampered firmware must fail the integrity check")
	}
	// Подпись при этом валидна (устройство честно подписало), но хеш не совпал.
	if !result.SignatureValid {
		t.Fatal("signature should still be valid; only the hash must mismatch")
	}
	if result.HashMatches {
		t.Fatal("hash must NOT match after tampering")
	}
}

func TestCloseSessionClearsKey(t *testing.T) {
	dev, _, _ := newHandshookDevice(t)
	dev.CloseSession()
	// После закрытия сессии отправка данных должна завершаться ошибкой.
	if _, _, err := dev.SendData([]byte("x")); err == nil {
		t.Fatal("expected error sending data after session close")
	}
}

func TestSLHDSADeviceHandshake(t *testing.T) {
	// Убеждаемся, что устройство работает и с постквантовой подписью SLH-DSA,
	// а не только с ECDSA.
	dev, err := NewDevice("dev-slh", crypto.SigSLHDSA, []byte("fw"))
	if err != nil {
		t.Fatalf("new slh device: %v", err)
	}
	gwKEM, _ := crypto.GenerateKEMKeyPair()
	dev.SetGatewayKEMPublicKey(gwKEM.Pub)

	msg1, _ := dev.StartHandshake()
	msg2, gwSS, _ := crypto.BuildMsg2(dev.KEM.Pub)
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		t.Fatalf("complete handshake: %v", err)
	}
	devIdentityPub, _ := dev.Identity.PublicKeyBytes()
	if _, err := crypto.FinalizeHandshake(devIdentityPub, crypto.SigSLHDSA, msg1, msg2, msg3, gwSS); err != nil {
		t.Fatalf("finalize slh handshake: %v", err)
	}
}
