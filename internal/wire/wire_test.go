package wire

import (
	"bytes"
	"fmt"
	"testing"

	"lacert/internal/crypto"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello-lacert-frame")
	if err := WriteFrame(&buf, TypeData, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	gotType, gotPayload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if gotType != TypeData {
		t.Fatalf("type mismatch: got %d want %d", gotType, TypeData)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: got %q want %q", gotPayload, payload)
	}
}

func TestMultipleFramesSequentially(t *testing.T) {
	var buf bytes.Buffer
	must(WriteFrame(&buf, TypeData, []byte("first")))
	must(WriteFrame(&buf, TypeRotation, []byte("second")))
	must(WriteFrame(&buf, TypeError, []byte("third")))

	for _, want := range []struct {
		typ byte
		val string
	}{
		{TypeData, "first"},
		{TypeRotation, "second"},
		{TypeError, "third"},
	} {
		typ, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if typ != want.typ || string(payload) != want.val {
			t.Fatalf("got (%d,%q) want (%d,%q)", typ, payload, want.typ, want.val)
		}
	}
}

func TestMsg1RoundTrip(t *testing.T) {
	identity, err := crypto.GenerateIdentity(crypto.SigECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := identity.PublicKeyBytes()
	m1, err := crypto.NewHandshakeMsg1("xiao-esp32c6-test", pub)
	if err != nil {
		t.Fatal(err)
	}

	encoded := EncodeMsg1(m1)
	decoded, err := DecodeMsg1(encoded)
	if err != nil {
		t.Fatalf("decode msg1: %v", err)
	}
	if decoded.DeviceID != m1.DeviceID {
		t.Fatalf("device id mismatch: got %q want %q", decoded.DeviceID, m1.DeviceID)
	}
	if decoded.Nonce != m1.Nonce {
		t.Fatal("nonce mismatch")
	}
	if !bytes.Equal(decoded.IdentityPub, m1.IdentityPub) {
		t.Fatal("identity pub mismatch")
	}
}

func TestMsg2RoundTrip(t *testing.T) {
	kp, err := crypto.GenerateKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m2, _, err := crypto.BuildMsg2(kp.Pub)
	if err != nil {
		t.Fatal(err)
	}

	encoded := EncodeMsg2(m2)
	decoded, err := DecodeMsg2(encoded)
	if err != nil {
		t.Fatalf("decode msg2: %v", err)
	}
	if !bytes.Equal(decoded.KEMCiphertext, m2.KEMCiphertext) {
		t.Fatal("ciphertext mismatch")
	}
	if decoded.GatewayNonce != m2.GatewayNonce {
		t.Fatal("gateway nonce mismatch")
	}
}

func TestMsg3RoundTrip(t *testing.T) {
	m3 := &crypto.HandshakeMsg3{Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	decoded, err := DecodeMsg3(EncodeMsg3(m3))
	if err != nil {
		t.Fatalf("decode msg3: %v", err)
	}
	if !bytes.Equal(decoded.Signature, m3.Signature) {
		t.Fatal("signature mismatch")
	}
}

func TestRotationRoundTrip(t *testing.T) {
	r := &crypto.RotationMsg{KEMCiphertext: bytes.Repeat([]byte{0xAB}, 1568)}
	decoded, err := DecodeRotation(EncodeRotation(r))
	if err != nil {
		t.Fatalf("decode rotation: %v", err)
	}
	if !bytes.Equal(decoded.KEMCiphertext, r.KEMCiphertext) {
		t.Fatal("ciphertext mismatch")
	}
}

func TestDataRoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 12)
	ciphertext := bytes.Repeat([]byte{0x02}, 100)
	encoded := EncodeData(nonce, ciphertext)
	gotNonce, gotCT, err := DecodeData(encoded)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCT, ciphertext) {
		t.Fatal("data round trip mismatch")
	}
}

func TestFirmwareRoundTrip(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x03}, crypto.ChallengeSize)
	encodedChallenge := EncodeFirmwareChallenge(challenge)
	decodedChallenge, err := DecodeFirmwareChallenge(encodedChallenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if !bytes.Equal(decodedChallenge, challenge) {
		t.Fatal("challenge mismatch")
	}

	var hash [crypto.FirmwareHashSize]byte
	copy(hash[:], bytes.Repeat([]byte{0x04}, crypto.FirmwareHashSize))
	resp := &crypto.FirmwareResponse{FirmwareHash: hash, Signature: []byte{9, 9, 9}}
	decodedResp, err := DecodeFirmwareResponse(EncodeFirmwareResponse(resp))
	if err != nil {
		t.Fatalf("decode firmware response: %v", err)
	}
	if decodedResp.FirmwareHash != resp.FirmwareHash {
		t.Fatal("firmware hash mismatch")
	}
	if !bytes.Equal(decodedResp.Signature, resp.Signature) {
		t.Fatal("signature mismatch")
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// --- аудит устойчивости к вредоносному/повреждённому вводу (fuzz-style) ---
//
// Все декодеры разбирают байты, пришедшие по сети от недоверенного
// источника (TCP-порт 7700). Ниже — регрессионные тесты для найденного при
// аудите переполнения: `takeFramed` вычисляло `2+n` в типе uint16 (тип
// значения n), что при n близком к 0xFFFF переполняется и обнуляет
// проверку границ, приводя к панике при попытке взять срез за пределами
// буфера. Поскольку handleConn в tcpserver не оборачивает разбор кадра в
// recover(), такая паника была бы фатальной для всего процесса gatewayd, а
// не только для одного соединения — то есть один вредоносный или даже
// просто случайно повреждённый TCP-пакет мог обрушить весь шлюз.

func TestTakeFramedDoesNotPanicOnAdversarialInput(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"empty", nil},
		{"single byte", []byte{0x01}},
		{"length field claims more than available (small)", []byte{0x00, 0x05, 0x01, 0x02}},
		{"length = 0xFFFE, only 2 bytes follow (the original overflow repro)", []byte{0xFF, 0xFE, 0x01, 0x02}},
		{"length = 0xFFFF (max uint16), empty rest", []byte{0xFF, 0xFF}},
		{"length = 0xFFFF, some data", []byte{0xFF, 0xFF, 0x01, 0x02, 0x03}},
		{"length = 0x0000, empty rest", []byte{0x00, 0x00}},
		{"all 0xFF bytes, various lengths", bytes.Repeat([]byte{0xFF}, 10)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("takeFramed panicked on input %x: %v", tc.buf, r)
				}
			}()
			_, _, _ = takeFramed(tc.buf)
		})
	}
}

// TestDecodersDoNotPanicOnAdversarialPayloads прогоняет все Decode*
// функции через тот же набор патологических входов — это функции, которые
// реально вызываются из tcpserver.serveSession на сырых байтах из сокета.
func TestDecodersDoNotPanicOnAdversarialPayloads(t *testing.T) {
	adversarialInputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF},
		{0xFF, 0xFE, 0x01, 0x02},
		{0xFF, 0xFF},
		{0x00, 0x00},
		bytes.Repeat([]byte{0xFF}, 4),
		bytes.Repeat([]byte{0xFF}, 32),
		bytes.Repeat([]byte{0xFF}, 64),
		bytes.Repeat([]byte{0x00}, 64),
	}

	decoders := map[string]func([]byte) error{
		"DecodeMsg1":              func(b []byte) error { _, err := DecodeMsg1(b); return err },
		"DecodeMsg2":              func(b []byte) error { _, err := DecodeMsg2(b); return err },
		"DecodeMsg3":              func(b []byte) error { _, err := DecodeMsg3(b); return err },
		"DecodeRotation":          func(b []byte) error { _, err := DecodeRotation(b); return err },
		"DecodeData":              func(b []byte) error { _, _, err := DecodeData(b); return err },
		"DecodeFirmwareChallenge": func(b []byte) error { _, err := DecodeFirmwareChallenge(b); return err },
		"DecodeFirmwareResponse":  func(b []byte) error { _, err := DecodeFirmwareResponse(b); return err },
	}

	for name, decode := range decoders {
		for i, input := range adversarialInputs {
			t.Run(fmt.Sprintf("%s/input_%d", name, i), func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s panicked on input %x: %v", name, input, r)
					}
				}()
				_ = decode(input) // ошибка ожидаема и это нормально — недопустима именно паника
			})
		}
	}
}
