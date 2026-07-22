package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/zeebo/blake3"
)

// Начальное рукопожатие реализует трёхшаговый обмен, описанный в работе
// (раздел "2. Начальное постквантовое рукопожатие"):
//
//   Msg1 (устройство -> шлюз):  Noise_XX-style начало + DeviceID + identity-pubkey
//   Msg2 (шлюз -> устройство):  ML-KEM-1024 шифротекст (encaps под KEM-pubkey устройства)
//   Msg3 (устройство -> шлюз):  подпись подтверждения (decaps-результат + efuse-подпись)
//
// Важное архитектурное уточнение относительно текста работы: чтобы шлюз мог
// сделать encaps в Msg2, ему уже должен быть известен KEM-публичный ключ
// устройства — то есть KEM-keypair генерируется на устройстве один раз при
// "Подготовке" и его публичная часть передаётся шлюзу при офлайн-регистрации
// (вместе с identity-pubkey и HMAC). Это не меняет суть протокола, просто
// делает явным то, что в тексте подразумевалось, но не было детализировано.
//
// Для непрерывной ротации ключей (rotation.go) дополнительно требуется,
// чтобы и шлюз имел собственную пару ML-KEM-1024, известную устройству —
// тогда любая из сторон может инициировать ротацию, инкапсулируя секрет под
// KEM-публичным ключом собеседника. Это даёт симметричную схему ротации,
// которая на UML-диаграмме показана как вычисление Ki+1 на обеих сторонах
// независимо.

// HandshakeMsg1 — первое сообщение, отправляемое устройством.
type HandshakeMsg1 struct {
	DeviceID    string
	Nonce       [32]byte // случайность устройства, защита от replay
	IdentityPub []byte   // efuse-привязанный публичный ключ подписи устройства
}

// Bytes — каноническое байтовое представление, используемое при подсчёте
// транскрипта рукопожатия (для подписи подтверждения в Msg3).
func (m *HandshakeMsg1) Bytes() []byte {
	var buf bytes.Buffer
	writeFramed(&buf, []byte(m.DeviceID))
	buf.Write(m.Nonce[:])
	writeFramed(&buf, m.IdentityPub)
	return buf.Bytes()
}

// HandshakeMsg2 — ответ шлюза с ML-KEM-1024 шифротекстом.
type HandshakeMsg2 struct {
	KEMCiphertext []byte // 1568 байт для ML-KEM-1024
	GatewayNonce  [32]byte
}

func (m *HandshakeMsg2) Bytes() []byte {
	var buf bytes.Buffer
	writeFramed(&buf, m.KEMCiphertext)
	buf.Write(m.GatewayNonce[:])
	return buf.Bytes()
}

// HandshakeMsg3 — подтверждение от устройства: подпись над транскриптом и
// над производным от K0 значением, что одновременно доказывает (а) владение
// efuse-привязанным приватным ключом подписи и (б) совпадение вычисленного
// устройством K0 с тем, что вычислит шлюз.
type HandshakeMsg3 struct {
	Signature []byte
}

// NewHandshakeMsg1 создаёт первое сообщение со стороны устройства.
func NewHandshakeMsg1(deviceID string, identityPub []byte) (*HandshakeMsg1, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return &HandshakeMsg1{DeviceID: deviceID, Nonce: nonce, IdentityPub: identityPub}, nil
}

// BuildMsg2 выполняется на стороне шлюза при получении Msg1. devKEMPub —
// публичный ключ ML-KEM-1024 устройства, известный шлюзу из БД устройств
// (записан туда при офлайн-регистрации). Возвращает Msg2 для отправки
// устройству и общий секрет (для последующего вычисления K0 в FinalizeHandshake).
func BuildMsg2(devKEMPub *mlkem1024.PublicKey) (msg2 *HandshakeMsg2, sharedSecret []byte, err error) {
	ct, ss, err := Encapsulate(devKEMPub)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulate: %w", err)
	}
	var gwNonce [32]byte
	if _, err := rand.Read(gwNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate gateway nonce: %w", err)
	}
	return &HandshakeMsg2{KEMCiphertext: ct, GatewayNonce: gwNonce}, ss, nil
}

// BuildMsg3 выполняется на стороне устройства при получении Msg2.
// devKEMPriv — приватный ключ ML-KEM-1024 устройства (хранится в защищённой
// области, в реальной системе недоступен программному чтению).
// identity — efuse-привязанная пара ключей подписи устройства.
// Возвращает Msg3 для отправки шлюзу и итоговый K0.
func BuildMsg3(
	devKEMPriv *mlkem1024.PrivateKey,
	identity *IdentityKeyPair,
	msg1 *HandshakeMsg1,
	msg2 *HandshakeMsg2,
) (msg3 *HandshakeMsg3, k0 []byte, err error) {
	sharedSecret, err := Decapsulate(devKEMPriv, msg2.KEMCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decapsulate: %w", err)
	}

	transcript := transcriptOf(msg1, msg2)
	k0 = DeriveK0(sharedSecret, transcript)
	zeroize(sharedSecret)

	confirmVal := confirmationValue(transcript, k0)
	sig, err := identity.Sign(confirmVal)
	if err != nil {
		return nil, nil, fmt.Errorf("sign confirmation: %w", err)
	}

	return &HandshakeMsg3{Signature: sig}, k0, nil
}

// FinalizeHandshake выполняется на стороне шлюза при получении Msg3.
// devIdentityPub/devSigAlg — зарегистрированные identity-данные устройства.
// sharedSecret — секрет, полученный шлюзом на шаге BuildMsg2 (тот же объект,
// что и на устройстве, при корректной работе протокола).
// Возвращает K0, если подпись верна и подтверждает совпадение ключа.
func FinalizeHandshake(
	devIdentityPub []byte,
	devSigAlg SigAlgorithm,
	msg1 *HandshakeMsg1,
	msg2 *HandshakeMsg2,
	msg3 *HandshakeMsg3,
	sharedSecret []byte,
) (k0 []byte, err error) {
	transcript := transcriptOf(msg1, msg2)
	k0 = DeriveK0(sharedSecret, transcript)

	confirmVal := confirmationValue(transcript, k0)
	ok, err := VerifySignature(devSigAlg, devIdentityPub, confirmVal, msg3.Signature)
	if err != nil {
		return nil, fmt.Errorf("verify confirmation signature: %w", err)
	}
	if !ok {
		zeroize(k0)
		return nil, errors.New("handshake confirmation failed: invalid signature or key mismatch")
	}
	return k0, nil
}

func transcriptOf(msg1 *HandshakeMsg1, msg2 *HandshakeMsg2) []byte {
	h := blake3.New()
	h.Write(msg1.Bytes())
	h.Write(msg2.Bytes())
	return h.Sum(nil)
}

func confirmationValue(transcript, k0 []byte) []byte {
	h := blake3.New()
	h.Write(transcript)
	h.Write([]byte("confirm"))
	h.Write(k0)
	return h.Sum(nil)
}

// writeFramed пишет 2-байтовую длину (big-endian) и затем сами данные —
// простой механизм кадрирования переменной длины для канонической
// сериализации сообщений перед хешированием/подписью.
func writeFramed(buf *bytes.Buffer, data []byte) {
	if len(data) > 0xFFFF {
		// См. wire.putFramed: усечение длины до uint16 сделало бы транскрипт
		// неоднозначным (разные сообщения дали бы одинаковые байты), а на нём
		// строится подпись подтверждения.
		panic("crypto: field too large for 2-byte length prefix")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	buf.Write(lenBuf[:])
	buf.Write(data)
}
