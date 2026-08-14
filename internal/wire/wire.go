// Package wire реализует двоичный протокол передачи сообщений LACERT по
// сети (TCP). Формат кадра:
//
//	[4 байта BE: длина payload][1 байт: тип сообщения][payload...]
//
// Сериализация полей сообщения внутри payload использует простое
// кадрирование переменной длины (2-байтовая BE-длина перед каждым полем
// переменного размера) — этого достаточно для прототипа; в дальнейшем
// (после переноса на ESP32) этот же формат используется и в прошивке, так
// как он не требует библиотек сериализации, что важно при ограниченной
// Flash-памяти.
package wire

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"lacert/internal/crypto"
)

// Типы сообщений — однобайтовый тег сразу после длины кадра.
const (
	TypeHandshakeMsg1     byte = 1
	TypeHandshakeMsg2     byte = 2
	TypeHandshakeMsg3     byte = 3
	TypeRotation          byte = 4
	TypeData              byte = 5
	TypeFirmwareChallenge byte = 6
	TypeFirmwareResponse  byte = 7
	TypeError             byte = 8
	// Атомарная ротация (варианты А+В): сообщение ротации с номером итерации
	// и подтверждение применения. TypeRotation (=4) сохранён для обратной
	// совместимости со старой неатомарной схемой.
	TypeRotationV2  byte = 9
	TypeRotationAck byte = 10
)

// MaxFrameSize — защитный предел на размер одного кадра (от заведомо
// испорченных/враждебных данных на входе TCP-соединения).
const MaxFrameSize = 64 * 1024

// WriteFrame пишет один кадр: [длина][тип][payload].
func WriteFrame(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("payload too large: %d > %d", len(payload), MaxFrameSize)
	}
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4] = msgType
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	if bw, ok := w.(*bufio.Writer); ok {
		return bw.Flush()
	}
	return nil
}

// ReadFrame читает один кадр целиком.
func ReadFrame(r io.Reader) (msgType byte, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err // включая io.EOF — нормальное закрытие соединения
	}
	length := binary.BigEndian.Uint32(header[0:4])
	if length > MaxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d > %d", length, MaxFrameSize)
	}
	msgType = header[4]
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read frame payload: %w", err)
	}
	return msgType, payload, nil
}

// --- кадрирование переменной длины внутри payload одного сообщения ---

// maxFieldSize — предел поля переменной длины: длина кодируется двумя байтами.
// Значение больше не помещается в uint16 и молча усекалось бы при кодировании
// (`uint16(65536)` = 0), из-за чего декодер на той стороне прочитал бы поле
// нулевой длины, а остаток данных принял за следующее поле. MaxFrameSize
// (65536) БОЛЬШЕ этого предела, так что случай достижим в принципе — лучше
// узнать о нём здесь, чем ловить рассинхрон разбора на проводе.
const maxFieldSize = 0xFFFF

func putFramed(buf []byte, data []byte) []byte {
	if len(data) > maxFieldSize {
		// Кодировщики wire не возвращают ошибку (все вызовы идут с полями
		// заведомо известного размера: ключи, шифротексты, подписи), поэтому
		// нарушение инварианта — это дефект в вызывающем коде, а не
		// некорректный ввод из сети. Паника здесь честнее тихого усечения:
		// в tcpserver она перехватывается и роняет одно соединение.
		panic("wire: field too large for 2-byte length prefix")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, data...)
	return buf
}

func takeFramed(buf []byte) (data, rest []byte, err error) {
	if len(buf) < 2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	// Критично: n приводится к int ДО сложения с 2, а не после. Если
	// написать `2+n` с n типа uint16 близким к максимуму (0xFFFE=65534),
	// Go выполнит сложение в типе uint16 и получит переполнение
	// (2+65534=65536 mod 65536 = 0) ДО приведения к int — то есть проверка
	// `len(buf) < int(2+n)` окажется `len(buf) < 0`, всегда false, и код
	// уйдёт в buf[2:65536] на 4-байтовом входе. Это реальная уязвимость
	// отказа в обслуживании: любой байтовый мусор на TCP-порту 7700
	// (например, случайный сканер сети, а не только злонамеренный ввод)
	// мог обрушить panic'ом горутину, обрабатывающую это соединение.
	// Найдено и исправлено при аудите проекта.
	//
	// Позже в handleConn добавлен recover() — но как второй рубеж, а не
	// замена этой проверке: паника там уронит одно соединение вместо
	// процесса, однако правильные границы здесь остаются основной защитой.
	n := int(binary.BigEndian.Uint16(buf[0:2]))
	if len(buf) < 2+n {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return buf[2 : 2+n], buf[2+n:], nil
}

// --- HandshakeMsg1 ---

func EncodeMsg1(m *crypto.HandshakeMsg1) []byte {
	var buf []byte
	buf = putFramed(buf, []byte(m.DeviceID))
	buf = append(buf, m.Nonce[:]...)
	buf = putFramed(buf, m.IdentityPub)
	return buf
}

func DecodeMsg1(payload []byte) (*crypto.HandshakeMsg1, error) {
	deviceID, rest, err := takeFramed(payload)
	if err != nil {
		return nil, fmt.Errorf("decode msg1 device id: %w", err)
	}
	if len(rest) < 32 {
		return nil, io.ErrUnexpectedEOF
	}
	var nonce [32]byte
	copy(nonce[:], rest[:32])
	rest = rest[32:]
	identityPub, _, err := takeFramed(rest)
	if err != nil {
		return nil, fmt.Errorf("decode msg1 identity pub: %w", err)
	}
	return &crypto.HandshakeMsg1{DeviceID: string(deviceID), Nonce: nonce, IdentityPub: identityPub}, nil
}

// --- HandshakeMsg2 ---

func EncodeMsg2(m *crypto.HandshakeMsg2) []byte {
	var buf []byte
	buf = putFramed(buf, m.KEMCiphertext)
	buf = append(buf, m.GatewayNonce[:]...)
	return buf
}

func DecodeMsg2(payload []byte) (*crypto.HandshakeMsg2, error) {
	ct, rest, err := takeFramed(payload)
	if err != nil {
		return nil, fmt.Errorf("decode msg2 ciphertext: %w", err)
	}
	if len(rest) < 32 {
		return nil, io.ErrUnexpectedEOF
	}
	var gwNonce [32]byte
	copy(gwNonce[:], rest[:32])
	return &crypto.HandshakeMsg2{KEMCiphertext: ct, GatewayNonce: gwNonce}, nil
}

// --- HandshakeMsg3 ---

func EncodeMsg3(m *crypto.HandshakeMsg3) []byte {
	return putFramed(nil, m.Signature)
}

func DecodeMsg3(payload []byte) (*crypto.HandshakeMsg3, error) {
	sig, _, err := takeFramed(payload)
	if err != nil {
		return nil, fmt.Errorf("decode msg3 signature: %w", err)
	}
	return &crypto.HandshakeMsg3{Signature: sig}, nil
}

// --- RotationMsg ---

func EncodeRotation(m *crypto.RotationMsg) []byte {
	return putFramed(nil, m.KEMCiphertext)
}

func DecodeRotation(payload []byte) (*crypto.RotationMsg, error) {
	ct, _, err := takeFramed(payload)
	if err != nil {
		return nil, fmt.Errorf("decode rotation ciphertext: %w", err)
	}
	return &crypto.RotationMsg{KEMCiphertext: ct}, nil
}

// --- RotationMsgV2 (атомарная ротация: номер итерации + шифротекст) ---

// EncodeRotationV2 собирает кадр начала ротации и подписывает его меткой на
// сеансовом ключе.
//
// Метка добавлена этой правкой формата. Прежде служебные кадры шли
// открытым текстом, и вклинившийся в соединение мог подменить или вбросить
// такой кадр, не зная сеансового ключа. Подробности — в crypto/controltag.go.
func EncodeRotationV2(m *crypto.RotationMsgV2, sessionKey []byte) []byte {
	body := encodeRotationV2Body(m)
	tag := crypto.ComputeControlTag(sessionKey, TypeRotationV2, m.Iteration, body)
	return append(body, tag...)
}

func encodeRotationV2Body(m *crypto.RotationMsgV2) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], m.Iteration)
	out := make([]byte, 0, 8+2+len(m.KEMCiphertext)+crypto.ControlTagSize)
	out = append(out, buf[:]...)
	out = putFramed(out, m.KEMCiphertext)
	return out
}

// DecodeRotationV2 разбирает кадр начала ротации и проверяет его метку.
//
// Метка проверяется до разбора содержимого: кадр от того, кто не знает
// сеансового ключа, отбрасывается целиком, и разбирать его незачем.
func DecodeRotationV2(payload []byte, sessionKey []byte) (*crypto.RotationMsgV2, error) {
	if len(payload) < 8+crypto.ControlTagSize {
		return nil, fmt.Errorf("decode rotation v2: payload too short")
	}
	split := len(payload) - crypto.ControlTagSize
	body, tag := payload[:split], payload[split:]

	iteration := binary.BigEndian.Uint64(body[0:8])
	if err := crypto.VerifyControlTag(sessionKey, TypeRotationV2, iteration, body, tag); err != nil {
		return nil, fmt.Errorf("decode rotation v2: %w", err)
	}

	ct, _, err := takeFramed(body[8:])
	if err != nil {
		return nil, fmt.Errorf("decode rotation v2 ciphertext: %w", err)
	}
	return &crypto.RotationMsgV2{Iteration: iteration, KEMCiphertext: ct}, nil
}

// --- RotationAck (подтверждение применения ротации) ---

// EncodeRotationAck собирает подтверждение ротации с меткой подлинности.
//
// Этот кадр опаснее прочих: прежде он состоял из восьми байт номера шага и
// ничего больше. Вброшенное подтверждение заставляло шлюз применить ротацию,
// тогда как устройство её не применяло — ключи расходились, и устройство
// в итоге отзывалось.
func EncodeRotationAck(a *crypto.RotationAck, sessionKey []byte) []byte {
	var body [8]byte
	binary.BigEndian.PutUint64(body[:], a.Iteration)
	tag := crypto.ComputeControlTag(sessionKey, TypeRotationAck, a.Iteration, body[:])
	return append(body[:], tag...)
}

func DecodeRotationAck(payload []byte, sessionKey []byte) (*crypto.RotationAck, error) {
	if len(payload) < 8+crypto.ControlTagSize {
		return nil, fmt.Errorf("decode rotation ack: payload too short")
	}
	body, tag := payload[:8], payload[8:8+crypto.ControlTagSize]
	iteration := binary.BigEndian.Uint64(body[0:8])
	if err := crypto.VerifyControlTag(sessionKey, TypeRotationAck, iteration, body, tag); err != nil {
		return nil, fmt.Errorf("decode rotation ack: %w", err)
	}
	return &crypto.RotationAck{Iteration: iteration}, nil
}

// --- Data packet ---

func EncodeData(nonce, ciphertext []byte) []byte {
	var buf []byte
	buf = putFramed(buf, nonce)
	buf = putFramed(buf, ciphertext)
	return buf
}

func DecodeData(payload []byte) (nonce, ciphertext []byte, err error) {
	nonce, rest, err := takeFramed(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decode data nonce: %w", err)
	}
	ciphertext, _, err = takeFramed(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("decode data ciphertext: %w", err)
	}
	return nonce, ciphertext, nil
}

// --- Firmware challenge / response ---

func EncodeFirmwareChallenge(challenge []byte) []byte {
	return putFramed(nil, challenge)
}

func DecodeFirmwareChallenge(payload []byte) (challenge []byte, err error) {
	challenge, _, err = takeFramed(payload)
	return challenge, err
}

func EncodeFirmwareResponse(r *crypto.FirmwareResponse) []byte {
	var buf []byte
	buf = append(buf, r.FirmwareHash[:]...)
	buf = putFramed(buf, r.Signature)
	return buf
}

func DecodeFirmwareResponse(payload []byte) (*crypto.FirmwareResponse, error) {
	if len(payload) < crypto.FirmwareHashSize {
		return nil, io.ErrUnexpectedEOF
	}
	var hash [crypto.FirmwareHashSize]byte
	copy(hash[:], payload[:crypto.FirmwareHashSize])
	sig, _, err := takeFramed(payload[crypto.FirmwareHashSize:])
	if err != nil {
		return nil, fmt.Errorf("decode firmware response signature: %w", err)
	}
	return &crypto.FirmwareResponse{FirmwareHash: hash, Signature: sig}, nil
}

// EncodeErrorMsg/DecodeErrorMsg — для передачи человекочитаемой ошибки
// собеседнику перед закрытием соединения (например, "device revoked").
// Кадр ошибки метку подлинности не несёт, и это осознанное решение.
//
// Две причины. Первая: кадр отправляется в том числе при отказе в рукопожатии,
// когда сеансового ключа ещё нет ни у одной стороны, и подписывать его нечем.
// Вторая: подделка этого кадра не даёт ничего сверх того, что и так доступно.
// Единственное следствие получения — устройство закрывает соединение и
// переподключается, а тот, кто способен вбросить кадр в соединение, способен
// и просто оборвать его.
//
// Отсюда важное ограничение, которое стоит держать в голове: содержимому
// кадра ошибки доверять нельзя, и решений на его основе принимать не следует.
// Сейчас устройство только пишет причину в журнал и разрывает связь — этого
// достаточно.
func EncodeErrorMsg(msg string) []byte     { return []byte(msg) }
func DecodeErrorMsg(payload []byte) string { return string(payload) }
