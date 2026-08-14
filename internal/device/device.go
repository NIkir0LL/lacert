// Package device эмулирует сторону IoT-устройства (плата XIAO ESP32-C6/S3)
// протокола LACERT — без реального железа. Каждый метод соответствует
// конкретному блоку UML-диаграммы из работы ("Подготовка", "Начальное
// рукопожатие", "Непрерывная ротация ключей", "Проверка целостности
// прошивки"). Поля Identity/KEM эмулируют ключи, которые на реальном
// устройстве лежат в efuse и программно не читаются — здесь это просто
// поля структуры, так как цель симулятора — проверить корректность логики
// протокола, а не повторить аппаратные гарантии (это будет сделано на
// этапе переноса на C/ESP-IDF).
package device

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"lacert/internal/crypto"
	"lacert/internal/regtool"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// Device — состояние одного симулируемого IoT-устройства.
type Device struct {
	ID       string
	Identity *crypto.IdentityKeyPair // efuse: ключ подписи (ECDSA P-256 или SLH-DSA)
	KEM      *crypto.KEMKeyPair      // efuse: ключ ML-KEM-1024

	// FirmwareImage — содержимое "прошивки" в симуляторе. На реальном
	// устройстве для проверки целостности достаточно было бы заранее
	// посчитанного хеша области Flash, без хранения образа целиком.
	FirmwareImage []byte

	session    *crypto.Session
	gatewayKEM *mlkem1024.PublicKey // публичный ключ шлюза, известен после регистрации/провижининга
}

// NewDevice эмулирует блок "Подготовка": активацию Secure Boot, генерацию
// efuse-ключей (ECDSA/SLH-DSA для подписи и ML-KEM-1024 для обмена ключами)
// и запись начального состояния. Выполняется один раз при первой загрузке.
func NewDevice(id string, sigAlg crypto.SigAlgorithm, firmwareImage []byte) (*Device, error) {
	identity, err := crypto.GenerateIdentity(sigAlg)
	if err != nil {
		return nil, fmt.Errorf("generate identity (efuse signing key): %w", err)
	}
	kem, err := crypto.GenerateKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate kem keypair (efuse kem key): %w", err)
	}
	return &Device{
		ID:            id,
		Identity:      identity,
		KEM:           kem,
		FirmwareImage: firmwareImage,
	}, nil
}

// SerialRegistrationOutput эмулирует вывод данных через Serial-порт сразу
// после "Подготовки" — то, что администратор физически считывает с
// устройства для офлайн-регистрации (см. internal/regtool).
func (d *Device) SerialRegistrationOutput() (regtool.SerialOutput, error) {
	identityPub, err := d.Identity.PublicKeyBytes()
	if err != nil {
		return regtool.SerialOutput{}, err
	}
	return regtool.BuildSerialOutput(d.ID, identityPub, d.KEM.PublicKeyBytes(), d.FirmwareHash()), nil
}

// SetGatewayKEMPublicKey запоминает публичный ключ ML-KEM-1024 шлюза.
// В реальной системе это часть данных, которыми устройство и шлюз
// обмениваются один раз при провижининге в изолированной сети (наряду с
// IP-адресом/именем шлюза в конфигурации устройства).
func (d *Device) SetGatewayKEMPublicKey(pub *mlkem1024.PublicKey) {
	d.gatewayKEM = pub
}

// StartHandshake — Msg1 блока "Начальное рукопожатие".
func (d *Device) StartHandshake() (*crypto.HandshakeMsg1, error) {
	identityPub, err := d.Identity.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	return crypto.NewHandshakeMsg1(d.ID, identityPub)
}

// CompleteHandshake обрабатывает Msg2 от шлюза, вычисляет K0 и формирует
// Msg3. После вызова у устройства появляется рабочая сессия с защищённым
// каналом.
func (d *Device) CompleteHandshake(msg1 *crypto.HandshakeMsg1, msg2 *crypto.HandshakeMsg2) (*crypto.HandshakeMsg3, error) {
	msg3, k0, err := crypto.BuildMsg3(d.KEM.Priv, d.Identity, msg1, msg2)
	if err != nil {
		return nil, fmt.Errorf("build msg3: %w", err)
	}
	session, err := crypto.NewSession(k0)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	d.session = session
	return msg3, nil
}

// HasSession сообщает, установлен ли защищённый канал.
// ControlKey отдаёт действующий сеансовый ключ для вычисления метки
// подлинности служебных кадров.
//
// Ключ наружу отдавать не хочется, но иначе транспорт не сможет подписать
// служебный кадр. Область применения ограничена: метка считается по ключу
// вместе с типом кадра и номером шага (см. crypto/controltag.go), так что
// использовать полученное значение для чего-то другого не выйдет без прямого
// умысла.
//
// Важно, когда именно его брать. Устройство применяет ротацию до отправки
// подтверждения, и после этого ключ уже новый, тогда как шлюз проверит метку
// прежним. Поэтому ключ берётся ДО применения ротации.
func (d *Device) ControlKey() ([32]byte, error) {
	if d.session == nil {
		return [32]byte{}, errors.New("no active session")
	}
	return d.session.CurrentKey()
}

func (d *Device) HasSession() bool {
	return d.session != nil
}

// SendData шифрует прикладные данные текущим сеансовым ключом и
// инкрементирует счётчик пакетов (для триггера ротации по числу пакетов).
func (d *Device) SendData(plaintext []byte) (nonce, ciphertext []byte, err error) {
	if d.session == nil {
		return nil, nil, errors.New("no active session: complete handshake first")
	}
	key, err := d.session.CurrentKey()
	if err != nil {
		return nil, nil, err
	}
	stats := d.session.Stats()
	nonce, ciphertext, err = crypto.EncryptPacket(key, uint32(stats.PacketCount), plaintext)
	if err != nil {
		return nil, nil, err
	}
	d.session.RecordPacket()
	return nonce, ciphertext, nil
}

// ReceiveData расшифровывает данные, пришедшие от собеседника (на устройстве
// это нужно, например, для приёма команд от шлюза в рамках уже установленной
// сессии).
func (d *Device) ReceiveData(nonce, ciphertext []byte) ([]byte, error) {
	if d.session == nil {
		return nil, errors.New("no active session")
	}
	key, err := d.session.CurrentKey()
	if err != nil {
		return nil, err
	}
	pt, err := crypto.DecryptPacket(key, nonce, ciphertext)
	if err != nil {
		return nil, err
	}
	d.session.RecordPacket()
	return pt, nil
}

// NeedsRotation сообщает, наступило ли время ротации ключа (300 секунд или
// 300 пакетов).
func (d *Device) NeedsRotation() bool {
	if d.session == nil {
		return false
	}
	return d.session.NeedsRotation()
}

// InitiateRotation — устройство сам инициирует ротацию (инкапсулирует секрет
// под KEM-публичным ключом шлюза). Используется, когда именно устройство
// первым замечает, что наступило время ротации (см. rotation.go в crypto —
// схема симметрична, инициировать может любая сторона).
func (d *Device) InitiateRotation() (*crypto.RotationMsg, error) {
	if d.session == nil {
		return nil, errors.New("no active session")
	}
	if d.gatewayKEM == nil {
		return nil, errors.New("gateway kem public key is not configured")
	}
	return crypto.InitiateRotation(d.session, d.gatewayKEM)
}

// HandleRotationFromGateway — устройство получает RotationMsg, инициированный
// шлюзом, и обновляет свою сессию.
func (d *Device) HandleRotationFromGateway(msg *crypto.RotationMsg) error {
	if d.session == nil {
		return errors.New("no active session")
	}
	return crypto.RespondToRotation(d.session, d.KEM.Priv, msg)
}

// --- Атомарная ротация (варианты А+В) на стороне устройства ---

// InitiateAtomicRotation — устройство инициирует атомарную ротацию,
// инкапсулируя секрет под KEM-ключом шлюза. Новый ключ вычислен, но применится
// только после получения RotationAck от шлюза (см. ApplyRotationAckFromGateway).
func (d *Device) InitiateAtomicRotation() (*crypto.RotationMsgV2, error) {
	if d.session == nil {
		return nil, errors.New("no active session")
	}
	if d.gatewayKEM == nil {
		return nil, errors.New("gateway kem public key is not configured")
	}
	return crypto.InitiateRotationAtomic(d.session, d.gatewayKEM)
}

// HandleAtomicRotationFromGateway — устройство получило RotationMsgV2 от шлюза,
// применяет ротацию и возвращает RotationAck для отправки обратно.
func (d *Device) HandleAtomicRotationFromGateway(msg *crypto.RotationMsgV2) (*crypto.RotationAck, error) {
	if d.session == nil {
		return nil, errors.New("no active session")
	}
	return crypto.RespondToRotationAtomic(d.session, d.KEM.Priv, msg)
}

// ApplyRotationAckFromGateway — устройство получило подтверждение своей
// инициированной ротации и коммитит переход на новый ключ.
func (d *Device) ApplyRotationAckFromGateway(ack *crypto.RotationAck) error {
	if d.session == nil {
		return errors.New("no active session")
	}
	return crypto.ApplyRotationAck(d.session, ack)
}

// SessionStats — для логирования/демонстрации.
func (d *Device) SessionStats() crypto.Stats {
	if d.session == nil {
		return crypto.Stats{}
	}
	return d.session.Stats()
}

// SessionIteration возвращает номер последней применённой атомарной ротации
// (0 сразу после рукопожатия).
func (d *Device) SessionIteration() uint64 {
	if d.session == nil {
		return 0
	}
	return d.session.Iteration()
}

// RespondFirmwareChallenge — блок "Проверка целостности прошивки": устройство
// подписывает запрос вместе с хешем своей текущей прошивки.
func (d *Device) RespondFirmwareChallenge(challenge []byte) (*crypto.FirmwareResponse, error) {
	return crypto.RespondToFirmwareChallenge(d.Identity, challenge, d.FirmwareImage)
}

// TamperFirmware эмулирует несанкционированную модификацию прошивки — для
// демонстрации того, что проверка целостности её обнаруживает.
func (d *Device) TamperFirmware(maliciousPayload []byte) {
	d.FirmwareImage = append(append([]byte{}, d.FirmwareImage...), maliciousPayload...)
}

// FirmwareHash — текущий хеш прошивки устройства (для удобства тестов/демо,
// аналог того, что реально вычисляется на ESP32 по области Flash).
func (d *Device) FirmwareHash() [sha256.Size]byte {
	return sha256.Sum256(d.FirmwareImage)
}

// CloseSession затирает ключи сессии — например, при разрыве соединения.
func (d *Device) CloseSession() {
	if d.session != nil {
		d.session.Close()
	}
}
