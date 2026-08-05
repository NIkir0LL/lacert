// Package crypto реализует криптографическое ядро протокола LACERT:
// постквантовое рукопожатие (ML-KEM-1024), непрерывную ротацию ключей
// (BLAKE3-деривация), симметричное шифрование данных (ChaCha20-Poly1305)
// и подписи для аутентификации устройства (ECDSA P-256 или SLH-DSA),
// эмулирующие привязку к efuse.
package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// SigAlgorithm — какая схема подписи используется как "efuse"-привязанный
// идентификационный ключ устройства/шлюза.
//
// В тексте работы для Msg3 рукопожатия и проверки целостности прошивки
// используется ECDSA P-256 (см. UML-диаграмму) — это значение по умолчанию.
// SLHDSA — это вариант алгоритма LACERT, описанный в разделе про разрабатываемый
// алгоритм: замена матричных операций на хеш-based подпись. Оба варианта
// реализованы, чтобы их можно было сравнить экспериментально (раздел
// "Сравнение и оценка результатов" работы).
type SigAlgorithm int

const (
	SigECDSAP256 SigAlgorithm = iota
	SigSLHDSA
	// SigEd25519 — классическая подпись на кривой Curve25519.
	// Добавлена по результатам замеров на микроконтроллере: на ESP32-S3 без
	// аппаратного ускорителя ECC подпись ECDSA P-256 занимает ~173 мс и
	// становится самой дорогой операцией протокола — дороже постквантовой
	// декапсуляции ML-KEM (~21 мс). Ed25519 обеспечивает сопоставимую
	// стойкость, но в программной реализации существенно быстрее.
	SigEd25519
)

func (a SigAlgorithm) String() string {
	switch a {
	case SigECDSAP256:
		return "ECDSA-P256"
	case SigSLHDSA:
		return "SLH-DSA-SHA2-128s"
	case SigEd25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// APIName возвращает идентификатор схемы в том виде, в каком он передаётся в
// поле sig_algorithm при регистрации устройства через REST.
//
// Отделён от String(): тот даёт человекочитаемое имя для журналов и отчётов
// ("SLH-DSA-SHA2-128s"), а протоколу нужен стабильный короткий ключ. Раньше
// такой строки не было вовсе, и клиенты писали её вручную — эмулятор,
// например, подставлял "ecdsa-p256" безусловно, из-за чего устройство с
// другой схемой регистрировалось под чужим алгоритмом и не могло завершить
// рукопожатие. Единственный источник истины избавляет от такого расхождения.
//
// Ed25519 намеренно не имеет имени: схема сохранена в ядре как инструмент
// сравнительных измерений, но устройствами не используется и REST API не
// принимается (см. parseSigAlgorithm в internal/api).
func (a SigAlgorithm) APIName() string {
	switch a {
	case SigECDSAP256:
		return "ecdsa-p256"
	case SigSLHDSA:
		return "slh-dsa"
	default:
		return ""
	}
}

// slhdsaID — конкретный параметр-набор SLH-DSA. Выбран "128s" (small): меньше
// размер ключей/подписи в обмен на более медленную генерацию подписи —
// для embedded-устройства с ограниченной Flash-памятью компактность важнее.
const slhdsaID = slhdsa.SHA2_128s

// IdentityKeyPair — пара ключей подписи, привязанная к "efuse" (в прототипе
// эмулируется обычным in-memory хранением приватного ключа в структуре
// устройства; при переносе на ESP32 приватная часть должна храниться так,
// чтобы не быть программно читаемой).
type IdentityKeyPair struct {
	Algorithm SigAlgorithm

	ecdsaPriv *ecdsa.PrivateKey
	ecdsaPub  *ecdsa.PublicKey

	slhPriv *slhdsa.PrivateKey
	slhPub  *slhdsa.PublicKey

	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey
}

// GenerateIdentity создаёт новую пару ключей подписи выбранного алгоритма.
// На реальном устройстве это происходит один раз при первой загрузке
// (блок "Подготовка" UML-диаграммы), и приватный ключ записывается в efuse.
func GenerateIdentity(alg SigAlgorithm) (*IdentityKeyPair, error) {
	switch alg {
	case SigECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa key: %w", err)
		}
		return &IdentityKeyPair{Algorithm: alg, ecdsaPriv: priv, ecdsaPub: &priv.PublicKey}, nil

	case SigSLHDSA:
		pub, priv, err := slhdsa.GenerateKey(rand.Reader, slhdsaID)
		if err != nil {
			return nil, fmt.Errorf("generate slh-dsa key: %w", err)
		}
		return &IdentityKeyPair{Algorithm: alg, slhPriv: &priv, slhPub: &pub}, nil

	case SigEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return &IdentityKeyPair{Algorithm: alg, edPriv: priv, edPub: pub}, nil

	default:
		return nil, fmt.Errorf("unknown signature algorithm %v", alg)
	}
}

// ecdsaCoordSize — размер одной координаты точки P-256 в байтах. Публичный
// ключ передаётся несжатой точкой: префикс 0x04, затем X и Y по 32 байта.
const ecdsaCoordSize = 32

// PublicKeyBytes возвращает сериализованный публичный ключ для передачи
// другой стороне / занесения в базу шлюза при офлайн-регистрации.
func (kp *IdentityKeyPair) PublicKeyBytes() ([]byte, error) {
	switch kp.Algorithm {
	case SigECDSAP256:
		// elliptic.Marshal объявлена устаревшей начиная с Go 1.21. Замена через
		// crypto/ecdh даёт тот же формат — несжатая точка 0x04 || X || Y, 65
		// байт, — поэтому совместимость с уже зарегистрированными устройствами
		// и с прошивкой сохраняется. Это проверяется тестом
		// TestECDSAPublicKeyWireFormatUnchanged.
		ecdhPub, err := kp.ecdsaPub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("convert ecdsa public key: %w", err)
		}
		return ecdhPub.Bytes(), nil
	case SigSLHDSA:
		return kp.slhPub.MarshalBinary()
	case SigEd25519:
		return append([]byte(nil), kp.edPub...), nil
	default:
		return nil, errors.New("unknown signature algorithm")
	}
}

// Sign подписывает сообщение приватным ключом ("efuse"-операция: на реальном
// устройстве вычисление происходит во внутреннем криптоускорителе, а сам
// приватный ключ программно прочитать нельзя).
func (kp *IdentityKeyPair) Sign(message []byte) ([]byte, error) {
	switch kp.Algorithm {
	case SigECDSAP256:
		digest := sha256.Sum256(message)
		return ecdsa.SignASN1(rand.Reader, kp.ecdsaPriv, digest[:])
	case SigSLHDSA:
		sig, err := slhdsa.SignRandomized(kp.slhPriv, rand.Reader, slhdsa.NewMessage(message), nil)
		if err != nil {
			return nil, fmt.Errorf("slh-dsa sign: %w", err)
		}
		return sig, nil
	case SigEd25519:
		// Ed25519 хеширует сообщение внутри себя (SHA-512), поэтому
		// предварительное хеширование, как для ECDSA, не требуется.
		return ed25519.Sign(kp.edPriv, message), nil
	default:
		return nil, errors.New("unknown signature algorithm")
	}
}

// VerifySignature проверяет подпись по сериализованному публичному ключу.
// Используется шлюзом для проверки Msg3 рукопожатия и ответа на проверку
// целостности прошивки, и устройством — для проверки, что оно говорит
// с легитимным шлюзом (в гибридной/симметричной схеме, см. handshake.go).
func VerifySignature(alg SigAlgorithm, pubBytes, message, signature []byte) (bool, error) {
	switch alg {
	case SigECDSAP256:
		// elliptic.Unmarshal объявлена устаревшей. Разбор идёт через
		// crypto/ecdh: он выполняет ту же проверку, что и прежняя функция, —
		// отвергает точку, не лежащую на кривой, и значения неверной длины.
		// Проверка обязательна: приняв произвольную точку, шлюз открыл бы путь
		// к атаке на недопустимую кривую.
		//
		// Обратного преобразования в ecdsa.PublicKey стандартная библиотека не
		// предоставляет, поэтому координаты берутся из уже проверенного
		// представления: Bytes() возвращает канонические 0x04 || X || Y.
		ecdhPub, err := ecdh.P256().NewPublicKey(pubBytes)
		if err != nil {
			return false, errors.New("invalid ecdsa public key bytes")
		}
		raw := ecdhPub.Bytes()
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(raw[1 : 1+ecdsaCoordSize]),
			Y:     new(big.Int).SetBytes(raw[1+ecdsaCoordSize:]),
		}
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(pub, digest[:], signature), nil

	case SigSLHDSA:
		var pub slhdsa.PublicKey
		pub.ID = slhdsaID
		if err := pub.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid slh-dsa public key bytes: %w", err)
		}
		return slhdsa.Verify(&pub, slhdsa.NewMessage(message), signature, nil), nil

	case SigEd25519:
		if len(pubBytes) != ed25519.PublicKeySize {
			return false, fmt.Errorf("invalid ed25519 public key size: %d", len(pubBytes))
		}
		return ed25519.Verify(ed25519.PublicKey(pubBytes), message, signature), nil

	default:
		return false, errors.New("unknown signature algorithm")
	}
}

// KEMKeyPair — пара ключей ML-KEM-1024 (Kyber-1024), используемая для
// постквантового установления общего секрета при рукопожатии и при каждой
// ротации ключей.
type KEMKeyPair struct {
	Pub  *mlkem1024.PublicKey
	Priv *mlkem1024.PrivateKey
}

// GenerateKEMKeyPair создаёт новую пару ключей ML-KEM-1024.
func GenerateKEMKeyPair() (*KEMKeyPair, error) {
	pub, priv, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ml-kem-1024 key: %w", err)
	}
	return &KEMKeyPair{Pub: pub, Priv: priv}, nil
}

// PublicKeyBytes сериализует публичный ключ ML-KEM-1024 (1568 байт — именно
// эта величина упоминается в работе как объём шифротекста при рукопожатии).
func (kp *KEMKeyPair) PublicKeyBytes() []byte {
	buf := make([]byte, mlkem1024.PublicKeySize)
	kp.Pub.Pack(buf)
	return buf
}

// UnpackKEMPublicKey восстанавливает публичный ключ ML-KEM-1024 из байт.
func UnpackKEMPublicKey(b []byte) (*mlkem1024.PublicKey, error) {
	if len(b) != mlkem1024.PublicKeySize {
		return nil, fmt.Errorf("invalid ml-kem-1024 public key size: got %d, want %d", len(b), mlkem1024.PublicKeySize)
	}
	var pub mlkem1024.PublicKey
	if err := pub.Unpack(b); err != nil {
		return nil, fmt.Errorf("unpack ml-kem-1024 public key: %w", err)
	}
	return &pub, nil
}

// Encapsulate инкапсулирует общий секрет под публичным ключом получателя.
// Возвращает шифротекст (1568 байт, отправляется по сети) и общий секрет
// (32 байта, остаётся локально).
func Encapsulate(pub *mlkem1024.PublicKey) (ciphertext, sharedSecret []byte, err error) {
	ct := make([]byte, mlkem1024.CiphertextSize)
	ss := make([]byte, mlkem1024.SharedKeySize)
	pub.EncapsulateTo(ct, ss, nil)
	return ct, ss, nil
}

// Decapsulate восстанавливает общий секрет из шифротекста приватным ключом.
func Decapsulate(priv *mlkem1024.PrivateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != mlkem1024.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: got %d, want %d", len(ciphertext), mlkem1024.CiphertextSize)
	}
	ss := make([]byte, mlkem1024.SharedKeySize)
	priv.DecapsulateTo(ss, ciphertext)
	return ss, nil
}
