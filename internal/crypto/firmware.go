package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// ChallengeSize — размер случайного запроса, упомянутый в работе (64 байта).
const ChallengeSize = 64

// FirmwareHashSize — размер SHA-256 хеша прошивки.
const FirmwareHashSize = sha256.Size

// BuildFirmwareChallenge генерируется шлюзом раз в час (см. раздел
// "5. Проверка целостности прошивки").
func BuildFirmwareChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate firmware challenge: %w", err)
	}
	return challenge, nil
}

// FirmwareResponse — ответ устройства на запрос целостности.
type FirmwareResponse struct {
	FirmwareHash [FirmwareHashSize]byte
	Signature    []byte
}

// RespondToFirmwareChallenge выполняется на устройстве: оно подписывает
// связку (challenge || хеш текущей прошивки) ключом из efuse. firmwareImage —
// в прототипе это содержимое прошивки (или, что эффективнее на реальном
// устройстве, заранее посчитанный хеш области Flash с прошивкой).
func RespondToFirmwareChallenge(identity *IdentityKeyPair, challenge, firmwareImage []byte) (*FirmwareResponse, error) {
	hash := sha256.Sum256(firmwareImage)

	toSign := make([]byte, 0, len(challenge)+len(hash))
	toSign = append(toSign, challenge...)
	toSign = append(toSign, hash[:]...)

	sig, err := identity.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("sign firmware response: %w", err)
	}

	return &FirmwareResponse{FirmwareHash: hash, Signature: sig}, nil
}

// FirmwareCheckResult различает причину провала проверки — это важно для
// журналирования на шлюзе (отдельно от решения "исключить устройство").
type FirmwareCheckResult struct {
	SignatureValid bool
	HashMatches    bool
}

// OK сообщает, прошла ли проверка целостности прошивки в целом.
func (r FirmwareCheckResult) OK() bool {
	return r.SignatureValid && r.HashMatches
}

// VerifyFirmwareResponse выполняется на шлюзе: проверяет подпись устройства
// и сравнивает присланный хеш прошивки с эталонным значением, сохранённым
// при регистрации устройства.
func VerifyFirmwareResponse(
	devIdentityPub []byte,
	devSigAlg SigAlgorithm,
	challenge []byte,
	resp *FirmwareResponse,
	referenceHash [FirmwareHashSize]byte,
) (FirmwareCheckResult, error) {
	toVerify := make([]byte, 0, len(challenge)+FirmwareHashSize)
	toVerify = append(toVerify, challenge...)
	toVerify = append(toVerify, resp.FirmwareHash[:]...)

	sigValid, err := VerifySignature(devSigAlg, devIdentityPub, toVerify, resp.Signature)
	if err != nil {
		return FirmwareCheckResult{}, fmt.Errorf("verify firmware response signature: %w", err)
	}

	// Сравнение за постоянное время. Хеш прошивки не секрет, и подделать ответ
	// без валидной подписи нельзя, так что практической атаки по времени здесь
	// нет. Но приучать сравнивать криптографические значения обычным == не
	// стоит: в другом месте такая привычка обойдётся дорого.
	hashMatches := subtle.ConstantTimeCompare(resp.FirmwareHash[:], referenceHash[:]) == 1

	return FirmwareCheckResult{SignatureValid: sigValid, HashMatches: hashMatches}, nil
}
