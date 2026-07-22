package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// MaxPayloadSize — ограничение полезной нагрузки одного пакета, упомянутое
// в работе ("payload ≤ 380 байт").
const MaxPayloadSize = 380

// EncryptPacket шифрует полезные данные под ключом key (32 байта — текущий Ki)
// с помощью ChaCha20-Poly1305. seqNum — номер пакета в рамках текущего ключа
// (0..299), используется как часть nonce, чтобы гарантировать уникальность
// nonce без необходимости хранить отдельный счётчик где-то ещё. Возвращает
// nonce (12 байт) и шифротекст с присоединённым тегом аутентификации.
func EncryptPacket(key [32]byte, seqNum uint32, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(plaintext) > MaxPayloadSize {
		return nil, nil, fmt.Errorf("payload too large: %d > %d", len(plaintext), MaxPayloadSize)
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("init chacha20poly1305: %w", err)
	}

	nonce = make([]byte, chacha20poly1305.NonceSize) // 12 байт
	// Случайные старшие 8 байт + seqNum в младших 4 байтах: исключает
	// коллизии nonce между разными процессами/перезапусками в рамках одного
	// ключа и одновременно делает повтор пакета детектируемым.
	if _, err := rand.Read(nonce[:8]); err != nil {
		return nil, nil, fmt.Errorf("generate nonce randomness: %w", err)
	}
	binary.BigEndian.PutUint32(nonce[8:], seqNum)

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// DecryptPacket расшифровывает и проверяет целостность пакета. Встроенный в
// ChaCha20-Poly1305 тег аутентификации позволяет немедленно обнаружить любое
// изменение или подмену пакета (см. раздел "Передача данных" работы).
func DecryptPacket(key [32]byte, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("init chacha20poly1305: %w", err)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, errors.New("invalid nonce size")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt/auth failed: %w", err)
	}
	return plaintext, nil
}
