// lacert_crypto.h — криптографические операции устройства.
// Каждая функция соответствует шагу протокола (см. docs/ru/PROTOCOL_SPEC.md).
// Реализация в lacert_crypto.c опирается на:
//   ECDSA P-256, ChaCha20-Poly1305, SHA-256 — mbedTLS (встроен в ESP-IDF)
//   ML-KEM-1024 — внешний компонент (PQClean/liboqs)
//   BLAKE3      — внешний компонент (официальная C-реализация)
#pragma once
#include "lacert_proto.h"

// --- Идентичность устройства (efuse-привязанные ключи) ---
typedef struct {
    // Приватный ключ ECDSA P-256 (в реальной системе — в защищённой области).
    // Здесь для прототипа — в структуре.
    uint8_t ecdsa_priv[32];
    uint8_t ecdsa_pub[LACERT_ECDSA_PUB_SIZE];   // 65 байт, 0x04||X||Y
    // Приватный/публичный ключ ML-KEM-1024 устройства.
    uint8_t kem_priv[3168];   // ML-KEM-1024 private key size
    uint8_t kem_pub[LACERT_KEM_PUBKEY_SIZE];
    lacert_sig_alg_t sig_alg;
} lacert_identity_t;

// --- BLAKE3 (вывод ключей) ---
// Универсальный BLAKE3: хеширует конкатенацию частей. out — 32 байта.
// parts/lens — массивы кусков для последовательного Write, count — их число.
lacert_err_t lacert_blake3(const uint8_t **parts, const size_t *lens,
                           size_t count, uint8_t out[32]);

// --- Метка подлинности служебных кадров ---
//
// Вычисляет BLAKE3(сеансовый ключ || тип кадра || номер шага || содержимое ||
// разделитель) и берёт первые LACERT_CONTROL_TAG_SIZE байт.
//
// Зачем каждая часть: ключ — без него метку не вычислить; тип кадра — иначе
// метку от подтверждения можно переставить на другой кадр; номер шага —
// привязывает метку к конкретному шагу ротации; содержимое — защищает сами
// данные.
lacert_err_t lacert_control_tag(const uint8_t session_key[32],
                                uint8_t frame_type, uint64_t iteration,
                                const uint8_t *body, size_t body_len,
                                uint8_t out[LACERT_CONTROL_TAG_SIZE]);

// Проверяет метку служебного кадра. Сравнение за постоянное время: иначе по
// времени ответа метку можно было бы подбирать побайтово.
lacert_err_t lacert_verify_control_tag(const uint8_t session_key[32],
                                       uint8_t frame_type, uint64_t iteration,
                                       const uint8_t *body, size_t body_len,
                                       const uint8_t *tag);

// --- SHA-256 ---
lacert_err_t lacert_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

// --- ML-KEM-1024 ---
// Генерация пары ключей ML-KEM-1024 (первый старт устройства).
lacert_err_t lacert_kem_keypair(uint8_t *kem_pub, uint8_t *kem_priv);

// Декапсуляция: получить общий секрет (32 байта) из ciphertext своим priv-ключом.
lacert_err_t lacert_kem_decapsulate(const uint8_t *kem_priv,
                                    const uint8_t *ciphertext,
                                    uint8_t shared[LACERT_KEM_SHARED_SIZE]);

// --- ECDSA P-256 ---
// Генерация пары ключей ECDSA P-256 (первый старт устройства).
lacert_err_t lacert_ecdsa_keypair(uint8_t priv[32], uint8_t pub[LACERT_ECDSA_PUB_SIZE]);

// Подпись: sig = ASN1(SignASN1(SHA-256(msg))). Возвращает длину подписи в *sig_len.
// sig — буфер минимум 80 байт (DER P-256 обычно <= 72).
lacert_err_t lacert_ecdsa_sign(const uint8_t ecdsa_priv[32],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig, size_t *sig_len);

// --- ChaCha20-Poly1305 ---
// Шифрование: nonce (12) = random(8)||u32_BE(seq). Пишет nonce и ciphertext+tag.
// ct должен вмещать pt_len + 16 (тег). Возвращает длину ct в *ct_len.
lacert_err_t lacert_chacha_seal(const uint8_t key[32], uint32_t seq,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t nonce_out[LACERT_CHACHA_NONCE_SIZE],
                                uint8_t *ct, size_t *ct_len);
// Расшифрование (для входящих данных, если понадобится).
lacert_err_t lacert_chacha_open(const uint8_t key[32],
                                const uint8_t nonce[LACERT_CHACHA_NONCE_SIZE],
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *pt, size_t *pt_len);

// --- Случайные байты ---
lacert_err_t lacert_random(uint8_t *out, size_t len);
