// lacert_proto.h — константы и типы протокола LACERT.
// Значения ДОЛЖНЫ совпадать со шлюзом (см. docs/ru/PROTOCOL_SPEC.md).
#pragma once
#include <stdint.h>
#include <stddef.h>

// --- Типы сообщений (1 байт после длины кадра) ---
#define LACERT_MSG_HANDSHAKE1        1
#define LACERT_MSG_HANDSHAKE2        2
#define LACERT_MSG_HANDSHAKE3        3
#define LACERT_MSG_ROTATION          4   // устаревшая, не используется
#define LACERT_MSG_DATA              5
#define LACERT_MSG_FW_CHALLENGE      6
#define LACERT_MSG_FW_RESPONSE       7
#define LACERT_MSG_ERROR             8
#define LACERT_MSG_ROTATION_V2       9
#define LACERT_MSG_ROTATION_ACK      10

// --- Размеры (байты), см. спецификацию ---
#define LACERT_MAX_FRAME_SIZE        (64 * 1024)
#define LACERT_KEM_PUBKEY_SIZE       1568
#define LACERT_KEM_CIPHERTEXT_SIZE   1568
#define LACERT_KEM_SHARED_SIZE       32
#define LACERT_SESSION_KEY_SIZE      32   // BLAKE3 выход = ключ ChaCha20
#define LACERT_ECDSA_PUB_SIZE        65   // несжатый P-256: 0x04||X||Y
#define LACERT_HANDSHAKE_NONCE_SIZE  32
#define LACERT_CHACHA_NONCE_SIZE     12
#define LACERT_CHACHA_TAG_SIZE       16
#define LACERT_SHA256_SIZE           32
#define LACERT_FW_CHALLENGE_SIZE     64
#define LACERT_FW_HASH_SIZE          32
#define LACERT_MAX_SIG_SIZE          128  // с запасом над DER ECDSA P-256 (~72)

// --- Строки-сепараторы для вывода ключей (БЕЗ завершающего нуля при хешировании!) ---
#define LACERT_SEP_HANDSHAKE   "lacert_handshake_v1"
#define LACERT_SEP_CONFIRM     "confirm"
#define LACERT_SEP_ROTATE      "rotate_v1"

// --- Схема подписи ---
typedef enum {
    LACERT_SIG_ECDSA_P256 = 0,   // рекомендуется для ESP32
    LACERT_SIG_SLH_DSA    = 1,   // не рекомендуется (медленно, тяжело)
} lacert_sig_alg_t;

// Код результата операций.
typedef enum {
    LACERT_OK = 0,
    LACERT_ERR_IO = -1,          // сеть/сокет
    LACERT_ERR_DECODE = -2,      // кривой кадр
    LACERT_ERR_CRYPTO = -3,      // ошибка криптооперации
    LACERT_ERR_AUTH = -4,        // подпись не сошлась / replay
    LACERT_ERR_STATE = -5,       // неверное состояние (напр. нет сессии)
} lacert_err_t;
