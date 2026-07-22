// lacert_client.h — клиентская логика протокола (рукопожатие, данные,
// обработка ротации и проверки прошивки). Соответствует internal/device +
// internal/transport/tcpclient шлюза.
#pragma once
#include "lacert_proto.h"
#include "lacert_crypto.h"

// Состояние сессии устройства.
typedef struct {
    int sock;                                  // TCP-сокет к шлюзу
    lacert_identity_t id;                      // ключи устройства
    uint8_t gw_kem_pub[LACERT_KEM_PUBKEY_SIZE]; // публичный ML-KEM шлюза
    char device_id[64];

    uint8_t session_key[LACERT_SESSION_KEY_SIZE]; // текущий Ki
    uint64_t iteration;                        // номер текущей итерации ротации
    uint32_t seq_num;                          // счётчик пакетов (для nonce)
    uint8_t firmware_image_hash[LACERT_FW_HASH_SIZE]; // SHA-256 своей прошивки

    // Транскрипт/данные Msg1 сохраняются между шагами рукопожатия.
    uint8_t last_nonce[LACERT_HANDSHAKE_NONCE_SIZE];
    int has_session;
} lacert_session_t;

// Провести рукопожатие: Msg1 → Msg2 → Msg3, установить session_key (K0).
lacert_err_t lacert_do_handshake(lacert_session_t *s);

// Отправить строку телеметрии (зашифрованную текущим ключом).
lacert_err_t lacert_send_data(lacert_session_t *s, const char *payload);

// Обработать один входящий кадр от шлюза (ротация/прошивка/ошибка).
// Вызывается в цикле приёма (в реальной прошивке — отдельная задача FreeRTOS).
lacert_err_t lacert_handle_incoming(lacert_session_t *s);
