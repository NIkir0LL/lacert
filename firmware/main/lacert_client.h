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
    // gw_kem_pub убран в 1.4.10: ключ шлюза устройство не использует — в
    // рукопожатии секрет инкапсулируется под ключ устройства (раздел 3.2), а
    // ротацию инициирует шлюз. Поле лежало мёртвым, но его получение по HTTP
    // блокировало запуск и переподключение. шлюза
    // Шлюз принимает идентификатор до LACERT_DEVICE_ID_MAX знаков (validateDeviceID
    // на его стороне), буфер держит столько же плюс ноль. До 1.4.10 здесь было
    // 64, и более длинный идентификатор молча обрезался при копировании.
    char device_id[LACERT_DEVICE_ID_MAX + 1];

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
