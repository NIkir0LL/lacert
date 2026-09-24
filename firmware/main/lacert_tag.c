// lacert_tag.c — метки подлинности служебных кадров (BLAKE3 над ключом
// сессии, типом, итерацией и телом). Файл платформо-независимый: собирается и
// на плате, и в Linux-версии. Порядок и состав частей должны совпадать с
// ComputeControlTag на стороне шлюза, иначе метки не сойдутся.
//
// Вынесен из lacert_crypto.c в 1.4.10: там он был рядом с mbedTLS-кодом, а
// Linux-сборка, у которой своя реализация криптопримитивов, его не получала и
// не собиралась с 1.3.0.
#include "lacert_crypto.h"
#include "lacert_wire.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Метка подлинности служебных кадров.
//
// Пакеты данных защищены шифрованием ChaCha20-Poly1305, которое само содержит
// метку подлинности. Служебные кадры — начало ротации и подтверждение — шли
// открытым текстом и никак не были связаны с сеансовым ключом, поэтому
// вклинившийся в соединение мог их подменить или вбросить.
//
// Метка на BLAKE3, а не подпись: подпись ECDSA стоит 22 мс на этом кристалле,
// а ротация происходит каждые пять минут либо каждые триста пакетов. Метка
// обходится в единицы микросекунд, и для защиты от постороннего этого
// достаточно — доказывать авторство третьей стороне здесь не нужно.
// ---------------------------------------------------------------------------
lacert_err_t lacert_control_tag(const uint8_t session_key[32],
                                uint8_t frame_type, uint64_t iteration,
                                const uint8_t *body, size_t body_len,
                                uint8_t out[LACERT_CONTROL_TAG_SIZE]) {
    uint8_t it_buf[8];
    lacert_put_u64(it_buf, iteration);

    // Порядок и состав частей должны совпадать с ComputeControlTag на стороне
    // шлюза, иначе метки не сойдутся.
    const uint8_t *parts[5] = {
        session_key, &frame_type, it_buf, body, (const uint8_t *)LACERT_SEP_CONTROL
    };
    const size_t lens[5] = {
        LACERT_SESSION_KEY_SIZE, 1, 8, body_len, strlen(LACERT_SEP_CONTROL)
    };

    uint8_t full[32];
    lacert_err_t e = lacert_blake3(parts, lens, 5, full);
    if (e != LACERT_OK) return e;

    memcpy(out, full, LACERT_CONTROL_TAG_SIZE);
    memset(full, 0, sizeof(full));
    return LACERT_OK;
}

lacert_err_t lacert_verify_control_tag(const uint8_t session_key[32],
                                       uint8_t frame_type, uint64_t iteration,
                                       const uint8_t *body, size_t body_len,
                                       const uint8_t *tag) {
    uint8_t want[LACERT_CONTROL_TAG_SIZE];
    lacert_err_t e = lacert_control_tag(session_key, frame_type, iteration,
                                        body, body_len, want);
    if (e != LACERT_OK) return e;

    // Сравнение за постоянное время: обычное сравнение завершилось бы на
    // первом несовпавшем байте, и по времени ответа метку можно было бы
    // подбирать побайтово — а это несравнимо дешевле полного перебора.
    uint8_t diff = 0;
    for (size_t i = 0; i < LACERT_CONTROL_TAG_SIZE; i++)
        diff |= (uint8_t)(want[i] ^ tag[i]);

    memset(want, 0, sizeof(want));
    return diff == 0 ? LACERT_OK : LACERT_ERR_AUTH;
}
