// lacert_client.c — реализация протокольной логики.
// Кодирование кадров и последовательность шагов реализованы полностью и
// соответствуют docs/ru/PROTOCOL_SPEC.md. Крипто-вызовы идут через
// lacert_crypto.* — там рабочие реализации поверх mbedTLS (ECDSA P-256,
// SHA-256, ChaCha20-Poly1305), BLAKE3 и ML-KEM-1024 из PQClean.
#include "lacert_client.h"
#include "lacert_wire.h"
#include <stdlib.h>
#include <string.h>

// Собрать канонические байты Msg1: putFramed(device_id)||nonce||putFramed(id_pub)
// Используется и для отправки, и для транскрипта — формат одинаков (раздел 3.3).
static size_t build_msg1_bytes(lacert_session_t *s, uint8_t *buf) {
    size_t off = 0;
    off = lacert_put_framed(buf, off, (const uint8_t*)s->device_id, strlen(s->device_id));
    memcpy(buf + off, s->last_nonce, LACERT_HANDSHAKE_NONCE_SIZE);
    off += LACERT_HANDSHAKE_NONCE_SIZE;
    off = lacert_put_framed(buf, off, s->id.ecdsa_pub, LACERT_ECDSA_PUB_SIZE);
    return off;
}

// Собрать канонические байты Msg2: putFramed(kem_ct)||gw_nonce
static size_t build_msg2_bytes(const uint8_t *kem_ct, size_t kem_ct_len,
                               const uint8_t *gw_nonce, uint8_t *buf) {
    size_t off = 0;
    off = lacert_put_framed(buf, off, kem_ct, kem_ct_len);
    memcpy(buf + off, gw_nonce, LACERT_HANDSHAKE_NONCE_SIZE);
    off += LACERT_HANDSHAKE_NONCE_SIZE;
    return off;
}

lacert_err_t lacert_do_handshake(lacert_session_t *s) {
    lacert_err_t e;

    // --- Msg1: генерируем nonce, отправляем ---
    e = lacert_random(s->last_nonce, LACERT_HANDSHAKE_NONCE_SIZE);
    if (e != LACERT_OK) return e;

    uint8_t m1[128 + LACERT_ECDSA_PUB_SIZE];
    size_t m1_len = build_msg1_bytes(s, m1);
    e = lacert_write_frame(s->sock, LACERT_MSG_HANDSHAKE1, m1, m1_len);
    if (e != LACERT_OK) return e;

    // --- Msg2: принимаем ---
    uint8_t type; uint8_t *payload; size_t plen;
    e = lacert_read_frame(s->sock, &type, &payload, &plen);
    if (e != LACERT_OK) return e;
    if (type != LACERT_MSG_HANDSHAKE2) { free(payload); return LACERT_ERR_STATE; }

    size_t off = 0;
    const uint8_t *kem_ct; size_t kem_ct_len;
    e = lacert_take_framed(payload, plen, &off, &kem_ct, &kem_ct_len);
    if (e != LACERT_OK) { free(payload); return e; }

    // Длину поля задаёт удалённая сторона, поэтому её нельзя брать на веру.
    // Шифротекст ML-KEM-1024 всегда ровно LACERT_KEM_CIPHERTEXT_SIZE байт,
    // так что любое другое значение — повреждённый или враждебный кадр.
    //
    // Без этой проверки было два дефекта сразу:
    //   • build_msg2_bytes писал 2 + kem_ct_len + 32 байт в буфер m2 на стеке
    //     размером 8 + 1568 + 32; поле длины 16-битное, поэтому кадр мог
    //     потребовать до ~64 КиБ и переполнить стек;
    //   • lacert_kem_decapsulate читает ровно 1568 байт независимо от
    //     kem_ct_len, то есть при более коротком поле читал за границей
    //     полученного буфера.
    // Устройство не аутентифицирует шлюз (раздел 3 спецификации), так что
    // отправить такой кадр может любой, кто дотянулся до сети.
    if (kem_ct_len != LACERT_KEM_CIPHERTEXT_SIZE) { free(payload); return LACERT_ERR_DECODE; }

    if (off + LACERT_HANDSHAKE_NONCE_SIZE > plen) { free(payload); return LACERT_ERR_DECODE; }
    const uint8_t *gw_nonce = payload + off;

    // --- Декапсуляция общего секрета ---
    uint8_t shared[LACERT_KEM_SHARED_SIZE];
    e = lacert_kem_decapsulate(s->id.kem_priv, kem_ct, shared);
    if (e != LACERT_OK) { free(payload); return e; }

    // --- transcript = BLAKE3(msg1_bytes || msg2_bytes) ---
    uint8_t m2[8 + LACERT_KEM_CIPHERTEXT_SIZE + LACERT_HANDSHAKE_NONCE_SIZE];
    size_t m2_len = build_msg2_bytes(kem_ct, kem_ct_len, gw_nonce, m2);
    free(payload); // gw_nonce/kem_ct скопированы в m2, payload больше не нужен

    uint8_t transcript[32];
    { const uint8_t *parts[2] = { m1, m2 };
      const size_t   lens[2]  = { m1_len, m2_len };
      e = lacert_blake3(parts, lens, 2, transcript);
      if (e != LACERT_OK) return e; }

    // --- K0 = BLAKE3(shared || transcript || "lacert_handshake_v1") ---
    { const uint8_t *parts[3] = { shared, transcript, (const uint8_t*)LACERT_SEP_HANDSHAKE };
      const size_t   lens[3]  = { LACERT_KEM_SHARED_SIZE, 32, strlen(LACERT_SEP_HANDSHAKE) };
      e = lacert_blake3(parts, lens, 3, s->session_key);
      if (e != LACERT_OK) return e; }
    memset(shared, 0, sizeof(shared)); // затираем секрет

    // --- confirm = BLAKE3(transcript || "confirm" || K0) ---
    uint8_t confirm[32];
    { const uint8_t *parts[3] = { transcript, (const uint8_t*)LACERT_SEP_CONFIRM, s->session_key };
      const size_t   lens[3]  = { 32, strlen(LACERT_SEP_CONFIRM), LACERT_SESSION_KEY_SIZE };
      e = lacert_blake3(parts, lens, 3, confirm);
      if (e != LACERT_OK) return e; }

    // --- подпись confirm и отправка Msg3 ---
    uint8_t sig[LACERT_MAX_SIG_SIZE]; size_t sig_len = 0;
    e = lacert_ecdsa_sign(s->id.ecdsa_priv, confirm, sizeof(confirm), sig, &sig_len);
    if (e != LACERT_OK) return e;

    uint8_t m3[2 + LACERT_MAX_SIG_SIZE];
    size_t m3_len = lacert_put_framed(m3, 0, sig, sig_len);
    e = lacert_write_frame(s->sock, LACERT_MSG_HANDSHAKE3, m3, m3_len);
    if (e != LACERT_OK) return e;

    s->iteration = 0;
    s->seq_num = 0;
    s->has_session = 1;
    return LACERT_OK;
}

lacert_err_t lacert_send_data(lacert_session_t *s, const char *payload) {
    if (!s->has_session) return LACERT_ERR_STATE;
    size_t pt_len = strlen(payload);
    // Шлюз отвергает пакеты длиннее протокольного лимита, поэтому проверяем
    // здесь: иначе устройство напрасно шифрует данные и занимает канал.
    if (pt_len > LACERT_MAX_PAYLOAD_SIZE) return LACERT_ERR_DECODE;

    uint8_t nonce[LACERT_CHACHA_NONCE_SIZE];
    uint8_t *ct = malloc(pt_len + LACERT_CHACHA_TAG_SIZE);
    if (!ct) return LACERT_ERR_IO;
    size_t ct_len = 0;

    lacert_err_t e = lacert_chacha_seal(s->session_key, s->seq_num,
                                        (const uint8_t*)payload, pt_len,
                                        nonce, ct, &ct_len);
    if (e != LACERT_OK) { free(ct); return e; }
    s->seq_num++;

    // payload кадра: putFramed(nonce) || putFramed(ciphertext)
    uint8_t *buf = malloc(2 + LACERT_CHACHA_NONCE_SIZE + 2 + ct_len);
    if (!buf) { free(ct); return LACERT_ERR_IO; }
    size_t off = 0;
    off = lacert_put_framed(buf, off, nonce, LACERT_CHACHA_NONCE_SIZE);
    off = lacert_put_framed(buf, off, ct, ct_len);
    e = lacert_write_frame(s->sock, LACERT_MSG_DATA, buf, off);
    free(ct); free(buf);
    return e;
}

// --- Обработка ротации, инициированной шлюзом (раздел 5) ---
static lacert_err_t handle_rotation_v2(lacert_session_t *s,
                                       const uint8_t *payload, size_t plen) {
    // Кадр: [8 байт номера шага][поле с шифротекстом][16 байт метки].
    if (plen < 8 + LACERT_CONTROL_TAG_SIZE) return LACERT_ERR_DECODE;

    size_t body_len = plen - LACERT_CONTROL_TAG_SIZE;
    const uint8_t *tag = payload + body_len;
    uint64_t iteration = lacert_get_u64(payload);

    // Метка проверяется ДО разбора содержимого: кадр от того, кто не знает
    // сеансового ключа, отбрасывается целиком, и разбирать его незачем.
    //
    // Ключ здесь ещё прежний — новый вступит в силу ниже, после успешной
    // ротации. Шлюз считает метку тем же прежним ключом.
    lacert_err_t e = lacert_verify_control_tag(s->session_key,
                                               LACERT_MSG_ROTATION_V2,
                                               iteration, payload, body_len, tag);
    if (e != LACERT_OK) return e;

    size_t off = 8;
    const uint8_t *kem_ct; size_t kem_ct_len;
    e = lacert_take_framed(payload, body_len, &off, &kem_ct, &kem_ct_len);
    if (e != LACERT_OK) return e;

    // Та же проверка, что и в рукопожатии: lacert_kem_decapsulate читает ровно
    // LACERT_KEM_CIPHERTEXT_SIZE байт независимо от длины поля, поэтому более
    // короткое поле привело бы к чтению за границей буфера.
    if (kem_ct_len != LACERT_KEM_CIPHERTEXT_SIZE) return LACERT_ERR_DECODE;

    // Проверка номера итерации (защита от replay/рассинхронизации).
    if (iteration != s->iteration + 1) return LACERT_ERR_AUTH;

    // mi = decapsulate(kem_ct)
    uint8_t mi[LACERT_KEM_SHARED_SIZE];
    e = lacert_kem_decapsulate(s->id.kem_priv, kem_ct, mi);
    if (e != LACERT_OK) return e;

    // next_key = BLAKE3(current_key || mi || u64_BE(iteration) || "rotate_v1")
    uint8_t it_buf[8]; lacert_put_u64(it_buf, iteration);
    uint8_t next_key[32];
    { const uint8_t *parts[4] = { s->session_key, mi, it_buf, (const uint8_t*)LACERT_SEP_ROTATE };
      const size_t   lens[4]  = { LACERT_SESSION_KEY_SIZE, LACERT_KEM_SHARED_SIZE, 8, strlen(LACERT_SEP_ROTATE) };
      e = lacert_blake3(parts, lens, 4, next_key);
      if (e != LACERT_OK) { memset(mi,0,sizeof(mi)); return e; } }
    memset(mi, 0, sizeof(mi));

    // Подтверждение подписывается ПРЕЖНИМ ключом, до применения ротации:
    // шлюз проверит метку тоже прежним, поскольку у него ротация вступит в
    // силу лишь после получения этого подтверждения. Если подписать новым,
    // метки не сойдутся и ротация не завершится ни у одной стороны.
    uint8_t ack[8 + LACERT_CONTROL_TAG_SIZE];
    lacert_put_u64(ack, iteration);
    e = lacert_control_tag(s->session_key, LACERT_MSG_ROTATION_ACK,
                           iteration, ack, 8, ack + 8);
    if (e != LACERT_OK) { memset(next_key, 0, sizeof(next_key)); return e; }

    // Теперь применяем новый ключ.
    memcpy(s->session_key, next_key, LACERT_SESSION_KEY_SIZE);
    memset(next_key, 0, sizeof(next_key));
    s->iteration = iteration;

    return lacert_write_frame(s->sock, LACERT_MSG_ROTATION_ACK,
                              ack, sizeof(ack));
}

// --- Обработка проверки прошивки (раздел 6) ---
static lacert_err_t handle_fw_challenge(lacert_session_t *s,
                                        const uint8_t *payload, size_t plen) {
    size_t off = 0;
    const uint8_t *challenge; size_t ch_len;
    lacert_err_t e = lacert_take_framed(payload, plen, &off, &challenge, &ch_len);
    if (e != LACERT_OK) return e;

    // Длину challenge задаёт удалённая сторона — проверяем границу, чтобы
    // повреждённый или враждебный кадр не переполнил буфер to_sign на стеке.
    if (ch_len > LACERT_FW_CHALLENGE_SIZE) return LACERT_ERR_DECODE;

    // to_sign = challenge || firmware_hash
    uint8_t to_sign[LACERT_FW_CHALLENGE_SIZE + LACERT_FW_HASH_SIZE];
    memcpy(to_sign, challenge, ch_len);
    memcpy(to_sign + ch_len, s->firmware_image_hash, LACERT_FW_HASH_SIZE);

    uint8_t sig[LACERT_MAX_SIG_SIZE]; size_t sig_len = 0;
    e = lacert_ecdsa_sign(s->id.ecdsa_priv, to_sign, ch_len + LACERT_FW_HASH_SIZE, sig, &sig_len);
    if (e != LACERT_OK) return e;

    // payload: firmware_hash(32, БЕЗ префикса) || putFramed(signature)
    uint8_t buf[LACERT_FW_HASH_SIZE + 2 + LACERT_MAX_SIG_SIZE];
    memcpy(buf, s->firmware_image_hash, LACERT_FW_HASH_SIZE);
    size_t o = lacert_put_framed(buf, LACERT_FW_HASH_SIZE, sig, sig_len);
    return lacert_write_frame(s->sock, LACERT_MSG_FW_RESPONSE, buf, o);
}

lacert_err_t lacert_handle_incoming(lacert_session_t *s) {
    uint8_t type; uint8_t *payload; size_t plen;
    lacert_err_t e = lacert_read_frame(s->sock, &type, &payload, &plen);
    if (e != LACERT_OK) return e;

    switch (type) {
        case LACERT_MSG_ROTATION_V2:
            e = handle_rotation_v2(s, payload, plen);
            break;
        case LACERT_MSG_FW_CHALLENGE:
            e = handle_fw_challenge(s, payload, plen);
            break;
        case LACERT_MSG_ERROR:
            // Шлюз сообщил об ошибке (напр. "device revoked") — обычно разрыв.
            e = LACERT_ERR_AUTH;
            break;
        default:
            e = LACERT_ERR_STATE;
            break;
    }
    free(payload);
    return e;
}
