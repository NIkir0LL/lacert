// lacert_crypto.c — реализация криптооперций устройства.
//
// СТАТУС: реализовано полностью.
//   SHA-256, ECDSA P-256, ChaCha20-Poly1305, random — mbedTLS (входит в ESP-IDF)
//   ML-KEM-1024 — components/ml_kem (PQClean)
//   BLAKE3      — components/blake3
// Совместимость с Go-шлюзом проверена на Linux-версии (см. firmware/linux-debug).
#include "lacert_crypto.h"
#include <string.h>
#include <stdbool.h>

// mbedTLS доступен в ESP-IDF:
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_random.h"

// Внешние компоненты (components/blake3, components/ml_kem):
#include "blake3.h"
#include "api.h"   // PQClean ML-KEM-1024 API

// ---------------------------------------------------------------------------
// Общий криптографический контекст (экспериментальная оптимизация).
//
// LACERT_SHARED_CRYPTO_CTX = 1 — генератор случайных чисел (CTR-DRBG) и
//                                параметры кривой P-256 создаются ОДИН РАЗ и
//                                переиспользуются;
//                          = 0 — исходное поведение: контекст создаётся заново
//                                на каждый вызов подписи.
//
// Зачем переключатель. Замер на mbedTLS 2.28 показывал выигрыш в 2,6 раза, но
// на mbedTLS 3.6 (версия из состава ESP-IDF v5.4) на x86-64 разницы нет:
// 348,2 мкс против 347,4 мкс по медиане пятнадцати прогонов. На ESP32 источник
// энтропии другой — аппаратный генератор, а не подсистема ОС, — поэтому
// результат может отличаться. Переключатель позволяет измерить обе версии на
// ОДНОЙ плате и одной сборке, не подменяя ничего постороннего.
//
// Как сравнить: собрать и прошить с 1, записать «ECDSA P-256 sign» из вывода
// LACERT_BENCH, затем поставить 0, пересобрать, прошить и записать снова.
//
// Потокобезопасность (при 1): протокол выполняется в единственной задаче
// (app_main), поэтому блокировка не нужна. Если появятся дополнительные
// задачи, обращения к контексту потребуется защитить мьютексом.
// ---------------------------------------------------------------------------
#ifndef LACERT_SHARED_CRYPTO_CTX
#define LACERT_SHARED_CRYPTO_CTX 1
#endif

#if LACERT_SHARED_CRYPTO_CTX
static mbedtls_entropy_context  s_entropy;
static mbedtls_ctr_drbg_context s_drbg;
static mbedtls_ecdsa_context    s_ecdsa;      // с заранее загруженной группой P-256
static bool                     s_ready = false;

static lacert_err_t crypto_ctx_init(void) {
    if (s_ready) return LACERT_OK;

    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_drbg);
    mbedtls_ecdsa_init(&s_ecdsa);

    const char *pers = "lacert";
    if (mbedtls_ctr_drbg_seed(&s_drbg, mbedtls_entropy_func, &s_entropy,
                              (const uint8_t *)pers, strlen(pers)) != 0) {
        goto fail;
    }
    if (mbedtls_ecp_group_load(&s_ecdsa.MBEDTLS_PRIVATE(grp),
                               MBEDTLS_ECP_DP_SECP256R1) != 0) {
        goto fail;
    }
    s_ready = true;
    return LACERT_OK;

fail:
    mbedtls_ecdsa_free(&s_ecdsa);
    mbedtls_ctr_drbg_free(&s_drbg);
    mbedtls_entropy_free(&s_entropy);
    return LACERT_ERR_CRYPTO;
}
#endif // LACERT_SHARED_CRYPTO_CTX

// ---------------------------------------------------------------------------
// SHA-256 — mbedTLS, готово.
// ---------------------------------------------------------------------------
lacert_err_t lacert_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (mbedtls_sha256(data, len, out, 0) != 0) return LACERT_ERR_CRYPTO;
    return LACERT_OK;
}

// ---------------------------------------------------------------------------
// BLAKE3 — внешний компонент. Хешируем части последовательно (важен порядок!).
// ---------------------------------------------------------------------------
lacert_err_t lacert_blake3(const uint8_t **parts, const size_t *lens,
                           size_t count, uint8_t out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    for (size_t i = 0; i < count; i++)
        blake3_hasher_update(&h, parts[i], lens[i]);
    blake3_hasher_finalize(&h, out, 32);
    return LACERT_OK;
}

// ---------------------------------------------------------------------------
// ML-KEM-1024 декапсуляция — внешний компонент (PQClean).
// ---------------------------------------------------------------------------
lacert_err_t lacert_kem_decapsulate(const uint8_t *kem_priv,
                                    const uint8_t *ciphertext,
                                    uint8_t shared[LACERT_KEM_SHARED_SIZE]) {
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared, ciphertext, kem_priv) != 0)
        return LACERT_ERR_CRYPTO;
    return LACERT_OK;
}

// Генерация пары ключей ML-KEM-1024 (нужна при первом старте устройства).
lacert_err_t lacert_kem_keypair(uint8_t *kem_pub, uint8_t *kem_priv) {
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(kem_pub, kem_priv) != 0)
        return LACERT_ERR_CRYPTO;
    return LACERT_OK;
}

// ---------------------------------------------------------------------------
// ECDSA P-256 подпись — mbedTLS. Вход: msg (подписывается SHA-256(msg)).
// Выход: ASN.1 DER (как ecdsa.SignASN1 в Go) — mbedtls_ecdsa_write_signature
// выдаёт именно DER. sig-буфер должен быть >= MBEDTLS_ECDSA_MAX_LEN (~72).
// ---------------------------------------------------------------------------
lacert_err_t lacert_ecdsa_sign(const uint8_t ecdsa_priv[32],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig, size_t *sig_len) {
    uint8_t digest[32];
    if (lacert_sha256(msg, msg_len, digest) != LACERT_OK) return LACERT_ERR_CRYPTO;

#if LACERT_SHARED_CRYPTO_CTX
    // Группа кривой и генератор случайных чисел уже созданы — остаётся
    // подставить приватный ключ и подписать.
    if (crypto_ctx_init() != LACERT_OK) return LACERT_ERR_CRYPTO;

    if (mbedtls_mpi_read_binary(&s_ecdsa.MBEDTLS_PRIVATE(d), ecdsa_priv, 32) != 0)
        return LACERT_ERR_CRYPTO;

    if (mbedtls_ecdsa_write_signature(&s_ecdsa, MBEDTLS_MD_SHA256,
                                      digest, sizeof(digest),
                                      sig, MBEDTLS_ECDSA_MAX_LEN, sig_len,
                                      mbedtls_ctr_drbg_random, &s_drbg) != 0)
        return LACERT_ERR_CRYPTO;

    return LACERT_OK;
#else
    // Исходное поведение: весь контекст создаётся на каждый вызов.
    mbedtls_ecdsa_context ecdsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    lacert_err_t rc = LACERT_ERR_CRYPTO;
    const char *pers = "lacert_ecdsa";

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t*)pers, strlen(pers)) != 0) goto done;
    if (mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp),
                               MBEDTLS_ECP_DP_SECP256R1) != 0) goto done;
    if (mbedtls_mpi_read_binary(&ecdsa.MBEDTLS_PRIVATE(d), ecdsa_priv, 32) != 0) goto done;

    if (mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256,
                                      digest, sizeof(digest),
                                      sig, MBEDTLS_ECDSA_MAX_LEN, sig_len,
                                      mbedtls_ctr_drbg_random, &drbg) != 0) goto done;
    rc = LACERT_OK;

done:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return rc;
#endif
}

// ---------------------------------------------------------------------------
// Генерация пары ключей ECDSA P-256 (при первом старте устройства).
// priv — 32 байта скаляра, pub — 65 байт (0x04||X||Y).
// ---------------------------------------------------------------------------
lacert_err_t lacert_ecdsa_keypair(uint8_t priv[32], uint8_t pub[LACERT_ECDSA_PUB_SIZE]) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    lacert_err_t rc = LACERT_ERR_CRYPTO;

#if !LACERT_SHARED_CRYPTO_CTX
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    const char *pers = "lacert_keygen";
#endif

#if LACERT_SHARED_CRYPTO_CTX
    // Генератор случайных чисел берётся из общего контекста (создан однажды).
    if (crypto_ctx_init() != LACERT_OK) goto done;
    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1,
                             mbedtls_ctr_drbg_random, &s_drbg) != 0) goto done;
#else
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t*)pers, strlen(pers)) != 0) goto done;
    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1,
                             mbedtls_ctr_drbg_random, &drbg) != 0) goto done;
#endif
    if (mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(d), priv, 32) != 0) goto done;

    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&ctx.MBEDTLS_PRIVATE(grp),
                                       &ctx.MBEDTLS_PRIVATE(Q),
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                       pub, LACERT_ECDSA_PUB_SIZE) != 0) goto done;
    if (olen != LACERT_ECDSA_PUB_SIZE) goto done;
    rc = LACERT_OK;
done:
    mbedtls_ecdsa_free(&ctx);
#if !LACERT_SHARED_CRYPTO_CTX
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
#endif
    return rc;
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 seal — mbedTLS. Совпадает с Go chacha20poly1305.Seal:
//   nonce = random(8) || u32_BE(seq);  AAD пусто;  тег (16) дописывается в конец.
// ---------------------------------------------------------------------------
lacert_err_t lacert_chacha_seal(const uint8_t key[32], uint32_t seq,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t nonce_out[LACERT_CHACHA_NONCE_SIZE],
                                uint8_t *ct, size_t *ct_len) {
    if (lacert_random(nonce_out, 8) != LACERT_OK) return LACERT_ERR_CRYPTO;
    nonce_out[8]  = (uint8_t)(seq >> 24);
    nonce_out[9]  = (uint8_t)(seq >> 16);
    nonce_out[10] = (uint8_t)(seq >> 8);
    nonce_out[11] = (uint8_t)(seq);

    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    lacert_err_t rc = LACERT_ERR_CRYPTO;

    if (mbedtls_chachapoly_setkey(&c, key) != 0) goto done;

    uint8_t tag[LACERT_CHACHA_TAG_SIZE];
    // AAD пусто (aad=NULL, aad_len=0), как в Go (последний аргумент Seal = nil).
    if (mbedtls_chachapoly_encrypt_and_tag(&c, pt_len, nonce_out,
                                           NULL, 0, pt, ct, tag) != 0)
        goto done;

    // Go возвращает ciphertext||tag — дописываем тег в конец.
    memcpy(ct + pt_len, tag, LACERT_CHACHA_TAG_SIZE);
    *ct_len = pt_len + LACERT_CHACHA_TAG_SIZE;
    rc = LACERT_OK;

done:
    mbedtls_chachapoly_free(&c);
    return rc;
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 open — тег = последние 16 байт ct (как в Go Open).
// ---------------------------------------------------------------------------
lacert_err_t lacert_chacha_open(const uint8_t key[32],
                                const uint8_t nonce[LACERT_CHACHA_NONCE_SIZE],
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *pt, size_t *pt_len) {
    if (ct_len < LACERT_CHACHA_TAG_SIZE) return LACERT_ERR_DECODE;
    size_t body = ct_len - LACERT_CHACHA_TAG_SIZE;
    const uint8_t *tag = ct + body;

    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    lacert_err_t rc = LACERT_ERR_CRYPTO;

    if (mbedtls_chachapoly_setkey(&c, key) != 0) goto done;
    if (mbedtls_chachapoly_auth_decrypt(&c, body, nonce,
                                        NULL, 0, tag, ct, pt) != 0) {
        rc = LACERT_ERR_AUTH; // тег не сошёлся — подмена/повреждение
        goto done;
    }
    *pt_len = body;
    rc = LACERT_OK;

done:
    mbedtls_chachapoly_free(&c);
    return rc;
}

// ---------------------------------------------------------------------------
// Случайные байты — аппаратный RNG ESP32 (esp_fill_random). Проще и надёжнее
// CTR-DRBG; на ESP32 это криптостойкий источник (при активном WiFi/RF).
// ---------------------------------------------------------------------------
lacert_err_t lacert_random(uint8_t *out, size_t len) {
    esp_fill_random(out, len);
    return LACERT_OK;
}
