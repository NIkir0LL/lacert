// bench_main.c — прошивка для замеров криптографии на кристалле.
//
// Отдельна от боевой прошивки намеренно. Здесь нет ни сети, ни хранилища, ни
// протокола: только вычисления. Причины две. Радиомодуль и обращения к флеш
// вносят разброс, который на фоне десятков миллисекунд заметен. И набор
// алгоритмов здесь шире рабочего — есть те, что в протоколе не используются, но
// нужны для сравнения.
//
// Что меряется сверх боевого набора:
//   • ECDH P-256 напрямую — в работе это число выведено косвенно, из времени
//     рукопожатия DTLS, и требует прямой проверки;
//   • X25519 — для оценки гибридной схемы, которую рекомендует BSI TR-02102;
//   • ML-KEM всех трёх уровней — цена стойкости;
//   • ML-DSA всех трёх уровней — заявлено как «намного быстрее SLH-DSA», но не
//     проверено на кристалле;
//   • SLH-DSA — до сих пор мерялась только на сервере.
//
// Наборы включаются по отдельности: если не хватит флеш или стека, лишнее
// отключается ниже, и остальное продолжает собираться.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "blake3.h"

// ─── Что включать в прогон ──────────────────────────────────────────────────
#define BENCH_CLASSIC   0   // ECDSA, ECDH, X25519, SHA-256, ChaCha20, BLAKE3
#define BENCH_MLKEM     0   // ML-KEM-512/768/1024
#define BENCH_MLDSA     0   // ML-DSA-44/65/87
#define BENCH_SLHDSA    1   // SLH-DSA (медленно: минуты на прогон)

#if BENCH_MLKEM
#include "mlkem512.h"
#include "mlkem768.h"
#include "mlkem1024.h"
#endif
#if BENCH_MLDSA
#include "mldsa44.h"
#include "mldsa65.h"
#include "mldsa87.h"
#endif
#if BENCH_SLHDSA
#include "slhdsa128s.h"
#endif

static const char *TAG = "bench";

// Число прогонов по классам стоимости операции. Для дорогих операций больше
// прогонов не нужно: разброс на фоне десятков миллисекунд мал, а время прогона
// растёт линейно.
#define ITERS_FAST   200   // микросекунды: хеши, шифрование
#define ITERS_MEDIUM  20   // миллисекунды: ECDSA, ML-KEM, ML-DSA
#define ITERS_SLOW     5   // сотни миллисекунд: генерация ключей ECDSA
#define ITERS_GLACIAL  2   // секунды и больше: SLH-DSA

static mbedtls_entropy_context s_entropy;
static mbedtls_ctr_drbg_context s_drbg;

// ─── Замер и отчёт ──────────────────────────────────────────────────────────

// Единый формат строки, чтобы результаты трёх прогонов сводились в таблицу без
// ручного разбора.
static void report(const char *alg, const char *op, int64_t total_us, int iters) {
    double avg = (double)total_us / iters;
    if (avg >= 1000.0) {
        ESP_LOGI(TAG, "%-18s %-14s %10.2f мс   (%d)", alg, op, avg / 1000.0, iters);
    } else {
        ESP_LOGI(TAG, "%-18s %-14s %10.1f мкс  (%d)", alg, op, avg, iters);
    }
}

// Для тяжёлых операций: каждая итерация замеряется отдельно, между итерациями
// управление отдаётся планировщику. Пауза в результат не входит.
#define BENCH_SLOW_OP(alg, op, iters, stmt)                \
    do {                                                   \
        int64_t _total = 0;                                \
        for (int _i = 0; _i < (iters); _i++) {             \
            int64_t _t = esp_timer_get_time();             \
            stmt;                                          \
            _total += esp_timer_get_time() - _t;           \
            vTaskDelay(1);                                 \
        }                                                  \
        report((alg), (op), _total, (iters));              \
    } while (0)

// Для лёгких операций: два вызова таймера стоят несколько микросекунд, а сама
// операция — десятки, поэтому меряется цикл целиком.
#define BENCH_FAST_OP(alg, op, iters, stmt)                \
    do {                                                   \
        int64_t _t = esp_timer_get_time();                 \
        for (int _i = 0; _i < (iters); _i++) { stmt; }     \
        report((alg), (op), esp_timer_get_time() - _t, (iters)); \
        vTaskDelay(1);                                     \
    } while (0)

// ─── Классические примитивы ─────────────────────────────────────────────────
#if BENCH_CLASSIC

static void bench_ecdsa(void) {
    mbedtls_ecdsa_context ctx;
    uint8_t msg[96], hash[32], sig[80];
    size_t sig_len = 0;
    esp_fill_random(msg, sizeof(msg));
    mbedtls_sha256(msg, sizeof(msg), hash, 0);

    mbedtls_ecdsa_init(&ctx);
    BENCH_SLOW_OP("ECDSA P-256", "keygen", ITERS_SLOW, {
        mbedtls_ecdsa_free(&ctx);
        mbedtls_ecdsa_init(&ctx);
        mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1,
                             mbedtls_ctr_drbg_random, &s_drbg);
    });

    BENCH_SLOW_OP("ECDSA P-256", "sign", ITERS_MEDIUM,
        mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                      sig, sizeof(sig), &sig_len,
                                      mbedtls_ctr_drbg_random, &s_drbg));

    BENCH_SLOW_OP("ECDSA P-256", "verify", ITERS_MEDIUM,
        mbedtls_ecdsa_read_signature(&ctx, hash, sizeof(hash), sig, sig_len));

    ESP_LOGI(TAG, "  (размер подписи: %u байт)", (unsigned)sig_len);
    mbedtls_ecdsa_free(&ctx);
}

// Прямой замер ECDH. Ради него прошивка во многом и делалась: в работе это
// число получено косвенно, из времени рукопожатия DTLS-ECDHE-PSK, в
// предположении, что симметричная часть на его фоне мала.
//
// Меряются две вещи. Умножение точки — сама операция, которую и должен
// ускорять аппаратный блок. И полный вызов согласования ключа — то, что
// вызывает протокол. Если первое быстрое, а второе нет, разница в обвязке
// mbedTLS, а не в кристалле.
static void bench_ecdh_curve(const char *name, mbedtls_ecp_group_id gid) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q, R;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, gid) != 0) {
        ESP_LOGW(TAG, "%s: кривая не поддержана этой сборкой mbedTLS", name);
        goto done;
    }
    // Пара ключей для второй стороны: умножаем на неё, как при согласовании.
    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &s_drbg) != 0) {
        ESP_LOGW(TAG, "%s: не удалось сгенерировать пару ключей", name);
        goto done;
    }

    BENCH_SLOW_OP(name, "keygen", ITERS_MEDIUM,
        mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &s_drbg));

    BENCH_SLOW_OP(name, "точка*скаляр", ITERS_MEDIUM,
        mbedtls_ecp_mul(&grp, &R, &d, &Q, mbedtls_ctr_drbg_random, &s_drbg));

done:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
}

static void bench_symmetric(void) {
    uint8_t buf[1024], out[1024 + 16], tag[16];
    uint8_t key[32], nonce[12], hash[32];
    esp_fill_random(buf, sizeof(buf));
    esp_fill_random(key, sizeof(key));
    esp_fill_random(nonce, sizeof(nonce));

    BENCH_FAST_OP("SHA-256", "1 КБ", ITERS_FAST,
        mbedtls_sha256(buf, sizeof(buf), hash, 0));

    blake3_hasher h;
    BENCH_FAST_OP("BLAKE3", "1 КБ", ITERS_FAST, {
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, buf, sizeof(buf));
        blake3_hasher_finalize(&h, hash, 32);
    });

    // Вывод ключа: два коротких куска, как в самом протоколе. Отличается от
    // хеширования килобайта и меряется отдельно.
    uint8_t k1[32], k2[32];
    esp_fill_random(k1, 32); esp_fill_random(k2, 32);
    BENCH_FAST_OP("BLAKE3", "вывод ключа", ITERS_FAST, {
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, k1, 32);
        blake3_hasher_update(&h, k2, 32);
        blake3_hasher_finalize(&h, hash, 32);
    });

    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    mbedtls_chachapoly_setkey(&cp, key);
    BENCH_FAST_OP("ChaCha20-Poly1305", "seal 1 КБ", ITERS_FAST,
        mbedtls_chachapoly_encrypt_and_tag(&cp, sizeof(buf), nonce, NULL, 0,
                                           buf, out, tag));
    mbedtls_chachapoly_free(&cp);
}
#endif // BENCH_CLASSIC

// ─── Постквантовые ──────────────────────────────────────────────────────────
#if BENCH_MLKEM
// Уровни ML-KEM отличаются стойкостью и ценой. В протоколе используется 1024,
// остальные два меряются, чтобы видеть, что именно стоит выбор.
#define BENCH_KEM(name, PFX)                                                  \
    do {                                                                      \
        uint8_t *pk = malloc(PFX##_CRYPTO_PUBLICKEYBYTES);                    \
        uint8_t *sk = malloc(PFX##_CRYPTO_SECRETKEYBYTES);                    \
        uint8_t *ct = malloc(PFX##_CRYPTO_CIPHERTEXTBYTES);                   \
        uint8_t ss[PFX##_CRYPTO_BYTES];                                       \
        if (!pk || !sk || !ct) {                                              \
            ESP_LOGE(TAG, name ": не хватило кучи");                          \
        } else {                                                              \
            BENCH_SLOW_OP(name, "keygen", ITERS_MEDIUM,                       \
                PFX##_crypto_kem_keypair(pk, sk));                            \
            BENCH_SLOW_OP(name, "encaps", ITERS_MEDIUM,                       \
                PFX##_crypto_kem_enc(ct, ss, pk));                            \
            BENCH_SLOW_OP(name, "decaps", ITERS_MEDIUM,                       \
                PFX##_crypto_kem_dec(ss, ct, sk));                            \
            ESP_LOGI(TAG, "  (ключ %u, шифротекст %u байт)",                  \
                     (unsigned)PFX##_CRYPTO_PUBLICKEYBYTES,                   \
                     (unsigned)PFX##_CRYPTO_CIPHERTEXTBYTES);                 \
        }                                                                     \
        free(pk); free(sk); free(ct);                                         \
    } while (0)
#endif

#if BENCH_MLDSA || BENCH_SLHDSA
// Подписные схемы: интересны и время, и размер подписи — на канале ESP32
// последнее часто важнее.
#define BENCH_SIGN(name, PFX, iters)                                          \
    do {                                                                      \
        uint8_t *pk = malloc(PFX##_CRYPTO_PUBLICKEYBYTES);                    \
        uint8_t *sk = malloc(PFX##_CRYPTO_SECRETKEYBYTES);                    \
        uint8_t *sig = malloc(PFX##_CRYPTO_BYTES);                            \
        uint8_t msg[96];                                                      \
        size_t sig_len = 0;                                                   \
        esp_fill_random(msg, sizeof(msg));                                    \
        if (!pk || !sk || !sig) {                                             \
            ESP_LOGE(TAG, name ": не хватило кучи");                          \
        } else {                                                              \
            BENCH_SLOW_OP(name, "keygen", iters, PFX##_crypto_sign_keypair(pk, sk)); \
            BENCH_SLOW_OP(name, "sign", iters,                                \
                PFX##_crypto_sign_signature(sig, &sig_len, msg, sizeof(msg), sk)); \
            BENCH_SLOW_OP(name, "verify", iters,                              \
                PFX##_crypto_sign_verify(sig, sig_len, msg, sizeof(msg), pk)); \
            ESP_LOGI(TAG, "  (подпись %u, ключ %u байт)",                     \
                     (unsigned)sig_len, (unsigned)PFX##_CRYPTO_PUBLICKEYBYTES); \
        }                                                                     \
        free(pk); free(sk); free(sig);                                        \
    } while (0)
#endif

// ─── Прогон ─────────────────────────────────────────────────────────────────

static void print_header(void) {
    ESP_LOGI(TAG, "==========================================================");
    ESP_LOGI(TAG, "ЗАМЕРЫ КРИПТОГРАФИИ НА КРИСТАЛЛЕ");
#if CONFIG_IDF_TARGET_ESP32C6
    ESP_LOGI(TAG, "плата: ESP32-C6 (RISC-V, 160 МГц)");
#elif CONFIG_IDF_TARGET_ESP32S3
    ESP_LOGI(TAG, "плата: ESP32-S3 (Xtensa, 240 МГц)");
#else
    ESP_LOGI(TAG, "плата: %s", CONFIG_IDF_TARGET);
#endif
#ifdef CONFIG_MBEDTLS_HARDWARE_ECC
    ESP_LOGI(TAG, "ускоритель ECC: ВКЛЮЧЁН");
#else
    ESP_LOGI(TAG, "ускоритель ECC: выключен (или не поддержан кристаллом)");
#endif
#ifdef CONFIG_MBEDTLS_HARDWARE_MPI
    ESP_LOGI(TAG, "ускоритель больших чисел: включён");
#endif
    ESP_LOGI(TAG, "оптимизация: %s",
#ifdef CONFIG_COMPILER_OPTIMIZATION_SIZE
             "-Os"
#elif defined(CONFIG_COMPILER_OPTIMIZATION_PERF)
             "-O2"
#else
             "-Og (ОТЛАДОЧНАЯ — числа будут занижены)"
#endif
    );
    ESP_LOGI(TAG, "куча при старте: %" PRIu32 " байт", esp_get_free_heap_size());
    ESP_LOGI(TAG, "----------------------------------------------------------");
    ESP_LOGI(TAG, "%-18s %-14s %10s", "алгоритм", "операция", "среднее");
    ESP_LOGI(TAG, "----------------------------------------------------------");
}

// ─── Запуск ─────────────────────────────────────────────────────────────────
//
// Каждое семейство алгоритмов выполняется в собственной задаче со своим
// размером стека. Причина в расходе стека у постквантовых подписей: в
// эталонной реализации PQClean развёрнутая матрица лежит на стеке целиком, и
// одному вызову ML-DSA-87 нужен кадр в 121 КБ (ML-DSA-65 — 78 КБ, ML-DSA-44 —
// 50 КБ, замерено через -fstack-usage). Общий стек пришлось бы задавать по
// максимуму и держать его всё время; отдельные задачи создаются и
// освобождаются по очереди, так что одновременно занят только один крупный
// стек.
//
// Если задача не создалась — не хватило кучи под стек. Прошивка сообщает об
// этом и идёт дальше: остальные наборы от этого не страдают.

typedef struct {
    const char *name;
    void (*fn)(void);
    uint32_t stack;
} bench_stage_t;

static volatile bool s_stage_done;

static void stage_task(void *arg) {
    const bench_stage_t *st = (const bench_stage_t *)arg;
    st->fn();
    UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "  [%s] запас стека: %u из %" PRIu32 " байт, куча: %" PRIu32,
             st->name, (unsigned)(hwm * sizeof(StackType_t)), st->stack,
             esp_get_free_heap_size());
    s_stage_done = true;
    vTaskDelete(NULL);
}

static void run_stage(const bench_stage_t *st) {
    ESP_LOGI(TAG, "── %s ──", st->name);
    s_stage_done = false;
    TaskHandle_t h = NULL;
    if (xTaskCreate(stage_task, "bench", st->stack / sizeof(StackType_t),
                    (void *)st, 5, &h) != pdPASS) {
        ESP_LOGE(TAG, "%s: не удалось создать задачу со стеком %" PRIu32
                 " байт (свободно в куче %" PRIu32 ") — набор пропущен",
                 st->name, st->stack, esp_get_free_heap_size());
        return;
    }
    while (!s_stage_done) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

#if BENCH_CLASSIC
static void stage_classic(void) {
    bench_ecdsa();
    bench_ecdh_curve("ECDH P-256", MBEDTLS_ECP_DP_SECP256R1);
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
    bench_ecdh_curve("X25519", MBEDTLS_ECP_DP_CURVE25519);
#else
    ESP_LOGW(TAG, "X25519 не собран: включите CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED");
#endif
    bench_symmetric();
}
#endif

#if BENCH_MLKEM
static void stage_mlkem(void) {
    BENCH_KEM("ML-KEM-512", PQCLEAN_MLKEM512_CLEAN);
    BENCH_KEM("ML-KEM-768", PQCLEAN_MLKEM768_CLEAN);
    BENCH_KEM("ML-KEM-1024", PQCLEAN_MLKEM1024_CLEAN);
}
#endif

#if BENCH_MLDSA
// Три уровня разнесены по задачам: держать 160 КБ стека ради одного ML-DSA-87
// всё время прогона незачем.
static void stage_mldsa44(void) { BENCH_SIGN("ML-DSA-44", PQCLEAN_MLDSA44_CLEAN, ITERS_MEDIUM); }
static void stage_mldsa65(void) { BENCH_SIGN("ML-DSA-65", PQCLEAN_MLDSA65_CLEAN, ITERS_MEDIUM); }
static void stage_mldsa87(void) { BENCH_SIGN("ML-DSA-87", PQCLEAN_MLDSA87_CLEAN, ITERS_MEDIUM); }
#endif

#if BENCH_SLHDSA
static void stage_slhdsa(void) {
    ESP_LOGW(TAG, "подпись SLH-DSA идёт секунды: этот набор займёт минуты");
    BENCH_SIGN("SLH-DSA-128s", PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN, ITERS_GLACIAL);
}
#endif

// Размеры стека взяты по замеру крупнейшего кадра плюс запас на обвязку.
static const bench_stage_t STAGES[] = {
#if BENCH_CLASSIC
    { "классические примитивы", stage_classic,  24 * 1024 },
#endif
#if BENCH_MLKEM
    { "ML-KEM (обмен ключами)", stage_mlkem,    48 * 1024 },
#endif
#if BENCH_MLDSA
    { "ML-DSA-44",              stage_mldsa44,  72 * 1024 },
    { "ML-DSA-65",              stage_mldsa65, 104 * 1024 },
    { "ML-DSA-87",             stage_mldsa87, 152 * 1024 },
#endif
#if BENCH_SLHDSA
    { "SLH-DSA (подпись)",      stage_slhdsa,   32 * 1024 },
#endif
};

void app_main(void) {
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_drbg);
    const char *pers = "lacert-bench";
    if (mbedtls_ctr_drbg_seed(&s_drbg, mbedtls_entropy_func, &s_entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        ESP_LOGE(TAG, "не удалось инициализировать генератор случайных чисел");
        return;
    }

    print_header();

    for (size_t i = 0; i < sizeof(STAGES) / sizeof(STAGES[0]); i++) {
        run_stage(&STAGES[i]);
    }

    ESP_LOGI(TAG, "----------------------------------------------------------");
    ESP_LOGI(TAG, "прогон завершён, куча: %" PRIu32 " байт", esp_get_free_heap_size());
    ESP_LOGI(TAG, "==========================================================");

    mbedtls_ctr_drbg_free(&s_drbg);
    mbedtls_entropy_free(&s_entropy);
}
