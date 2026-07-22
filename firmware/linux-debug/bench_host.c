// bench_host.c — микробенчмарк криптографии на хосте (x86-64).
//
// Прогоняет ТЕ ЖЕ операции и ТЕМ ЖЕ кодом (lacert_crypto.c + компоненты
// ml_kem/blake3), что и режим LACERT_BENCH в прошивке. Это даёт колонку
// «x86-64» для таблицы сравнения архитектур: расхождения нельзя списать на
// разные библиотеки — реализация одна и та же.
//
// Сборка (пример):
//   gcc -O2 -std=c11 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2
//       -DBLAKE3_NO_AVX512 -I../main -I../components/ml_kem -I../components/blake3
//       bench_host.c ../main/lacert_crypto.c ../components/ml_kem/*.c
//       ../components/blake3/blake3.c ../components/blake3/blake3_dispatch.c
//       ../components/blake3/blake3_portable.c -lmbedcrypto -o bench_host
#define _POSIX_C_SOURCE 200809L   // clock_gettime
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lacert_crypto.h"
#include "lacert_proto.h"
#include "api.h"   // PQClean ML-KEM-1024

#define BENCH_ITERS 20

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void report(const char *name, long long total_us, int iters) {
    double avg = (double)total_us / iters;
    if (avg >= 1000.0)
        printf("  %-28s %8.2f мс   (%d прогонов)\n", name, avg / 1000.0, iters);
    else
        printf("  %-28s %8.1f мкс  (%d прогонов)\n", name, avg, iters);
}

// Та же методика, что в прошивке (LACERT_BENCH).
// BENCH_SLOW — тяжёлые операции: каждая итерация замеряется отдельно (на плате
// между ними ещё отдаётся управление планировщику, здесь это не нужно).
// BENCH_FAST — лёгкие операции: цикл меряется целиком, иначе накладные расходы
// на вызовы таймера (несколько микросекунд) исказили бы результат.
#define BENCH_SLOW(name, iters, stmt)               \
    do {                                            \
        long long _total = 0;                       \
        for (int _i = 0; _i < (iters); _i++) {      \
            long long _t = now_us();                \
            stmt;                                   \
            _total += now_us() - _t;                \
        }                                           \
        report((name), _total, (iters));            \
    } while (0)

#define BENCH_FAST(name, iters, stmt)               \
    do {                                            \
        long long _t = now_us();                    \
        for (int _i = 0; _i < (iters); _i++) { stmt; } \
        report((name), now_us() - _t, (iters));     \
    } while (0)

int main(void) {
    const int N = BENCH_ITERS;

    printf("==================================================\n");
    printf("МИКРОБЕНЧМАРК КРИПТОГРАФИИ (без сети)\n");
    printf("платформа: x86-64 (хост)\n");
    printf("--------------------------------------------------\n");

    uint8_t *pk = malloc(LACERT_KEM_PUBKEY_SIZE);
    uint8_t *sk = malloc(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    uint8_t *ct = malloc(LACERT_KEM_CIPHERTEXT_SIZE);
    if (!pk || !sk || !ct) { printf("нет памяти\n"); return 1; }

    uint8_t ss[LACERT_KEM_SHARED_SIZE];
    uint8_t priv[32], pub[LACERT_ECDSA_PUB_SIZE];
    uint8_t msg[96], hash[32], sig[LACERT_MAX_SIG_SIZE];
    size_t sig_len = 0;
    lacert_random(msg, sizeof(msg));

    int keygen_n = N / 4 > 0 ? N / 4 : 1;

    BENCH_SLOW("ECDSA P-256 keypair", keygen_n, lacert_ecdsa_keypair(priv, pub));
    BENCH_SLOW("ECDSA P-256 sign", N,
             lacert_ecdsa_sign(priv, msg, sizeof(msg), sig, &sig_len));
    printf("  (размер подписи: %u байт)\n", (unsigned)sig_len);

    BENCH_SLOW("ML-KEM-1024 keypair", keygen_n, lacert_kem_keypair(pk, sk));
    BENCH_SLOW("ML-KEM-1024 encapsulate", N,
             PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk));
    BENCH_SLOW("ML-KEM-1024 decapsulate", N, lacert_kem_decapsulate(sk, ct, ss));

    const uint8_t *parts[2] = { ss, msg };
    const size_t lens[2] = { LACERT_KEM_SHARED_SIZE, 32 };
    BENCH_FAST("BLAKE3 (вывод ключа)", N * 10, lacert_blake3(parts, lens, 2, hash));
    BENCH_FAST("SHA-256 (96 байт)", N * 10, lacert_sha256(msg, sizeof(msg), hash));

    uint8_t nonce[LACERT_CHACHA_NONCE_SIZE];
    uint8_t out[160]; size_t out_len = 0;
    uint8_t key[32]; lacert_random(key, 32);
    BENCH_FAST("ChaCha20-Poly1305 seal", N * 10,
             lacert_chacha_seal(key, (uint32_t)_i, msg, sizeof(msg), nonce, out, &out_len));

    printf("==================================================\n");
    free(pk); free(sk); free(ct);
    return 0;
}
