// lacert_hs_bench.c — криптографическая стоимость рукопожатия LACERT,
// измеренная на C с тем же mbedTLS, что и стенд DTLS.
//
// Зачем отдельный замер. Рукопожатие LACERT уже измерено в Go (122,8 мкс), но
// сравнивать это число с DTLS на mbedTLS нельзя: в Go подпись P-256 идёт через
// ассемблерную реализацию и выполняется за 25 мкс, тогда как та же операция в
// mbedTLS занимает 365 мкс. Разница в 14 раз отражала бы выбор библиотеки, а не
// свойства протоколов.
//
// Что считается. Полный криптографический путь рукопожатия, обе стороны:
//   шлюз:      ML-KEM-1024 инкапсуляция + BLAKE3 + проверка подписи ECDSA
//   устройство: ML-KEM-1024 декапсуляция + BLAKE3 + формирование подписи ECDSA
//
// Подготовка ключей (генерация пар ML-KEM и ECDSA) в замер НЕ входит: она
// выполняется однократно при провижининге, а не на каждое подключение — так же,
// как в DTLS не учитывается выпуск сертификата.
//
// Сборка: см. команду в конце файла.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lacert_crypto.h"
#include "lacert_proto.h"
#include "api.h"           // PQClean ML-KEM-1024

#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

// Проверка подписи — это работа ШЛЮЗА. В прошивке её нет (устройство только
// подписывает), поэтому здесь она выполняется напрямую через mbedTLS — той же
// библиотекой, что использует стенд DTLS.
static int verify_sig(const uint8_t *pub, size_t pub_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int rc = -1;

    if (mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp),
                               MBEDTLS_ECP_DP_SECP256R1) != 0) goto done;
    if (mbedtls_ecp_point_read_binary(&ctx.MBEDTLS_PRIVATE(grp),
                                      &ctx.MBEDTLS_PRIVATE(Q),
                                      pub, pub_len) != 0) goto done;

    uint8_t digest[32];
    if (mbedtls_sha256(msg, msg_len, digest, 0) != 0) goto done;

    rc = mbedtls_ecdsa_read_signature(&ctx, digest, sizeof(digest), sig, sig_len);
done:
    mbedtls_ecdsa_free(&ctx);
    return rc;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 20;

    printf("==================================================\n");
    printf("LACERT — КРИПТОГРАФИЧЕСКАЯ СТОИМОСТЬ РУКОПОЖАТИЯ\n");
    printf("платформа: x86-64 (хост), та же сборка mbedTLS, что у стенда DTLS\n");
    printf("--------------------------------------------------\n");

    // --- Провижининг: выполняется однократно, в замер не входит ---
    uint8_t dev_kem_pk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dev_kem_sk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (lacert_kem_keypair(dev_kem_pk, dev_kem_sk) != LACERT_OK) {
        fprintf(stderr, "ошибка генерации пары ML-KEM\n"); return 1;
    }
    uint8_t ecdsa_priv[32], ecdsa_pub[LACERT_ECDSA_PUB_SIZE];
    if (lacert_ecdsa_keypair(ecdsa_priv, ecdsa_pub) != LACERT_OK) {
        fprintf(stderr, "ошибка генерации пары ECDSA\n"); return 1;
    }

    double t_encap = 0, t_decap = 0, t_sign = 0, t_verify = 0, t_hash = 0, t_total = 0;
    size_t sig_len_last = 0;

    for (int i = 0; i < iters; i++) {
        double t_iter0 = now_us();

        // ---- Шлюз: инкапсуляция к публичному ключу устройства (Msg2) ----
        uint8_t ct[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        uint8_t ss_gw[LACERT_KEM_SHARED_SIZE];
        double t0 = now_us();
        if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss_gw, dev_kem_pk) != 0) {
            fprintf(stderr, "ошибка инкапсуляции\n"); return 1;
        }
        t_encap += now_us() - t0;

        // ---- Устройство: декапсуляция ----
        uint8_t ss_dev[LACERT_KEM_SHARED_SIZE];
        t0 = now_us();
        if (lacert_kem_decapsulate(dev_kem_sk, ct, ss_dev) != LACERT_OK) {
            fprintf(stderr, "ошибка декапсуляции\n"); return 1;
        }
        t_decap += now_us() - t0;

        if (memcmp(ss_gw, ss_dev, LACERT_KEM_SHARED_SIZE) != 0) {
            fprintf(stderr, "общий секрет разошёлся\n"); return 1;
        }

        // ---- Вывод K0: BLAKE3(shared || transcript) ----
        uint8_t transcript[64];
        memcpy(transcript, ct, 32);
        memcpy(transcript + 32, dev_kem_pk, 32);
        uint8_t k0[32];
        const uint8_t *parts[2] = { ss_dev, transcript };
        const size_t   lens[2]  = { LACERT_KEM_SHARED_SIZE, sizeof(transcript) };
        t0 = now_us();
        if (lacert_blake3(parts, lens, 2, k0) != LACERT_OK) {
            fprintf(stderr, "ошибка BLAKE3\n"); return 1;
        }
        t_hash += now_us() - t0;

        // ---- Устройство: подпись подтверждения ключа (Msg3) ----
        // Подписывается BLAKE3(transcript || "confirm" || K0).
        uint8_t confirm[32];
        const uint8_t *cparts[3] = { transcript, (const uint8_t *)"confirm", k0 };
        const size_t   clens[3]  = { sizeof(transcript), 7, sizeof(k0) };
        if (lacert_blake3(cparts, clens, 3, confirm) != LACERT_OK) {
            fprintf(stderr, "ошибка BLAKE3 (confirm)\n"); return 1;
        }

        uint8_t sig[LACERT_MAX_SIG_SIZE];
        size_t  sig_len = 0;
        t0 = now_us();
        if (lacert_ecdsa_sign(ecdsa_priv, confirm, sizeof(confirm), sig, &sig_len) != LACERT_OK) {
            fprintf(stderr, "ошибка подписи\n"); return 1;
        }
        t_sign += now_us() - t0;
        sig_len_last = sig_len;

        // ---- Шлюз: проверка подписи ----
        t0 = now_us();
        if (verify_sig(ecdsa_pub, LACERT_ECDSA_PUB_SIZE,
                       confirm, sizeof(confirm), sig, sig_len) != 0) {
            fprintf(stderr, "подпись не прошла проверку\n"); return 1;
        }
        t_verify += now_us() - t0;

        t_total += now_us() - t_iter0;
    }

    printf("  ML-KEM-1024 инкапсуляция (шлюз)   %8.1f мкс\n", t_encap / iters);
    printf("  ML-KEM-1024 декапсуляция (устр.)  %8.1f мкс\n", t_decap / iters);
    printf("  BLAKE3 вывод ключа                %8.1f мкс\n", t_hash / iters);
    printf("  ECDSA подпись (устройство)        %8.1f мкс\n", t_sign / iters);
    printf("  ECDSA проверка (шлюз)             %8.1f мкс\n", t_verify / iters);
    printf("  --------------------------------------------\n");
    printf("  ВСЕГО за рукопожатие              %8.1f мкс   (%d прогонов)\n",
           t_total / iters, iters);
    printf("\n");
    printf("  Объём рукопожатия (полезная нагрузка протокола):\n");
    printf("    публичный ключ ML-KEM устройства  %5d байт  (при провижининге, не в канале)\n",
           PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("    шифротекст ML-KEM (Msg2)          %5d байт\n",
           PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    printf("    подпись ECDSA (Msg3)              %5zu байт\n", sig_len_last);
    printf("==================================================\n");
    return 0;
}

// Сборка (из каталога /tmp/dtls, FW — каталог firmware проекта):
//   gcc -O2 -std=c11 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2
//       -DBLAKE3_NO_AVX512 -I$FW/linux-debug -I$FW/main -I$FW/components/ml_kem
//       -I$FW/components/blake3 -I$MB/include lacert_hs_bench.c
//       $FW/main/lacert_crypto.c $FW/components/ml_kem/*.c
//       $FW/components/blake3/blake3.c $FW/components/blake3/blake3_dispatch.c
//       $FW/components/blake3/blake3_portable.c -L$MB/library -lmbedcrypto
//       -o lacert_hs_bench
