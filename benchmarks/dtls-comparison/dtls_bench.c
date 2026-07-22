// dtls_bench.c — стоимость установления сессии DTLS 1.2 на mbedTLS.
//
// Методика намеренно повторяет ту, которой измерялось рукопожатие LACERT
// (BenchmarkFullHandshakeECDSA): клиент и сервер работают в ОДНОМ процессе и
// обмениваются через буферы в памяти. Сеть исключена — иначе измерялась бы
// задержка канала, а не стоимость протокола.
//
// Сборка:
//   gcc -O2 -std=c11 dtls_bench.c -I$MB/include -L$MB/library
//       -lmbedtls -lmbedx509 -lmbedcrypto -o dtls_bench

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_cookie.h"

// ---------------------------------------------------------------------------
// Транспорт в памяти: два однонаправленных буфера.
// ---------------------------------------------------------------------------
#define PIPE_CAP 65536

typedef struct {
    unsigned char buf[PIPE_CAP];
    size_t head, tail;
} pipe_t;

typedef struct {
    pipe_t *rx;          // откуда читает эта сторона
    pipe_t *tx;          // куда пишет эта сторона
    size_t  sent_bytes;  // счётчик переданного (для объёма рукопожатия)
} endpoint_t;

static void pipe_reset(pipe_t *p) { p->head = p->tail = 0; }

static int ep_send(void *ctx, const unsigned char *b, size_t n) {
    endpoint_t *e = (endpoint_t *)ctx;
    pipe_t *p = e->tx;
    if (p->tail + n > PIPE_CAP) return MBEDTLS_ERR_SSL_WANT_WRITE;
    memcpy(p->buf + p->tail, b, n);
    p->tail += n;
    e->sent_bytes += n;
    return (int)n;
}

static int ep_recv(void *ctx, unsigned char *b, size_t n) {
    endpoint_t *e = (endpoint_t *)ctx;
    pipe_t *p = e->rx;
    size_t avail = p->tail - p->head;
    if (avail == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t take = avail < n ? avail : n;
    memcpy(b, p->buf + p->head, take);
    p->head += take;
    if (p->head == p->tail) pipe_reset(p);
    return (int)take;
}

// Таймеры DTLS. Потери в памяти невозможны, поэтому повтор не нужен:
// таймер всегда сообщает «время не вышло».
static void tm_set(void *ctx, uint32_t inter, uint32_t fin) { (void)ctx; (void)inter; (void)fin; }
static int  tm_get(void *ctx) { (void)ctx; return 0; }

// ---------------------------------------------------------------------------
static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static const unsigned char PSK[16] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
    0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4
};
static const char PSK_ID[] = "lacert-device-1";

typedef struct {
    const char *name;
    int use_psk;
    const char *suite;   // явно заданный набор шифров
} mode_t_;

// Один полный обмен: рукопожатие до конца с обеих сторон.
// Возвращает 0 при успехе; в *bytes — суммарно передано байт.
static int run_handshake(mbedtls_ssl_context *cli, mbedtls_ssl_context *srv,
                         endpoint_t *ec, endpoint_t *es, size_t *bytes) {
    int rc_c = MBEDTLS_ERR_SSL_WANT_READ, rc_s = MBEDTLS_ERR_SSL_WANT_READ;
    for (int step = 0; step < 200; step++) {
        if (rc_c == MBEDTLS_ERR_SSL_WANT_READ || rc_c == MBEDTLS_ERR_SSL_WANT_WRITE)
            rc_c = mbedtls_ssl_handshake(cli);
        if (rc_s == MBEDTLS_ERR_SSL_WANT_READ || rc_s == MBEDTLS_ERR_SSL_WANT_WRITE)
            rc_s = mbedtls_ssl_handshake(srv);

        if (rc_c == 0 && rc_s == 0) {
            if (bytes) *bytes = ec->sent_bytes + es->sent_bytes;
            return 0;
        }
        int fatal_c = (rc_c != 0 && rc_c != MBEDTLS_ERR_SSL_WANT_READ && rc_c != MBEDTLS_ERR_SSL_WANT_WRITE);
        int fatal_s = (rc_s != 0 && rc_s != MBEDTLS_ERR_SSL_WANT_READ && rc_s != MBEDTLS_ERR_SSL_WANT_WRITE);
        if (fatal_c || fatal_s) {
            fprintf(stderr, "  handshake failed: client=-0x%04x server=-0x%04x\n",
                    (unsigned)-rc_c, (unsigned)-rc_s);
            return -1;
        }
    }
    fprintf(stderr, "  handshake did not converge\n");
    return -1;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 20;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    const char *pers = "dtls_bench";
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        fprintf(stderr, "drbg seed failed\n"); return 1;
    }

    // Сертификат и ключ сервера (нужны только режиму ECDHE-ECDSA).
    mbedtls_x509_crt srv_crt; mbedtls_pk_context srv_key;
    mbedtls_x509_crt_init(&srv_crt); mbedtls_pk_init(&srv_key);
    if (mbedtls_x509_crt_parse_file(&srv_crt, "srv.crt") != 0 ||
        mbedtls_pk_parse_keyfile(&srv_key, "srv.key", NULL,
                                 mbedtls_ctr_drbg_random, &drbg) != 0) {
        fprintf(stderr, "не удалось загрузить srv.crt / srv.key\n"); return 1;
    }
    // Сертификат устройства: у LACERT устройство доказывает подлинность
    // подписью, поэтому для сопоставимости DTLS настраивается на взаимную
    // аутентификацию, а не только серверную.
    mbedtls_x509_crt cli_crt; mbedtls_pk_context cli_key;
    mbedtls_x509_crt_init(&cli_crt); mbedtls_pk_init(&cli_key);
    if (mbedtls_x509_crt_parse_file(&cli_crt, "cli.crt") != 0 ||
        mbedtls_pk_parse_keyfile(&cli_key, "cli.key", NULL,
                                 mbedtls_ctr_drbg_random, &drbg) != 0) {
        fprintf(stderr, "не удалось загрузить cli.crt / cli.key\n"); return 1;
    }

    printf("==================================================\n");
    printf("DTLS 1.2 — СТОИМОСТЬ УСТАНОВЛЕНИЯ СЕССИИ\n");
    printf("платформа: x86-64 (хост), mbedTLS %s\n", MBEDTLS_VERSION_STRING);
    printf("транспорт: буферы в памяти (сеть исключена)\n");
    printf("--------------------------------------------------\n");

    // Наборы задаются явно: без этого mbedTLS для «PSK» выбирает ECDHE-PSK,
    // и замер перестаёт быть нижней границей стоимости.
    mode_t_ modes[3] = {
        {"DTLS-PSK",         1, "TLS-PSK-WITH-CHACHA20-POLY1305-SHA256"},
        {"DTLS-ECDHE-PSK",   1, "TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256"},
        {"DTLS-ECDHE-ECDSA (взаимная)", 0, "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
    };

    for (int m = 0; m < 3; m++) {
        int suite_id = mbedtls_ssl_get_ciphersuite_id(modes[m].suite);
        if (suite_id == 0) {
            printf("  %-22s набор недоступен в сборке\n", modes[m].name);
            continue;
        }
        int suites[2] = { suite_id, 0 };
        double total = 0;
        size_t hs_bytes = 0;
        int ok = 0;

        for (int i = 0; i < iters; i++) {
            pipe_t p_c2s, p_s2c;
            pipe_reset(&p_c2s); pipe_reset(&p_s2c);
            endpoint_t ec = { .rx = &p_s2c, .tx = &p_c2s, .sent_bytes = 0 };
            endpoint_t es = { .rx = &p_c2s, .tx = &p_s2c, .sent_bytes = 0 };

            mbedtls_ssl_context cli, srv;
            mbedtls_ssl_config  cfg_c, cfg_s;
            mbedtls_ssl_init(&cli); mbedtls_ssl_init(&srv);
            mbedtls_ssl_config_init(&cfg_c); mbedtls_ssl_config_init(&cfg_s);

            mbedtls_ssl_config_defaults(&cfg_c, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
            mbedtls_ssl_config_defaults(&cfg_s, MBEDTLS_SSL_IS_SERVER,
                MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);

            mbedtls_ssl_conf_rng(&cfg_c, mbedtls_ctr_drbg_random, &drbg);
            mbedtls_ssl_conf_rng(&cfg_s, mbedtls_ctr_drbg_random, &drbg);
            mbedtls_ssl_conf_ciphersuites(&cfg_c, suites);
            mbedtls_ssl_conf_ciphersuites(&cfg_s, suites);

            // Cookie-обмен отключён: он защищает от amplification-атак на
            // открытом UDP и к стоимости криптографии отношения не имеет.
            mbedtls_ssl_conf_dtls_cookies(&cfg_s, NULL, NULL, NULL);

            if (modes[m].use_psk) {
                mbedtls_ssl_conf_psk(&cfg_c, PSK, sizeof(PSK),
                                     (const unsigned char *)PSK_ID, strlen(PSK_ID));
                mbedtls_ssl_conf_psk(&cfg_s, PSK, sizeof(PSK),
                                     (const unsigned char *)PSK_ID, strlen(PSK_ID));
            } else {
                // Клиент проверяет сертификат сервера…
                mbedtls_ssl_conf_ca_chain(&cfg_c, &srv_crt, NULL);
                mbedtls_ssl_conf_authmode(&cfg_c, MBEDTLS_SSL_VERIFY_REQUIRED);
                mbedtls_ssl_conf_own_cert(&cfg_s, &srv_crt, &srv_key);
                // …и предъявляет свой, а сервер требует его проверки.
                mbedtls_ssl_conf_own_cert(&cfg_c, &cli_crt, &cli_key);
                mbedtls_ssl_conf_ca_chain(&cfg_s, &cli_crt, NULL);
                mbedtls_ssl_conf_authmode(&cfg_s, MBEDTLS_SSL_VERIFY_REQUIRED);
            }

            mbedtls_ssl_setup(&cli, &cfg_c);
            mbedtls_ssl_setup(&srv, &cfg_s);
            // При строгой проверке сертификата клиент обязан знать ожидаемое
            // имя узла — иначе проверка отвергается как небезопасная.
            if (!modes[m].use_psk) mbedtls_ssl_set_hostname(&cli, "lacert-dtls-bench");
            mbedtls_ssl_set_bio(&cli, &ec, ep_send, ep_recv, NULL);
            mbedtls_ssl_set_bio(&srv, &es, ep_send, ep_recv, NULL);
            mbedtls_ssl_set_timer_cb(&cli, NULL, tm_set, tm_get);
            mbedtls_ssl_set_timer_cb(&srv, NULL, tm_set, tm_get);

            double t0 = now_us();
            int rc = run_handshake(&cli, &srv, &ec, &es, &hs_bytes);
            double dt = now_us() - t0;

            if (rc == 0) {
                total += dt; ok++;
                if (i == 0) {
                    const char *cs = mbedtls_ssl_get_ciphersuite(&cli);
                    printf("  %-22s набор: %s\n", modes[m].name, cs ? cs : "?");
                }
            }

            mbedtls_ssl_free(&cli); mbedtls_ssl_free(&srv);
            mbedtls_ssl_config_free(&cfg_c); mbedtls_ssl_config_free(&cfg_s);
            if (rc != 0) break;
        }

        if (ok == 0) { printf("  %-22s НЕ УДАЛОСЬ\n", modes[m].name); continue; }
        printf("  %-22s %8.1f мкс   (%d прогонов)\n", modes[m].name, total / ok, ok);
        printf("  %-22s %8zu байт  за рукопожатие\n", "  трафик:", hs_bytes);
    }

    printf("==================================================\n");

    mbedtls_x509_crt_free(&srv_crt); mbedtls_pk_free(&srv_key);
    mbedtls_x509_crt_free(&cli_crt); mbedtls_pk_free(&cli_key);
    mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy);
    return 0;
}
