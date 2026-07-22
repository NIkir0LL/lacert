// main_linux.c — точка входа ЛИНУКС-ОТЛАДКИ клиента LACERT, максимально
// приближённая к реальной прошивке ESP32:
//   1) Постоянные ключи. При первом запуске генерируются и сохраняются в файл
//      (моделирует NVS/efuse на ESP32); при последующих — загружаются, чтобы
//      device_id оставался «тем же устройством» после перезапуска.
//   2) Реальный хеш прошивки. SHA-256 берётся от собственного исполняемого
//      файла (на ESP32 — от образа прошивки).
//   3) Переподключение. При разрыве связи клиент ждёт и переподключается,
//      повторяя рукопожатие — как реальное устройство после потери сети.
//
// Сборка и запуск — см. build_linux.sh / README.md.
#define _DEFAULT_SOURCE
#include "lacert_client.h"
#include "lacert_crypto.h"
#include "lacert_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "api.h"  // PQClean ML-KEM keypair

// --- hex-помощники ---
static void to_hex(const uint8_t *b, size_t n, char *out){
    static const char *h = "0123456789abcdef";
    for (size_t i=0;i<n;i++){ out[2*i]=h[b[i]>>4]; out[2*i+1]=h[b[i]&15]; }
    out[2*n]=0;
}
static int from_hex(const char *h, uint8_t *out, int maxlen){
    int n=0;
    while(h[0]&&h[1]&&h[0]!='"'&&h[0]!='\n'&&n<maxlen){
        int hi=(h[0]<='9')?h[0]-'0':(h[0]|32)-'a'+10;
        int lo=(h[1]<='9')?h[1]-'0':(h[1]|32)-'a'+10;
        out[n++]=(hi<<4)|lo; h+=2;
    }
    return n;
}

static int http_request(const char *host, int port, const char *req,
                        char *resp, size_t resp_max);

// --- 1) Постоянные ключи: хранилище в файле (моделирует NVS/efuse ESP32) ---
static int keystore_load(const char *path, lacert_identity_t *id){
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[8192];
    int ok = 1;
    #define RDHEX(field, size) \
        if (!fgets(line, sizeof(line), f) || from_hex(line, id->field, size) != size) ok = 0;
    RDHEX(ecdsa_priv, 32)
    RDHEX(ecdsa_pub, LACERT_ECDSA_PUB_SIZE)
    RDHEX(kem_priv, 3168)
    RDHEX(kem_pub, LACERT_KEM_PUBKEY_SIZE)
    #undef RDHEX
    fclose(f);
    return ok;
}
static void keystore_save(const char *path, const lacert_identity_t *id){
    FILE *f = fopen(path, "w");
    if (!f) { perror("keystore save"); return; }
    char buf[8192];
    to_hex(id->ecdsa_priv, 32, buf);                   fprintf(f, "%s\n", buf);
    to_hex(id->ecdsa_pub, LACERT_ECDSA_PUB_SIZE, buf);  fprintf(f, "%s\n", buf);
    to_hex(id->kem_priv, 3168, buf);                   fprintf(f, "%s\n", buf);
    to_hex(id->kem_pub, LACERT_KEM_PUBKEY_SIZE, buf);   fprintf(f, "%s\n", buf);
    fclose(f);
    chmod(path, 0600);
}

static void generate_keys(lacert_identity_t *id){
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    const BIGNUM *d = EC_KEY_get0_private_key(ec);
    BN_bn2binpad(d, id->ecdsa_priv, 32);
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                       id->ecdsa_pub, LACERT_ECDSA_PUB_SIZE, NULL);
    EC_KEY_free(ec);
    PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(id->kem_pub, id->kem_priv);
}

// --- 2) Реальный хеш прошивки: SHA-256 собственного бинарника ---
static int compute_self_firmware_hash(const char *self_path, uint8_t out[32]){
    FILE *f = fopen(self_path, "rb");
    if (!f) return 0;
    SHA256_CTX c; SHA256_Init(&c);
    uint8_t buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) SHA256_Update(&c, buf, n);
    fclose(f);
    SHA256_Final(out, &c);
    return 1;
}

static int register_device(const char *host, int http_port,
                           const char *admin_token, lacert_session_t *s){
    char id_hex[131], kem_hex[3200], fw_hex[65];
    to_hex(s->id.ecdsa_pub, LACERT_ECDSA_PUB_SIZE, id_hex);
    to_hex(s->id.kem_pub, LACERT_KEM_PUBKEY_SIZE, kem_hex);
    to_hex(s->firmware_image_hash, LACERT_FW_HASH_SIZE, fw_hex);

    uint8_t sum[32];
    { const uint8_t *parts[4] = {
          (const uint8_t*)s->device_id, s->id.ecdsa_pub, s->id.kem_pub, s->firmware_image_hash };
      const size_t lens[4] = {
          strlen(s->device_id), LACERT_ECDSA_PUB_SIZE, LACERT_KEM_PUBKEY_SIZE, LACERT_FW_HASH_SIZE };
      lacert_blake3(parts, lens, 4, sum); }
    char checksum[9]; to_hex(sum, 4, checksum);

    char body[8192];
    snprintf(body, sizeof(body),
        "{\"device_id\":\"%s\",\"identity_pub_hex\":\"%s\","
        "\"kem_pub_hex\":\"%s\",\"firmware_hash_hex\":\"%s\","
        "\"checksum\":\"%s\",\"sig_algorithm\":\"ecdsa-p256\"}",
        s->device_id, id_hex, kem_hex, fw_hex, checksum);

    char req[16384], resp[8192];
    if (admin_token && admin_token[0]) {
        snprintf(req, sizeof(req),
            "POST /api/v1/devices HTTP/1.1\r\nHost: %s\r\n"
            "Authorization: Bearer %s\r\nContent-Type: application/json\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
            host, admin_token, strlen(body), body);
    } else {
        snprintf(req, sizeof(req),
            "POST /api/v1/devices HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: application/json\r\nContent-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s", host, strlen(body), body);
    }
    if (http_request(host, http_port, req, resp, sizeof(resp)) < 0) return -1;
    if (strstr(resp, "201")) { printf("Регистрация: новое устройство (201)\n"); return 0; }
    if (strstr(resp, "exists") || strstr(resp, "400")) {
        printf("Регистрация: устройство уже зарегистрировано (ок при повторном запуске)\n");
        return 0;
    }
    printf("Регистрация: ответ: %.60s\n", resp);
    return 0;
}

static int fetch_gateway_key(const char *host, int http_port, lacert_session_t *s){
    char req[512], resp[8192];
    snprintf(req, sizeof(req),
        "GET /api/v1/gateway HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (http_request(host, http_port, req, resp, sizeof(resp)) < 0) return -1;
    char *kp = strstr(resp, "kem_pub_hex");
    if (!kp) return -1;
    kp = strchr(kp, ':'); if (!kp) return -1;
    kp = strchr(kp, '"'); if (!kp) return -1; kp++;
    from_hex(kp, s->gw_kem_pub, LACERT_KEM_PUBKEY_SIZE);
    return 0;
}

static int tcp_connect(const char *host, int tcp_port){
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_port=htons(tcp_port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){ close(fd); return -1; }
    return fd;
}

/* Замеры на хосте — те же, что снимает прошивка на плате (LACERT_MEASURE).
   Один и тот же клиентский код на x86 и на ESP32 даёт прямо сравнимые цифры. */
static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}
static long long m_handshake_us, m_rotation_us, m_fw_sign_us;

static int run_session(lacert_session_t *s, const char *host, int tcp_port,
                       time_t deadline, int *seq, int *rot_total, int *fw_total){
    s->sock = tcp_connect(host, tcp_port);
    if (s->sock < 0){ printf("  [сеть] не удалось подключиться, повтор...\n"); return -1; }

    s->has_session = 0;
    long long t0 = now_us();
    if (lacert_do_handshake(s) != LACERT_OK){
        printf("  [!] рукопожатие не удалось, переподключение...\n");
        close(s->sock); return -1;
    }
    m_handshake_us = now_us() - t0;
    printf("=== сессия установлена (рукопожатие ок) ===\n");
    printf("  [замер] рукопожатие: %lld мкс (%.2f мс)\n", m_handshake_us, m_handshake_us/1000.0);

    time_t last_send = 0;
    while (time(NULL) < deadline) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(s->sock, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int r = select(s->sock + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) { printf("  [сеть] select() ошибка — разрыв\n"); close(s->sock); return -1; }
        if (r > 0 && FD_ISSET(s->sock, &rfds)) {
            uint64_t iter_before = s->iteration;
            long long ti = now_us();
            lacert_err_t e = lacert_handle_incoming(s);
            long long dti = now_us() - ti;
            if (e == LACERT_OK) {
                if (s->iteration > iter_before){
                    (*rot_total)++;
                    m_rotation_us = dti;
                    printf("  [ротация] новый ключ, итерация=%llu  [замер: %lld мкс]\n",
                           (unsigned long long)s->iteration, dti);
                } else {
                    (*fw_total)++;
                    m_fw_sign_us = dti;
                    printf("  [прошивка] ответил на challenge (#%d)  [замер: %lld мкс]\n",
                           *fw_total, dti);
                }
            } else if (e == LACERT_ERR_AUTH){
                printf("  [шлюз] ошибка/отзыв — сессия закрыта\n");
                close(s->sock); return -2;
            } else {
                printf("  [сеть] соединение потеряно, переподключение...\n");
                close(s->sock); return -1;
            }
        }
        time_t now = time(NULL);
        if (now - last_send >= 2) {
            char msg[192];
            // Те же поля замеров, что шлёт прошивка на плате, — чтобы можно было
            // сравнить x86 и ESP32 на одном и том же клиентском коде.
            snprintf(msg, sizeof(msg),
                     "temperature=2%d.5; seq=%d; handshake_us=%lld; "
                     "rotation_us=%lld; fw_sign_us=%lld",
                     (*seq)%10, *seq, m_handshake_us, m_rotation_us, m_fw_sign_us);
            if (lacert_send_data(s, msg) != LACERT_OK){
                printf("  [сеть] отправка не удалась, переподключение...\n");
                close(s->sock); return -1;
            }
            printf("отправлено: %s\n", msg);
            (*seq)++; last_send = now;
        }
    }
    close(s->sock);
    return 0;
}

int main(int argc, char **argv){
    const char *host = (argc>1)?argv[1]:"127.0.0.1";
    int http_port = (argc>2)?atoi(argv[2]):8080;
    int tcp_port  = (argc>3)?atoi(argv[3]):7700;
    const char *admin_token = getenv("LACERT_ADMIN_TOKEN");
    const char *device_id = getenv("LACERT_DEVICE_ID");
    if (!device_id) device_id = "linux-c-client-1";
    const char *keyfile = getenv("LACERT_KEYFILE");
    if (!keyfile) keyfile = "lacert_device.keys";

    int run_seconds = 60;
    { const char *rs = getenv("LACERT_RUN_SECONDS"); if (rs) run_seconds = atoi(rs); }

    lacert_session_t s; memset(&s, 0, sizeof(s));
    strncpy(s.device_id, device_id, sizeof(s.device_id)-1);
    s.id.sig_alg = LACERT_SIG_ECDSA_P256;

    int fresh_keys = 0;
    if (keystore_load(keyfile, &s.id)) {
        printf("Ключи загружены из %s (устройство уже существует)\n", keyfile);
    } else {
        printf("Ключей нет — генерирую новые и сохраняю в %s\n", keyfile);
        generate_keys(&s.id);
        keystore_save(keyfile, &s.id);
        fresh_keys = 1;
    }

    if (!compute_self_firmware_hash(argv[0], s.firmware_image_hash)) {
        const char *fw = "lacert-linux-fallback";
        SHA256((const uint8_t*)fw, strlen(fw), s.firmware_image_hash);
    }
    { char h[65]; to_hex(s.firmware_image_hash, 8, h);
      printf("Хеш прошивки (первые 8 байт): %s...\n", h); }

    if (register_device(host, http_port, admin_token, &s) < 0) {
        fprintf(stderr, "нет связи с HTTP шлюза (%s:%d)\n", host, http_port);
        return 1;
    }
    if (fresh_keys)
        printf("(первый запуск: firmware_hash зафиксирован при регистрации)\n");

    if (fetch_gateway_key(host, http_port, &s) < 0) {
        fprintf(stderr, "не удалось получить публичный ключ шлюза\n"); return 1;
    }
    printf("Публичный ML-KEM шлюза получен\n");

    printf("=== Работаю %d секунд, с переподключением при разрыве ===\n", run_seconds);
    time_t deadline = time(NULL) + run_seconds;
    int seq = 0, rot_total = 0, fw_total = 0, reconnects = 0;

    int handshake_failures = 0;
    while (time(NULL) < deadline) {
        int before = seq;
        int rc = run_session(&s, host, tcp_port, deadline, &seq, &rot_total, &fw_total);
        if (rc == -2) { printf("Устройство отозвано шлюзом — выходим.\n"); break; }
        if (rc == 0) break;

        if (seq == before) handshake_failures++; else handshake_failures = 0;

        reconnects++;
        printf("  ... переподключение через 2с (попытка %d)\n", reconnects);
        sleep(2);

        // Шлюз мог перезапуститься и сгенерировать новую пару ключей —
        // обновляем его публичный ключ, иначе рукопожатие заведомо провалится.
        while (fetch_gateway_key(host, http_port, &s) < 0) {
            printf("  [!] шлюз недоступен — жду 3с\n");
            sleep(3);
            if (time(NULL) >= deadline) break;
        }

        // Рукопожатие проваливается подряд, хотя HTTP отвечает? Вероятно, шлюз
        // больше не знает это устройство (работал без базы и перезапустился,
        // либо запись удалили). Пробуем зарегистрироваться заново —
        // регистрация идемпотентна.
        if (handshake_failures >= 3) {
            printf("  [!] рукопожатие не удаётся %d раз подряд — перерегистрация\n",
                   handshake_failures);
            if (register_device(host, http_port, admin_token, &s) == 0)
                handshake_failures = 0;
        }
    }

    printf("\n=== ИТОГ ===\n");
    printf("отправлено пакетов:           %d\n", seq);
    printf("ротаций применено:            %d\n", rot_total);
    printf("ответов на проверку прошивки: %d\n", fw_total);
    printf("переподключений:              %d\n", reconnects);
    printf("финальная итерация ключа:     %llu\n", (unsigned long long)s.iteration);
    return 0;
}

static int http_request(const char *host, int port, const char *req,
                        char *resp, size_t resp_max){
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr)!=1) return -1;
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return -1;
    if (connect(fd,(struct sockaddr*)&a,sizeof(a))<0){ close(fd); return -1; }
    size_t rl=strlen(req), sent=0;
    while(sent<rl){ int n=send(fd,req+sent,rl-sent,0); if(n<=0){close(fd);return -1;} sent+=n; }
    size_t got=0; int n;
    while(got<resp_max-1 && (n=recv(fd,resp+got,resp_max-1-got,0))>0) got+=n;
    resp[got]=0; close(fd);
    return (int)got;
}
