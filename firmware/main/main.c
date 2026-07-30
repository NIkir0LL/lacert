// main.c — прошивка LACERT для ESP32 (XIAO ESP32-C6, XIAO ESP32-S3, ESP32-S3-N8R2).
//
// Что делает при старте:
//   1. Поднимает WiFi (данные сети — в menuconfig / CONFIG_LACERT_*).
//   2. Загружает ключи устройства из NVS; при первом старте генерирует их
//      (ECDSA P-256 + ML-KEM-1024) и сохраняет — устройство остаётся «тем же»
//      после перезагрузки.
//   3. Считает SHA-256 своего образа прошивки (для проверки целостности).
//   4. Регистрируется на шлюзе через REST (идемпотентно) и забирает его
//      публичный ML-KEM-ключ.
//   5. Подключается по TCP, проводит рукопожатие и в цикле шлёт телеметрию,
//      отвечая на ротацию ключа и проверку прошивки. При разрыве —
//      переподключается.
//
// Логика протокола — в lacert_client.c (тот же код, что проверен на Linux).
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"   // esp_timer_get_time — замеры на самой плате
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_http_client.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "lacert_client.h"
#include "lacert_crypto.h"
#include "lacert_wire.h"

static const char *TAG = "lacert";

// ---------------------------------------------------------------------------
// Настройки стенда. Проще всего задать здесь; при желании вынести в menuconfig.
// ---------------------------------------------------------------------------
#define LACERT_WIFI_SSID      "Samsung"
#define LACERT_WIFI_PASS      "1234567890"
#define LACERT_GW_HOST        "192.168.1.10"   // IP шлюза в локальной сети
#define LACERT_GW_HTTP_PORT   8080
#define LACERT_GW_TCP_PORT    7700
#define LACERT_DEVICE_ID      "xiao-esp32-1"
#define LACERT_ADMIN_TOKEN    ""               // токен шлюза, если включён

#define TELEMETRY_PERIOD_MS   2000
#define RECONNECT_DELAY_MS    2000
// Пауза между попытками достучаться до шлюза, когда он недоступен
// (перезагрузка сервера, обрыв сети). Плата не сдаётся и ждёт его возвращения.
#define GATEWAY_RETRY_DELAY_MS 5000
// Сколько неудачных рукопожатий подряд считать признаком того, что шлюз забыл
// устройство (перезапустился без базы, либо запись удалили) — после этого
// пробуем зарегистрироваться заново.
#define HANDSHAKE_FAILURES_BEFORE_REREGISTER 3

// ---------------------------------------------------------------------------
// ЗАМЕРЫ НА ЖЕЛЕЗЕ. Все цифры в отчёте до сих пор снимались на сервере x86-64;
// эти счётчики измеряют то же самое прямо на плате и уходят вместе с
// телеметрией, поэтому попадают в базу и на графики дашборда — оттуда их можно
// брать для работы. Накладные расходы ничтожны: пара вызовов esp_timer.
// Чтобы отключить, поставьте 0.
// ---------------------------------------------------------------------------
#define LACERT_MEASURE 1

// ---------------------------------------------------------------------------
// МИКРОБЕНЧМАРК КРИПТОГРАФИИ. Прогоняет каждую операцию LACERT_BENCH_ITERS раз
// подряд и печатает среднее время — БЕЗ сети, поэтому цифры чистые и прямо
// сопоставимы с замерами на сервере (там мерилось так же, по операциям).
// Замеры handshake_us/rotation_us из телеметрии для этого не годятся: они
// включают обмен по WiFi, который добавляет десятки миллисекунд шума.
//
// Выполняется один раз при старте, до подключения к шлюзу. Для обычной работы
// можно выключить (0) — на протокол не влияет.
// ---------------------------------------------------------------------------
#define LACERT_BENCH        1
#define LACERT_BENCH_ITERS  20

#if LACERT_MEASURE
// Последние измеренные значения (мкс). 0 = ещё не измерено.
static int64_t s_handshake_us;   // полное рукопожатие Msg1 -> Msg2 -> Msg3
static int64_t s_rotation_us;    // обработка одной ротации ключа
static int64_t s_fw_sign_us;     // подпись ответа на проверку прошивки
#endif

// ---------------------------------------------------------------------------
// ИНДИКАЦИЯ СВЕТОДИОДОМ. Поддержаны два типа плат — выберите свой:
//
//   1 = простой одноцветный светодиод (XIAO ESP32-S3 / XIAO ESP32-C6)
//   2 = адресный RGB WS2812 (ESP32-S3-DevKitC-1 и подобные)
//
// Разница принципиальная: адресный RGB управляется импульсным протоколом
// (через RMT), обычным gpio_set_level его не зажечь.
// ---------------------------------------------------------------------------
#define LACERT_LED_MODE          1     // <-- 1 для XIAO, 2 для DevKitC-1 с RGB

// --- Режим 1: простой светодиод ---
// На XIAO светодиод ИНВЕРСНЫЙ: горит при НИЗКОМ уровне (частая ловушка).
#if CONFIG_IDF_TARGET_ESP32S3
  #define LACERT_LED_GPIO        21    // XIAO ESP32-S3 (жёлтый); бывает 48 на др. ревизиях
#elif CONFIG_IDF_TARGET_ESP32C6
  #define LACERT_LED_GPIO        15    // XIAO ESP32-C6
#else
  #define LACERT_LED_GPIO        -1
#endif
#define LACERT_LED_ACTIVE_LOW    1     // 0 — если светодиод горит при ВЫСОКОМ уровне

// --- Режим 2: адресный RGB (WS2812) ---
#define LACERT_RGB_GPIO          48    // ESP32-S3-DevKitC-1 (на ранних ревизиях 38)
#define LACERT_RGB_BRIGHTNESS    24    // 0..255; ярче 40 обычно слепит

#define LED_BLINK_MS             40

// ---------------------------------------------------------------------------
// Светодиод: индикация событий протокола, чтобы видеть работу платы без
// монитора.
//   рукопожатие  — 3 вспышки (RGB: зелёный)
//   передача     — 1 короткая  (RGB: синий)
//   ротация ключа— 2 вспышки  (RGB: фиолетовый)
//   ошибка/разрыв— 1 длинная  (RGB: красный)
// ---------------------------------------------------------------------------
typedef enum {
    LED_EV_LINK_UP,   // защищённый канал установлен
    LED_EV_DATA,      // отправлен пакет телеметрии
    LED_EV_ROTATION,  // применён новый ключ
    LED_EV_FIRMWARE,  // ответ на проверку целостности
    LED_EV_ERROR,     // разрыв/отказ
} led_event_t;

#if LACERT_LED_MODE == 2
// --------- Режим 2: адресный RGB WS2812 через RMT ---------
#include "driver/rmt_tx.h"

static rmt_channel_handle_t s_rmt;
static rmt_encoder_handle_t s_enc;

static void led_init(void) {
    rmt_tx_channel_config_t tx = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = LACERT_RGB_GPIO,
        .mem_block_symbols = 64,
        .resolution_hz = 10 * 1000 * 1000,  // 10 МГц -> такт 0,1 мкс
        .trans_queue_depth = 4,
    };
    if (rmt_new_tx_channel(&tx, &s_rmt) != ESP_OK) { s_rmt = NULL; return; }

    // Тайминги WS2812: "0" = 0,3 мкс высокий + 0,9 мкс низкий;
    //                  "1" = 0,9 мкс высокий + 0,3 мкс низкий.
    rmt_bytes_encoder_config_t enc = {
        .bit0 = { .level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9 },
        .bit1 = { .level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3 },
        .flags.msb_first = 1,
    };
    if (rmt_new_bytes_encoder(&enc, &s_enc) != ESP_OK) { s_rmt = NULL; return; }
    rmt_enable(s_rmt);
}

static void rgb_set(uint8_t r, uint8_t g, uint8_t b) {
    if (!s_rmt) return;
    uint8_t grb[3] = { g, r, b };   // WS2812 ждёт порядок G-R-B
    rmt_transmit_config_t cfg = { .loop_count = 0 };
    rmt_transmit(s_rmt, s_enc, grb, sizeof(grb), &cfg);
    rmt_tx_wait_all_done(s_rmt, 100);
}

static void rgb_flash(uint8_t r, uint8_t g, uint8_t b, int times, int on_ms) {
    for (int i = 0; i < times; i++) {
        rgb_set(r, g, b);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        rgb_set(0, 0, 0);
        if (i + 1 < times) vTaskDelay(pdMS_TO_TICKS(on_ms));
    }
}

static void led_event(led_event_t ev) {
    const uint8_t B = LACERT_RGB_BRIGHTNESS;
    switch (ev) {
        case LED_EV_LINK_UP:  rgb_flash(0, B, 0, 3, LED_BLINK_MS); break;      // зелёный
        case LED_EV_DATA:     rgb_flash(0, 0, B, 1, LED_BLINK_MS); break;      // синий
        case LED_EV_ROTATION: rgb_flash(B, 0, B, 2, LED_BLINK_MS); break;      // фиолетовый
        case LED_EV_FIRMWARE: rgb_flash(0, B, B, 1, LED_BLINK_MS); break;      // бирюзовый
        case LED_EV_ERROR:    rgb_flash(B, 0, 0, 1, 400); break;               // красный
    }
}

#else
// --------- Режим 1: простой одноцветный светодиод ---------
static void led_init(void) {
    if (LACERT_LED_GPIO < 0) return;
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << LACERT_LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    gpio_set_level(LACERT_LED_GPIO, LACERT_LED_ACTIVE_LOW ? 1 : 0);  // погашен
}

static inline void led_set(bool on) {
    if (LACERT_LED_GPIO < 0) return;
    int level = LACERT_LED_ACTIVE_LOW ? (on ? 0 : 1) : (on ? 1 : 0);
    gpio_set_level(LACERT_LED_GPIO, level);
}

static void led_flash(int times, int on_ms) {
    if (LACERT_LED_GPIO < 0) return;
    for (int i = 0; i < times; i++) {
        led_set(true);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        led_set(false);
        if (i + 1 < times) vTaskDelay(pdMS_TO_TICKS(on_ms));
    }
}

static void led_event(led_event_t ev) {
    switch (ev) {
        case LED_EV_LINK_UP:  led_flash(3, LED_BLINK_MS); break;
        case LED_EV_DATA:     led_flash(1, LED_BLINK_MS); break;
        case LED_EV_ROTATION: led_flash(2, LED_BLINK_MS); break;
        case LED_EV_FIRMWARE: led_flash(1, LED_BLINK_MS); break;
        case LED_EV_ERROR:    led_flash(1, 400); break;
    }
}
#endif

// ---------------------------------------------------------------------------
// WiFi
// ---------------------------------------------------------------------------
static EventGroupHandle_t s_wifi_events;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi отключился, переподключаюсь...");
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi подключён, IP: " IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wc = { 0 };
    strncpy((char *)wc.sta.ssid, LACERT_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
    strncpy((char *)wc.sta.password, LACERT_WIFI_PASS, sizeof(wc.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "жду подключения к WiFi «%s»...", LACERT_WIFI_SSID);
    xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
}

// ---------------------------------------------------------------------------
// Ключи устройства в NVS (моделирует efuse: генерируются один раз, живут вечно)
// ---------------------------------------------------------------------------
#define NVS_NS "lacert"

static bool keys_load(lacert_identity_t *id) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    bool ok = true;
    size_t n;
    n = 32;                       if (nvs_get_blob(h, "ec_priv", id->ecdsa_priv, &n) != ESP_OK || n != 32) ok = false;
    n = LACERT_ECDSA_PUB_SIZE;    if (ok && (nvs_get_blob(h, "ec_pub", id->ecdsa_pub, &n) != ESP_OK || n != LACERT_ECDSA_PUB_SIZE)) ok = false;
    n = sizeof(id->kem_priv);     if (ok && (nvs_get_blob(h, "kem_priv", id->kem_priv, &n) != ESP_OK)) ok = false;
    n = LACERT_KEM_PUBKEY_SIZE;   if (ok && (nvs_get_blob(h, "kem_pub", id->kem_pub, &n) != ESP_OK || n != LACERT_KEM_PUBKEY_SIZE)) ok = false;
    nvs_close(h);
    return ok;
}

static bool keys_save(const lacert_identity_t *id) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = true;
    if (nvs_set_blob(h, "ec_priv",  id->ecdsa_priv, 32) != ESP_OK) ok = false;
    if (nvs_set_blob(h, "ec_pub",   id->ecdsa_pub, LACERT_ECDSA_PUB_SIZE) != ESP_OK) ok = false;
    if (nvs_set_blob(h, "kem_priv", id->kem_priv, sizeof(id->kem_priv)) != ESP_OK) ok = false;
    if (nvs_set_blob(h, "kem_pub",  id->kem_pub, LACERT_KEM_PUBKEY_SIZE) != ESP_OK) ok = false;
    if (ok && nvs_commit(h) != ESP_OK) ok = false;
    nvs_close(h);
    return ok;
}

// ---------------------------------------------------------------------------
// Хеш собственной прошивки (SHA-256 работающего раздела)
// ---------------------------------------------------------------------------
static void firmware_hash(uint8_t out[LACERT_FW_HASH_SIZE]) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    if (run && esp_partition_get_sha256(run, out) == ESP_OK) return;
    // Запасной вариант (не должно случаться): хеш от идентификатора.
    lacert_sha256((const uint8_t *)LACERT_DEVICE_ID, strlen(LACERT_DEVICE_ID), out);
}

// ---------------------------------------------------------------------------
// HTTP: регистрация и получение публичного ключа шлюза
// ---------------------------------------------------------------------------
static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = h[b[i] >> 4]; out[2*i+1] = h[b[i] & 15]; }
    out[2*n] = 0;
}
static int from_hex(const char *h, uint8_t *out, int maxlen) {
    int n = 0;
    while (h[0] && h[1] && h[0] != '"' && n < maxlen) {
        int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        out[n++] = (hi << 4) | lo; h += 2;
    }
    return n;
}

// Буфер ответа HTTP. Флаг truncated поднимается, если ответ не поместился:
// без него данные молча отбрасывались, а вызывающий код разбирал обрезанный
// JSON и получал невнятную ошибку разбора вместо понятной причины.
typedef struct { char *buf; int len; int cap; bool truncated; } http_resp_t;

static esp_err_t http_evt(esp_http_client_event_t *evt) {
    http_resp_t *r = (http_resp_t *)evt->user_data;
    if (evt->event_id == HTTP_EVENT_ON_DATA && r && r->buf) {
        int n = evt->data_len;
        if (r->len + n < r->cap) {
            memcpy(r->buf + r->len, evt->data, n);
            r->len += n;
            r->buf[r->len] = 0;
        } else {
            r->truncated = true;
        }
    }
    return ESP_OK;
}

// Регистрация устройства (идемпотентно: повтор с теми же ключами — не ошибка).
static bool register_device(lacert_session_t *s) {
    // checksum = hex(BLAKE3(deviceID||idPub||kemPub||fwHash))[:8]
    uint8_t sum[32];
    const uint8_t *parts[4] = { (const uint8_t *)s->device_id, s->id.ecdsa_pub,
                                s->id.kem_pub, s->firmware_image_hash };
    const size_t lens[4] = { strlen(s->device_id), LACERT_ECDSA_PUB_SIZE,
                             LACERT_KEM_PUBKEY_SIZE, LACERT_FW_HASH_SIZE };
    lacert_blake3(parts, lens, 4, sum);
    char checksum[9]; to_hex(sum, 4, checksum);

    // hex-представления ключей
    char *id_hex  = malloc(2*LACERT_ECDSA_PUB_SIZE + 1);
    char *kem_hex = malloc(2*LACERT_KEM_PUBKEY_SIZE + 1);
    char fw_hex[2*LACERT_FW_HASH_SIZE + 1];
    if (!id_hex || !kem_hex) { free(id_hex); free(kem_hex); return false; }
    to_hex(s->id.ecdsa_pub, LACERT_ECDSA_PUB_SIZE, id_hex);
    to_hex(s->id.kem_pub, LACERT_KEM_PUBKEY_SIZE, kem_hex);
    to_hex(s->firmware_image_hash, LACERT_FW_HASH_SIZE, fw_hex);

    int body_cap = 2*LACERT_KEM_PUBKEY_SIZE + 512;
    char *body = malloc(body_cap);
    if (!body) { free(id_hex); free(kem_hex); return false; }
    snprintf(body, body_cap,
        "{\"device_id\":\"%s\",\"identity_pub_hex\":\"%s\","
        "\"kem_pub_hex\":\"%s\",\"firmware_hash_hex\":\"%s\","
        "\"checksum\":\"%s\",\"sig_algorithm\":\"ecdsa-p256\"}",
        s->device_id, id_hex, kem_hex, fw_hex, checksum);

    char url[128];
    snprintf(url, sizeof(url), "http://%s:%d/api/v1/devices",
             LACERT_GW_HOST, LACERT_GW_HTTP_PORT);

    char resp[256] = {0};
    http_resp_t r = { .buf = resp, .len = 0, .cap = sizeof(resp), .truncated = false };
    esp_http_client_config_t cfg = {
        .url = url, .method = HTTP_METHOD_POST,
        .event_handler = http_evt, .user_data = &r, .timeout_ms = 8000,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    esp_http_client_set_header(c, "Content-Type", "application/json");
    if (strlen(LACERT_ADMIN_TOKEN) > 0) {
        char auth[160];
        snprintf(auth, sizeof(auth), "Bearer %s", LACERT_ADMIN_TOKEN);
        esp_http_client_set_header(c, "Authorization", auth);
    }
    esp_http_client_set_post_field(c, body, strlen(body));

    bool ok = false;
    if (esp_http_client_perform(c) == ESP_OK) {
        int code = esp_http_client_get_status_code(c);
        if (code == 201) { ESP_LOGI(TAG, "регистрация: новое устройство (201)"); ok = true; }
        else if (code == 400 || code == 409) {
            ESP_LOGI(TAG, "регистрация: устройство уже известно шлюзу (%d) — это норма", code);
            ok = true;
        } else {
            ESP_LOGE(TAG, "регистрация: код %d, ответ: %s", code, resp);
        }
    } else {
        ESP_LOGE(TAG, "регистрация: не удалось обратиться к шлюзу");
    }
    esp_http_client_cleanup(c);
    free(id_hex); free(kem_hex); free(body);
    return ok;
}

// Получить публичный ML-KEM-ключ шлюза.
static bool fetch_gateway_key(lacert_session_t *s) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%d/api/v1/gateway",
             LACERT_GW_HOST, LACERT_GW_HTTP_PORT);

    int cap = 2*LACERT_KEM_PUBKEY_SIZE + 512;
    char *resp = malloc(cap);
    if (!resp) return false;
    resp[0] = 0;
    http_resp_t r = { .buf = resp, .len = 0, .cap = cap, .truncated = false };

    esp_http_client_config_t cfg = {
        .url = url, .method = HTTP_METHOD_GET,
        .event_handler = http_evt, .user_data = &r, .timeout_ms = 8000,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    bool ok = false;
    // Запрос выполняем первым: флаг truncated поднимается обработчиком событий
    // во время передачи, до неё он всегда сброшен.
    esp_err_t perr = esp_http_client_perform(c);
    int status = esp_http_client_get_status_code(c);
    if (r.truncated) {
        // Обрезанный ответ разбирать бессмысленно: ключ в нём заведомо неполный.
        ESP_LOGW(TAG, "ответ шлюза не поместился в буфер (%d байт), разбор пропущен", cap);
    } else if (perr == ESP_OK && status == 200) {
        char *kp = strstr(resp, "kem_pub_hex");
        if (kp && (kp = strchr(kp, ':')) && (kp = strchr(kp, '"'))) {
            kp++;
            if (from_hex(kp, s->gw_kem_pub, LACERT_KEM_PUBKEY_SIZE) == LACERT_KEM_PUBKEY_SIZE) {
                ESP_LOGI(TAG, "публичный ML-KEM шлюза получен");
                ok = true;
            }
        }
    }
    if (!ok) ESP_LOGE(TAG, "не удалось получить ключ шлюза");
    esp_http_client_cleanup(c);
    free(resp);
    return ok;
}

// ---------------------------------------------------------------------------
// TCP-соединение со шлюзом
// ---------------------------------------------------------------------------
static int tcp_connect(void) {
    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port = htons(LACERT_GW_TCP_PORT);
    if (inet_pton(AF_INET, LACERT_GW_HOST, &a.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

// ---------------------------------------------------------------------------
// Одна сессия: рукопожатие + цикл (телеметрия / ротация / проверка прошивки)
// ---------------------------------------------------------------------------
static void run_session(lacert_session_t *s, int *seq) {
    s->sock = tcp_connect();
    if (s->sock < 0) {
        ESP_LOGW(TAG, "нет TCP-соединения со шлюзом");
        led_event(LED_EV_ERROR);
        return;
    }

    s->has_session = 0;
#if LACERT_MEASURE
    int64_t t0 = esp_timer_get_time();
#endif
    if (lacert_do_handshake(s) != LACERT_OK) {
        // Сюда же попадаем, если устройство отозвано на шлюзе: отзыв закрывает
        // сессию без отдельного кадра ошибки, и дальше шлюз просто не пускает
        // устройство в рукопожатие. Показываем красный — «канал не установлен».
        ESP_LOGE(TAG, "рукопожатие не удалось (отозвано на шлюзе? шлюз перезапущен?)");
        led_event(LED_EV_ERROR);
        close(s->sock);
        return;
    }
#if LACERT_MEASURE
    s_handshake_us = esp_timer_get_time() - t0;
    ESP_LOGI(TAG, "[замер] рукопожатие: %lld мкс (%.1f мс)",
             (long long)s_handshake_us, s_handshake_us / 1000.0);
#endif
    ESP_LOGI(TAG, "=== защищённый канал установлен ===");
    led_event(LED_EV_LINK_UP);

    TickType_t last_send = 0;
    while (1) {
        // Ждём входящий кадр до 1 секунды (ротация / проверка прошивки).
        fd_set rfds; FD_ZERO(&rfds); FD_SET(s->sock, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int r = select(s->sock + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            // Ошибка select (сокет сломался, а не просто «нет данных») —
            // прекращаем сессию, вызывающий переподключится.
            ESP_LOGW(TAG, "select() вернул ошибку — разрыв соединения");
            break;
        }

        if (r > 0 && FD_ISSET(s->sock, &rfds)) {
            uint64_t iter_before = s->iteration;
#if LACERT_MEASURE
            int64_t ti = esp_timer_get_time();
#endif
            lacert_err_t e = lacert_handle_incoming(s);
            if (e == LACERT_OK) {
#if LACERT_MEASURE
                int64_t dt = esp_timer_get_time() - ti;
#endif
                if (s->iteration > iter_before) {
#if LACERT_MEASURE
                    s_rotation_us = dt;
                    ESP_LOGI(TAG, "[замер] ротация ключа: %lld мкс", (long long)dt);
#endif
                    ESP_LOGI(TAG, "[ротация] новый ключ, итерация=%llu",
                             (unsigned long long)s->iteration);
                    led_event(LED_EV_ROTATION);
                } else {
#if LACERT_MEASURE
                    s_fw_sign_us = dt;
                    ESP_LOGI(TAG, "[замер] ответ на проверку прошивки: %lld мкс", (long long)dt);
#endif
                    ESP_LOGI(TAG, "[прошивка] ответил на проверку целостности");
                    led_event(LED_EV_FIRMWARE);
                }
            } else if (e == LACERT_ERR_AUTH) {
                ESP_LOGE(TAG, "шлюз отклонил устройство (отзыв?) — закрываю сессию");
                led_event(LED_EV_ERROR);
                break;
            } else {
                ESP_LOGW(TAG, "соединение потеряно (код %d)", e);
                led_event(LED_EV_ERROR);
                break;
            }
        }

        // Телеметрия по таймеру.
        TickType_t now = xTaskGetTickCount();
        if ((now - last_send) * portTICK_PERIOD_MS >= TELEMETRY_PERIOD_MS) {
            char msg[192];
#if LACERT_MEASURE
            // Вместе с показаниями датчика шлём замеры, снятые НА ПЛАТЕ:
            // свободная куча, минимум кучи за всё время работы, время
            // рукопожатия/ротации/подписи прошивки. Шлюз разбирает пары
            // ключ=значение, поэтому всё это автоматически попадает в базу и
            // на графики дашборда — удобно для отчёта и для контроля утечек.
            snprintf(msg, sizeof(msg),
                     "temperature=2%d.5; seq=%d; heap_free=%lu; heap_min=%lu; "
                     "handshake_us=%lld; rotation_us=%lld; fw_sign_us=%lld",
                     (*seq) % 10, *seq,
                     (unsigned long)esp_get_free_heap_size(),
                     (unsigned long)esp_get_minimum_free_heap_size(),
                     (long long)s_handshake_us,
                     (long long)s_rotation_us,
                     (long long)s_fw_sign_us);
#else
            // Здесь можно подставить реальные показания датчика.
            snprintf(msg, sizeof(msg), "temperature=2%d.5; seq=%d", (*seq) % 10, *seq);
#endif
            if (lacert_send_data(s, msg) != LACERT_OK) {
                ESP_LOGW(TAG, "не удалось отправить телеметрию — разрыв");
                break;
            }
            ESP_LOGI(TAG, "отправлено: %s", msg);
            led_event(LED_EV_DATA);
            (*seq)++;
            last_send = now;
        }
    }
    close(s->sock);
    s->has_session = 0;
}

#if LACERT_BENCH
// ---------------------------------------------------------------------------
// Микробенчмарк: чистое время криптоопераций на этом кристалле.
// ---------------------------------------------------------------------------
#include "api.h"   // PQClean ML-KEM-1024: нужен encapsulate для замера

static void bench_report(const char *name, int64_t total_us, int iters) {
    double avg = (double)total_us / iters;
    if (avg >= 1000.0)
        ESP_LOGI(TAG, "  %-28s %8.2f мс   (%d прогонов)", name, avg / 1000.0, iters);
    else
        ESP_LOGI(TAG, "  %-28s %8.1f мкс  (%d прогонов)", name, avg, iters);
}

// Два макроса — под разные по стоимости операции.
//
// BENCH_SLOW — для тяжёлых операций (ECDSA, ML-KEM: единицы и сотни мс).
// Замеряем каждую итерацию отдельно, а МЕЖДУ итерациями отдаём управление
// планировщику: иначе задача держит ядро дольше таймаута сторожевого таймера
// (ECDSA sign на S3 — 173 мс, 20 прогонов подряд = 3,5 с) и срабатывает
// task_wdt. Пауза стоит между замерами и в результат не входит. Накладные
// расходы на два вызова таймера (единицы мкс) на фоне десятков миллисекунд
// пренебрежимо малы.
#define BENCH_SLOW(name, iters, stmt)                     \
    do {                                                  \
        int64_t _total = 0;                               \
        for (int _i = 0; _i < (iters); _i++) {            \
            int64_t _t = esp_timer_get_time();            \
            stmt;                                         \
            _total += esp_timer_get_time() - _t;          \
            vTaskDelay(1);   /* не входит в замер */      \
        }                                                 \
        bench_report((name), _total, (iters));            \
    } while (0)

// BENCH_FAST — для лёгких операций (BLAKE3, SHA-256, ChaCha20: десятки мкс).
// Здесь замер по итерациям исказил бы результат: два вызова esp_timer_get_time()
// стоят несколько микросекунд, а сама операция — всего десятки. Поэтому меряем
// цикл целиком (один замер на все прогоны) и берём больше итераций. Сторожевой
// таймер не мешает: весь цикл укладывается в единицы миллисекунд.
#define BENCH_FAST(name, iters, stmt)                     \
    do {                                                  \
        int64_t _t = esp_timer_get_time();                \
        for (int _i = 0; _i < (iters); _i++) { stmt; }    \
        bench_report((name), esp_timer_get_time() - _t, (iters)); \
        vTaskDelay(1);                                    \
    } while (0)

static void run_benchmarks(void) {
    const int N = LACERT_BENCH_ITERS;

    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "МИКРОБЕНЧМАРК КРИПТОГРАФИИ (без сети)");
#if CONFIG_IDF_TARGET_ESP32C6
    ESP_LOGI(TAG, "плата: ESP32-C6 (RISC-V, 160 МГц)");
#elif CONFIG_IDF_TARGET_ESP32S3
    ESP_LOGI(TAG, "плата: ESP32-S3 (Xtensa, 240 МГц)");
#endif
    ESP_LOGI(TAG, "свободная куча до замеров: %lu байт",
             (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "--------------------------------------------------");

    // Буферы в куче: ключи ML-KEM большие, на стеке им тесно.
    uint8_t *pk = malloc(LACERT_KEM_PUBKEY_SIZE);
    uint8_t *sk = malloc(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    uint8_t *ct = malloc(LACERT_KEM_CIPHERTEXT_SIZE);
    if (!pk || !sk || !ct) {
        ESP_LOGE(TAG, "не хватило памяти на буферы бенчмарка");
        free(pk); free(sk); free(ct);
        return;
    }
    uint8_t ss[LACERT_KEM_SHARED_SIZE];
    uint8_t priv[32], pub[LACERT_ECDSA_PUB_SIZE];
    uint8_t msg[96], hash[32], sig[LACERT_MAX_SIG_SIZE];
    size_t sig_len = 0;
    lacert_random(msg, sizeof(msg));

    // Генерация ключей дороже прочего — прогонов меньше.
    int keygen_n = (N / 4) > 0 ? (N / 4) : 1;

    BENCH_SLOW("ECDSA P-256 keypair", keygen_n, lacert_ecdsa_keypair(priv, pub));
    BENCH_SLOW("ECDSA P-256 sign", N,
             lacert_ecdsa_sign(priv, msg, sizeof(msg), sig, &sig_len));
    ESP_LOGI(TAG, "  (размер подписи: %u байт)", (unsigned)sig_len);

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

    ESP_LOGI(TAG, "--------------------------------------------------");
    ESP_LOGI(TAG, "свободная куча после замеров: %lu байт",
             (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "==================================================");

    free(pk); free(sk); free(ct);
}
#endif

// ---------------------------------------------------------------------------
void app_main(void) {
    // NVS (для ключей и WiFi)
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    led_init();

    wifi_init_sta();

    // Сессия устройства
    static lacert_session_t s;   // static: структура большая (ключи ML-KEM)
    memset(&s, 0, sizeof(s));
    strncpy(s.device_id, LACERT_DEVICE_ID, sizeof(s.device_id) - 1);
    s.id.sig_alg = LACERT_SIG_ECDSA_P256;

    // Ключи: из NVS или генерируем при первом старте.
    if (keys_load(&s.id)) {
        ESP_LOGI(TAG, "ключи загружены из NVS (устройство уже инициализировано)");
    } else {
        ESP_LOGI(TAG, "первый старт: генерирую ключи (ECDSA + ML-KEM-1024)...");
        if (lacert_ecdsa_keypair(s.id.ecdsa_priv, s.id.ecdsa_pub) != LACERT_OK) {
            ESP_LOGE(TAG, "не удалось сгенерировать ключ ECDSA"); return;
        }
        if (lacert_kem_keypair(s.id.kem_pub, s.id.kem_priv) != LACERT_OK) {
            ESP_LOGE(TAG, "не удалось сгенерировать ключ ML-KEM"); return;
        }
        if (!keys_save(&s.id)) { ESP_LOGE(TAG, "не удалось сохранить ключи в NVS"); return; }
        ESP_LOGI(TAG, "ключи сгенерированы и сохранены в NVS");
    }

    // Хеш прошивки — для проверки целостности шлюзом.
    firmware_hash(s.firmware_image_hash);
    ESP_LOGI(TAG, "хеш прошивки посчитан (SHA-256 раздела)");

    ESP_LOGI(TAG, "свободная куча: %lu байт", (unsigned long)esp_get_free_heap_size());

#if LACERT_BENCH
    run_benchmarks();
#endif

    // Регистрация и получение ключа шлюза. ВАЖНО: не сдаёмся, если шлюз сейчас
    // недоступен. Реальный сценарий — общее отключение питания: плата
    // поднимается за секунды, а сервер со шлюзом грузится минуту. Раньше здесь
    // был выход из app_main, и устройство оставалось «мёртвым» до ручной
    // перезагрузки. Теперь повторяем попытки, пока шлюз не ответит.
    while (!register_device(&s)) {
        ESP_LOGW(TAG, "шлюз недоступен (регистрация) — повтор через %d мс",
                 GATEWAY_RETRY_DELAY_MS);
        led_event(LED_EV_ERROR);
        vTaskDelay(pdMS_TO_TICKS(GATEWAY_RETRY_DELAY_MS));
    }
    while (!fetch_gateway_key(&s)) {
        ESP_LOGW(TAG, "шлюз недоступен (ключ) — повтор через %d мс",
                 GATEWAY_RETRY_DELAY_MS);
        led_event(LED_EV_ERROR);
        vTaskDelay(pdMS_TO_TICKS(GATEWAY_RETRY_DELAY_MS));
    }

    // Основной цикл: сессия, при разрыве — переподключение.
    int seq = 0;
    int handshake_failures = 0;
    while (1) {
        int before = seq;
        run_session(&s, &seq);
        // Если сессия не поднялась (ни одного пакета не ушло) — считаем неудачей.
        if (seq == before && !s.has_session) handshake_failures++;
        else handshake_failures = 0;

        ESP_LOGW(TAG, "переподключение через %d мс...", RECONNECT_DELAY_MS);
        vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));

        // Обновляем публичный ключ шлюза: при перезапуске шлюз генерирует новую
        // пару, и рукопожатие со старым ключом заведомо провалится. Если шлюз
        // ещё не поднялся — ждём его здесь, а не бьёмся в TCP впустую.
        while (!fetch_gateway_key(&s)) {
            ESP_LOGW(TAG, "шлюз недоступен — жду %d мс", GATEWAY_RETRY_DELAY_MS);
            vTaskDelay(pdMS_TO_TICKS(GATEWAY_RETRY_DELAY_MS));
        }

        // Рукопожатие не удаётся подряд несколько раз, хотя шлюз отвечает по
        // HTTP? Скорее всего, он больше не знает это устройство: работал без
        // базы и перезапустился, либо запись удалили. Пробуем зарегистрироваться
        // заново — операция идемпотентна (если устройство известно, шлюз просто
        // ответит 400/409, и мы ничего не сломаем).
        if (handshake_failures >= HANDSHAKE_FAILURES_BEFORE_REREGISTER) {
            ESP_LOGW(TAG, "рукопожатие не удаётся %d раз подряд — пробую перерегистрироваться",
                     handshake_failures);
            if (register_device(&s)) handshake_failures = 0;
        }
    }
}
