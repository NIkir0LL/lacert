// Личные настройки платы: сеть, адрес шлюза, идентификатор, токен.
//
// Скопируйте этот файл в lacert_config.h рядом и заполните. Копия в
// репозиторий не попадает: она в .gitignore, а сборщик выпусков её не берёт.
// Без неё сборка остановится с понятной ошибкой, а не соберёт прошивку с
// пустой сетью.
//
// У каждой платы должен быть свой LACERT_DEVICE_ID, иначе они будут
// вытеснять друг друга на шлюзе.
#pragma once

#define LACERT_WIFI_SSID      "имя_вашей_сети"
#define LACERT_WIFI_PASS      "пароль"
#define LACERT_GW_HOST        "192.168.1.10"   // IP шлюза в локальной сети
#define LACERT_GW_HTTP_PORT   8080
#define LACERT_GW_TCP_PORT    7700
#define LACERT_DEVICE_ID      "xiao-esp32-1"   // уникальный на каждую плату
#define LACERT_ADMIN_TOKEN    ""               // токен шлюза, если включён

// Индикация: 1 — простой светодиод (XIAO ESP32-S3 / XIAO ESP32-C6),
// 2 — адресный RGB WS2812 (ESP32-S3-DevKitC-1 и подобные).
#define LACERT_LED_MODE       1
