// randombytes_esp.c — источник случайности для PQClean на ESP32.
// PQClean требует внешнюю PQCLEAN_randombytes (см. randombytes.h; возвращает int).
// Используем аппаратный ГСЧ ESP32 — он криптостойкий при активном радиомодуле.
#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"
#include "randombytes.h"

int PQCLEAN_randombytes(uint8_t *output, size_t n) {
    esp_fill_random(output, n);
    return 0;
}
