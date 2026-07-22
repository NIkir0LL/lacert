// esp_random.h — заглушка ESP32-API генератора случайных чисел для сборки
// на хосте (x86-64).
//
// На плате esp_random() обращается к аппаратному генератору. При сборке
// bench_host на обычном компьютере такого источника нет, поэтому здесь
// используется криптографический генератор операционной системы: getrandom(2)
// в Linux, а при его отсутствии — /dev/urandom.
//
// Источник должен быть криптографически стойким: эти байты идут в генерацию
// ключей ML-KEM. Заменять их на rand() нельзя — замеры от этого не изменятся,
// но получившиеся ключи будут предсказуемыми, и файл легко утечёт в реальную
// сборку.
//
// Файл нужен ТОЛЬКО для сборки на хосте. В прошивке используется настоящий
// esp_random.h из состава ESP-IDF.

#ifndef LACERT_HOST_ESP_RANDOM_H
#define LACERT_HOST_ESP_RANDOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(__linux__)
#  include <sys/random.h>
#endif

static inline void esp_fill_random(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;

#if defined(__linux__)
    while (got < len) {
        ssize_t n = getrandom(p + got, len - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
#endif

    if (got < len) {                      // запасной путь
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) {
            got += fread(p + got, 1, len - got, f);
            fclose(f);
        }
    }

    if (got < len) {                      // источник недоступен — не молчим
        fprintf(stderr,
                "esp_random (host stub): не удалось получить %zu случайных байт\n",
                len - got);
        abort();
    }
}

static inline uint32_t esp_random(void) {
    uint32_t v;
    esp_fill_random(&v, sizeof(v));
    return v;
}

#endif // LACERT_HOST_ESP_RANDOM_H
