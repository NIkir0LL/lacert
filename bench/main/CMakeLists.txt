# Компонент замеров. Зависит от всех криптографических компонентов сразу:
# смысл прошивки в том, чтобы сравнить их между собой в одном прогоне.
idf_component_register(
    SRCS "bench_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        mbedtls
        esp_hw_support      # esp_fill_random
        esp_timer           # esp_timer_get_time
        blake3
        pqclean_common
        mlkem512 mlkem768 mlkem1024
        mldsa44 mldsa65 mldsa87
        slhdsa128s
)
