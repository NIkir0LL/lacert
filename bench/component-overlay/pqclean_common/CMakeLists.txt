# Общие файлы PQClean: SHA-3 (fips202), SHA-2 (sha2) и источник случайности.
# Вынесены в отдельный компонент, потому что их используют сразу несколько
# алгоритмов: ML-KEM и ML-DSA опираются на SHA-3, SLH-DSA в варианте sha2 — на
# SHA-2. Если положить эти файлы в каждый алгоритм, линковка упадёт на
# повторяющихся символах.
idf_component_register(
    SRCS "fips202.c" "sha2.c" "randombytes_esp.c"
    INCLUDE_DIRS "."
    REQUIRES esp_hw_support
)
