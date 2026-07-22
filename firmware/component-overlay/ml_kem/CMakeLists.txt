# ML-KEM-1024 (Kyber) из PQClean + SHA-3 (fips202) + источник случайности ESP32.
idf_component_register(
    SRCS
        "cbd.c" "indcpa.c" "kem.c" "ntt.c" "poly.c" "polyvec.c"
        "reduce.c" "symmetric-shake.c" "verify.c" "fips202.c"
        "randombytes_esp.c"
    INCLUDE_DIRS "."
    REQUIRES esp_hw_support
)
