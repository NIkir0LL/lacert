# BLAKE3, переносимая реализация. Файлы под SIMD (x86 и ARM) не скачиваются:
# на ESP32 они бесполезны и не собираются.
idf_component_register(
    SRCS "blake3.c" "blake3_dispatch.c" "blake3_portable.c"
    INCLUDE_DIRS "."
)
