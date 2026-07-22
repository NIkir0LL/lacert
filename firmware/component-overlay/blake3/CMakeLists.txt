# BLAKE3 для ESP32 (портируемая реализация: SIMD-версии только для x86,
# на Xtensa/RISC-V dispatch автоматически берёт blake3_portable).
idf_component_register(
    SRCS "blake3.c" "blake3_dispatch.c" "blake3_portable.c"
    INCLUDE_DIRS "."
)
# Отключаем x86-специфичные пути явно.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
)
