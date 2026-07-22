# Компонент main: клиент протокола LACERT.
# lacert_wire.c и lacert_client.c — платформо-независимые (те же файлы
# проверены на Linux против Go-шлюза, см. ../linux-debug).
idf_component_register(
    SRCS
        "main.c"
        "lacert_wire.c"
        "lacert_crypto.c"
        "lacert_client.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_netif
        esp_event
        esp_http_client
        app_update          # esp_ota_get_running_partition
        spi_flash           # esp_partition_get_sha256
        nvs_flash
        esp_driver_gpio     # GPIO — простой светодиод (XIAO)
        esp_driver_rmt      # RMT — адресный RGB WS2812 (DevKitC-1)
        mbedtls
        esp_hw_support      # esp_random
        esp_timer           # esp_timer_get_time — замеры на плате (LACERT_MEASURE)
        lwip
        ml_kem
        blake3
)
