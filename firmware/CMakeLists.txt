# Верхнеуровневый CMakeLists проекта прошивки LACERT для ESP32.
# Один проект собирается под все три платы:
#   idf.py set-target esp32c6   (XIAO ESP32-C6, RISC-V)
#   idf.py set-target esp32s3   (XIAO ESP32-S3 и ESP32-S3-N8R2, Xtensa)
# затем: idf.py build flash monitor
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(lacert_firmware)
