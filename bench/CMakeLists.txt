# Прошивка для замеров криптографии на кристалле.
# Собирается отдельно от боевой прошивки: здесь нет ни сети, ни протокола.
#
#   ./scripts/fetch-components.sh      (один раз — скачать PQClean и BLAKE3)
#   idf.py set-target esp32c6          (или esp32s3)
#   idf.py build flash monitor
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(lacert_bench)
