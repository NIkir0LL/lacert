# Сравнение LACERT с DTLS 1.2

Два стенда, измеряющие стоимость установления сессии на одной платформе и с
одной сборкой mbedTLS. Методика и результаты — в
[`docs/ru/MEASUREMENTS.md`](../../docs/ru/MEASUREMENTS.md), раздел 3.5.

| Файл | Что делает |
|------|------------|
| `dtls_bench.c` | DTLS 1.2 в трёх режимах: PSK, ECDHE-PSK, ECDHE-ECDSA со взаимной проверкой |
| `lacert_hs_bench.c` | криптографический путь рукопожатия LACERT на C |

Оба используют транспорт в памяти: клиент и сервер работают в одном процессе,
сеть исключена.

## Подготовка

Нужен mbedTLS 3.6 с включёнными `MBEDTLS_SSL_PROTO_DTLS`, `MBEDTLS_SSL_SRV_C`,
`MBEDTLS_SSL_CLI_C`, `MBEDTLS_CHACHAPOLY_C` и наборами PSK и ECDHE-ECDSA.

Сертификаты для режима ECDHE-ECDSA:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out srv.key
openssl req -new -x509 -key srv.key -out srv.crt -days 365 \
  -subj "/CN=lacert-dtls-bench" -sha256
openssl ecparam -name prime256v1 -genkey -noout -out cli.key
openssl req -new -x509 -key cli.key -out cli.crt -days 365 \
  -subj "/CN=lacert-device-1" -sha256
```

## Сборка и запуск

Команды приведены в комментариях внутри каждого файла. Аргумент — число
прогонов, по умолчанию 20.

```bash
./dtls_bench 20
./lacert_hs_bench 20
```

## Замечание о сопоставимости

Рукопожатие LACERT измерено и в реализации шлюза на Go (122,8 мкс), но
сравнивать это значение с DTLS нельзя: в Go подпись P-256 идёт через
ассемблерную реализацию и выполняется в 14 раз быстрее, чем в mbedTLS. Поэтому
для сравнения написан отдельный стенд на C.
