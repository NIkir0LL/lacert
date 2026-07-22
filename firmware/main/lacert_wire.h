// lacert_wire.h — кодирование/декодирование кадров и полей протокола.
// Соответствует internal/wire шлюза (см. docs/ru/PROTOCOL_SPEC.md, раздел 1).
#pragma once
#include "lacert_proto.h"

// --- Кадр: [4 байта BE длина][1 байт тип][payload] ---

// Записать кадр в сокет sock. payload может быть NULL при len==0.
lacert_err_t lacert_write_frame(int sock, uint8_t msg_type,
                                const uint8_t *payload, size_t len);

// Прочитать один кадр целиком. Выделяет буфер под payload (вызывающий
// освобождает через free). Возвращает тип в *msg_type, payload/len.
lacert_err_t lacert_read_frame(int sock, uint8_t *msg_type,
                               uint8_t **payload, size_t *len);

// --- Кадрирование полей внутри payload: [uint16 BE len][данные] ---

// Дописать поле переменной длины в buf по смещению *off. Возвращает новое off.
// buf должен быть достаточного размера (проверка на стороне вызывающего).
size_t lacert_put_framed(uint8_t *buf, size_t off,
                         const uint8_t *data, size_t len);

// Прочитать поле переменной длины из payload по смещению *off.
// Возвращает указатель на данные внутри payload (без копирования) и их длину.
// Продвигает *off за поле. Возвращает LACERT_ERR_DECODE при нехватке байт.
lacert_err_t lacert_take_framed(const uint8_t *payload, size_t payload_len,
                                size_t *off, const uint8_t **data, size_t *len);

// --- Помощники BE ---
void lacert_put_u16(uint8_t *b, uint16_t v);   // 2 байта BE
void lacert_put_u32(uint8_t *b, uint32_t v);   // 4 байта BE
void lacert_put_u64(uint8_t *b, uint64_t v);   // 8 байт BE
uint16_t lacert_get_u16(const uint8_t *b);
uint32_t lacert_get_u32(const uint8_t *b);
uint64_t lacert_get_u64(const uint8_t *b);
