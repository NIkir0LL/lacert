// lacert_wire.c — реализация кодирования кадров и полей.
// Этот модуль НЕ зависит от криптографии, поэтому реализован полностью
// (в отличие от lacert_crypto.c, где заготовки под внешние библиотеки).
#include "lacert_wire.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// --- BE-помощники ---
void lacert_put_u16(uint8_t *b, uint16_t v) { b[0]=v>>8; b[1]=v; }
void lacert_put_u32(uint8_t *b, uint32_t v) { b[0]=v>>24; b[1]=v>>16; b[2]=v>>8; b[3]=v; }
void lacert_put_u64(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8*i));
}
uint16_t lacert_get_u16(const uint8_t *b){ return ((uint16_t)b[0]<<8)|b[1]; }
uint32_t lacert_get_u32(const uint8_t *b){
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}
uint64_t lacert_get_u64(const uint8_t *b){
    uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|b[i]; return v;
}

// --- Надёжная запись/чтение всего буфера в сокет ---
static lacert_err_t write_all(int sock, const uint8_t *buf, size_t len){
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return LACERT_ERR_IO;
        sent += (size_t)n;
    }
    return LACERT_OK;
}
static lacert_err_t read_all(int sock, uint8_t *buf, size_t len){
    size_t got = 0;
    while (got < len) {
        int n = recv(sock, buf + got, len - got, 0);
        if (n <= 0) return LACERT_ERR_IO;   // 0 = соединение закрыто
        got += (size_t)n;
    }
    return LACERT_OK;
}

lacert_err_t lacert_write_frame(int sock, uint8_t msg_type,
                                const uint8_t *payload, size_t len){
    if (len > LACERT_MAX_FRAME_SIZE) return LACERT_ERR_DECODE;
    uint8_t header[5];
    lacert_put_u32(header, (uint32_t)len);
    header[4] = msg_type;
    lacert_err_t e = write_all(sock, header, 5);
    if (e != LACERT_OK) return e;
    if (len > 0) return write_all(sock, payload, len);
    return LACERT_OK;
}

lacert_err_t lacert_read_frame(int sock, uint8_t *msg_type,
                               uint8_t **payload, size_t *len){
    uint8_t header[5];
    lacert_err_t e = read_all(sock, header, 5);
    if (e != LACERT_OK) return e;
    uint32_t plen = lacert_get_u32(header);
    if (plen > LACERT_MAX_FRAME_SIZE) return LACERT_ERR_DECODE;
    *msg_type = header[4];
    *len = plen;
    if (plen == 0) { *payload = NULL; return LACERT_OK; }
    *payload = malloc(plen);
    if (!*payload) return LACERT_ERR_IO;
    e = read_all(sock, *payload, plen);
    if (e != LACERT_OK) { free(*payload); *payload = NULL; return e; }
    return LACERT_OK;
}

size_t lacert_put_framed(uint8_t *buf, size_t off,
                         const uint8_t *data, size_t len){
    lacert_put_u16(buf + off, (uint16_t)len);
    off += 2;
    if (len > 0) { memcpy(buf + off, data, len); off += len; }
    return off;
}

lacert_err_t lacert_take_framed(const uint8_t *payload, size_t payload_len,
                                size_t *off, const uint8_t **data, size_t *len){
    if (*off + 2 > payload_len) return LACERT_ERR_DECODE;
    uint16_t n = lacert_get_u16(payload + *off);
    *off += 2;
    if (*off + n > payload_len) return LACERT_ERR_DECODE;
    *data = payload + *off;
    *len = n;
    *off += n;
    return LACERT_OK;
}
