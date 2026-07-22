// lacert_crypto_linux.c — реализация криптомодуля для ЛИНУКС-ОТЛАДКИ.
// Использует OpenSSL (вместо mbedTLS), проверенные PQClean (ML-KEM) и BLAKE3.
// На ESP32 используется lacert_crypto.c (mbedTLS) — этот файл только для
// проверки протокола на большом компьютере.
#include "lacert_crypto.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "blake3.h"
#include "api.h"   // PQClean ML-KEM-1024

// --- SHA-256 (OpenSSL) ---
lacert_err_t lacert_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
    return LACERT_OK;
}

// --- BLAKE3 (проверено: совпадает с zeebo/blake3 в Go) ---
lacert_err_t lacert_blake3(const uint8_t **parts, const size_t *lens,
                           size_t count, uint8_t out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    for (size_t i = 0; i < count; i++)
        blake3_hasher_update(&h, parts[i], lens[i]);
    blake3_hasher_finalize(&h, out, 32);
    return LACERT_OK;
}

// --- ML-KEM-1024 декапсуляция (проверено: совпадает с circl в Go) ---
lacert_err_t lacert_kem_decapsulate(const uint8_t *kem_priv,
                                    const uint8_t *ciphertext,
                                    uint8_t shared[LACERT_KEM_SHARED_SIZE]) {
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared, ciphertext, kem_priv) != 0)
        return LACERT_ERR_CRYPTO;
    return LACERT_OK;
}

// --- random ---
lacert_err_t lacert_random(uint8_t *out, size_t len) {
    return RAND_bytes(out, (int)len) == 1 ? LACERT_OK : LACERT_ERR_CRYPTO;
}

// --- ECDSA P-256 подпись → ASN.1 DER (как Go SignASN1) ---
lacert_err_t lacert_ecdsa_sign(const uint8_t ecdsa_priv[32],
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig, size_t *sig_len) {
    uint8_t digest[32];
    lacert_sha256(msg, msg_len, digest);

    lacert_err_t rc = LACERT_ERR_CRYPTO;
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *d = BN_bin2bn(ecdsa_priv, 32, NULL);
    if (!key || !d) goto done;
    if (EC_KEY_set_private_key(key, d) != 1) goto done;

    ECDSA_SIG *s = ECDSA_do_sign(digest, 32, key);
    if (!s) goto done;
    // сериализация в DER
    unsigned char *p = sig;
    int n = i2d_ECDSA_SIG(s, &p);
    ECDSA_SIG_free(s);
    if (n <= 0) goto done;
    *sig_len = (size_t)n;
    rc = LACERT_OK;

done:
    if (d) BN_free(d);
    if (key) EC_KEY_free(key);
    return rc;
}

// --- ChaCha20-Poly1305 seal (OpenSSL EVP), формат как Go: ct||tag, AAD пусто ---
lacert_err_t lacert_chacha_seal(const uint8_t key[32], uint32_t seq,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t nonce_out[LACERT_CHACHA_NONCE_SIZE],
                                uint8_t *ct, size_t *ct_len) {
    if (lacert_random(nonce_out, 8) != LACERT_OK) return LACERT_ERR_CRYPTO;
    nonce_out[8]  = (uint8_t)(seq >> 24);
    nonce_out[9]  = (uint8_t)(seq >> 16);
    nonce_out[10] = (uint8_t)(seq >> 8);
    nonce_out[11] = (uint8_t)(seq);

    lacert_err_t rc = LACERT_ERR_CRYPTO;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return rc;
    int outl = 0;
    if (EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, key, nonce_out) != 1) goto done;
    if (EVP_EncryptUpdate(c, ct, &outl, pt, (int)pt_len) != 1) goto done;
    int total = outl;
    if (EVP_EncryptFinal_ex(c, ct + total, &outl) != 1) goto done;
    total += outl;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) goto done;
    memcpy(ct + total, tag, 16);   // тег в конец, как Go
    *ct_len = (size_t)total + 16;
    rc = LACERT_OK;
done:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

lacert_err_t lacert_chacha_open(const uint8_t key[32],
                                const uint8_t nonce[LACERT_CHACHA_NONCE_SIZE],
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *pt, size_t *pt_len) {
    if (ct_len < 16) return LACERT_ERR_DECODE;
    size_t body = ct_len - 16;
    lacert_err_t rc = LACERT_ERR_CRYPTO;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return rc;
    int outl = 0;
    if (EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(c, pt, &outl, ct, (int)body) != 1) goto done;
    int total = outl;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void*)(ct + body)) != 1) goto done;
    if (EVP_DecryptFinal_ex(c, pt + total, &outl) != 1) { rc = LACERT_ERR_AUTH; goto done; }
    *pt_len = (size_t)(total + outl);
    rc = LACERT_OK;
done:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

// PQClean требует внешнюю randombytes.
void PQCLEAN_randombytes(uint8_t *out, size_t n){ RAND_bytes(out, (int)n); }
