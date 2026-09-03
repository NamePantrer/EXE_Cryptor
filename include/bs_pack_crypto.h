/*
 * BankShield — криптография формата упаковки (v3/v4)
 * Общие функции для протектора и тестов.
 */

#ifndef BS_PACK_CRYPTO_H
#define BS_PACK_CRYPTO_H

#include "bs_pack_format.h"
#include "bs_crypto.h"
#include <stddef.h>

#define BS_PACK_KDF_WRAP_V3   48u   /* aes_key + iv */
#define BS_PACK_KDF_WRAP_V4   48u   /* v4: тот же wrap, отдельный mac-ключ не храним */

// PBKDF2-HMAC-SHA256 (итерации задаёт вызывающий)
void bs_pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations,
                      uint8_t *out, size_t out_len);

// MAC по нагрузке: HMAC(mac_key, iv || ciphertext) — проверять ДО decrypt
void bs_pack_payload_mac(const uint8_t mac_key[BS_PACK_KEY_SIZE],
                         const uint8_t iv[BS_PACK_IV_SIZE],
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t out_mac[BS_PACK_HASH_SIZE]);

// Ключ HMAC заголовка (от открытого aes_key, до XOR-обёртки)
void bs_pack_header_hmac_key(const uint8_t aes_key[BS_PACK_KEY_SIZE],
                             uint8_t hmac_key[BS_PACK_KEY_SIZE]);

// v4: отдельный ключ для MAC нагрузки (не кладём в заголовок)
void bs_pack_payload_mac_key(const uint8_t aes_key[BS_PACK_KEY_SIZE],
                             uint8_t mac_key[BS_PACK_KEY_SIZE]);

// XOR-обёртка ключей в заголовке (v3: 48 байт KDF, v4: 80 байт)
void bs_pack_wrap_keys(bs_pack_header *hdr,
                       const uint8_t stub_binding_hash[BS_PACK_HASH_SIZE],
                       int use_v4_layout);

void bs_pack_unwrap_keys(bs_pack_header *hdr,
                         const uint8_t stub_binding_hash[BS_PACK_HASH_SIZE]);

#endif /* BS_PACK_CRYPTO_H */
