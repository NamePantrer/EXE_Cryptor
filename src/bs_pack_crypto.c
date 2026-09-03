/*
 * BankShield — криптография упаковки
 */

#include "../include/bs_pack_crypto.h"
#include <string.h>

static const uint8_t BS_HDR_HMAC_LABEL[] =
    "BankShield-HMAC-Key-Derivation";
static const uint8_t BS_PAYLOAD_MAC_LABEL[] =
    "BankShield-Payload-MAC-Key-v4";

void bs_pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t out_len) {
    uint32_t block_num = 1;
    size_t offset = 0;

    while (offset < out_len) {
        uint8_t salt_block[128];
        if (salt_len > 120) return;

        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len]     = (uint8_t)(block_num >> 24);
        salt_block[salt_len + 1] = (uint8_t)(block_num >> 16);
        salt_block[salt_len + 2] = (uint8_t)(block_num >> 8);
        salt_block[salt_len + 3] = (uint8_t)(block_num);

        uint8_t u[32], t[32];
        bs_hmac_sha256(password, pass_len, salt_block, salt_len + 4, u);
        memcpy(t, u, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            bs_hmac_sha256(password, pass_len, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }

        size_t to_copy = (out_len - offset < 32) ? out_len - offset : 32;
        memcpy(out + offset, t, to_copy);
        offset += to_copy;
        block_num++;
    }
}

void bs_pack_payload_mac(const uint8_t mac_key[BS_PACK_KEY_SIZE],
                         const uint8_t iv[BS_PACK_IV_SIZE],
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t out_mac[BS_PACK_HASH_SIZE]) {
    bs_sha256_ctx ctx;
    uint8_t inner[32];

    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, iv, BS_PACK_IV_SIZE);
    bs_sha256_update(&ctx, ciphertext, ct_len);
    bs_sha256_final(&ctx, inner);

    bs_hmac_sha256(mac_key, BS_PACK_KEY_SIZE, inner, sizeof(inner), out_mac);
    bs_secure_zero(inner, sizeof(inner));
}

void bs_pack_header_hmac_key(const uint8_t aes_key[BS_PACK_KEY_SIZE],
                             uint8_t hmac_key[BS_PACK_KEY_SIZE]) {
    bs_hmac_sha256(aes_key, BS_PACK_KEY_SIZE,
                   BS_HDR_HMAC_LABEL, sizeof(BS_HDR_HMAC_LABEL) - 1,
                   hmac_key);
}

void bs_pack_payload_mac_key(const uint8_t aes_key[BS_PACK_KEY_SIZE],
                             uint8_t mac_key[BS_PACK_KEY_SIZE]) {
    bs_hmac_sha256(aes_key, BS_PACK_KEY_SIZE,
                   BS_PAYLOAD_MAC_LABEL, sizeof(BS_PAYLOAD_MAC_LABEL) - 1,
                   mac_key);
}

static size_t pack_kdf_len(const bs_pack_header *hdr) {
    (void)hdr;
    return BS_PACK_KDF_WRAP_V3;
}

void bs_pack_wrap_keys(bs_pack_header *hdr,
                       const uint8_t stub_binding_hash[BS_PACK_HASH_SIZE],
                       int use_v4_layout) {
    uint8_t hek[BS_PACK_KDF_WRAP_V3];

    if (use_v4_layout)
        hdr->version = BS_PACK_VERSION_V4;

    bs_pbkdf2_sha256(stub_binding_hash, BS_PACK_HASH_SIZE,
                      hdr->kdf_salt, BS_KDF_SALT_SIZE,
                      hdr->kdf_iterations, hek, sizeof(hek));

    for (size_t i = 0; i < 32; i++) hdr->aes_key[i] ^= hek[i];
    for (size_t i = 0; i < 16; i++) hdr->aes_iv[i] ^= hek[32 + i];

    bs_secure_zero(hek, sizeof(hek));
}

void bs_pack_unwrap_keys(bs_pack_header *hdr,
                         const uint8_t stub_binding_hash[BS_PACK_HASH_SIZE]) {
    uint8_t hek[BS_PACK_KDF_WRAP_V3];

    bs_pbkdf2_sha256(stub_binding_hash, BS_PACK_HASH_SIZE,
                      hdr->kdf_salt, BS_KDF_SALT_SIZE,
                      hdr->kdf_iterations, hek, sizeof(hek));

    for (size_t i = 0; i < 32; i++) hdr->aes_key[i] ^= hek[i];
    for (size_t i = 0; i < 16; i++) hdr->aes_iv[i] ^= hek[32 + i];

    bs_secure_zero(hek, sizeof(hek));
}
