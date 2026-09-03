/*
 * BankShield - AES-256 Encryption Engine, SHA-256 Hash Generator
 * 
 *   - AES-256-CBC шифровка
 *   - SHA-256 генерация хеша
 *   - HMAC-SHA256 аутентификация под сообщения
 *   - Polymorphic генерация цепочки хешей
 *   - генерация случайного количества уровней (CSPRNG)
 */

#ifndef BS_CRYPTO_H
#define BS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define BS_AES_BLOCK_SIZE   16
#define BS_AES_KEY_SIZE     32   // 256 битов
#define BS_AES_ROUNDS       14
#define BS_AES_EXPANDED_KEY 240  // 240 байтов

typedef struct {
    uint8_t round_key[BS_AES_EXPANDED_KEY];
    uint8_t iv[BS_AES_BLOCK_SIZE];
} bs_aes_ctx;

/* Initialize AES context with key and IV */
void bs_aes_init(bs_aes_ctx *ctx, const uint8_t key[BS_AES_KEY_SIZE],
                 const uint8_t iv[BS_AES_BLOCK_SIZE]);

/* AES-256-CBC encrypt (in-place, len must be multiple of 16) */
void bs_aes_cbc_encrypt(bs_aes_ctx *ctx, uint8_t *data, size_t len);

/* AES-256-CBC decrypt (in-place, len must be multiple of 16) */
void bs_aes_cbc_decrypt(bs_aes_ctx *ctx, uint8_t *data, size_t len);

/* PKCS7 padding: returns new length (padded) */
size_t bs_aes_pad(uint8_t *data, size_t len, size_t buf_capacity);

/* PKCS7 unpadding: returns original length */
size_t bs_aes_unpad(const uint8_t *data, size_t len);

/* ========================== SHA-256 ========================== */

#define BS_SHA256_DIGEST_SIZE 32
#define BS_SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[BS_SHA256_BLOCK_SIZE];
    uint32_t buffer_len;
} bs_sha256_ctx;

void bs_sha256_init(bs_sha256_ctx *ctx);
void bs_sha256_update(bs_sha256_ctx *ctx, const uint8_t *data, size_t len);
void bs_sha256_final(bs_sha256_ctx *ctx, uint8_t digest[BS_SHA256_DIGEST_SIZE]);

/* One-shot SHA-256 */
void bs_sha256(const uint8_t *data, size_t len, uint8_t digest[BS_SHA256_DIGEST_SIZE]);

/* ======================== HMAC-SHA256 ======================== */

#define BS_HMAC_SHA256_SIZE BS_SHA256_DIGEST_SIZE

void bs_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t mac[BS_HMAC_SHA256_SIZE]);

/* =================== Polymorphic Hash Chain ================== */

#define BS_HASH_CHAIN_DEPTH 8   /* Number of cascading hashes */

typedef struct {
    uint8_t  chain[BS_HASH_CHAIN_DEPTH][BS_SHA256_DIGEST_SIZE];
    uint8_t  salt[16];
    uint32_t iterations;
    uint8_t  final_hash[BS_SHA256_DIGEST_SIZE];
} bs_hash_chain;

/* Generate a polymorphic hash chain from data + random salt */
void bs_hash_chain_generate(bs_hash_chain *hc, const uint8_t *data,
                            size_t len, uint32_t iterations);

/* Verify data against a previously generated hash chain */
int bs_hash_chain_verify(const bs_hash_chain *hc, const uint8_t *data,
                         size_t len);

/* ===================== Secure Random (CSPRNG) ================= */

/* Fill buffer with cryptographically secure random bytes */
int bs_csprng_fill(uint8_t *buf, size_t len);

/* Generate a random AES-256 key */
int bs_generate_key(uint8_t key[BS_AES_KEY_SIZE]);

/* Generate a random IV */
int bs_generate_iv(uint8_t iv[BS_AES_BLOCK_SIZE]);

/* ===================== Utility ================================ */

/* Constant-time memory comparison (anti-timing-attack) */
int bs_secure_compare(const uint8_t *a, const uint8_t *b, size_t len);

/* Secure memory wipe */
void bs_secure_zero(void *ptr, size_t len);

/* Convert hash to hex string (out must be >= 65 bytes for SHA-256) */
void bs_hash_to_hex(const uint8_t *hash, size_t hash_len, char *out);

#endif /* BS_CRYPTO_H */
