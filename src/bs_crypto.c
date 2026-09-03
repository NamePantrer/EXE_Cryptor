/*
 * BankShield — реализация AES-256, SHA-256 и цепочки хешей
 * Учебный проект, 2026
 *
 * Писал без openssl — чистый C, для понимания как устроено внутри.
 * bs_secure_compare — чтобы memcmp не палил длину по времени.
 */

#include "../include/bs_crypto.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* ================================================================
 * Реализация AES-256
 * ================================================================ */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// gf(2^8) для mixcolumns (из конспекта по крипте)
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

static void aes_key_expansion(const uint8_t key[32], uint8_t *round_key) {
    int i;
    uint8_t temp[4];
    
        // первые 32 байта копируем как есть
    memcpy(round_key, key, 32);
    
    for (i = 8; i < 4 * (BS_AES_ROUNDS + 1); i++) {
        temp[0] = round_key[(i-1)*4 + 0];
        temp[1] = round_key[(i-1)*4 + 1];
        temp[2] = round_key[(i-1)*4 + 2];
        temp[3] = round_key[(i-1)*4 + 3];
        
        if (i % 8 == 0) {
                // rcon на каждый 8-й раунд
            uint8_t t = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ aes_rcon[i/8];
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[t];
        } else if (i % 8 == 4) {
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];
        }
        
        round_key[i*4 + 0] = round_key[(i-8)*4 + 0] ^ temp[0];
        round_key[i*4 + 1] = round_key[(i-8)*4 + 1] ^ temp[1];
        round_key[i*4 + 2] = round_key[(i-8)*4 + 2] ^ temp[2];
        round_key[i*4 + 3] = round_key[(i-8)*4 + 3] ^ temp[3];
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int i = 0; i < 16; i++)
        state[i] ^= round_key[i];
}

static void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = aes_sbox[state[i]];
}

static void aes_inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = aes_inv_sbox[state[i]];
}

static void aes_shift_rows(uint8_t state[16]) {
    uint8_t t;
    // Строка 1: сдвиг влево на 1
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    // Строка 2: сдвиг влево на 2
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    // Строка 3: сдвиг влево на 3
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

static void aes_inv_shift_rows(uint8_t state[16]) {
    uint8_t t;
    // Строка 1: сдвиг вправо на 1
    t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    // Строка 2: сдвиг вправо на 2
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    // Строка 3: сдвиг вправо на 3
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

static void aes_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c+0] = gf_mul(a0,2) ^ gf_mul(a1,3) ^ a2 ^ a3;
        state[c+1] = a0 ^ gf_mul(a1,2) ^ gf_mul(a2,3) ^ a3;
        state[c+2] = a0 ^ a1 ^ gf_mul(a2,2) ^ gf_mul(a3,3);
        state[c+3] = gf_mul(a0,3) ^ a1 ^ a2 ^ gf_mul(a3,2);
    }
}

static void aes_inv_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c+0] = gf_mul(a0,14) ^ gf_mul(a1,11) ^ gf_mul(a2,13) ^ gf_mul(a3,9);
        state[c+1] = gf_mul(a0,9)  ^ gf_mul(a1,14) ^ gf_mul(a2,11) ^ gf_mul(a3,13);
        state[c+2] = gf_mul(a0,13) ^ gf_mul(a1,9)  ^ gf_mul(a2,14) ^ gf_mul(a3,11);
        state[c+3] = gf_mul(a0,11) ^ gf_mul(a1,13) ^ gf_mul(a2,9)  ^ gf_mul(a3,14);
    }
}

static void aes_encrypt_block(const uint8_t *round_key, uint8_t block[16]) {
    aes_add_round_key(block, round_key);
    for (int round = 1; round < BS_AES_ROUNDS; round++) {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, round_key + round * 16);
    }
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, round_key + BS_AES_ROUNDS * 16);
}

static void aes_decrypt_block(const uint8_t *round_key, uint8_t block[16]) {
    aes_add_round_key(block, round_key + BS_AES_ROUNDS * 16);
    for (int round = BS_AES_ROUNDS - 1; round >= 1; round--) {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, round_key + round * 16);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, round_key);
}

// ==================== Публичный API AES ====================

void bs_aes_init(bs_aes_ctx *ctx, const uint8_t key[BS_AES_KEY_SIZE],
                 const uint8_t iv[BS_AES_BLOCK_SIZE]) {
    aes_key_expansion(key, ctx->round_key);
    memcpy(ctx->iv, iv, BS_AES_BLOCK_SIZE);
}

void bs_aes_cbc_encrypt(bs_aes_ctx *ctx, uint8_t *data, size_t len) {
    uint8_t *prev = ctx->iv;
    for (size_t i = 0; i < len; i += BS_AES_BLOCK_SIZE) {
        for (int j = 0; j < BS_AES_BLOCK_SIZE; j++)
            data[i + j] ^= prev[j];
        aes_encrypt_block(ctx->round_key, data + i);
        prev = data + i;
    }
    memcpy(ctx->iv, prev, BS_AES_BLOCK_SIZE);
}

void bs_aes_cbc_decrypt(bs_aes_ctx *ctx, uint8_t *data, size_t len) {
    uint8_t tmp[BS_AES_BLOCK_SIZE];
    uint8_t prev[BS_AES_BLOCK_SIZE];
    memcpy(prev, ctx->iv, BS_AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < len; i += BS_AES_BLOCK_SIZE) {
        memcpy(tmp, data + i, BS_AES_BLOCK_SIZE);
        aes_decrypt_block(ctx->round_key, data + i);
        for (int j = 0; j < BS_AES_BLOCK_SIZE; j++)
            data[i + j] ^= prev[j];
        memcpy(prev, tmp, BS_AES_BLOCK_SIZE);
    }
    memcpy(ctx->iv, prev, BS_AES_BLOCK_SIZE);
}

size_t bs_aes_pad(uint8_t *data, size_t len, size_t buf_capacity) {
    uint8_t pad_val = (uint8_t)(BS_AES_BLOCK_SIZE - (len % BS_AES_BLOCK_SIZE));
    size_t new_len = len + pad_val;
    if (new_len > buf_capacity) return 0;
    for (size_t i = len; i < new_len; i++)
        data[i] = pad_val;
    return new_len;
}

size_t bs_aes_unpad(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_val = data[len - 1];
    if (pad_val == 0 || pad_val > BS_AES_BLOCK_SIZE) return 0;
    // Проверка всех байт паддинга за постоянное время
    uint8_t bad = 0;
    for (size_t i = 0; i < pad_val; i++)
        bad |= data[len - 1 - i] ^ pad_val;
    return bad ? 0 : len - pad_val;
}

/* ================================================================
 * Реализация SHA-256
 * ================================================================ */

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x)  (ROR32(x, 2)  ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SHA_EP1(x)  (ROR32(x, 6)  ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SHA_SIG0(x) (ROR32(x, 7)  ^ ROR32(x, 18) ^ ((x) >> 3))
#define SHA_SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(bs_sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8)  | ((uint32_t)data[i*4+3]);
    
    for (int i = 16; i < 64; i++)
        w[i] = SHA_SIG1(w[i-2]) + w[i-7] + SHA_SIG0(w[i-15]) + w[i-16];
    
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA_EP1(e) + SHA_CH(e,f,g) + sha256_k[i] + w[i];
        uint32_t t2 = SHA_EP0(a) + SHA_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void bs_sha256_init(bs_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

void bs_sha256_update(bs_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->buffer_len++] = data[i];
        if (ctx->buffer_len == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bit_count += 512;
            ctx->buffer_len = 0;
        }
    }
}

void bs_sha256_final(bs_sha256_ctx *ctx, uint8_t digest[BS_SHA256_DIGEST_SIZE]) {
    uint64_t total_bits = ctx->bit_count + (uint64_t)ctx->buffer_len * 8;
    
// Добавить бит 1
    ctx->buffer[ctx->buffer_len++] = 0x80;
    
// Дополнить до 56 байт
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64) ctx->buffer[ctx->buffer_len++] = 0;
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56) ctx->buffer[ctx->buffer_len++] = 0;
    
// Длина в битах (big-endian)
    for (int i = 7; i >= 0; i--)
        ctx->buffer[ctx->buffer_len++] = (uint8_t)(total_bits >> (i * 8));
    
    sha256_transform(ctx, ctx->buffer);
    
// Вывод дайджеста (big-endian)
    for (int i = 0; i < 8; i++) {
        digest[i*4+0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
    
// Затереть внутреннее состояние
    bs_secure_zero(ctx, sizeof(*ctx));
}

void bs_sha256(const uint8_t *data, size_t len, uint8_t digest[BS_SHA256_DIGEST_SIZE]) {
    bs_sha256_ctx ctx;
    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, data, len);
    bs_sha256_final(&ctx, digest);
}

/* ================================================================
 * HMAC-SHA256
 * ================================================================ */

void bs_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t mac[BS_HMAC_SHA256_SIZE]) {
    uint8_t k_pad[BS_SHA256_BLOCK_SIZE];
    uint8_t key_hash[BS_SHA256_DIGEST_SIZE];
    bs_sha256_ctx ctx;
    
// Если ключ длиннее блока — сначала хешируем его
    if (key_len > BS_SHA256_BLOCK_SIZE) {
        bs_sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = BS_SHA256_DIGEST_SIZE;
    }
    
// Внутренний хеш: H(K ^ ipad || сообщение)
    memset(k_pad, 0x36, BS_SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++)
        k_pad[i] ^= key[i];
    
    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, k_pad, BS_SHA256_BLOCK_SIZE);
    bs_sha256_update(&ctx, data, data_len);
    bs_sha256_final(&ctx, mac);
    
// Внешний хеш: H(K ^ opad || внутренний_хеш)
    memset(k_pad, 0x5c, BS_SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++)
        k_pad[i] ^= key[i];
    
    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, k_pad, BS_SHA256_BLOCK_SIZE);
    bs_sha256_update(&ctx, mac, BS_SHA256_DIGEST_SIZE);
    bs_sha256_final(&ctx, mac);
    
// Затереть промежуточные буферы
    bs_secure_zero(k_pad, sizeof(k_pad));
    bs_secure_zero(key_hash, sizeof(key_hash));
}

/* ================================================================
 * Полиморфная цепочка хешей
 * ================================================================ */

void bs_hash_chain_generate(bs_hash_chain *hc, const uint8_t *data,
                            size_t len, uint32_t iterations) {
                            // Случайная соль
    bs_csprng_fill(hc->salt, sizeof(hc->salt));
    hc->iterations = iterations;
    
// Уровень 0: SHA-256(соль || данные)
    bs_sha256_ctx ctx;
    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, hc->salt, sizeof(hc->salt));
    bs_sha256_update(&ctx, data, len);
    bs_sha256_final(&ctx, hc->chain[0]);
    
// Уровни 1..DEPTH-1: каскад HMAC с растягиванием итераций
    for (int level = 1; level < BS_HASH_CHAIN_DEPTH; level++) {
    // На каждом уровне — что-то вроде PBKDF2 по итерациям
        uint8_t temp[BS_SHA256_DIGEST_SIZE];
        memcpy(temp, hc->chain[level - 1], BS_SHA256_DIGEST_SIZE);
        
        for (uint32_t iter = 0; iter < iterations; iter++) {
            bs_hmac_sha256(hc->salt, sizeof(hc->salt),
                          temp, BS_SHA256_DIGEST_SIZE, temp);
        }
        
// Подмешиваем хеш исходных данных на каждом уровне
        bs_sha256_init(&ctx);
        bs_sha256_update(&ctx, temp, BS_SHA256_DIGEST_SIZE);
        bs_sha256_update(&ctx, hc->chain[0], BS_SHA256_DIGEST_SIZE);
        
// Уникальная «приправка» для номера уровня
        uint8_t tweak[4] = { (uint8_t)level, (uint8_t)(level >> 8),
                              (uint8_t)(iterations), (uint8_t)(iterations >> 8) };
        bs_sha256_update(&ctx, tweak, sizeof(tweak));
        bs_sha256_final(&ctx, hc->chain[level]);
    }
    
// Финальный хеш: HMAC по всей цепочке
    bs_hmac_sha256(hc->chain[BS_HASH_CHAIN_DEPTH - 1], BS_SHA256_DIGEST_SIZE,
                   (const uint8_t*)hc->chain, sizeof(hc->chain),
                   hc->final_hash);
}

int bs_hash_chain_verify(const bs_hash_chain *hc, const uint8_t *data,
                         size_t len) {
    bs_hash_chain verify;
    verify.iterations = hc->iterations;
    memcpy(verify.salt, hc->salt, sizeof(verify.salt));
    
// Пересчитать уровень 0
    bs_sha256_ctx ctx;
    bs_sha256_init(&ctx);
    bs_sha256_update(&ctx, verify.salt, sizeof(verify.salt));
    bs_sha256_update(&ctx, data, len);
    bs_sha256_final(&ctx, verify.chain[0]);
    
// Сверить уровень 0
    if (!bs_secure_compare(verify.chain[0], hc->chain[0], BS_SHA256_DIGEST_SIZE))
        goto fail;
    
// Пересчитать и сверить каждый уровень
    for (int level = 1; level < BS_HASH_CHAIN_DEPTH; level++) {
        uint8_t temp[BS_SHA256_DIGEST_SIZE];
        memcpy(temp, verify.chain[level - 1], BS_SHA256_DIGEST_SIZE);
        
        for (uint32_t iter = 0; iter < verify.iterations; iter++) {
            bs_hmac_sha256(verify.salt, sizeof(verify.salt),
                          temp, BS_SHA256_DIGEST_SIZE, temp);
        }
        
        bs_sha256_init(&ctx);
        bs_sha256_update(&ctx, temp, BS_SHA256_DIGEST_SIZE);
        bs_sha256_update(&ctx, verify.chain[0], BS_SHA256_DIGEST_SIZE);
        
        uint8_t tweak[4] = { (uint8_t)level, (uint8_t)(level >> 8),
                              (uint8_t)(verify.iterations), (uint8_t)(verify.iterations >> 8) };
        bs_sha256_update(&ctx, tweak, sizeof(tweak));
        bs_sha256_final(&ctx, verify.chain[level]);
        
        if (!bs_secure_compare(verify.chain[level], hc->chain[level], BS_SHA256_DIGEST_SIZE))
            goto fail;
    }
    
// Сверить финальный HMAC
    uint8_t final_mac[BS_SHA256_DIGEST_SIZE];
    bs_hmac_sha256(verify.chain[BS_HASH_CHAIN_DEPTH - 1], BS_SHA256_DIGEST_SIZE,
                   (const uint8_t*)verify.chain, sizeof(verify.chain),
                   final_mac);
    
    int result = bs_secure_compare(final_mac, hc->final_hash, BS_SHA256_DIGEST_SIZE);
    bs_secure_zero(&verify, sizeof(verify));
    bs_secure_zero(final_mac, sizeof(final_mac));
    return result;

fail:
    bs_secure_zero(&verify, sizeof(verify));
    return 0;
}

/* ================================================================
 * CSPRNG — криптостойкий генератор случайных чисел
 * ================================================================ */

int bs_csprng_fill(uint8_t *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV prov;
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        return -1;
    BOOL ok = CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    return ok ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) { close(fd); return -1; }
        total += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

int bs_generate_key(uint8_t key[BS_AES_KEY_SIZE]) {
    return bs_csprng_fill(key, BS_AES_KEY_SIZE);
}

int bs_generate_iv(uint8_t iv[BS_AES_BLOCK_SIZE]) {
    return bs_csprng_fill(iv, BS_AES_BLOCK_SIZE);
}

/* ================================================================
 * Вспомогательные функции
 * ================================================================ */

int bs_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

void bs_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

void bs_hash_to_hex(const uint8_t *hash, size_t hash_len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < hash_len; i++) {
        out[i*2]     = hex[(hash[i] >> 4) & 0x0f];
        out[i*2 + 1] = hex[hash[i] & 0x0f];
    }
    out[hash_len * 2] = '\0';
}
