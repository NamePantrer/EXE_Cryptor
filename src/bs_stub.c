/*
 * BankShield — загрузчик (stub)
 * курсовой/пет-проект, 2026
 *
 * Оболочка защищённого exe — stub собирается отдельно,
 * потом протектор дописывает в конец зашифрованный оригинал.
 *
 * При запуске:
 *   1. Читает свой файл с диска
 *   2. Ищет хвостовую метку → заголовок пакета
 *   3. Anti-debug (если включено)
 *   4. Проверка полиморфной цепочки хешей
 *   5. Расшифровка AES-256-CBC
 *   6. Проверка SHA-256 расшифрованного файла
 *   7. Временный файл (DELETE_ON_CLOSE)
 *   8. Запуск оригинальной программы
 *   9. Ожидание выхода и очистка
 *
 * Без внешних DLL — криптография внутри stub.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Формат пакета
#include "../include/bs_pack_format.h"

/* ================================================================
 * Динамический резолвер API — меньше следов в IAT
 * GetProcAddress по хешу имени (djb2).
 * ================================================================ */

// djb2 по имени функции (для resolve_api)
static DWORD api_hash(const char *name) {
    DWORD h = 5381;
    while (*name) { h = ((h << 5) + h) ^ (unsigned char)*name; name++; }
    return h;
}

// ищем экспорт в модуле по хешу, не по строке
static FARPROC resolve_api(HMODULE mod, DWORD target_hash) {
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER*)mod;
    IMAGE_NT_HEADERS *n = (IMAGE_NT_HEADERS*)((unsigned char*)mod + d->e_lfanew);
    DWORD exp_rva = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)((unsigned char*)mod + exp_rva);
    DWORD *names = (DWORD*)((unsigned char*)mod + exp->AddressOfNames);
    WORD  *ords  = (WORD*)((unsigned char*)mod + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)((unsigned char*)mod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char*)((unsigned char*)mod + names[i]);
        if (api_hash(fn) == target_hash)
            return (FARPROC)((unsigned char*)mod + funcs[ords[i]]);
    }
    return NULL;
}

// хеши посчитал заранее — в рантайме строк меньше
#define H_NtUnmapViewOfSection      0x7473FDF5u
#define H_NtQueryInformationProcess 0x8BE68952u
#define H_VirtualAllocEx            0x87E8ADD4u
#define H_WriteProcessMemory        0xCF9E4312u
#define H_ReadProcessMemory         0x447B0E1Du
#define H_GetThreadContext          0xC76B4E42u
#define H_SetThreadContext          0xA917D6D6u

// Типизированные указатели на функции
typedef LONG (NTAPI *fn_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LPVOID (WINAPI *fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *fn_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *fn_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL (WINAPI *fn_SetThreadContext)(HANDLE, const CONTEXT*);

static struct {
    fn_NtUnmapViewOfSection     NtUnmap;
    fn_NtQueryInformationProcess NtQIP;
    fn_VirtualAllocEx           VAllocEx;
    fn_WriteProcessMemory       WPM;
    fn_ReadProcessMemory        RPM;
    fn_GetThreadContext         GTC;
    fn_SetThreadContext         STC;
} dyn = {0};

static void resolve_all_apis(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    if (ntdll) {
        dyn.NtUnmap = (fn_NtUnmapViewOfSection)resolve_api(ntdll, H_NtUnmapViewOfSection);
        dyn.NtQIP   = (fn_NtQueryInformationProcess)resolve_api(ntdll, H_NtQueryInformationProcess);
    }
    if (k32) {
        dyn.VAllocEx = (fn_VirtualAllocEx)resolve_api(k32, H_VirtualAllocEx);
        dyn.WPM      = (fn_WriteProcessMemory)resolve_api(k32, H_WriteProcessMemory);
        dyn.RPM      = (fn_ReadProcessMemory)resolve_api(k32, H_ReadProcessMemory);
        dyn.GTC      = (fn_GetThreadContext)resolve_api(k32, H_GetThreadContext);
        dyn.STC      = (fn_SetThreadContext)resolve_api(k32, H_SetThreadContext);
    }
}

/* ================================================================
 * Зашифрованные строки ошибок (не светим текст в бинарнике)
 * XOR с ключом, зависящим от позиции байта
 * ================================================================ */

#define STR_KEY     0xA7
#define SDEC(out, enc, len) do { \
    for (int _i = 0; _i < (len); _i++) (out)[_i] = (enc)[_i] ^ (STR_KEY ^ (_i & 0x1F)); \
    (out)[(len)] = 0; \
} while(0)

// строки ошибок в бинарнике не храним открытым текстом
// SDEC — расшифровка на стеке
static void stub_fatal_enc(const unsigned char *enc, int len);

/* ================================================================
 * Встроенный AES-256 (минимальная реализация)
 * ================================================================ */

static const unsigned char stub_sbox[256] = {
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

static const unsigned char stub_inv_sbox[256] = {
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

static const unsigned char stub_rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static unsigned char stub_gf_mul(unsigned char a, unsigned char b) {
    unsigned char r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

static void stub_aes_key_expand(const unsigned char key[32], unsigned char *rk) {
    memcpy(rk, key, 32);
    unsigned char t[4];
    for (int i = 8; i < 60; i++) {
        t[0]=rk[(i-1)*4]; t[1]=rk[(i-1)*4+1]; t[2]=rk[(i-1)*4+2]; t[3]=rk[(i-1)*4+3];
        if (i % 8 == 0) {
            unsigned char tmp = t[0];
            t[0] = stub_sbox[t[1]] ^ stub_rcon[i/8];
            t[1] = stub_sbox[t[2]];
            t[2] = stub_sbox[t[3]];
            t[3] = stub_sbox[tmp];
        } else if (i % 8 == 4) {
            t[0]=stub_sbox[t[0]]; t[1]=stub_sbox[t[1]];
            t[2]=stub_sbox[t[2]]; t[3]=stub_sbox[t[3]];
        }
        rk[i*4]=rk[(i-8)*4]^t[0]; rk[i*4+1]=rk[(i-8)*4+1]^t[1];
        rk[i*4+2]=rk[(i-8)*4+2]^t[2]; rk[i*4+3]=rk[(i-8)*4+3]^t[3];
    }
}

static void stub_aes_decrypt_block(const unsigned char *rk, unsigned char b[16]) {
// AddRoundKey (last)
    for (int i = 0; i < 16; i++) b[i] ^= rk[14*16+i];

    for (int round = 13; round >= 1; round--) {
    // InvShiftRows
        unsigned char t;
        t=b[13]; b[13]=b[9]; b[9]=b[5]; b[5]=b[1]; b[1]=t;
        t=b[2]; b[2]=b[10]; b[10]=t; t=b[6]; b[6]=b[14]; b[14]=t;
        t=b[3]; b[3]=b[7]; b[7]=b[11]; b[11]=b[15]; b[15]=t;
        // InvSubBytes
        for (int i = 0; i < 16; i++) b[i] = stub_inv_sbox[b[i]];
        // AddRoundKey
        for (int i = 0; i < 16; i++) b[i] ^= rk[round*16+i];
        // InvMixColumns
        for (int c = 0; c < 4; c++) {
            int off = c*4;
            unsigned char a0=b[off], a1=b[off+1], a2=b[off+2], a3=b[off+3];
            b[off]   = stub_gf_mul(a0,14)^stub_gf_mul(a1,11)^stub_gf_mul(a2,13)^stub_gf_mul(a3,9);
            b[off+1] = stub_gf_mul(a0,9)^stub_gf_mul(a1,14)^stub_gf_mul(a2,11)^stub_gf_mul(a3,13);
            b[off+2] = stub_gf_mul(a0,13)^stub_gf_mul(a1,9)^stub_gf_mul(a2,14)^stub_gf_mul(a3,11);
            b[off+3] = stub_gf_mul(a0,11)^stub_gf_mul(a1,13)^stub_gf_mul(a2,9)^stub_gf_mul(a3,14);
        }
    }
    // Финальный раунд без MixColumns
    unsigned char t2;
    t2=b[13]; b[13]=b[9]; b[9]=b[5]; b[5]=b[1]; b[1]=t2;
    t2=b[2]; b[2]=b[10]; b[10]=t2; t2=b[6]; b[6]=b[14]; b[14]=t2;
    t2=b[3]; b[3]=b[7]; b[7]=b[11]; b[11]=b[15]; b[15]=t2;
    for (int i = 0; i < 16; i++) b[i] = stub_inv_sbox[b[i]];
    for (int i = 0; i < 16; i++) b[i] ^= rk[i];
}

static void stub_aes_cbc_decrypt(const unsigned char key[32],
                                  const unsigned char iv[16],
                                  unsigned char *data, size_t len) {
    unsigned char rk[240];
    stub_aes_key_expand(key, rk);

    unsigned char prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < len; i += 16) {
        unsigned char tmp[16];
        memcpy(tmp, data + i, 16);
        stub_aes_decrypt_block(rk, data + i);
        for (int j = 0; j < 16; j++)
            data[i + j] ^= prev[j];
        memcpy(prev, tmp, 16);
    }

// Затереть round keys
    volatile unsigned char *p = (volatile unsigned char*)rk;
    for (int i = 0; i < 240; i++) p[i] = 0;
}

/* ================================================================
 * Встроенный SHA-256
 * ================================================================ */

static const uint32_t stub_sha_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define STUB_ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void stub_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

// Полные блоки по 64 байта
    size_t total_bits = len * 8;
    size_t pos = 0;

// Данные + паддинг + длина
// Буфер с паддингом
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    unsigned char *buf = (unsigned char*)calloc(padded_len, 1);
    if (!buf) return;
    memcpy(buf, data, len);
    buf[len] = 0x80;

// Длина в битах, big-endian
    for (int i = 0; i < 8; i++)
        buf[padded_len - 1 - i] = (unsigned char)(total_bits >> (i * 8));

// Каждый блок 64 байта
    for (pos = 0; pos < padded_len; pos += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[pos+i*4]<<24) | ((uint32_t)buf[pos+i*4+1]<<16) |
                   ((uint32_t)buf[pos+i*4+2]<<8) | buf[pos+i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = STUB_ROR(w[i-15],7)^STUB_ROR(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = STUB_ROR(w[i-2],17)^STUB_ROR(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = STUB_ROR(e,6)^STUB_ROR(e,11)^STUB_ROR(e,25);
            uint32_t ch = (e&f)^(~e&g);
            uint32_t t1 = hh + S1 + ch + stub_sha_k[i] + w[i];
            uint32_t S0 = STUB_ROR(a,2)^STUB_ROR(a,13)^STUB_ROR(a,22);
            uint32_t maj = (a&b)^(a&c)^(b&c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    for (int i = 0; i < 8; i++) {
        out[i*4]=(unsigned char)(h[i]>>24); out[i*4+1]=(unsigned char)(h[i]>>16);
        out[i*4+2]=(unsigned char)(h[i]>>8); out[i*4+3]=(unsigned char)(h[i]);
    }

// Затереть буфер
    volatile unsigned char *vp = (volatile unsigned char*)buf;
    for (size_t i = 0; i < padded_len; i++) vp[i] = 0;
    free(buf);
}

/* ================================================================
 * Встроенный HMAC-SHA256
 * ================================================================ */

// v4: MAC нагрузки (как в bs_pack_crypto.c)
static void stub_pack_payload_mac(const unsigned char mac_key[32],
                                  const unsigned char iv[16],
                                  const unsigned char *ct, size_t ct_len,
                                  unsigned char out_mac[32]) {
    unsigned char *buf = (unsigned char*)malloc(16 + ct_len);
    unsigned char inner[32];
    if (!buf) return;
    memcpy(buf, iv, 16);
    memcpy(buf + 16, ct, ct_len);
    stub_sha256(buf, 16 + ct_len, inner);
    free(buf);
    stub_hmac_sha256(mac_key, 32, inner, 32, out_mac);
    stub_secure_wipe(inner, sizeof(inner));
}

static void stub_hmac_sha256(const unsigned char *key, size_t key_len,
                              const unsigned char *data, size_t data_len,
                              unsigned char mac[32]) {
    unsigned char k_pad[64];
    unsigned char key_hash[32];

    if (key_len > 64) {
        stub_sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = 32;
    }

// Внутренний HMAC
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    size_t inner_len = 64 + data_len;
    unsigned char *inner_buf = (unsigned char*)malloc(inner_len);
    if (!inner_buf) return;
    memcpy(inner_buf, k_pad, 64);
    memcpy(inner_buf + 64, data, data_len);
    stub_sha256(inner_buf, inner_len, mac);
    free(inner_buf);

// Внешний HMAC
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    unsigned char outer_buf[64 + 32];
    memcpy(outer_buf, k_pad, 64);
    memcpy(outer_buf + 64, mac, 32);
    stub_sha256(outer_buf, 96, mac);
}

/* ================================================================
 * PBKDF2 на базе HMAC-SHA256
 * ================================================================ */

static void stub_pbkdf2_sha256(const unsigned char *password, size_t pass_len,
                                const unsigned char *salt, size_t salt_len,
                                uint32_t iterations, unsigned char *out, size_t out_len) {
    uint32_t block_num = 1;
    size_t offset = 0;
    while (offset < out_len) {
        unsigned char salt_block[128];
        if (salt_len > 120) return;
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len]   = (unsigned char)(block_num >> 24);
        salt_block[salt_len+1] = (unsigned char)(block_num >> 16);
        salt_block[salt_len+2] = (unsigned char)(block_num >> 8);
        salt_block[salt_len+3] = (unsigned char)(block_num);

        unsigned char u[32], t[32];
        stub_hmac_sha256(password, pass_len, salt_block, salt_len + 4, u);
        memcpy(t, u, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            stub_hmac_sha256(password, pass_len, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }
        size_t to_copy = (out_len - offset < 32) ? out_len - offset : 32;
        memcpy(out + offset, t, to_copy);
        offset += to_copy;
        block_num++;
    }
}

/* ================================================================
 * Anti-debug (встроенный, несколько проверок)
 * ================================================================ */

static int stub_check_debugger(void) {
    int score = 0;

// 1: IsDebuggerPresent
    if (IsDebuggerPresent()) score += 10;

// 2: удалённый отладчик
    BOOL remote_dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_dbg);
    if (remote_dbg) score += 10;

// 3: NtGlobalFlag в PEB
#if defined(_M_X64) || defined(__x86_64__)
    unsigned char *peb = (unsigned char*)__readgsqword(0x60);
    DWORD ntg = *(DWORD*)(peb + 0xBC);
#else
    unsigned char *peb = (unsigned char*)__readfsdword(0x30);
    DWORD ntg = *(DWORD*)(peb + 0x68);
#endif
    if (ntg & 0x70) score += 10;

// 4: NtQueryInformationProcess — порты/объекты отладки
    if (dyn.NtQIP) {
        DWORD_PTR dport = 0;
        if (dyn.NtQIP(GetCurrentProcess(), 7, &dport, sizeof(dport), NULL) == 0 && dport)
            score += 10;
        HANDLE dobj = NULL;
        if (dyn.NtQIP(GetCurrentProcess(), 0x1E, &dobj, sizeof(dobj), NULL) == 0)
            score += 10;
        DWORD dflags = 1;
        if (dyn.NtQIP(GetCurrentProcess(), 0x1F, &dflags, sizeof(dflags), NULL) == 0 && dflags == 0)
            score += 10;
    }

// 5: аппаратные breakpoints
    {
        CONTEXT dbg_ctx;
        memset(&dbg_ctx, 0, sizeof(dbg_ctx));
        dbg_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &dbg_ctx)) {
            if (dbg_ctx.Dr0 || dbg_ctx.Dr1 || dbg_ctx.Dr2 || dbg_ctx.Dr3)
                score += 10;
        }
    }

// 6: timing (RDTSC)
    {
        LARGE_INTEGER t1, t2, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t1);
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) dummy += i;
        QueryPerformanceCounter(&t2);
        double ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
        if (ms > 100.0) score += 5;
    }

// 7: поиск 0xCC в своём коде
    {
        unsigned char *code = (unsigned char*)(void*)stub_check_debugger;
        int bp_count = 0;
        for (int i = 0; i < 64; i++) {
            if (code[i] == 0xCC) bp_count++;
        }
        if (bp_count > 0) score += 10;
    }

    return score >= 10;
}

/* ================================================================
 * Безопасное затирание
 * ================================================================ */

static void stub_secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

// Сравнение за постоянное время
static int stub_secure_cmp(const unsigned char *a, const unsigned char *b, size_t len) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* ================================================================
 * Проверка цепочки хешей
 * ================================================================ */

static int stub_verify_hash_chain(const bs_pack_header *hdr,
                                   const unsigned char *original_data,
                                   size_t original_size) {
    unsigned char chain[BS_PACK_CHAIN_DEPTH][32];

// Уровень 0: SHA-256(соль || данные)
    size_t buf0_len = BS_PACK_SALT_SIZE + original_size;
    unsigned char *buf0 = (unsigned char*)malloc(buf0_len);
    if (!buf0) return 0;
    memcpy(buf0, hdr->chain_salt, BS_PACK_SALT_SIZE);
    memcpy(buf0 + BS_PACK_SALT_SIZE, original_data, original_size);
    stub_sha256(buf0, buf0_len, chain[0]);
    free(buf0);

    if (!stub_secure_cmp(chain[0], hdr->chain_hashes[0], 32))
        return 0;

// Уровни 1..DEPTH-1
    for (int level = 1; level < BS_PACK_CHAIN_DEPTH; level++) {
        unsigned char temp[32];
        memcpy(temp, chain[level - 1], 32);

        for (uint32_t iter = 0; iter < hdr->chain_iterations; iter++) {
            stub_hmac_sha256(hdr->chain_salt, BS_PACK_SALT_SIZE, temp, 32, temp);
        }

// Смешивание уровней
        unsigned char mix_buf[32 + 32 + 4];
        memcpy(mix_buf, temp, 32);
        memcpy(mix_buf + 32, chain[0], 32);
        mix_buf[64] = (unsigned char)level;
        mix_buf[65] = (unsigned char)(level >> 8);
        mix_buf[66] = (unsigned char)(hdr->chain_iterations);
        mix_buf[67] = (unsigned char)(hdr->chain_iterations >> 8);
        stub_sha256(mix_buf, 68, chain[level]);

        if (!stub_secure_cmp(chain[level], hdr->chain_hashes[level], 32))
            return 0;
    }

// Финальный HMAC цепочки
    unsigned char final_mac[32];
    stub_hmac_sha256(chain[BS_PACK_CHAIN_DEPTH - 1], 32,
                     (const unsigned char*)chain, sizeof(chain), final_mac);

    int ok = stub_secure_cmp(final_mac, hdr->chain_final, 32);
    stub_secure_wipe(chain, sizeof(chain));
    stub_secure_wipe(final_mac, sizeof(final_mac));
    return ok;
}

/* ================================================================
 * Вывод ошибок (зашифрованные строки)
 * ================================================================ */

static void stub_fatal(const char *msg) {
    MessageBoxA(NULL, msg,
                "Application Error", MB_OK | MB_ICONERROR);
    ExitProcess(1);
}

static void stub_fatal_enc(const unsigned char *enc, int len) {
    char buf[256];
    if (len > 255) len = 255;
    SDEC(buf, enc, len);
    stub_fatal(buf);
}

/* ================================================================
 * Самопроверка stub (патчи, NOP и т.д.)
 * ================================================================ */

static int stub_verify_self_integrity(const unsigned char *stub_hash_expected) {
    HMODULE self = GetModuleHandleA(NULL);
    if (!self) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)self;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((unsigned char*)self + dos->e_lfanew);
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);

// Хеш .text в памяти — SizeOfRawData как у протектора
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(secs[i].Name, ".text", 5) == 0) {
            unsigned char *code = (unsigned char*)self + secs[i].VirtualAddress;
            DWORD code_size = secs[i].SizeOfRawData;
            unsigned char hash[32];
            stub_sha256(code, code_size, hash);
            return stub_secure_cmp(hash, stub_hash_expected, 32);
        }
    }
    return 0;  // .text не найдена
}

/* ================================================================
 * Случайное имя временного файла
 * ================================================================ */

static void stub_random_name(char *out, size_t max_len) {
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

// Обрезать путь temp, если длинный
    size_t td_len = strlen(temp_dir);
    if (td_len > MAX_PATH - 20) td_len = MAX_PATH - 20;
    temp_dir[td_len] = '\0';

// PID + GetTickCount для уникальности
    DWORD pid = GetCurrentProcessId();
    DWORD tick = GetTickCount();
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);

    DWORD seed = pid ^ tick ^ pc.LowPart;
    char name[16];
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 12; i++) {
        seed = seed * 1103515245 + 12345;
        name[i] = charset[(seed >> 16) % 36];
    }
    name[12] = '\0';

    snprintf(out, max_len, "%s%s.tmp", temp_dir, name);
}

/* ================================================================
 * Process hollowing (RunPE) — запуск из памяти
 * Через динамические API. >= 0 код выхода ребёнка, < 0 ошибка.
 * ================================================================ */

static int stub_run_pe(unsigned char *pe_data, size_t pe_size,
                       const char *host_path, int is_console) {
                       // Все динамические API на месте
    if (!dyn.VAllocEx || !dyn.WPM || !dyn.RPM || !dyn.GTC || !dyn.STC)
        return -99;

    if (pe_size < sizeof(IMAGE_DOS_HEADER))
        return -1;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pe_size) return -1;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;

// Архитектура x86/x64 должна совпадать
#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return -100;
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return -100;
#endif

    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);
    WORD num_secs = nt->FileHeader.NumberOfSections;

// Проброс аргументов командной строки
    char *orig_cmd = GetCommandLineA();
    char *args = orig_cmd;
    if (args[0] == '"') { args = strchr(args + 1, '"'); if (args) args++; }
    else { while (*args && *args != ' ') args++; }
    while (*args == ' ') args++;

    char cmdline[32768];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", host_path, args);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (is_console) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
    }

// Дочерний процесс в suspended
    DWORD create_flags_rpe = CREATE_SUSPENDED;
    /* DETACHED_PROCESS убран — для GUI не нужен
       hollowing and can interfere with process creation. */

    if (!CreateProcessA(host_path, cmdline, NULL, NULL,
                        is_console ? TRUE : FALSE,
                        create_flags_rpe, NULL, NULL, &si, &pi))
        return -2;

// Контекст потока (динамический API)
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!dyn.GTC(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return -3;
    }

// ImageBase в PEB дочернего процесса
#ifdef _WIN64
    uintptr_t peb_imgbase = (uintptr_t)ctx.Rdx + 0x10;
#else
    uintptr_t peb_imgbase = (uintptr_t)ctx.Ebx + 0x08;
#endif

    uintptr_t orig_base = 0;
    dyn.RPM(pi.hProcess, (LPCVOID)peb_imgbase,
            &orig_base, sizeof(orig_base), NULL);

// Снять образ с адресного пространства ребёнка
    if (dyn.NtUnmap)
        dyn.NtUnmap(pi.hProcess, (PVOID)orig_base);

// Выделить память по предпочитаемому ImageBase
    uintptr_t desired = (uintptr_t)nt->OptionalHeader.ImageBase;
    DWORD img_size = nt->OptionalHeader.SizeOfImage;

    void *alloc = dyn.VAllocEx(pi.hProcess, (LPVOID)desired, img_size,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uintptr_t actual = alloc ? desired : 0;

    if (!alloc) {
    // Любой адрес, если preferred занят
        alloc = dyn.VAllocEx(pi.hProcess, NULL, img_size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!alloc) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return -4;
        }
        actual = (uintptr_t)alloc;
    }

// Релокации, если база другая
    if (actual != desired) {
        ptrdiff_t delta = (ptrdiff_t)(actual - desired);
        DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (!reloc_rva || !reloc_sz) {
        // Нет таблицы релокаций — RunPE отменяем
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return -5;
        }

// Таблица релокаций в сыром PE
        unsigned char *reloc_raw = NULL;
        for (int i = 0; i < num_secs; i++) {
            if (reloc_rva >= secs[i].VirtualAddress &&
                reloc_rva < secs[i].VirtualAddress + secs[i].SizeOfRawData) {
                reloc_raw = pe_data + secs[i].PointerToRawData +
                            (reloc_rva - secs[i].VirtualAddress);
                break;
            }
        }

        if (reloc_raw) {
            DWORD pos = 0;
            while (pos < reloc_sz) {
                IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION*)(reloc_raw + pos);
                if (!blk->SizeOfBlock || blk->SizeOfBlock > reloc_sz) break;

                WORD *entries = (WORD*)(blk + 1);
                int cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (int i = 0; i < cnt; i++) {
                    WORD type = entries[i] >> 12;
                    WORD off  = entries[i] & 0xFFF;
                    DWORD rva = blk->VirtualAddress + off;

                    for (int s = 0; s < num_secs; s++) {
                        if (rva >= secs[s].VirtualAddress &&
                            rva < secs[s].VirtualAddress + secs[s].SizeOfRawData) {
                            unsigned char *p = pe_data + secs[s].PointerToRawData +
                                               (rva - secs[s].VirtualAddress);
#ifdef _WIN64
                            if (type == IMAGE_REL_BASED_DIR64)
                                *(uint64_t*)p += delta;
#else
                            if (type == IMAGE_REL_BASED_HIGHLOW)
                                *(uint32_t*)p += (uint32_t)delta;
#endif
                            break;
                        }
                    }
                }
                pos += blk->SizeOfBlock;
            }
        }
        nt->OptionalHeader.ImageBase = actual;
    }

// Записать заголовки PE в ребёнка
    dyn.WPM(pi.hProcess, alloc, pe_data,
            nt->OptionalHeader.SizeOfHeaders, NULL);

// Записать все секции
    for (int i = 0; i < num_secs; i++) {
        if (secs[i].SizeOfRawData > 0) {
            dyn.WPM(pi.hProcess,
                (LPVOID)(actual + secs[i].VirtualAddress),
                pe_data + secs[i].PointerToRawData,
                secs[i].SizeOfRawData, NULL);
        }
    }

// Заголовки PE не затираем: иначе 0xC0000005 при LdrInitializeThunk

// Обновить ImageBase в PEB
    dyn.WPM(pi.hProcess, (LPVOID)peb_imgbase,
            &actual, sizeof(actual), NULL);

// Новая точка входа в контексте потока
    uintptr_t entry = actual + nt->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
    ctx.Rcx = entry;
#else
    ctx.Eax = (DWORD)entry;
#endif

    dyn.STC(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

// Ждём завершения дочернего процесса
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exit_code;
}

/* ================================================================
 * Основная логика загрузчика
 * ================================================================ */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    // api тянем динамически — в iat меньше палевных импортов
    resolve_all_apis();

    // -mwindows: консоли нет, для консольных exe позже AllocConsole

    char self_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH))
        stub_fatal("Failed to locate self.");

    // читаем самих себя с диска (там stub + payload)
    HANDLE hFile = CreateFileA(self_path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        stub_fatal("Cannot open self for reading.");

    LARGE_INTEGER file_size;
    GetFileSizeEx(hFile, &file_size);
    size_t total_size = (size_t)file_size.QuadPart;

    // с конца: tail magic BSHENDBB
    if (total_size < sizeof(bs_pack_tail) + sizeof(bs_pack_header) + 64)
        stub_fatal("Invalid protected file (too small).");

    bs_pack_tail tail;
    LONG high = (LONG)(((LONGLONG)total_size - sizeof(bs_pack_tail)) >> 32);
    SetFilePointer(hFile, (LONG)((LONGLONG)total_size - sizeof(bs_pack_tail)),
                   &high, FILE_BEGIN);
    DWORD read_bytes;
    ReadFile(hFile, &tail, sizeof(tail), &read_bytes, NULL);

    if (tail.tail_magic != BS_PACK_TAIL_MAGIC || tail.magic_check != BS_PACK_MAGIC)
        stub_fatal("This file is not protected or has been corrupted.");

    // перед tail — bs_pack_header с ключами/хешами
    bs_pack_header header;
    if (tail.header_size != sizeof(bs_pack_header))
        stub_fatal("Incompatible protection format version.");

    LONGLONG header_pos = (LONGLONG)total_size - sizeof(bs_pack_tail) - sizeof(bs_pack_header);
    high = (LONG)(header_pos >> 32);
    SetFilePointer(hFile, (LONG)header_pos, &high, FILE_BEGIN);
    ReadFile(hFile, &header, sizeof(header), &read_bytes, NULL);

    if (header.magic != BS_PACK_MAGIC ||
        (header.version != BS_PACK_VERSION_V3 && header.version != BS_PACK_VERSION_V4))
        stub_fatal("Invalid protection header.");

    // самопроверка .text stub (если протектор записал хеш)
    {
        unsigned char zero_hash[32] = {0};
        if (!stub_secure_cmp(header.stub_text_hash, zero_hash, 32)) {
            if (!stub_verify_self_integrity(header.stub_text_hash)) {
                stub_fatal("Stub code integrity check failed.\nThe loader has been modified.");
            }
        }
    }

    // aes_key/iv в заголовке xor — ключ через pbkdf2 от тела stub
    {
        unsigned char *stub_portion = (unsigned char*)malloc((size_t)header.payload_offset);
        if (!stub_portion)
            stub_fatal("Memory allocation failed.");

        LONG kdf_high = 0;
        SetFilePointer(hFile, 0, &kdf_high, FILE_BEGIN);
        DWORD kdf_read = 0;
        ReadFile(hFile, stub_portion, (DWORD)header.payload_offset, &kdf_read, NULL);

        unsigned char stub_kdf_hash[32];
        stub_sha256(stub_portion, (size_t)header.payload_offset, stub_kdf_hash);
        free(stub_portion);

        unsigned char hek[48];
        stub_pbkdf2_sha256(stub_kdf_hash, 32,
                           header.kdf_salt, BS_KDF_SALT_SIZE,
                           header.kdf_iterations, hek, 48);

        for (int i = 0; i < 32; i++) header.aes_key[i] ^= hek[i];
        for (int i = 0; i < 16; i++) header.aes_iv[i] ^= hek[32 + i];

        stub_secure_wipe(hek, sizeof(hek));
        stub_secure_wipe(stub_kdf_hash, sizeof(stub_kdf_hash));
    }

    // hmac по заголовку (без поля header_hmac)
    unsigned char hmac_key[32];
    stub_hmac_sha256(header.aes_key, 32,
                     (const unsigned char*)"BankShield-HMAC-Key-Derivation", 30,
                     hmac_key);

    unsigned char computed_hmac[32];
    size_t hmac_data_len = (size_t)((unsigned char*)&header.header_hmac - (unsigned char*)&header);
    stub_hmac_sha256(hmac_key, 32, (const unsigned char*)&header, hmac_data_len,
                     computed_hmac);

    if (!stub_secure_cmp(computed_hmac, header.header_hmac, 32))
        stub_fatal("Protection header integrity check failed.\nThe file may have been tampered with.");

    if (header.options & BS_OPT_ANTI_DEBUG) {  // antidebug по опции
        if (stub_check_debugger()) {
            stub_fatal("Security violation detected.\nApplication cannot run in this environment.");
        }
    }

    // ciphertext сразу после stub, offset в header
    if (header.encrypted_size > BS_MAX_PAYLOAD_SIZE || header.encrypted_size == 0)
        stub_fatal("Invalid payload size.");

    unsigned char *encrypted = (unsigned char*)VirtualAlloc(NULL, (SIZE_T)header.encrypted_size,
                                                            MEM_COMMIT, PAGE_READWRITE);
    if (!encrypted)
        stub_fatal("Memory allocation failed.");

    high = (LONG)((LONGLONG)header.payload_offset >> 32);
    SetFilePointer(hFile, (LONG)header.payload_offset, &high, FILE_BEGIN);
    
    size_t remaining = (size_t)header.encrypted_size;
    // на всякий — читаем чанками, exe бывают жирные
    size_t offset = 0;
    while (remaining > 0) {
        DWORD chunk = (DWORD)(remaining > 0x40000000 ? 0x40000000 : remaining);
        DWORD got;
        if (!ReadFile(hFile, encrypted + offset, chunk, &got, NULL) || got == 0) {
            VirtualFree(encrypted, 0, MEM_RELEASE);
            CloseHandle(hFile);
            stub_fatal("Failed to read encrypted payload.");
        }
        offset += got;
        remaining -= got;
    }
    CloseHandle(hFile);

    unsigned char enc_hash[32];
    stub_sha256(encrypted, (size_t)header.encrypted_size, enc_hash);
    if (!stub_secure_cmp(enc_hash, header.encrypted_hash, 32)) {
        VirtualFree(encrypted, 0, MEM_RELEASE);
        stub_fatal("Encrypted payload integrity check failed.\nThe file has been modified.");
    }

    if (header.version >= BS_PACK_VERSION_V4) {
        unsigned char mac_key[32], mac_chk[32];
        stub_hmac_sha256(header.aes_key, 32,
                         (const unsigned char*)"BankShield-Payload-MAC-Key-v4", 29,
                         mac_key);
        stub_pack_payload_mac(mac_key, header.aes_iv,
                              encrypted, (size_t)header.encrypted_size, mac_chk);
        stub_secure_wipe(mac_key, sizeof(mac_key));
        if (!stub_secure_cmp(mac_chk, header.payload_hmac, 32)) {
            VirtualFree(encrypted, 0, MEM_RELEASE);
            stub_fatal("Payload authentication failed (HMAC).\nCiphertext was tampered.");
        }
        stub_secure_wipe(mac_chk, sizeof(mac_chk));
    }

    stub_aes_cbc_decrypt(header.aes_key, header.aes_iv,
                          encrypted, (size_t)header.encrypted_size);

    size_t orig_size = (size_t)header.original_size;  // без паддинга
    unsigned char dec_hash[32];
    stub_sha256(encrypted, orig_size, dec_hash);
    if (!stub_secure_cmp(dec_hash, header.original_hash, 32)) {
        stub_secure_wipe(encrypted, (size_t)header.encrypted_size);
        VirtualFree(encrypted, 0, MEM_RELEASE);
        stub_fatal("Decryption integrity check failed.\nKeys may be corrupted.");
    }

    if (header.options & BS_OPT_INTEGRITY_CHECK) {  // полиморфная цепочка
        if (!stub_verify_hash_chain(&header, encrypted, orig_size)) {
            stub_secure_wipe(encrypted, (size_t)header.encrypted_size);
            VirtualFree(encrypted, 0, MEM_RELEASE);
            stub_fatal("Hash chain verification failed.\nThe original program has been altered.");
        }
    }

    int is_console_app = 0;
    {
        // глянем subsystem в pe — нужна ли консоль
        if (orig_size >= sizeof(IMAGE_DOS_HEADER)) {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)encrypted;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                DWORD pe_off = (DWORD)dos->e_lfanew;
                if (pe_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 72 <= orig_size) {
                    DWORD pe_sig = *(DWORD *)(encrypted + pe_off);
                    if (pe_sig == IMAGE_NT_SIGNATURE) {
                        IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *)(encrypted + pe_off + 4);
                        (void)fh;  // убрать warning
                        unsigned char *opt = encrypted + pe_off + 4 + sizeof(IMAGE_FILE_HEADER);
                        WORD magic = *(WORD *)opt;
                        WORD subsystem = 0;
                        if (magic == 0x20b) {
                            if (pe_off + 4 + sizeof(IMAGE_FILE_HEADER) + 70 <= orig_size)
                                subsystem = *(WORD *)(opt + 68);  // pe32+
                        } else {
                            if (pe_off + 4 + sizeof(IMAGE_FILE_HEADER) + 70 <= orig_size)
                                subsystem = *(WORD *)(opt + 68);
                        }
                        if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
                            is_console_app = 1;
                    }
                }
            }
        }
    }

    if (header.options & BS_OPT_ANTI_DEBUG) {  // ещё раз перед запуском
        if (stub_check_debugger()) {
            stub_secure_wipe(encrypted, (size_t)header.encrypted_size);
            VirtualFree(encrypted, 0, MEM_RELEASE);
            stub_fatal("Security violation detected.");
        }
    }

    if (is_console_app) {
        AllocConsole();  // stub gui, а payload консольный
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }

    DWORD saved_options = header.options;

    // runpe отключил — ловил 0xC0000141, надёжнее temp+CreateProcess

    char temp_path[MAX_PATH];
    stub_random_name(temp_path, MAX_PATH);
    {
        size_t tplen = strlen(temp_path);
        if (tplen > 4) { temp_path[tplen - 4] = '\0'; strcat(temp_path, ".exe"); }
    }

    HANDLE hTemp = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
                                NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        stub_secure_wipe(encrypted, (size_t)header.encrypted_size);
        VirtualFree(encrypted, 0, MEM_RELEASE);
        stub_fatal("Failed to create temporary file.");
    }

    DWORD written;
    remaining = orig_size;
    offset = 0;
    while (remaining > 0) {
        DWORD chunk = (DWORD)(remaining > 0x40000000 ? 0x40000000 : remaining);
        WriteFile(hTemp, encrypted + offset, chunk, &written, NULL);
        offset += written;
        remaining -= written;
    }
    CloseHandle(hTemp);

    stub_secure_wipe(encrypted, (size_t)header.encrypted_size);  // не оставляем plain в памяти
    VirtualFree(encrypted, 0, MEM_RELEASE);
    stub_secure_wipe(&header, sizeof(header));
    stub_secure_wipe(hmac_key, sizeof(hmac_key));

    if (saved_options & BS_OPT_HIDE_TEMP)
        SetFileAttributesA(temp_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    char *orig_cmdline = GetCommandLineA();
    char *args = orig_cmdline;
    if (args[0] == '"') { args = strchr(args + 1, '"'); if (args) args++; }
    else { while (*args && *args != ' ') args++; }
    while (*args == ' ') args++;

    char cmdline[32768];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", temp_path, args);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    DWORD create_flags = 0;
    BOOL inherit_handles = FALSE;

    if (is_console_app) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        inherit_handles = TRUE;
    } else {
        create_flags = DETACHED_PROCESS;
    }

    if (!CreateProcessA(temp_path, cmdline, NULL, NULL, inherit_handles,
                         create_flags, NULL, NULL, &si, &pi)) {
        DeleteFileA(temp_path);
        stub_fatal("Failed to launch the application.");
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    for (int i = 0; i < 10; i++) {
        if (DeleteFileA(temp_path)) break;
        Sleep(100);
    }

    ExitProcess(exit_code);
    return 0;
}
