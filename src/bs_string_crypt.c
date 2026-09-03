/*
 * BankShield — шифрование строк (реализация)
 * Учебный проект, 2026
 */

#include "../include/bs_string_crypt.h"
#include "../include/bs_crypto.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Шифрование / расшифровка строк в рантайме
 * ================================================================ */

void bs_string_decrypt(const bs_enc_string *enc, char *out, size_t out_size) {
    size_t len = enc->length;
    if (len >= out_size) len = out_size - 1;
    
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (char)bs_dec_byte(enc->data[i], enc->key, i);
    }
    out[len] = '\0';
}

void bs_string_encrypt(const char *plain, bs_enc_string *out, uint8_t key) {
    size_t len = strlen(plain);
    if (len > BS_MAX_ENC_STRING) len = BS_MAX_ENC_STRING;
    
    out->key = key;
    out->length = (uint16_t)len;
    out->seed = 0;
    
    for (uint32_t i = 0; i < len; i++) {
        out->data[i] = BS_ENC_BYTE((uint8_t)plain[i], key, i);
    }
}

void bs_string_wipe(char *str, size_t len) {
    volatile char *p = (volatile char *)str;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

/* ================================================================
 * Таблица строк (реестр зашифрованных строк)
 * ================================================================ */

#define MAX_TABLE_ENTRIES 256

typedef struct {
    char id[64];
    bs_enc_string enc;
    int used;
} string_table_entry;

static string_table_entry g_string_table[MAX_TABLE_ENTRIES];
static int g_table_init = 0;
static uint8_t g_table_key = 0;

static void ensure_table_init(void) {
    if (!g_table_init) {
        memset(g_string_table, 0, sizeof(g_string_table));
        // один ключ на всю таблицу (рандом из csprng)
        bs_csprng_fill(&g_table_key, 1);
        if (g_table_key == 0) g_table_key = 0x42;
        g_table_init = 1;
    }
}

int bs_string_table_add(const char *id, const char *plain) {
    ensure_table_init();
    
    // ищем слот — или обновляем по id
    int slot = -1;
    for (int i = 0; i < MAX_TABLE_ENTRIES; i++) {
        if (!g_string_table[i].used) {
            if (slot < 0) slot = i;
        } else if (strncmp(g_string_table[i].id, id, 63) == 0) {
            slot = i;  // уже есть такой id
            break;
        }
    }
    
    if (slot < 0) return -1;  // 256 слотов кончились
    
    strncpy(g_string_table[slot].id, id, 63);
    g_string_table[slot].id[63] = '\0';
    bs_string_encrypt(plain, &g_string_table[slot].enc, g_table_key);
    g_string_table[slot].used = 1;
    
    return 0;
}

int bs_string_table_get(const char *id, char *out, size_t out_size) {
    ensure_table_init();
    
    for (int i = 0; i < MAX_TABLE_ENTRIES; i++) {
        if (g_string_table[i].used && 
            strncmp(g_string_table[i].id, id, 63) == 0) {
            bs_string_decrypt(&g_string_table[i].enc, out, out_size);
            return 0;
        }
    }
    
    return -1;
}

void bs_string_table_destroy(void) {
    // при выходе — затереть таблицу
    volatile uint8_t *p = (volatile uint8_t*)g_string_table;
    for (size_t i = 0; i < sizeof(g_string_table); i++) p[i] = 0;
    g_table_init = 0;
    g_table_key = 0;
}
