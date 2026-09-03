/*
 * BankShield — безопасная память (реализация)
 * Учебный проект, 2026
 */

#include "../include/bs_secure_mem.h"
#include "../include/bs_crypto.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* ================================================================
 * Внутний учёт выделений
 * ================================================================ */

#define CANARY_SIZE 16
#define CANARY_MAGIC 0xDEADBEEFCAFEBABEULL
#define MAX_TRACKED 1024

typedef struct {
    void     *ptr;  // указатель для пользователя
    void     *real_ptr;  // реальное начало блока (guard/канарейки)
    size_t    user_size;  // запрошенный размер
    size_t    real_size;  // полный размер выделения
    uint32_t  flags;
    uint8_t   enc_key[32];  // ключ шифрования для этого блока
    uint8_t   enc_iv[16];
    uint8_t   canary_front[CANARY_SIZE];
    uint8_t   canary_back[CANARY_SIZE];
    int       locked;  // 1 = сейчас зашифровано
} alloc_entry;

static alloc_entry g_allocs[MAX_TRACKED];
static int g_alloc_count = 0;
static int g_initialized = 0;

// Найти запись по пользовательскому указателю
static alloc_entry* find_entry(void *ptr) {
    for (int i = 0; i < g_alloc_count; i++) {
        if (g_allocs[i].ptr == ptr)
            return &g_allocs[i];
    }
    return NULL;
}

/* ================================================================
 * Публичный API
 * ================================================================ */

int bs_secure_mem_init(void) {
    memset(g_allocs, 0, sizeof(g_allocs));
    g_alloc_count = 0;
    g_initialized = 1;
    return 0;
}

void bs_secure_mem_shutdown(void) {
// Затереть и освободить все блоки
    for (int i = 0; i < g_alloc_count; i++) {
        if (g_allocs[i].real_ptr) {
            bs_secure_zero(g_allocs[i].real_ptr, g_allocs[i].real_size);
#ifdef _WIN32
            if (g_allocs[i].flags & BS_MEM_GUARD_PAGES) {
                VirtualFree(g_allocs[i].real_ptr, 0, MEM_RELEASE);
            } else {
                free(g_allocs[i].real_ptr);
            }
#else
            free(g_allocs[i].real_ptr);
#endif
        }
    }
    bs_secure_zero(g_allocs, sizeof(g_allocs));
    g_alloc_count = 0;
    g_initialized = 0;
}

void* bs_secure_malloc(size_t size, uint32_t flags) {
    if (!g_initialized || g_alloc_count >= MAX_TRACKED || size == 0)
        return NULL;
    
    alloc_entry *entry = &g_allocs[g_alloc_count];
    memset(entry, 0, sizeof(*entry));
    entry->flags = flags;
    entry->user_size = size;
    
// Полный размер с канарейками
    size_t total = size;
    if (flags & BS_MEM_CANARY)
        total += CANARY_SIZE * 2;
    
// Округление до блока AES, если включено шифрование
    if (flags & BS_MEM_ENCRYPTED) {
        total = ((total + 15) / 16) * 16;
    }
    
    entry->real_size = total;
    
#ifdef _WIN32
    if (flags & BS_MEM_GUARD_PAGES) {
    // Выделение с guard-страницами по краям
        DWORD page_size = 4096;
        size_t alloc_size = ((total + page_size - 1) / page_size + 2) * page_size;
        
        uint8_t *base = (uint8_t*)VirtualAlloc(NULL, alloc_size,
                                                 MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_READWRITE);
        if (!base) return NULL;
        
// Первая и последняя страница — PAGE_NOACCESS
        DWORD old;
        VirtualProtect(base, page_size, PAGE_NOACCESS, &old);
        VirtualProtect(base + alloc_size - page_size, page_size, PAGE_NOACCESS, &old);
        
        entry->real_ptr = base;
        entry->ptr = base + page_size;  // пользовательский указатель после guard
        entry->real_size = alloc_size;
    } else
#endif
    {
        entry->real_ptr = malloc(total);
        if (!entry->real_ptr) return NULL;
        entry->ptr = (flags & BS_MEM_CANARY) ? 
            (uint8_t*)entry->real_ptr + CANARY_SIZE : entry->real_ptr;
    }
    
// Обнуляем выделение
    memset(entry->real_ptr, 0, 
           (flags & BS_MEM_GUARD_PAGES) ? 0 : total);  // при guard уже нули
    
// Ставим канарейки
    if (flags & BS_MEM_CANARY) {
        bs_csprng_fill(entry->canary_front, CANARY_SIZE);
        bs_csprng_fill(entry->canary_back, CANARY_SIZE);
        
        if (!(flags & BS_MEM_GUARD_PAGES)) {
            memcpy(entry->real_ptr, entry->canary_front, CANARY_SIZE);
            memcpy((uint8_t*)entry->ptr + size, entry->canary_back, CANARY_SIZE);
        }
    }
    
// Свой ключ шифрования на блок
    if (flags & BS_MEM_ENCRYPTED) {
        bs_generate_key(entry->enc_key);
        bs_generate_iv(entry->enc_iv);
    }
    
#ifdef _WIN32
// По возможности не попадать в дампы
    if (flags & BS_MEM_NO_DUMP) {
    // На новых Windows есть MEM_EXCLUDE_FROM_DUMP; здесь VirtualLock
        VirtualLock(entry->ptr, size);
    }
#endif
    
    entry->locked = 0;
    g_alloc_count++;
    
    return entry->ptr;
}

void bs_secure_free(void *ptr) {
    if (!ptr) return;
    
    alloc_entry *entry = find_entry(ptr);
    if (!entry) return;
    
// Затираем содержимое
    if (entry->flags & BS_MEM_WIPE_ON_FREE) {
    // Несколько проходов затирания
        size_t wipe_size = entry->user_size;
        volatile uint8_t *p = (volatile uint8_t*)ptr;
        
// Проход 1: нули
        for (size_t i = 0; i < wipe_size; i++) p[i] = 0x00;
        // Проход 2: 0xFF
        for (size_t i = 0; i < wipe_size; i++) p[i] = 0xFF;
        // Проход 3: случайные байты
        uint8_t *rand_buf = (uint8_t*)malloc(wipe_size);
        if (rand_buf) {
            bs_csprng_fill(rand_buf, wipe_size);
            for (size_t i = 0; i < wipe_size; i++) p[i] = rand_buf[i];
            bs_secure_zero(rand_buf, wipe_size);
            free(rand_buf);
        }
        // Проход 4: снова нули
        for (size_t i = 0; i < wipe_size; i++) p[i] = 0x00;
    }
    
// Затираем ключи
    bs_secure_zero(entry->enc_key, sizeof(entry->enc_key));
    bs_secure_zero(entry->enc_iv, sizeof(entry->enc_iv));
    
// Освобождаем память
#ifdef _WIN32
    if (entry->flags & BS_MEM_GUARD_PAGES) {
        VirtualFree(entry->real_ptr, 0, MEM_RELEASE);
    } else {
        free(entry->real_ptr);
    }
#else
    free(entry->real_ptr);
#endif
    
// Убираем из таблицы
    entry->ptr = NULL;
    entry->real_ptr = NULL;
}

int bs_secure_lock(void *ptr) {
    alloc_entry *entry = find_entry(ptr);
    if (!entry || entry->locked || !(entry->flags & BS_MEM_ENCRYPTED))
        return -1;
    
// Шифруем данные на месте
    size_t enc_size = ((entry->user_size + 15) / 16) * 16;
    bs_aes_ctx aes;
    uint8_t iv_copy[16];
    memcpy(iv_copy, entry->enc_iv, 16);
    bs_aes_init(&aes, entry->enc_key, iv_copy);
    bs_aes_cbc_encrypt(&aes, (uint8_t*)ptr, enc_size);
    bs_secure_zero(&aes, sizeof(aes));
    
    entry->locked = 1;
    return 0;
}

int bs_secure_unlock(void *ptr) {
    alloc_entry *entry = find_entry(ptr);
    if (!entry || !entry->locked || !(entry->flags & BS_MEM_ENCRYPTED))
        return -1;
    
// Расшифровываем на месте
    size_t enc_size = ((entry->user_size + 15) / 16) * 16;
    bs_aes_ctx aes;
    uint8_t iv_copy[16];
    memcpy(iv_copy, entry->enc_iv, 16);
    bs_aes_init(&aes, entry->enc_key, iv_copy);
    bs_aes_cbc_decrypt(&aes, (uint8_t*)ptr, enc_size);
    bs_secure_zero(&aes, sizeof(aes));
    
    entry->locked = 0;
    return 0;
}

int bs_secure_rekey(void *ptr) {
    alloc_entry *entry = find_entry(ptr);
    if (!entry || !(entry->flags & BS_MEM_ENCRYPTED))
        return -1;
    
// Если заблокировано — сначала расшифровать
    if (entry->locked) {
        bs_secure_unlock(ptr);
    }
    
// Новый ключ и IV
    bs_generate_key(entry->enc_key);
    bs_generate_iv(entry->enc_iv);
    
// Снова заблокировать, если нужно
    bs_secure_lock(ptr);
    
    return 0;
}

int bs_secure_check_canary(void *ptr) {
    alloc_entry *entry = find_entry(ptr);
    if (!entry || !(entry->flags & BS_MEM_CANARY))
        return -1;
    
    if (!(entry->flags & BS_MEM_GUARD_PAGES)) {
    // Передняя канарейка
        if (!bs_secure_compare((uint8_t*)entry->real_ptr,
                               entry->canary_front, CANARY_SIZE))
            return -2;  // переполнение снизу
        
// Задняя канарейка
        if (!bs_secure_compare((uint8_t*)entry->ptr + entry->user_size,
                               entry->canary_back, CANARY_SIZE))
            return -3;  // переполнение сверху
    }
    
    return 0;
}

/* ================================================================
 * Безопасные строки
 * ================================================================ */

char* bs_secure_strdup(const char *str, uint32_t flags) {
    size_t len = strlen(str) + 1;
    char *dst = (char*)bs_secure_malloc(len, flags);
    if (dst) {
        memcpy(dst, str, len);
    }
    return dst;
}

/* ================================================================
 * Зашифрованный буфер
 * ================================================================ */

int bs_encrypted_buffer_create(bs_encrypted_buffer *buf,
                                const void *data, size_t size) {
    if (!buf || !data || size == 0)
        return -1;
    
    buf->data_size = size;
    buf->flags = 0;
    
// Ключ и IV
    bs_generate_key(buf->key);
    bs_generate_iv(buf->iv);
    
// Буфер с запасом под PKCS7
    size_t padded = ((size + 15) / 16) * 16;
    buf->cipher_data = (uint8_t*)malloc(padded);
    if (!buf->cipher_data) return -2;
    
// Копия и паддинг
    memcpy(buf->cipher_data, data, size);
    size_t actual_padded = bs_aes_pad(buf->cipher_data, size, padded);
    if (actual_padded == 0) {
        free(buf->cipher_data);
        return -3;
    }
    
// Шифруем
    bs_aes_ctx aes;
    bs_aes_init(&aes, buf->key, buf->iv);
    bs_aes_cbc_encrypt(&aes, buf->cipher_data, actual_padded);
    bs_secure_zero(&aes, sizeof(aes));
    
    return 0;
}

void* bs_encrypted_buffer_open(bs_encrypted_buffer *buf) {
    if (!buf || !buf->cipher_data) return NULL;
    
    size_t padded = ((buf->data_size + 15) / 16) * 16;
    uint8_t *plain = (uint8_t*)malloc(padded);
    if (!plain) return NULL;
    
    memcpy(plain, buf->cipher_data, padded);
    
    bs_aes_ctx aes;
    uint8_t iv_copy[16];
    memcpy(iv_copy, buf->iv, 16);
    bs_aes_init(&aes, buf->key, iv_copy);
    bs_aes_cbc_decrypt(&aes, plain, padded);
    bs_secure_zero(&aes, sizeof(aes));
    
    return plain;
}

void bs_encrypted_buffer_close(bs_encrypted_buffer *buf, void *plaintext) {
    if (!plaintext) return;
    
    size_t padded = ((buf->data_size + 15) / 16) * 16;
    
// Новый IV при закрытии (forward secrecy)
    bs_generate_iv(buf->iv);
    
    bs_aes_ctx aes;
    bs_aes_init(&aes, buf->key, buf->iv);
    
// Паддинг открытого текста
    memset((uint8_t*)plaintext + buf->data_size, 0, padded - buf->data_size);
    bs_aes_pad((uint8_t*)plaintext, buf->data_size, padded);
    
// Шифруем и сохраняем
    bs_aes_cbc_encrypt(&aes, (uint8_t*)plaintext, padded);
    memcpy(buf->cipher_data, plaintext, padded);
    
// Затираем открытый текст
    bs_secure_zero(plaintext, padded);
    free(plaintext);
    bs_secure_zero(&aes, sizeof(aes));
}

void bs_encrypted_buffer_destroy(bs_encrypted_buffer *buf) {
    if (!buf) return;
    if (buf->cipher_data) {
        size_t padded = ((buf->data_size + 15) / 16) * 16;
        bs_secure_zero(buf->cipher_data, padded);
        free(buf->cipher_data);
    }
    bs_secure_zero(buf->key, sizeof(buf->key));
    bs_secure_zero(buf->iv, sizeof(buf->iv));
    memset(buf, 0, sizeof(*buf));
}
