/*
 * BankShield — безопасная работа с памятью
 * Учебный проект, 2026
 *
 * Возможности:
 *   - шифрованные выделения в куче
 *   - guard-страницы вокруг буферов
 *   - затирание при освобождении
 *   - регионы, исключённые из дампов
 *   - канарейки против переполнения
 */

#ifndef BS_SECURE_MEM_H
#define BS_SECURE_MEM_H

#include <stdint.h>
#include <stddef.h>

// Флаги защиты памяти
#define BS_MEM_ENCRYPTED    0x01  // шифровать содержимое в покое
#define BS_MEM_GUARD_PAGES  0x02  // guard-страницы
#define BS_MEM_NO_DUMP      0x04  // не попадать в дампы памяти
#define BS_MEM_CANARY       0x08  // канарейки
#define BS_MEM_WIPE_ON_FREE 0x10  // затирание при free

// Максимальная защита по умолчанию
#define BS_MEM_MAX_SECURITY \
    (BS_MEM_ENCRYPTED | BS_MEM_GUARD_PAGES | BS_MEM_NO_DUMP | \
     BS_MEM_CANARY | BS_MEM_WIPE_ON_FREE)

typedef struct bs_secure_alloc bs_secure_alloc;

// Инициализация подсистемы
int bs_secure_mem_init(void);

// Завершение и затирание всех защищённых блоков
void bs_secure_mem_shutdown(void);

// Выделить защищённую память
void* bs_secure_malloc(size_t size, uint32_t flags);

// Освободить (с затиранием, если включён флаг)
void bs_secure_free(void *ptr);

// Заблокировать регион (нужен unlock для доступа)
int bs_secure_lock(void *ptr);

// Разблокировать для чтения/записи
int bs_secure_unlock(void *ptr);

// Перешифровать регион новым ключом
int bs_secure_rekey(void *ptr);

// Проверить канарейки
int bs_secure_check_canary(void *ptr);

// === Безопасные операции со строками ===

// Копия строки в защищённую память
char* bs_secure_strdup(const char *str, uint32_t flags);

// Конкатенация в защищённый буфер
int bs_secure_strcat(char *dst, size_t dst_size, const char *src);

// === Зашифрованный буфер ===

typedef struct {
    uint8_t *cipher_data;
    size_t   data_size;
    uint8_t  key[32];
    uint8_t  iv[16];
    uint32_t flags;
} bs_encrypted_buffer;

// Создать зашифрованный буфер из открытого текста
int bs_encrypted_buffer_create(bs_encrypted_buffer *buf,
                                const void *data, size_t size);

// Открыть — временный вид в открытом виде (нужно закрыть)
void* bs_encrypted_buffer_open(bs_encrypted_buffer *buf);

// Закрыть — снова зашифровать и освободить plaintext
void bs_encrypted_buffer_close(bs_encrypted_buffer *buf, void *plaintext);

// Уничтожить буфер со затиранием
void bs_encrypted_buffer_destroy(bs_encrypted_buffer *buf);

#endif  // BS_SECURE_MEM_H
