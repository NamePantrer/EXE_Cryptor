/*
 * BankShield — шифрование строк на этапе компиляции
 * Учебный проект, 2026
 *
 * Чувствительные строки не лежат в бинарнике открытым текстом.
 * Расшифровка только в рантайме, потом память затирается.
 */

#ifndef BS_STRING_CRYPT_H
#define BS_STRING_CRYPT_H

#include <stdint.h>
#include <stddef.h>

// Максимальная длина зашифрованной строки
#define BS_MAX_ENC_STRING 512

// Дескриптор зашифрованной строки
typedef struct {
    uint8_t  data[BS_MAX_ENC_STRING];
    uint16_t length;
    uint8_t  key;  // XOR-ключ для быстрого слоя
    uint32_t seed;  // сид для зависимости от позиции байта
} bs_enc_string;

// === Макросы обфускации на этапе компиляции ===

/*
 * Несколько слоёв:
 * 1) XOR с ключом, зависящим от позиции
 * 2) подстановка через S-box (в макросах ниже — упрощённый вариант)
 * 3) побитовые сдвиги
 */

// Зашифровать один байт на этапе компиляции
#define BS_ENC_BYTE(c, key, pos) \
    ((uint8_t)(((c) ^ ((key) + (pos) * 0x9E)) + ((pos) ^ 0x5A)))

// Расшифровать один байт в рантайме
static inline uint8_t bs_dec_byte(uint8_t c, uint8_t key, uint32_t pos) {
    c = (uint8_t)(c - ((pos) ^ 0x5A));
    c = c ^ (uint8_t)((key) + (pos) * 0x9E);
    return c;
}

// Расшифровать строку по дескриптору
void bs_string_decrypt(const bs_enc_string *enc, char *out, size_t out_size);

// Зашифровать строку в рантайме (для динамических строк)
void bs_string_encrypt(const char *plain, bs_enc_string *out, uint8_t key);

// Безопасно затереть расшифрованную строку
void bs_string_wipe(char *str, size_t len);

// === Глобальная таблица зашифрованных строк ===

// Добавить строку в таблицу
int bs_string_table_add(const char *id, const char *plain);

// Достать и расшифровать строку по id
int bs_string_table_get(const char *id, char *out, size_t out_size);

// Уничтожить всю таблицу
void bs_string_table_destroy(void);

// === Макрос: расшифровка на стеке ===

/*
 * Пример:
 *   BS_DECRYPTED_STRING(my_str, "\x8a\x9b\xac...", 12, 0x42);
 *   printf("%s\n", my_str);
 *   BS_WIPE_STRING(my_str, 12);
 */
#define BS_DECRYPTED_STRING(name, enc_data, enc_len, enc_key) \
    char name[(enc_len) + 1]; \
    do { \
        const uint8_t *_ed = (const uint8_t*)(enc_data); \
        for (uint32_t _i = 0; _i < (enc_len); _i++) { \
            (name)[_i] = (char)bs_dec_byte(_ed[_i], (enc_key), _i); \
        } \
        (name)[(enc_len)] = '\0'; \
    } while(0)

#define BS_WIPE_STRING(name, len) \
    do { \
        volatile char *_p = (volatile char*)(name); \
        for (size_t _i = 0; _i < (len) + 1; _i++) _p[_i] = 0; \
    } while(0)

#endif  // BS_STRING_CRYPT_H
