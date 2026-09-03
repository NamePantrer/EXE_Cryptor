/*
 * BankShield — формат упаковки (pack format)
 * Учебный проект, 2026
 *
 * Общие структуры для утилиты-протектора и загрузчика (stub).
 * Описывает бинарный формат зашифрованной нагрузки в конце EXE.
 *
 * Схема защищённого файла:
 * ┌─────────────────────────────┐
 * │  Загрузчик stub (.exe)      │  ← запускается первым, внутри расшифровка
 * ├─────────────────────────────┤
 * │  Зашифрованная нагрузка     │  ← оригинальный EXE, AES-256-CBC
 * ├─────────────────────────────┤
 * │  bs_pack_header             │  ← ключи, хеши, метаданные
 * ├─────────────────────────────┤
 * │  BS_PACK_TAIL_MAGIC (8 Б)  │  ← метка в конце файла для поиска заголовка
 * └─────────────────────────────┘
 */

#ifndef BS_PACK_FORMAT_H
#define BS_PACK_FORMAT_H

#include <stdint.h>

// Магические байты — признак файла BankShield
#define BS_PACK_MAGIC       0x42534B50  // 'BSKP'
#define BS_PACK_VERSION_V3  3
#define BS_PACK_VERSION_V4  4
#define BS_PACK_VERSION     BS_PACK_VERSION_V4
#define BS_PACK_TAIL_MAGIC  0x425348454E444242ULL  // 'BSHENDBB'

// Максимальный размер исходного EXE: 500 МБ
#define BS_MAX_PAYLOAD_SIZE (500ULL * 1024 * 1024)

// Параметры шифрования
#define BS_PACK_KEY_SIZE    32  // AES-256
#define BS_PACK_IV_SIZE     16
#define BS_PACK_HASH_SIZE   32  // SHA-256
#define BS_PACK_SALT_SIZE   16

// Глубина полиморфной цепочки хешей
#define BS_PACK_CHAIN_DEPTH 8

// PBKDF2 (привязка ключей к stub)
#define BS_KDF_SALT_SIZE       32
#define BS_KDF_ITERATIONS_V3   10000u    // старые файлы v3
#define BS_KDF_ITERATIONS_V4   100000u   // v4: OWASP-минимум для PBKDF2-SHA256
#define BS_KDF_ITERATIONS      BS_KDF_ITERATIONS_V4

// Флаги опций для защищённого EXE
#define BS_OPT_ANTI_DEBUG       0x0001  // проверки anti-debug
#define BS_OPT_ANTI_VM          0x0002  // блокировать ВМ
#define BS_OPT_INTEGRITY_CHECK  0x0004  // проверка целостности
#define BS_OPT_DELETE_ON_RUN    0x0008  // самоудаление после первого запуска
#define BS_OPT_MEMORY_ONLY      0x0010  // не писать расшифрованное на диск (пока не сделано)
#define BS_OPT_HIDE_TEMP        0x0020  // скрывать временные файлы

// Защита по умолчанию
#define BS_OPT_DEFAULT (BS_OPT_ANTI_DEBUG | BS_OPT_INTEGRITY_CHECK | BS_OPT_HIDE_TEMP)

/*
 * Заголовок пакета — перед хвостовой магией в конце файла.
 * Stub читает свой файл, ищет tail magic (конец − 8 байт),
 * потом заголовок, потом зашифрованную нагрузку.
 */
typedef struct {
// Идентификация
    uint32_t magic;  // BS_PACK_MAGIC
    uint32_t version;  // BS_PACK_VERSION
    uint32_t header_size;  // sizeof(bs_pack_header)

// Информация о нагрузке
    uint64_t original_size;  // размер оригинала до шифрования
    uint64_t encrypted_size;  // размер после шифрования (с паддингом)
    uint64_t payload_offset;  // смещение нагрузки от начала файла

// Ключи шифрования
    uint8_t  aes_key[BS_PACK_KEY_SIZE];  // ключ AES-256
    uint8_t  aes_iv[BS_PACK_IV_SIZE];  // IV AES-256

// Проверка целостности
    uint8_t  original_hash[BS_PACK_HASH_SIZE];  // SHA-256 оригинала
    uint8_t  encrypted_hash[BS_PACK_HASH_SIZE];  // SHA-256 зашифрованной нагрузки

// Полиморфная цепочка для оригинала
    uint8_t  chain_salt[BS_PACK_SALT_SIZE];
    uint32_t chain_iterations;
    uint8_t  chain_hashes[BS_PACK_CHAIN_DEPTH][BS_PACK_HASH_SIZE];
    uint8_t  chain_final[BS_PACK_HASH_SIZE];

// HMAC по заголовку (это поле в расчёт не входит)
    uint8_t  header_hmac[BS_PACK_HASH_SIZE];

// Опции защиты
    uint32_t options;                            /* флаги BS_OPT_* */

// Антивзлом: хеш части stub
    uint8_t  stub_hash[BS_PACK_HASH_SIZE];

// KDF: aes_key / aes_iv / (v4) mac_key — XOR с PBKDF2
    uint8_t  kdf_salt[BS_KDF_SALT_SIZE];
    uint32_t kdf_iterations;

// Самопроверка: хеш секции .text stub на этапе сборки
    uint8_t  stub_text_hash[BS_PACK_HASH_SIZE];

// v4: HMAC ciphertext (проверка до decrypt); ключ MAC = KDF(aes_key)
    uint8_t  payload_hmac[BS_PACK_HASH_SIZE];

    uint8_t  reserved[32];  // было 64 в v3 — размер заголовка не меняли
} bs_pack_header;

/*
 * Хвост в самом конце защищённого файла.
 * Stub переходит к (размер_файла − sizeof(bs_pack_tail)).
 */
typedef struct {
    uint32_t header_size;  // размер bs_pack_header
    uint32_t magic_check;  // BS_PACK_MAGIC для проверки
    uint64_t tail_magic;  // BS_PACK_TAIL_MAGIC
} bs_pack_tail;

#endif  // BS_PACK_FORMAT_H
