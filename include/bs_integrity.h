/*
 * BankShield — проверка целостности
 * Учебный проект, 2026
 *
 * Самопроверка EXE:
 *   - хеши секций PE
 *   - CRC32 сегментов кода
 *   - якорь цепочки хешей
 *   - повторная проверка в рантайме
 *   - валидация таблицы импорта
 */

#ifndef BS_INTEGRITY_H
#define BS_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>
#include "bs_crypto.h"

// Максимум отслеживаемых секций
#define BS_MAX_SECTIONS 32

// Запись целостности одной секции PE
typedef struct {
    char     name[8];
    uint32_t virt_addr;
    uint32_t virt_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint8_t  sha256[BS_SHA256_DIGEST_SIZE];
    uint32_t crc32;
} bs_section_record;

// Манифест целостности, вшивается в EXE
typedef struct {
    uint32_t magic;  // 0x42534844 = 'BSHD'
    uint32_t version;
    uint32_t section_count;
    bs_section_record sections[BS_MAX_SECTIONS];
    uint8_t  master_hash[BS_SHA256_DIGEST_SIZE];  // хеш всех хешей секций
    bs_hash_chain chain;  // полиморфная цепочка для master
    uint8_t  hmac[BS_HMAC_SHA256_SIZE];  // HMAC по всему манифесту
} bs_integrity_manifest;

// === Функции на этапе сборки (утилита протектора) ===

// Посчитать CRC32
uint32_t bs_crc32(const uint8_t *data, size_t len);

// Собрать манифест из PE на диске
int bs_integrity_build_manifest(const char *pe_path,
                                 const uint8_t hmac_key[32],
                                 bs_integrity_manifest *out);

// Вшить манифест в overlay или новую секцию PE
int bs_integrity_embed_manifest(const char *pe_path,
                                 const bs_integrity_manifest *manifest);

// === Функции в рантайме (защищённое приложение) ===

// Проверить целостность своего EXE при старте
int bs_integrity_verify_self(void);

// Проверить регион памяти по ожидаемому хешу
int bs_integrity_verify_region(const void *addr, size_t size,
                                const uint8_t expected_sha256[BS_SHA256_DIGEST_SIZE]);

// Периодический мониторинг целостности
int bs_integrity_start_monitor(uint32_t interval_ms);
void bs_integrity_stop_monitor(void);

// Текстовое описание кода результата
const char* bs_integrity_status_string(int result_code);

#endif  // BS_INTEGRITY_H
