/*
 * BankShield — PE-протектор (версия 1)
 * Учебный проект, 2026
 *
 * Утилита после сборки:
 *   1. Читает готовый PE (.exe)
 *   2. Считает хеши секций (SHA-256 + CRC32)
 *   3. Строит полиморфную цепочку хешей
 *   4. Шифрует код/данные AES-256-CBC
 *   5. Пишет защищённый PE с манифестом целостности
 *
 * Запуск: bs_protect <input.exe> <output.exe>
 */

#include "../include/bs_crypto.h"
#include "../include/bs_integrity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* ================================================================
 * Вспомогательные функции для PE
 * ================================================================ */

typedef struct {
    uint8_t  *data;
    size_t    size;
} pe_buffer;

static int pe_read_file(const char *path, pe_buffer *buf) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    buf->size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    
    buf->data = (uint8_t*)malloc(buf->size);
    if (!buf->data) { fclose(f); return -2; }
    
    if (fread(buf->data, 1, buf->size, f) != buf->size) {
        free(buf->data);
        fclose(f);
        return -3;
    }
    
    fclose(f);
    return 0;
}

static int pe_write_file(const char *path, const pe_buffer *buf) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    
    if (fwrite(buf->data, 1, buf->size, f) != buf->size) {
        fclose(f);
        return -2;
    }
    
    fclose(f);
    return 0;
}

/* ================================================================
 * Шифрование секций
 * ================================================================ */

typedef struct {
    uint8_t  key[BS_AES_KEY_SIZE];
    uint8_t  iv[BS_AES_BLOCK_SIZE];
    uint32_t section_index;
    uint32_t original_offset;
    uint32_t original_size;
    uint8_t  original_hash[BS_SHA256_DIGEST_SIZE];
} encrypted_section_info;

#define MAX_ENCRYPTED_SECTIONS 16

typedef struct {
    uint32_t                magic;  // 'BSPK' = 0x4253504B
    uint32_t                version;
    uint32_t                enc_count;
    encrypted_section_info  sections[MAX_ENCRYPTED_SECTIONS];
    uint8_t                 master_key[BS_AES_KEY_SIZE];  // мастер-ключ
    bs_hash_chain           chain;
    uint8_t                 manifest_hmac[BS_HMAC_SHA256_SIZE];
} protection_pack;

static int encrypt_section(uint8_t *section_data, uint32_t size,
                            const uint8_t key[32], const uint8_t iv[16]) {
                            // Размер кратен 16 байтам (блок AES)
    uint32_t aligned = (size + 15) & ~15u;
    
    bs_aes_ctx aes;
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    bs_aes_init(&aes, key, iv_copy);
    bs_aes_cbc_encrypt(&aes, section_data, aligned);
    bs_secure_zero(&aes, sizeof(aes));
    
    return 0;
}

/* ================================================================
 * Основной процесс защиты
 * ================================================================ */

static void print_hash(const char *label, const uint8_t *hash) {
    char hex[65];
    bs_hash_to_hex(hash, 32, hex);
    printf("  %s: %s\n", label, hex);
}

static int protect_pe(const char *input_path, const char *output_path) {
    printf("[*] BankShield PE Protector v1.0\n");
    printf("[*] Input:  %s\n", input_path);
    printf("[*] Output: %s\n\n", output_path);
    
    // грузим pe в память целиком
    pe_buffer pe;
    if (pe_read_file(input_path, &pe) != 0) {
        printf("[!] Failed to read input file\n");
        return -1;
    }
    
    printf("[+] Read %zu bytes\n", pe.size);
    
    // mz + pe signature
    if (pe.size < sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] File too small for PE\n");
        free(pe.data);
        return -2;
    }
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pe.data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        free(pe.data);
        return -3;
    }
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(pe.data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid PE signature\n");
        free(pe.data);
        return -4;
    }
    
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    WORD num_sections = nt->FileHeader.NumberOfSections;
    
    printf("[+] Found %d sections\n\n", num_sections);
    
    // --- сначала хеши секций ---
    printf("=== Phase 1: Hash Generation ===\n");
    
    protection_pack pack;
    memset(&pack, 0, sizeof(pack));
    pack.magic = 0x4253504B;
    pack.version = 1;
    pack.enc_count = 0;
    
    bs_sha256_ctx master_ctx;
    bs_sha256_init(&master_ctx);
    
    for (WORD i = 0; i < num_sections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        
        uint32_t raw_off = sections[i].PointerToRawData;
        uint32_t raw_size = sections[i].SizeOfRawData;
        
        printf("  Section [%s] offset=0x%08X size=0x%08X\n", name, raw_off, raw_size);
        
        if (raw_size > 0 && raw_off > 0 && raw_off + raw_size <= pe.size) {
            uint8_t hash[32];
            bs_sha256(pe.data + raw_off, raw_size, hash);
            uint32_t crc = bs_crc32(pe.data + raw_off, raw_size);
            
            print_hash("SHA-256", hash);
            printf("  CRC32:   %08X\n", crc);
            
            // копим в master
            bs_sha256_update(&master_ctx, hash, 32);
        }
        printf("\n");
    }
    
    // master = sha от всех sha секций
    uint8_t master_hash[32];
    bs_sha256_final(&master_ctx, master_hash);
    printf("=== Master Hash ===\n");
    print_hash("Master SHA-256", master_hash);
    
    // цепочка (добавил на второй неделе)
    printf("\n=== Phase 2: Polymorphic Hash Chain ===\n");
    
    bs_hash_chain_generate(&pack.chain, master_hash, 32, 500);
    
    for (int i = 0; i < BS_HASH_CHAIN_DEPTH; i++) {
        char label[32];
        snprintf(label, sizeof(label), "Chain[%d]", i);
        print_hash(label, pack.chain.chain[i]);
    }
    print_hash("Final Hash", pack.chain.final_hash);
    
    // sanity check
    if (bs_hash_chain_verify(&pack.chain, master_hash, 32)) {
        printf("[+] Hash chain verification: PASSED\n");
    } else {
        printf("[!] Hash chain verification: FAILED\n");
        free(pe.data);
        return -5;
    }
    
    // шифруем .text и т.п.
    printf("\n=== Phase 3: Section Encryption ===\n");
    
    bs_generate_key(pack.master_key);  // мастер-ключ на весь пак
    
    for (WORD i = 0; i < num_sections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        
        uint32_t raw_off = sections[i].PointerToRawData;
        uint32_t raw_size = sections[i].SizeOfRawData;
        DWORD chars = sections[i].Characteristics;
        
        // код + init data, ресурсы/релокации пропускаем
        int should_encrypt = 0;
        if (chars & IMAGE_SCN_CNT_CODE) should_encrypt = 1;
        if (chars & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            if (!(chars & IMAGE_SCN_MEM_DISCARDABLE))
                should_encrypt = 1;
        }
        
        if (should_encrypt && raw_size > 0 && raw_off > 0 &&
            pack.enc_count < MAX_ENCRYPTED_SECTIONS) {
            
            encrypted_section_info *info = &pack.sections[pack.enc_count];
            info->section_index = i;
            info->original_offset = raw_off;
            info->original_size = raw_size;
            
            bs_sha256(pe.data + raw_off, raw_size, info->original_hash);
            
            bs_generate_key(info->key);  // ключ на секцию
            bs_generate_iv(info->iv);
            
            uint32_t aligned = (raw_size + 15) & ~15u;
            if (raw_off + aligned <= pe.size) {  // не вылезти за буфер
                encrypt_section(pe.data + raw_off, raw_size, info->key, info->iv);
                printf("  [+] Encrypted section [%s] (%u bytes)\n", name, raw_size);
                pack.enc_count++;
            } else {
                printf("  [-] Skipping [%s] (alignment overflow)\n", name);
            }
        }
    }
    
    printf("[+] Encrypted %u sections\n", pack.enc_count);
    
    printf("\n=== Phase 4: HMAC Seal ===\n");
    
    uint8_t hmac_key[32];
    // Ключ HMAC из мастер-ключа
    bs_hmac_sha256(pack.master_key, 32,
                   (const uint8_t*)"BankShield-HMAC-Key-Derivation", 30,
                   hmac_key);
    
    size_t hmac_data_size = offsetof(protection_pack, manifest_hmac);
    bs_hmac_sha256(hmac_key, 32, (const uint8_t*)&pack, hmac_data_size,
                   pack.manifest_hmac);
    print_hash("HMAC", pack.manifest_hmac);
    
    // overlay в конец exe
    printf("\n=== Phase 5: Embedding Protection Pack ===\n");
    
    size_t new_size = pe.size + sizeof(protection_pack);
    uint8_t *new_data = (uint8_t*)realloc(pe.data, new_size);
    if (!new_data) {
        printf("[!] Memory allocation failed\n");
        free(pe.data);
        return -6;
    }
    pe.data = new_data;
    
    memcpy(pe.data + pe.size, &pack, sizeof(protection_pack));
    pe.size = new_size;
    
    printf("[+] Appended protection pack (%zu bytes)\n", sizeof(protection_pack));
    
    if (pe_write_file(output_path, &pe) != 0) {
        printf("[!] Failed to write output file\n");
        free(pe.data);
        return -7;
    }
    
    printf("\n[+] Protected PE written: %s (%zu bytes)\n", output_path, pe.size);
    printf("[+] Protection complete!\n");
    
    bs_secure_zero(&pack, sizeof(pack));  // ключи не оставляем
    bs_secure_zero(hmac_key, sizeof(hmac_key));
    free(pe.data);
    
    return 0;
}

/* ================================================================
 * main
 * ================================================================ */

int main(int argc, char *argv[]) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║    BankShield PE Protector v1.0          ║\n");
    printf("║    Polymorphic Hash Chain Protection     ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    if (argc < 3) {
        printf("Usage: %s <input.exe> <output.exe>\n\n", argv[0]);
        printf("Options:\n");
        printf("  input.exe   - The original unprotected executable\n");
        printf("  output.exe  - Output path for the protected executable\n");
        return 1;
    }
    
    return protect_pe(argv[1], argv[2]);
}
