/*
 * BankShield — универсальный PE-протектор v2.0
 * Учебный проект, 2026
 *
 * Отдельная утилита: защищает любой Windows EXE.
 *
 * Как работает:
 *   1. Берёт готовый stub.exe (загрузчик)
 *   2. Берёт input.exe (программу для защиты)
 *   3. Шифрует input AES-256-CBC со случайным ключом
 *   4. Строит полиморфную цепочку хешей
 *   5. Дописывает нагрузку + заголовок к stub → output.exe
 *
 * На целевой машине не нужны DLL — только Windows.
 *
 * Запуск: bs_protect <input.exe> <output.exe> [опции]
 */

#include "../include/bs_crypto.h"
#include "../include/bs_integrity.h"
#include "../include/bs_pack_format.h"
#include "../include/bs_pack_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define access _access
#define F_OK 0
#else
#include <unistd.h>
#endif

typedef struct {
    const char *input_path;
    const char *output_path;
    const char *stub_path;
    uint32_t    options;
} protect_config;

static void print_banner(void) {
    printf(
    "\n"
    "  ____              _    ____  _     _      _     _ \n"
    " | __ )  __ _ _ __ | | _/ ___|| |__ (_) ___| | __| |\n"
    " |  _ \\ / _` | '_ \\| |/ \\___ \\| '_ \\| |/ _ \\ |/ _` |\n"
    " | |_) | (_| | | | |   < ___) | | | | |  __/ | (_| |\n"
    " |____/ \\__,_|_| |_|_|\\_\\____/|_| |_|_|\\___|_|\\__,_|\n"
    "\n"
    "  Universal PE Protector v2.0\n"
    "  AES-256-CBC + EtM (v4) + Hash Chain + Anti-Debug\n"
    "\n"
    );
}

static void print_usage(const char *prog) {
    printf("Usage: %s <input.exe> <output.exe> [options]\n\n", prog);
    printf("Options:\n");
    printf("  --stub <path>      Path to loader stub (default: auto-detect)\n");
    printf("  --no-antidebug     Disable anti-debugger protection\n");
    printf("  --no-integrity     Disable hash chain verification at runtime\n");
    printf("  --no-hide          Don't hide temporary files\n");
    printf("\nExamples:\n");
    printf("  %s myapp.exe myapp_protected.exe\n", prog);
    printf("  %s server.exe server_safe.exe --no-antidebug\n", prog);
    printf("  %s bank.exe bank_release.exe --stub custom_stub.exe\n", prog);
}

static void print_hex_line(const char *label, const unsigned char *data, int len) {
    printf("  %-20s ", label);
    for (int i = 0; i < len && i < 32; i++) printf("%02x", data[i]);
    printf("\n");
}

// Автопоиск stub.exe
static const char* find_stub(const char *argv0) {
    static char path_buf[MAX_PATH];

// Вариант 1: рядом с bs_protect.exe
    strncpy(path_buf, argv0, MAX_PATH - 20);
    char *last_sep = strrchr(path_buf, '\\');
    if (!last_sep) last_sep = strrchr(path_buf, '/');
    if (last_sep) {
        strcpy(last_sep + 1, "bs_stub.exe");
        if (access(path_buf, F_OK) == 0) return path_buf;
    }

// Вариант 2: ./build/bs_stub.exe
    if (access("build\\bs_stub.exe", F_OK) == 0) return "build\\bs_stub.exe";
    if (access("build/bs_stub.exe", F_OK) == 0) return "build/bs_stub.exe";

// Вариант 3: ./bs_stub.exe
    if (access("bs_stub.exe", F_OK) == 0) return "bs_stub.exe";

    return NULL;
}

// Прочитать весь файл в память
static unsigned char* read_file_full(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || (uint64_t)sz > BS_MAX_PAYLOAD_SIZE) {
        fclose(f);
        return NULL;
    }

    unsigned char *data = (unsigned char*)malloc((size_t)sz);
    if (!data) { fclose(f); return NULL; }

    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        free(data);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)sz;
    return data;
}

static int write_file_full(const char *path, const unsigned char *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, size, f) != size) { fclose(f); return -2; }
    fclose(f);
    return 0;
}

/* ================================================================
 * Основной конвейер защиты
 * ================================================================ */

static int do_protect(const protect_config *cfg) {
    int rc = 0;

    printf("[*] Input:  %s\n", cfg->input_path);
    printf("[*] Output: %s\n", cfg->output_path);
    printf("[*] Stub:   %s\n", cfg->stub_path);
    printf("[*] Options: 0x%04X", cfg->options);
    if (cfg->options & BS_OPT_ANTI_DEBUG)      printf(" [AntiDebug]");
    if (cfg->options & BS_OPT_INTEGRITY_CHECK) printf(" [HashChain]");
    if (cfg->options & BS_OPT_HIDE_TEMP)       printf(" [HideTemp]");
    printf("\n\n");

// ---- Читаем stub ----
    printf("[1/8] Reading loader stub...\n");
    size_t stub_size;
    unsigned char *stub_data = read_file_full(cfg->stub_path, &stub_size);
    if (!stub_data) {
        printf("  [!] Failed to read stub: %s\n", cfg->stub_path);
        return -1;
    }
    printf("  Stub size: %zu bytes\n", stub_size);

// ---- Читаем входной EXE ----
    printf("[2/8] Reading input executable...\n");
    size_t input_size;
    unsigned char *input_data = read_file_full(cfg->input_path, &input_size);
    if (!input_data) {
        printf("  [!] Failed to read input: %s\n", cfg->input_path);
        free(stub_data);
        return -2;
    }
    printf("  Original size: %zu bytes\n", input_size);

// Быстрая проверка MZ
    if (input_size < 64 || input_data[0] != 'M' || input_data[1] != 'Z') {
        printf("  [!] Warning: Input doesn't look like a PE file (no MZ header)\n");
        printf("  [!] Continuing anyway — the protector works with any binary\n");
    }

// ---- Хеши ----
    printf("[3/8] Generating hashes...\n");
    bs_pack_header header;
    memset(&header, 0, sizeof(header));

    header.magic = BS_PACK_MAGIC;
    header.version = BS_PACK_VERSION;
    header.header_size = sizeof(bs_pack_header);
    header.original_size = (uint64_t)input_size;
    header.payload_offset = (uint64_t)stub_size;
    header.options = cfg->options;

// SHA-256 оригинала
    bs_sha256(input_data, input_size, header.original_hash);
    print_hex_line("Original SHA-256:", header.original_hash, 32);

// SHA-256 stub (антивзлом)
    bs_sha256(stub_data, stub_size, header.stub_hash);
    print_hex_line("Stub SHA-256:", header.stub_hash, 32);

// Хеш секции .text stub для самопроверки
    {
        if (stub_size > sizeof(IMAGE_DOS_HEADER) && stub_data[0] == 'M' && stub_data[1] == 'Z') {
            IMAGE_DOS_HEADER *sdos = (IMAGE_DOS_HEADER*)stub_data;
            IMAGE_NT_HEADERS *snt = (IMAGE_NT_HEADERS*)(stub_data + sdos->e_lfanew);
            if (snt->Signature == IMAGE_NT_SIGNATURE) {
                IMAGE_SECTION_HEADER *ssecs = IMAGE_FIRST_SECTION(snt);
                for (WORD si = 0; si < snt->FileHeader.NumberOfSections; si++) {
                    if (memcmp(ssecs[si].Name, ".text", 5) == 0 &&
                        ssecs[si].SizeOfRawData > 0 &&
                        ssecs[si].PointerToRawData + ssecs[si].SizeOfRawData <= stub_size) {
                        bs_sha256(stub_data + ssecs[si].PointerToRawData,
                                  ssecs[si].SizeOfRawData, header.stub_text_hash);
                        print_hex_line("Stub .text hash:", header.stub_text_hash, 32);
                        break;
                    }
                }
            }
        }
    }

// ---- Полиморфная цепочка ----
    printf("[4/8] Building polymorphic hash chain (8 levels)...\n");

// Соль
    bs_csprng_fill(header.chain_salt, BS_PACK_SALT_SIZE);
    header.chain_iterations = 200;

// Заполняем поля заголовка через bs_hash_chain_generate
    {
        bs_hash_chain hc;
        memcpy(hc.salt, header.chain_salt, BS_PACK_SALT_SIZE);
        hc.iterations = header.chain_iterations;

// Генерация цепочки
        bs_hash_chain_generate(&hc, input_data, input_size, header.chain_iterations);

// Соль могла обновиться внутри функции
        memcpy(header.chain_salt, hc.salt, BS_PACK_SALT_SIZE);

// Копируем уровни в заголовок
        for (int i = 0; i < BS_PACK_CHAIN_DEPTH; i++) {
            memcpy(header.chain_hashes[i], hc.chain[i], 32);
            char label[32];
            snprintf(label, sizeof(label), "  Chain[%d]:", i);
            print_hex_line(label, hc.chain[i], 32);
        }
        memcpy(header.chain_final, hc.final_hash, 32);
        print_hex_line("  Final:", hc.final_hash, 32);

// Самотест
        if (bs_hash_chain_verify(&hc, input_data, input_size)) {
            printf("  [+] Chain self-test: PASSED\n");
        } else {
            printf("  [!] Chain self-test: FAILED — aborting\n");
            rc = -3;
            goto cleanup;
        }
    }

// ---- Ключ и шифрование ----
    printf("[5/8] Encrypting with AES-256-CBC...\n");

    bs_generate_key(header.aes_key);
    bs_generate_iv(header.aes_iv);
    print_hex_line("AES Key:", header.aes_key, 32);
    print_hex_line("AES IV:", header.aes_iv, 16);

// Дополнение до размера блока AES
    size_t padded_size = ((input_size + 15) / 16) * 16;
    header.encrypted_size = (uint64_t)padded_size;

    unsigned char *padded = (unsigned char*)calloc(padded_size, 1);
    if (!padded) {
        printf("  [!] Memory allocation failed\n");
        rc = -4;
        goto cleanup;
    }
    memcpy(padded, input_data, input_size);
    // Нули в хвосте — original_size храним отдельно

// Шифруем на месте
    bs_aes_ctx aes;
    bs_aes_init(&aes, header.aes_key, header.aes_iv);
    bs_aes_cbc_encrypt(&aes, padded, padded_size);
    bs_secure_zero(&aes, sizeof(aes));

    printf("  Encrypted size: %zu bytes (padded from %zu)\n", padded_size, input_size);

    {
        uint8_t mac_key[32];
        bs_pack_payload_mac_key(header.aes_key, mac_key);
        bs_pack_payload_mac(mac_key, header.aes_iv,
                            padded, padded_size, header.payload_hmac);
        bs_secure_zero(mac_key, sizeof(mac_key));
    }
    print_hex_line("Payload HMAC:", header.payload_hmac, 32);

    bs_sha256(padded, padded_size, header.encrypted_hash);
    print_hex_line("Encrypted SHA-256:", header.encrypted_hash, 32);

    printf("[6/8] Sealing header + key wrap (PBKDF2 x %u)...\n", BS_KDF_ITERATIONS);

    {
        uint8_t hmac_key[32];
        bs_pack_header_hmac_key(header.aes_key, hmac_key);
        size_t hmac_data_len = (size_t)((unsigned char*)&header.header_hmac -
                                        (unsigned char*)&header);
        bs_hmac_sha256(hmac_key, 32, (const unsigned char*)&header,
                       hmac_data_len, header.header_hmac);
        bs_secure_zero(hmac_key, sizeof(hmac_key));
    }
    print_hex_line("Header HMAC:", header.header_hmac, 32);

    bs_csprng_fill(header.kdf_salt, BS_KDF_SALT_SIZE);
    header.kdf_iterations = BS_KDF_ITERATIONS;
    bs_pack_wrap_keys(&header, header.stub_hash, 1);

    print_hex_line("KDF Salt:", header.kdf_salt, 32);
    printf("  [+] Keys wrapped (AES + IV + payload MAC key)\n");
    printf("  [+] Format v%d — legacy v3 still readable by stub\n", BS_PACK_VERSION_V4);

// ---- Сборка выходного файла ----
    printf("[8/8] Assembling protected executable...\n");

    bs_pack_tail tail;
    tail.header_size = sizeof(bs_pack_header);
    tail.magic_check = BS_PACK_MAGIC;
    tail.tail_magic = BS_PACK_TAIL_MAGIC;

    /*
     * Структура output:
     * [stub_data]  (stub_size байт)
     * [padded]     (padded_size байт)  ← зашифрованная нагрузка
     * [header]     (заголовок)
     * [tail]       (хвост)
     */
    size_t output_size = stub_size + padded_size + sizeof(header) + sizeof(tail);
    unsigned char *output = (unsigned char*)malloc(output_size);
    if (!output) {
        printf("  [!] Memory allocation failed\n");
        free(padded);
        rc = -5;
        goto cleanup;
    }

    size_t pos = 0;
    memcpy(output + pos, stub_data, stub_size);     pos += stub_size;
    memcpy(output + pos, padded, padded_size);       pos += padded_size;
    memcpy(output + pos, &header, sizeof(header));   pos += sizeof(header);
    memcpy(output + pos, &tail, sizeof(tail));       pos += sizeof(tail);

// Запись на диск
    if (write_file_full(cfg->output_path, output, output_size) != 0) {
        printf("  [!] Failed to write output: %s\n", cfg->output_path);
        free(output);
        free(padded);
        rc = -6;
        goto cleanup;
    }

    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║  PROTECTION COMPLETE                          ║\n");
    printf("  ╠═══════════════════════════════════════════════╣\n");
    printf("  ║  Output:    %-33s ║\n", cfg->output_path);
    printf("  ║  Size:      %-33zu ║\n", output_size);
    printf("  ║  Original:  %-33zu ║\n", input_size);
    printf("  ║  Overhead:  %-33zu ║\n", output_size - input_size);
    printf("  ║  Encrypted: %-3d sections (whole file)         ║\n", 1);
    printf("  ║  Hash chain: 8 levels x 200 iterations        ║\n");
    printf("  ║  Key derivation: PBKDF2 x %-5u (v4)          ║\n", BS_KDF_ITERATIONS);
    printf("  ║  Payload auth:   HMAC-SHA256 (pre-decrypt)    ║\n");
    printf("  ║  Execution: In-memory (RunPE + fallback)       ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n");
    printf("\n  The file %s can be run on any Windows PC.\n", cfg->output_path);
    printf("  No additional software or libraries needed.\n\n");

    free(output);
    free(padded);

cleanup:
    bs_secure_zero(&header, sizeof(header));
    bs_secure_zero(hmac_key, sizeof(hmac_key));
    if (input_data) { bs_secure_zero(input_data, input_size); free(input_data); }
    if (stub_data) free(stub_data);

    return rc;
}

/* ================================================================
 * Разбор аргументов и main
 * ================================================================ */

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    protect_config cfg;
    cfg.input_path = argv[1];
    cfg.output_path = argv[2];
    cfg.stub_path = NULL;
    cfg.options = BS_OPT_DEFAULT;  // AntiDebug + цепочка + скрытие temp

// Опции командной строки
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            cfg.stub_path = argv[++i];
        } else if (strcmp(argv[i], "--no-antidebug") == 0) {
            cfg.options &= ~BS_OPT_ANTI_DEBUG;
        } else if (strcmp(argv[i], "--no-integrity") == 0) {
            cfg.options &= ~BS_OPT_INTEGRITY_CHECK;
        } else if (strcmp(argv[i], "--no-hide") == 0) {
            cfg.options &= ~BS_OPT_HIDE_TEMP;
        } else {
            printf("[!] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

// Ищем stub, если не передали --stub
    if (!cfg.stub_path) {
        cfg.stub_path = find_stub(argv[0]);
        if (!cfg.stub_path) {
            printf("[!] Loader stub (bs_stub.exe) not found!\n");
            printf("    Build it first, or specify --stub <path>\n");
            printf("    Expected locations:\n");
            printf("      - Next to bs_protect.exe\n");
            printf("      - ./build/bs_stub.exe\n");
            printf("      - ./bs_stub.exe\n");
            return 1;
        }
    }

// Проверяем, что файлы есть
    if (access(cfg.input_path, F_OK) != 0) {
        printf("[!] Input file not found: %s\n", cfg.input_path);
        return 1;
    }
    if (access(cfg.stub_path, F_OK) != 0) {
        printf("[!] Stub file not found: %s\n", cfg.stub_path);
        return 1;
    }

    return do_protect(&cfg);
}
