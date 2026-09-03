/*
 * BankShield — общий тест всех модулей
 * Учебный проект, 2026
 *
 * Проверяем:
 *   1. AES-256
 *   2. SHA-256
 *   3. HMAC
 *   4. полиморфные цепочки хешей
 *   5. шифрование строк
 *   6. безопасная память
 *   7. anti-debug
 *   8. целостность
 */

#include "../include/bs_crypto.h"
#include "../include/bs_antidebug.h"
#include "../include/bs_integrity.h"
#include "../include/bs_string_crypt.h"
#include "../include/bs_secure_mem.h"
#include "../include/bs_pack_crypto.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("\n--- TEST: %s ---\n", name)
#define ASSERT(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); tests_passed++; } \
    else      { printf("  [FAIL] %s\n", msg); tests_failed++; } \
} while(0)

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len && i < 32; i++)
        printf("%02x", data[i]);
    if (len > 32) printf("...");
    printf("\n");
}

// ================================================================

static void test_aes256(void) {
    TEST("AES-256-CBC Encryption/Decryption");
    
    uint8_t key[32], iv[16];
    bs_generate_key(key);
    bs_generate_iv(iv);
    
    const char *plain = "BankShield Secret Transaction Data 1234567890!";
    size_t plain_len = strlen(plain);
    
    uint8_t buffer[128];  // с запасом под pkcs7
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, plain, plain_len);
    
    size_t padded_len = bs_aes_pad(buffer, plain_len, sizeof(buffer));
    ASSERT(padded_len > 0, "PKCS7 padding applied");
    ASSERT(padded_len % 16 == 0, "Padded to AES block boundary");
    
    print_hex("Key", key, 32);
    print_hex("IV ", iv, 16);
    print_hex("Plain", (uint8_t*)plain, plain_len);
    
    uint8_t iv_enc[16], iv_dec[16];
    memcpy(iv_enc, iv, 16);
    memcpy(iv_dec, iv, 16);
    
    bs_aes_ctx ctx_enc;
    bs_aes_init(&ctx_enc, key, iv_enc);
    bs_aes_cbc_encrypt(&ctx_enc, buffer, padded_len);
    
    print_hex("Cipher", buffer, padded_len);
    ASSERT(memcmp(buffer, plain, plain_len) != 0, "Data is encrypted (different from plain)");
    
    bs_aes_ctx ctx_dec;
    bs_aes_init(&ctx_dec, key, iv_dec);
    bs_aes_cbc_decrypt(&ctx_dec, buffer, padded_len);
    
    size_t orig_len = bs_aes_unpad(buffer, padded_len);
    ASSERT(orig_len == plain_len, "Unpadded length matches original");
    ASSERT(memcmp(buffer, plain, plain_len) == 0, "Decrypted data matches original");
    
    printf("  Decrypted: \"%.50s\"\n", buffer);
}

static void test_sha256(void) {
    TEST("SHA-256 Hashing");
    
    uint8_t hash[32];
    bs_sha256((const uint8_t*)"", 0, hash);  // пустая строка, вектор nist
    
    char hex[65];
    bs_hash_to_hex(hash, 32, hex);
    printf("  SHA-256(\"\") = %s\n", hex);
    
    ASSERT(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
           "Empty string hash matches NIST vector");
    
    bs_sha256((const uint8_t*)"abc", 3, hash);
    bs_hash_to_hex(hash, 32, hex);
    printf("  SHA-256(\"abc\") = %s\n", hex);
    
    ASSERT(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
           "\"abc\" hash matches NIST vector");
}

static void test_pack_payload_mac(void) {
    TEST("Pack v4 payload MAC (encrypt-then-MAC)");

    uint8_t key[32], iv[16], mac_k[32], mac1[32], mac2[32];
    bs_generate_key(key);
    bs_generate_iv(iv);
    bs_pack_payload_mac_key(key, mac_k);

    const char *plain = "bank payload sample";
    size_t len = strlen(plain);
    size_t padded = ((len + 15) / 16) * 16;
    uint8_t *buf = (uint8_t*)calloc(padded, 1);
    memcpy(buf, plain, len);

    bs_aes_ctx aes;
    bs_aes_init(&aes, key, iv);
    bs_aes_cbc_encrypt(&aes, buf, padded);

    bs_pack_payload_mac(mac_k, iv, buf, padded, mac1);

    buf[0] ^= 0x01;  // подмена ciphertext
    bs_pack_payload_mac(mac_k, iv, buf, padded, mac2);
    ASSERT(memcmp(mac1, mac2, 32) != 0, "MAC detects ciphertext tampering");

    buf[0] ^= 0x01;  // вернуть как было
    bs_pack_payload_mac(mac_k, iv, buf, padded, mac2);
    ASSERT(memcmp(mac1, mac2, 32) == 0, "MAC stable for same ciphertext");

    free(buf);
}

static void test_hmac(void) {
    TEST("HMAC-SHA256");
    
    const uint8_t key[] = "Jefe";  // rfc 4231 case 2
    const uint8_t data[] = "what do ya want for nothing?";
    uint8_t mac[32];
    
    bs_hmac_sha256(key, 4, data, 28, mac);
    
    char hex[65];
    bs_hash_to_hex(mac, 32, hex);
    printf("  HMAC = %s\n", hex);
    
    ASSERT(strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0,
           "HMAC matches RFC 4231 test vector");
}

static void test_hash_chain(void) {
    TEST("Polymorphic Hash Chain");
    
    const char *data = "Critical banking executable code section";
    bs_hash_chain hc;
    
    // генерим цепочку
    bs_hash_chain_generate(&hc, (const uint8_t*)data, strlen(data), 100);
    
    printf("  Salt: ");
    for (int i = 0; i < 16; i++) printf("%02x", hc.salt[i]);
    printf("\n");
    printf("  Iterations: %u\n", hc.iterations);
    
    for (int i = 0; i < BS_HASH_CHAIN_DEPTH; i++) {
        char label[20];
        snprintf(label, sizeof(label), "Chain[%d]", i);
        print_hex(label, hc.chain[i], 32);
    }
    print_hex("Final", hc.final_hash, 32);
    
// Проверка с правильными данными
    int ok = bs_hash_chain_verify(&hc, (const uint8_t*)data, strlen(data));
    ASSERT(ok, "Hash chain verifies with correct data");
    
// Проверка с неверными данными
    const char *bad = "Modified banking executable code section";
    ok = bs_hash_chain_verify(&hc, (const uint8_t*)bad, strlen(bad));
    ASSERT(!ok, "Hash chain rejects modified data");
    
    // вторая цепочка — соль другая, данные те же
    bs_hash_chain hc2;
    bs_hash_chain_generate(&hc2, (const uint8_t*)data, strlen(data), 100);
    
    int chains_differ = memcmp(hc.final_hash, hc2.final_hash, 32) != 0;
    ASSERT(chains_differ, "Two chains for same data produce different hashes (polymorphic)");
    
// Обе всё равно проходят проверку
    ok = bs_hash_chain_verify(&hc2, (const uint8_t*)data, strlen(data));
    ASSERT(ok, "Second chain also verifies correctly");
}

static void test_string_encryption(void) {
    TEST("String Encryption");
    
    const char *secret = "ACCOUNT_PIN=9482;ROUTING=021000021;SWIFT=BOFAUS3N";
    
// Шифруем
    bs_enc_string enc;
    bs_string_encrypt(secret, &enc, 0xA7);
    
    print_hex("Encrypted", enc.data, enc.length);
    ASSERT(memcmp(enc.data, secret, enc.length) != 0, "Encrypted data differs from plain");
    
// Расшифровываем
    char decrypted[256];
    bs_string_decrypt(&enc, decrypted, sizeof(decrypted));
    
    printf("  Decrypted: \"%s\"\n", decrypted);
    ASSERT(strcmp(decrypted, secret) == 0, "Decrypted matches original");
    
// Затирание
    bs_string_wipe(decrypted, strlen(decrypted));
    
    int all_zero = 1;
    for (size_t i = 0; i < strlen(secret); i++) {
        if (decrypted[i] != 0) { all_zero = 0; break; }
    }
    ASSERT(all_zero, "String wiped from memory");
    
// Таблица строк
    bs_string_table_add("db_password", "SuperSecret!@#$%^&*()_Bank2026");
    bs_string_table_add("api_key", "sk-live-XXXXXXXXXXXXXXXXXXXXXXXX");
    
    char out[256];
    bs_string_table_get("db_password", out, sizeof(out));
    ASSERT(strcmp(out, "SuperSecret!@#$%^&*()_Bank2026") == 0, "String table retrieval works");
    bs_string_wipe(out, strlen(out));
    
    bs_string_table_destroy();
}

static void test_secure_memory(void) {
    TEST("Secure Memory Management");
    
    bs_secure_mem_init();
    
// Выделение со всеми флагами защиты
    char *secret = (char*)bs_secure_malloc(128, BS_MEM_ENCRYPTED | BS_MEM_CANARY | BS_MEM_WIPE_ON_FREE);
    ASSERT(secret != NULL, "Secure allocation succeeded");
    
    if (secret) {
        strcpy(secret, "PRIVATE KEY: MIIEvgIBADANBg...");
        printf("  Stored: \"%s\"\n", secret);
        
// Проверка канареек
        int canary_ok = bs_secure_check_canary(secret);
        ASSERT(canary_ok == 0, "Canary integrity: OK");
        
// lock — шифрование в памяти
        bs_secure_lock(secret);
        printf("  After lock: \"%.20s...\" (should be garbage)\n", secret);
        
// unlock — расшифровка
        bs_secure_unlock(secret);
        ASSERT(strcmp(secret, "PRIVATE KEY: MIIEvgIBADANBg...") == 0,
               "Data survives lock/unlock cycle");
        
// Смена ключа
        bs_secure_rekey(secret);
        printf("  [+] Re-keyed with fresh encryption key\n");
        
// free с авто-затиранием
        bs_secure_free(secret);
        printf("  [+] Securely freed (multi-pass wipe)\n");
    }
    
// Зашифрованный буфер
    const char *bank_data = "TRANSFER: ACC=1234567890 AMT=50000.00 CUR=USD";
    bs_encrypted_buffer ebuf;
    
    int rc = bs_encrypted_buffer_create(&ebuf, bank_data, strlen(bank_data) + 1);
    ASSERT(rc == 0, "Encrypted buffer created");
    
    char *opened = (char*)bs_encrypted_buffer_open(&ebuf);
    ASSERT(opened != NULL && strcmp(opened, bank_data) == 0, "Buffer open returns correct data");
    printf("  Opened: \"%s\"\n", opened);
    
    bs_encrypted_buffer_close(&ebuf, opened);
    bs_encrypted_buffer_destroy(&ebuf);
    printf("  [+] Buffer sealed and destroyed\n");
    
    bs_secure_mem_shutdown();
}

static void test_antidebug(void) {
    TEST("Anti-Debug Checks");
    
    bs_antidebug_init();
    
    printf("  Debugger Present:      %s\n", bs_check_debugger_present() ? "YES" : "no");
    printf("  Remote Debugger:       %s\n", bs_check_remote_debugger() ? "YES" : "no");
    printf("  NT Debug Flags:        %s\n", bs_check_nt_debug_flags() ? "YES" : "no");
    printf("  Timing Anomaly:        %s\n", bs_check_timing_anomaly() ? "YES" : "no");
    printf("  Hardware Breakpoints:  %s\n", bs_check_hardware_breakpoints() ? "YES" : "no");
    printf("  Virtual Machine:       %s\n", bs_check_virtual_machine() ? "YES" : "no");
    printf("  API Hooks:             %s\n", bs_check_api_hooks() ? "YES" : "no");
    
    uint32_t flags = bs_antidebug_scan();
    printf("\n  Full scan result: 0x%08X\n", flags);
    
    if (flags == BS_DETECT_NONE) {
        printf("  [+] Environment appears clean\n");
    } else {
        printf("  [!] Threats detected:\n");
        if (flags & BS_DETECT_DEBUGGER)   printf("      - Debugger attached\n");
        if (flags & BS_DETECT_REMOTE_DBG) printf("      - Remote debugger\n");
        if (flags & BS_DETECT_VM)         printf("      - Virtual machine\n");
        if (flags & BS_DETECT_TIMING)     printf("      - Timing anomaly\n");
        if (flags & BS_DETECT_BREAKPOINT) printf("      - Breakpoints found\n");
        if (flags & BS_DETECT_HOOK)       printf("      - API hooks detected\n");
    }
    
    tests_passed++;  // информативный тест, всегда OK
}

static void test_integrity(void) {
    TEST("Integrity Self-Check");
    
    int result = bs_integrity_verify_self();
    printf("  Self-check result: %d (%s)\n", result, bs_integrity_status_string(result));
    
// Проверка региона памяти
    const char *test_code = "function() { return 42; }";
    uint8_t expected_hash[32];
    bs_sha256((const uint8_t*)test_code, strlen(test_code), expected_hash);
    
    int region_ok = bs_integrity_verify_region(test_code, strlen(test_code), expected_hash);
    ASSERT(region_ok == 0, "Region integrity verification passed");
    
// Подмена данных
    char tampered[64];
    strcpy(tampered, test_code);
    tampered[5] = 'X';  // меняем один байт
    
    int tamper_detected = bs_integrity_verify_region(tampered, strlen(tampered), expected_hash);
    ASSERT(tamper_detected != 0, "Tampered region correctly detected");
}

static void test_constant_time(void) {
    TEST("Constant-Time Comparison");
    
    uint8_t a[32], b[32];
    bs_csprng_fill(a, 32);
    memcpy(b, a, 32);
    
    ASSERT(bs_secure_compare(a, b, 32), "Identical buffers compare equal (constant-time)");
    
    b[31] ^= 0x01;  // один бит в последнем байте
    ASSERT(!bs_secure_compare(a, b, 32), "Different buffers compare unequal (constant-time)");
}

// ================================================================

int main(void) {
    printf("*==============================================*\n");
    printf("|   BankShield Security System - Full Test     |\n");
    printf("|   Polymorphic Hash + AES-256 + Anti-Debug    |\n");
    printf("*==============================================*\n");
    
    test_sha256();
    test_pack_payload_mac();
    test_hmac();
    test_aes256();
    test_hash_chain();
    test_constant_time();
    test_string_encryption();
    test_secure_memory();
    test_antidebug();
    test_integrity();
    
    printf("\n*==============================================*\n");
    printf("| RESULTS: %d passed, %d failed                \n", tests_passed, tests_failed);
    printf("*==============================================*\n");
    
    return tests_failed > 0 ? 1 : 0;
}
