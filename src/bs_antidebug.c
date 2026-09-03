/*
 * BankShield — защита от отладки (реализация)
 * Учебный проект, 2026
 *
 * Многослойные проверки под Windows, при угрозе — самоуничтожение кода.
 */

#include "../include/bs_antidebug.h"
#include "../include/bs_crypto.h"
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

// Указатель на NtQueryInformationProcess
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static bs_threat_callback g_threat_cb = NULL;
static void *g_threat_userdata = NULL;
static volatile int g_monitoring = 0;

void bs_antidebug_init(void) {
    g_threat_cb = NULL;
    g_threat_userdata = NULL;
    g_monitoring = 0;
}

void bs_antidebug_set_callback(bs_threat_callback cb, void *user_data) {
    g_threat_cb = cb;
    g_threat_userdata = user_data;
}

// ============ Отдельные проверки ============

int bs_check_debugger_present(void) {
// Способ 1: API IsDebuggerPresent
    if (IsDebuggerPresent())
        return 1;
    
// Способ 2: флаг BeingDebugged в PEB
#if defined(_M_X64) || defined(__x86_64__)
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb && peb->BeingDebugged)
        return 1;
    
// Способ 3: NtGlobalFlag в PEB
    DWORD ntglobal = *(DWORD*)((BYTE*)peb + 
#if defined(_M_X64) || defined(__x86_64__)
        0xBC
#else
        0x68
#endif
    );
    // Флаги кучи при отладке (0x70)
    if (ntglobal & 0x70)
        return 1;
    
    return 0;
}

int bs_check_remote_debugger(void) {
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present))
        return present ? 1 : 0;
    return 0;
}

int bs_check_nt_debug_flags(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    pNtQueryInformationProcess NtQIP = 
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQIP) return 0;
    
// ProcessDebugPort = 0x07
    DWORD_PTR debug_port = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x07,
                            &debug_port, sizeof(debug_port), NULL);
    if (status == 0 && debug_port != 0)
        return 1;
    
// ProcessDebugObjectHandle = 0x1E
    HANDLE debug_obj = NULL;
    status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E,
                   &debug_obj, sizeof(debug_obj), NULL);
    if (status == 0 && debug_obj != NULL)
        return 1;
    
// ProcessDebugFlags = 0x1F
    DWORD debug_flags = 0;
    status = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F,
                   &debug_flags, sizeof(debug_flags), NULL);
    if (status == 0 && debug_flags == 0)
        return 1;
    
    return 0;
}

int bs_check_timing_anomaly(void) {
// RDTSC: под отладчиком цикл «дороже»
    unsigned __int64 t1 = __rdtsc();
    
// Лёгкий цикл — без отладчика должен быть быстрым
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    
    unsigned __int64 t2 = __rdtsc();
    unsigned __int64 diff = t2 - t1;
    
// Порог: норма < ~100k тактов, с отладчиком сильно больше
    return (diff > 100000) ? 1 : 0;
}

int bs_check_breakpoints(const void *func_start, size_t scan_len) {
    const uint8_t *p = (const uint8_t *)func_start;
    for (size_t i = 0; i < scan_len; i++) {
        if (p[i] == 0xCC)  // программная точка останова INT3
            return 1;
    }
    return 0;
}

int bs_check_hardware_breakpoints(void) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return 0;
    
// Регистры DR0–DR3 — аппаратные breakpoints
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
        return 1;
    
    return 0;
}

int bs_check_virtual_machine(void) {
// Типичные признаки виртуальной машины
    
// Способ 1: бит гипервизора в CPUID
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 0x01);
    // Бит 31 ECX — гипервизор
    if (cpuinfo[2] & (1 << 31))
        return 1;
    
// Способ 2: DLL гостевых ВМ в процессе
    const char *vm_dlls[] = {
        "vmGuestLib.dll",  // VMware
        "vboxhook.dll",  // VirtualBox
        "SbieDll.dll",  // Sandboxie
        NULL
    };
    for (int i = 0; vm_dlls[i]; i++) {
        if (GetModuleHandleA(vm_dlls[i]))
            return 1;
    }
    
// Способ 3: строка вендора через CPUID 0x40000000
    __cpuid(cpuinfo, 0x40000000);
    char vendor[13];
    memcpy(vendor, &cpuinfo[1], 4);
    memcpy(vendor + 4, &cpuinfo[2], 4);
    memcpy(vendor + 8, &cpuinfo[3], 4);
    vendor[12] = 0;
    
    if (strstr(vendor, "VMware") || strstr(vendor, "VBox") ||
        strstr(vendor, "Hyper-V") || strstr(vendor, "KVMKVMKVM"))
        return 1;
    
    return 0;
}

int bs_check_api_hooks(void) {
// Inline-хуки на важных API
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    
    struct { HMODULE mod; const char *name; } apis[] = {
        { k32,   "VirtualProtect" },
        { k32,   "WriteProcessMemory" },
        { k32,   "CreateFileA" },
        { ntdll, "NtQueryInformationProcess" },
        { ntdll, "NtSetInformationThread" },
        { 0, NULL }
    };
    
    for (int i = 0; apis[i].name; i++) {
        if (!apis[i].mod) continue;
        uint8_t *func = (uint8_t*)GetProcAddress(apis[i].mod, apis[i].name);
        if (!func) continue;
        
// JMP (0xE9) или косвенный jmp в начале функции — признак хука
        if (func[0] == 0xE9 || func[0] == 0xEB ||
            (func[0] == 0xFF && func[1] == 0x25)) {
            return 1;
        }
    }
    
    return 0;
}

int bs_check_code_integrity(const uint8_t *expected_hash) {
// Базовый адрес нашего модуля
    HMODULE self = GetModuleHandleA(NULL);
    if (!self) return 0;
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)self;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    
// Секция .text и её SHA-256
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            uint8_t *code = (uint8_t*)self + section[i].VirtualAddress;
            DWORD code_size = section[i].Misc.VirtualSize;
            
            uint8_t hash[32];
            bs_sha256(code, code_size, hash);
            
            return bs_secure_compare(hash, expected_hash, 32);
        }
    }
    
    return 0;  // секция .text не найдена
}

// ============ Полное сканирование ============

uint32_t bs_antidebug_scan(void) {
    uint32_t flags = BS_DETECT_NONE;
    
    if (bs_check_debugger_present())
        flags |= BS_DETECT_DEBUGGER;
    
    if (bs_check_remote_debugger())
        flags |= BS_DETECT_REMOTE_DBG;
    
    if (bs_check_nt_debug_flags())
        flags |= BS_DETECT_DEBUGGER;
    
    if (bs_check_timing_anomaly())
        flags |= BS_DETECT_TIMING;
    
    if (bs_check_hardware_breakpoints())
        flags |= BS_DETECT_BREAKPOINT;
    
    if (bs_check_virtual_machine())
        flags |= BS_DETECT_VM;
    
    if (bs_check_api_hooks())
        flags |= BS_DETECT_HOOK;
    
// Вызвать колбэк, если что-то нашли
    if (flags != BS_DETECT_NONE && g_threat_cb) {
        g_threat_cb(flags, g_threat_userdata);
    }
    
    return flags;
}

// ============ Реакция ============

void bs_self_destruct(void) {
// Затираем секции кода случайными байтами
    HMODULE self = GetModuleHandleA(NULL);
    if (!self) return;
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)self;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint8_t *addr = (uint8_t*)self + section[i].VirtualAddress;
        DWORD size = section[i].Misc.VirtualSize;
        DWORD old_protect;
        
        if (VirtualProtect(addr, size, PAGE_READWRITE, &old_protect)) {
        // Заполнить случайными байтами
            bs_csprng_fill(addr, size);
        }
    }
}

void bs_panic_exit(int code) {
    bs_self_destruct();
    ExitProcess((UINT)code);
}

void bs_antidebug_monitor_loop(void) {
    g_monitoring = 1;
    while (g_monitoring) {
        uint32_t result = bs_antidebug_scan();
        if (result & (BS_DETECT_DEBUGGER | BS_DETECT_REMOTE_DBG | BS_DETECT_HOOK)) {
        // Серьёзная угроза — немедленный выход
            bs_panic_exit(0xDEAD);
        }
        Sleep(1000 + (GetTickCount() % 2000));  // случайный интервал
    }
}

#else  // заглушки для не-Windows

void bs_antidebug_init(void) {}
uint32_t bs_antidebug_scan(void) { return BS_DETECT_NONE; }
void bs_antidebug_set_callback(bs_threat_callback cb, void *user_data) { (void)cb; (void)user_data; }
int bs_check_debugger_present(void) { return 0; }
int bs_check_remote_debugger(void) { return 0; }
int bs_check_nt_debug_flags(void) { return 0; }
int bs_check_timing_anomaly(void) { return 0; }
int bs_check_breakpoints(const void *func_start, size_t scan_len) { (void)func_start; (void)scan_len; return 0; }
int bs_check_hardware_breakpoints(void) { return 0; }
int bs_check_virtual_machine(void) { return 0; }
int bs_check_api_hooks(void) { return 0; }
int bs_check_code_integrity(const uint8_t *expected_hash) { (void)expected_hash; return 1; }
void bs_self_destruct(void) {}
void bs_panic_exit(int code) { _exit(code); }
void bs_antidebug_monitor_loop(void) {}

#endif
