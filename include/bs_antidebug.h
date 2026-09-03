/*
 * BankShield — защита от отладки и вмешательства
 * Учебный проект, 2026
 *
 * Несколько уровней обнаружения:
 *   - отладчики (user-mode и kernel-mode)
 *   - виртуализация / песочницы
 *   - инъекции в код
 *   - аномалии по времени (timing)
 *   - аппаратные точки останова
 */

#ifndef BS_ANTIDEBUG_H
#define BS_ANTIDEBUG_H

#include <stdint.h>

// Флаги результата проверки
#define BS_DETECT_NONE          0x00000000
#define BS_DETECT_DEBUGGER      0x00000001
#define BS_DETECT_REMOTE_DBG    0x00000002
#define BS_DETECT_VM            0x00000004
#define BS_DETECT_SANDBOX       0x00000008
#define BS_DETECT_TIMING        0x00000010
#define BS_DETECT_BREAKPOINT    0x00000020
#define BS_DETECT_HOOK          0x00000040
#define BS_DETECT_INJECTION     0x00000080
#define BS_DETECT_PATCHED       0x00000100

// Колбэк при обнаружении угрозы
typedef void (*bs_threat_callback)(uint32_t threat_flags, void *user_data);

// Инициализация подсистемы anti-debug
void bs_antidebug_init(void);

// Полная проверка, возвращает объединённые флаги
uint32_t bs_antidebug_scan(void);

// Зарегистрировать колбэк при угрозе
void bs_antidebug_set_callback(bs_threat_callback cb, void *user_data);

// === Отдельные проверки ===

// IsDebuggerPresent и флаги PEB
int bs_check_debugger_present(void);

// Удалённый отладчик через CheckRemoteDebuggerPresent
int bs_check_remote_debugger(void);

// Проверки через NtQueryInformationProcess
int bs_check_nt_debug_flags(void);

// Обнаружение по времени (RDTSC)
int bs_check_timing_anomaly(void);

// Программные точки останова (0xCC / INT3)
int bs_check_breakpoints(const void *func_start, size_t scan_len);

// Аппаратные точки останова (регистры отладки)
int bs_check_hardware_breakpoints(void);

// Типичные среды ВМ
int bs_check_virtual_machine(void);

// Хуки API (IAT / inline)
int bs_check_api_hooks(void);

// Целостность кода по сохранённому хешу
int bs_check_code_integrity(const uint8_t *expected_hash);

// === Реакция на угрозу ===

// Испортить свою память, чтобы усложнить дамп
void bs_self_destruct(void);

// Стереть чувствительные данные и завершить процесс
void bs_panic_exit(int code);

// Фоновый мониторинг (вызывать из потока)
void bs_antidebug_monitor_loop(void);

#endif  // BS_ANTIDEBUG_H
