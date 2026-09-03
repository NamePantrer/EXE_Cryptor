# BankShield — Makefile
# Нужен MinGW-w64 (gcc) на Windows
#
# Сборка:  make
# Тесты:   make test
# Демо:    make protect-demo

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -DWIN32 -D_WIN32
LDFLAGS = -ladvapi32 -lcrypt32

# Stub: без внешних DLL, GUI-подсистема (без консоли)
# Для консольных программ stub вызывает AllocConsole() при запуске.
STUB_CFLAGS = -Wall -O2 -s -I./include -DWIN32 -D_WIN32
STUB_LDFLAGS = -mwindows -ladvapi32 -static

SRC_DIR = src
INC_DIR = include
TEST_DIR = test
BUILD_DIR = build

LIB_SRCS = $(SRC_DIR)/bs_crypto.c \
           $(SRC_DIR)/bs_pack_crypto.c \
           $(SRC_DIR)/bs_antidebug.c \
           $(SRC_DIR)/bs_integrity.c \
           $(SRC_DIR)/bs_secure_mem.c \
           $(SRC_DIR)/bs_string_crypt.c

LIB_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))

.PHONY: all clean test protect-demo protect

all: $(BUILD_DIR) $(BUILD_DIR)/bs_stub.exe $(BUILD_DIR)/bs_protect.exe $(BUILD_DIR)/bs_test.exe

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Загрузчик stub (автономный)
$(BUILD_DIR)/bs_stub.exe: $(SRC_DIR)/bs_stub.c $(INC_DIR)/bs_pack_format.h
	$(CC) $(STUB_CFLAGS) $(SRC_DIR)/bs_stub.c -o $@ $(STUB_LDFLAGS)

# Утилита протектора v2
$(BUILD_DIR)/bs_protect.exe: $(LIB_OBJS) $(SRC_DIR)/bs_protect_v2.c
	$(CC) $(CFLAGS) $(LIB_OBJS) $(SRC_DIR)/bs_protect_v2.c -o $@ $(LDFLAGS)

# Тестовый бинарник
$(BUILD_DIR)/bs_test.exe: $(LIB_OBJS) $(TEST_DIR)/test_all.c
	$(CC) $(CFLAGS) $(LIB_OBJS) $(TEST_DIR)/test_all.c -o $@ $(LDFLAGS)

test: $(BUILD_DIR)/bs_test.exe
	./$(BUILD_DIR)/bs_test.exe

protect-demo: all
	$(BUILD_DIR)/bs_protect.exe $(BUILD_DIR)/bs_test.exe $(BUILD_DIR)/bs_test_protected.exe

# Usage: make protect TARGET=app.exe OUTPUT=app_safe.exe
protect: $(BUILD_DIR)/bs_protect.exe $(BUILD_DIR)/bs_stub.exe
	$(BUILD_DIR)/bs_protect.exe $(TARGET) $(OUTPUT)

clean:
	rm -rf $(BUILD_DIR)
