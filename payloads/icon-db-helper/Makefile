# Build a small PS5 payload that points the PPSA01650 tile at the persistent SKYBOZ PNG.
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
SQLITE_DIR ?= $(CURDIR)/.deps/sqlite-amalgamation-3460000

ifeq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk),)
$(error PS5 payload SDK not found at "$(PS5_PAYLOAD_SDK)")
endif
ifeq ($(wildcard $(SQLITE_DIR)/sqlite3.c),)
$(error SQLite amalgamation not found at "$(SQLITE_DIR)")
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BUILD_DIR := build
BIN := SKYBOZ_IconDB_Helper.elf
COMMON_CFLAGS := -fplt -O2 -fvisibility=hidden -Isource -I$(SQLITE_DIR)
SQLITE_CFLAGS := $(COMMON_CFLAGS) -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_LOAD_EXTENSION

all: $(BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/icon_db_helper.o: source/icon_db_helper.c | $(BUILD_DIR)
	$(CC) $(COMMON_CFLAGS) -Wall -Wextra -c -o $@ $<

$(BUILD_DIR)/sqlite3.o: $(SQLITE_DIR)/sqlite3.c | $(BUILD_DIR)
	$(CC) $(SQLITE_CFLAGS) -c -o $@ $<

$(BIN): $(BUILD_DIR)/icon_db_helper.o $(BUILD_DIR)/sqlite3.o
	$(CC) -o $@ $^

clean:
	rm -rf $(BUILD_DIR) $(BIN)

.PHONY: all clean
