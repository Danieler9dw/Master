CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -g
LDFLAGS ?=

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
TEST_DIR := tests

SERVER_SRCS := $(wildcard $(SRC_DIR)/*.c)
SERVER_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SRCS))

TARGET := $(BIN_DIR)/tacacsd
TEST_BINS := $(BIN_DIR)/test_md5 $(BIN_DIR)/test_packet $(BIN_DIR)/test_eap $(BIN_DIR)/test_eap_attr

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SERVER_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJS) $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "== $$t =="; \
		./$$t || exit 1; \
	done

$(BIN_DIR)/test_md5: $(TEST_DIR)/test_md5.c $(BUILD_DIR)/md5.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/test_md5.c $(BUILD_DIR)/md5.o

$(BIN_DIR)/test_packet: $(TEST_DIR)/test_packet.c $(BUILD_DIR)/packet.o $(BUILD_DIR)/md5.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/test_packet.c $(BUILD_DIR)/packet.o $(BUILD_DIR)/md5.o

$(BIN_DIR)/test_eap: $(TEST_DIR)/test_eap.c $(BUILD_DIR)/eap.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/test_eap.c $(BUILD_DIR)/eap.o

$(BIN_DIR)/test_eap_attr: $(TEST_DIR)/test_eap_attr.c $(BUILD_DIR)/eap_attr.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/test_eap_attr.c $(BUILD_DIR)/eap_attr.o

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
