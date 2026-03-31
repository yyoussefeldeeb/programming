CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I./include
LDFLAGS = -lssl -lcrypto -pthread 

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

SOURCES = $(SRC_DIR)/auth.c $(SRC_DIR)/encryption.c
SERVER_SRC = $(SRC_DIR)/server.c
CLIENT_SRC = $(SRC_DIR)/client.c

OBJECTS = $(BUILD_DIR)/auth.o $(BUILD_DIR)/encryption.o
SERVER_OBJ = $(BUILD_DIR)/server.o
CLIENT_OBJ = $(BUILD_DIR)/client.o

SERVER_EXE = $(BUILD_DIR)/server
CLIENT_EXE = $(BUILD_DIR)/client

.PHONY: all clean build

all: build $(SERVER_EXE) $(CLIENT_EXE)

build:
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_EXE): $(SERVER_OBJ) $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Server built: $@"

$(CLIENT_EXE): $(CLIENT_OBJ) $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Client built: $@"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Build artifacts cleaned"
