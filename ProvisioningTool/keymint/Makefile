CC = g++
SRC_DIR = src

CONSTRUCT_APDUS_SRC = $(SRC_DIR)/construct_apdus.cpp \
                      $(SRC_DIR)/cppbor/cppbor.cpp \
                      $(SRC_DIR)/cppbor/cppbor_parse.cpp \
                      $(SRC_DIR)/utils.cpp \
                      $(SRC_DIR)/cppcose/cppcose.cpp

CONSTRUCT_APDUS_OBJFILES = $(CONSTRUCT_APDUS_SRC:.cpp=.o)
CONSTRUCT_APDUS_BIN = construct_keymint_apdus

# source files for provision
PROVISION_SRC = $(SRC_DIR)/provision.cpp \
                $(SRC_DIR)/socket.cpp \
                $(SRC_DIR)/cppbor/cppbor.cpp \
                $(SRC_DIR)/cppbor/cppbor_parse.cpp \
                $(SRC_DIR)/utils.cpp \

#object files for keymint provision
PROVISION_OBJFILES = $(PROVISION_SRC:.cpp=.o)
PROVISION_BIN = provision_keymint

ifeq ($(OS),Windows_NT)
    uname_S := Windows
else
    uname_S := $(shell uname -s)
endif

ifeq ($(uname_S), Windows)
    PLATFORM = -D__WIN32__
endif
ifeq ($(uname_S), Linux)
    PLATFORM = -D__LINUX__
endif

DEBUG = -g
CXXFLAGS = $(DEBUG) $(PLATFORM) -Wall -std=c++2a
CFLAGS = $(CXXFLAGS) -Iinclude
LDFLAGS = -Llib/
LIB_JSON = -ljsoncpp
LIB_CRYPTO = -lcrypto
LDLIBS = $(LIB_JSON) $(LIB_CRYPTO)

all: $(CONSTRUCT_APDUS_BIN) $(PROVISION_BIN)

$(CONSTRUCT_APDUS_BIN): $(CONSTRUCT_APDUS_OBJFILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(PROVISION_BIN): $(PROVISION_OBJFILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f $(CONSTRUCT_APDUS_OBJFILES) $(CONSTRUCT_APDUS_BIN) $(PROVISION_OBJFILES) $(PROVISION_BIN)
