# Shared OpenOrbis PS4 payload build fragment for PS4-MCP game projects.
#
# Include from a game repository Makefile instead of duplicating toolchain
# flags in every project:
#
#   WORKBENCH_DIR ?= ../PS4-MCP
#   TARGET        ?= payload.elf
#   SRCS          := src/payload.cpp $(WORKBENCH_DIR)/internals/src/runtime.cpp
#   include $(WORKBENCH_DIR)/templates/payload/orbis.mk
#
# Overridable variables: OO_PS4_TOOLCHAIN, CLANG, LLD, WORKBENCH_DIR,
# INTERNALS_INCLUDE, BUILD, TARGET, SRCS, CXXFLAGS_EXTRA, LDFLAGS_EXTRA,
# LDLIBS_EXTRA. Install the toolchain with scripts/setup-toolchain.{sh,ps1}.

OO_PS4_TOOLCHAIN ?= $(HOME)/.local/openorbis-ps4-toolchain
CLANG            ?= clang++
LLD              ?= ld.lld
WORKBENCH_DIR    ?= ../PS4-MCP
INTERNALS_INCLUDE ?= $(WORKBENCH_DIR)/internals/include
BUILD            ?= build
TARGET           ?= payload.elf
SRCS             ?= src/payload.cpp $(WORKBENCH_DIR)/internals/src/runtime.cpp
LDLIBS_EXTRA     ?=

HDRS := $(wildcard src/*.hpp src/generated/*.hpp) $(wildcard $(INTERNALS_INCLUDE)/internals/*.hpp)
OBJS := $(patsubst %.cpp,$(BUILD)/%.o,$(notdir $(SRCS)))

CXXFLAGS := --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables \
	-fno-exceptions -fno-rtti -O2 -Wall -std=c++17 -D__PS4__ -D_BSD_SOURCE \
	-isysroot $(OO_PS4_TOOLCHAIN) \
	-isystem $(OO_PS4_TOOLCHAIN)/include \
	-isystem $(OO_PS4_TOOLCHAIN)/include/c++/v1 \
	-Isrc -Iinclude -I$(INTERNALS_INCLUDE) $(CXXFLAGS_EXTRA)

LDFLAGS := -m elf_x86_64 -pie --script $(OO_PS4_TOOLCHAIN)/link.x --eh-frame-hdr \
	-L$(OO_PS4_TOOLCHAIN)/lib -lkernel -lc $(LDLIBS_EXTRA) \
	$(OO_PS4_TOOLCHAIN)/lib/crt1.o $(LDFLAGS_EXTRA)

all: $(TARGET)

$(TARGET): check-generated $(OBJS)
	python -c "import os; os.makedirs(r'$(@D)', exist_ok=True)"
	$(LLD) -o $@ $(OBJS) $(LDFLAGS)

check-generated:
	python build.py --check-generated

$(BUILD)/%.o: src/%.cpp $(HDRS) | $(BUILD)
	$(CLANG) $(CXXFLAGS) -c -o $@ $<

$(BUILD)/%.o: $(WORKBENCH_DIR)/internals/src/%.cpp $(HDRS) | $(BUILD)
	$(CLANG) $(CXXFLAGS) -c -o $@ $<

$(BUILD):
	python -c "import os; os.makedirs('$(BUILD)', exist_ok=True)"

.PHONY: all check-generated
