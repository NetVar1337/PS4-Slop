# game resident payload build.
# This example lives inside PS4-MCP; standalone projects use ../PS4-MCP.
WORKBENCH_DIR ?= ../..
TARGET       ?= payload.elf
SRCS         := src/payload.cpp $(WORKBENCH_DIR)/internals/src/runtime.cpp \
                $(WORKBENCH_DIR)/internals/src/draw.cpp $(WORKBENCH_DIR)/internals/src/input.cpp
LDLIBS_EXTRA ?= -lScePad -lSceUserService
CXXFLAGS_EXTRA := -DPS4WB_ENGINE_UNREAL
include $(WORKBENCH_DIR)/templates/payload/orbis.mk

PS4_PROFILE     ?= $(WORKBENCH_DIR)/profiles/ps4-1400.local.json
PS4_WORKBENCH   ?= ps4-workbench
PID             ?= 0
TARGET_MANIFEST ?=

inject: $(TARGET)
	$(PS4_WORKBENCH) --profile $(PS4_PROFILE) --toolset full inject --pid $(PID) --target $(TARGET_MANIFEST) --payload $(CURDIR)/$(TARGET)

host-test:
	python build.py --host-test --engine unreal

clean:
	rm -rf $(BUILD) $(TARGET)

.PHONY: inject host-test clean
