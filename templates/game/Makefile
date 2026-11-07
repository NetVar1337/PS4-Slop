# __NAME__ resident payload build.
# Shared OpenOrbis toolchain flags come from the workbench's orbis.mk fragment;
# do not duplicate them here.
WORKBENCH_DIR ?= ../PS4-MCP
TARGET       ?= __PAYLOAD__
SRCS         := src/payload.cpp $(WORKBENCH_DIR)/internals/src/runtime.cpp
CXXFLAGS_EXTRA := __ENGINE_DEFINE__
include $(WORKBENCH_DIR)/templates/payload/orbis.mk

# Staging goes through the workbench CLI (ps4-workbench inject), which performs
# the hash-qualified upload and RPC recovery; no per-project injector needed.
# Requires a qualified local profile with the process_inject permission.
PS4_PROFILE     ?= $(WORKBENCH_DIR)/profiles/ps4-1400.local.json
PS4_WORKBENCH   ?= ps4-workbench
PID             ?= 0
TARGET_MANIFEST ?=

inject: $(TARGET)
	$(PS4_WORKBENCH) --profile $(PS4_PROFILE) --toolset full inject --pid $(PID) --target $(TARGET_MANIFEST) --payload $(CURDIR)/$(TARGET)

host-test:
	python build.py --host-test --engine __ENGINE__

clean:
	rm -rf $(BUILD) $(TARGET)

.PHONY: inject host-test clean
