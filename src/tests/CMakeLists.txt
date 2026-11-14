option(SLOP_BUILD_TESTS "Build the core logic test harness" ON)

if(NOT SLOP_BUILD_TESTS)
    return()
endif()

if(NOT WIN32)
    # Portable subset: the areas whose fixtures are built in memory or on
    # loopback (Mach-O/IPA, Unicorn emulation, the ps4debug/ps5debug fake
    # servers). Areas that need SlopTarget.exe or Win32 APIs are Windows-only.
    add_executable(slop_tests
        test_main.cpp
        test_ipa.cpp
        test_emu.cpp
        test_ps4.cpp
        test_ps4_chaos.cpp
        test_ps4_debug.cpp
        test_ps5.cpp
        test_disasm_accuracy.cpp
    )
    target_include_directories(slop_tests PRIVATE
        "${CMAKE_SOURCE_DIR}/src/tests"
        "${CMAKE_SOURCE_DIR}/src")
    target_link_libraries(slop_tests PRIVATE slop_core httplib::httplib)
    target_compile_options(slop_tests PRIVATE
        -Wall -Wextra -Werror -Wno-switch -Wno-unused-but-set-variable
        -Wno-unused-function -Wno-stringop-truncation)
    set_target_properties(slop_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    add_test(NAME slop_tests COMMAND slop_tests)
    return()
endif()

add_executable(slop_tests
    test_main.cpp
    test_app_performance.cpp
    test_infra.cpp
    test_memory.cpp
    test_disasm.cpp
    test_disasm_accuracy.cpp
    test_mcp.cpp
    test_analysis.cpp
    test_emu.cpp
    test_network.cpp
    test_persist.cpp
    test_re.cpp
    test_script.cpp
    test_module_dump.cpp
    test_process_tables.cpp
    test_decomp.cpp
    test_hyperion.cpp
    test_detect_fs.cpp
    test_xray.cpp
    test_magicmida.cpp
    test_ipa.cpp
    test_ps4.cpp
    test_ps4_debug.cpp
    test_ps4_chaos.cpp
    test_ps4_tooling.cpp
    test_ps5.cpp
    test_harness.cpp
)

target_include_directories(slop_tests PRIVATE "${CMAKE_SOURCE_DIR}/src/tests")
target_include_directories(slop_tests PRIVATE "${CMAKE_SOURCE_DIR}/src")

target_link_libraries(slop_tests PRIVATE slop_core httplib::httplib)

# Real-world PE fixture: the built SlopTarget.exe itself (hidden local
# user-mode target used by the test harness only)
if(TARGET slop_target)
    target_compile_definitions(slop_tests PRIVATE
        SLOP_TARGET_EXE_PATH=\"$<TARGET_FILE:slop_target>\"
    )
    add_dependencies(slop_tests slop_target)
endif()

# the --port / ready-announce test spawns the real engine binary
if(TARGET reverse-slop-engine)
    add_dependencies(slop_tests reverse-slop-engine)
endif()

if(MSVC)
    target_compile_options(slop_tests PRIVATE /W4 /WX /EHsc)
endif()

set_target_properties(slop_tests PROPERTIES
    OUTPUT_NAME "slop_tests"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

# One CTest entry per test area (a test_<area>.cpp file, the harness derives
# the same area name from __FILE__) plus one entry running the whole suite.
# Derived from the source list so a new test file is registered automatically.
# CI runs `ctest -L area`; `ctest -L all` is the single-process full run.
get_target_property(_slop_test_sources slop_tests SOURCES)
set(_slop_test_areas "")
foreach(_src IN LISTS _slop_test_sources)
    get_filename_component(_name "${_src}" NAME_WE)
    if(_name MATCHES "^test_(.+)$" AND NOT _name STREQUAL "test_main")
        list(APPEND _slop_test_areas "${CMAKE_MATCH_1}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _slop_test_areas)
list(SORT _slop_test_areas)

foreach(_area IN LISTS _slop_test_areas)
    add_test(NAME "slop_tests_${_area}" COMMAND slop_tests)
    set_tests_properties("slop_tests_${_area}" PROPERTIES
        ENVIRONMENT "SLOP_TEST_AREA=${_area}"
        LABELS "slop;area"
        # the per-test watchdog is the real guard; this caps a wedged process
        # (600 s leaves room for the 4x-slower ASan lane, healthy areas take < 40 s)
        TIMEOUT 600
    )
    # the backend's debug-event listener binds the fixed port 755: the ps4
    # areas run one at a time, alongside every other area
    if(_area MATCHES "^ps4")
        set_tests_properties("slop_tests_${_area}" PROPERTIES RESOURCE_LOCK ps4_debug_port)
    endif()
endforeach()

# ASan lane: the mcp area is the HTTP/JSON/SSE/fs/web attack surface, but a
# few of its cases drive the Unicorn emulator (incompatible with ASan). Run
# the area without those cases so the transport stays sanitized.
add_test(NAME slop_tests_mcp_noemu COMMAND slop_tests)
set_tests_properties(slop_tests_mcp_noemu PROPERTIES
    ENVIRONMENT "SLOP_TEST_AREA=mcp;SLOP_TEST_EXCLUDE=emulate"
    LABELS "slop;asan;mcpnoemu"
    TIMEOUT 600
)

add_test(NAME slop_tests_all COMMAND slop_tests)
set_tests_properties(slop_tests_all PROPERTIES
    LABELS "slop;all"
    TIMEOUT 5400
)

if(TARGET slop_decomp_target_o0 AND TARGET slop_decomp_target_o2)
    add_executable(slop_bench bench_hyperion.cpp)
    target_include_directories(slop_bench PRIVATE "${CMAKE_SOURCE_DIR}/src")
    target_link_libraries(slop_bench PRIVATE slop_core nlohmann_json::nlohmann_json psapi)
    target_compile_definitions(slop_bench PRIVATE
        SLOP_DECOMP_TARGET_O0_PATH="$<TARGET_FILE:slop_decomp_target_o0>"
        SLOP_DECOMP_TARGET_O2_PATH="$<TARGET_FILE:slop_decomp_target_o2>"
    )
    add_dependencies(slop_bench slop_decomp_target_o0 slop_decomp_target_o2)
    if(MSVC)
        target_compile_options(slop_bench PRIVATE /W4 /WX /EHsc)
    endif()
    set_target_properties(slop_bench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
endif()

add_executable(slop_app_bench bench_app.cpp)
target_include_directories(slop_app_bench PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(slop_app_bench PRIVATE slop_core nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(slop_app_bench PRIVATE /W4 /WX /EHsc)
endif()
set_target_properties(slop_app_bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
