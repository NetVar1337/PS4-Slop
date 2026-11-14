cmake_minimum_required(VERSION 3.25)

set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0090 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0141 NEW)

# Single version source: the VERSION file. tools/sync_version.ps1 copies it
# into app/package.json, app/src-tauri/tauri.conf.json and Cargo.toml, and CI
# fails a tag build whose tag does not match it.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" SLOP_VERSION LIMIT_COUNT 1)
string(STRIP "${SLOP_VERSION}" SLOP_VERSION)
if(NOT SLOP_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got '${SLOP_VERSION}'")
endif()
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/tools/magicmida-version.txt" SLOP_MAGICMIDA_VERSION LIMIT_COUNT 1)
string(STRIP "${SLOP_MAGICMIDA_VERSION}" SLOP_MAGICMIDA_VERSION)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/VERSION"
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/magicmida-version.txt")

# MASM only exists on Windows; elsewhere only the portable libraries build
set(_slop_languages C CXX)
if(CMAKE_HOST_WIN32)
    list(APPEND _slop_languages ASM_MASM)
endif()
project(reverse-slop VERSION ${SLOP_VERSION} LANGUAGES ${_slop_languages})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# compile_commands.json feeds clang-tidy (tools/clang_tidy.ps1) and IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo,Release>:Embedded>")

option(SLOP_BUILD_TEST_TARGET "Build SlopTarget.exe test target" ON)
option(SLOP_BUILD_TESTS "Build the core logic test harness" ON)
option(SLOP_BUILD_ENGINE "Build the headless engine host (Tauri front end backend)" ON)
option(SLOP_BUILD_UI "Build the legacy ImGui shell (reverse-slop.exe)" ON)
option(SLOP_ANALYZE "Run MSVC /analyze on first-party targets" OFF)
option(SLOP_BUILD_FUZZ "Build the libFuzzer targets in src/fuzz (needs SLOP_SANITIZE=address)" OFF)
set(SLOP_SANITIZE "" CACHE STRING "Sanitizer for every target: empty or 'address'")
set_property(CACHE SLOP_SANITIZE PROPERTY STRINGS "" "address")

if(MSVC)
    add_compile_definitions(UNICODE _UNICODE)
    # scoped to c and cxx so the vendored asm sources never see compiler switches
    add_compile_options(
        "$<$<COMPILE_LANGUAGE:C,CXX>:/permissive->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/Zc:__cplusplus>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/GS>"
    )
    add_link_options(
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        # deliberately NOT /guard:cf + /GUARD:CF (CFG) and NOT /CETCOMPAT: the
        # Unicorn emulator executes code it generates at runtime, which is in no
        # CFG target table and does no shadow-stack bookkeeping, so either one
        # kills the first emulation run with STATUS_STACK_BUFFER_OVERRUN
        # (__fastfail). ASLR/DEP/stack cookies stay on; tools/check_binaries.ps1
        # verifies them on the release artifacts, SECURITY.md explains the two
        # omissions.
    )
endif()

if(SLOP_SANITIZE STREQUAL "address")
    if(NOT MSVC)
        message(FATAL_ERROR "SLOP_SANITIZE=address is wired for MSVC only")
    endif()
    # Applied before the dependencies are added: MSVC's STL container
    # annotations must match across every object in the link
    # (/FAILIFMISMATCH:annotate_*), so instrumentation is all-or-nothing.
    # /RTC and incremental linking are incompatible with ASan.
    foreach(_slop_flags_var CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG)
        string(REGEX REPLACE "/RTC[1csu]+" "" ${_slop_flags_var} "${${_slop_flags_var}}")
    endforeach()
    add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:/fsanitize=address>")
    # instrumentation multiplies COMDAT sections; large tables (ps4_nid.cpp)
    # overflow the default object format
    add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:/bigobj>")
    add_link_options(/INCREMENTAL:NO)
    add_compile_definitions(SLOP_ASAN=1)
elseif(NOT SLOP_SANITIZE STREQUAL "")
    message(FATAL_ERROR "unsupported SLOP_SANITIZE='${SLOP_SANITIZE}' (use '' or 'address')")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(deps)

# Off Windows: the headless engine, its core and the portable test subset.
# The window shell (DX11/ImGui), the Win32 user-mode backend and the pieces
# that need Windows-only services (Schannel, CNG certificate minting, the
# Win32 debug API, the magicmida sidecar) are replaced by POSIX ports or
# gated out; docs/linux.md lists what runs and what does not.
if(NOT WIN32)
    add_compile_definitions(
        SLOP_VERSION_STRING="${PROJECT_VERSION}"
        SLOP_MAGICMIDA_VERSION="${SLOP_MAGICMIDA_VERSION}"
    )
    enable_testing()

    add_subdirectory(src/hyperion)
    add_subdirectory(src/core)

    if(SLOP_BUILD_ENGINE)
        add_subdirectory(src/engine)
    endif()

    if(SLOP_BUILD_TESTS)
        add_subdirectory(src/tests)
    endif()

    return()
endif()

include(slop_resources)

# Everything below is first-party: dependency targets were created above and
# never see these options.
add_compile_definitions(
    SLOP_VERSION_STRING="${PROJECT_VERSION}"
    SLOP_MAGICMIDA_VERSION="${SLOP_MAGICMIDA_VERSION}"
)
if(MSVC AND SLOP_ANALYZE)
    # dependency headers come in through SYSTEM include dirs (/external:I),
    # /analyze:external- keeps the analysis on our own code.
    # /analyze:WX- keeps the findings advisory: the lane reports them in the run
    # summary instead of failing the build. The codebase carries a standing
    # backlog of C6xxx findings, so treating them as errors made the lane red
    # from the day it was added. /WX still applies to ordinary compiler warnings.
    add_compile_options(
        "$<$<COMPILE_LANGUAGE:C,CXX>:/analyze>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/analyze:external->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/analyze:WX->"
    )
endif()

enable_testing()

add_subdirectory(src/hyperion)
add_subdirectory(src/core)

if(SLOP_BUILD_UI)
    add_subdirectory(src/ui)
    add_subdirectory(src/app)
endif()

if(SLOP_BUILD_ENGINE)
    add_subdirectory(src/engine)
endif()

if(SLOP_BUILD_TEST_TARGET)
    add_subdirectory(src/target)
endif()

if(SLOP_BUILD_TESTS)
    add_subdirectory(src/tests)
endif()

if(SLOP_BUILD_FUZZ)
    add_subdirectory(src/fuzz)
endif()

add_subdirectory(src/live)
