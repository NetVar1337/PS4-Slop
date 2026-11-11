include_guard(GLOBAL)
include(FetchContent)

# Downloaded dependency sources plus their sub-builds/binary dirs. The primary
# build/ tree uses _ext/ (cached by CI); the other presets (debug, asan,
# analyze) point this into their own binary dir because a dependency's binary
# dir under here belongs to exactly one build tree.
set(SLOP_DEPS_DIR "${CMAKE_SOURCE_DIR}/_ext" CACHE PATH "FetchContent base dir for dependency sources and builds")
set(FETCHCONTENT_BASE_DIR "${SLOP_DEPS_DIR}" CACHE PATH "" FORCE)
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# Every archive is pinned by SHA-256 and every git dependency by a full commit
# SHA, so a moved tag or a tampered download fails the configure instead of
# being compiled into the shipped engine. Bumping a dep means updating both
# the URL and its hash (tools/dep_hash.ps1 prints the hash of a URL).
# Dear ImGui v1.92.1-docking (tag object e0b5968) -> commit 44aa9a4
set(SLOP_IMGUI_COMMIT "44aa9a4b3a6f27d09a4eb5770d095cbd376dfc4b")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
# zlib's examples register CTest entries (example/example64); CTest lists only
# reverse-slop's own tests
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER ON CACHE BOOL "" FORCE)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)

set(FT_DISABLE_ZLIB TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_BROTLI TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_BZIP2 TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_PNG TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_HARFBUZZ TRUE CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)

set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_ARCH "x86" CACHE STRING "" FORCE)

# hyperion engine deps
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
set(SPDLOG_ENABLE_PCH OFF CACHE BOOL "" FORCE)

# capstone only for the architectures hyperion decodes beyond x86 and x64,
# keep the tool set small so builds stay quick (was all 16 arches: single
# biggest C++ configure/compile saving, ~1-3 min on CI)
set(CAPSTONE_BUILD_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)

FetchContent_Declare(fmt
    URL https://github.com/fmtlib/fmt/archive/refs/tags/11.1.4.zip
    URL_HASH SHA256=7e85cbf6125a76daa0f83cd9240eff863d988aca68cd5f66c01ff7b59fa886b6
    SYSTEM
)

FetchContent_Declare(spdlog
    URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.3.zip
    URL_HASH SHA256=b74274c32c8be5dba70b7006c1d41b7d3e5ff0dff8390c8b6390c1189424e094
    SYSTEM
)

FetchContent_Declare(capstone
    URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.zip
    URL_HASH SHA256=3b3bdad8a75c4a9cbec28efd47778e412904db1588ec606d516b7196e8e6668e
    SYSTEM
)

FetchContent_Declare(zlib_kr
    URL https://github.com/madler/zlib/archive/refs/tags/v1.3.1.zip
    URL_HASH SHA256=50b24b47bf19e1f35d2a21ff36d2a366638cdf958219a66f30ce0861201760e6
    SYSTEM
)

FetchContent_Declare(freetype
    URL https://github.com/freetype/freetype/archive/refs/tags/VER-2-13-3.zip
    URL_HASH SHA256=a7165cb405dfce349ae64d6f59efb2567565ca8edbacbeff2a8d0e4cfa779cf5
    SYSTEM
)

# v3.12.0 release tarball (the layout upstream recommends for FetchContent)
FetchContent_Declare(nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    SYSTEM
)

# v4.1.1; git (not an archive) because zycore comes in as a submodule.
# GIT_SHALLOW cannot fetch an arbitrary commit, so this one is a full clone
FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc
    GIT_SUBMODULES_RECURSE TRUE
    SYSTEM
)

FetchContent_Declare(imgui
    URL https://github.com/ocornut/imgui/archive/${SLOP_IMGUI_COMMIT}.zip
    URL_HASH SHA256=56c0ada056a6a9676759d533afc6f0b0c7cfbf6fe72b51a8a2b3d77dad75dfb4
    SYSTEM
)

FetchContent_Declare(httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.18.7.zip
    URL_HASH SHA256=a5e878f58b035b6b2258c982af5696b7e510ee7e6033799e083bcdc6efc0cdfe
    SYSTEM
)

FetchContent_Declare(unicorn
    URL https://github.com/unicorn-engine/unicorn/archive/refs/tags/2.1.4.zip
    URL_HASH SHA256=787a4b46ad5df58f1eec11343c55b163779df32dbe9e7d9d0f99967f34a1ff79
    SYSTEM
)

FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip
    URL_HASH SHA256=1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032
    SYSTEM
)

# lua.org is the canonical host but is regularly unreachable from the CI
# runners, which failed the configure step outright. The mirrors below serve
# the byte-identical tarball (same SHA256), so CMake falls through to them
# without changing the layout or weakening the integrity check.
FetchContent_Declare(lua
    URL https://www.lua.org/ftp/lua-5.4.7.tar.gz
        https://sources.buildroot.org/lua/lua-5.4.7.tar.gz
        https://distfiles.macports.org/lua/lua-5.4.7.tar.gz
        https://ftp.osuosl.org/pub/blfs/conglomeration/lua/lua-5.4.7.tar.gz
    URL_HASH SHA256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
    SYSTEM
)

# httplib grabs openssl or zlib off the host when they happen to be installed,
# which dragged libssl and libcrypto runtime dlls into the engine on the ci
# runner, we serve plain loopback http so none of that is ever wanted
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(freetype nlohmann_json zydis imgui httplib unicorn sqlite lua fmt spdlog capstone zlib_kr)

# zlib builds both a shared and a static lib, we only want the static one so
# the exes stay freestanding
if(NOT TARGET ZLIB::ZLIB)
    add_library(ZLIB::ZLIB ALIAS zlibstatic)
endif()

# vendored c sources with no cmake build of their own
add_library(slop_sqlite STATIC
    "${sqlite_SOURCE_DIR}/sqlite3.c"
)
target_include_directories(slop_sqlite SYSTEM PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(slop_sqlite PRIVATE
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_THREADSAFE=1
)
if(MSVC)
    target_compile_options(slop_sqlite PRIVATE /W0)
endif()

# Lua must build as C++: LUAI_THROW then raises a real C++ exception, so a
# lua error unwinds host C++ frames with correct per-state destructor
# tracking. As C (longjmp, a foreign RtlUnwind) every registered dtor in a
# binding frame runs, constructed or not, and shared_ptr locals blow up.
set(slop_lua_sources
    "${lua_SOURCE_DIR}/src/lapi.c"
    "${lua_SOURCE_DIR}/src/lauxlib.c"
    "${lua_SOURCE_DIR}/src/lbaselib.c"
    "${lua_SOURCE_DIR}/src/lcode.c"
    "${lua_SOURCE_DIR}/src/lcorolib.c"
    "${lua_SOURCE_DIR}/src/lctype.c"
    "${lua_SOURCE_DIR}/src/ldblib.c"
    "${lua_SOURCE_DIR}/src/ldebug.c"
    "${lua_SOURCE_DIR}/src/ldo.c"
    "${lua_SOURCE_DIR}/src/ldump.c"
    "${lua_SOURCE_DIR}/src/lfunc.c"
    "${lua_SOURCE_DIR}/src/lgc.c"
    "${lua_SOURCE_DIR}/src/linit.c"
    "${lua_SOURCE_DIR}/src/liolib.c"
    "${lua_SOURCE_DIR}/src/llex.c"
    "${lua_SOURCE_DIR}/src/lmathlib.c"
    "${lua_SOURCE_DIR}/src/lmem.c"
    "${lua_SOURCE_DIR}/src/loadlib.c"
    "${lua_SOURCE_DIR}/src/lobject.c"
    "${lua_SOURCE_DIR}/src/lopcodes.c"
    "${lua_SOURCE_DIR}/src/loslib.c"
    "${lua_SOURCE_DIR}/src/lparser.c"
    "${lua_SOURCE_DIR}/src/lstate.c"
    "${lua_SOURCE_DIR}/src/lstring.c"
    "${lua_SOURCE_DIR}/src/lstrlib.c"
    "${lua_SOURCE_DIR}/src/ltable.c"
    "${lua_SOURCE_DIR}/src/ltablib.c"
    "${lua_SOURCE_DIR}/src/ltm.c"
    "${lua_SOURCE_DIR}/src/lundump.c"
    "${lua_SOURCE_DIR}/src/lutf8lib.c"
    "${lua_SOURCE_DIR}/src/lvm.c"
    "${lua_SOURCE_DIR}/src/lzio.c"
)
set_source_files_properties(${slop_lua_sources} PROPERTIES LANGUAGE CXX)
add_library(slop_lua STATIC ${slop_lua_sources})
target_include_directories(slop_lua SYSTEM PUBLIC "${lua_SOURCE_DIR}/src")
target_compile_definitions(slop_lua PRIVATE
    LUA_USE_WINDOWS
)
if(MSVC)
    target_compile_options(slop_lua PRIVATE /W0)
endif()

if(MSVC)
    foreach(_slop_dep_target freetype Zydis Zycore nlohmann_json_schema_validator
                             unicorn unicorn-common fmt spdlog capstone)
        if(TARGET ${_slop_dep_target})
            target_compile_options(${_slop_dep_target} PRIVATE /W0)
        endif()
    endforeach()
endif()

add_library(slop_imgui STATIC
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
    "${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.cpp"
)

target_include_directories(slop_imgui SYSTEM PUBLIC
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
    "${imgui_SOURCE_DIR}/misc/freetype"
)

target_compile_definitions(slop_imgui PUBLIC IMGUI_ENABLE_FREETYPE)
target_link_libraries(slop_imgui PUBLIC freetype d3d11 dxgi)

if(MSVC)
    target_compile_options(slop_imgui PRIVATE /W0)
endif()
