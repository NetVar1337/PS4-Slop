set(SLOP_CORE_SOURCES
    infra/capability.hpp
    infra/published.hpp
    infra/cancel.hpp
    infra/clock.hpp
    infra/limits.hpp
    infra/diag.hpp
    infra/diag.cpp
    infra/paths.hpp
    infra/paths.cpp
    infra/settings.hpp
    infra/settings.cpp
    infra/work_queue.hpp
    infra/work_queue.cpp
    infra/jobs.hpp
    infra/jobs.cpp
    infra/text_format.hpp
    infra/text_format.cpp
    infra/event_bus.hpp
    infra/event_bus.cpp
    infra/app_control.hpp
    infra/app_control.cpp
    infra/lifecycle.hpp
    infra/lifecycle.cpp
    memory/reader.hpp
    memory/read_util.hpp
    memory/read_util.cpp
    memory/memscan.hpp
    memory/memscan.cpp
    memory/watch_service.hpp
    memory/watch_service.cpp
    memory/aob.hpp
    memory/aob.cpp
    memory/pointer_scan.hpp
    memory/pointer_scan.cpp
    memory/snapshot.hpp
    memory/snapshot.cpp
    memory/console_scan.hpp
    memory/console_scan.cpp
    memory/session_reader.hpp
    analysis/packer.hpp
    analysis/packer.cpp
    analysis/signatures.hpp
    analysis/signatures.cpp
    analysis/danger.hpp
    analysis/danger.cpp
    analysis/libsig.hpp
    analysis/libsig.cpp
    analysis/xray.hpp
    analysis/xray.cpp
    analysis/ps4_syscalls.hpp
    analysis/ps4_syscalls.cpp
    analysis/imgpatch.hpp
    analysis/imgpatch.cpp
    analysis/recover.hpp
    analysis/recover.cpp
    analysis/devirt.hpp
    analysis/devirt.cpp
    analysis/magicmida.hpp
    analysis/magicmida.cpp
    network/traffic_store.hpp
    network/traffic_store.cpp
    network/capture_service.hpp
    network/capture_service.cpp
    network/http_proxy.hpp
    network/http_proxy.cpp
    network/parsers.hpp
    network/parsers.cpp
    network/redact.hpp
    network/redact.cpp
    network/pcap_import.hpp
    network/pcap_import.cpp
    network/net_socket.hpp
    network/net_socket.cpp
    network/tls_stream.hpp
    network/tls_stream.cpp
    persist/session_store.hpp
    persist/session_store.cpp
    re/rtti.hpp
    re/rtti.cpp
    re/type_catalog.hpp
    re/type_catalog.cpp
    process/heap_list.hpp
    process/heap_list.cpp
    infra/deferred.hpp
    infra/deferred.cpp
    util/fs_tools.hpp
    util/fs_tools.cpp
    util/zip_reader.hpp
    util/zip_reader.cpp
    util/zip_writer.hpp
    util/zip_writer.cpp
    util/sha256.hpp
    util/sha256.cpp
    memory/offsets.hpp
    memory/offsets.cpp
    memory/dissect.hpp
    memory/dissect.cpp
    network/web_fetch.hpp
    network/web_fetch.cpp
    network/mitm_pki.hpp
    network/mitm_pki.cpp
    script/lua_engine.hpp
    script/lua_engine.cpp
    emu/taint.hpp
    emu/taint.cpp
    emu/unicorn.hpp
    emu/unicorn.cpp
    emu/orbis.hpp
    emu/orbis.cpp
    emu/session.hpp
    emu/session.cpp
    disasm/engine.hpp
    disasm/engine.cpp
    disasm/pe_parser.hpp
    disasm/pe_parser.cpp
    disasm/ipa.hpp
    disasm/ipa.cpp
    disasm/image_open.hpp
    disasm/image_open.cpp
    disasm/strings.hpp
    disasm/strings.cpp
    disasm/function_index.hpp
    disasm/function_index.cpp
    disasm/xrefs.hpp
    disasm/xrefs.cpp
    disasm/binary_state.hpp
    disasm/binary_state.cpp
    disasm/hyperion_session.hpp
    disasm/hyperion_session.cpp
    debugger/callstack.hpp
    debugger/callstack.cpp
    debugger/debug_target.hpp
    debugger/composite.hpp
    debugger/composite.cpp
    debugger/ps4_debug_target.hpp
    debugger/ps4_debug_target.cpp
    debugger/local_debugger.hpp
    debugger/local_debugger.cpp
    runtime/context.hpp
    runtime/backend.hpp
    runtime/backend_usermode.hpp
    runtime/backend_usermode.cpp
    runtime/backend_registry.hpp
    runtime/backend_registry.cpp
    runtime/ps4_protocol.hpp
    runtime/backend_ps4.hpp
    runtime/backend_ps4.cpp
    runtime/ps5_protocol.hpp
    runtime/backend_ps5.hpp
    runtime/backend_ps5.cpp
    runtime/scan_bridge.hpp
    runtime/scan_bridge.cpp
    runtime/session.hpp
    runtime/session.cpp
    runtime/console_manager.hpp
    runtime/console_manager.cpp
    process/process_list.hpp
    process/process_list.cpp
    process/process_icon.hpp
    process/process_icon.cpp
    process/target_service.hpp
    process/target_service.cpp
    process/module_table.hpp
    process/module_table.cpp
    process/module_dump.hpp
    process/module_dump.cpp
    process/thread_table.hpp
    process/thread_table.cpp
    process/handle_table.hpp
    process/handle_table.cpp
    mcp/mcp_server.hpp
    mcp/mcp_server.cpp
    mcp/mcp_tools.hpp
    mcp/mcp_tools.cpp
    mcp/tools_common.hpp
    mcp/tools_common.cpp
    mcp/tools_target.cpp
    mcp/tools_memory.cpp
    mcp/tools_disasm.cpp
    mcp/tools_debugger.cpp
    mcp/tools_emulate.cpp
    mcp/tools_analyze.cpp
    mcp/tools_network.cpp
    mcp/tools_fs_web.cpp
    mcp/tools_decomp.cpp
    mcp/tools_persist.cpp
    mcp/tools_re.cpp
    mcp/tools_xray.cpp
    mcp/tools_patch.cpp
    mcp/tools_types_notes.cpp
    mcp/tools_devirt.cpp
    mcp/tools_script.cpp
    mcp/tools_app_guide.cpp
    mcp/tools_host.cpp
    mcp/tools_gdb.cpp
    runtime/broker.hpp
    runtime/broker.cpp
    runtime/gdb_rsp.hpp
    runtime/gdb_rsp.cpp
    infra/mcp_onboard.hpp
    infra/mcp_onboard.cpp
)

if(NOT WIN32)
    # Whole-file replacements: the Win32 implementation cannot be #ifdef'd
    # into shape (Win32 debug API, Schannel, CNG certificate minting, GDI
    # icons, Toolhelp heaps). Everything else keeps its file and grows a
    # POSIX branch; docs/linux.md lists both sets.
    list(REMOVE_ITEM SLOP_CORE_SOURCES
        runtime/backend_usermode.cpp
        util/fs_tools.cpp
        network/tls_stream.cpp
        network/mitm_pki.cpp
        process/process_icon.cpp
        process/heap_list.cpp
        debugger/local_debugger.cpp
    )
    list(APPEND SLOP_CORE_SOURCES
        runtime/backend_posix.cpp
        util/fs_tools_posix.cpp
        network/tls_stream_posix.cpp
        network/mitm_pki_posix.cpp
        process/process_icon_posix.cpp
        process/heap_list_posix.cpp
        debugger/local_debugger_posix.cpp
    )
endif()

add_library(slop_core STATIC ${SLOP_CORE_SOURCES})

target_include_directories(slop_core PUBLIC "${CMAKE_SOURCE_DIR}/src")

# Deliberately NOT slop_imgui, core must never see ImGui headers
target_link_libraries(slop_core PUBLIC
    nlohmann_json::nlohmann_json
    Zydis
    httplib::httplib
    slop_hyperion
)

if(WIN32)
    # Win32 system libs (static link, no import lib needed for ntdll, resolved at runtime)
    target_link_libraries(slop_core PRIVATE
        psapi advapi32 shlwapi ole32 shell32 crypt32 winhttp dbghelp setupapi
        unicorn
        slop_sqlite
        slop_lua
        ws2_32
    )
else()
    target_link_libraries(slop_core PRIVATE
        unicorn
        slop_sqlite
        slop_lua
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        dl
    )
endif()

target_compile_definitions(slop_core PUBLIC
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(slop_core PRIVATE /W4 /WX /EHsc)
else()
    # MSVC /W4 does not flag these two, and the ported code is full of them
    target_compile_options(slop_core PRIVATE
        -Wall -Wextra -Werror -Wno-switch -Wno-unused-but-set-variable)
endif()
