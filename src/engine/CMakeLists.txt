# Console-subsystem host for the core. Links slop_core only, never slop_ui,
# so the ImGui/DX11 stack cannot creep back in through this target
add_executable(reverse-slop-engine
    engine_main.cpp
)

slop_add_win_resources(reverse-slop-engine
    DESCRIPTION "reverse-slop engine (MCP/HTTP host)"
    MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/engine.manifest.in")

target_include_directories(reverse-slop-engine PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(reverse-slop-engine PRIVATE slop_core)

if(MSVC)
    target_compile_options(reverse-slop-engine PRIVATE /W4 /WX)
endif()
