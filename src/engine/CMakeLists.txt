# Console-subsystem host for the core. Links slop_core only, never slop_ui,
# so the ImGui/DX11 stack cannot creep back in through this target
add_executable(reverse-slop-engine
    engine_main.cpp
    engine.rc
)

# The manifest is embedded as an RT_MANIFEST resource by engine.rc, keep the
# linker's own manifest machinery out of it entirely (CMP0090 NEW)
target_link_options(reverse-slop-engine PRIVATE "/MANIFEST:NO")

target_include_directories(reverse-slop-engine PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(reverse-slop-engine PRIVATE slop_core)

if(MSVC)
    target_compile_options(reverse-slop-engine PRIVATE /W4)
endif()
