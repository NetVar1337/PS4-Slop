# Legacy ImGui shell, built when SLOP_BUILD_UI is ON (CI keeps it compiling)
add_executable(reverse-slop WIN32
    main.cpp
)

slop_add_win_resources(reverse-slop
    DESCRIPTION "reverse-slop legacy ImGui shell"
    MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/app.manifest.in")

target_include_directories(reverse-slop PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(reverse-slop PRIVATE slop_ui)

if(MSVC)
    target_compile_options(reverse-slop PRIVATE /W4 /WX)
endif()
