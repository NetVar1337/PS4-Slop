add_executable(slop_live
    live_drive.cpp
)

target_include_directories(slop_live PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(slop_live PRIVATE slop_core nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(slop_live PRIVATE /W4 /WX /EHsc /O2)
endif()

set_target_properties(slop_live PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/live"
)
