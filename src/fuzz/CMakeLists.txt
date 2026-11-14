# src/fuzz/CMakeLists.txt
# libFuzzer harnesses for the parsers that consume untrusted input (ELF/PE/
# Mach-O loaders, .ipa, ZIP, the ps4debug wire format, .NET metadata).
#
# MSVC only: /fsanitize=fuzzer needs the MSVC libFuzzer runtime. ASan is part
# of the same instrumentation (the STL container annotations must match across
# every object in the link), so the preset sets SLOP_SANITIZE=address for the
# whole tree instead of instrumenting the harness alone.

if(NOT SLOP_BUILD_FUZZ)
    return()
endif()

if(NOT MSVC)
    message(FATAL_ERROR "SLOP_BUILD_FUZZ needs MSVC (/fsanitize=fuzzer)")
endif()
if(NOT SLOP_SANITIZE STREQUAL "address")
    message(FATAL_ERROR "SLOP_BUILD_FUZZ needs SLOP_SANITIZE=address: the libFuzzer "
                        "runtime and the ASan-instrumented libraries must come from one "
                        "build (see the ninja-msvc-fuzz preset)")
endif()

set(SLOP_FUZZ_TARGETS elf pe macho ipa zip ps4 dotnet)

foreach(_name IN LISTS SLOP_FUZZ_TARGETS)
    add_executable(fuzz_${_name} fuzz_${_name}.cpp)
    target_link_libraries(fuzz_${_name} PRIVATE slop_core)
    # /fsanitize=fuzzer at compile time also emits the libFuzzer runtime's
    # defaultlib, so the link needs no extra switch (link.exe would reject it)
    target_compile_options(fuzz_${_name} PRIVATE /W4 /WX /EHsc /bigobj /fsanitize=fuzzer)
    set_target_properties(fuzz_${_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
endforeach()

# Regenerates src/fuzz/corpus/<target>/ from the in-memory test fixtures.
# Run it by hand after a fixture or format change; the seeds are committed.
add_executable(slop_fuzz_corpus gen_corpus.cpp)
target_include_directories(slop_fuzz_corpus PRIVATE "${CMAKE_SOURCE_DIR}/src/tests")
target_link_libraries(slop_fuzz_corpus PRIVATE slop_core)
target_compile_options(slop_fuzz_corpus PRIVATE /W4 /WX /EHsc /bigobj)
set_target_properties(slop_fuzz_corpus PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
