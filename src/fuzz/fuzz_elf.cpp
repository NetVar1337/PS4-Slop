// src/fuzz/fuzz_elf.cpp
// libFuzzer target: hype::ELFLoader over an untrusted executable or memory
// dump (PS4 eboots, dumped SELF segments, Linux binaries). Built by the
// ninja-msvc-fuzz preset (SLOP_BUILD_FUZZ=ON).

#include "core/loader/elf_loader.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!hype::ELFLoader::is_elf(data, size)) return 0;

    hype::ELFLoader loader;
    if (auto img = loader.load_buffer(data, size)) {
        // walk what the loader built so the parse stays observable
        volatile size_t n = img->segments.size() + img->imports.size() +
                            img->exports.size() + img->symbols.size() +
                            img->runtime_funcs.size();
        (void)n;
        (void)img->base;
        (void)img->entry;
        (void)loader.header_base();
    }

    // relocations write into the image: fuzz them over a mutable copy, with
    // the load base taken from the input so both the in-place and the
    // relocated layouts are reached
    std::vector<uint8_t> copy(data, data + size);
    hype::va_t load_base = 0;
    if (size >= 8) {
        load_base = (static_cast<hype::va_t>(copy[0]) << 56) |
                    (static_cast<hype::va_t>(copy[1]) << 48) |
                    (static_cast<hype::va_t>(copy[2]) << 40) |
                    (static_cast<hype::va_t>(copy[3]) << 32) |
                    (static_cast<hype::va_t>(copy[4]) << 24) |
                    (static_cast<hype::va_t>(copy[5]) << 16) |
                    (static_cast<hype::va_t>(copy[6]) << 8) |
                    static_cast<hype::va_t>(copy[7]);
        load_base &= ~hype::va_t(0xFFF);   // page aligned, as a real mapping is
    }
    const auto stats = hype::ELFLoader::apply_relocations(std::span<uint8_t>(copy), load_base);
    volatile size_t applied = stats.applied + stats.imported + stats.skipped;
    (void)applied;
    return 0;
}
