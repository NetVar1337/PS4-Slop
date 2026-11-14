// src/fuzz/fuzz_macho.cpp
// libFuzzer target: Mach-O (thin, FAT, FAT64) into the analyzer's PE-shaped
// image, including the slice selection an .ipa or a dumped dylib goes through.

#include "core/loader/macho_loader.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!hype::MachOLoader::is_macho(data, size)) return 0;
    const auto slice = hype::MachOLoader::select_slice(data, size);
    if (!slice || slice->offset > size || slice->size > size - slice->offset) return 0;

    hype::MachOLoader loader;
    if (auto img = loader.load_buffer(data, size)) {
        volatile size_t n = img->segments.size() + img->imports.size() +
                            img->exports.size() + img->symbols.size() +
                            img->runtime_funcs.size();
        (void)n;
        (void)img->base;
        (void)img->entry;
        (void)img->encrypted;
    }
    return 0;
}
