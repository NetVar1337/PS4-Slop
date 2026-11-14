// src/fuzz/fuzz_zip.cpp
// libFuzzer target: the in-memory ZIP reader (central directory, ZIP64,
// stored/deflate extraction) behind .ipa, .hdb bundles and web-fetch archives.

#include "core/util/zip_reader.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace zip = slop::core::util::zip;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!zip::has_zip_magic(data, size)) return 0;
    zip::archive_t ar;
    std::string err;
    if (!ar.open(data, size, &err)) return 0;

    std::vector<uint8_t> out;
    for (const auto& e : ar.entries()) {
        // 1 MiB cap: a crafted entry must not turn one input into gigabytes
        if (ar.extract(e, out, &err, 1u << 20)) {
            volatile size_t n = out.size();
            (void)n;
        }
        (void)ar.find(e.name);
    }
    return 0;
}
