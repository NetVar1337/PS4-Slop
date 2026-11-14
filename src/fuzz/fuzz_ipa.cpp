// src/fuzz/fuzz_ipa.cpp
// libFuzzer target: .ipa (ZIP + Info.plist + Mach-O payload) resolution.
// The archive is untrusted: the bundle name, the plist and the executable
// entry all come from the container.

#include "core/disasm/ipa.hpp"

#include <cstddef>
#include <cstdint>

namespace ipa = slop::core::disasm::ipa;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // bounded so a deflate bomb cannot make the fuzzer allocate without limit
    if (size > (1u << 18)) return 0;
    if (!ipa::looks_like_ipa(data, size)) return 0;
    const auto r = ipa::extract_main_binary(data, size);
    volatile size_t n = r.binary.size() + r.bundle.executable.size() +
                        r.bundle.bundle_id.size() + r.bundle.version.size() +
                        r.bundle.min_os.size() + r.error.size();
    (void)n;
    (void)r.ok;
    return 0;
}
