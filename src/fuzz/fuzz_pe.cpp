// src/fuzz/fuzz_pe.cpp
// libFuzzer target: the dependency-free PE32+ parser that every loaded
// Windows image, dump and capture goes through.

#include "core/disasm/pe_parser.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto pe = slop::core::disasm::pe_parse(data, size);
    if (!pe.ok) return 0;

    // exercise the RVAs the analyzer derives from the parsed tables
    volatile size_t n = pe.sections.size() + pe.imports.size() + pe.exports.size() +
                        pe.runtime_funcs.size();
    (void)n;
    for (const auto& s : pe.sections) {
        (void)pe.section_for_rva(s.rva);
        if (auto off = pe.rva_to_offset(s.rva)) (void)pe.offset_to_va(*off);
        if (auto off = pe.rva_to_offset(s.rva + s.virtual_size)) (void)pe.offset_to_va(*off);
    }
    for (const auto& e : pe.exports) {
        if (auto off = pe.rva_to_offset(e.rva)) (void)pe.offset_to_va(*off);
        (void)pe.va_to_offset(pe.image_base + e.rva);
    }
    for (const auto& d : pe.imports) {
        for (const auto& f : d.functions) (void)pe.va_to_offset(f.iat_rva);
    }
    return 0;
}
