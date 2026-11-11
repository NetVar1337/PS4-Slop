#pragma once

// quick RTTI reconstruction without a hyperion session. MSVC x64 (PE): type
// descriptors by name, locators by self offsets, vftables by their minus one
// slot. Itanium ABI (ELF, PS4 clang): type_info objects by their name
// pointer, vtables by offset_to_top + type_info pointer

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"

namespace slop::core::re {

struct rtti_class_t {
    std::string             name;        // demangled: "MyClass" from ".?AVMyClass@@" / "7MyClass"
    std::string             mangled;     // Itanium type_info name ("N2ns5InnerE"); empty for MSVC
    uint64_t                td_va = 0;   // TypeDescriptor VA / Itanium type_info VA
    std::vector<uint64_t>   col_vas;     // MSVC Complete Object Locator VAs
    std::vector<uint64_t>   vftables;    // vftable VAs (first virtual function slot)
    std::vector<uint64_t>   methods;     // Itanium: primary vtable's virtual functions
    std::vector<std::string> bases;      // Itanium: direct bases
};

struct rtti_result_t {
    std::vector<rtti_class_t> classes;
    size_t scanned_bytes = 0;
};

// MSVC RTTI in the non-executable sections of a PE image
rtti_result_t rtti_scan(const disasm::pe_image_t& pe,
                        const std::vector<uint8_t>& file);

// Itanium RTTI over every section of an ELF image (`file` must hold
// relocated pointers). ptr_size 8 for x64/AArch64, 4 for 32-bit images
rtti_result_t rtti_scan_itanium(const disasm::pe_image_t& pe,
                                const std::vector<uint8_t>& file,
                                unsigned ptr_size = 8);

// Read up to `max_slots` function pointers starting at `vftable_va`
std::optional<std::vector<uint64_t>> read_vftable(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    uint64_t vftable_va, size_t max_slots = 32);

} // namespace slop::core::re
