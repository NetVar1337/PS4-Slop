#pragma once
// Itanium C++ ABI RTTI / vtable recovery (clang and gcc on ELF: PS4 Orbis,
// Linux, Android). Works on any byte spans with their VAs so the analyzer
// (PEImage segments) and reverse-slop's quick scanner (pe_image_t sections)
// share one implementation. Pointers must already be relocated
//
// layouts (P = pointer size):
//   type_info            [vptr][const char* name]
//   __si_class_type_info [vptr][name][base type_info*]
//   __vmi_class_type_info[vptr][name][u32 flags][u32 base_count]
//                        {[base type_info*][long offset_flags]} * base_count
//   vtable               ...[offset_to_top][type_info*][vfn0][vfn1]...
//                        the object's vptr points at vfn0 (the address point)
#include "core/types.h"
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hype {

struct RttiSpan {
    va_t                va = 0;
    std::span<const u8> data;
    bool                exec = false;
};

struct ItaniumClass {
    std::string              mangled;     // type_info name string: "N3foo3BarE"
    std::string              name;        // demangled: "foo::Bar"
    va_t                     type_info = 0;
    std::vector<va_t>        vtables;     // address points, primary (offset_to_top 0) first
    std::vector<va_t>        methods;     // primary vtable's virtual functions
    std::vector<std::string> bases;       // direct bases, demangled
};

// Demangle a type_info name (an Itanium <type> without the _Z prefix) that
// names a class/struct/union/enum. nullopt for anything else or malformed
std::optional<std::string> demangle_itanium_type(std::string_view mangled);

// Classes that own at least one vtable, plus the bases they name. ptr_size
// is 8 (x64/AArch64) or 4 (x86/ARM)
std::vector<ItaniumClass> scan_itanium_rtti(std::span<const RttiSpan> spans,
                                            unsigned ptr_size = 8);

}
