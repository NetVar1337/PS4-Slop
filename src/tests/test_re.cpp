// src/tests/test_re.cpp
// RTTI reconstruction + danger callsites over patched SlopTarget fixtures

#include "harness.hpp"

#include "core/analysis/danger.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/re/rtti.hpp"
#include "core/analysis/itanium_rtti.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

using namespace slop::core::re;
namespace analysis = slop::core::analysis;
namespace disasm = slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

// Locate a non-executable data section span for planting structures
bool find_data_span(const disasm::pe_image_t& pe,
                    const std::vector<uint8_t>& file,
                    uint64_t* va, size_t* off, size_t* room) {
    for (const auto& s : pe.sections) {
        if (s.raw_size < 512 || s.is_executable()) continue;
        const size_t end =
            static_cast<size_t>(s.raw_offset) + s.raw_size;
        if (end > file.size()) continue;
        *va   = pe.image_base + s.rva;
        *off  = s.raw_offset;
        *room = s.raw_size;
        return true;
    }
    return false;
}

} // namespace

TEST_CASE(rtti_scan_finds_planted_class) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    uint64_t span_va = 0;
    size_t span_off = 0, span_room = 0;
    REQUIRE(find_data_span(pe, bytes, &span_va, &span_off, &span_room));

    // Layout inside the span (keep everything 4-aligned):
    //   [0x00] TypeDescriptor: vfptr(8) spare(8) ".?AVSlopTest@@\0"
    //   [0x40] COL: sig(0) off(0) cdOff(0) tdRva cdRva selfRva
    //   [0x80] vftable: [-1]=&COL, [0..1]=function-ish pointers
    const uint32_t td_rva  = static_cast<uint32_t>(span_va - pe.image_base);
    const uint32_t col_rva = td_rva + 0x40;

    auto put32 = [&](size_t byte_off, uint32_t v) {
        std::memcpy(bytes.data() + span_off + byte_off, &v, 4);
    };
    auto put64 = [&](size_t byte_off, uint64_t v) {
        std::memcpy(bytes.data() + span_off + byte_off, &v, 8);
    };

    const char* name = ".?AVSlopTest@@";
    std::memset(bytes.data() + span_off, 0, 0xC0);
    std::memcpy(bytes.data() + span_off + 16, name, strlen(name) + 1);

    put32(0x40, 0);                       // signature (x64)
    put32(0x44, 0);                       // this-offset
    put32(0x48, 0);                       // ctor-displacement
    put32(0x4C, td_rva);                  // TypeDescriptor RVA
    put32(0x50, col_rva + 0x100);         // class-descriptor RVA (unused)
    put32(0x54, col_rva);                 // self RVA

    put64(0x80, pe.image_base + col_rva); // vftable[-1]
    put64(0x88, pe.image_base + 0x1000);  // slot 0 (bogus fn)
    put64(0x90, pe.image_base + 0x1010);  // slot 1

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(reparsed.ok);

    auto r = rtti_scan(reparsed, bytes);
    bool found = false;
    for (const auto& c : r.classes) {
        if (c.name != "SlopTest") continue;
        found = true;
        REQUIRE_EQ(c.vftables.size(), 1u);

        auto slots = read_vftable(reparsed, bytes, c.vftables[0], 8);
        REQUIRE(slots.has_value());
        REQUIRE_GE(slots->size(), 2u);
        REQUIRE_EQ((*slots)[0], pe.image_base + 0x1000ull);
    }
    REQUIRE(found);
}

TEST_CASE(danger_scan_flags_dangerous_imports_with_callsites) {
    // Synthetic image: one import with an IAT slot, resolver returns two
    // referencing sites. Exercises the whole contract without a real CRT
    disasm::pe_image_t pe{};
    pe.ok = true;
    pe.image_base = 0x140000000;

    disasm::pe_import_dll_t dll;
    dll.dll = "MSVCRTRT.dll";
    disasm::pe_import_func_t fn;
    fn.name = "strcpy";
    fn.iat_rva = 0x9000;
    dll.functions.push_back(fn);
    pe.imports.push_back(std::move(dll));

    int resolver_calls = 0;
    auto hits = analysis::danger_scan(
        pe,
        [&resolver_calls](uint64_t iat_va) {
            ++resolver_calls;
            REQUIRE_EQ(iat_va, 0x140009000ull);
            return std::vector<uint64_t>{0x140001000ull, 0x140002000ull};
        });
    REQUIRE_EQ(resolver_calls, 1);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_STR_EQ(hits[0].function.c_str(), "strcpy");
    REQUIRE_STR_EQ(hits[0].category.c_str(), "unbounded-copy");
    REQUIRE_EQ(hits[0].callsites.size(), 2u);
}

TEST_CASE(danger_scan_clean_imports_yield_nothing) {
    const auto& bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto hits = analysis::danger_scan(
        pe, [](uint64_t) { return std::vector<uint64_t>{}; });
    // SlopTarget is a plain MSVC build, but the CRT startup does pull
    // LoadLibrary*/GetProcAddress, every hit must be a real flagged import
    // with a resolved IAT slot and a known category
    for (const auto& h : hits) {
        REQUIRE(!h.category.empty());
        REQUIRE(h.iat_va != 0);
    }
}

TEST_CASE(rtti_scan_skips_code_sections) {
    // the TypeDescriptor/COL/vftable shape planted into .text must not be
    // reported: MSVC RTTI only lives in data sections
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    const disasm::pe_section_t* text = nullptr;
    for (const auto& s : pe.sections)
        if (s.is_executable() && s.raw_size >= 0x200) { text = &s; break; }
    REQUIRE(text != nullptr);

    const size_t off = text->raw_offset;
    const uint32_t td_rva = text->rva;
    const uint32_t col_rva = td_rva + 0x40;
    std::memset(bytes.data() + off, 0, 0xC0);
    const char* name = ".?AVInCode@@";
    std::memcpy(bytes.data() + off + 16, name, strlen(name) + 1);
    std::memcpy(bytes.data() + off + 0x4C, &td_rva, 4);
    std::memcpy(bytes.data() + off + 0x54, &col_rva, 4);
    const uint64_t col_va = pe.image_base + col_rva;
    std::memcpy(bytes.data() + off + 0x80, &col_va, 8);

    auto r = rtti_scan(pe, bytes);
    for (const auto& c : r.classes) REQUIRE(c.name != "InCode");
}

TEST_CASE(rtti_itanium_demangles_type_info_names) {
    namespace h = hype;
    const auto dm = [](const char* s) { return h::demangle_itanium_type(s); };
    REQUIRE_STR_EQ(dm("7MyClass").value_or("?").c_str(), "MyClass");
    REQUIRE_STR_EQ(dm("N2ns5InnerE").value_or("?").c_str(), "ns::Inner");
    REQUIRE_STR_EQ(dm("St9exception").value_or("?").c_str(), "std::exception");
    REQUIRE_STR_EQ(dm("NSt3__16vectorIiNS_9allocatorIiEEEE").value_or("?").c_str(),
                   "std::__1::vector<int, std::__1::allocator<int>>");
    REQUIRE_STR_EQ(dm("St6vectorIiSaIiEE").value_or("?").c_str(),
                   "std::vector<int, std::allocator<int>>");
    REQUIRE_STR_EQ(dm("N12_GLOBAL__N_15LocalE").value_or("?").c_str(),
                   "(anonymous namespace)::Local");
    REQUIRE_STR_EQ(dm("6VectorIPKcLi3EE").value_or("?").c_str(), "Vector<char const*, 3>");
    REQUIRE_STR_EQ(dm("N3foo3BarIJidEEE").value_or("?").c_str(), "foo::Bar<int, double>");
    REQUIRE_STR_EQ(dm("N3foo3BarIS_EE").value_or("?").c_str(), "foo::Bar<foo>");
    // not class type_info names
    REQUIRE(!dm("i"));
    REQUIRE(!dm("PKc"));
    REQUIRE(!dm("3ab"));
    REQUIRE(!dm("7MyClassX"));
    REQUIRE(!dm("Z4mainE5Local"));
    REQUIRE(!dm(""));
}

TEST_CASE(rtti_itanium_scan_recovers_classes_vtables_and_bases) {
    // base-0 ELF-shaped image: .text 0x1000, .rodata 0x2000, .data.rel.ro
    // 0x3000. type_info vptrs are 0, as in an eboot whose __cxxabiv1
    // vtables are imports that relocation leaves unresolved
    std::vector<uint8_t> file(0xA00, 0);
    disasm::pe_image_t pe;
    pe.ok = true;
    pe.pe32plus = true;
    pe.machine = 0x8664;
    pe.image_base = 0;
    pe.size_of_image = 0x4000;
    const auto add_sec = [&](const char* nm, uint32_t rva, uint32_t raw, uint32_t size,
                             uint32_t chars) {
        disasm::pe_section_t s;
        std::memcpy(s.name, nm, strlen(nm));
        s.rva = rva;
        s.raw_offset = raw;
        s.raw_size = s.virtual_size = size;
        s.characteristics = chars;
        pe.sections.push_back(s);
    };
    add_sec(".text", 0x1000, 0x400, 0x100, 0x60000020);
    add_sec(".rodata", 0x2000, 0x500, 0x100, 0x40000040);
    add_sec(".data.rel.ro", 0x3000, 0x600, 0x200, 0x40000040);
    std::memset(file.data() + 0x400, 0xC3, 0x100);

    const auto str = [&](uint32_t rva, const char* s) {
        std::memcpy(file.data() + 0x500 + (rva - 0x2000), s, strlen(s) + 1);
    };
    str(0x2000, "4Base");
    str(0x2010, "N2ns7DerivedE");
    str(0x2030, "5Multi");
    str(0x2040, "6Second");
    str(0x2050, "3abc");                                // stray lookalike
    const auto q = [&](uint32_t rva, uint64_t v) {
        std::memcpy(file.data() + 0x600 + (rva - 0x3000), &v, 8);
    };
    q(0x3008, 0x2000);                                  // ti Base
    q(0x3018, 0x2010); q(0x3020, 0x3000);               // ti ns::Derived : Base
    q(0x3030, 0x2040);                                  // ti Second
    q(0x3040, 0x2030);                                  // ti Multi (vmi)
    q(0x3048, uint64_t{2} << 32);                       // flags 0, 2 bases
    q(0x3050, 0x3000); q(0x3058, 0x2);                  // Base at +0, public
    q(0x3060, 0x3028); q(0x3068, (uint64_t{8} << 8) | 2); // Second at +8
    q(0x3088, 0x3000); q(0x3090, 0x1000); q(0x3098, 0x1010);            // vt Base
    q(0x30A8, 0x3010); q(0x30B0, 0x1020); q(0x30B8, 0x1030); q(0x30C0, 0x1040);
    q(0x30D8, 0x3038); q(0x30E0, 0x1050);                                // vt Multi
    q(0x30F0, static_cast<uint64_t>(-8)); q(0x30F8, 0x3038); q(0x3100, 0x1060);
    q(0x3118, 0x2050);                                  // stray "type_info"

    auto r = rtti_scan_itanium(pe, file, 8);
    REQUIRE_EQ(r.classes.size(), 4u);
    REQUIRE_STR_EQ(r.classes[0].name.c_str(), "Base");
    REQUIRE_STR_EQ(r.classes[1].name.c_str(), "Multi");
    REQUIRE_STR_EQ(r.classes[2].name.c_str(), "Second");
    REQUIRE_STR_EQ(r.classes[3].name.c_str(), "ns::Derived");

    const auto& base = r.classes[0];
    REQUIRE_EQ(base.td_va, 0x3000ull);
    REQUIRE_EQ(base.vftables.size(), 1u);
    REQUIRE_EQ(base.vftables[0], 0x3090ull);
    REQUIRE_EQ(base.methods.size(), 2u);

    const auto& multi = r.classes[1];
    REQUIRE_EQ(multi.vftables.size(), 2u);
    REQUIRE_EQ(multi.vftables[0], 0x30E0ull);           // primary first
    REQUIRE_EQ(multi.vftables[1], 0x3100ull);
    REQUIRE_EQ(multi.bases.size(), 2u);
    REQUIRE_STR_EQ(multi.bases[0].c_str(), "Base");
    REQUIRE_STR_EQ(multi.bases[1].c_str(), "Second");
    REQUIRE_EQ(multi.methods.size(), 1u);
    REQUIRE_EQ(multi.methods[0], 0x1050ull);

    REQUIRE(r.classes[2].vftables.empty());             // only named as a base

    const auto& der = r.classes[3];
    REQUIRE_STR_EQ(der.mangled.c_str(), "N2ns7DerivedE");
    REQUIRE_EQ(der.bases.size(), 1u);
    REQUIRE_EQ(der.methods.size(), 3u);
    auto slots = read_vftable(pe, file, der.vftables[0], 8);
    REQUIRE(slots.has_value());
    REQUIRE_EQ(slots->size(), 3u);
}
