// src/tests/test_disasm.cpp
// Tests for core/disasm: engine, pe_parser, strings, function_index, xrefs
// Uses the real built SlopTarget.exe as a live PE fixture

#include "harness.hpp"

#include "core/analysis/packer.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/disasm/strings.hpp"
#include "core/disasm/xrefs.hpp"
#include "core/infra/event_bus.hpp"
#include "core/loader/elf_loader.h"
#include "core/loader/ps4_nid.h"
#include "core/loader/self_loader.h"

#include "elf_fixture.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using namespace slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

} // namespace

// === engine ===

TEST_CASE(engine_decode_pe32_default_widths) {
    engine_t engine;
    REQUIRE(engine.init(false));
    static const uint8_t bytes[] = {0x8B, 0x01};
    const auto instruction = engine.decode(0x401000, bytes, sizeof(bytes));
    REQUIRE(instruction.has_value());
    REQUIRE_EQ(instruction->length, 2u);
    REQUIRE_EQ(instruction->ops[0].reg, ZYDIS_REGISTER_EAX);
    REQUIRE_EQ(instruction->ops[1].mem_base, ZYDIS_REGISTER_ECX);
}

TEST_CASE(engine_init_and_decode_mov) {
    engine_t e;
    REQUIRE(e.init());

    // 48 89 E8 = mov rax, rbp (formatter uppercases mnemonics)
    const uint8_t code[] = {0x48, 0x89, 0xE8};
    auto insn = e.decode(0x140001000, code, sizeof(code));
    REQUIRE(insn.has_value());
    REQUIRE_EQ(insn->length, 3);

    std::string lower = insn->text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    REQUIRE(lower.find("mov") != std::string::npos);
    REQUIRE(lower.find("rax") != std::string::npos);
    REQUIRE(lower.find("rbp") != std::string::npos);
    REQUIRE(insn->flow == flow_t::none);
}

TEST_CASE(engine_call_rel32_resolves_target) {
    engine_t e;
    REQUIRE(e.init());

    // e8 10 00 00 00 = call +0x10 -> target = va + 5 + 16
    const uint8_t code[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    const uint64_t va = 0x140010000;
    auto insn = e.decode(va, code, sizeof(code));
    REQUIRE(insn.has_value());
    REQUIRE(insn->flow == flow_t::call);
    REQUIRE(insn->has_rel_target);
    REQUIRE_EQ(insn->rel_target, va + 5 + 0x10);
}

TEST_CASE(engine_ret_and_garbage) {
    engine_t e;
    REQUIRE(e.init());

    const uint8_t ret_b[] = {0xC3};
    auto r = e.decode(0x1000, ret_b, sizeof(ret_b));
    REQUIRE(r.has_value());
    REQUIRE(r->flow == flow_t::ret);

    const uint8_t junk[] = {0xFF, 0xFF};
    REQUIRE(!e.decode(0x1000, junk, sizeof(junk)).has_value());
}

// === pe_parser against the real SlopTarget.exe ===

TEST_CASE(pe_parse_slop_target_headers) {
    const auto& bytes = slop_target_bytes();
    REQUIRE_GT(bytes.size(), 1024u);

    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE(pe.pe32plus);
    REQUIRE_EQ(pe.machine, 0x8664);          // AMD64
    REQUIRE(pe.entry_rva != 0);
    REQUIRE_GE(pe.sections.size(), 3u);       // .text/.rdata/.data at minimum
    REQUIRE(pe.image_base != 0);

    // Entry point must map back into the file
    REQUIRE(pe.rva_to_offset(pe.entry_rva).has_value());
}

TEST_CASE(pe_parse_slop_target_sections_roundtrip) {
    auto pe = pe_parse(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(pe.ok);

    bool has_text = false;
    bool text_exec = false;
    for (const auto& s : pe.sections) {
        if (std::string(s.name) == ".text") {
            has_text = true;
            text_exec = s.is_executable();
        }
    }
    REQUIRE(has_text);
    REQUIRE(text_exec);

    // offset_to_va inverts va_to_offset for the entrypoint
    auto entry_off = pe.rva_to_offset(pe.entry_rva);
    REQUIRE(entry_off.has_value());
    auto entry_va = pe.offset_to_va(*entry_off);
    REQUIRE(entry_va.has_value());
    REQUIRE_EQ(*entry_va, pe.image_base + pe.entry_rva);
}

TEST_CASE(pe_parse_imports_present) {
    auto pe = pe_parse(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(pe.ok);
    REQUIRE(!pe.imports.empty());

    bool any_kernel32 = false;
    for (const auto& dll : pe.imports) {
        // Every import must have a plausible DLL name
        REQUIRE(!dll.dll.empty());
        if (_stricmp(dll.dll.c_str(), "KERNEL32.dll") == 0)
            any_kernel32 = true;
    }
    REQUIRE(any_kernel32);   // MSVC-linked exes always import kernel32
}

// === strings: synthetic determinism first ===

TEST_CASE(strings_synthetic_ascii_and_utf16) {
    // Layout: non-printable junk, "hello world\0", junk byte, UTF-16 L"ABC\0"
    std::vector<uint8_t> buf;
    const uintptr_t base = 0x1000;

    buf.insert(buf.end(), {0xAA, 0xBB, 0xCC});                    // @0 non-printable
    const size_t ascii_off = buf.size();
    for (const char c : std::string("hello world"))
        buf.push_back(static_cast<uint8_t>(c));
    buf.push_back(0x00);
    buf.push_back(0xEE);                                          // separator junk

    const size_t u16_off = buf.size();
    buf.insert(buf.end(), {'A', 0x00, 'B', 0x00, 'C', 0x00, 0x00, 0x00});

    auto hits = extract_strings(buf.data(), buf.size(), base, 2);
    REQUIRE_GE(hits.size(), 2u);

    bool found_a = false, found_u = false;
    for (const auto& h : hits) {
        if (!h.utf16 && h.text == "hello world" && h.va == base + ascii_off)
            found_a = true;
        if (h.utf16 && h.text == "ABC" && h.va == base + u16_off)
            found_u = true;
    }
    REQUIRE(found_a);
    REQUIRE(found_u);
}

TEST_CASE(strings_reject_short_and_unterminated) {
    std::vector<uint8_t> buf;
    for (const char c : std::string("abc"))                       // too short (<4)
        buf.push_back(static_cast<uint8_t>(c));
    buf.push_back(0x00);
    for (const char c : std::string("no-terminator-string"))      // truly unterminated
        buf.push_back(static_cast<uint8_t>(c));                   // (std::string range excludes NUL)

    string_stats_t st;
    auto hits = extract_strings(buf.data(), buf.size(), 0x2000, 4, 1000, &st);
    REQUIRE(hits.empty());
    REQUIRE(!st.truncated);
}

TEST_CASE(strings_scan_real_image_finds_data) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Scan every non-executable section with raw data
    size_t total_hits = 0;
    for (const auto& s : pe.sections) {
        if (s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > bytes.size()) continue;
        auto hits = extract_strings(bytes.data() + s.raw_offset, s.raw_size,
                                    pe.image_base + s.rva, 6);
        total_hits += hits.size();
        for (const auto& h : hits) {
            REQUIRE(!h.text.empty());
            REQUIRE(h.text.size() >= 6u);
        }
    }
    REQUIRE_GT(total_hits, 10u);   // MSVC binaries carry plenty of strings
}

TEST_CASE(pe_parse_slop_target_runtime_funcs) {
    auto pe = pe_parse(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(pe.ok);
    // x64 MSVC output carries .pdata with thousands of exact function ranges
    REQUIRE_GT(pe.runtime_funcs.size(), 1000u);
    for (const auto& rf : pe.runtime_funcs) {
        REQUIRE(rf.end_rva > rf.begin_rva);
        // Every entry must land in the file inside an executable section
        REQUIRE(pe.rva_to_offset(rf.begin_rva).has_value());
        const auto* sec = pe.section_for_rva(rf.begin_rva);
        REQUIRE(sec != nullptr);
        REQUIRE(sec->is_executable());
    }
}

// === function index + xrefs against the real image ===

TEST_CASE(function_index_discovers_entrypoint) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    engine_t eng;
    REQUIRE(eng.init());

    function_index_t fi;
    REQUIRE(fi.build(pe, bytes, eng, pe.image_base));
    REQUIRE(!fi.functions().empty());

    const uint64_t entry_va = pe.image_base + pe.entry_rva;

    // Entrypoint must be a discovered function start..
    bool entry_listed = false;
    for (const auto& f : fi.functions())
        if (f.va == entry_va) { entry_listed = true; break; }
    REQUIRE(entry_listed);

    // ...and containing() resolves it
    auto owner = fi.containing(entry_va);
    REQUIRE(owner.has_value());
    REQUIRE_EQ(*owner, entry_va);
}

TEST_CASE(function_index_seeded_from_pdata_and_covers_terminator) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE_GT(pe.runtime_funcs.size(), 1000u);

    engine_t eng;
    REQUIRE(eng.init());

    function_index_t fi;
    REQUIRE(fi.build(pe, bytes, eng, pe.image_base));

    // Compiler-reported functions are all present (plus heuristic extras)
    REQUIRE_GE(fi.functions().size(), pe.runtime_funcs.size());

    // Spot-check: a .pdata start is a discovered function start
    const uint64_t pdata_start = pe.image_base + pe.runtime_funcs.front().begin_rva;
    bool found = false;
    for (const auto& f : fi.functions())
        if (f.va == pdata_start) { found = true; break; }
    REQUIRE(found);

    // The terminating instruction belongs to its function: containing() must
    // resolve the last byte, not just the entry address
    const uint64_t entry_va = pe.image_base + pe.entry_rva;
    const function_t* entry_fn = nullptr;
    for (const auto& f : fi.functions())
        if (f.va == entry_va) { entry_fn = &f; break; }
    REQUIRE(entry_fn != nullptr);
    REQUIRE_GT(entry_fn->size, 1u);
    auto last = fi.containing(entry_fn->va + entry_fn->size - 1);
    REQUIRE(last.has_value());
    REQUIRE_EQ(*last, entry_fn->va);
}

TEST_CASE(xref_index_builds_and_consistent) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    engine_t eng;
    REQUIRE(eng.init());

    xref_index_t xi;
    REQUIRE(xi.build(pe, bytes, eng, pe.image_base));

    // A linked exe has plenty of calls + rip-relative data refs
    REQUIRE_GT(xi.total(), 20u);

    // Spot-check consistency on a sample of targets
    auto targets = xi.targets();
    REQUIRE(!targets.empty());
    size_t checked = 0;
    size_t seen_refs = 0;
    for (uint64_t t : targets) {
        const auto& refs = xi.refs_to(t);
        seen_refs += refs.size();
        for (const auto& r : refs)
            REQUIRE_EQ(r.to, t);
        if (++checked >= 64) break;
    }
    REQUIRE(seen_refs > 0);
}

TEST_CASE(binary_state_parallel_load_deterministic) {
    // The sync stages (functions/xrefs/strings) build concurrently: two
    // loads must produce identical indexes.
    namespace bs = slop::core::disasm::binary_state;
    size_t prev_fns = 0, prev_xrefs = 0, prev_strings = 0;
    uint64_t prev_first = 0, prev_last = 0;
    for (int run = 0; run < 2; ++run) {
        REQUIRE(bs::load_file(SLOP_TARGET_EXE_PATH));
        const auto& bin = bs::get();
        REQUIRE(bin.ready);
        const size_t nf = bin.fns.functions().size();
        REQUIRE_GT(nf, 1000u);
        if (run > 0) {
            REQUIRE_EQ(nf, prev_fns);
            REQUIRE_EQ(bin.xrefs.total(), prev_xrefs);
            REQUIRE_EQ(bin.strings.size(), prev_strings);
            REQUIRE_EQ(bin.fns.functions().front().va, prev_first);
            REQUIRE_EQ(bin.fns.functions().back().va, prev_last);
        }
        prev_fns = nf;
        prev_xrefs = bin.xrefs.total();
        prev_strings = bin.strings.size();
        prev_first = bin.fns.functions().front().va;
        prev_last = bin.fns.functions().back().va;
        bs::unload();
    }
}

TEST_CASE(load_packed_filerecoverysrv) {
    const char* path = R"(C:\Users\kozydot\Downloads\Compressed\FileRecoverySrvE\FileRecoverySrv.exe)";
    std::ifstream probe(path, std::ios::binary);
    if (!probe) return; // Skip if local fixture not present
    probe.close();

    namespace bs = slop::core::disasm::binary_state;
    REQUIRE(bs::load_file(path));
    const auto& bin = bs::get();
    REQUIRE(bin.ready);
    if (bin.hype) {
        while (bin.hype->running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        REQUIRE(bin.hype->ready());
        REQUIRE(bin.hype->error().empty());
    }
    auto pack = slop::core::analysis::packer_analyze(bin.pe, bin.file);
    REQUIRE(pack.packed);
    bs::unload();
}

// === ELF / SELF / PS4 ===

namespace {

namespace bs = slop::core::disasm::binary_state;
using elf_fixture::ps4_layout;

const pe_import_dll_t* find_dll(const pe_image_t& pe, const std::string& dll) {
    for (const auto& d : pe.imports)
        if (d.dll == dll) return &d;
    return nullptr;
}

bool has_import(const pe_import_dll_t* d, const std::string& name, uint32_t rva) {
    if (!d) return false;
    return std::any_of(d->functions.begin(), d->functions.end(), [&](const auto& f) {
        return f.name == name && f.iat_rva == rva;
    });
}

} // namespace

TEST_CASE(disasm_default_function_name_canonical) {
    REQUIRE_STR_EQ(default_function_name(0x4DDA48), "sub_4DDA48");
    REQUIRE_STR_EQ(default_function_name(0), "sub_0");
    REQUIRE_STR_EQ(default_function_name(0x7FF6ABCD0010ull), "sub_7FF6ABCD0010");
    REQUIRE_STR_EQ(default_function_name(~0ull), "sub_FFFFFFFFFFFFFFFF");
}

TEST_CASE(disasm_ps4_nid_hash_matches_published_values) {
    // pairs from ps4libdoc (name -> encoded_id)
    REQUIRE_STR_EQ(hype::nid::encode("sceKernelUsleep"), "1jfXLRVzisc");
    REQUIRE_STR_EQ(hype::nid::encode("__stack_chk_fail"), "Ou3iL1abvng");
    REQUIRE_STR_EQ(hype::nid::encode("sceKernelStopUnloadModule"), "QKd0qM58Qes");
    REQUIRE_STR_EQ(hype::nid::encode("sceKernelPollEventFlag"), "9lvj5DjHZiA");
    REQUIRE_EQ(hype::nid::hash("sceKernelStopUnloadModule"), 0x40A774A8CE7C41EBull);

    uint64_t v = 0;
    REQUIRE(hype::nid::decode("QKd0qM58Qes", v));
    REQUIRE_EQ(v, 0x40A774A8CE7C41EBull);
    REQUIRE_FALSE(hype::nid::decode("short", v));
    REQUIRE_FALSE(hype::nid::decode("QKd0qM58Qe!", v));

    uint64_t id = 0;
    REQUIRE(hype::nid::decode_id("A", id));
    REQUIRE_EQ(id, 0u);
    REQUIRE(hype::nid::decode_id("B", id));
    REQUIRE_EQ(id, 1u);
    REQUIRE(hype::nid::decode_id("BA", id));
    REQUIRE_EQ(id, 64u);
}

TEST_CASE(disasm_ps4_nid_database_and_overrides) {
    hype::nid::clear_overrides();   // never read the real user profile here
    REQUIRE_GT(hype::nid::builtin_count(), 40000u);
    REQUIRE(hype::nid::lookup("1jfXLRVzisc").value_or("") == "sceKernelUsleep");
    REQUIRE(hype::nid::lookup("1jfXLRVzisc#A#B").value_or("") == "sceKernelUsleep");
    REQUIRE_FALSE(hype::nid::lookup("AAAAAAAAAAA").has_value());

    // override file: bare name (NID computed) and "<nid> name"; overrides win
    const std::string custom_nid = hype::nid::encode("myGameInternalFn");
    const std::string file =
        "# comment\r\n\r\nmyGameInternalFn\r\n1jfXLRVzisc renamedUsleep\r\nbad line here\r\n";
    elf_fixture::temp_file_t tf(std::vector<uint8_t>(file.begin(), file.end()), "nids");
    REQUIRE_EQ(hype::nid::load_overrides(tf.path), 2u);
    REQUIRE(hype::nid::lookup(custom_nid).value_or("") == "myGameInternalFn");
    REQUIRE(hype::nid::lookup("1jfXLRVzisc").value_or("") == "renamedUsleep");
    hype::nid::add_override("AAAAAAAAAAA", "zeroNid");
    REQUIRE(hype::nid::lookup("AAAAAAAAAAA#A#A").value_or("") == "zeroNid");
    hype::nid::clear_overrides();
    REQUIRE(hype::nid::lookup("1jfXLRVzisc").value_or("") == "sceKernelUsleep");
    REQUIRE_FALSE(hype::nid::lookup("AAAAAAAAAAA").has_value());
    REQUIRE(hype::nid::default_override_path().filename() == "nids.txt");
}

TEST_CASE(disasm_ps4_elf_imports_resolved_and_grouped_by_library) {
    hype::nid::clear_overrides();
    const auto elf = elf_fixture::build_ps4_elf();
    const auto img = open_image(elf);
    REQUIRE(img.ok);
    REQUIRE(img.format == image_format_t::elf);
    REQUIRE_EQ(img.pe.image_base, 0u);
    REQUIRE_EQ(img.pe.entry_rva, static_cast<uint32_t>(ps4_layout::kEntry));

    const auto* kernel = find_dll(img.pe, "libkernel");
    const auto* libc   = find_dll(img.pe, "libSceLibcInternal");
    REQUIRE(kernel != nullptr);
    REQUIRE(libc != nullptr);
    REQUIRE(has_import(kernel, "sceKernelUsleep", static_cast<uint32_t>(ps4_layout::kSlotUsleep)));
    REQUIRE(has_import(kernel, "__stack_chk_guard", static_cast<uint32_t>(ps4_layout::kSlotGuard)));
    REQUIRE(has_import(kernel, "AAAAAAAAAAA", static_cast<uint32_t>(ps4_layout::kSlotUnknown)));
    REQUIRE(has_import(libc, "memset", static_cast<uint32_t>(ps4_layout::kSlotMemset)));
    REQUIRE(find_dll(img.pe, "sce_imports") == nullptr);

    // defined dynlib symbols become exports with resolved names
    REQUIRE(std::any_of(img.pe.exports.begin(), img.pe.exports.end(), [](const auto& e) {
        return e.name == "module_start" && e.rva == ps4_layout::kFunc3;
    }));
}

TEST_CASE(disasm_elf_relro_folded_without_overlap) {
    const auto elf = elf_fixture::build_ps4_elf();
    const auto img = open_image(elf);
    REQUIRE(img.ok);
    // .text, .data, and only the RELRO tail that no PT_LOAD covers
    REQUIRE_EQ(img.pe.sections.size(), size_t{3});
    REQUIRE_EQ(img.pe.sections[0].rva, 0u);
    REQUIRE_EQ(img.pe.sections[1].rva, 0x1000u);
    REQUIRE_EQ(img.pe.sections[2].rva, 0x2000u);
    REQUIRE_EQ(img.pe.sections[2].virtual_size, 0x800u);
    REQUIRE_EQ(img.pe.sections[2].raw_offset, 0x3000u);
    for (size_t i = 0; i + 1 < img.pe.sections.size(); ++i)
        REQUIRE_LE(img.pe.sections[i].rva + img.pe.sections[i].virtual_size,
                   img.pe.sections[i + 1].rva);
    REQUIRE(img.pe.sections[0].is_executable());
}

TEST_CASE(disasm_elf_load_buffer_borrows_bytes) {
    const auto elf = elf_fixture::build_ps4_elf();
    hype::ELFLoader loader;
    const auto img = loader.load_buffer(elf.data(), elf.size());
    REQUIRE(img.has_value());
    REQUIRE(img->raw.data() == elf.data());
    REQUIRE(img->storage.empty());   // no copy of the file, no zero-fill tails here
    for (const auto& seg : img->segments) {
        REQUIRE(seg.data.data() >= elf.data());
        REQUIRE(seg.data.data() + seg.data.size() <= elf.data() + elf.size());
    }
    REQUIRE(img->format == hype::ImageFormat::ELF);
}

TEST_CASE(disasm_elf_extended_numbering) {
    const auto elf = elf_fixture::build_extended_numbering_elf();
    hype::ELFLoader loader;
    const auto img = loader.load_buffer(elf.data(), elf.size());
    REQUIRE(img.has_value());
    REQUIRE_EQ(img->segments.size(), size_t{1});
    REQUIRE_STR_EQ(img->segments[0].name, ".text");   // names come from the real shstrndx
    REQUIRE_EQ(img->segments[0].va, 0x400000u);
    const auto opened = open_image(elf);
    REQUIRE(opened.ok);
    REQUIRE_EQ(opened.pe.sections.size(), size_t{1});
}

TEST_CASE(disasm_elf_entry_when_header_sits_below_first_segment) {
    // item 38: ELF header at base, first PT_LOAD at base + 0x1000
    constexpr uint64_t base = 0x7000000;
    const auto elf = elf_fixture::build_header_below_segment_elf(base);
    const auto img = open_image(elf);
    REQUIRE(img.ok);
    REQUIRE_EQ(img.pe.image_base, base + 0x1000);
    REQUIRE_EQ(img.header_base, base);
    elf_fixture::temp_file_t tf(elf, "elf38");
    const std::string path = tf.path.string();
    for (uint64_t override_base : {uint64_t{0}, base, base + 0x1000}) {
        REQUIRE(bs::load_file(path, override_base));
        const auto& bin = bs::get();
        REQUIRE_EQ(bin.base + bin.pe.entry_rva, base + 0x1010);
        REQUIRE(bin.offset_of(base + 0x1010).value_or(0) == 0x1010u);
    }
    // any other runtime base shifts relative to the lowest segment
    REQUIRE(bs::load_file(path, 0x9000000));
    REQUIRE_EQ(bs::get().base + bs::get().pe.entry_rva, 0x9000010u);
    bs::unload();
}

TEST_CASE(disasm_elf_relocations_applied_on_file_load) {
    using L = ps4_layout;
    const auto elf = elf_fixture::build_ps4_elf();

    // static helper over a copy: natural base, then idempotent re-apply
    auto copy = elf;
    auto st = hype::ELFLoader::apply_relocations(copy);
    REQUIRE_EQ(st.applied, size_t{2});
    REQUIRE_EQ(st.imported, size_t{4});
    REQUIRE_EQ(elf_fixture::get64(copy, L::file_off(L::kSlotRel)), L::kFunc2);
    REQUIRE_EQ(elf_fixture::get64(copy, L::file_off(L::kSlotRelro)), L::kString);
    auto again = copy;
    hype::ELFLoader::apply_relocations(again);
    REQUIRE(again == copy);

    elf_fixture::temp_file_t tf(elf, "elfrel");
    const std::string path = tf.path.string();
    // runtime base: pointers follow the rebase
    REQUIRE(bs::load_file(path, 0x400000));
    {
        const auto& bin = bs::get();
        REQUIRE_EQ(bin.base, 0x400000u);
        REQUIRE_EQ(bin.relocations_applied, size_t{2});
        REQUIRE_EQ(elf_fixture::get64(bin.file, L::file_off(L::kSlotRel)), 0x400000u + L::kFunc2);
        REQUIRE_EQ(elf_fixture::get64(bin.file, L::file_off(L::kSlotRelro)), 0x400000u + L::kString);
        // import slots stay for the runtime linker
        REQUIRE_EQ(elf_fixture::get64(bin.file, L::file_off(L::kSlotUsleep)), 0u);
    }
    // memory dumps carry their own relocations: leave the bytes alone
    REQUIRE(bs::load_file(path, 0x400000, /*apply_relocs=*/false));
    REQUIRE_EQ(bs::get().relocations_applied, size_t{0});
    REQUIRE_EQ(elf_fixture::get64(bs::get().file, L::file_off(L::kSlotRel)), 0u);
    // the annotation key ignores relocation
    const uint64_t hash_unrelocated = bs::get().file_hash;
    REQUIRE(bs::load_file(path));
    REQUIRE_EQ(bs::get().file_hash, hash_unrelocated);
    bs::unload();
}

TEST_CASE(disasm_self_fake_signed_and_compressed_unwrap) {
    const auto elf = elf_fixture::build_ps4_elf();
    for (auto mode : {elf_fixture::self_mode::plain, elf_fixture::self_mode::compressed}) {
        const auto self = elf_fixture::wrap_self(elf, mode);
        REQUIRE(hype::SELFLoader::is_self(self.data(), self.size()));
        const auto ex = hype::SELFLoader::extract_elf(self.data(), self.size());
        REQUIRE(ex.ok);
        REQUIRE_EQ(ex.encrypted_segments, 0u);
        // every program header's bytes land at its p_offset
        for (const auto& ph : elf_fixture::ps4_phdrs())
            REQUIRE(std::equal(elf.begin() + static_cast<std::ptrdiff_t>(ph.offset),
                               elf.begin() + static_cast<std::ptrdiff_t>(ph.offset + ph.filesz),
                               ex.elf.begin() + static_cast<std::ptrdiff_t>(ph.offset)));
        const auto img = open_image(self);
        REQUIRE(img.ok);
        REQUIRE(img.format == image_format_t::self);
        REQUIRE_STR_EQ(image_format_name(img.format), "self");
        REQUIRE(find_dll(img.pe, "libkernel") != nullptr);
    }
}

TEST_CASE(disasm_self_encrypted_fails_with_dump_hint) {
    const auto self = elf_fixture::wrap_self(elf_fixture::build_ps4_elf(),
                                             elf_fixture::self_mode::encrypted);
    const auto img = open_image(self);
    REQUIRE_FALSE(img.ok);
    REQUIRE(img.error.find("encrypted SELF") != std::string::npos);
    REQUIRE(img.error.find("target.ps4_dump_module") != std::string::npos);
    REQUIRE(img.error.find("program header 0") != std::string::npos);

    elf_fixture::temp_file_t tf(self, "selfenc");
    REQUIRE_FALSE(bs::load_file(tf.path.string()));
    REQUIRE(bs::last_load_error().find("ps4_dump_module") != std::string::npos);
}

TEST_CASE(disasm_loaded_counts_strings_and_publishes_image_changed) {
    auto sub = slop::core::infra::event_bus::subscribe();
    const auto elf = elf_fixture::build_ps4_elf();
    elf_fixture::temp_file_t tf(elf, "elfstr");
    REQUIRE(bs::load_file(tf.path.string()));
    // strings are collected at load, no strings call needed
    const auto& bin = bs::get();
    REQUIRE(std::any_of(bin.strings.begin(), bin.strings.end(),
                        [](const string_hit_t& s) { return s.text == "hello ps4 world"; }));
    REQUIRE_STR_EQ(image_format_name(bin.format), "elf");

    auto saw = [&](const char* needle) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        std::string frame;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!sub->wait(frame, 200)) return false;
            if (frame.find("image.changed") != std::string::npos &&
                frame.find(needle) != std::string::npos)
                return true;
        }
        return false;
    };
    REQUIRE(saw("\"loaded\":true"));
    bs::unload();
    REQUIRE(saw("\"loaded\":false"));
}

TEST_CASE(disasm_arm64_decode_fills_operands) {
    // ldr x0, [x1, #8]
    const uint8_t ldr[] = {0x20, 0x04, 0x40, 0xF9};
    insn_t in;
    REQUIRE(hyperion_session::session_t::decode(0x1000, ldr, sizeof(ldr), in, hype::Arch::ARM64));
    REQUIRE_EQ(in.op_count, 2u);
    REQUIRE(in.ops[0].cls == op_class_t::reg);
    REQUIRE_NE(in.ops[0].arm_reg, 0u);
    REQUIRE(in.ops[0].reg == ZYDIS_REGISTER_NONE);
    REQUIRE(in.ops[1].cls == op_class_t::mem);
    REQUIRE_NE(in.ops[1].arm_base, 0u);
    REQUIRE_EQ(in.ops[1].disp, 8);
    // b #+0x10 keeps its branch target
    const uint8_t b[] = {0x04, 0x00, 0x00, 0x14};
    REQUIRE(hyperion_session::session_t::decode(0x2000, b, sizeof(b), in, hype::Arch::ARM64));
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, 0x2010u);
    REQUIRE(in.ops[0].cls == op_class_t::imm);
}

TEST_CASE(disasm_arm64_decode_parallel_per_thread_handles) {
    const uint8_t ldr[] = {0x20, 0x04, 0x40, 0xF9};
    insn_t ref;
    REQUIRE(hyperion_session::session_t::decode(0x1000, ldr, sizeof(ldr), ref, hype::Arch::ARM64));
    std::atomic<int> bad{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 2000; ++i) {
                insn_t in;
                const uint64_t va = 0x1000 + static_cast<uint64_t>(t) * 0x10000 + static_cast<uint64_t>(i) * 4;
                if (!hyperion_session::session_t::decode(va, ldr, sizeof(ldr), in, hype::Arch::ARM64) ||
                    in.text != ref.text || in.va != va)
                    ++bad;
            }
        });
    }
    for (auto& th : threads) th.join();
    REQUIRE_EQ(bad.load(), 0);
}
