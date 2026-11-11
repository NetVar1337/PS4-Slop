#include "harness.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/process/module_dump.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <vector>

namespace {

constexpr uintptr_t kImageBase = 0x140000000ull;

std::vector<uint8_t> make_mapped_image() {
    std::vector<uint8_t> image(0x3000, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.BaseOfCode = 0x1000;
    nt->OptionalHeader.ImageBase = kImageBase;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x3000;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto* sections = IMAGE_FIRST_SECTION(nt);
    std::memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = 0x180;
    sections[0].VirtualAddress = 0x1000;
    sections[0].SizeOfRawData = 0x200;
    sections[0].PointerToRawData = 0x200;
    sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;

    std::memcpy(sections[1].Name, ".data", 5);
    sections[1].Misc.VirtualSize = 0x100;
    sections[1].VirtualAddress = 0x2000;
    sections[1].SizeOfRawData = 0x200;
    sections[1].PointerToRawData = 0x400;
    sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    std::fill_n(image.begin() + 0x1000, 0x200, uint8_t{0x90});
    image[0x1000] = 0xCC;
    std::fill_n(image.begin() + 0x2000, 0x200, uint8_t{0x42});
    image[0x2000] = 0x7A;
    return image;
}

slop::core::process::module_read_fn_t reader_for(
    const std::vector<uint8_t>& image, uintptr_t fail_begin = 0,
    uintptr_t fail_end = 0) {
    return [&image, fail_begin, fail_end](uintptr_t address, void* output,
                                          size_t size) {
        slop::core::runtime::io_result_t result;
        if (address < kImageBase || size > image.size() ||
            address - kImageBase > image.size() - size ||
            (fail_begin < fail_end && address < fail_end &&
             address + size > fail_begin)) {
            result.error = ERROR_PARTIAL_COPY;
            return result;
        }
        std::memcpy(output, image.data() + (address - kImageBase), size);
        result.ok = true;
        result.bytes = size;
        return result;
    };
}

} // namespace

TEST_CASE(module_dump_reconstructs_file_layout) {
    const auto mapped = make_mapped_image();
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);

    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE_EQ(result.section_count, size_t{2});
    REQUIRE_EQ(output.size(), size_t{0x600});
    REQUIRE_EQ(output[0x200], uint8_t{0xCC});
    REQUIRE_EQ(output[0x201], uint8_t{0x90});
    REQUIRE_EQ(output[0x400], uint8_t{0x7A});
    REQUIRE_EQ(output[0x401], uint8_t{0x42});

    const auto pe = slop::core::disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.sections.size(), size_t{2});
    REQUIRE_EQ(pe.sections[0].raw_offset, uint32_t{0x200});
    REQUIRE_EQ(pe.sections[1].raw_offset, uint32_t{0x400});
}

TEST_CASE(module_dump_rejects_invalid_headers) {
    auto mapped = make_mapped_image();
    mapped[0] = 0;
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);
    REQUIRE_FALSE(result.ok);
    REQUIRE(output.empty());
    REQUIRE_FALSE(result.error.empty());
}

TEST_CASE(module_dump_strict_and_best_effort_reads) {
    const auto mapped = make_mapped_image();
    const auto failing_reader = reader_for(mapped, kImageBase + 0x2000,
                                           kImageBase + 0x2200);
    std::vector<uint8_t> output;

    auto strict = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output);
    REQUIRE_FALSE(strict.ok);
    REQUIRE(output.empty());

    slop::core::process::module_dump_options_t options;
    options.strict_reads = false;
    auto best_effort = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output,
        options);
    REQUIRE(best_effort.ok);
    REQUIRE_FALSE(best_effort.complete);
    REQUIRE_EQ(output[0x400], uint8_t{0});
    REQUIRE_EQ(output[0x5FF], uint8_t{0});
}

TEST_CASE(module_dump_captures_live_test_process) {
    using namespace slop::core;
    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] live self-dump requires user-mode backend\n");
        return;
    }

    runtime::session_t session;
    REQUIRE(session.open(GetCurrentProcessId()));
    auto modules = runtime::active().enum_modules(session.handle());
    REQUIRE(modules.ok);
    REQUIRE_FALSE(modules.items.empty());
    if (!modules.ok || modules.items.empty()) return;

    const auto module = modules.items.front();
    const auto path = std::filesystem::temp_directory_path() /
                      L"reverse_slop_live_module_dump.exe";
    const auto result = process::dump_module_pe(session, module, path.string());
    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE(result.bytes_written >= 1024);

    std::ifstream file(path, std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                     std::istreambuf_iterator<char>{}};
    REQUIRE_EQ(bytes.size(), result.bytes_written);
    const auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE_FALSE(pe.sections.empty());

    std::error_code ec;
    std::filesystem::remove(path, ec);
    session.close();
}

namespace {

// a fake address space: three segments with an unmapped gap and a hole
struct fake_space_t {
    std::map<uint64_t, uint8_t> bytes;   // sparse; absent = 0
    uint64_t bad_lo = 0, bad_hi = 0;     // reads touching this range fail
    slop::core::runtime::io_result_t read(uintptr_t a, void* dst, size_t n) const {
        slop::core::runtime::io_result_t r;
        if (a < bad_hi && a + n > bad_lo) { r.error = 5; return r; }
        auto* out = static_cast<uint8_t*>(dst);
        for (size_t i = 0; i < n; ++i) {
            auto it = bytes.find(a + i);
            out[i] = it == bytes.end() ? 0 : it->second;
        }
        r.ok = true;
        r.bytes = n;
        return r;
    }
};

template <typename T>
T rd(const std::vector<uint8_t>& v, size_t off) {
    T x{};
    std::memcpy(&x, v.data() + off, sizeof(T));
    return x;
}

} // namespace

TEST_CASE(module_dump_rebuilds_elf_from_segments) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0xC3;
    mem.bytes[0x401234] = 0x90;
    mem.bytes[0x480010] = 0xAB;
    mem.bytes[0x4C8FFF] = 0xEE;
    const std::vector<process::mapped_segment_t> segs = {
        {0x400000, 0x480000, 5},    // r-x
        {0x480000, 0x4C0000, 1},    // r--
        {0x4C8000, 0x500000, 3},    // rw-
    };
    std::vector<uint8_t> out;
    process::elf_rebuild_info_t info;
    auto res = process::reconstruct_elf_from_segments(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out, {}, &info);
    REQUIRE(res.ok);
    REQUIRE(res.complete);
    CHECK(res.module_base == 0x400000u);
    CHECK(info.segments == 3u);
    CHECK(!info.had_header);
    CHECK(info.entry == 0u);
    CHECK(!res.warnings.empty());   // says the header was rebuilt
    REQUIRE(out.size() > 64u);
    CHECK(std::memcmp(out.data(), "\x7f" "ELF", 4) == 0);
    CHECK(out[4] == 2);
    CHECK(out[5] == 1);
    CHECK(rd<uint16_t>(out, 16) == 2);    // ET_EXEC
    CHECK(rd<uint16_t>(out, 18) == 62);   // EM_X86_64
    CHECK(rd<uint64_t>(out, 24) == 0u);   // entry unknown
    CHECK(rd<uint64_t>(out, 32) == 64u);  // phoff
    CHECK(rd<uint16_t>(out, 54) == 56);   // phentsize
    REQUIRE(rd<uint16_t>(out, 56) == 3);  // phnum
    CHECK(rd<uint16_t>(out, 60) == 0);    // no section headers
    const uint32_t want_flags[3] = {5, 4, 6};
    uint64_t prev_end = 0;
    for (size_t i = 0; i < 3; ++i) {
        const size_t ph = 64 + i * 56;
        const uint64_t off = rd<uint64_t>(out, ph + 8);
        const uint64_t va = rd<uint64_t>(out, ph + 16);
        const uint64_t fsz = rd<uint64_t>(out, ph + 32);
        CHECK(rd<uint32_t>(out, ph) == 1u);   // PT_LOAD
        CHECK(rd<uint32_t>(out, ph + 4) == want_flags[i]);
        CHECK(va == segs[i].start);
        CHECK(fsz == segs[i].end - segs[i].start);
        CHECK(rd<uint64_t>(out, ph + 40) == fsz);
        CHECK(off % 0x4000 == va % 0x4000);
        CHECK(off >= prev_end);
        prev_end = off + fsz;
        REQUIRE(off + fsz <= out.size());
        // every byte sits at p_offset + (va - p_vaddr)
        for (const auto& [a, b] : mem.bytes)
            if (a >= va && a < va + fsz) CHECK(out[off + (a - va)] == b);
    }
}

TEST_CASE(module_dump_elf_keeps_in_memory_header_entry) {
    using namespace slop::core;
    fake_space_t mem;
    // an in-memory ELF header with a PIE-relative entry (ET_SCE_DYNEXEC style)
    const uint8_t ident[8] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 9};
    for (size_t i = 0; i < sizeof(ident); ++i) mem.bytes[0x800000 + i] = ident[i];
    const uint16_t type = 0xFE10;
    mem.bytes[0x800010] = static_cast<uint8_t>(type & 0xFF);
    mem.bytes[0x800011] = static_cast<uint8_t>(type >> 8);
    const uint64_t entry = 0x1230;
    for (int i = 0; i < 8; ++i) mem.bytes[0x800018 + i] = static_cast<uint8_t>(entry >> (8 * i));
    const std::vector<process::mapped_segment_t> segs = {{0x800000, 0x810000, 5}};
    std::vector<uint8_t> out;
    process::elf_rebuild_info_t info;
    auto res = process::reconstruct_elf_from_segments(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out, {}, &info);
    REQUIRE(res.ok);
    CHECK(info.had_header);
    CHECK(info.source_type == 0xFE10);
    CHECK(info.entry == 0x801230u);
    CHECK(rd<uint64_t>(out, 24) == 0x801230u);
}

TEST_CASE(module_dump_elf_unreadable_pages_strict_and_lenient) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0x11;
    mem.bad_lo = 0x404000;
    mem.bad_hi = 0x405000;
    const std::vector<process::mapped_segment_t> segs = {{0x400000, 0x410000, 5}};
    auto rf = [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); };
    std::vector<uint8_t> out;
    process::module_dump_options_t strict;
    strict.chunk_size = 0x1000;
    strict.strict_reads = true;
    auto res = process::reconstruct_elf_from_segments(segs, rf, out, strict);
    CHECK(!res.ok);
    CHECK(res.error.find("0x404000") != std::string::npos);
    CHECK(out.empty());

    process::module_dump_options_t lenient = strict;
    lenient.strict_reads = false;
    res = process::reconstruct_elf_from_segments(segs, rf, out, lenient);
    REQUIRE(res.ok);
    CHECK(!res.complete);
    bool named = false;
    for (const auto& w : res.warnings)
        if (w.find("0x404000..0x405000") != std::string::npos) named = true;
    CHECK(named);

    // bad layouts are refused
    std::vector<process::mapped_segment_t> overlap = {{0x400000, 0x402000, 1}, {0x401000, 0x403000, 1}};
    CHECK(!process::reconstruct_elf_from_segments(overlap, rf, out).ok);
    CHECK(!process::reconstruct_elf_from_segments({}, rf, out).ok);
}

TEST_CASE(module_dump_raw_span_zero_fills_gaps) {
    using namespace slop::core;
    fake_space_t mem;
    mem.bytes[0x400000] = 0x01;
    mem.bytes[0x401FFF] = 0x02;
    mem.bytes[0x403000] = 0x03;
    mem.bytes[0x402800] = 0x77;   // inside the gap: must not appear
    const std::vector<process::mapped_segment_t> segs = {{0x400000, 0x402000, 5}, {0x403000, 0x404000, 3}};
    std::vector<uint8_t> out;
    auto res = process::dump_raw_span(
        segs, [&](uintptr_t a, void* d, size_t n) { return mem.read(a, d, n); }, out);
    REQUIRE(res.ok);
    REQUIRE(out.size() == 0x4000u);
    CHECK(out[0] == 0x01);
    CHECK(out[0x1FFF] == 0x02);
    CHECK(out[0x2800] == 0x00);
    CHECK(out[0x3000] == 0x03);
    CHECK(res.section_count == 2u);
}
