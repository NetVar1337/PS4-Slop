// src/fuzz/gen_corpus.cpp
// Writes the seed corpora under src/fuzz/corpus/<target>/ from the same
// in-memory fixtures the test suite uses, so the seeds stay in sync with the
// formats the parsers are expected to accept.
//
//   build-ninja-msvc-fuzz/fuzz/slop_fuzz_corpus.exe src/fuzz/corpus
//
// Only re-run after a fixture or format change; the generated files are
// committed (they are small).

#include "core/dotnet/dotnet_metadata.h"
#include "core/runtime/ps4_protocol.hpp"

#include "elf_fixture.hpp"
#include "macho_fixture.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace mf = slop_test::macho;
namespace ps4 = slop::core::runtime::ps4;

namespace {

int g_written = 0;

void put(const fs::path& dir, const char* name, const std::vector<uint8_t>& bytes) {
    fs::create_directories(dir);
    std::ofstream out(dir / name, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        std::fprintf(stderr, "cannot write %s\n", (dir / name).string().c_str());
        std::exit(1);
    }
    std::printf("  %-28s %6zu bytes\n", (dir / name).string().c_str(), bytes.size());
    ++g_written;
}

// a minimal but structurally valid PE32+ (one .text section) — the same shape
// the magicmida tests build
std::vector<uint8_t> make_pe(bool x64) {
    std::vector<uint8_t> bytes(0x400, 0);
    auto put16 = [&bytes](size_t at, uint16_t v) { std::memcpy(bytes.data() + at, &v, 2); };
    auto put32 = [&bytes](size_t at, uint32_t v) { std::memcpy(bytes.data() + at, &v, 4); };
    bytes[0] = 'M';
    bytes[1] = 'Z';
    put32(0x3c, 0x80);
    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    put16(0x84, x64 ? 0x8664 : 0x014c);
    put16(0x86, 1);
    put16(0x94, x64 ? 0xf0 : 0xe0);
    const size_t optional = 0x98;
    put16(optional, x64 ? 0x20b : 0x10b);
    put32(optional + 16, 0x1000);
    put32(optional + 56, 0x2000);
    put32(optional + 60, 0x200);
    put32(optional + (x64 ? 108 : 92), 16);
    const size_t section = optional + (x64 ? 0xf0 : 0xe0);
    std::memcpy(bytes.data() + section, ".text", 5);
    put32(section + 8, 0x100);
    put32(section + 12, 0x1000);
    put32(section + 16, 0x200);
    put32(section + 20, 0x200);
    put32(section + 36, 0x60000020);
    bytes[0x200] = 0xc3;
    return bytes;
}

// A minimal ECMA-335 metadata root: BSJB header, a #~ table stream with one
// row each in Module/TypeDef/MethodDef/Field, and a #Strings heap. Enough for
// MetadataReader::init to accept it, so the fuzzer starts from a valid layout
// instead of rediscovering the header from noise.
std::vector<uint8_t> make_metadata_root() {
    std::vector<uint8_t> b;
    auto u8  = [&b](uint8_t v) { b.push_back(v); };
    auto u16 = [&b](uint16_t v) { b.push_back(uint8_t(v)); b.push_back(uint8_t(v >> 8)); };
    auto u32 = [&b](uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
    };
    auto u64 = [&b](uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(uint8_t(v >> (8 * i)));
    };
    auto pad4 = [&b] { while (b.size() % 4) b.push_back(0); };

    // root header
    for (char c : std::string("BSJB")) u8(uint8_t(c));
    u16(1);            // major
    u16(1);            // minor
    u32(0);            // reserved
    const std::string version = "v4.0.30319";
    u32(uint32_t(version.size() + 1));
    b.insert(b.end(), version.begin(), version.end());
    u8(0);
    pad4();
    u16(0);            // flags
    u16(2);            // stream count

    // "#~" stream header (offset patched below) + "#Strings"
    const size_t tilde_hdr = b.size();
    u32(0);            // offset, patched
    u32(0);            // size, patched
    for (char c : std::string("#~")) u8(uint8_t(c));
    u8(0);
    pad4();
    const size_t strings_hdr = b.size();
    u32(0);            // offset, patched
    u32(0);            // size, patched
    for (char c : std::string("#Strings")) u8(uint8_t(c));
    u8(0);
    pad4();

    // #~ tables stream
    const size_t tilde = b.size();
    u32(0);            // reserved
    u8(2);             // major
    u8(0);             // minor
    u8(0);             // heap sizes: 2-byte string/guid/blob indices
    u8(1);             // reserved
    u64((1ull << 0x00) | (1ull << 0x02) | (1ull << 0x04) | (1ull << 0x06));  // Module, TypeDef, Field, MethodDef
    u64(0);            // sorted
    u32(1);            // Module
    u32(1);            // TypeDef
    u32(1);            // Field
    u32(1);            // MethodDef
    // Module row: Generation u16, Name, Mvid, EncId, EncBaseId
    u16(0); u16(1); u16(0); u16(0); u16(0);
    // TypeDef row: Flags u32, Name, Namespace, Extends, FieldList, MethodList
    u32(0); u16(2); u16(3); u16(0); u16(1); u16(1);
    // Field row: Flags u16, Name, Sig
    u16(0x0006); u16(4); u16(5);
    // MethodDef row: RVA u32, ImplFlags u16, Flags u16, Name, Sig, ParamList
    u32(0x2000); u16(0); u16(0x0016); u16(6); u16(7); u16(1);
    const size_t tilde_end = b.size();

    // #Strings heap: empty string, then the names referenced above
    const size_t strings = b.size();
    u8(0);
    for (const char* s : {"<Module>", "Program", "Main", "counter", "sig"}) {
        for (const char* p = s; *p; ++p) u8(uint8_t(*p));
        u8(0);
    }
    const size_t strings_end = b.size();

    auto patch = [&b](size_t at, uint32_t v) {
        std::memcpy(b.data() + at, &v, 4);
    };
    patch(tilde_hdr, uint32_t(tilde));
    patch(tilde_hdr + 4, uint32_t(tilde_end - tilde));
    patch(strings_hdr, uint32_t(strings));
    patch(strings_hdr + 4, uint32_t(strings_end - strings));
    return b;
}

std::vector<uint8_t> make_debug_event() {
    ps4::debug_event_packet_t pkt{};
    pkt.lwpid  = 0x1234;
    pkt.status = 0x0000007F;   // stopped, SIGTRAP
    std::strncpy(pkt.tdname, "main", sizeof(pkt.tdname) - 1);
    pkt.regs.rip = 0x400500;
    pkt.regs.rsp = 0x7FFF00008000ull;
    pkt.regs.rbp = 0x7FFF00007FF0ull;
    pkt.regs.rax = 0x2A;
    pkt.regs.rflags = 0x202;
    for (int i = 0; i < 16; ++i)
        reinterpret_cast<uint64_t*>(pkt.dbregs)[i] = 0xD000 + uint64_t(i);
    std::vector<uint8_t> out(sizeof(pkt));
    std::memcpy(out.data(), &pkt, sizeof(pkt));
    return out;
}

std::vector<uint8_t> make_proc_list() {
    std::vector<uint8_t> out;
    for (const auto& [name, pid] : {std::pair{"eboot.bin", 1234}, std::pair{"SceShellUI", 42}}) {
        ps4::proc_list_entry_t e{};
        std::strncpy(e.p_comm, name, sizeof(e.p_comm) - 1);
        e.pid = pid;
        const auto* p = reinterpret_cast<const uint8_t*>(&e);
        out.insert(out.end(), p, p + sizeof(e));
    }
    return out;
}

std::vector<uint8_t> make_ipa(bool deflate) {
    const auto exe = mf::build_arm64_exe();
    const auto plist = mf::build_bplist({{"CFBundleExecutable", "Demo"},
                                         {"CFBundleIdentifier", "com.example.demo"},
                                         {"CFBundleShortVersionString", "1.0"},
                                         {"MinimumOSVersion", "14.0"}});
    const std::vector<mf::zip_entry_t> entries = {
        {"Payload/", {}, false},
        {"Payload/Demo.app/", {}, false},
        {"Payload/Demo.app/Info.plist", plist, false},
        {"Payload/Demo.app/Demo", exe, std::nullopt},
    };
    return mf::build_zip(entries, deflate);
}

std::vector<uint8_t> make_zip() {
    const std::vector<mf::zip_entry_t> entries = {
        {"readme.txt", mf::bytes_of("reverse-slop corpus seed\n"), std::nullopt},
        {"dir/", {}, false},
        {"dir/data.bin", std::vector<uint8_t>(256, 0x41), std::nullopt},
    };
    return mf::build_zip(entries, true);
}

} // namespace

int main(int argc, char** argv) {
    const fs::path root = argc > 1 ? fs::path(argv[1]) : fs::path("src/fuzz/corpus");

    std::printf("elf_loader:\n");
    put(root / "elf", "ps4_elf.bin", elf_fixture::build_ps4_elf());
    put(root / "elf", "header_below_segment.bin",
        elf_fixture::build_header_below_segment_elf(0x400000));
    put(root / "elf", "extended_numbering.bin",
        elf_fixture::build_extended_numbering_elf());
    put(root / "elf", "arm64_adrp.bin", elf_fixture::build_arm64_adrp_elf());

    std::printf("pe_parser:\n");
    put(root / "pe", "pe64.bin", make_pe(true));
    put(root / "pe", "pe32.bin", make_pe(false));

    std::printf("macho_loader:\n");
    const auto exe = mf::build_arm64_exe();
    put(root / "macho", "arm64_exe.bin", exe);
    put(root / "macho", "x86_64_stub.bin", mf::build_x86_64_stub());
    put(root / "macho", "fat_two_slices.bin",
        mf::build_fat({{0x0100000C, 0, exe, 14}, {0x01000007, 3, mf::build_x86_64_stub(), 14}}));

    std::printf("ipa:\n");
    put(root / "ipa", "demo_deflate.ipa", make_ipa(true));
    put(root / "ipa", "demo_stored.ipa", make_ipa(false));

    std::printf("zip_reader:\n");
    put(root / "zip", "bundle.zip", make_zip());

    std::printf("ps4:\n");
    put(root / "ps4", "debug_event.bin", make_debug_event());
    put(root / "ps4", "proc_list.bin", make_proc_list());

    std::printf("dotnet:\n");
    const auto meta = make_metadata_root();
    {
        hype::MetadataReader r;
        if (!r.init(meta.data(), meta.size())) {
            std::fprintf(stderr, "dotnet seed does not parse: fix make_metadata_root()\n");
            return 1;
        }
        std::printf("  metadata root accepted, %u TypeDef row(s)\n",
                    r.table_rows(hype::mdt::TypeDef));
    }
    put(root / "dotnet", "metadata_root.bin", meta);

    std::printf("%d seed file(s) under %s\n", g_written, root.string().c_str());
    return 0;
}
