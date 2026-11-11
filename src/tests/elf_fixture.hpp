#pragma once

// src/tests/elf_fixture.hpp
// Synthetic ELF / PS4 SELF images built in memory for the loader, analyzer and
// decompiler tests. Every byte is laid out here so the expectations in the
// tests can be exact (VAs, relocation slots, NID imports, segment pieces).

#include "core/loader/ps4_nid.h"

#include <zlib.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace elf_fixture {

inline void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
inline void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
inline void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) { std::memcpy(b.data() + off, &v, 8); }
inline uint64_t get64(const std::vector<uint8_t>& b, size_t off) {
    uint64_t v = 0;
    std::memcpy(&v, b.data() + off, 8);
    return v;
}

constexpr uint32_t PT_LOAD = 1, PT_DYNAMIC = 2;
constexpr uint32_t PT_SCE_DYNLIBDATA = 0x61000000, PT_SCE_RELRO = 0x61000010;
constexpr uint32_t PF_X = 1, PF_W = 2, PF_R = 4;

struct phdr_t {
    uint32_t type, flags;
    uint64_t offset, vaddr, filesz, memsz;
};

// ELF64 header at 0 with program headers right after it (phoff 0x40)
inline void write_ehdr(std::vector<uint8_t>& b, uint16_t type, uint16_t machine,
                       uint64_t entry, const std::vector<phdr_t>& phs,
                       uint64_t shoff = 0, uint16_t shnum = 0, uint16_t shstrndx = 0,
                       uint16_t phnum_field = 0xFFFE) {
    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;  // ELFCLASS64
    b[5] = 1;  // little endian
    b[6] = 1;  // EV_CURRENT
    b[7] = 9;  // FreeBSD
    put16(b, 16, type);
    put16(b, 18, machine);
    put32(b, 20, 1);
    put64(b, 24, entry);
    put64(b, 32, 0x40);
    put64(b, 40, shoff);
    put16(b, 52, 64);
    put16(b, 54, 56);
    put16(b, 56, phnum_field == 0xFFFE ? static_cast<uint16_t>(phs.size()) : phnum_field);
    put16(b, 58, shoff ? 64 : 0);
    put16(b, 60, shnum);
    put16(b, 62, shstrndx);
    for (size_t i = 0; i < phs.size(); ++i) {
        const size_t o = 0x40 + i * 56;
        put32(b, o, phs[i].type);
        put32(b, o + 4, phs[i].flags);
        put64(b, o + 8, phs[i].offset);
        put64(b, o + 16, phs[i].vaddr);
        put64(b, o + 24, phs[i].vaddr);
        put64(b, o + 32, phs[i].filesz);
        put64(b, o + 40, phs[i].memsz);
        put64(b, o + 48, 0x1000);
    }
}

// ---------------------------------------------------------------------------
// PS4-style x86-64 eboot (ET_SCE_DYNEXEC, base 0) with SCE dynlib data:
//   .text  va 0x0000-0x1000  file 0x1000   entry 0x100
//   .data  va 0x1000-0x2000  file 0x2000
//   RELRO  va 0x1800-0x2800  file 0x2800   (first half overlaps .data)
//   DYNLIBDATA file 0x4000, DYNAMIC file 0x5000

struct ps4_layout {
    static constexpr uint64_t kEntry     = 0x100;   // calls func2/func3, imports
    static constexpr uint64_t kFunc2     = 0x140;   // (a, b, c) -> a * b + c, SysV
    static constexpr uint64_t kFunc3     = 0x180;   // a + 1, exported as module_start
    static constexpr uint64_t kString    = 0x1100;  // "hello ps4 world"
    static constexpr uint64_t kSlotRel   = 0x1000;  // RELATIVE -> kFunc2
    static constexpr uint64_t kSlotUsleep = 0x1008; // JUMP_SLOT sceKernelUsleep
    static constexpr uint64_t kSlotGuard = 0x1010;  // GLOB_DAT __stack_chk_guard
    static constexpr uint64_t kSlotMemset = 0x1018; // JUMP_SLOT memset (libc)
    static constexpr uint64_t kSlotUnknown = 0x1020;// JUMP_SLOT unresolvable NID
    static constexpr uint64_t kSlotRelro = 0x2000;  // RELATIVE -> kString, in RELRO tail
    static constexpr size_t   kTextOff   = 0x1000;
    static constexpr size_t   kDataOff   = 0x2000;
    static constexpr size_t   kRelroOff  = 0x2800;
    static constexpr size_t   kDynlibOff = 0x4000;
    static constexpr size_t   kDynOff    = 0x5000;
    static constexpr size_t   kSize      = 0x5200;
    // file offset of a va inside .text/.data/RELRO
    static size_t file_off(uint64_t va) {
        if (va < 0x1000) return kTextOff + va;
        if (va < 0x2000) return kDataOff + (va - 0x1000);
        return kRelroOff + (va - 0x1800);
    }
};

inline std::vector<phdr_t> ps4_phdrs() {
    using L = ps4_layout;
    return {
        {PT_LOAD, PF_R | PF_X, L::kTextOff, 0x0000, 0x1000, 0x1000},
        {PT_LOAD, PF_R | PF_W, L::kDataOff, 0x1000, 0x1000, 0x1000},
        {PT_SCE_RELRO, PF_R, L::kRelroOff, 0x1800, 0x1000, 0x1000},
        {PT_SCE_DYNLIBDATA, PF_R, L::kDynlibOff, 0, 0x1000, 0},
        {PT_DYNAMIC, PF_R | PF_W, L::kDynOff, 0, 0x200, 0},
    };
}

inline std::vector<uint8_t> build_ps4_elf() {
    using L = ps4_layout;
    std::vector<uint8_t> b(L::kSize, 0);
    write_ehdr(b, 0xFE10, 62, L::kEntry, ps4_phdrs());

    // .text: int3 padding, then the three functions
    std::memset(b.data() + L::kTextOff, 0xCC, 0x1000);
    std::vector<uint8_t> code;
    auto rel32 = [&](uint64_t target) {
        const uint64_t next = L::kEntry + code.size() + 4;
        const int32_t r = static_cast<int32_t>(static_cast<int64_t>(target) - static_cast<int64_t>(next));
        for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(r >> (8 * i)));
    };
    auto bytes = [&](std::initializer_list<uint8_t> v) { code.insert(code.end(), v); };
    bytes({0x55});                                // push rbp
    bytes({0x48, 0x89, 0xE5});                    // mov rbp, rsp
    bytes({0xBF, 0x05, 0x00, 0x00, 0x00});        // mov edi, 5
    bytes({0xBE, 0x07, 0x00, 0x00, 0x00});        // mov esi, 7
    bytes({0xBA, 0x09, 0x00, 0x00, 0x00});        // mov edx, 9
    bytes({0xE8}); rel32(L::kFunc2);              // call func2
    bytes({0x89, 0xC7});                          // mov edi, eax
    bytes({0xE8}); rel32(L::kFunc3);              // call func3
    bytes({0x48, 0x8D, 0x0D}); rel32(L::kString); // lea rcx, [rip+string]
    bytes({0xB9, 0x00, 0x11, 0x00, 0x00});        // mov ecx, 0x1100 (address)
    bytes({0x25, 0x00, 0x1F, 0x00, 0x00});        // and eax, 0x1F00 (constant)
    bytes({0xFF, 0x15}); rel32(L::kSlotUsleep);   // call [rip+usleep slot]
    bytes({0x5D});                                // pop rbp
    bytes({0xC3});                                // ret
    std::memcpy(b.data() + L::kTextOff + L::kEntry, code.data(), code.size());
    const uint8_t f2[] = {0x89, 0xF8,             // mov eax, edi
                          0x0F, 0xAF, 0xC6,       // imul eax, esi
                          0x01, 0xD0,             // add eax, edx
                          0xC3};                  // ret
    std::memcpy(b.data() + L::kTextOff + L::kFunc2, f2, sizeof(f2));
    const uint8_t f3[] = {0x8D, 0x47, 0x01,       // lea eax, [rdi+1]
                          0xC3};                  // ret
    std::memcpy(b.data() + L::kTextOff + L::kFunc3, f3, sizeof(f3));

    // .data string
    const char* s = "hello ps4 world";
    std::memcpy(b.data() + L::file_off(L::kString), s, std::strlen(s) + 1);

    // SCE strtab
    std::string strtab(1, '\0');
    auto add_str = [&](const std::string& v) {
        const uint32_t off = static_cast<uint32_t>(strtab.size());
        strtab += v;
        strtab.push_back('\0');
        return off;
    };
    const uint32_t s_libkernel = add_str("libkernel");
    const uint32_t s_libc      = add_str("libSceLibcInternal");
    const uint32_t s_usleep    = add_str(hype::nid::encode("sceKernelUsleep") + "#A#A");
    const uint32_t s_guard     = add_str(hype::nid::encode("__stack_chk_guard") + "#A#A");
    const uint32_t s_memset    = add_str(hype::nid::encode("memset") + "#B#B");
    const uint32_t s_unknown   = add_str("AAAAAAAAAAA#A#A");
    const uint32_t s_modstart  = add_str(hype::nid::encode("module_start") + "#A#A");
    const size_t dl = L::kDynlibOff;
    std::memcpy(b.data() + dl, strtab.data(), strtab.size());

    // symtab at +0x200: null, usleep, guard, memset, unknown, module_start
    auto sym = [&](size_t idx, uint32_t name, uint8_t info, uint16_t shndx, uint64_t value) {
        const size_t o = dl + 0x200 + idx * 24;
        put32(b, o, name);
        b[o + 4] = info;
        put16(b, o + 6, shndx);
        put64(b, o + 8, value);
    };
    sym(1, s_usleep, 0x12, 0, 0);       // GLOBAL FUNC, undefined
    sym(2, s_guard, 0x11, 0, 0);        // GLOBAL OBJECT, undefined
    sym(3, s_memset, 0x12, 0, 0);
    sym(4, s_unknown, 0x12, 0, 0);
    sym(5, s_modstart, 0x12, 1, L::kFunc3);
    // rela at +0x400, jmprel at +0x600
    auto rela = [&](size_t off, uint64_t where, uint32_t type, uint32_t symi, int64_t addend) {
        put64(b, off, where);
        put64(b, off + 8, (static_cast<uint64_t>(symi) << 32) | type);
        put64(b, off + 16, static_cast<uint64_t>(addend));
    };
    rela(dl + 0x400 + 0 * 24, L::kSlotRel, 8, 0, static_cast<int64_t>(L::kFunc2));
    rela(dl + 0x400 + 1 * 24, L::kSlotRelro, 8, 0, static_cast<int64_t>(L::kString));
    rela(dl + 0x400 + 2 * 24, L::kSlotGuard, 6, 2, 0);
    rela(dl + 0x600 + 0 * 24, L::kSlotUsleep, 7, 1, 0);
    rela(dl + 0x600 + 1 * 24, L::kSlotMemset, 7, 3, 0);
    rela(dl + 0x600 + 2 * 24, L::kSlotUnknown, 7, 4, 0);

    // PT_DYNAMIC
    size_t d = L::kDynOff;
    auto dyn = [&](int64_t tag, uint64_t val) {
        put64(b, d, static_cast<uint64_t>(tag));
        put64(b, d + 8, val);
        d += 16;
    };
    dyn(0x61000035, 0);                          // DT_SCE_STRTAB
    dyn(0x61000037, strtab.size());              // DT_SCE_STRSZ
    dyn(0x61000039, 0x200);                      // DT_SCE_SYMTAB
    dyn(0x6100003F, 6 * 24);                     // DT_SCE_SYMTABSZ
    dyn(0x6100002F, 0x400);                      // DT_SCE_RELA
    dyn(0x61000031, 3 * 24);                     // DT_SCE_RELASZ
    dyn(0x61000029, 0x600);                      // DT_SCE_JMPREL
    dyn(0x6100002B, 3 * 24);                     // DT_SCE_PLTRELSZ
    dyn(0x61000015, (0ull << 48) | s_libkernel); // DT_SCE_IMPORT_LIB id 0
    dyn(0x61000015, (1ull << 48) | s_libc);      // DT_SCE_IMPORT_LIB id 1
    dyn(0x6100000F, (0ull << 48) | s_libkernel); // DT_SCE_NEEDED_MODULE id 0
    dyn(0x6100000F, (1ull << 48) | s_libc);      // DT_SCE_NEEDED_MODULE id 1
    dyn(0, 0);
    return b;
}

// ---------------------------------------------------------------------------
// Item 38 layout: ELF header page at `base`, first PT_LOAD at base + 0x1000
// (file offset 0x1000), entry base + 0x1010
inline std::vector<uint8_t> build_header_below_segment_elf(uint64_t base) {
    std::vector<uint8_t> b(0x2000, 0);
    const std::vector<phdr_t> phs = {{PT_LOAD, PF_R | PF_X, 0x1000, base + 0x1000, 0x1000, 0x1000}};
    write_ehdr(b, 2 /*ET_EXEC*/, 62, base + 0x1010, phs);
    std::memset(b.data() + 0x1000, 0xCC, 0x1000);
    const uint8_t fn[] = {0x31, 0xC0, 0xC3};   // xor eax, eax ; ret
    std::memcpy(b.data() + 0x1010, fn, sizeof(fn));
    return b;
}

// ---------------------------------------------------------------------------
// Extended numbering: e_phnum = PN_XNUM, e_shnum = 0, e_shstrndx = SHN_XINDEX,
// the real counts in section header 0 (sh_info / sh_size / sh_link)
inline std::vector<uint8_t> build_extended_numbering_elf() {
    std::vector<uint8_t> b(0x1400, 0);
    const std::vector<phdr_t> phs = {{PT_LOAD, PF_R | PF_X, 0x1000, 0x400000, 0x100, 0x100}};
    write_ehdr(b, 2, 62, 0x400000, phs, /*shoff*/ 0x200, /*shnum*/ 0, /*shstrndx*/ 0xFFFF,
               /*phnum*/ 0xFFFF);
    const char shstr[] = "\0.text\0.shstrtab\0";
    std::memcpy(b.data() + 0x300, shstr, sizeof(shstr));
    auto sh = [&](size_t i, uint32_t name, uint32_t type, uint64_t flags, uint64_t addr,
                  uint64_t off, uint64_t size, uint32_t link, uint32_t info) {
        const size_t o = 0x200 + i * 64;
        put32(b, o, name);
        put32(b, o + 4, type);
        put64(b, o + 8, flags);
        put64(b, o + 16, addr);
        put64(b, o + 24, off);
        put64(b, o + 32, size);
        put32(b, o + 40, link);
        put32(b, o + 44, info);
    };
    sh(0, 0, 0, 0, 0, 0, /*real shnum*/ 3, /*real shstrndx*/ 2, /*real phnum*/ 1);
    sh(1, 1, 1 /*PROGBITS*/, 0x6 /*ALLOC|EXEC*/, 0x400000, 0x1000, 0x100, 0, 0);
    sh(2, 7, 3 /*STRTAB*/, 0, 0, 0x300, sizeof(shstr), 0, 0);
    std::memset(b.data() + 0x1000, 0xC3, 0x100);
    return b;
}

// ---------------------------------------------------------------------------
// AArch64 ELF: adrp x0, page ; add x0, x0, #0x10 ; ret -> string at 0x20010
inline std::vector<uint8_t> build_arm64_adrp_elf() {
    std::vector<uint8_t> b(0x3000, 0);
    const std::vector<phdr_t> phs = {
        {PT_LOAD, PF_R | PF_X, 0x1000, 0x10000, 0x100, 0x100},
        {PT_LOAD, PF_R, 0x2000, 0x20000, 0x100, 0x100},
    };
    write_ehdr(b, 2, 183, 0x10000, phs);
    const uint32_t code[] = {0x90000080u,   // adrp x0, 0x20000
                             0x91004000u,   // add x0, x0, #0x10
                             0xD65F03C0u};  // ret
    std::memcpy(b.data() + 0x1000, code, sizeof(code));
    const char* s = "arm64 string here";
    std::memcpy(b.data() + 0x2010, s, std::strlen(s) + 1);
    return b;
}

// ---------------------------------------------------------------------------
// PS4 SELF around an ELF64: one blocked segment per program header with
// file bytes (id = phdr index), optionally deflated or flagged encrypted
enum class self_mode { plain, compressed, encrypted };

inline std::vector<uint8_t> wrap_self(const std::vector<uint8_t>& elf, self_mode mode) {
    uint16_t phnum = 0;
    std::memcpy(&phnum, elf.data() + 56, 2);
    struct seg_t { uint32_t id; std::vector<uint8_t> data; uint64_t plain; };
    std::vector<seg_t> segs;
    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t o = 0x40 + size_t{i} * 56;
        uint64_t off = 0, filesz = 0;
        std::memcpy(&off, elf.data() + o + 8, 8);
        std::memcpy(&filesz, elf.data() + o + 32, 8);
        if (!filesz) continue;
        std::vector<uint8_t> data(elf.begin() + static_cast<std::ptrdiff_t>(off),
                                  elf.begin() + static_cast<std::ptrdiff_t>(off + filesz));
        if (mode == self_mode::compressed) {
            uLongf clen = compressBound(static_cast<uLong>(data.size()));
            std::vector<uint8_t> z(clen);
            compress(z.data(), &clen, data.data(), static_cast<uLong>(data.size()));
            z.resize(clen);
            segs.push_back({i, std::move(z), filesz});
        } else {
            segs.push_back({i, std::move(data), filesz});
        }
    }
    const size_t table_end = 0x20 + segs.size() * 0x20;
    const size_t elf_hdrs = 0x40 + size_t{phnum} * 56;
    size_t cursor = (table_end + elf_hdrs + 0xF) & ~size_t{0xF};
    std::vector<uint8_t> out(cursor, 0);
    const uint8_t magic[] = {0x4F, 0x15, 0x3D, 0x1D};
    std::memcpy(out.data(), magic, 4);
    out[4] = 0; out[5] = 1; out[6] = 1; out[7] = 0x12;
    out[8] = 1; out[9] = 4;
    put16(out, 0x18, static_cast<uint16_t>(segs.size()));
    put16(out, 0x1A, 0x22);
    std::memcpy(out.data() + table_end, elf.data(), elf_hdrs);
    for (size_t k = 0; k < segs.size(); ++k) {
        uint64_t flags = 0x800 | 0x1 | (uint64_t{segs[k].id} << 20);
        if (mode == self_mode::compressed) flags |= 0x8;
        if (mode == self_mode::encrypted) flags |= 0x2 | 0x4;
        const size_t o = 0x20 + k * 0x20;
        put64(out, o, flags);
        put64(out, o + 8, cursor);
        put64(out, o + 16, segs[k].data.size());
        put64(out, o + 24, segs[k].plain);
        out.resize(cursor + segs[k].data.size());
        std::memcpy(out.data() + cursor, segs[k].data.data(), segs[k].data.size());
        cursor = (out.size() + 0xF) & ~size_t{0xF};
        out.resize(cursor, 0);
    }
    put32(out, 0x10, static_cast<uint32_t>(out.size()));
    return out;
}

// Writes bytes to a unique temp file (removed by the guard's destructor)
struct temp_file_t {
    std::filesystem::path path;
    explicit temp_file_t(const std::vector<uint8_t>& bytes, const char* stem) {
        static int counter = 0;
        path = std::filesystem::temp_directory_path() /
               (std::string("slop_test_") + stem + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)) + "_" +
                std::to_string(++counter) + ".bin");
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    }
    ~temp_file_t() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    temp_file_t(const temp_file_t&) = delete;
    temp_file_t& operator=(const temp_file_t&) = delete;
};

} // namespace elf_fixture
