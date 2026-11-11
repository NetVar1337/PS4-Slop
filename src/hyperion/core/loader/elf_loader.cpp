#include "elf_loader.h"
#include "ps4_nid.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace hype {

namespace {

constexpr u32 ELF_MAGIC = 0x464C457F; // "\x7fELF"

constexpr u8 ELFCLASS32 = 1;
constexpr u8 ELFCLASS64 = 2;
constexpr u8 ELFDATA2LSB = 1;

// Machine types
constexpr u16 EM_386     = 3;
constexpr u16 EM_MIPS    = 8;
constexpr u16 EM_PPC     = 20;
constexpr u16 EM_PPC64   = 21;
constexpr u16 EM_ARM     = 40;
constexpr u16 EM_X86_64  = 62;
constexpr u16 EM_AARCH64 = 183;

// Program header types
constexpr u32 PT_LOAD    = 1;
constexpr u32 PT_DYNAMIC = 2;
// PS4 SCE-specific program header types
constexpr u32 PT_SCE_DYNLIBDATA = 0x61000000;
constexpr u32 PT_SCE_RELRO      = 0x61000010;

// Extended numbering (ELF gABI)
constexpr u16 PN_XNUM    = 0xFFFF;
constexpr u16 SHN_XINDEX = 0xFFFF;

// Standard dynamic tags
constexpr i64 DT_NULL     = 0;
constexpr i64 DT_PLTRELSZ = 2;
constexpr i64 DT_STRTAB   = 5;
constexpr i64 DT_SYMTAB   = 6;
constexpr i64 DT_RELA     = 7;
constexpr i64 DT_RELASZ   = 8;
constexpr i64 DT_STRSZ    = 10;
constexpr i64 DT_SYMENT   = 11;
constexpr i64 DT_REL      = 17;
constexpr i64 DT_RELSZ    = 18;
constexpr i64 DT_PLTREL   = 20;
constexpr i64 DT_JMPREL   = 23;

// PS4 SCE dynamic tags (d_val is an offset within PT_SCE_DYNLIBDATA)
constexpr i64 DT_SCE_NEEDED_MODULE = 0x6100000F;
constexpr i64 DT_SCE_IMPORT_LIB    = 0x61000015;
constexpr i64 DT_SCE_JMPREL        = 0x61000029;
constexpr i64 DT_SCE_PLTRELSZ      = 0x6100002B;
constexpr i64 DT_SCE_RELA          = 0x6100002F;
constexpr i64 DT_SCE_RELASZ        = 0x61000031;
constexpr i64 DT_SCE_STRTAB        = 0x61000035;
constexpr i64 DT_SCE_STRSZ         = 0x61000037;
constexpr i64 DT_SCE_SYMTAB        = 0x61000039;
constexpr i64 DT_SCE_SYMTABSZ      = 0x6100003F;

// Segment flags
constexpr u32 PF_X = 1;
constexpr u32 PF_W = 2;
constexpr u32 PF_R = 4;

// Section types / flags
constexpr u32 SHT_SYMTAB = 2;
constexpr u32 SHT_DYNSYM = 11;
constexpr u64 SHF_ALLOC  = 2;

// Symbol binding/type
constexpr u8 STB_LOCAL  = 0;
constexpr u8 STB_GLOBAL = 1;
constexpr u8 STB_WEAK   = 2;
constexpr u8 STT_FUNC   = 2;

// Relocation types applied to static images
constexpr u32 R_X86_64_64        = 1;
constexpr u32 R_X86_64_GLOB_DAT  = 6;
constexpr u32 R_X86_64_JUMP_SLOT = 7;
constexpr u32 R_X86_64_RELATIVE  = 8;
constexpr u32 R_AARCH64_ABS64     = 257;
constexpr u32 R_AARCH64_GLOB_DAT  = 1025;
constexpr u32 R_AARCH64_JUMP_SLOT = 1026;
constexpr u32 R_AARCH64_RELATIVE  = 1027;

// A .bss larger than this is not materialized (the analyzer sees the file
// bytes only); keeps a bogus p_memsz from allocating gigabytes
constexpr u64 kMaxZeroFill = 256ull << 20;
constexpr u64 kPage = 0x1000;

u32 elf_to_pe_flags(u32 pflags) {
    u32 f = 0;
    if (pflags & PF_R) f |= 0x40000000;
    if (pflags & PF_W) f |= 0x80000000;
    if (pflags & PF_X) f |= 0x20000000;
    return f;
}

template <class T>
bool rd(const u8* base, size_t size, u64 off, T& out) {
    if (off > size || sizeof(T) > size - off) return false;
    std::memcpy(&out, base + off, sizeof(T));
    return true;
}

struct Phdr { u32 type = 0, flags = 0; u64 offset = 0, vaddr = 0, filesz = 0, memsz = 0; };
struct Shdr { u32 name = 0, type = 0; u64 flags = 0, addr = 0, offset = 0, size = 0; u32 link = 0, info = 0; u64 entsize = 0; };
struct Sym  { u32 name = 0; u8 info = 0, other = 0; u16 shndx = 0; u64 value = 0, size = 0; };
struct Reloc { u64 offset = 0; u32 sym = 0, type = 0; i64 addend = 0; };

std::string_view cstr_at(const u8* base, size_t size, u64 off, u64 limit_end) {
    const u64 end = std::min<u64>(limit_end, size);
    if (off >= end) return {};
    const char* s = reinterpret_cast<const char*>(base + off);
    const size_t max = static_cast<size_t>(end - off);
    const void* nul = std::memchr(s, 0, max);
    return nul ? std::string_view(s, static_cast<const char*>(nul) - s) : std::string_view{};
}

} // namespace

// ---------------------------------------------------------------------------
// View: every read is bounds-checked against the buffer, 32-bit structures
// come back widened to the 64-bit shapes

struct ELFLoader::View {
    const u8* b = nullptr;
    size_t    n = 0;
    bool      is64 = true;
    u64 phoff = 0, shoff = 0;
    u32 phnum = 0, shnum = 0, shstrndx = 0;
    u16 phentsize = 0, shentsize = 0;

    bool phdr(u32 i, Phdr& p) const {
        const u64 off = phoff + u64{i} * phentsize;
        if (is64) {
            if (phentsize < 56) return false;
            return rd(b, n, off, p.type) && rd(b, n, off + 4, p.flags) &&
                   rd(b, n, off + 8, p.offset) && rd(b, n, off + 16, p.vaddr) &&
                   rd(b, n, off + 32, p.filesz) && rd(b, n, off + 40, p.memsz);
        }
        if (phentsize < 32) return false;
        u32 v[8];
        if (!rd(b, n, off, v)) return false;
        p = {v[0], v[6], v[1], v[2], v[4], v[5]};
        return true;
    }
    bool shdr(u32 i, Shdr& s) const {
        if (!shoff) return false;
        const u64 off = shoff + u64{i} * shentsize;
        if (is64) {
            if (shentsize < 64) return false;
            return rd(b, n, off, s.name) && rd(b, n, off + 4, s.type) &&
                   rd(b, n, off + 8, s.flags) && rd(b, n, off + 16, s.addr) &&
                   rd(b, n, off + 24, s.offset) && rd(b, n, off + 32, s.size) &&
                   rd(b, n, off + 40, s.link) && rd(b, n, off + 44, s.info) &&
                   rd(b, n, off + 56, s.entsize);
        }
        if (shentsize < 40) return false;
        u32 v[10];
        if (!rd(b, n, off, v)) return false;
        s = {v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[9]};
        return true;
    }
    u64 sym_size() const { return is64 ? 24 : 16; }
    bool sym(u64 off, Sym& s) const {
        if (is64)
            return rd(b, n, off, s.name) && rd(b, n, off + 4, s.info) &&
                   rd(b, n, off + 5, s.other) && rd(b, n, off + 6, s.shndx) &&
                   rd(b, n, off + 8, s.value) && rd(b, n, off + 16, s.size);
        u32 name = 0, value = 0, size = 0;
        if (!rd(b, n, off, name) || !rd(b, n, off + 4, value) || !rd(b, n, off + 8, size) ||
            !rd(b, n, off + 12, s.info) || !rd(b, n, off + 13, s.other) ||
            !rd(b, n, off + 14, s.shndx))
            return false;
        s.name = name;
        s.value = value;
        s.size = size;
        return true;
    }
    u64 reloc_size(bool rela) const { return is64 ? (rela ? 24 : 16) : (rela ? 12 : 8); }
    bool reloc(u64 off, bool rela, Reloc& r) const {
        if (is64) {
            u64 info = 0;
            if (!rd(b, n, off, r.offset) || !rd(b, n, off + 8, info)) return false;
            r.sym = static_cast<u32>(info >> 32);
            r.type = static_cast<u32>(info);
            r.addend = 0;
            return !rela || rd(b, n, off + 16, r.addend);
        }
        u32 o = 0, info = 0;
        if (!rd(b, n, off, o) || !rd(b, n, off + 4, info)) return false;
        r.offset = o;
        r.sym = info >> 8;
        r.type = info & 0xFF;
        i32 a = 0;
        if (rela && !rd(b, n, off + 8, a)) return false;
        r.addend = a;
        return true;
    }
    // file offset backing `va` inside some PT_LOAD's file bytes
    bool va_to_off(u64 va, u64 need, u64& out) const {
        for (u32 i = 0; i < phnum; ++i) {
            Phdr p;
            if (!phdr(i, p) || p.type != PT_LOAD) continue;
            if (va < p.vaddr || va - p.vaddr >= p.filesz) continue;
            if (p.filesz - (va - p.vaddr) < need) return false;
            out = p.offset + (va - p.vaddr);
            return out <= n && need <= n - out;
        }
        return false;
    }
};

struct ELFLoader::DynTables {
    bool sce = false;
    // absolute file offsets / byte sizes; 0 = absent
    u64 rela_off = 0, rela_sz = 0;
    bool rela_is_rela = true;
    u64 jmprel_off = 0, jmprel_sz = 0;
    bool jmprel_is_rela = true;
    u64 sym_off = 0, sym_end = 0;
    u64 str_off = 0, str_end = 0;
    std::vector<std::pair<u64, u32>> import_libs;     // lib id -> name offset
    std::vector<std::pair<u64, u32>> needed_modules;  // module id -> name offset

    bool has_symbols() const { return sym_off && str_off && sym_end > sym_off; }
};

ELFLoader::View ELFLoader::view() const {
    View v;
    v.b = base_;
    v.n = size_;
    v.is64 = is64_;
    v.phoff = phoff_;
    v.shoff = shoff_;
    v.phnum = phnum_;
    v.shnum = shnum_;
    v.shstrndx = shstrndx_;
    v.phentsize = phentsize_;
    v.shentsize = shentsize_;
    return v;
}

ELFLoader::DynTables ELFLoader::find_dyn_tables(const View& v) const {
    DynTables t;
    Phdr dyn, dynlib;
    bool have_dyn = false, have_dynlib = false;
    for (u32 i = 0; i < v.phnum; ++i) {
        Phdr p;
        if (!v.phdr(i, p)) break;
        if (p.type == PT_DYNAMIC && !have_dyn) { dyn = p; have_dyn = true; }
        if (p.type == PT_SCE_DYNLIBDATA && !have_dynlib) { dynlib = p; have_dynlib = true; }
    }
    if (!have_dyn || dyn.offset >= size_) return t;
    if (have_dynlib && dynlib.offset >= size_) have_dynlib = false;

    const u64 ent = is64_ ? 16 : 8;
    const u64 dyn_end = std::min<u64>(dyn.offset + dyn.filesz, size_);
    std::unordered_map<i64, u64> tags;
    for (u64 off = dyn.offset; off + ent <= dyn_end; off += ent) {
        i64 tag = 0;
        u64 val = 0;
        if (is64_) {
            if (!rd(base_, size_, off, tag) || !rd(base_, size_, off + 8, val)) break;
        } else {
            i32 t32 = 0;
            u32 v32 = 0;
            if (!rd(base_, size_, off, t32) || !rd(base_, size_, off + 4, v32)) break;
            tag = t32;
            val = v32;
        }
        if (tag == DT_NULL) break;
        if (tag == DT_SCE_IMPORT_LIB) t.import_libs.emplace_back(val >> 48, static_cast<u32>(val));
        else if (tag == DT_SCE_NEEDED_MODULE) t.needed_modules.emplace_back(val >> 48, static_cast<u32>(val));
        else tags.emplace(tag, val);
    }
    const auto tag = [&](i64 k) -> u64 {
        const auto it = tags.find(k);
        return it == tags.end() ? 0 : it->second;
    };

    if (have_dynlib && tags.count(DT_SCE_STRTAB) && tags.count(DT_SCE_SYMTAB)) {
        // PS4: offsets are relative to PT_SCE_DYNLIBDATA's file bytes
        t.sce = true;
        const u64 lo = dynlib.offset;
        const u64 hi = std::min<u64>(dynlib.offset + dynlib.filesz, size_);
        const auto place = [&](u64 rel, u64 sz, u64& off, u64& end_or_sz, bool is_size) {
            if (!sz || rel > hi - lo || sz > hi - lo - rel) return;
            off = lo + rel;
            end_or_sz = is_size ? sz : lo + rel + sz;
        };
        place(tag(DT_SCE_STRTAB), tag(DT_SCE_STRSZ), t.str_off, t.str_end, false);
        place(tag(DT_SCE_SYMTAB), tag(DT_SCE_SYMTABSZ), t.sym_off, t.sym_end, false);
        place(tag(DT_SCE_RELA), tag(DT_SCE_RELASZ), t.rela_off, t.rela_sz, true);
        place(tag(DT_SCE_JMPREL), tag(DT_SCE_PLTRELSZ), t.jmprel_off, t.jmprel_sz, true);
        return t;
    }

    // standard: tag values are virtual addresses
    const auto map = [&](u64 va, u64 sz, u64& off) {
        u64 o = 0;
        if (va && v.va_to_off(va, sz ? sz : 1, o)) off = o;
    };
    if (u64 sz = tag(DT_STRSZ); tag(DT_STRTAB)) {
        map(tag(DT_STRTAB), sz, t.str_off);
        if (t.str_off) t.str_end = t.str_off + sz;
    }
    if (tag(DT_SYMTAB)) {
        map(tag(DT_SYMTAB), v.sym_size(), t.sym_off);
        if (t.sym_off) t.sym_end = size_;   // DT_SYMTAB carries no size
    }
    if (tag(DT_RELA)) {
        map(tag(DT_RELA), tag(DT_RELASZ), t.rela_off);
        if (t.rela_off) t.rela_sz = tag(DT_RELASZ);
    } else if (tag(DT_REL)) {
        map(tag(DT_REL), tag(DT_RELSZ), t.rela_off);
        if (t.rela_off) { t.rela_sz = tag(DT_RELSZ); t.rela_is_rela = false; }
    }
    if (tag(DT_JMPREL)) {
        map(tag(DT_JMPREL), tag(DT_PLTRELSZ), t.jmprel_off);
        if (t.jmprel_off) {
            t.jmprel_sz = tag(DT_PLTRELSZ);
            const u64 pltrel = tag(DT_PLTREL);
            t.jmprel_is_rela = pltrel ? pltrel == static_cast<u64>(DT_RELA) : is64_;
        }
    }
    (void)DT_SYMENT;
    return t;
}

// ---------------------------------------------------------------------------

bool ELFLoader::is_elf(const u8* data, size_t size) {
    u32 magic = 0;
    return rd(data, size, 0, magic) && magic == ELF_MAGIC;
}

std::optional<PEImage> ELFLoader::load_buffer(const u8* data, size_t size) {
    if (!data || size < 52) return std::nullopt;
    PEImage img;
    img.raw = std::span<const u8>(data, size);
    base_ = data;
    size_ = size;
    return finish_load(img);
}

std::optional<PEImage> ELFLoader::load(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return std::nullopt;

    const auto end = f.tellg();
    if (end < 52) return std::nullopt;
    const size_t sz = static_cast<size_t>(end);
    f.seekg(0);

    auto file = std::make_shared<std::vector<u8>>(sz);
    f.read(reinterpret_cast<char*>(file->data()), static_cast<std::streamsize>(sz));
    if (!f) return std::nullopt;
    if (apply_relocs_) apply_relocations(*file);

    PEImage img;
    img.storage.push_back(file);
    img.raw = *file;
    base_ = file->data();
    size_ = sz;
    auto out = finish_load(img);
    if (out)
        spdlog::info("elf: loaded {}", path.filename().string());
    return out;
}

std::optional<PEImage> ELFLoader::finish_load(PEImage& img) {
    img.format = ImageFormat::ELF;
    if (!parse_header(img)) return std::nullopt;
    if (!parse_segments(img)) return std::nullopt;
    parse_sections(img);
    parse_symbols(img);
    parse_dynamic(img);
    if (img.imports.empty()) parse_sce_dynlibdata(img);

    spdlog::info("elf: base=0x{:X} entry=0x{:X} segs={} imports={} exports={}",
                 img.base, img.entry, img.segments.size(), img.imports.size(),
                 img.exports.size());
    return std::move(img);
}

bool ELFLoader::parse_header(PEImage& img) {
    if (size_ < 52) return false;
    u32 magic = 0;
    rd(base_, size_, 0, magic);
    if (magic != ELF_MAGIC) return false;

    const u8 ei_class = base_[4];
    const u8 ei_data  = base_[5];
    if (ei_class == ELFCLASS64) is64_ = true;
    else if (ei_class == ELFCLASS32) is64_ = false;
    else return false;
    if (ei_data != ELFDATA2LSB) {
        spdlog::warn("elf: big-endian images are not supported");
        return false;
    }
    if (is64_ && size_ < 64) return false;

    rd(base_, size_, 18, machine_);
    u16 phnum16 = 0, shnum16 = 0, shstrndx16 = 0;
    if (is64_) {
        u64 entry = 0;
        rd(base_, size_, 24, entry);
        rd(base_, size_, 32, phoff_);
        rd(base_, size_, 40, shoff_);
        rd(base_, size_, 54, phentsize_);
        rd(base_, size_, 56, phnum16);
        rd(base_, size_, 58, shentsize_);
        rd(base_, size_, 60, shnum16);
        rd(base_, size_, 62, shstrndx16);
        img.entry = entry;
    } else {
        u32 entry = 0, phoff = 0, shoff = 0;
        rd(base_, size_, 24, entry);
        rd(base_, size_, 28, phoff);
        rd(base_, size_, 32, shoff);
        rd(base_, size_, 42, phentsize_);
        rd(base_, size_, 44, phnum16);
        rd(base_, size_, 46, shentsize_);
        rd(base_, size_, 48, shnum16);
        rd(base_, size_, 50, shstrndx16);
        img.entry = entry;
        phoff_ = phoff;
        shoff_ = shoff;
    }

    switch (machine_) {
    case EM_X86_64:  img.arch = Arch::X64;   break;
    case EM_386:     img.arch = Arch::X86;   break;
    case EM_AARCH64: img.arch = Arch::ARM64; break;
    case EM_ARM:     img.arch = Arch::ARM;   break;
    case EM_MIPS:    img.arch = Arch::MIPS;  break;
    case EM_PPC:
    case EM_PPC64:   img.arch = Arch::PPC;   break;
    default:
        spdlog::warn("elf: unsupported machine 0x{:X}", machine_);
        return false;
    }

    // Extended numbering: the real counts live in section header 0
    phnum_ = phnum16;
    shnum_ = shnum16;
    shstrndx_ = shstrndx16;
    if (shoff_ && (phnum16 == PN_XNUM || shnum16 == 0 || shstrndx16 == SHN_XINDEX)) {
        Shdr s0;
        View v = view();
        if (v.shdr(0, s0)) {
            if (phnum16 == PN_XNUM) phnum_ = s0.info;
            if (shnum16 == 0) shnum_ = static_cast<u32>(std::min<u64>(s0.size, 0xFFFFFFFFu));
            if (shstrndx16 == SHN_XINDEX) shstrndx_ = s0.link;
        }
    }
    // cap counts by what the file can hold so a hostile header can't spin
    if (phentsize_ && phoff_ < size_)
        phnum_ = static_cast<u32>(std::min<u64>(phnum_, (size_ - phoff_) / phentsize_));
    else
        phnum_ = 0;
    if (shentsize_ && shoff_ && shoff_ < size_)
        shnum_ = static_cast<u32>(std::min<u64>(shnum_, (size_ - shoff_) / shentsize_));
    else
        shnum_ = 0;
    return true;
}

bool ELFLoader::parse_segments(PEImage& img) {
    const View v = view();
    std::vector<Phdr> loads, relros;
    for (u32 i = 0; i < v.phnum; ++i) {
        Phdr p;
        if (!v.phdr(i, p)) break;
        if (p.type == PT_LOAD && p.memsz) loads.push_back(p);
        else if (p.type == PT_SCE_RELRO && p.memsz) relros.push_back(p);
    }
    if (loads.empty() && relros.empty()) return false;

    auto make_seg = [&](const Phdr& p, u64 va, u64 memsz, std::string name) {
        Segment seg;
        seg.name     = std::move(name);
        seg.va       = va;
        seg.size     = memsz;
        const u64 skip = va - p.vaddr;
        seg.file_off = p.offset + skip;
        seg.file_sz  = p.filesz > skip ? std::min(p.filesz - skip, memsz) : 0;
        seg.flags    = elf_to_pe_flags(p.flags);
        if (seg.file_sz && seg.file_off <= size_ && seg.file_sz <= size_ - seg.file_off) {
            const u64 mem = memsz - seg.file_sz <= kMaxZeroFill ? memsz : seg.file_sz;
            seg.data = segment_bytes(img, base_ + seg.file_off,
                                     static_cast<size_t>(seg.file_sz), static_cast<size_t>(mem));
        } else if (!seg.file_sz && memsz <= kMaxZeroFill) {
            seg.data = segment_bytes(img, base_, 0, static_cast<size_t>(memsz));
        }
        return seg;
    };
    auto perm_name = [](u32 pflags) -> std::string {
        if (pflags & PF_X) return ".text";
        if (pflags & PF_W) return ".data";
        return ".rodata";
    };

    for (const auto& p : loads)
        img.segments.push_back(make_seg(p, p.vaddr, p.memsz, perm_name(p.flags)));

    // PT_SCE_RELRO is mapped by the PS4 loader on its own. When a LOAD
    // already covers (part of) it, only the uncovered pieces become segments
    // so no byte is analyzed twice
    for (const auto& r : relros) {
        std::vector<std::pair<u64, u64>> pieces{{r.vaddr, r.vaddr + r.memsz}};
        for (const auto& l : loads) {
            const u64 ls = l.vaddr, le = l.vaddr + l.memsz;
            std::vector<std::pair<u64, u64>> next;
            for (auto [s, e] : pieces) {
                if (le <= s || ls >= e) { next.emplace_back(s, e); continue; }
                if (s < ls) next.emplace_back(s, ls);
                if (le < e) next.emplace_back(le, e);
            }
            pieces = std::move(next);
        }
        for (auto [s, e] : pieces)
            img.segments.push_back(make_seg(r, s, e - s, ".data.rel.ro"));
    }

    std::sort(img.segments.begin(), img.segments.end(),
              [](const Segment& a, const Segment& b) { return a.va < b.va; });

    // image base: lowest mapped address, page-aligned down
    const Phdr* first = nullptr;
    for (const auto& p : loads)
        if (!first || p.vaddr < first->vaddr) first = &p;
    const va_t lo = img.segments.front().va;
    img.base = lo & ~(kPage - 1);
    header_base_ = img.base;
    if (first && first->vaddr >= first->offset) {
        const va_t hb = first->vaddr - first->offset;
        if ((hb & (kPage - 1)) == 0) header_base_ = hb;
    }
    return true;
}

void ELFLoader::parse_sections(PEImage& img) {
    const View v = view();
    if (!v.shnum) return;

    u64 shstr_off = 0, shstr_end = 0;
    Shdr strsh;
    if (v.shstrndx && v.shstrndx < v.shnum && v.shdr(v.shstrndx, strsh)) {
        shstr_off = strsh.offset;
        shstr_end = strsh.offset + strsh.size;
    }
    if (!shstr_end) return;

    // name each segment after the largest allocated section it holds
    std::vector<u64> best(img.segments.size(), 0);
    for (u32 i = 1; i < v.shnum; ++i) {
        Shdr sh;
        if (!v.shdr(i, sh)) break;
        if (!(sh.flags & SHF_ALLOC) || sh.addr == 0 || sh.size == 0) continue;
        const auto name = cstr_at(base_, size_, shstr_off + sh.name, shstr_end);
        if (name.empty()) continue;
        for (size_t s = 0; s < img.segments.size(); ++s) {
            auto& seg = img.segments[s];
            if (!seg.contains(sh.addr)) continue;
            if (sh.size > best[s]) {
                best[s] = sh.size;
                seg.name = std::string(name);
            }
            break;
        }
    }
}

void ELFLoader::parse_symbols(PEImage& img) {
    const View v = view();
    for (u32 si = 0; si < v.shnum; ++si) {
        Shdr sh;
        if (!v.shdr(si, sh)) break;
        if (sh.type != SHT_SYMTAB && sh.type != SHT_DYNSYM) continue;
        if (sh.entsize < v.sym_size() || sh.offset > size_ || sh.size > size_ - sh.offset) continue;
        Shdr strsh;
        if (sh.link >= v.shnum || !v.shdr(sh.link, strsh)) continue;
        const u64 str_end = strsh.offset + strsh.size;

        const u64 count = sh.size / sh.entsize;
        std::unordered_set<va_t> export_addrs;
        for (const auto& e : img.exports) export_addrs.insert(e.addr);
        for (u64 i = 1; i < count; ++i) {
            Sym sym;
            if (!v.sym(sh.offset + i * sh.entsize, sym)) break;
            const u8 bind = sym.info >> 4;
            const u8 type = sym.info & 0xF;
            if (type != STT_FUNC || sym.value == 0 || sym.shndx == 0) continue;
            const auto name = cstr_at(base_, size_, strsh.offset + sym.name, str_end);
            if (name.empty()) continue;
            // ARM Thumb functions carry the mode in bit 0
            const va_t addr = img.arch == Arch::ARM ? (sym.value & ~u64{1}) : sym.value;

            if (bind == STB_GLOBAL || bind == STB_WEAK) {
                // .dynsym repeats the exported subset of .symtab
                if (!export_addrs.insert(addr).second) continue;
                Export exp;
                exp.name = std::string(name);
                exp.addr = addr;
                img.exports.push_back(std::move(exp));
            } else if (bind == STB_LOCAL) {
                img.symbols.push_back({std::string(name), addr});
            }
        }
    }
}

void ELFLoader::parse_dynamic(PEImage& img) {
    const View v = view();
    const DynTables t = find_dyn_tables(v);
    if (t.sce || !t.has_symbols() || !t.str_off) return;

    std::unordered_set<va_t> seen;
    auto emit = [&](u64 off, u64 sz, bool rela) {
        if (!off || !sz) return;
        const u64 esz = v.reloc_size(rela);
        for (u64 o = off; o + esz <= off + sz; o += esz) {
            Reloc r;
            if (!v.reloc(o, rela, r)) break;
            if (!r.sym) continue;
            Sym sym;
            const u64 soff = t.sym_off + u64{r.sym} * v.sym_size();
            if (soff + v.sym_size() > t.sym_end || !v.sym(soff, sym)) continue;
            if (sym.shndx != 0) continue;   // defined here: not an import
            const auto name = cstr_at(base_, size_, t.str_off + sym.name, t.str_end);
            if (name.empty() || !seen.insert(r.offset).second) continue;
            Import imp;
            imp.dll = "extern";
            imp.name = std::string(name);
            imp.ordinal = 0;
            imp.iat_addr = r.offset;
            img.imports.push_back(std::move(imp));
        }
    };
    emit(t.jmprel_off, t.jmprel_sz, t.jmprel_is_rela);
    emit(t.rela_off, t.rela_sz, t.rela_is_rela);
}

// PS4 OELF: imports/exports live in PT_SCE_DYNLIBDATA. Symbol names are
// "<nid>#<lib id>#<module id>"; DT_SCE_IMPORT_LIB maps library ids to names
// (libkernel, libSceGnmDriver, ...), DT_SCE_NEEDED_MODULE maps module ids
void ELFLoader::parse_sce_dynlibdata(PEImage& img) {
    if (!is64_) return;
    const View v = view();
    const DynTables t = find_dyn_tables(v);
    if (!t.sce || !t.has_symbols()) return;

    const auto sce_str = [&](u32 off) { return cstr_at(base_, size_, t.str_off + off, t.str_end); };
    std::unordered_map<u64, std::string> lib_names, module_names;
    for (const auto& [id, off] : t.import_libs) lib_names[id] = std::string(sce_str(off));
    for (const auto& [id, off] : t.needed_modules) module_names[id] = std::string(sce_str(off));

    // "<nid>#L#M" -> resolved name (or the bare NID) and the library name
    auto resolve = [&](std::string_view raw, std::string& name, std::string& lib) {
        const size_t h1 = raw.find('#');
        const std::string_view nid_s = raw.substr(0, h1);
        auto resolved = nid::lookup(nid_s);
        name = resolved ? *resolved : std::string(nid_s);
        lib.clear();
        if (h1 == std::string_view::npos) return;
        const size_t h2 = raw.find('#', h1 + 1);
        const std::string_view lib_s = raw.substr(h1 + 1, h2 == std::string_view::npos
                                                            ? std::string_view::npos : h2 - h1 - 1);
        u64 lib_id = 0, mod_id = 0;
        if (nid::decode_id(lib_s, lib_id)) {
            if (auto it = lib_names.find(lib_id); it != lib_names.end() && !it->second.empty()) {
                lib = it->second;
                return;
            }
        }
        if (h2 != std::string_view::npos && nid::decode_id(raw.substr(h2 + 1), mod_id)) {
            if (auto it = module_names.find(mod_id); it != module_names.end() && !it->second.empty()) {
                lib = it->second;
                return;
            }
        }
        lib = fmt::format("lib#{}", lib_s);
    };

    std::unordered_set<va_t> seen;
    auto emit = [&](u64 off, u64 sz) {
        if (!off || !sz) return;
        const u64 esz = v.reloc_size(true);
        for (u64 o = off; o + esz <= off + sz; o += esz) {
            Reloc r;
            if (!v.reloc(o, true, r)) break;
            if (!r.sym) continue;
            Sym sym;
            const u64 soff = t.sym_off + u64{r.sym} * v.sym_size();
            if (soff + v.sym_size() > t.sym_end || !v.sym(soff, sym)) continue;
            if (sym.shndx != 0) continue;
            const auto raw = sce_str(sym.name);
            if (raw.empty() || !seen.insert(r.offset).second) continue;
            Import imp;
            resolve(raw, imp.name, imp.dll);
            imp.ordinal = 0;
            imp.iat_addr = r.offset;
            img.imports.push_back(std::move(imp));
        }
    };
    emit(t.jmprel_off, t.jmprel_sz);
    emit(t.rela_off, t.rela_sz);

    // exported (defined) functions: module_start, prx entry points
    for (u64 soff = t.sym_off + v.sym_size(); soff + v.sym_size() <= t.sym_end; soff += v.sym_size()) {
        Sym sym;
        if (!v.sym(soff, sym)) break;
        const u8 bind = sym.info >> 4;
        if (sym.shndx == 0 || sym.value == 0 || (sym.info & 0xF) != STT_FUNC) continue;
        if (bind != STB_GLOBAL && bind != STB_WEAK) continue;
        const auto raw = sce_str(sym.name);
        if (raw.empty()) continue;
        Export exp;
        std::string lib;
        resolve(raw, exp.name, lib);
        exp.addr = sym.value;
        img.exports.push_back(std::move(exp));
    }

    if (!img.imports.empty())
        spdlog::info("elf: PS4 dynlibdata: {} imports from {} libraries",
                     img.imports.size(), lib_names.size());
}

ELFLoader::RelocStats ELFLoader::apply_relocations(std::span<u8> file, va_t load_base) {
    RelocStats st;
    ELFLoader L;
    L.base_ = file.data();
    L.size_ = file.size();
    PEImage scratch;
    if (!L.parse_header(scratch) || !L.is64_) return st;
    const bool x64 = L.machine_ == EM_X86_64;
    const bool a64 = L.machine_ == EM_AARCH64;
    if (!x64 && !a64) return st;

    const View v = L.view();
    // natural base = lowest PT_LOAD, page-aligned (parse_segments' rule)
    u64 lo = ~u64{0};
    for (u32 i = 0; i < v.phnum; ++i) {
        Phdr p;
        if (!v.phdr(i, p)) break;
        if ((p.type == PT_LOAD || p.type == PT_SCE_RELRO) && p.memsz && p.vaddr < lo) lo = p.vaddr;
    }
    if (lo == ~u64{0}) return st;
    const u64 natural = lo & ~(kPage - 1);
    const u64 bias = load_base ? load_base - natural : 0;

    const DynTables t = L.find_dyn_tables(v);
    // slot -> file offset; PS4 RELRO slots are mapped too
    auto slot_off = [&](u64 va, u64& out) {
        if (v.va_to_off(va, 8, out)) return true;
        for (u32 i = 0; i < v.phnum; ++i) {
            Phdr p;
            if (!v.phdr(i, p) || p.type != PT_SCE_RELRO) continue;
            if (va < p.vaddr || va - p.vaddr >= p.filesz || p.filesz - (va - p.vaddr) < 8) continue;
            out = p.offset + (va - p.vaddr);
            return out + 8 <= L.size_;
        }
        return false;
    };

    auto apply = [&](u64 off, u64 sz, bool rela) {
        if (!off || !sz || !rela) return;   // ELF64 x86-64/AArch64 use RELA only
        const u64 esz = v.reloc_size(true);
        for (u64 o = off; o + esz <= off + sz; o += esz) {
            Reloc r;
            if (!v.reloc(o, true, r)) break;
            const bool relative = (x64 && r.type == R_X86_64_RELATIVE) ||
                                  (a64 && r.type == R_AARCH64_RELATIVE);
            const bool abs64    = (x64 && r.type == R_X86_64_64) ||
                                  (a64 && r.type == R_AARCH64_ABS64);
            const bool slot     = (x64 && (r.type == R_X86_64_GLOB_DAT ||
                                           r.type == R_X86_64_JUMP_SLOT)) ||
                                  (a64 && (r.type == R_AARCH64_GLOB_DAT ||
                                           r.type == R_AARCH64_JUMP_SLOT));
            if (!relative && !abs64 && !slot) { ++st.skipped; continue; }

            u64 value = 0;
            if (relative) {
                value = bias + static_cast<u64>(r.addend);
            } else {
                Sym sym;
                const u64 soff = t.sym_off + u64{r.sym} * v.sym_size();
                if (!r.sym || !t.has_symbols() || soff + v.sym_size() > t.sym_end ||
                    !v.sym(soff, sym)) { ++st.skipped; continue; }
                if (sym.shndx == 0) { ++st.imported; continue; }
                const u64 s = bias + sym.value;
                // x86-64 GLOB_DAT/JUMP_SLOT are S; AArch64 slots and both ABS64 are S + A
                value = (x64 && slot) ? s : s + static_cast<u64>(r.addend);
            }
            u64 foff = 0;
            if (!slot_off(r.offset, foff)) { ++st.skipped; continue; }
            std::memcpy(file.data() + foff, &value, 8);
            ++st.applied;
        }
    };
    apply(t.rela_off, t.rela_sz, t.rela_is_rela);
    apply(t.jmprel_off, t.jmprel_sz, t.jmprel_is_rela);
    return st;
}

}
