#include "elf_loader.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <fstream>
#include <cstring>

namespace hype {

namespace {

constexpr u32 ELF_MAGIC = 0x464C457F; // "\x7fELF"

// ELF classes
constexpr u8 ELFCLASS32 = 1;
constexpr u8 ELFCLASS64 = 2;

// Endianness
constexpr u8 ELFDATA2LSB = 1;
constexpr u8 ELFDATA2MSB = 2;

// Machine types
constexpr u16 EM_386     = 3;
constexpr u16 EM_MIPS    = 8;
constexpr u16 EM_PPC     = 20;
constexpr u16 EM_PPC64   = 21;
constexpr u16 EM_ARM     = 40;
constexpr u16 EM_X86_64  = 62;
constexpr u16 EM_AARCH64 = 183;

// Segment types
constexpr u32 PT_LOAD         = 1;
[[maybe_unused]] constexpr u32 PT_DYNAMIC = 2;
// PS4 SCE-specific program header types
constexpr u32 PT_SCE_DYNLIBDATA = 0x61000000;
constexpr u32 PT_SCE_RELRO      = 0x61000010;

// PS4 SCE dynamic tags (d_val is offset within PT_SCE_DYNLIBDATA)
constexpr i64 DT_SCE_STRTAB  = 0x61000035;
constexpr i64 DT_SCE_STRSZ   = 0x61000037;
constexpr i64 DT_SCE_SYMTAB  = 0x61000039;
constexpr i64 DT_SCE_SYMTABSZ = 0x6100003F;
constexpr i64 DT_SCE_JMPREL  = 0x61000029;
constexpr i64 DT_SCE_PLTRELSZ = 0x6100002B;
constexpr i64 DT_SCE_RELA    = 0x6100002F;
constexpr i64 DT_SCE_RELASZ  = 0x61000031;

// Segment flags
constexpr u32 PF_X = 1;
constexpr u32 PF_W = 2;
constexpr u32 PF_R = 4;

// Section types
constexpr u32 SHT_SYMTAB  = 2;
[[maybe_unused]] constexpr u32 SHT_STRTAB  = 3;
[[maybe_unused]] constexpr u32 SHT_DYNAMIC = 6;
constexpr u32 SHT_DYNSYM  = 11;

// Symbol binding/type
constexpr u8 STB_GLOBAL = 1;
constexpr u8 STB_WEAK   = 2;
constexpr u8 STT_FUNC   = 2;

// Dynamic tags
[[maybe_unused]] constexpr i64 DT_NEEDED  = 1;
[[maybe_unused]] constexpr i64 DT_PLTGOT  = 3;
[[maybe_unused]] constexpr i64 DT_STRTAB  = 5;
[[maybe_unused]] constexpr i64 DT_JMPREL  = 23;
[[maybe_unused]] constexpr i64 DT_PLTRELSZ = 2;

#pragma pack(push, 1)
struct Elf32_Ehdr {
    u8  e_ident[16];
    u16 e_type, e_machine;
    u32 e_version;
    u32 e_entry, e_phoff, e_shoff;
    u32 e_flags;
    u16 e_ehsize, e_phentsize, e_phnum;
    u16 e_shentsize, e_shnum, e_shstrndx;
};

struct Elf64_Ehdr {
    u8  e_ident[16];
    u16 e_type, e_machine;
    u32 e_version;
    u64 e_entry, e_phoff, e_shoff;
    u32 e_flags;
    u16 e_ehsize, e_phentsize, e_phnum;
    u16 e_shentsize, e_shnum, e_shstrndx;
};

struct Elf32_Phdr {
    u32 p_type, p_offset, p_vaddr, p_paddr;
    u32 p_filesz, p_memsz, p_flags, p_align;
};

struct Elf64_Phdr {
    u32 p_type, p_flags;
    u64 p_offset, p_vaddr, p_paddr;
    u64 p_filesz, p_memsz, p_align;
};

struct Elf32_Shdr {
    u32 sh_name, sh_type, sh_flags;
    u32 sh_addr, sh_offset, sh_size;
    u32 sh_link, sh_info, sh_addralign, sh_entsize;
};

struct Elf64_Shdr {
    u32 sh_name, sh_type;
    u64 sh_flags, sh_addr, sh_offset, sh_size;
    u32 sh_link, sh_info;
    u64 sh_addralign, sh_entsize;
};

struct Elf32_Sym {
    u32 st_name;
    u32 st_value;
    u32 st_size;
    u8  st_info, st_other;
    u16 st_shndx;
};

struct Elf64_Sym {
    u32 st_name;
    u8  st_info, st_other;
    u16 st_shndx;
    u64 st_value, st_size;
};

struct Elf64_Dyn {
    i64 d_tag;
    u64 d_val;
};

struct Elf32_Dyn {
    i32 d_tag;
    u32 d_val;
};

struct Elf64_Rela {
    u64 r_offset;
    u64 r_info;
    i64 r_addend;
};

struct Elf32_Rel {
    u32 r_offset;
    u32 r_info;
};
#pragma pack(pop)

u32 elf_to_pe_flags(u32 pflags) {
    u32 f = 0;
    if (pflags & PF_R) f |= 0x40000000;
    if (pflags & PF_W) f |= 0x80000000;
    if (pflags & PF_X) f |= 0x20000000;
    return f;
}

const char* strtab_get(const u8* strtab, size_t strtab_sz, u32 offset) {
    if (offset >= strtab_sz) return "";
    return reinterpret_cast<const char*>(strtab + offset);
}

} // anon

bool ELFLoader::is_elf(const u8* data, size_t size) {
    if (size < 4) return false;
    u32 magic = 0;
    std::memcpy(&magic, data, 4);
    return magic == ELF_MAGIC;
}

std::optional<PEImage> ELFLoader::load_buffer(const u8* data, size_t size) {
    if (size < 64) return std::nullopt;

    PEImage img;
    auto file = std::make_shared<std::vector<u8>>(data, data + size);
    img.storage.push_back(file);
    img.raw = *file;

    base_ = file->data();
    size_ = size;

    if (!parse_header(img)) return std::nullopt;
    if (!parse_segments(img)) return std::nullopt;
    if (!parse_sections(img)) return std::nullopt;
    if (!parse_symbols(img)) return std::nullopt;
    parse_dynamic(img);
    if (img.imports.empty()) parse_sce_dynlibdata(img);

    spdlog::info("elf: loaded buffer - base=0x{:X} entry=0x{:X} segs={} imports={} exports={}",
                 img.base, img.entry,
                 img.segments.size(), img.imports.size(), img.exports.size());
    return img;
}

std::optional<PEImage> ELFLoader::load(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return std::nullopt;

    size_t sz = static_cast<size_t>(f.tellg());
    if (sz < 64) return std::nullopt;
    f.seekg(0);

    PEImage img;
    auto file = std::make_shared<std::vector<u8>>(sz);
    f.read(reinterpret_cast<char*>(file->data()), sz);
    img.storage.push_back(file);
    img.raw = *file;

    base_ = file->data();
    size_ = sz;

    if (!parse_header(img)) return std::nullopt;
    if (!parse_segments(img)) return std::nullopt;
    if (!parse_sections(img)) return std::nullopt;
    if (!parse_symbols(img)) return std::nullopt;
    parse_dynamic(img);
    if (img.imports.empty()) parse_sce_dynlibdata(img);

    spdlog::info("elf: loaded {} - base=0x{:X} entry=0x{:X} segs={} imports={} exports={}",
                 path.filename().string(), img.base, img.entry,
                 img.segments.size(), img.imports.size(), img.exports.size());
    return img;
}

bool ELFLoader::parse_header(PEImage& img) {
    if (size_ < sizeof(Elf32_Ehdr)) return false;

    u32 magic = 0;
    std::memcpy(&magic, base_, 4);
    if (magic != ELF_MAGIC) return false;

    u8 ei_class = base_[4];
    u8 ei_data  = base_[5];

    if (ei_class == ELFCLASS64) is64_ = true;
    else if (ei_class == ELFCLASS32) is64_ = false;
    else return false;

    le_ = (ei_data == ELFDATA2LSB);
    if (ei_data == ELFDATA2MSB) {
        spdlog::warn("elf: big-endian not fully supported");
        return false;
    }

    if (is64_) {
        if (size_ < sizeof(Elf64_Ehdr)) return false;
        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);
        switch (eh->e_machine) {
        case EM_X86_64:  img.arch = Arch::X64;   break;
        case EM_386:     img.arch = Arch::X86;   break;
        case EM_AARCH64: img.arch = Arch::ARM64; break;
        case EM_ARM:     img.arch = Arch::ARM;   break;
        case EM_MIPS:    img.arch = Arch::MIPS;  break;
        case EM_PPC:
        case EM_PPC64:   img.arch = Arch::PPC;   break;
        default:
            spdlog::warn("elf: unsupported machine 0x{:X}", eh->e_machine);
            return false;
        }
        img.entry = eh->e_entry;
    } else {
        if (size_ < sizeof(Elf32_Ehdr)) return false;
        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(base_);
        switch (eh->e_machine) {
        case EM_386:     img.arch = Arch::X86;   break;
        case EM_X86_64:  img.arch = Arch::X64;   break;
        case EM_ARM:     img.arch = Arch::ARM;   break;
        case EM_MIPS:    img.arch = Arch::MIPS;  break;
        case EM_PPC:     img.arch = Arch::PPC;   break;
        default:
            spdlog::warn("elf: unsupported machine 0x{:X}", eh->e_machine);
            return false;
        }
        img.entry = eh->e_entry;
    }

    return true;
}

bool ELFLoader::parse_segments(PEImage& img) {
    va_t lo = ~va_t(0), hi = 0;

    if (is64_) {
        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);
        for (u16 i = 0; i < eh->e_phnum; ++i) {
            size_t off = eh->e_phoff + i * eh->e_phentsize;
            if (off + sizeof(Elf64_Phdr) > size_) break;
            auto* ph = reinterpret_cast<const Elf64_Phdr*>(base_ + off);
            // PT_SCE_RELRO is a PS4 read-only-after-reloc segment, treat as PT_LOAD
            if (ph->p_type != PT_LOAD && ph->p_type != PT_SCE_RELRO) continue;

            Segment seg;
            seg.name = fmt::format("LOAD_{}", img.segments.size());
            seg.va = ph->p_vaddr;
            seg.size = ph->p_memsz;
            seg.file_off = ph->p_offset;
            seg.file_sz = ph->p_filesz;
            seg.flags = elf_to_pe_flags(ph->p_flags);

            if (ph->p_offset + ph->p_filesz <= size_) {
                seg.data = segment_bytes(img, base_ + ph->p_offset, ph->p_filesz, ph->p_memsz);
            }

            if (seg.va < lo) lo = seg.va;
            if (seg.va + seg.size > hi) hi = seg.va + seg.size;
            img.segments.push_back(std::move(seg));
        }
    } else {
        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(base_);
        for (u16 i = 0; i < eh->e_phnum; ++i) {
            size_t off = eh->e_phoff + i * eh->e_phentsize;
            if (off + sizeof(Elf32_Phdr) > size_) break;
            auto* ph = reinterpret_cast<const Elf32_Phdr*>(base_ + off);
            if (ph->p_type != PT_LOAD) continue;

            Segment seg;
            seg.name = fmt::format("LOAD_{}", img.segments.size());
            seg.va = ph->p_vaddr;
            seg.size = ph->p_memsz;
            seg.file_off = ph->p_offset;
            seg.file_sz = ph->p_filesz;
            seg.flags = elf_to_pe_flags(ph->p_flags);

            if (ph->p_offset + ph->p_filesz <= size_) {
                seg.data = segment_bytes(img, base_ + ph->p_offset, ph->p_filesz, ph->p_memsz);
            }

            if (seg.va < lo) lo = seg.va;
            if (seg.va + seg.size > hi) hi = seg.va + seg.size;
            img.segments.push_back(std::move(seg));
        }
    }

    img.base = (lo != ~va_t(0)) ? lo : 0;
    return !img.segments.empty();
}

bool ELFLoader::parse_sections(PEImage& img) {
    const u8* shstrtab = nullptr;
    size_t shstrtab_sz = 0;

    if (is64_) {
        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);
        if (eh->e_shnum == 0 || eh->e_shstrndx == 0) return true;

        size_t str_off = eh->e_shoff + eh->e_shstrndx * eh->e_shentsize;
        if (str_off + sizeof(Elf64_Shdr) > size_) return true;
        auto* str_sh = reinterpret_cast<const Elf64_Shdr*>(base_ + str_off);
        if (str_sh->sh_offset + str_sh->sh_size <= size_) {
            shstrtab = base_ + str_sh->sh_offset;
            shstrtab_sz = static_cast<size_t>(str_sh->sh_size);
        }

        for (u16 i = 0; i < eh->e_shnum; ++i) {
            size_t off = eh->e_shoff + i * eh->e_shentsize;
            if (off + sizeof(Elf64_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf64_Shdr*>(base_ + off);
            if (sh->sh_addr == 0 || sh->sh_size == 0) continue;

            const char* name = shstrtab ? strtab_get(shstrtab, shstrtab_sz, sh->sh_name) : "";

            for (auto& seg : img.segments) {
                if (sh->sh_addr >= seg.va && sh->sh_addr < seg.va + seg.size) {
                    if (name[0]) seg.name = name;
                    break;
                }
            }
        }
    } else {
        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(base_);
        if (eh->e_shnum == 0 || eh->e_shstrndx == 0) return true;

        size_t str_off = eh->e_shoff + eh->e_shstrndx * eh->e_shentsize;
        if (str_off + sizeof(Elf32_Shdr) > size_) return true;
        auto* str_sh = reinterpret_cast<const Elf32_Shdr*>(base_ + str_off);
        if (str_sh->sh_offset + str_sh->sh_size <= size_) {
            shstrtab = base_ + str_sh->sh_offset;
            shstrtab_sz = str_sh->sh_size;
        }

        for (u16 i = 0; i < eh->e_shnum; ++i) {
            size_t off = eh->e_shoff + i * eh->e_shentsize;
            if (off + sizeof(Elf32_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf32_Shdr*>(base_ + off);
            if (sh->sh_addr == 0 || sh->sh_size == 0) continue;

            const char* name = shstrtab ? strtab_get(shstrtab, shstrtab_sz, sh->sh_name) : "";

            for (auto& seg : img.segments) {
                if (sh->sh_addr >= seg.va && sh->sh_addr < seg.va + seg.size) {
                    if (name[0]) seg.name = name;
                    break;
                }
            }
        }
    }
    return true;
}

bool ELFLoader::parse_symbols(PEImage& img) {
    if (is64_) {
        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);
        for (u16 si = 0; si < eh->e_shnum; ++si) {
            size_t off = eh->e_shoff + si * eh->e_shentsize;
            if (off + sizeof(Elf64_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf64_Shdr*>(base_ + off);

            if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) continue;
            if (sh->sh_offset + sh->sh_size > size_) continue;
            if (sh->sh_entsize < sizeof(Elf64_Sym)) continue;

            // get linked strtab
            size_t strtab_off_hdr = eh->e_shoff + sh->sh_link * eh->e_shentsize;
            if (strtab_off_hdr + sizeof(Elf64_Shdr) > size_) continue;
            auto* str_sh = reinterpret_cast<const Elf64_Shdr*>(base_ + strtab_off_hdr);
            if (str_sh->sh_offset + str_sh->sh_size > size_) continue;

            const u8* strtab = base_ + str_sh->sh_offset;
            size_t strtab_sz = static_cast<size_t>(str_sh->sh_size);
            size_t count = static_cast<size_t>(sh->sh_size / sh->sh_entsize);

            for (size_t i = 1; i < count; ++i) {
                auto* sym = reinterpret_cast<const Elf64_Sym*>(
                    base_ + sh->sh_offset + i * sh->sh_entsize);

                u8 bind = sym->st_info >> 4;
                u8 type = sym->st_info & 0xF;
                if (sym->st_value == 0) continue;
                if (sym->st_shndx == 0) continue;

                const char* name = strtab_get(strtab, strtab_sz, sym->st_name);
                if (!name[0]) continue;

                if (type == STT_FUNC && (bind == STB_GLOBAL || bind == STB_WEAK)) {
                    Export exp;
                    exp.name = name;
                    exp.ordinal = 0;
                    exp.addr = sym->st_value;
                    img.exports.push_back(std::move(exp));
                }
            }
        }
    } else {
        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(base_);
        for (u16 si = 0; si < eh->e_shnum; ++si) {
            size_t off = eh->e_shoff + si * eh->e_shentsize;
            if (off + sizeof(Elf32_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf32_Shdr*>(base_ + off);

            if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) continue;
            if (sh->sh_offset + sh->sh_size > size_) continue;
            if (sh->sh_entsize < sizeof(Elf32_Sym)) continue;

            size_t strtab_off_hdr = eh->e_shoff + sh->sh_link * eh->e_shentsize;
            if (strtab_off_hdr + sizeof(Elf32_Shdr) > size_) continue;
            auto* str_sh = reinterpret_cast<const Elf32_Shdr*>(base_ + strtab_off_hdr);
            if (str_sh->sh_offset + str_sh->sh_size > size_) continue;

            const u8* strtab = base_ + str_sh->sh_offset;
            size_t strtab_sz = str_sh->sh_size;
            size_t count = sh->sh_size / sh->sh_entsize;

            for (size_t i = 1; i < count; ++i) {
                auto* sym = reinterpret_cast<const Elf32_Sym*>(
                    base_ + sh->sh_offset + i * sh->sh_entsize);

                u8 bind = sym->st_info >> 4;
                u8 type = sym->st_info & 0xF;
                if (sym->st_value == 0) continue;
                if (sym->st_shndx == 0) continue;

                const char* name = strtab_get(strtab, strtab_sz, sym->st_name);
                if (!name[0]) continue;

                if (type == STT_FUNC && (bind == STB_GLOBAL || bind == STB_WEAK)) {
                    Export exp;
                    exp.name = name;
                    exp.ordinal = 0;
                    exp.addr = sym->st_value;
                    img.exports.push_back(std::move(exp));
                }
            }
        }
    }
    return true;
}

bool ELFLoader::parse_dynamic(PEImage& img) {
    if (is64_) {
        auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);

        // Find .dynsym strtab and .rela.plt for import resolution
        const Elf64_Shdr* dynsym_sh = nullptr;
        const Elf64_Shdr* relaplt_sh = nullptr;
        const u8* dynstr = nullptr;
        size_t dynstr_sz = 0;

        for (u16 i = 0; i < eh->e_shnum; ++i) {
            size_t off = eh->e_shoff + i * eh->e_shentsize;
            if (off + sizeof(Elf64_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf64_Shdr*>(base_ + off);

            if (sh->sh_type == SHT_DYNSYM) {
                dynsym_sh = sh;
                size_t str_hdr_off = eh->e_shoff + sh->sh_link * eh->e_shentsize;
                if (str_hdr_off + sizeof(Elf64_Shdr) <= size_) {
                    auto* sth = reinterpret_cast<const Elf64_Shdr*>(base_ + str_hdr_off);
                    if (sth->sh_offset + sth->sh_size <= size_) {
                        dynstr = base_ + sth->sh_offset;
                        dynstr_sz = static_cast<size_t>(sth->sh_size);
                    }
                }
            }

            // .rela.plt type = SHT_RELA (4)
            if (sh->sh_type == 4) {
                // check name via shstrtab
                size_t str_sec_off = eh->e_shoff + eh->e_shstrndx * eh->e_shentsize;
                if (str_sec_off + sizeof(Elf64_Shdr) <= size_) {
                    auto* ssh = reinterpret_cast<const Elf64_Shdr*>(base_ + str_sec_off);
                    if (ssh->sh_offset + ssh->sh_size <= size_) {
                        const char* n = strtab_get(base_ + ssh->sh_offset,
                            static_cast<size_t>(ssh->sh_size), sh->sh_name);
                        if (std::strcmp(n, ".rela.plt") == 0)
                            relaplt_sh = sh;
                    }
                }
            }
        }

        if (dynsym_sh && dynstr && relaplt_sh) {
            size_t rela_count = static_cast<size_t>(relaplt_sh->sh_size / relaplt_sh->sh_entsize);
            for (size_t i = 0; i < rela_count; ++i) {
                size_t roff = static_cast<size_t>(relaplt_sh->sh_offset) + i * static_cast<size_t>(relaplt_sh->sh_entsize);
                if (roff + sizeof(Elf64_Rela) > size_) break;
                auto* rela = reinterpret_cast<const Elf64_Rela*>(base_ + roff);

                u32 sym_idx = static_cast<u32>(rela->r_info >> 32);
                size_t sym_off = static_cast<size_t>(dynsym_sh->sh_offset) + sym_idx * sizeof(Elf64_Sym);
                if (sym_off + sizeof(Elf64_Sym) > size_) continue;

                auto* sym = reinterpret_cast<const Elf64_Sym*>(base_ + sym_off);
                const char* name = strtab_get(dynstr, dynstr_sz, sym->st_name);
                if (!name[0]) continue;

                Import imp;
                imp.dll = "extern";
                imp.name = name;
                imp.ordinal = 0;
                imp.iat_addr = rela->r_offset;
                img.imports.push_back(std::move(imp));
            }
        }
    } else {
        auto* eh = reinterpret_cast<const Elf32_Ehdr*>(base_);

        const Elf32_Shdr* dynsym_sh = nullptr;
        const Elf32_Shdr* relplt_sh = nullptr;
        const u8* dynstr = nullptr;
        size_t dynstr_sz = 0;

        for (u16 i = 0; i < eh->e_shnum; ++i) {
            size_t off = eh->e_shoff + i * eh->e_shentsize;
            if (off + sizeof(Elf32_Shdr) > size_) break;
            auto* sh = reinterpret_cast<const Elf32_Shdr*>(base_ + off);

            if (sh->sh_type == SHT_DYNSYM) {
                dynsym_sh = sh;
                size_t str_hdr_off = eh->e_shoff + sh->sh_link * eh->e_shentsize;
                if (str_hdr_off + sizeof(Elf32_Shdr) <= size_) {
                    auto* sth = reinterpret_cast<const Elf32_Shdr*>(base_ + str_hdr_off);
                    if (sth->sh_offset + sth->sh_size <= size_) {
                        dynstr = base_ + sth->sh_offset;
                        dynstr_sz = sth->sh_size;
                    }
                }
            }

            // .rel.plt type = SHT_REL (9)
            if (sh->sh_type == 9) {
                size_t str_sec_off = eh->e_shoff + eh->e_shstrndx * eh->e_shentsize;
                if (str_sec_off + sizeof(Elf32_Shdr) <= size_) {
                    auto* ssh = reinterpret_cast<const Elf32_Shdr*>(base_ + str_sec_off);
                    if (ssh->sh_offset + ssh->sh_size <= size_) {
                        const char* n = strtab_get(base_ + ssh->sh_offset, ssh->sh_size, sh->sh_name);
                        if (std::strcmp(n, ".rel.plt") == 0)
                            relplt_sh = sh;
                    }
                }
            }
        }

        if (dynsym_sh && dynstr && relplt_sh) {
            size_t rel_count = relplt_sh->sh_size / relplt_sh->sh_entsize;
            for (size_t i = 0; i < rel_count; ++i) {
                size_t roff = relplt_sh->sh_offset + i * relplt_sh->sh_entsize;
                if (roff + sizeof(Elf32_Rel) > size_) break;
                auto* rel = reinterpret_cast<const Elf32_Rel*>(base_ + roff);

                u32 sym_idx = rel->r_info >> 8;
                size_t sym_off = dynsym_sh->sh_offset + sym_idx * sizeof(Elf32_Sym);
                if (sym_off + sizeof(Elf32_Sym) > size_) continue;

                auto* sym = reinterpret_cast<const Elf32_Sym*>(base_ + sym_off);
                const char* name = strtab_get(dynstr, dynstr_sz, sym->st_name);
                if (!name[0]) continue;

                Import imp;
                imp.dll = "extern";
                imp.name = name;
                imp.ordinal = 0;
                imp.iat_addr = rel->r_offset;
                img.imports.push_back(std::move(imp));
            }
        }
    }
    return true;
}

// PS4 OELF: imports live in PT_SCE_DYNLIBDATA, not in section headers.
// Walk PT_DYNAMIC tags to find strtab/symtab/jmprel offsets (all relative
// to the start of PT_SCE_DYNLIBDATA), then emit one Import per PLT slot.
void ELFLoader::parse_sce_dynlibdata(PEImage& img) {
    if (!is64_) return;
    auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base_);

    // find PT_SCE_DYNLIBDATA and PT_DYNAMIC offsets
    u64 dynlib_file_off = 0, dynlib_filesz = 0;
    u64 dyn_file_off = 0,    dyn_filesz = 0;
    for (u16 i = 0; i < eh->e_phnum; ++i) {
        size_t poff = static_cast<size_t>(eh->e_phoff) + i * eh->e_phentsize;
        if (poff + sizeof(Elf64_Phdr) > size_) break;
        auto* ph = reinterpret_cast<const Elf64_Phdr*>(base_ + poff);
        if (ph->p_type == PT_SCE_DYNLIBDATA) {
            dynlib_file_off = ph->p_offset;
            dynlib_filesz   = ph->p_filesz;
        } else if (ph->p_type == 2 /* PT_DYNAMIC */) {
            dyn_file_off = ph->p_offset;
            dyn_filesz   = ph->p_filesz;
        }
    }
    if (!dynlib_file_off || !dyn_file_off) return;
    if (dynlib_file_off + dynlib_filesz > size_) return;
    if (dyn_file_off + dyn_filesz > size_) return;

    // parse PT_DYNAMIC tags — DT_SCE_* values are offsets within PT_SCE_DYNLIBDATA
    u64 strtab_off = 0, strsz = 0;
    u64 symtab_off = 0, symtabsz = 0;
    u64 jmprel_off = 0, jmprelsz = 0;
    u64 rela_off = 0,   relasz = 0;

    size_t dyn_count = static_cast<size_t>(dyn_filesz) / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < dyn_count; ++i) {
        size_t doff = static_cast<size_t>(dyn_file_off) + i * sizeof(Elf64_Dyn);
        if (doff + sizeof(Elf64_Dyn) > size_) break;
        auto* d = reinterpret_cast<const Elf64_Dyn*>(base_ + doff);
        if (d->d_tag == 0) break;
        switch (d->d_tag) {
        case DT_SCE_STRTAB:   strtab_off = d->d_val; break;
        case DT_SCE_STRSZ:    strsz      = d->d_val; break;
        case DT_SCE_SYMTAB:   symtab_off = d->d_val; break;
        case DT_SCE_SYMTABSZ: symtabsz   = d->d_val; break;
        case DT_SCE_JMPREL:   jmprel_off = d->d_val; break;
        case DT_SCE_PLTRELSZ: jmprelsz   = d->d_val; break;
        case DT_SCE_RELA:     rela_off   = d->d_val; break;
        case DT_SCE_RELASZ:   relasz     = d->d_val; break;
        default: break;
        }
    }
    if (!strtab_off || !strsz || !symtab_off || !symtabsz) return;

    // pointers into PT_SCE_DYNLIBDATA content
    const u8* dynbase = base_ + dynlib_file_off;
    auto safe_ptr = [&](u64 rel_off, size_t need) -> const u8* {
        if (rel_off + need > dynlib_filesz) return nullptr;
        return dynbase + rel_off;
    };

    const u8* strtab = safe_ptr(strtab_off, strsz);
    if (!strtab) return;

    // helper: get a NID or library name from the SCE strtab
    auto sce_str = [&](u32 idx) -> const char* {
        return strtab_get(strtab, static_cast<size_t>(strsz), idx);
    };

    // group imports by library (strip trailing "#module" from NID name)
    // NID format: "<11chars>#<lib_id>#<mod_id>" — lib_id part identifies the .prx
    // The strtab also contains library names like "libScePad.prx" at known indices.
    // We group all imports under a single "sce_imports" dll for simplicity; the
    // NID string itself carries the library hint for callers that want it.
    constexpr size_t kSymEntSize = sizeof(Elf64_Sym); // 24 bytes

    // emit from JMPREL (PLT slots = lazy-bound function imports)
    auto emit_rela = [&](u64 rel_off, u64 rel_sz) {
        if (!rel_off || !rel_sz) return;
        const u8* rela_base = safe_ptr(rel_off, static_cast<size_t>(rel_sz));
        if (!rela_base) return;
        size_t count = static_cast<size_t>(rel_sz) / sizeof(Elf64_Rela);
        for (size_t i = 0; i < count; ++i) {
            auto* r = reinterpret_cast<const Elf64_Rela*>(rela_base + i * sizeof(Elf64_Rela));
            u32 sym_idx = static_cast<u32>(r->r_info >> 32);
            if (!sym_idx) continue;
            u64 sym_off = symtab_off + sym_idx * kSymEntSize;
            const u8* symp = safe_ptr(sym_off, kSymEntSize);
            if (!symp) continue;
            auto* sym = reinterpret_cast<const Elf64_Sym*>(symp);
            const char* name = sce_str(sym->st_name);
            if (!name[0]) continue;

            Import imp;
            imp.dll      = "sce_imports";
            imp.name     = name;   // e.g. "ub6vaobIaEY#+#+"
            imp.ordinal  = 0;
            imp.iat_addr = r->r_offset;
            img.imports.push_back(std::move(imp));
        }
    };

    emit_rela(jmprel_off, jmprelsz);
    // also scan DT_SCE_RELA for GLOB_DAT entries (data symbol imports); skip
    // if the table is implausibly large (> 32 MB) to avoid scanning huge reloc sets
    if (rela_off && relasz && relasz <= 0x2000000ULL)
        emit_rela(rela_off, relasz);

    if (!img.imports.empty())
        spdlog::info("elf: PS4 SCE dynlibdata resolved {} imports", img.imports.size());
}

}
