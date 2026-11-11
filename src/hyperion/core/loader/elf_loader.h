#pragma once
#include "core/types.h"
#include "pe_loader.h"
#include <filesystem>
#include <optional>
#include <span>

namespace hype {

class ELFLoader {
public:
    static bool is_elf(const u8* data, size_t size);

    // Reads the file and keeps its bytes in PEImage::storage. A file on disk
    // is unrelocated, so relocations are applied at the natural image base
    // unless set_apply_relocations(false) was called
    std::optional<PEImage> load(const std::filesystem::path& path);

    // Borrows `data` (it must outlive the image, as with PELoader). Nothing
    // is copied and nothing is relocated: a memory dump already carries the
    // console's relocations, and a caller that owns a file image applies them
    // in place with apply_relocations() first
    std::optional<PEImage> load_buffer(const u8* data, size_t size);

    void set_apply_relocations(bool on) { apply_relocs_ = on; }

    // Address of the ELF header for the last load: the lowest PT_LOAD's
    // p_vaddr - p_offset when that is a valid page-aligned address, else the
    // image base. Equals PEImage::base unless the headers sit below the first
    // loadable segment (base + 0x1000 starting layouts)
    va_t header_base() const { return header_base_; }

    struct RelocStats {
        size_t applied  = 0;   // slots written
        size_t imported = 0;   // undefined-symbol slots left for the runtime linker
        size_t skipped  = 0;   // unsupported types or slots outside the file bytes
    };
    // Applies R_X86_64_{RELATIVE,64,GLOB_DAT,JUMP_SLOT} and
    // R_AARCH64_{RELATIVE,ABS64,GLOB_DAT,JUMP_SLOT} from PT_DYNAMIC (standard
    // and PS4 PT_SCE_DYNLIBDATA tables) over `file` in place, as if the image
    // were mapped at `load_base` (0 = its natural base). RELA writes are
    // absolute, so applying twice gives the same bytes. ELF64 only
    static RelocStats apply_relocations(std::span<u8> file, va_t load_base = 0);

private:
    struct View;        // bounds-checked, class-normalized header/table reader
    struct DynTables;   // relocation/symbol tables located via PT_DYNAMIC
    View view() const;
    DynTables find_dyn_tables(const View& v) const;

    bool parse_header(PEImage& img);
    bool parse_segments(PEImage& img);
    void parse_sections(PEImage& img);
    void parse_symbols(PEImage& img);
    void parse_dynamic(PEImage& img);
    void parse_sce_dynlibdata(PEImage& img);  // PS4 OELF import/export resolution
    std::optional<PEImage> finish_load(PEImage& img);

    const u8* base_ = nullptr;
    size_t size_ = 0;
    bool is64_ = false;
    bool apply_relocs_ = true;
    u16  machine_ = 0;
    // header fields with extended numbering resolved
    u64  phoff_ = 0, shoff_ = 0;
    u32  phnum_ = 0, shnum_ = 0, shstrndx_ = 0;
    u16  phentsize_ = 0, shentsize_ = 0;
    va_t header_base_ = 0;
};

}
