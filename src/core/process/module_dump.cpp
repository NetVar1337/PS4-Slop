#include "core/process/module_dump.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <system_error>

namespace slop::core::process {

namespace {

constexpr size_t kMaxHeaderBytes = 4u * 1024u * 1024u;
constexpr size_t kMaxOutputBytes = 512u * 1024u * 1024u;
constexpr uint16_t kMaxSections = 256;

bool add_fits(size_t a, size_t b, size_t limit, size_t& sum) {
    if (a > limit || b > limit - a) return false;
    sum = a + b;
    return true;
}

bool read_exact(const module_read_fn_t& read, uintptr_t address, void* dst,
                size_t size, size_t chunk_size) {
    auto* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    const size_t chunk = std::max<size_t>(chunk_size, 4096);
    while (done < size) {
        const size_t take = std::min(chunk, size - done);
        const auto io = read(address + done, out + done, take);
        if (!io.ok || io.bytes != take) return false;
        done += take;
    }
    return true;
}

bool write_atomic(const std::string& output_path,
                  const std::vector<uint8_t>& data, std::string& error) {
    const std::filesystem::path final_path{output_path};
    if (final_path.empty()) {
        error = "output path is empty";
        return false;
    }

    const auto temporary = final_path.wstring() + L".slop-tmp-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY |
                              FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "failed to create temporary dump file (error " +
                std::to_string(GetLastError()) + ")";
        return false;
    }

    bool ok = true;
    size_t written_total = 0;
    while (written_total < data.size()) {
        const DWORD take = static_cast<DWORD>(std::min<size_t>(
            data.size() - written_total, 1u * 1024u * 1024u));
        DWORD written = 0;
        if (!WriteFile(file, data.data() + written_total, take, &written,
                       nullptr) || written != take) {
            ok = false;
            break;
        }
        written_total += written;
    }
    if (ok) ok = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);

    if (ok) {
        ok = MoveFileExW(temporary.c_str(), final_path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (!ok) {
        const DWORD code = GetLastError();
        DeleteFileW(temporary.c_str());
        error = "failed to write dump file (error " + std::to_string(code) + ")";
    }
    return ok;
}

} // namespace

module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base, uint32_t module_size, const module_read_fn_t& read,
    std::vector<uint8_t>& output, const module_dump_options_t& options) {
    module_dump_result_t result;
    result.module_base = module_base;
    output.clear();

    if (module_base == 0 || module_size < sizeof(IMAGE_DOS_HEADER) || !read) {
        result.error = "invalid module range or reader";
        return result;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read_exact(read, module_base, &dos, sizeof(dos), options.chunk_size)) {
        result.error = "failed to read DOS header";
        return result;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        static_cast<size_t>(dos.e_lfanew) > kMaxHeaderBytes) {
        result.error = "module does not contain a valid DOS header";
        return result;
    }

    const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
    size_t coff_end = 0;
    if (!add_fits(nt_offset, sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER),
                  kMaxHeaderBytes, coff_end)) {
        result.error = "PE header offset is out of range";
        return result;
    }
    std::vector<uint8_t> prefix(coff_end);
    if (!read_exact(read, module_base, prefix.data(), prefix.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE header";
        return result;
    }
    uint32_t signature = 0;
    IMAGE_FILE_HEADER file_header{};
    std::memcpy(&signature, prefix.data() + nt_offset, sizeof(signature));
    std::memcpy(&file_header, prefix.data() + nt_offset + sizeof(signature),
                sizeof(file_header));
    if (signature != IMAGE_NT_SIGNATURE || file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > kMaxSections) {
        result.error = "module does not contain a valid PE header";
        return result;
    }
    if (file_header.SizeOfOptionalHeader < sizeof(uint16_t)) {
        result.error = "PE optional header is truncated";
        return result;
    }

    size_t optional_offset = coff_end;
    size_t section_table = 0;
    size_t section_table_end = 0;
    if (!add_fits(optional_offset, file_header.SizeOfOptionalHeader,
                  kMaxHeaderBytes, section_table) ||
        !add_fits(section_table,
                  static_cast<size_t>(file_header.NumberOfSections) *
                      sizeof(IMAGE_SECTION_HEADER),
                  kMaxHeaderBytes, section_table_end)) {
        result.error = "PE section table is out of range";
        return result;
    }

    std::vector<uint8_t> tables(section_table_end);
    if (!read_exact(read, module_base, tables.data(), tables.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE section table";
        return result;
    }

    uint16_t optional_magic = 0;
    std::memcpy(&optional_magic, tables.data() + optional_offset,
                sizeof(optional_magic));
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            result.error = "PE32+ optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            result.error = "PE32 optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER32 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
    } else {
        result.error = "unsupported PE optional-header magic";
        return result;
    }

    if (size_of_image == 0 || size_of_headers < section_table_end ||
        size_of_headers > kMaxHeaderBytes) {
        result.error = "PE image/header sizes are invalid";
        return result;
    }
    if (module_size < size_of_image) {
        result.warnings.push_back("enumerated module size is smaller than SizeOfImage");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    std::memcpy(sections.data(), tables.data() + section_table,
                sections.size() * sizeof(IMAGE_SECTION_HEADER));

    size_t output_size = size_of_headers;
    for (const auto& section : sections) {
        size_t end = 0;
        if (!add_fits(section.PointerToRawData, section.SizeOfRawData,
                      kMaxOutputBytes, end)) {
            result.error = "PE section raw range is out of bounds";
            return result;
        }
        output_size = std::max(output_size, end);
    }
    if (output_size < 1024 || output_size > kMaxOutputBytes) {
        result.error = "reconstructed PE size is invalid";
        return result;
    }

    output.assign(output_size, 0);
    if (!read_exact(read, module_base, output.data(), size_of_headers,
                    options.chunk_size)) {
        result.error = "failed to read complete PE headers";
        output.clear();
        return result;
    }

    bool complete = true;
    for (const auto& section : sections) {
        if (section.SizeOfRawData == 0) continue;

        const uint64_t section_end = static_cast<uint64_t>(section.VirtualAddress) +
                                     section.SizeOfRawData;
        size_t readable = section.SizeOfRawData;
        if (section.VirtualAddress >= size_of_image) {
            readable = 0;
        } else if (section_end > size_of_image) {
            readable = size_of_image - section.VirtualAddress;
        }

        if (readable != 0 && !read_exact(
                read, module_base + section.VirtualAddress,
                output.data() + section.PointerToRawData, readable,
                options.chunk_size)) {
            if (options.strict_reads) {
                result.error = "failed to read section " +
                    std::string(reinterpret_cast<const char*>(section.Name),
                                strnlen(reinterpret_cast<const char*>(section.Name), 8));
                output.clear();
                return result;
            }
            std::fill_n(output.data() + section.PointerToRawData, readable, 0);
            complete = false;
        }
        if (readable < section.SizeOfRawData) {
            complete = false;
            result.warnings.push_back("section data extends beyond SizeOfImage and was zero-filled");
        }
    }

    const auto parsed = disasm::pe_parse(output.data(), output.size());
    if (!parsed.ok || parsed.sections.size() != sections.size()) {
        result.error = "reconstructed image failed PE validation";
        output.clear();
        return result;
    }

    result.ok = true;
    result.complete = complete;
    result.bytes_written = output.size();
    result.section_count = sections.size();
    return result;
}

module_dump_result_t dump_module_pe(
    runtime::session_t& session, const runtime::module_info_t& module,
    const std::string& output_path, const module_dump_options_t& options) {
    std::vector<uint8_t> image;
    auto result = reconstruct_mapped_pe(
        module.base, module.size,
        [&session](uintptr_t address, void* destination, size_t size) {
            return session.read(address, destination, size);
        },
        image, options);
    result.output_path = output_path;
    if (!result.ok) return result;

    if (!write_atomic(output_path, image, result.error)) {
        result.ok = false;
        result.bytes_written = 0;
        return result;
    }
    return result;
}

namespace {

constexpr uint64_t kElfPage = 0x4000;   // PS4 page size; also a multiple of 4 KiB

#pragma pack(push, 1)
struct elf64_ehdr_t {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
struct elf64_phdr_t {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)
static_assert(sizeof(elf64_ehdr_t) == 64);
static_assert(sizeof(elf64_phdr_t) == 56);

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

// copy [start, end) through read into dst; unreadable chunks zero-fill (non
// strict) or fail. Returns false only on a strict failure
bool read_segment(const module_read_fn_t& read, uint64_t start, uint64_t end, uint8_t* dst,
                  const module_dump_options_t& options, module_dump_result_t& result) {
    const size_t chunk = std::max<size_t>(options.chunk_size, 4096);
    uint64_t failed_from = 0, failed_bytes = 0;
    auto flush_warning = [&] {
        if (!failed_bytes) return;
        char b[96];
        std::snprintf(b, sizeof(b), "unreadable 0x%llX..0x%llX zero-filled",
                      static_cast<unsigned long long>(failed_from),
                      static_cast<unsigned long long>(failed_from + failed_bytes));
        result.warnings.emplace_back(b);
        failed_bytes = 0;
    };
    for (uint64_t a = start; a < end;) {
        const size_t take = static_cast<size_t>(std::min<uint64_t>(chunk, end - a));
        uint8_t* out = dst + (a - start);
        const auto io = read(static_cast<uintptr_t>(a), out, take);
        if (!io.ok || io.bytes != take) {
            if (options.strict_reads) {
                char b[96];
                std::snprintf(b, sizeof(b), "read failed at 0x%llX (%zu bytes)",
                              static_cast<unsigned long long>(a), take);
                result.error = b;
                return false;
            }
            std::memset(out, 0, take);
            result.complete = false;
            if (!failed_bytes) failed_from = a;
            failed_bytes += take;
        } else {
            flush_warning();
        }
        a += take;
    }
    flush_warning();
    return true;
}

bool validate_segments(const std::vector<mapped_segment_t>& segs, std::string& error) {
    if (segs.empty()) { error = "no segments to dump"; return false; }
    uint64_t total = 0;
    for (size_t i = 0; i < segs.size(); ++i) {
        const auto& s = segs[i];
        if (s.end <= s.start) { error = "empty or inverted segment"; return false; }
        if (i > 0 && s.start < segs[i - 1].end) { error = "segments overlap or are unsorted"; return false; }
        total += s.end - s.start;
        if (total > kMaxOutputBytes) { error = "module larger than the dump cap (512 MiB)"; return false; }
    }
    return true;
}

} // namespace

module_dump_result_t reconstruct_elf_from_segments(
    const std::vector<mapped_segment_t>& segments, const module_read_fn_t& read,
    std::vector<uint8_t>& output, const module_dump_options_t& options,
    elf_rebuild_info_t* info) {
    module_dump_result_t result;
    output.clear();
    elf_rebuild_info_t meta;
    if (!validate_segments(segments, result.error)) return result;
    if (segments.size() >= 0xFFFF) {
        result.error = "too many segments for one ELF program header table";
        return result;
    }
    const uint64_t base = segments.front().start;
    const uint64_t end  = segments.back().end;
    result.module_base = base;
    result.complete = true;

    // layout: ehdr, phdrs, then every segment at a page-aligned offset whose
    // residue matches its vaddr (p_offset % p_align == p_vaddr % p_align)
    const size_t n = segments.size();
    uint64_t off = align_up(sizeof(elf64_ehdr_t) + n * sizeof(elf64_phdr_t), kElfPage);
    std::vector<uint64_t> offsets(n);
    for (size_t i = 0; i < n; ++i) {
        off += (segments[i].start - off) & (kElfPage - 1);   // match the residue
        offsets[i] = off;
        off += segments[i].end - segments[i].start;
    }
    if (off > kMaxOutputBytes) {
        result.error = "reconstructed ELF larger than the dump cap (512 MiB)";
        return result;
    }
    output.assign(static_cast<size_t>(off), 0);

    for (size_t i = 0; i < n; ++i) {
        if (!read_segment(read, segments[i].start, segments[i].end,
                          output.data() + offsets[i], options, result)) {
            output.clear();
            result.complete = false;
            return result;
        }
    }

    // an in-memory ELF header (rare on PS4: the SELF loader maps only the
    // segments) tells us the entry point and the original type
    const uint8_t* first = output.data() + offsets[0];
    const uint64_t first_len = segments[0].end - segments[0].start;
    if (first_len >= sizeof(elf64_ehdr_t) && std::memcmp(first, "\x7f" "ELF", 4) == 0 &&
        first[4] == 2 /*ELFCLASS64*/) {
        elf64_ehdr_t src{};
        std::memcpy(&src, first, sizeof(src));
        meta.had_header = true;
        meta.source_type = src.e_type;
        const uint64_t span = end - base;
        if (src.e_entry >= base && src.e_entry < end) meta.entry = src.e_entry;          // absolute
        else if (src.e_entry != 0 && src.e_entry < span) meta.entry = base + src.e_entry; // PIE-relative
    }

    elf64_ehdr_t eh{};
    const uint8_t ident[16] = {0x7F, 'E', 'L', 'F', 2 /*64-bit*/, 1 /*LE*/, 1 /*version*/,
                               9 /*FreeBSD*/, 0, 0, 0, 0, 0, 0, 0, 0};
    std::memcpy(eh.e_ident, ident, sizeof(ident));
    eh.e_type      = 2;      // ET_EXEC: p_vaddr are the runtime addresses
    eh.e_machine   = 62;     // EM_X86_64
    eh.e_version   = 1;
    eh.e_entry     = meta.entry;
    eh.e_phoff     = sizeof(elf64_ehdr_t);
    eh.e_shoff     = 0;
    eh.e_ehsize    = sizeof(elf64_ehdr_t);
    eh.e_phentsize = sizeof(elf64_phdr_t);
    eh.e_phnum     = static_cast<uint16_t>(n);
    eh.e_shentsize = 64;
    eh.e_shnum     = 0;
    eh.e_shstrndx  = 0;
    std::memcpy(output.data(), &eh, sizeof(eh));
    for (size_t i = 0; i < n; ++i) {
        const auto& s = segments[i];
        elf64_phdr_t ph{};
        ph.p_type   = 1;   // PT_LOAD
        ph.p_flags  = ((s.prot & 1) ? 4u : 0u) | ((s.prot & 2) ? 2u : 0u) | ((s.prot & 4) ? 1u : 0u);
        ph.p_offset = offsets[i];
        ph.p_vaddr  = s.start;
        ph.p_paddr  = s.start;
        ph.p_filesz = s.end - s.start;
        ph.p_memsz  = s.end - s.start;
        ph.p_align  = kElfPage;
        std::memcpy(output.data() + sizeof(eh) + i * sizeof(ph), &ph, sizeof(ph));
    }
    meta.segments = n;
    result.ok = true;
    result.bytes_written = output.size();
    result.section_count = n;
    if (!meta.had_header)
        result.warnings.emplace_back("no ELF header in memory: rebuilt one from the console maps "
                                     "(entry unknown, no section headers/symbols)");
    if (info) *info = meta;
    return result;
}

module_dump_result_t dump_raw_span(const std::vector<mapped_segment_t>& segments,
                                   const module_read_fn_t& read, std::vector<uint8_t>& output,
                                   const module_dump_options_t& options) {
    module_dump_result_t result;
    output.clear();
    if (!validate_segments(segments, result.error)) return result;
    const uint64_t base = segments.front().start;
    const uint64_t span = segments.back().end - base;
    if (span > kMaxOutputBytes) {
        result.error = "module span larger than the dump cap (512 MiB)";
        return result;
    }
    result.module_base = base;
    result.complete = true;
    output.assign(static_cast<size_t>(span), 0);   // gaps stay zero
    for (const auto& s : segments) {
        if (!read_segment(read, s.start, s.end, output.data() + (s.start - base), options, result)) {
            output.clear();
            result.complete = false;
            return result;
        }
    }
    result.ok = true;
    result.bytes_written = output.size();
    result.section_count = segments.size();
    return result;
}

bool write_dump_file(const std::string& output_path, const std::vector<uint8_t>& data,
                     std::string& error) {
    return write_atomic(output_path, data, error);
}

} // namespace slop::core::process
