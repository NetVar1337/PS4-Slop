#include "self_loader.h"

#include <fmt/format.h>
#include <zlib.h>

#include <algorithm>
#include <cstring>

namespace hype {

namespace {

constexpr size_t kHeaderSize  = 0x20;
constexpr size_t kSegmentSize = 0x20;
constexpr size_t kEhdrSize    = 64;
constexpr size_t kPhdrSize    = 56;

constexpr u64 SF_ENCR = 0x2;
constexpr u64 SF_SIGN = 0x4;
constexpr u64 SF_DFLG = 0x8;
constexpr u64 SF_BFLG = 0x800;

constexpr u32 PT_LOAD           = 1;
constexpr u32 PT_DYNAMIC        = 2;
constexpr u32 PT_SCE_DYNLIBDATA = 0x61000000;
constexpr u32 PT_SCE_RELRO      = 0x61000010;

template <class T>
T rd(const u8* p) {
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

bool needs_bytes(u32 type) {
    return type == PT_LOAD || type == PT_SCE_RELRO || type == PT_DYNAMIC ||
           type == PT_SCE_DYNLIBDATA;
}

} // namespace

bool SELFLoader::is_self(const u8* data, size_t size) {
    return size >= 4 && rd<u32>(data) == kMagic;
}

SelfExtractResult SELFLoader::extract_elf(const u8* data, size_t size) {
    SelfExtractResult r;
    const auto fail = [&](std::string why) {
        r.ok = false;
        r.error = "self: " + std::move(why);
        r.elf.clear();
        return r;
    };

    if (!is_self(data, size)) return fail("not a SELF (bad magic)");
    if (size < kHeaderSize) return fail("truncated header");
    // version 0, mode 1, little endian (1)
    if (data[4] != 0 || data[6] != 1)
        return fail(fmt::format("unsupported SELF version {} / endian {}", data[4], data[6]));
    r.program_type = data[9];
    const u16 seg_count = rd<u16>(data + 0x18);
    const size_t table_end = kHeaderSize + size_t{seg_count} * kSegmentSize;
    if (table_end + kEhdrSize > size) return fail("truncated segment table");

    for (u16 i = 0; i < seg_count; ++i) {
        const u8* p = data + kHeaderSize + size_t{i} * kSegmentSize;
        SelfSegmentInfo s;
        s.flags       = rd<u64>(p);
        s.offset      = rd<u64>(p + 8);
        s.file_size   = rd<u64>(p + 16);
        s.memory_size = rd<u64>(p + 24);
        s.id          = static_cast<u32>((s.flags >> 20) & 0xFFF);
        s.blocked     = (s.flags & SF_BFLG) != 0;
        s.encrypted   = (s.flags & SF_ENCR) != 0;
        s.compressed  = (s.flags & SF_DFLG) != 0;
        s.sign        = (s.flags & SF_SIGN) != 0;
        if (s.blocked && s.encrypted) ++r.encrypted_segments;
        if (s.blocked && s.compressed) ++r.compressed_segments;
        r.segments.push_back(s);
    }

    // embedded ELF header + program headers
    const u8* eh = data + table_end;
    if (rd<u32>(eh) != 0x464C457F) return fail("no ELF header after the segment table");
    if (eh[4] != 2 || eh[5] != 1) return fail("embedded ELF is not ELF64 little-endian");
    const u64 phoff     = rd<u64>(eh + 0x20);
    const u16 phentsize = rd<u16>(eh + 0x36);
    const u16 phnum     = rd<u16>(eh + 0x38);
    if (phentsize != kPhdrSize) return fail(fmt::format("unexpected e_phentsize {}", phentsize));
    if (phnum == 0 || phnum == 0xFFFF) return fail("embedded ELF has no program headers");
    const size_t phdrs_in_self = table_end + static_cast<size_t>(phoff);
    if (phoff > size || phdrs_in_self + size_t{phnum} * kPhdrSize > size)
        return fail("truncated program header table");

    if (r.encrypted_segments) {
        const auto enc = std::find_if(r.segments.begin(), r.segments.end(),
            [](const SelfSegmentInfo& s) { return s.blocked && s.encrypted; });
        return fail(fmt::format(
            "encrypted SELF: {} of {} data segments are encrypted (first: SELF "
            "segment {} = program header {}). Retail eboot.bin/.sprx files are "
            "decrypted only on the console; run the title on a PS4 with the "
            "ps4debug payload and call target.ps4_dump_module {{name, load:true}} "
            "(or dump the decrypted ELF with a homebrew dumper) and load that "
            "file instead",
            r.encrypted_segments,
            std::count_if(r.segments.begin(), r.segments.end(),
                          [](const SelfSegmentInfo& s) { return s.blocked; }),
            enc - r.segments.begin(), enc->id));
    }

    // output layout: ELF header + phdrs at their file offsets, each
    // program header's bytes at its p_offset
    struct Ph { u32 type; u64 offset; u64 filesz; };
    std::vector<Ph> phs(phnum);
    u64 out_size = std::max<u64>(kEhdrSize, phoff + u64{phnum} * kPhdrSize);
    for (u16 i = 0; i < phnum; ++i) {
        const u8* ph = data + phdrs_in_self + size_t{i} * kPhdrSize;
        phs[i] = {rd<u32>(ph), rd<u64>(ph + 0x08), rd<u64>(ph + 0x20)};
        if (phs[i].filesz == 0) continue;
        if (phs[i].offset > (u64{1} << 34) || phs[i].filesz > (u64{1} << 34))
            return fail(fmt::format("program header {} has an implausible extent", i));
        out_size = std::max(out_size, phs[i].offset + phs[i].filesz);
    }
    // Match the PE/Mach-O loader cap. 16 GiB let a ~200-byte hostile SELF
    // force a single huge zero-fill allocation.
    if (out_size > (u64{1} << 31)) return fail("rebuilt ELF would exceed 2 GiB");

    r.elf.assign(static_cast<size_t>(out_size), 0);
    std::memcpy(r.elf.data(), eh, kEhdrSize);
    // no section headers survive in a SELF
    std::memset(r.elf.data() + 0x28, 0, 8);    // e_shoff
    std::memset(r.elf.data() + 0x3C, 0, 4);    // e_shnum, e_shstrndx
    std::memcpy(r.elf.data() + phoff, data + phdrs_in_self, size_t{phnum} * kPhdrSize);

    for (u16 i = 0; i < phnum; ++i) {
        const Ph& ph = phs[i];
        if (ph.filesz == 0) continue;
        const auto seg = std::find_if(r.segments.begin(), r.segments.end(),
            [i](const SelfSegmentInfo& s) { return s.blocked && s.id == i; });
        if (seg == r.segments.end()) {
            if (needs_bytes(ph.type))
                return fail(fmt::format("no SELF segment carries program header {} "
                                        "(type 0x{:X})", i, ph.type));
            continue;   // version/comment segments live outside the blocks
        }
        if (seg->offset > size || seg->file_size > size - seg->offset)
            return fail(fmt::format("SELF segment for program header {} runs past the file", i));
        u8* dst = r.elf.data() + ph.offset;
        const u8* src = data + seg->offset;
        if (seg->compressed) {
            uLongf out_len = static_cast<uLongf>(ph.filesz);
            const int zr = uncompress(dst, &out_len, src, static_cast<uLong>(seg->file_size));
            if (zr != Z_OK)
                return fail(fmt::format("inflating program header {} failed (zlib {})", i, zr));
        } else {
            std::memcpy(dst, src, static_cast<size_t>(std::min(seg->file_size, ph.filesz)));
        }
    }

    r.ok = true;
    return r;
}

}
