#pragma once
// PS4 SELF (signed ELF) container: a 0x20-byte header, a table of 0x20-byte
// segment entries, then the embedded ELF header and program headers. Every
// loadable program header's bytes live in a "blocked" SELF segment whose id
// (flags >> 20) is the program header index; the segment may be encrypted
// (retail eboot.bin/.sprx, keys never leave the console) and/or deflated.
//
// extract_elf() rebuilds a plain ELF (section headers dropped, they are not
// in a SELF) from a fake-signed/unencrypted SELF, inflating compressed
// segments. An encrypted SELF fails with an error naming the segment and
// pointing at the on-console dump path, since decryption needs the
// console's keys.
#include "core/types.h"
#include <string>
#include <vector>

namespace hype {

struct SelfSegmentInfo {
    u64  flags = 0;
    u64  offset = 0;
    u64  file_size = 0;     // stored (possibly compressed) size
    u64  memory_size = 0;   // plaintext size
    u32  id = 0;            // program header index
    bool blocked = false;
    bool encrypted = false;
    bool compressed = false;
    bool sign = false;
};

struct SelfExtractResult {
    bool                         ok = false;
    std::string                  error;
    std::vector<u8>              elf;          // rebuilt ELF on success
    std::vector<SelfSegmentInfo> segments;     // parsed segment table
    u32                          encrypted_segments = 0;
    u32                          compressed_segments = 0;
    u8                           program_type = 0;
};

class SELFLoader {
public:
    static constexpr u32 kMagic = 0x1D3D154F;   // bytes 4F 15 3D 1D
    static bool is_self(const u8* data, size_t size);
    static SelfExtractResult extract_elf(const u8* data, size_t size);
};

}
