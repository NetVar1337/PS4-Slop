// src/core/util/zip_writer.cpp

#include "core/util/zip_writer.hpp"

#include <cstdint>
#include <unordered_set>

#include <zlib.h>

namespace slop::core::util::zip {

namespace {

constexpr uint32_t kLocalSig   = 0x04034b50;
constexpr uint32_t kCentralSig = 0x02014b50;
constexpr uint32_t kEocdSig    = 0x06054b50;
constexpr uint16_t kVersion    = 20;   // 2.0: stored + deflate, no zip64
// 2024-01-01 00:00:00 in MS-DOS form; a fixed stamp keeps bundles reproducible
constexpr uint16_t kDosTime = 0;
constexpr uint16_t kDosDate = ((2024 - 1980) << 9) | (1 << 5) | 1;

void put16(std::string& o, uint16_t v) {
    o.push_back(static_cast<char>(v & 0xFF));
    o.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void put32(std::string& o, uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

bool fail(std::string* err, const std::string& msg) {
    if (err) *err = msg;
    return false;
}

} // namespace

bool write_stored(const std::vector<file_t>& files, std::string& out, std::string* err) {
    if (files.size() > 0xFFFF) return fail(err, "zip: too many entries");
    std::unordered_set<std::string> seen;
    std::string central;
    out.clear();

    for (const auto& f : files) {
        if (f.name.empty() || f.name.size() > 0xFFFF)
            return fail(err, "zip: bad entry name");
        if (!seen.insert(f.name).second)
            return fail(err, "zip: duplicate entry '" + f.name + "'");
        if (f.data.size() > 0xFFFFFFFFull)
            return fail(err, "zip: entry '" + f.name + "' is over 4 GiB");

        const auto size = static_cast<uint32_t>(f.data.size());
        uLong crc = ::crc32(0L, Z_NULL, 0);
        crc = ::crc32(crc, reinterpret_cast<const Bytef*>(f.data.data()), size);
        const auto offset = static_cast<uint32_t>(out.size());

        put32(out, kLocalSig);
        put16(out, kVersion);
        put16(out, 0);            // flags
        put16(out, 0);            // method: stored
        put16(out, kDosTime);
        put16(out, kDosDate);
        put32(out, static_cast<uint32_t>(crc));
        put32(out, size);         // compressed == uncompressed
        put32(out, size);
        put16(out, static_cast<uint16_t>(f.name.size()));
        put16(out, 0);            // extra length
        out += f.name;
        out += f.data;

        put32(central, kCentralSig);
        put16(central, kVersion); // version made by
        put16(central, kVersion); // version needed
        put16(central, 0);
        put16(central, 0);
        put16(central, kDosTime);
        put16(central, kDosDate);
        put32(central, static_cast<uint32_t>(crc));
        put32(central, size);
        put32(central, size);
        put16(central, static_cast<uint16_t>(f.name.size()));
        put16(central, 0);        // extra
        put16(central, 0);        // comment
        put16(central, 0);        // disk start
        put16(central, 0);        // internal attrs
        put32(central, 0);        // external attrs
        put32(central, offset);
        central += f.name;
    }

    if (out.size() + central.size() > 0xFFFFFFFFull)
        return fail(err, "zip: archive over 4 GiB");
    const auto cd_offset = static_cast<uint32_t>(out.size());
    out += central;

    put32(out, kEocdSig);
    put16(out, 0);   // this disk
    put16(out, 0);   // central directory disk
    put16(out, static_cast<uint16_t>(files.size()));
    put16(out, static_cast<uint16_t>(files.size()));
    put32(out, static_cast<uint32_t>(central.size()));
    put32(out, cd_offset);
    put16(out, 0);   // comment length
    return true;
}

} // namespace slop::core::util::zip
