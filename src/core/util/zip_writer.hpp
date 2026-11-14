#pragma once

// src/core/util/zip_writer.hpp
// minimal stored (method 0) zip writer: the diagnostics bundle is a handful of
// small text files, so deflating them buys nothing and costs a dependency on
// the compressor's output staying stable

#include <string>
#include <string_view>
#include <vector>

namespace slop::core::util::zip {

struct file_t {
    std::string name;   // '/' separators, no leading slash
    std::string data;
};

// Builds the archive in `out`. False + err on an empty/duplicate name, a name
// over 65535 bytes, or a payload over 4 GiB. Timestamps are fixed so the same
// input always produces the same bytes
bool write_stored(const std::vector<file_t>& files, std::string& out,
                  std::string* err = nullptr);

} // namespace slop::core::util::zip
