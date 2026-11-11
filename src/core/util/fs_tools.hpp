#pragma once

// host filesystem helpers behind the mcp fs tool
// paths are UTF-8; recursive walks never follow reparse points (junctions,
// symlinks, mount points) and stop as soon as the cancel token fires

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/infra/cancel.hpp"

namespace slop::core::util {

struct file_entry_t {
    std::string name;
    std::string path;
    uint64_t    size = 0;
    bool        directory = false;
    bool        reparse = false;    // junction / symlink / mount point
};

// reads up to max_bytes starting at offset; *total_size (optional) gets the
// file size. a short read is an error, reading at/after EOF yields 0 bytes
bool read_file(const std::string& path, uint64_t offset, std::vector<uint8_t>* out,
               size_t max_bytes, uint64_t* total_size = nullptr,
               std::string* error = nullptr);
bool read_file(const std::string& path, std::vector<uint8_t>* out,
               size_t max_bytes, std::string* error = nullptr);
bool write_file(const std::string& path, const std::vector<uint8_t>& bytes,
                bool append, std::string* error = nullptr);
// error is set (and the partial listing returned) when enumeration fails midway
std::vector<file_entry_t> list_directory(const std::string& dir,
                                         std::string* error = nullptr);
bool create_directory(const std::string& path, std::string* error = nullptr);
bool delete_path(const std::string& path, std::string* error = nullptr);

// Recursive case-insensitive filename substring search under `root`
std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results,
                                       const infra::cancel_token_t& cancel = {});

// Content grep: case-insensitive literal substring match across files under
// root whose name ends with glob_suffix (empty = every file)
struct grep_hit_t {
    std::string path;
    uint32_t    line = 0;
    std::string text;
};
std::vector<grep_hit_t> grep_in_files(const std::string& root,
                                      const std::string& needle,
                                      const std::string& glob_suffix,
                                      size_t max_hits,
                                      const infra::cancel_token_t& cancel = {});

} // namespace slop::core::util
