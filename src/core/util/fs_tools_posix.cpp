// src/core/util/fs_tools_posix.cpp
// POSIX twin of fs_tools.cpp: same contract, std::filesystem instead of the
// Win32 file API. Paths are byte strings; symlinks are resolved and never
// followed during walks, matching the Windows reparse-point rule.

#include "core/util/fs_tools.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <system_error>

namespace slop::core::util {

namespace {

namespace fs = std::filesystem;

constexpr int kSearchDepth = 8;
constexpr int kGrepDepth   = 6;

std::string lower_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string err_text(const std::error_code& ec) {
    return ec.message();
}

} // namespace

bool canonical_path(const std::string& path, std::string* out, std::string* error) {
    if (path.empty()) {
        if (error) *error = "empty path";
        return false;
    }
    std::error_code ec;
    // weakly_canonical resolves the existing prefix and appends the rest, so a
    // write target can be judged before it exists
    fs::path p = fs::weakly_canonical(fs::path(path), ec);
    if (ec) {
        if (error) *error = "cannot resolve path: " + err_text(ec);
        return false;
    }
    *out = p.string();
    return true;
}

bool path_within(const std::string& path, const std::string& root) {
    if (root.empty() || path.size() < root.size()) return false;
    if (path.compare(0, root.size(), root) != 0) return false;
    if (path.size() == root.size()) return true;
    return root.back() == '/' || path[root.size()] == '/';
}

bool read_file(const std::string& path, uint64_t offset, std::vector<uint8_t>* out,
               size_t max_bytes, uint64_t* total_size, std::string* error) {
    out->clear();
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (error) *error = "cannot open file";
        return false;
    }
    f.seekg(0, std::ios::end);
    const auto end = f.tellg();
    if (end < 0) {
        if (error) *error = "cannot stat file";
        return false;
    }
    const uint64_t size = static_cast<uint64_t>(end);
    if (total_size) *total_size = size;
    if (offset >= size) return true;
    const size_t len = static_cast<size_t>(std::min<uint64_t>(size - offset, max_bytes));
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    out->resize(len);
    f.read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(len));
    if (static_cast<size_t>(f.gcount()) != len) {
        out->resize(static_cast<size_t>(std::max<std::streamsize>(f.gcount(), 0)));
        if (error) *error = "short read: got " + std::to_string(out->size()) + " of " +
                            std::to_string(len) + " bytes";
        return false;
    }
    return true;
}

bool read_file(const std::string& path, std::vector<uint8_t>* out,
               size_t max_bytes, std::string* error) {
    return read_file(path, 0, out, max_bytes, nullptr, error);
}

bool write_file(const std::string& path, const std::vector<uint8_t>& bytes,
                bool append, std::string* error) {
    std::ofstream f(path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    if (!f) {
        if (error) *error = "cannot open file for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f) {
        if (error) *error = "write failed (disk full?)";
        return false;
    }
    return true;
}

std::vector<file_entry_t> list_directory(const std::string& dir, std::string* error) {
    std::vector<file_entry_t> out;
    std::error_code ec;
    fs::directory_iterator it(fs::path(dir), ec);
    if (ec) {
        if (error) *error = "cannot list directory: " + err_text(ec);
        return out;
    }
    for (const auto& de : it) {
        std::error_code entry_ec;
        const bool is_link = de.is_symlink(entry_ec);
        file_entry_t e;
        e.name = de.path().filename().string();
        e.path = de.path().string();
        e.directory = de.is_directory(entry_ec);
        e.reparse = is_link;
        if (!e.directory) e.size = de.file_size(entry_ec);
        out.push_back(std::move(e));
    }
    return out;
}

bool create_directory(const std::string& path, std::string* error) {
    std::error_code ec;
    fs::create_directories(fs::path(path), ec);
    if (ec) {
        if (error) *error = "create failed: " + err_text(ec);
        return false;
    }
    return true;
}

bool delete_path(const std::string& path, std::string* error) {
    std::error_code ec;
    const bool removed = fs::remove(fs::path(path), ec);
    if (ec || !removed) {
        if (error) *error = "delete failed: " + (ec ? err_text(ec) : "not found");
        return false;
    }
    return true;
}

std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results,
                                       const infra::cancel_token_t& cancel) {
    std::vector<file_entry_t> out;
    const std::string needle_l = lower_copy(needle);

    std::function<void(const std::string&, int)> walk = [&](const std::string& dir, int depth) {
        if (depth > kSearchDepth || out.size() >= max_results || cancel.cancelled()) return;
        for (const auto& e : list_directory(dir)) {
            if (out.size() >= max_results || cancel.cancelled()) return;
            if (lower_copy(e.name).find(needle_l) != std::string::npos) out.push_back(e);
            if (e.directory && !e.reparse) walk(e.path, depth + 1);
        }
    };
    walk(root, 0);
    return out;
}

std::vector<grep_hit_t> grep_in_files(const std::string& root,
                                      const std::string& needle,
                                      const std::string& glob_suffix,
                                      size_t max_hits,
                                      const infra::cancel_token_t& cancel) {
    std::vector<grep_hit_t> out;
    const std::string needle_l = lower_copy(needle);
    const std::string suffix_l = lower_copy(glob_suffix);

    std::function<void(const std::string&, int)> walk = [&](const std::string& dir, int depth) {
        if (out.size() >= max_hits || depth > kGrepDepth || cancel.cancelled()) return;
        for (const auto& e : list_directory(dir)) {
            if (out.size() >= max_hits || cancel.cancelled()) return;
            if (e.directory) {
                if (!e.reparse) walk(e.path, depth + 1);
                continue;
            }
            if (!suffix_l.empty() && !lower_copy(e.name).ends_with(suffix_l)) continue;
            std::ifstream f(e.path, std::ios::binary);
            if (!f) continue;
            std::string line;
            uint32_t lineno = 0;
            while (std::getline(f, line)) {
                ++lineno;
                if ((lineno & 0x3FF) == 0 && cancel.cancelled()) return;
                if (lower_copy(line).find(needle_l) != std::string::npos) {
                    grep_hit_t hit;
                    hit.path = e.path;
                    hit.line = lineno;
                    hit.text = line.substr(0, std::min<size_t>(line.size(), 240));
                    out.push_back(std::move(hit));
                    if (out.size() >= max_hits) return;
                }
            }
        }
    };
    walk(root, 0);
    return out;
}

} // namespace slop::core::util
