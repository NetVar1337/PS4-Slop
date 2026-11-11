// src/core/util/fs_tools.cpp

#include "core/util/fs_tools.hpp"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iterator>

namespace slop::core::util {

namespace {

constexpr int kSearchDepth = 8;
constexpr int kGrepDepth   = 6;

std::wstring to_w(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                      nullptr, 0);
    if (n <= 0) return std::wstring(s.begin(), s.end());   // not utf-8, keep bytes
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string to_utf8(const wchar_t* w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string lower_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string win32_error(const char* what) {
    return std::string(what) + " (win32 error " + std::to_string(GetLastError()) + ")";
}

} // namespace

bool read_file(const std::string& path, uint64_t offset, std::vector<uint8_t>* out,
               size_t max_bytes, uint64_t* total_size, std::string* error) {
    out->clear();
    std::ifstream f(to_w(path), std::ios::binary);
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
    std::ofstream f(to_w(path), std::ios::binary |
                                    (append ? std::ios::app : std::ios::trunc));
    if (!f) {
        if (error) *error = "cannot open file for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f) {
        if (error) *error = "write failed (disk full or file locked?)";
        return false;
    }
    return true;
}

std::vector<file_entry_t> list_directory(const std::string& dir,
                                         std::string* error) {
    std::vector<file_entry_t> out;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((to_w(dir) + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = win32_error("cannot list directory");
        return out;
    }
    for (;;) {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            file_entry_t e;
            e.name = to_utf8(fd.cFileName);
            e.path = dir + "\\" + e.name;
            ULARGE_INTEGER sz;
            sz.HighPart = fd.nFileSizeHigh;
            sz.LowPart = fd.nFileSizeLow;
            e.size = sz.QuadPart;
            e.directory = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            e.reparse   = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            out.push_back(std::move(e));
        }
        if (FindNextFileW(h, &fd)) continue;
        if (GetLastError() != ERROR_NO_MORE_FILES && error)
            *error = win32_error("directory enumeration stopped early");
        break;
    }
    FindClose(h);
    return out;
}

bool create_directory(const std::string& path, std::string* error) {
    if (!CreateDirectoryW(to_w(path).c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            if (error) *error = win32_error("create failed");
            return false;
        }
    }
    return true;
}

bool delete_path(const std::string& path, std::string* error) {
    if (DeleteFileW(to_w(path).c_str())) return true;
    if (RemoveDirectoryW(to_w(path).c_str())) return true;
    if (error) *error = win32_error("delete failed");
    return false;
}

std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results,
                                       const infra::cancel_token_t& cancel) {
    std::vector<file_entry_t> out;
    const std::string needle_l = lower_copy(needle);

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (depth > kSearchDepth || out.size() >= max_results || cancel.cancelled()) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_results || cancel.cancelled()) return;
                if (lower_copy(e.name).find(needle_l) != std::string::npos)
                    out.push_back(e);
                // never descend through junctions/symlinks: loops and huge detours
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

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (out.size() >= max_hits || depth > kGrepDepth || cancel.cancelled()) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_hits || cancel.cancelled()) return;
                if (e.directory) {
                    if (!e.reparse) walk(e.path, depth + 1);
                    continue;
                }
                if (!suffix_l.empty() && !lower_copy(e.name).ends_with(suffix_l)) continue;
                std::ifstream f(to_w(e.path), std::ios::binary);
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
