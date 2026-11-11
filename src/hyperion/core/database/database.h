#pragma once
#include "core/analysis/analysis_db.h"
#include "core/loader/pe_loader.h"
#include <filesystem>
#include <string>

namespace hype {

// .hdb project directory. v2 layout:
//   meta.bin      "HYPEHDB\0", u32 version, u32 caps, u8 arch, u8 format,
//                 u16 0, u64 base, u64 entry
//   names.bin "NAMS", comments.bin "CMTS", funcs.bin "FUNC", xrefs.bin
//   "XREF", types.bin "TYPE" (type defs, then applied types): each file is
//   tag, u32 version, u32 count, then records with u32-length strings
// caps says which section files the save wrote. Load validates magic,
// version, tags, record counts against the bytes present and every length
// before allocating. v1 projects (17-byte meta.bin, untagged sections, u16
// lengths) still load through the same bounds checks
class Database {
public:
    static constexpr u32 kVersion = 2;
    enum Caps : u32 {
        kNames = 1, kComments = 2, kFuncs = 4, kXrefs = 8, kTypes = 16,
        kAll = kNames | kComments | kFuncs | kXrefs | kTypes,
    };

    bool save(const std::filesystem::path& dir, const PEImage& img, const AnalysisDB& db,
              std::string* error = nullptr);
    // Fills `db` with everything the project holds: names, comments,
    // functions (entry + name), xrefs, types and applied types
    bool load(const std::filesystem::path& dir, PEImage& img, AnalysisDB& db,
              std::string* error = nullptr);

    struct MergeStats {
        size_t names = 0, comments = 0, functions = 0, xrefs = 0, types = 0, applied_types = 0;
    };
    // Fold a loaded project into a live analysis: names and comments
    // overwrite, function names apply to functions the live DB knows (others
    // become plain names), missing xrefs are added, types are matched by
    // name (new ones added) and applied types remapped to the live ids
    static MergeStats merge(const AnalysisDB& from, AnalysisDB& into);
};

}
