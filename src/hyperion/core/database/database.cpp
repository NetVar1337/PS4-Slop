#include "database.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <spdlog/spdlog.h>
#include <tuple>

namespace hype {

namespace fs = std::filesystem;

namespace {

constexpr char   kMagic[8]  = {'H', 'Y', 'P', 'E', 'H', 'D', 'B', '\0'};
constexpr size_t kMetaV2    = 36;
constexpr size_t kMetaV1    = 17;               // u8 arch, u64 base, u64 entry
constexpr u32    kMaxString = 1u << 20;         // names, comments, type names
constexpr u64    kMaxFile   = 4ull << 30;

void set_error(std::string* error, std::string msg) {
    if (error) *error = std::move(msg);
}

class Out {
public:
    explicit Out(const fs::path& p) : f_(p, std::ios::binary | std::ios::trunc) {}
    explicit operator bool() const { return static_cast<bool>(f_); }

    template <class T> void put(T v) { f_.write(reinterpret_cast<const char*>(&v), sizeof(T)); }
    void bytes(const void* p, size_t n) { f_.write(static_cast<const char*>(p), static_cast<std::streamsize>(n)); }
    void str(const std::string& s) {
        const u32 n = static_cast<u32>(std::min<size_t>(s.size(), kMaxString));
        put(n);
        bytes(s.data(), n);
    }
    void header(const char (&tag)[5], u32 count) {
        bytes(tag, 4);
        put(Database::kVersion);
        put(count);
    }
    bool finish() {
        f_.flush();
        return static_cast<bool>(f_);
    }

private:
    std::ofstream f_;
};

// Whole-file reader: every get() is bounds-checked, counts are checked
// against the bytes left before anything is reserved
class In {
public:
    bool open(const fs::path& p, std::string* error) {
        name_ = p.filename().string();
        std::error_code ec;
        const auto size = fs::file_size(p, ec);
        if (ec) return fail(error, "cannot stat");
        if (size > kMaxFile) return fail(error, "file too large");
        std::ifstream f(p, std::ios::binary);
        if (!f) return fail(error, "cannot open");
        buf_.resize(static_cast<size_t>(size));
        if (size && !f.read(reinterpret_cast<char*>(buf_.data()), static_cast<std::streamsize>(size)))
            return fail(error, "read failed");
        return true;
    }

    size_t size() const { return buf_.size(); }
    size_t rem() const { return buf_.size() - p_; }

    template <class T> bool get(T& v) {
        if (rem() < sizeof(T)) return false;
        std::memcpy(&v, buf_.data() + p_, sizeof(T));
        p_ += sizeof(T);
        return true;
    }
    bool str(std::string& s, bool u16_len) {
        u32 n = 0;
        if (u16_len) {
            u16 n16 = 0;
            if (!get(n16)) return false;
            n = n16;
        } else if (!get(n)) {
            return false;
        }
        if (n > kMaxString || n > rem()) return false;
        s.assign(reinterpret_cast<const char*>(buf_.data() + p_), n);
        p_ += n;
        return true;
    }
    // record count, at most what the remaining bytes could hold
    bool count(u32& n, size_t min_record) {
        return get(n) && static_cast<u64>(n) * min_record <= rem();
    }
    // v2 section header; v1 files have none
    bool header(const char (&tag)[5], u32 version, u32& count_out, size_t min_record,
                std::string* error) {
        if (version >= 2) {
            if (rem() < 8) return fail(error, "truncated header");
            if (std::memcmp(buf_.data() + p_, tag, 4) != 0) return fail(error, "bad section tag");
            p_ += 4;
            u32 v = 0;
            if (!get(v) || v != version) return fail(error, "section version mismatch");
        }
        if (!count(count_out, min_record)) return fail(error, "record count exceeds file size");
        return true;
    }
    bool fail(std::string* error, const char* what) {
        set_error(error, name_ + ": " + what);
        return false;
    }

private:
    std::vector<u8> buf_;
    size_t          p_ = 0;
    std::string     name_;
};

std::string bad_record(const char* file, u32 i) {
    return std::string(file) + ": truncated or oversized record " + std::to_string(i);
}

// Types by name: existing definitions win, the rest are added with fresh ids
// and their internal references remapped. Returns old id -> new id
std::unordered_map<u32, u32> import_types(const std::vector<TypeDef>& defs, TypeSystem& into,
                                          size_t* added) {
    std::unordered_map<u32, u32> remap;
    std::vector<u32> fresh;
    for (const auto& td : defs) {
        if (const TypeDef* have = into.find_by_name(td.name); have && have->kind == td.kind) {
            remap[td.id] = have->id;
            continue;
        }
        const u32 id = into.insert(td);
        remap[td.id] = id;
        fresh.push_back(id);
    }
    const auto map_id = [&remap](u32 old) {
        const auto it = remap.find(old);
        return it != remap.end() ? it->second : 0u;
    };
    for (u32 id : fresh) {
        TypeDef* td = into.get(id);
        for (auto& f : td->fields) f.type_id = map_id(f.type_id);
        if (td->pointee_id) td->pointee_id = map_id(td->pointee_id);
        if (td->array_elem_id) td->array_elem_id = map_id(td->array_elem_id);
    }
    if (added) *added = fresh.size();
    return remap;
}

} // namespace

bool Database::save(const fs::path& dir, const PEImage& img, const AnalysisDB& db,
                    std::string* error) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        set_error(error, "cannot create " + dir.string() + ": " + ec.message());
        return false;
    }
    const auto failed = [&](const char* file) {
        set_error(error, std::string("write failed: ") + file);
        return false;
    };

    {
        Out f(dir / "names.bin");
        if (!f) return failed("names.bin");
        f.header("NAMS", static_cast<u32>(db.names.size()));
        for (const auto& [addr, name] : db.names) { f.put(addr); f.str(name); }
        if (!f.finish()) return failed("names.bin");
    }
    {
        Out f(dir / "comments.bin");
        if (!f) return failed("comments.bin");
        f.header("CMTS", static_cast<u32>(db.comments.size()));
        for (const auto& [addr, cmt] : db.comments) { f.put(addr); f.str(cmt); }
        if (!f.finish()) return failed("comments.bin");
    }
    {
        Out f(dir / "funcs.bin");
        if (!f) return failed("funcs.bin");
        f.header("FUNC", static_cast<u32>(db.funcs.size()));
        for (const auto& [entry, func] : db.funcs) { f.put(func.entry); f.str(func.name); }
        if (!f.finish()) return failed("funcs.bin");
    }
    {
        Out f(dir / "xrefs.bin");
        if (!f) return failed("xrefs.bin");
        f.header("XREF", static_cast<u32>(db.xrefs.size()));
        for (const auto& xr : db.xrefs) {
            f.put(xr.from);
            f.put(xr.to);
            f.put(static_cast<u8>(xr.type));
        }
        if (!f.finish()) return failed("xrefs.bin");
    }
    {
        Out f(dir / "types.bin");
        if (!f) return failed("types.bin");
        const auto& all = db.types.all();
        f.header("TYPE", static_cast<u32>(all.size()));
        for (const auto& [id, td] : all) {
            f.put(td.id);
            f.put(static_cast<u8>(td.kind));
            f.str(td.name);
            f.put(td.size);
            f.put(td.pointee_id);
            f.put(td.array_elem_id);
            f.put(td.array_count);
            f.put(static_cast<u32>(td.fields.size()));
            for (const auto& fl : td.fields) {
                f.str(fl.name);
                f.put(fl.type_id);
                f.put(fl.offset);
                f.put(fl.size);
                f.str(fl.comment);
            }
            f.put(static_cast<u32>(td.members.size()));
            for (const auto& m : td.members) {
                f.str(m.name);
                f.put(m.value);
            }
        }
        f.put(static_cast<u32>(db.applied_types.size()));
        for (const auto& [addr, tid] : db.applied_types) {
            f.put(addr);
            f.put(tid);
        }
        if (!f.finish()) return failed("types.bin");
    }
    // meta last: a project dir without it never half-loads
    {
        Out f(dir / "meta.bin");
        if (!f) return failed("meta.bin");
        f.bytes(kMagic, sizeof(kMagic));
        f.put(kVersion);
        f.put(static_cast<u32>(kAll));
        f.put(static_cast<u8>(img.arch));
        f.put(static_cast<u8>(img.format));
        f.put(u16{0});
        f.put(img.base);
        f.put(img.entry);
        if (!f.finish()) return failed("meta.bin");
    }

    spdlog::info("saved project: {}", dir.string());
    return true;
}

bool Database::load(const fs::path& dir, PEImage& img, AnalysisDB& db, std::string* error) {
    if (!fs::exists(dir / "meta.bin")) {
        set_error(error, "not a project directory (no meta.bin): " + dir.string());
        return false;
    }

    u32 version = 1;
    u32 caps = kAll;
    {
        In f;
        if (!f.open(dir / "meta.bin", error)) return false;
        u8 arch = 0, format = 0;
        if (f.size() == kMetaV2) {
            char magic[8] = {};
            for (char& c : magic) f.get(c);
            if (std::memcmp(magic, kMagic, sizeof(kMagic)) != 0)
                return f.fail(error, "bad magic (not a .hdb project)");
            f.get(version);
            if (version != kVersion) {
                set_error(error, "meta.bin: unsupported project version " + std::to_string(version));
                return false;
            }
            u16 reserved = 0;
            f.get(caps);
            f.get(arch);
            f.get(format);
            f.get(reserved);
            if (caps & ~static_cast<u32>(kAll)) return f.fail(error, "unknown capability bits");
            if (format > static_cast<u8>(ImageFormat::MachO)) return f.fail(error, "bad image format");
        } else if (f.size() == kMetaV1) {
            f.get(arch);   // legacy project: no magic, every section present
        } else {
            return f.fail(error, "unrecognized header size");
        }
        if (arch > static_cast<u8>(Arch::PPC)) return f.fail(error, "bad arch");
        f.get(img.base);
        f.get(img.entry);
        img.arch = static_cast<Arch>(arch);
        img.format = static_cast<ImageFormat>(format);
        db.arch = img.arch;
        db.image_base = img.base;
    }
    const bool v1 = version == 1;

    // name/comment style maps: u64 addr + string
    const auto load_strings = [&](const char* file, const char (&tag)[5], u32 cap,
                                  std::unordered_map<va_t, std::string>& out) {
        if (!(caps & cap)) return true;
        In f;
        if (!f.open(dir / file, error)) return false;
        u32 n = 0;
        if (!f.header(tag, version, n, v1 ? 10 : 12, error)) return false;
        for (u32 i = 0; i < n; ++i) {
            va_t addr = 0;
            std::string s;
            if (!f.get(addr) || !f.str(s, v1)) {
                set_error(error, bad_record(file, i));
                return false;
            }
            out[addr] = std::move(s);
        }
        return true;
    };
    if (!load_strings("names.bin", "NAMS", kNames, db.names)) return false;
    if (!load_strings("comments.bin", "CMTS", kComments, db.comments)) return false;

    if (caps & kFuncs) {
        In f;
        if (!f.open(dir / "funcs.bin", error)) return false;
        u32 n = 0;
        if (!f.header("FUNC", version, n, v1 ? 10 : 12, error)) return false;
        for (u32 i = 0; i < n; ++i) {
            Function fn{};
            if (!f.get(fn.entry) || !f.str(fn.name, v1)) {
                set_error(error, bad_record("funcs.bin", i));
                return false;
            }
            const va_t entry = fn.entry;
            db.funcs[entry] = std::move(fn);
        }
    }

    if (caps & kXrefs) {
        In f;
        if (!f.open(dir / "xrefs.bin", error)) return false;
        u32 n = 0;
        if (!f.header("XREF", version, n, 17, error)) return false;
        db.xrefs.reserve(n);
        for (u32 i = 0; i < n; ++i) {
            Xref x{};
            u8 type = 0;
            if (!f.get(x.from) || !f.get(x.to) || !f.get(type) ||
                type > static_cast<u8>(XrefType::DataOffset)) {
                set_error(error, bad_record("xrefs.bin", i));
                return false;
            }
            x.type = static_cast<XrefType>(type);
            db.add_xref_unlocked(x);
        }
    }

    if (caps & kTypes) {
        In f;
        if (!f.open(dir / "types.bin", error)) return false;
        u32 n = 0;
        // smallest def: id, kind, empty name, size (+3 refs in v2), 2 counts
        if (!f.header("TYPE", version, n, v1 ? 19 : 33, error)) return false;
        std::vector<TypeDef> defs;
        defs.reserve(n);
        for (u32 i = 0; i < n; ++i) {
            TypeDef td{};
            u8 kind = 0;
            bool ok = f.get(td.id) && f.get(kind) && kind <= static_cast<u8>(TypeKind::Typedef) &&
                      f.str(td.name, v1) && f.get(td.size);
            if (ok && !v1) ok = f.get(td.pointee_id) && f.get(td.array_elem_id) && f.get(td.array_count);
            u32 fc = 0;
            ok = ok && f.count(fc, v1 ? 14 : 20);
            for (u32 j = 0; ok && j < fc; ++j) {
                TypeField fl{};
                ok = f.str(fl.name, v1) && f.get(fl.type_id) && f.get(fl.offset) && f.get(fl.size);
                if (ok && !v1) ok = f.str(fl.comment, false);
                if (ok) td.fields.push_back(std::move(fl));
            }
            u32 mc = 0;
            ok = ok && f.count(mc, v1 ? 10 : 12);
            for (u32 j = 0; ok && j < mc; ++j) {
                EnumMember m{};
                ok = f.str(m.name, v1) && f.get(m.value);
                if (ok) td.members.push_back(std::move(m));
            }
            if (!ok) {
                set_error(error, bad_record("types.bin", i));
                return false;
            }
            td.kind = static_cast<TypeKind>(kind);
            defs.push_back(std::move(td));
        }
        const auto remap = import_types(defs, db.types, nullptr);
        u32 atc = 0;
        if (!f.count(atc, 12)) {
            set_error(error, "types.bin: applied type count exceeds file size");
            return false;
        }
        for (u32 i = 0; i < atc; ++i) {
            va_t addr = 0;
            u32 tid = 0;
            if (!f.get(addr) || !f.get(tid)) {
                set_error(error, bad_record("types.bin applied", i));
                return false;
            }
            const auto it = remap.find(tid);
            if (it != remap.end()) db.applied_types[addr] = it->second;
        }
    }

    spdlog::info("loaded project: {} (v{})", dir.string(), version);
    return true;
}

Database::MergeStats Database::merge(const AnalysisDB& from, AnalysisDB& into) {
    MergeStats st;
    for (const auto& [va, n] : from.names) {
        into.names[va] = n;
        ++st.names;
    }
    for (const auto& [va, c] : from.comments) {
        into.comments[va] = c;
        ++st.comments;
    }
    for (const auto& [entry, fn] : from.funcs) {
        // an unnamed function's sub_<va> carries nothing to merge
        if (fn.name.empty() || fn.name.rfind("sub_", 0) == 0) continue;
        auto live = into.funcs.find(entry);
        if (live != into.funcs.end()) live->second.name = fn.name;
        into.names[entry] = fn.name;
        ++st.functions;
    }
    {
        std::set<std::tuple<va_t, va_t, u8>> have;
        for (const auto& x : into.xrefs) have.emplace(x.from, x.to, static_cast<u8>(x.type));
        for (const auto& x : from.xrefs) {
            if (!have.emplace(x.from, x.to, static_cast<u8>(x.type)).second) continue;
            into.add_xref(x);
            ++st.xrefs;
        }
    }
    {
        std::vector<TypeDef> defs;
        defs.reserve(from.types.all().size());
        for (const auto& [id, td] : from.types.all()) defs.push_back(td);
        const auto remap = import_types(defs, into.types, &st.types);
        for (const auto& [addr, tid] : from.applied_types) {
            const auto it = remap.find(tid);
            if (it == remap.end()) continue;
            into.applied_types[addr] = it->second;
            ++st.applied_types;
        }
    }
    return st;
}

}
