#include "itanium_rtti.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace hype {

namespace {

constexpr size_t kMaxNameLen = 1024;
constexpr int    kMaxDepth   = 64;

std::string join(const std::vector<std::string>& parts) {
    std::string out;
    for (const auto& p : parts) {
        if (p.empty()) continue;
        if (!out.empty()) out += ", ";
        out += p;
    }
    return out;
}

// The <type> subset type_info names use: class/enum names (nested, std::,
// template, anonymous namespace, unnamed types and lambdas, abi tags) and,
// inside template arguments, builtins, cv/pointer/reference/array/function/
// member-pointer types, literals, packs and substitutions
class Demangler {
public:
    explicit Demangler(std::string_view s) : s_(s) {}

    std::optional<std::string> class_type() {
        const char c = peek();
        if (!(c == 'N' || c == 'S' || is_digit(c))) return std::nullopt;
        auto t = type();
        if (!t || p_ != s_.size()) return std::nullopt;
        return t;
    }

private:
    std::string_view         s_;
    size_t                   p_ = 0;
    int                      depth_ = 0;
    std::vector<std::string> subs_;

    struct depth_guard {
        int& d;
        ~depth_guard() { --d; }
    };

    char peek(size_t k = 0) const { return p_ + k < s_.size() ? s_[p_ + k] : '\0'; }
    bool eof() const { return p_ >= s_.size(); }
    bool eat(char c) {
        if (peek() != c) return false;
        ++p_;
        return true;
    }
    static bool is_digit(char c) { return c >= '0' && c <= '9'; }

    bool number(size_t& n) {
        if (!is_digit(peek())) return false;
        n = 0;
        while (is_digit(peek())) {
            n = n * 10 + static_cast<size_t>(s_[p_++] - '0');
            if (n > kMaxNameLen) return false;
        }
        return true;
    }

    // [<number>] _  ->  1 for "_", n + 2 for "<n>_"
    std::optional<size_t> discriminator() {
        size_t idx = 1;
        if (is_digit(peek())) {
            size_t n = 0;
            if (!number(n)) return std::nullopt;
            idx = n + 2;
        }
        if (!eat('_')) return std::nullopt;
        return idx;
    }

    std::optional<std::string> source_name() {
        size_t n = 0;
        if (!number(n) || n == 0 || p_ + n > s_.size()) return std::nullopt;
        const std::string_view id = s_.substr(p_, n);
        p_ += n;
        if (id.rfind("_GLOBAL__N", 0) == 0) return std::string("(anonymous namespace)");
        if (is_digit(id[0])) return std::nullopt;
        for (char c : id)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '.'))
                return std::nullopt;
        return std::string(id);
    }

    bool abi_tags(std::string& name) {
        while (peek() == 'B') {
            ++p_;
            auto tag = source_name();
            if (!tag) return false;
            name += "[abi:" + *tag + "]";
        }
        return true;
    }

    std::optional<std::string> unqualified_name() {
        if (is_digit(peek())) return source_name();
        if (peek() == 'U' && peek(1) == 't') {
            p_ += 2;
            auto idx = discriminator();
            if (!idx) return std::nullopt;
            return "{unnamed type#" + std::to_string(*idx) + "}";
        }
        if (peek() == 'U' && peek(1) == 'l') {
            p_ += 2;
            std::vector<std::string> params;
            while (!eof() && peek() != 'E') {
                auto t = type();
                if (!t) return std::nullopt;
                params.push_back(*t);
            }
            if (!eat('E')) return std::nullopt;
            auto idx = discriminator();
            if (!idx) return std::nullopt;
            if (params.size() == 1 && params[0] == "void") params.clear();
            return "{lambda(" + join(params) + ")#" + std::to_string(*idx) + "}";
        }
        return std::nullopt;
    }

    // at 'S', not "St"
    std::optional<std::string> substitution() {
        if (!eat('S')) return std::nullopt;
        switch (peek()) {
        case 'a': ++p_; return std::string("std::allocator");
        case 'b': ++p_; return std::string("std::basic_string");
        case 's': ++p_; return std::string("std::string");
        case 'i': ++p_; return std::string("std::istream");
        case 'o': ++p_; return std::string("std::ostream");
        case 'd': ++p_; return std::string("std::iostream");
        case '_':
            ++p_;
            if (subs_.empty()) return std::nullopt;
            return subs_[0];
        default: break;
        }
        size_t id = 0;
        bool any = false;
        while (is_digit(peek()) || (peek() >= 'A' && peek() <= 'Z')) {
            const char c = s_[p_++];
            id = id * 36 + static_cast<size_t>(is_digit(c) ? c - '0' : c - 'A' + 10);
            any = true;
            if (id > 4096) return std::nullopt;
        }
        if (!any || !eat('_') || id + 1 >= subs_.size()) return std::nullopt;
        return subs_[id + 1];
    }

    std::optional<std::string> template_args() {
        if (!eat('I')) return std::nullopt;
        std::vector<std::string> args;
        while (!eof() && peek() != 'E') {
            auto a = template_arg();
            if (!a) return std::nullopt;
            args.push_back(*a);
        }
        if (!eat('E')) return std::nullopt;
        return "<" + join(args) + ">";
    }

    std::optional<std::string> template_arg() {
        if (peek() == 'L') {
            ++p_;
            if (peek() == '_') return std::nullopt;   // L_Z <encoding> E
            auto t = type();
            if (!t) return std::nullopt;
            const bool neg = eat('n');
            std::string digits;
            while (!eof() && peek() != 'E') digits += s_[p_++];
            if (!eat('E') || digits.empty()) return std::nullopt;
            if (*t == "bool") return std::string(digits == "0" ? "false" : "true");
            const std::string v = (neg ? "-" : "") + digits;
            if (*t == "int") return v;
            if (*t == "unsigned int") return v + "u";
            if (*t == "long") return v + "l";
            if (*t == "unsigned long") return v + "ul";
            if (*t == "long long") return v + "ll";
            if (*t == "unsigned long long") return v + "ull";
            return "(" + *t + ")" + v;
        }
        if (peek() == 'J') {
            ++p_;
            std::vector<std::string> pack;
            while (!eof() && peek() != 'E') {
                auto a = template_arg();
                if (!a) return std::nullopt;
                pack.push_back(*a);
            }
            if (!eat('E')) return std::nullopt;
            return join(pack);
        }
        if (peek() == 'X') return std::nullopt;   // expressions
        return type();
    }

    std::optional<std::string> builtin() {
        static constexpr std::pair<char, const char*> kOne[] = {
            {'v', "void"}, {'w', "wchar_t"}, {'b', "bool"}, {'c', "char"},
            {'a', "signed char"}, {'h', "unsigned char"}, {'s', "short"},
            {'t', "unsigned short"}, {'i', "int"}, {'j', "unsigned int"},
            {'l', "long"}, {'m', "unsigned long"}, {'x', "long long"},
            {'y', "unsigned long long"}, {'n', "__int128"}, {'o', "unsigned __int128"},
            {'f', "float"}, {'d', "double"}, {'e', "long double"},
            {'g', "__float128"}, {'z', "..."}};
        for (const auto& [k, v] : kOne)
            if (peek() == k) { ++p_; return std::string(v); }
        if (peek() == 'D') {
            static constexpr std::pair<char, const char*> kTwo[] = {
                {'n', "decltype(nullptr)"}, {'s', "char16_t"}, {'i', "char32_t"},
                {'u', "char8_t"}, {'a', "auto"}, {'c', "decltype(auto)"}, {'h', "half"}};
            for (const auto& [k, v] : kTwo)
                if (peek(1) == k) { p_ += 2; return std::string(v); }
        }
        return std::nullopt;
    }

    std::optional<std::string> template_param() {   // at 'T'
        ++p_;
        size_t idx = 0;
        if (is_digit(peek())) {
            size_t n = 0;
            if (!number(n)) return std::nullopt;
            idx = n + 1;
        }
        if (!eat('_')) return std::nullopt;
        return "T" + std::to_string(idx);
    }

    std::optional<std::string> nested_name() {
        if (!eat('N')) return std::nullopt;
        while (peek() == 'r' || peek() == 'V' || peek() == 'K') ++p_;
        if (peek() == 'R' || peek() == 'O') ++p_;
        std::string prefix;
        while (!eof() && peek() != 'E') {
            if (peek() == 'S') {
                if (peek(1) == 't') {        // "std" is never a substitution
                    if (!prefix.empty()) return std::nullopt;
                    p_ += 2;
                    prefix = "std";
                    continue;
                }
                auto sub = substitution();
                if (!sub || !prefix.empty()) return std::nullopt;
                prefix = *sub;
                continue;
            }
            if (peek() == 'I') {
                if (prefix.empty()) return std::nullopt;
                auto a = template_args();
                if (!a) return std::nullopt;
                prefix += *a;
                subs_.push_back(prefix);
                continue;
            }
            if (peek() == 'T') {
                if (!prefix.empty()) return std::nullopt;
                auto t = template_param();
                if (!t) return std::nullopt;
                prefix = *t;
                subs_.push_back(prefix);
                continue;
            }
            auto u = unqualified_name();
            if (!u) return std::nullopt;
            std::string name = *u;
            if (!abi_tags(name)) return std::nullopt;
            prefix = prefix.empty() ? name : prefix + "::" + name;
            subs_.push_back(prefix);
        }
        if (!eat('E') || prefix.empty() || prefix == "std") return std::nullopt;
        return prefix;
    }

    std::optional<std::string> class_enum_type() {
        if (peek() == 'N') return nested_name();
        std::string name;
        if (peek() == 'S' && peek(1) == 't') {
            p_ += 2;
            auto u = unqualified_name();
            if (!u) return std::nullopt;
            name = "std::" + *u;
        } else {
            auto u = unqualified_name();
            if (!u) return std::nullopt;
            name = *u;
        }
        if (!abi_tags(name)) return std::nullopt;
        subs_.push_back(name);
        if (peek() == 'I') {
            auto a = template_args();
            if (!a) return std::nullopt;
            name += *a;
            subs_.push_back(name);
        }
        return name;
    }

    std::optional<std::string> type() {
        if (++depth_ > kMaxDepth) { --depth_; return std::nullopt; }
        depth_guard guard{depth_};

        if (auto b = builtin()) return b;
        const char c = peek();
        switch (c) {
        case 'P': case 'R': case 'O': {
            ++p_;
            auto t = type();
            if (!t) return std::nullopt;
            std::string r = *t + (c == 'P' ? "*" : c == 'R' ? "&" : "&&");
            subs_.push_back(r);
            return r;
        }
        case 'K': case 'V': case 'r': {
            ++p_;
            auto t = type();
            if (!t) return std::nullopt;
            std::string r = *t + (c == 'K' ? " const" : c == 'V' ? " volatile" : " restrict");
            subs_.push_back(r);
            return r;
        }
        case 'A': {
            ++p_;
            size_t n = 0;
            if (!number(n) || !eat('_')) return std::nullopt;
            auto t = type();
            if (!t) return std::nullopt;
            std::string r = *t + "[" + std::to_string(n) + "]";
            subs_.push_back(r);
            return r;
        }
        case 'F': {
            ++p_;
            eat('Y');
            auto ret = type();
            if (!ret) return std::nullopt;
            std::vector<std::string> params;
            while (!eof() && peek() != 'E') {
                if ((peek() == 'R' || peek() == 'O') && peek(1) == 'E') { ++p_; continue; }
                auto t = type();
                if (!t) return std::nullopt;
                params.push_back(*t);
            }
            if (!eat('E')) return std::nullopt;
            if (params.size() == 1 && params[0] == "void") params.clear();
            std::string r = *ret + " (" + join(params) + ")";
            subs_.push_back(r);
            return r;
        }
        case 'M': {
            ++p_;
            auto cls = type();
            if (!cls) return std::nullopt;
            auto mem = type();
            if (!mem) return std::nullopt;
            std::string r = *mem + " " + *cls + "::*";
            subs_.push_back(r);
            return r;
        }
        case 'T': {
            auto t = template_param();
            if (!t) return std::nullopt;
            std::string r = *t;
            subs_.push_back(r);
            if (peek() == 'I') {
                auto a = template_args();
                if (!a) return std::nullopt;
                r += *a;
                subs_.push_back(r);
            }
            return r;
        }
        case 'D':
            if (peek(1) == 'p') {
                p_ += 2;
                auto t = type();
                if (!t) return std::nullopt;
                std::string r = *t + "...";
                subs_.push_back(r);
                return r;
            }
            return std::nullopt;   // decltype / vendor types
        case 'S':
            if (peek(1) != 't') {
                auto sub = substitution();
                if (!sub) return std::nullopt;
                if (peek() == 'I') {
                    auto a = template_args();
                    if (!a) return std::nullopt;
                    std::string r = *sub + *a;
                    subs_.push_back(r);
                    return r;
                }
                return sub;
            }
            return class_enum_type();
        default:
            if (c == 'N' || is_digit(c) || c == 'U') return class_enum_type();
            return std::nullopt;
        }
    }
};

// Bounds-checked reads over the spans, sorted by VA
class Reader {
public:
    Reader(std::span<const RttiSpan> spans, unsigned ps)
        : spans_(spans.begin(), spans.end()), ps_(ps) {
        std::erase_if(spans_, [](const RttiSpan& s) { return s.data.empty(); });
        std::sort(spans_.begin(), spans_.end(),
                  [](const RttiSpan& a, const RttiSpan& b) { return a.va < b.va; });
    }

    const std::vector<RttiSpan>& spans() const { return spans_; }

    const RttiSpan* find(va_t va) const {
        auto it = std::upper_bound(spans_.begin(), spans_.end(), va,
                                   [](va_t v, const RttiSpan& s) { return v < s.va; });
        // overlapping spans (RELRO inside a LOAD): any earlier one may hold va
        for (int back = 0; it != spans_.begin() && back < 4; ++back) {
            --it;
            if (va - it->va < it->data.size()) return &*it;
        }
        return nullptr;
    }

    bool read(va_t va, void* out, size_t n) const {
        const RttiSpan* s = find(va);
        if (!s) return false;
        const size_t off = static_cast<size_t>(va - s->va);
        if (off + n > s->data.size()) return false;
        std::memcpy(out, s->data.data() + off, n);
        return true;
    }

    std::optional<u64> ptr(va_t va) const {
        if (ps_ == 8) {
            u64 v = 0;
            if (!read(va, &v, 8)) return std::nullopt;
            return v;
        }
        u32 v = 0;
        if (!read(va, &v, 4)) return std::nullopt;
        return v;
    }

    std::optional<i64> sptr(va_t va) const {
        auto v = ptr(va);
        if (!v) return std::nullopt;
        return ps_ == 8 ? static_cast<i64>(*v) : static_cast<i64>(static_cast<i32>(*v));
    }

    bool exec(va_t va) const {
        const RttiSpan* s = find(va);
        return s && s->exec;
    }

    std::optional<std::string_view> cstr(va_t va) const {
        const RttiSpan* s = find(va);
        if (!s) return std::nullopt;
        const size_t off = static_cast<size_t>(va - s->va);
        const size_t lim = std::min(s->data.size(), off + kMaxNameLen + 1);
        size_t end = off;
        while (end < lim && s->data[end] != 0) ++end;
        if (end >= lim) return std::nullopt;
        return std::string_view(reinterpret_cast<const char*>(s->data.data() + off), end - off);
    }

private:
    std::vector<RttiSpan> spans_;
    unsigned              ps_;
};

} // namespace

std::optional<std::string> demangle_itanium_type(std::string_view mangled) {
    if (mangled.empty() || mangled.size() > kMaxNameLen) return std::nullopt;
    return Demangler(mangled).class_type();
}

std::vector<ItaniumClass> scan_itanium_rtti(std::span<const RttiSpan> spans, unsigned ptr_size) {
    if (ptr_size != 4 && ptr_size != 8) return {};
    const Reader rd(spans, ptr_size);
    const unsigned ps = ptr_size;

    // every pointer-aligned slot of every span, with its value
    const auto for_each_slot = [&](auto&& fn) {
        for (const auto& s : rd.spans()) {
            const va_t first = (s.va + ps - 1) / ps * ps;
            const va_t end   = s.va + s.data.size();
            for (va_t va = first; va + ps <= end; va += ps) {
                const u8* at = s.data.data() + (va - s.va);
                u64 v = 0;
                if (ps == 8) std::memcpy(&v, at, 8);
                else { u32 w = 0; std::memcpy(&w, at, 4); v = w; }
                fn(va, v);
            }
        }
    };

    struct ti_t {
        std::string       mangled, name;
        std::vector<va_t> bases, vtables, methods;
        bool              primary = false;
    };
    std::map<va_t, ti_t> tis;

    // pass 1: type_info objects, found by their name pointer (+P) landing on
    // a string that demangles as a class type
    std::unordered_map<va_t, std::optional<std::string>> names;
    for_each_slot([&](va_t slot, u64 v) {
        if (!v || slot < ps) return;
        const RttiSpan* tgt = rd.find(v);
        if (!tgt) return;
        const u8 c0 = tgt->data[static_cast<size_t>(v - tgt->va)];
        if (!(c0 == 'N' || c0 == 'S' || (c0 >= '1' && c0 <= '9'))) return;
        auto it = names.find(v);
        if (it == names.end()) {
            std::optional<std::string> dm;
            if (auto sv = rd.cstr(v)) dm = demangle_itanium_type(*sv);
            it = names.emplace(v, std::move(dm)).first;
        }
        if (!it->second) return;
        const va_t ti = slot - ps;
        if (tis.count(ti)) return;
        ti_t t;
        t.mangled = std::string(*rd.cstr(v));
        t.name    = *it->second;
        tis.emplace(ti, std::move(t));
    });
    if (tis.empty()) return {};

    // pass 2: __si_class_type_info (one base pointer) or
    // __vmi_class_type_info (flags, count, {base, offset_flags}...)
    std::unordered_set<va_t> base_slots;
    for (auto& [ti, t] : tis) {
        const va_t p2 = ti + 2 * ps;
        if (auto b = rd.ptr(p2); b && *b != ti && tis.count(*b)) {
            t.bases.push_back(*b);
            base_slots.insert(p2);
            continue;
        }
        u32 flags = 0, count = 0;
        if (!rd.read(p2, &flags, 4) || !rd.read(p2 + 4, &count, 4)) continue;
        if (flags > 3 || count == 0 || count > 64) continue;
        const va_t arr = p2 + 8;
        std::vector<va_t> bs;
        for (u32 i = 0; i < count; ++i) {
            auto bp = rd.ptr(arr + i * 2ull * ps);
            if (!bp || *bp == ti || !tis.count(*bp)) { bs.clear(); break; }
            bs.push_back(*bp);
        }
        if (bs.empty()) continue;
        for (u32 i = 0; i < count; ++i) base_slots.insert(arr + i * 2ull * ps);
        t.bases = std::move(bs);
    }

    // pass 3: vtables, a type_info pointer preceded by offset_to_top (0 for
    // the primary vtable, minus the subobject offset for secondary ones)
    for_each_slot([&](va_t slot, u64 v) {
        if (!v || slot < ps || base_slots.count(slot) || tis.count(slot)) return;
        auto it = tis.find(v);
        if (it == tis.end()) return;
        auto top = rd.sptr(slot - ps);
        if (!top || *top > 0 || *top < -0x1000000) return;
        auto& t = it->second;
        const va_t ap = slot + ps;
        if (std::find(t.vtables.begin(), t.vtables.end(), ap) != t.vtables.end()) return;
        std::vector<va_t> methods;
        for (va_t e = ap; methods.size() < 4096; e += ps) {
            auto fn = rd.ptr(e);
            if (!fn || !*fn || !rd.exec(*fn)) break;
            methods.push_back(*fn);
        }
        if (*top == 0 && !t.primary) {
            t.vtables.insert(t.vtables.begin(), ap);
            t.methods = std::move(methods);
            t.primary = true;
        } else {
            t.vtables.push_back(ap);
        }
    });

    // a type_info nothing's vtable names (and no polymorphic class derives
    // from) is indistinguishable from a stray pointer to a lookalike string
    std::unordered_set<va_t> keep;
    for (const auto& [ti, t] : tis) {
        if (t.vtables.empty()) continue;
        keep.insert(ti);
        keep.insert(t.bases.begin(), t.bases.end());
    }

    std::vector<ItaniumClass> out;
    out.reserve(keep.size());
    for (const auto& [ti, t] : tis) {
        if (!keep.count(ti)) continue;
        ItaniumClass c;
        c.mangled   = t.mangled;
        c.name      = t.name;
        c.type_info = ti;
        c.vtables   = t.vtables;
        c.methods   = t.methods;
        for (va_t b : t.bases) c.bases.push_back(tis.at(b).name);
        out.push_back(std::move(c));
    }
    std::sort(out.begin(), out.end(), [](const ItaniumClass& a, const ItaniumClass& b) {
        return a.name != b.name ? a.name < b.name : a.type_info < b.type_info;
    });
    return out;
}

}
