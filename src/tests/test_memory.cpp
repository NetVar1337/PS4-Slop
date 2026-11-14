// src/tests/test_memory.cpp
// Tests for core/memory: CE-port memscan engine, aob, pointer_scan, snapshot

#include "harness.hpp"

#include "core/infra/limits.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/console_scan.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/dissect.hpp"
#include "core/memory/offsets.hpp"
#include "core/memory/pointer_scan.hpp"
#include "core/memory/read_util.hpp"
#include "core/memory/snapshot.hpp"
#include "core/memory/watch_service.hpp"
#include "core/util/sha256.hpp"
#include "core/process/target_service.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace slop::core::memory;
using slop::core::infra::cancel_token_t;

// ---------------------------------------------------------------------------
// Sparse page-backed fake reader, deterministic, no live process needed
// ---------------------------------------------------------------------------

namespace {

constexpr size_t kPageSize = 4096;

struct fake_reader_t final : public reader_t {
    std::unordered_map<uintptr_t, std::vector<uint8_t>> pages;

    uint8_t* ptr(uintptr_t addr) {
        const uintptr_t page = addr & ~(kPageSize - 1);
        auto it = pages.find(page);
        if (it == pages.end()) return nullptr;
        return it->second.data() + (addr - page);
    }

    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto* out = static_cast<uint8_t*>(dst);
        while (len > 0) {
            const uintptr_t page = addr & ~(kPageSize - 1);
            auto it = pages.find(page);
            if (it == pages.end()) return false;
            const size_t off  = addr - page;
            const size_t avail = kPageSize - off;
            const size_t n = len < avail ? len : avail;
            std::memcpy(out, it->second.data() + off, n);
            out += n;
            addr += n;
            len -= n;
        }
        return true;
    }

    void write(uintptr_t addr, const void* src, size_t len) {
        auto* in = static_cast<const uint8_t*>(src);
        while (len > 0) {
            const uintptr_t page = addr & ~(kPageSize - 1);
            auto& buf = pages[page];
            if (buf.empty()) buf.assign(kPageSize, 0xEE);
            const size_t off  = addr - page;
            const size_t avail = kPageSize - off;
            const size_t n = len < avail ? len : avail;
            std::memcpy(buf.data() + off, in, n);
            in += n;
            addr += n;
            len -= n;
        }
    }
};

constexpr uint32_t kRW     = 0x04;      // PAGE_READWRITE
constexpr uint32_t kRO     = 0x02;      // PAGE_READONLY
constexpr uint32_t kExec   = 0x20;      // PAGE_EXECUTE_READ
constexpr uint32_t kPrivate = 0x20000;  // MEM_PRIVATE
constexpr uint32_t kImage   = 0x1000000;

scan_region_t rw_region(uintptr_t base, size_t size) {
    return {base, size, kRW, kPrivate};
}

} // namespace

// Reusable error-string scratch for aob_compile calls that don't inspect it
std::string& err_placeholder() {
    static std::string e;
    e.clear();
    return e;
}

// === aob: compile ===

TEST_CASE(aob_compile_spaced) {
    auto p = aob_compile("DE AD BE EF", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 4u);
    REQUIRE_EQ(p->nibble_mask[0], 0xFF);
    REQUIRE_EQ(p->bytes[3], 0xEF);
}

TEST_CASE(aob_compile_wildcards) {
    auto p = aob_compile("DE ?? BE", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 3u);
    REQUIRE_EQ(p->nibble_mask[0], 0xFF);
    REQUIRE_EQ(p->nibble_mask[1], 0x00);
    REQUIRE_EQ(p->nibble_mask[2], 0xFF);
}

TEST_CASE(aob_compile_nibble_wildcards) {
    auto p = aob_compile("D? ?E", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->nibble_mask[0], 0xF0);   // high nibble literal
    REQUIRE_EQ(p->nibble_mask[1], 0x0F);   // low nibble literal
    const uint8_t buf1[] = {0xDE, 0x8E};
    REQUIRE(aob_match(*p, buf1, sizeof(buf1)));
    const uint8_t buf2[] = {0x5E, 0x8F};
    REQUIRE(!aob_match(*p, buf2, sizeof(buf2)));
}

TEST_CASE(aob_compile_star_wildcard) {
    auto p = aob_compile("DE * BE", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->nibble_mask[1], 0x00);
}

TEST_CASE(aob_compile_compact) {
    auto p = aob_compile("DEADBEEF", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 4u);
    REQUIRE_EQ(p->bytes[1], 0xAD);
}

TEST_CASE(aob_compile_0x_prefix) {
    auto p = aob_compile("0xDE, 0xAD", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 2u);
    REQUIRE_EQ(p->bytes[0], 0xDE);
}

TEST_CASE(aob_compile_rejects_odd_compact) {
    auto p = aob_compile("DEA", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_compile_rejects_garbage) {
    auto p = aob_compile("ZZ QQ", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_compile_rejects_empty) {
    auto p = aob_compile("   ", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_to_string_roundtrip) {
    auto p = aob_compile("de ?? ef", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_STR_EQ(aob_to_string(*p), "DE ?? EF");
}

TEST_CASE(aob_from_bytes_format) {
    const uint8_t data[] = {0x01, 0xAB};
    REQUIRE_STR_EQ(aob_from_bytes(data, sizeof(data)), "01 AB");
}

// === aob: match + scan ===

TEST_CASE(aob_match_basic) {
    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0x00, 0xCA, 0xFE, 0xBA, 0x99};
    REQUIRE(!aob_match(*p, buf, sizeof(buf)));        // not anchored at 0
    REQUIRE(aob_match(*p, buf + 1, sizeof(buf) - 1)); // anchored at +1
    REQUIRE(aob_contains(*p, buf, sizeof(buf)));      // sliding search
}

TEST_CASE(aob_match_wildcard_hits_anything) {
    auto p = aob_compile("CA ?? BA", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0xCA, 0x77, 0xBA};
    REQUIRE(aob_match(*p, buf, sizeof(buf)));
}

TEST_CASE(aob_match_fails_when_pattern_longer) {
    auto p = aob_compile("01 02 03 04 05", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0x01, 0x02};
    REQUIRE(!aob_match(*p, buf, sizeof(buf)));
}

TEST_CASE(aob_scan_finds_planted_pattern) {
    fake_reader_t r;
    uint8_t planted[16]{};
    planted[5] = 0xCA;
    planted[6] = 0xFE;
    planted[7] = 0xBA;
    r.write(0x10000, planted, sizeof(planted));

    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());

    auto hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p,
                         aob_scan_options_t{}, cancel_token_t{}, nullptr);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_EQ(hits[0], 0x10005u);
}

TEST_CASE(aob_scan_alignment) {
    fake_reader_t r;
    uint8_t planted[16]{};
    planted[1] = 0xCA; planted[2] = 0xFE; planted[3] = 0xBA;
    r.write(0x10000, planted, sizeof(planted));

    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());

    // Pattern starts at +1 (not 4-aligned): alignment 4 skips it
    aob_scan_options_t opt;
    opt.alignment = 4;
    auto hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p, opt,
                         cancel_token_t{}, nullptr);
    REQUIRE(hits.empty());

    opt.alignment = 1;
    hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p, opt,
                    cancel_token_t{}, nullptr);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_EQ(hits[0], 0x10001u);
}

// === memscan: widths + comparison kernel ===

TEST_CASE(value_sizes_correct) {
    REQUIRE_EQ(value_size(value_width_t::i8), 1u);
    REQUIRE_EQ(value_size(value_width_t::u16), 2u);
    REQUIRE_EQ(value_size(value_width_t::f32), 4u);
    REQUIRE_EQ(value_size(value_width_t::f64), 8u);
}

namespace {

scan_config_t cfg_for(scan_type_t t, value_width_t w, double v1, double v2 = 0) {
    scan_config_t c;
    c.type  = t;
    c.width = w;
    c.value1 = v1;
    c.value2 = v2;
    return c;
}

} // namespace

TEST_CASE(compare_signed_vs_unsigned_increased) {
    // i8: -1 (0xFF) -> 0 (0x00) is an INCREASE as signed..
    REQUIRE(check_value(cfg_for(scan_type_t::increased, value_width_t::i8, 0),
                        value_width_t::i8, 0x00, 0xFF));
    // ...but a DECREASE as unsigned (255 -> 0)
    REQUIRE(!check_value(cfg_for(scan_type_t::increased, value_width_t::u8, 0),
                         value_width_t::u8, 0x00, 0xFF));
    REQUIRE(check_value(cfg_for(scan_type_t::decreased, value_width_t::u8, 0),
                        value_width_t::u8, 0x00, 0xFF));
}

TEST_CASE(compare_exact_and_changed_unchanged) {
    REQUIRE(check_value(cfg_for(scan_type_t::exact_value, value_width_t::i32, 42),
                        value_width_t::i32, 42, 7));
    REQUIRE(!check_value(cfg_for(scan_type_t::exact_value, value_width_t::i32, 41),
                         value_width_t::i32, 42, 7));

    REQUIRE(check_value(cfg_for(scan_type_t::changed, value_width_t::u32, 0),
                        value_width_t::u32, 2, 1));
    REQUIRE(!check_value(cfg_for(scan_type_t::changed, value_width_t::u32, 0),
                         value_width_t::u32, 9, 9));
    REQUIRE(check_value(cfg_for(scan_type_t::unchanged, value_width_t::u32, 0),
                        value_width_t::u32, 9, 9));
}

TEST_CASE(compare_between_bigger_smaller) {
    REQUIRE(check_value(cfg_for(scan_type_t::between, value_width_t::u32, 10, 20),
                        value_width_t::u32, 15, 0));
    REQUIRE(!check_value(cfg_for(scan_type_t::between, value_width_t::u32, 10, 20),
                         value_width_t::u32, 25, 0));
    REQUIRE(check_value(cfg_for(scan_type_t::bigger_than, value_width_t::i32, 5),
                        value_width_t::i32, 6, 0));
    REQUIRE(check_value(cfg_for(scan_type_t::smaller_than, value_width_t::i32, 5),
                        value_width_t::i32, 4, 0));
}

TEST_CASE(compare_increased_by_decreased_by) {
    // check_value takes (curr, prev): 10 = 7 + 3
    REQUIRE(check_value(cfg_for(scan_type_t::increased_by, value_width_t::u32, 3),
                        value_width_t::u32, 10, 7));
    REQUIRE(!check_value(cfg_for(scan_type_t::increased_by, value_width_t::u32, 3),
                         value_width_t::u32, 11, 7));
    REQUIRE(check_value(cfg_for(scan_type_t::decreased_by, value_width_t::u32, 3),
                        value_width_t::u32, 4, 7));
}

TEST_CASE(compare_float_widths) {
    const uint64_t f_one  = value_from_double(value_width_t::f32, 1.0);
    const uint64_t f_two  = value_from_double(value_width_t::f32, 2.0);
    REQUIRE(check_value(cfg_for(scan_type_t::increased, value_width_t::f32, 0),
                        value_width_t::f32, f_two, f_one));
    REQUIRE(check_value(cfg_for(scan_type_t::exact_value, value_width_t::f64, 3.5),
                        value_width_t::f64,
                        value_from_double(value_width_t::f64, 3.5),
                        value_from_double(value_width_t::f64, 3.5)));
}

TEST_CASE(compare_float_rounding_truncated) {
    // CE truncated: value <= v < value + 10^-accuracy
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::truncated;
    c.float_accuracy = 1; // window [100.5, 100.6)
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.55), 0));
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.5), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.6), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.49), 0));
}

TEST_CASE(compare_float_rounding_extreme) {
    // CE extreme rounding: value - eps <= v <= value + eps
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::extreme;
    c.float_accuracy = 1; // window [100.4, 100.6]
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.44), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.39), 0));
}

TEST_CASE(compare_float_rounding_rounded) {
    // CE rounded: RoundTo(v, -accuracy) == RoundTo(value, -accuracy)
    // banker's rounding: RoundTo(100.5, 0) = 100, RoundTo(100.4, 0) = 100,
    // RoundTo(100.6, 0) = 101
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::rounded;
    c.float_accuracy = 0; // integer rounding
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.4), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.6), 0));
}

TEST_CASE(float_accuracy_from_text_derivation) {
    REQUIRE_EQ(float_accuracy_from_text("100.5"), 1u);
    REQUIRE_EQ(float_accuracy_from_text("100.25"), 2u);
    REQUIRE_EQ(float_accuracy_from_text("100"), 0u);
    REQUIRE_EQ(float_accuracy_from_text("1e3"), 0u);
    REQUIRE_EQ(float_accuracy_from_text("1.5e2"), 1u);
}

// === memscan: parse / format ===

TEST_CASE(parse_and_format_roundtrip_ints) {
    uint64_t bits = 0;
    REQUIRE(parse_value_text(value_width_t::i32, "-42", bits));
    REQUIRE_EQ(bits, static_cast<uint64_t>(0xFFFFFFD6u));
    REQUIRE_STR_EQ(format_value_text(value_width_t::i32, bits), "-42");

    REQUIRE(parse_value_text(value_width_t::u64, "0xDEADBEEF", bits));
    REQUIRE_EQ(bits, 0xDEADBEEFull);
    REQUIRE_STR_EQ(format_value_text(value_width_t::u64, bits), "3735928559");

    REQUIRE(!parse_value_text(value_width_t::u8, "-1", bits));   // unsigned rejects sign
    REQUIRE(!parse_value_text(value_width_t::i32, "abc", bits));
}

TEST_CASE(parse_and_format_roundtrip_floats) {
    uint64_t bits = 0;
    REQUIRE(parse_value_text(value_width_t::f32, "3.5", bits));
    REQUIRE_STR_EQ(format_value_text(value_width_t::f32, bits),
                   format_value_text(value_width_t::f32,
                                     value_from_double(value_width_t::f32, 3.5)));
    REQUIRE(!parse_value_text(value_width_t::f32, "not-a-float", bits));
}

// === memscan: region filtering (CE region walk) ===

TEST_CASE(filter_regions_drops_guard_and_noaccess) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000, kRW | 0x100 /*guard*/, kPrivate},
        {0x20000, 0x1000, 0x01 /*noaccess*/,    kPrivate},
        {0x30000, 0x1000, kRW,                  kPrivate},
    };
    auto out = filter_regions(in, scan_config_t{});
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x30000u);
}

TEST_CASE(filter_regions_writable_pref) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000, kRW,  kPrivate},
        {0x20000, 0x1000, kRO,  kPrivate},
    };
    scan_config_t cfg;
    cfg.writable = region_pref_t::include; // writable only
    auto out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x10000u);

    cfg.writable = region_pref_t::exclude; // read-only only
    out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x20000u);
}

TEST_CASE(filter_regions_type_and_range) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000,   kRW, kImage},
        {0x20000, 0x10000,  kRW, kPrivate},   // extends past the range end
        {0x30000, 0x1000,   kRW, kPrivate},
    };
    scan_config_t cfg;
    cfg.mem_image = false;              // drop module-backed
    cfg.begin = 0x20000;                // clip to [0x20000, 0x28000)
    cfg.end   = 0x28000;
    auto out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x20000u);
    REQUIRE_EQ(out[0].size, 0x8000u);   // clipped at the range end
}

// === memscan: first scan (address list) ===

TEST_CASE(first_scan_exact_finds_aligned_u32) {
    fake_reader_t r;
    const uint32_t needle = 1337;
    r.write(0x20010, &needle, 4);
    r.write(0x20100, &needle, 4);
    const uint32_t other = 9999;
    r.write(0x20200, &other, 4);

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 1337);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x20000, 0x2000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 2u);
    REQUIRE_EQ(engine.stats().found, engine.results().size());
    REQUIRE(!engine.stats().truncated);
    REQUIRE(engine.has_results());
}

TEST_CASE(first_scan_skips_unmapped_hole) {
    fake_reader_t r;
    // Only one mapped page inside the scanned region
    const uint32_t needle = 777;
    r.write(0x30004, &needle, 4);

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 777);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x30000, 0x2000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x30004u);
}

TEST_CASE(first_scan_alignment_changes_slot_count) {
    fake_reader_t r;
    const uint8_t z[32]{};
    r.write(0x40000, z, sizeof(z)); // materialize the page with zeros

    // Address-list scan (exact 0): hit count equals the slot count, so the
    // fastscan stepping is observable through results
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x40000, 0x20)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 8u);

    cfg.fast = fastscan_method_t::off;
    memscan_t e2;
    REQUIRE(e2.first_scan(r, {rw_region(0x40000, 0x20)}, cfg,
                          cancel_token_t{}, nullptr));
    REQUIRE_EQ(e2.results().size(), 29u); // 32 - 4 + 1
}

TEST_CASE(first_scan_truncates_at_max_results) {
    fake_reader_t r;
    const uint8_t z[256]{};
    r.write(0x50000, z, sizeof(z)); // materialize the page

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 0);
    cfg.max_results = 5;
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x50000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 5u);
    REQUIRE(engine.stats().truncated);
}

TEST_CASE(first_scan_ends_with_fastscan) {
    fake_reader_t r;
    const uint32_t needle = 42;
    r.write(0x6010C, &needle, 4);   // ends in 0x0C
    r.write(0x60104, &needle, 4);   // ends in 0x04 (must be skipped)

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 42);
    cfg.fast = fastscan_method_t::ends_with;
    cfg.fast_digits = 2;
    cfg.fast_tail   = 0x0C;         // addresses ending in "0C"

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x60000, 0x1000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x6010Cu);
}

// === memscan: unknown-initial region scan + FirstNextScan ===

TEST_CASE(unknown_scan_stashes_then_firstnext_increased) {
    fake_reader_t r;
    const uint32_t v1 = 100;
    r.write(0x60000, &v1, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::unknown_initial, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x60000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));

    // Unknown scan: no address rows, stash alive
    REQUIRE(engine.results().empty());
    REQUIRE(engine.region_scan_active());
    REQUIRE_EQ(engine.stats().slots_tracked, 0x100u); // one page run

    // Mutate upward; firstnext (increased) builds the address list
    const uint32_t v2 = 250;
    r.write(0x60000, &v2, 4);

    scan_config_t ncfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x60000u);
    REQUIRE_EQ(engine.results()[0].bits, static_cast<uint64_t>(250));
    REQUIRE(!engine.region_scan_active()); // stash consumed
}

TEST_CASE(unknown_scan_firstnext_unchanged) {
    fake_reader_t r;
    const uint8_t z[64]{};
    r.write(0x70000, z, sizeof(z));

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::unknown_initial, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x70000, 0x40)}, cfg,
                              cancel_token_t{}, nullptr));

    scan_config_t ncfg = cfg_for(scan_type_t::unchanged, value_width_t::u32, 0);
    ncfg.fast = fastscan_method_t::alignment;   // keep the first scan's stepping
    ncfg.fast_alignment = 4;
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 16u); // 64 bytes / 4 unchanged slots
}

// === memscan: NextNextScan (address list) ===

TEST_CASE(rescan_kinds_filter_correctly) {
    fake_reader_t r;
    const uint32_t v1 = 100;
    r.write(0x80000, &v1, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 100);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x80000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);

    // Mutate our known address upward
    const uint32_t v2 = 250;
    r.write(0x80000, &v2, 4);

    scan_config_t ncfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x80000u);
    REQUIRE_EQ(engine.results()[0].bits, static_cast<uint64_t>(250));

    // Exact rescan against 100: now 250 -> zero hits
    scan_config_t ecfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 100);
    REQUIRE(engine.next_scan(r, ecfg, cancel_token_t{}, nullptr));
    REQUIRE(engine.results().empty());
}

TEST_CASE(rescan_drops_freed_addresses) {
    fake_reader_t r;
    const uint32_t v = 5;
    r.write(0x90000, &v, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 5);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x90000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);

    // Simulate free: remove the page entirely
    r.pages.erase(0x90000);

    scan_config_t ncfg = cfg_for(scan_type_t::unchanged, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE(engine.results().empty());
}

TEST_CASE(rescan_without_previous_fails) {
    fake_reader_t r;
    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    std::string err;
    REQUIRE(!engine.next_scan(r, cfg, cancel_token_t{}, &err));
    REQUIRE(!err.empty());
}

// === memscan: all-types scan ===

TEST_CASE(all_types_scan_matches_multiple_widths) {
    fake_reader_t r;
    const uint32_t needle = 7;                    // also 7 as u8, u16; and 7.0f? no, bits differ
    r.write(0xA0004, &needle, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 7);
    cfg.scan_all_types = true;
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    REQUIRE(engine.first_scan(r, {rw_region(0xA0000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));

    // u8 7 at 0xA0004, u16 7 at 0xA0004, u32 7 at 0xA0004 -> 3 rows
    size_t u8_hits = 0, u16_hits = 0, u32_hits = 0;
    for (const auto& h : engine.results()) {
        if (h.matched == value_width_t::u8)  ++u8_hits;
        if (h.matched == value_width_t::u16) ++u16_hits;
        if (h.matched == value_width_t::u32) ++u32_hits;
    }
    REQUIRE_EQ(u8_hits, 1u);
    REQUIRE_EQ(u16_hits, 1u);
    REQUIRE_EQ(u32_hits, 1u);
}

// === pointer scan ===

TEST_CASE(pointer_scan_depth_one) {
    fake_reader_t r;
    const uintptr_t kTarget  = 0x90000;
    const uintptr_t kHolder  = 0xA0000;
    const uint64_t val = kTarget - 16; // holder + off 16 -> target
    r.write(kHolder, &val, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 1;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;

    auto chains = pointer_scan(r, {rw_region(0xA0000, 0x10000)}, opt,
                               cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);

    bool found = false;
    for (auto& c : chains) {
        if (c.depth() == 1 && c.addresses[0] == kHolder && c.offsets[0] == 16)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(pointer_scan_depth_two_chain) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kMid    = 0xA0000; // points to target
    const uintptr_t kRoot   = 0xB0000; // points near mid

    const uint64_t mid_val = kTarget - 16;
    const uint64_t root_val = kMid - 8;
    r.write(kMid, &mid_val, 8);
    r.write(kRoot, &root_val, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 2;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;

    auto chains = pointer_scan(r, {rw_region(0xA0000, 0x20000)}, opt,
                               cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);

    bool found = false;
    for (auto& c : chains) {
        if (c.depth() == 2 &&
            c.addresses[0] == kRoot && c.offsets[0] == 8 &&
            c.addresses[1] == kMid && c.offsets[1] == 16)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(pointer_scan_static_roots_filter) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kHeapRoot  = 0xA0000; // private-memory holder
    const uintptr_t kCodeRoot  = 0xB0000; // module-backed holder
    const uint64_t v1 = kTarget - 16;
    const uint64_t v2 = kTarget - 16;
    r.write(kHeapRoot, &v1, 8);
    r.write(kCodeRoot, &v2, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 1;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;
    opt.only_module_backed = true;

    std::vector<scan_region_t> regions = {
        {kHeapRoot, 0x1000, kRW, kPrivate},   // private heap
        {kCodeRoot, 0x1000, kRO, kImage},     // module image
    };
    auto chains = pointer_scan(r, regions, opt, cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);
    for (auto& c : chains)
        REQUIRE_EQ(c.addresses[0], kCodeRoot); // only module-backed roots
}

// === snapshot ===

TEST_CASE(snapshot_capture_and_diff) {
    fake_reader_t r;
    std::vector<uint8_t> region(256);
    for (size_t i = 0; i < region.size(); ++i) region[i] = static_cast<uint8_t>(i);
    r.write(0xD0000, region.data(), region.size());

    auto snap_a = snapshot_capture(r, 0xD0000, 256, cancel_token_t{},
                                   slop::core::infra::limits::max_snapshot_region_bytes);
    REQUIRE(snap_a.complete);
    REQUIRE_EQ(snap_a.bytes[10], 10);

    // Mutate two runs: [50..54) and [100..101)
    const uint8_t five[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    r.write(0xD0000 + 50, five, 5);
    const uint8_t one[1] = {0xBB};
    r.write(0xD0000 + 100, one, 1);

    auto snap_b = snapshot_capture(r, 0xD0000, 256, cancel_token_t{},
                                   slop::core::infra::limits::max_snapshot_region_bytes);
    auto d = snapshot_diff(snap_a, snap_b);
    REQUIRE(d.valid);
    REQUIRE_EQ(d.changed.size(), 2u);
    REQUIRE_EQ(d.changed[0].offset, 50u);
    REQUIRE_EQ(d.changed[0].length, 5u);
    REQUIRE_EQ(d.changed[1].offset, 100u);
    REQUIRE_EQ(d.changed[1].length, 1u);
}

TEST_CASE(snapshot_diff_invalid_on_mismatch) {
    region_snapshot_t a, b;
    a.base = 0x1000; a.bytes = {1, 2, 3};
    b.base = 0x1000; b.bytes = {1, 2};
    auto d = snapshot_diff(a, b);
    REQUIRE(!d.valid);

    b.bytes = {9, 9, 9};
    b.base = 0x2000;
    d = snapshot_diff(a, b);
    REQUIRE(!d.valid);
}

// ===========================================================================
// Remote-aware scheduling, read-ahead, coalescing (audit items 39/40)
// ===========================================================================

namespace {

// Wraps a fake reader, reports chosen hints and records every read
struct hinted_reader_t final : public reader_t {
    fake_reader_t& inner;
    reader_hints_t h;
    std::atomic<int> in_flight{0};
    std::atomic<int> max_in_flight{0};
    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::pair<uintptr_t, size_t>> calls;

    hinted_reader_t(fake_reader_t& r, reader_hints_t hints) : inner(r), h(hints) {}

    bool read(uintptr_t addr, void* dst, size_t len) override {
        const int now = ++in_flight;
        int prev = max_in_flight.load();
        while (now > prev && !max_in_flight.compare_exchange_weak(prev, now)) {}
        // widen the window so concurrent workers would visibly overlap
        std::this_thread::sleep_for(std::chrono::microseconds(300));
        const bool ok = inner.read(addr, dst, len);
        {
            std::lock_guard lk(mu);
            calls.push_back({addr, len});
        }
        cv.notify_all();
        --in_flight;
        return ok;
    }
    reader_hints_t hints() const noexcept override { return h; }

    size_t call_count() {
        std::lock_guard lk(mu);
        return calls.size();
    }
    void reset_calls() {
        std::lock_guard lk(mu);
        calls.clear();
    }
};

scan_config_t exact_u32(uint32_t v) {
    scan_config_t c;
    c.type   = scan_type_t::exact_value;
    c.width  = value_width_t::u32;
    c.value1 = static_cast<double>(v);
    c.value2 = static_cast<double>(v);
    return c;
}

} // namespace

TEST_CASE(memory_remote_hints_single_worker_big_chunks) {
    fake_reader_t r;
    std::vector<scan_region_t> regions;
    std::vector<uint8_t> zeros(64 * 1024, 0);
    const uint32_t needle = 0x5EED5EED;
    for (uintptr_t i = 0; i < 16; ++i) {
        const uintptr_t base = 0x1000000 + i * 0x20000;
        r.write(base, zeros.data(), zeros.size());
        r.write(base + 0x100, &needle, 4);
        regions.push_back(rw_region(base, zeros.size()));
    }
    // one big region: the first wire read must use the remote chunk size
    const uintptr_t big = 0x4000000;
    std::vector<uint8_t> big_bytes(9u << 20, 0);
    r.write(big, big_bytes.data(), big_bytes.size());
    r.write(big + (8u << 20) + 0x40, &needle, 4);
    regions.push_back(rw_region(big, big_bytes.size()));

    hinted_reader_t hr(r, remote_reader_hints());
    memscan_t engine;
    scan_config_t cfg = exact_u32(needle);
    cfg.threads = 16;   // asked for many, the serialized reader caps it at 1
    REQUIRE(engine.first_scan(hr, regions, cfg, cancel_token_t{}));
    REQUIRE_EQ(engine.results().size(), 17u);
    REQUIRE_EQ(hr.max_in_flight.load(), 1);

    bool saw_big_chunk = false;
    for (const auto& c : hr.calls) {
        REQUIRE_LE(c.second, kRemoteChunkBytes + 3);   // chunk + u32 overlap tail
        if (c.first == big && c.second == kRemoteChunkBytes + 3) saw_big_chunk = true;
    }
    REQUIRE(saw_big_chunk);
    REQUIRE_EQ(engine.stats().regions_scanned, 17u);
}

TEST_CASE(memory_read_ahead_prefetches_next_chunk) {
    fake_reader_t r;
    const uintptr_t base = 0x2000000;
    const size_t chunk = 0x4000;
    std::vector<uint8_t> bytes(chunk * 4);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i * 7);
    r.write(base, bytes.data(), bytes.size());

    hinted_reader_t hr(r, {});
    detail::chunk_walk_t walk;
    walk.chunk = chunk;
    walk.read_ahead = true;

    std::vector<uint8_t> seen;
    bool prefetched = false;
    detail::chunked_read(hr, {{base, bytes.size()}}, walk, cancel_token_t{},
        [&](size_t range, uintptr_t addr, const uint8_t* data, size_t len,
            uintptr_t limit) {
            REQUIRE_EQ(range, 0u);
            REQUIRE_EQ(addr, base + seen.size());
            REQUIRE_EQ(limit, addr + len);
            if (addr == base) {
                // while chunk 0 is being processed the producer must already
                // be fetching chunk 1 (double buffering)
                std::unique_lock lk(hr.mu);
                prefetched = hr.cv.wait_for(lk, std::chrono::seconds(10), [&] {
                    for (const auto& c : hr.calls) if (c.first == base + chunk) return true;
                    return false;
                });
            }
            seen.insert(seen.end(), data, data + len);
            return true;
        });
    REQUIRE(prefetched);
    REQUIRE(seen == bytes);
}

TEST_CASE(memory_read_ahead_stops_early_and_spans_ranges) {
    fake_reader_t r;
    std::vector<uint8_t> page(0x3000, 0x11);
    r.write(0x3000000, page.data(), page.size());
    r.write(0x3100000, page.data(), page.size());
    r.write(0x3200000, page.data(), page.size());

    detail::chunk_walk_t walk;
    walk.chunk = 0x1000;
    walk.read_ahead = true;
    const std::vector<detail::read_range_t> ranges = {
        {0x3000000, 0x3000}, {0x3100000, 0}, {0x3100000, 0x3000}, {0x3200000, 0x3000}};

    // full walk: every range in order, empty ranges skipped
    std::vector<size_t> order;
    uint64_t total = 0;
    detail::chunked_read(r, ranges, walk, cancel_token_t{},
        [&](size_t range, uintptr_t, const uint8_t*, size_t len, uintptr_t) {
            if (order.empty() || order.back() != range) order.push_back(range);
            total += len;
            return true;
        });
    REQUIRE((order == std::vector<size_t>{0, 2, 3}));
    REQUIRE_EQ(total, 0x9000u);

    // early stop: returning false ends the walk and joins the producer
    size_t delivered = 0;
    detail::chunked_read(r, ranges, walk, cancel_token_t{},
        [&](size_t, uintptr_t, const uint8_t*, size_t, uintptr_t) {
            return ++delivered < 2;
        });
    REQUIRE_EQ(delivered, 2u);
}

TEST_CASE(memory_scan_finds_value_straddling_chunk_border) {
    fake_reader_t r;
    const uintptr_t base = 0x5000000;
    std::vector<uint8_t> zeros(0x2000, 0);
    r.write(base, zeros.data(), zeros.size());
    const uint32_t needle = 0xA1B2C3D4;
    r.write(base + 0xFFE, &needle, 4);   // crosses the 0x1000 chunk border
    r.write(base + 0x10, &needle, 4);

    for (const bool remote : {false, true}) {
        hinted_reader_t hr(r, remote ? remote_reader_hints() : reader_hints_t{});
        memscan_t engine;
        scan_config_t cfg = exact_u32(needle);
        cfg.chunk_bytes = 0x1000;
        cfg.threads = 1;
        REQUIRE(engine.first_scan(hr, {rw_region(base, zeros.size())}, cfg, cancel_token_t{}));
        REQUIRE_EQ(engine.results().size(), 2u);   // found once, no overlap duplicate
        REQUIRE_EQ(engine.results()[0].address, base + 0x10);
        REQUIRE_EQ(engine.results()[1].address, base + 0xFFE);
        REQUIRE_EQ(engine.stats().bytes_scanned, zeros.size());
    }
}

TEST_CASE(memory_aob_finds_pattern_straddling_chunk_border) {
    fake_reader_t r;
    const uintptr_t base = 0x5100000;
    std::vector<uint8_t> zeros(0x2000, 0);
    r.write(base, zeros.data(), zeros.size());
    const uint8_t pat[] = {0xDE, 0xAD, 0xBE, 0xEF};
    r.write(base + 0xFFE, pat, sizeof(pat));

    auto p = aob_compile("DE AD BE EF", err_placeholder());
    REQUIRE(p.has_value());
    aob_scan_options_t opt;
    opt.chunk_bytes = 0x1000;
    hinted_reader_t hr(r, remote_reader_hints());
    aob_stats_t st{};
    auto hits = aob_scan(hr, {rw_region(base, zeros.size())}, *p, opt, cancel_token_t{}, &st);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_EQ(hits[0], base + 0xFFE);
    REQUIRE_EQ(st.bytes_scanned, zeros.size());
    REQUIRE_EQ(hr.max_in_flight.load(), 1);
}

TEST_CASE(memory_remote_rescan_coalesces_reads) {
    fake_reader_t r;
    const uintptr_t base = 0x6000000;
    std::vector<uint8_t> zeros(0x2000, 0);
    r.write(base, zeros.data(), zeros.size());
    const uint32_t v = 77;
    for (uintptr_t i = 0; i < 100; ++i) r.write(base + i * 16, &v, 4);
    r.write(base + 0xFFC, &v, 4);    // last slot of page 0
    r.write(base + 0x1000, &v, 4);   // first slot of page 1

    hinted_reader_t hr(r, remote_reader_hints());
    memscan_t engine;
    scan_config_t cfg = exact_u32(v);
    REQUIRE(engine.first_scan(hr, {rw_region(base, zeros.size())}, cfg, cancel_token_t{}));
    REQUIRE_EQ(engine.results().size(), 102u);

    // address-list rescan: neighbouring rows ride one wire read
    hr.reset_calls();
    scan_config_t again = exact_u32(v);
    REQUIRE(engine.next_scan(hr, again, cancel_token_t{}));
    REQUIRE_EQ(engine.results().size(), 102u);
    REQUIRE_EQ(hr.call_count(), 1u);

    // page 1 disappears: the group read fails, rows settle one by one
    r.pages.erase(base + 0x1000);
    hr.reset_calls();
    REQUIRE(engine.next_scan(hr, again, cancel_token_t{}));
    REQUIRE_EQ(engine.results().size(), 101u);
    REQUIRE_EQ(engine.results().back().address, base + 0xFFC);

    // a local reader keeps one read per row
    hinted_reader_t local(r, reader_hints_t{});
    REQUIRE(engine.next_scan(local, again, cancel_token_t{}));
    REQUIRE_EQ(local.call_count(), 101u);
}

// ===========================================================================
// Pointer chains: module-backed roots + verify pass (audit item 43)
// ===========================================================================

TEST_CASE(memory_pointer_scan_module_root_checks_chain_root) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kMid    = 0xA0000;   // heap object pointing at target
    const uintptr_t kRoot   = 0xB0000;   // module global pointing at mid
    const uint64_t mid_val  = kTarget - 16;
    const uint64_t root_val = kMid - 8;
    r.write(kMid, &mid_val, 8);
    r.write(kRoot, &root_val, 8);

    pointer_scan_options_t opt;
    opt.target = kTarget;
    opt.depth = 2;
    opt.alignment = 8;
    opt.only_module_backed = true;
    std::vector<scan_region_t> regions = {
        {kMid, 0x1000, kRW, kPrivate},
        {kRoot, 0x1000, kRO, kImage},
    };
    auto chains = pointer_scan(r, regions, opt, cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);
    bool two_level = false;
    for (const auto& c : chains) {
        REQUIRE_EQ(c.addresses[0], kRoot);   // the root, not the last holder
        if (c.depth() == 2 && c.addresses[1] == kMid) two_level = true;
    }
    REQUIRE(two_level);
}

TEST_CASE(memory_pointer_verify_drops_stale_chains) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kMid    = 0xA0000;
    const uintptr_t kRoot   = 0xB0000;
    const uint64_t mid_val  = kTarget - 16;
    const uint64_t root_val = kMid - 8;
    r.write(kMid, &mid_val, 8);
    r.write(kRoot, &root_val, 8);

    pointer_chain_result_t good;     // root -> mid -> target
    good.addresses = {kRoot, kMid};
    good.offsets   = {8, 16};
    pointer_chain_result_t wrong;    // lands 8 bytes off
    wrong.addresses = {kRoot, kMid};
    wrong.offsets   = {8, 24};
    pointer_chain_result_t dead;     // root page unmapped
    dead.addresses = {0xC0000};
    dead.offsets   = {0};

    auto landed = pointer_chain_resolve(r, good);
    REQUIRE(landed.has_value());
    REQUIRE_EQ(*landed, kTarget);

    pointer_verify_options_t vo;
    vo.target = kTarget;
    vo.samples = 3;
    pointer_verify_stats_t st{};
    auto kept = pointer_verify(r, {good, wrong, dead}, vo, cancel_token_t{}, &st);
    REQUIRE_EQ(kept.size(), 1u);
    REQUIRE_EQ(kept[0].offsets[1], 16);
    REQUIRE_EQ(st.checked, 3u);
    REQUIRE_EQ(st.dropped_mismatch, 1u);
    REQUIRE_EQ(st.dropped_unreadable, 1u);
    REQUIRE_EQ(st.samples_done, 3u);
    // memoized per pass: kRoot and kMid read once per sample on pass 1 for
    // two chains (+1 for the dead root), then once each on passes 2 and 3
    REQUIRE_EQ(st.reads, 3u + 2u + 2u);

    // the object moves: the chain follows live pointers (root re-pointed)
    const uintptr_t kMid2 = 0xA0800;
    r.write(kMid2, &mid_val, 8);
    const uint64_t root_val2 = kMid2 - 8;
    r.write(kRoot, &root_val2, 8);
    auto still = pointer_verify(r, kept, vo, cancel_token_t{}, &st);
    REQUIRE_EQ(still.size(), 1u);

    // the target itself moves: verifying against the old address drops it
    const uint64_t mid_val2 = 0x91000 - 16;
    r.write(kMid2, &mid_val2, 8);
    auto gone = pointer_verify(r, kept, vo, cancel_token_t{}, &st);
    REQUIRE_EQ(gone.size(), 0u);
    REQUIRE_EQ(st.dropped_mismatch, 1u);
    vo.target = 0x91000;
    REQUIRE_EQ(pointer_verify(r, kept, vo, cancel_token_t{}, nullptr).size(), 1u);
}

// ===========================================================================
// Console AOB multi-match walk (audit item 44)
// ===========================================================================

namespace {

// emulates CMD_PROC_SCAN_AOB: first full match inside [addr, addr+len)
struct fake_console_t {
    uintptr_t base = 0x400000;
    std::vector<uint8_t> mem;
    std::vector<uint8_t> pat;
    size_t calls = 0;
    size_t fail_after = SIZE_MAX;
    bool   lie = false;

    console_find_fn fn() {
        return [this](uint64_t addr, uint32_t len, uint64_t& hit) {
            if (++calls > fail_after) return false;
            hit = 0;
            if (lie) { hit = addr + len + 64; return true; }
            const uint64_t end = addr + len;
            for (uint64_t a = addr; a + pat.size() <= end; ++a) {
                if (a < base || a + pat.size() > base + mem.size()) continue;
                if (std::memcmp(mem.data() + (a - base), pat.data(), pat.size()) == 0) {
                    hit = a;
                    return true;
                }
            }
            return true;
        };
    }
    void plant(size_t off) { std::memcpy(mem.data() + off, pat.data(), pat.size()); }
};

} // namespace

TEST_CASE(memory_console_aob_returns_every_match) {
    fake_console_t fc;
    fc.mem.assign(1024, 0);
    fc.pat = {0x48, 0x8B, 0x05, 0x90};
    // 61 straddles the first window end, 129 the border of a no-hit slide
    for (size_t off : {size_t{0}, size_t{61}, size_t{66}, size_t{129}, size_t{200},
                       size_t{1020}})
        fc.plant(off);

    console_aob_options_t opt;
    opt.pattern_len = fc.pat.size();
    opt.window = 64;   // tiny windows: matches straddle window borders
    console_aob_stats_t st{};
    auto hits = console_aob_all(fc.fn(), {rw_region(fc.base, fc.mem.size())}, opt,
                                cancel_token_t{}, &st);
    const std::vector<uint64_t> want = {fc.base + 0,   fc.base + 61,  fc.base + 66,
                                        fc.base + 129, fc.base + 200, fc.base + 1020};
    REQUIRE(hits == want);
    REQUIRE_EQ(st.matches, 6u);
    REQUIRE(!st.truncated);
    REQUIRE(!st.failed);
    REQUIRE_GE(st.calls, 5u);

    // alignment keeps only aligned hits; the walk still steps past the rest
    opt.alignment = 4;
    hits = console_aob_all(fc.fn(), {rw_region(fc.base, fc.mem.size())}, opt,
                           cancel_token_t{}, &st);
    REQUIRE((hits == std::vector<uint64_t>{fc.base, fc.base + 200, fc.base + 1020}));

    // cap -> truncated with the first max_results hits
    opt.alignment = 1;
    opt.max_results = 2;
    hits = console_aob_all(fc.fn(), {rw_region(fc.base, fc.mem.size())}, opt,
                           cancel_token_t{}, &st);
    REQUIRE_EQ(hits.size(), 2u);
    REQUIRE(st.truncated);

    // transport failure mid-walk -> partial results + failed flag
    opt.max_results = 0;
    opt.window = 1u << 20;
    fc.calls = 0;
    fc.fail_after = 2;
    hits = console_aob_all(fc.fn(), {rw_region(fc.base, fc.mem.size())}, opt,
                           cancel_token_t{}, &st);
    REQUIRE_EQ(hits.size(), 2u);
    REQUIRE(st.failed);
    REQUIRE_EQ(st.failed_at, fc.base + 62);

    // a reply outside the asked window is a protocol error, not a hit
    fc.fail_after = SIZE_MAX;
    fc.lie = true;
    hits = console_aob_all(fc.fn(), {rw_region(fc.base, fc.mem.size())}, opt,
                           cancel_token_t{}, &st);
    REQUIRE(hits.empty());
    REQUIRE(st.failed);
    REQUIRE(st.bad_reply);
}

// ===========================================================================
// Watchlist freeze: dirty check, write cap, failure surfacing (items 41/42)
// ===========================================================================

namespace {

struct fake_io_t final : public watch::detail::pass_io_t {
    std::map<uint64_t, uint64_t> mem;
    std::set<uint64_t> read_only;
    size_t reads = 0;
    size_t writes = 0;

    bool read(uint64_t addr, void* dst, size_t n) override {
        ++reads;
        auto it = mem.find(addr);
        if (it == mem.end()) return false;
        std::memcpy(dst, &it->second, n);
        return true;
    }
    bool write(uint64_t addr, const void* src, size_t n) override {
        ++writes;
        if (read_only.count(addr) || !mem.count(addr)) return false;
        std::memcpy(&mem[addr], src, n);
        return true;
    }
};

watch::entry_t frozen_u32(uint64_t id, uint64_t addr, uint64_t hold) {
    watch::entry_t e;
    e.id = id;
    e.addr = addr;
    e.width = value_width_t::u32;
    e.freeze = true;
    e.frozen_bits = hold;
    return e;
}

} // namespace

TEST_CASE(memory_watch_freeze_dirty_check_and_failures) {
    fake_io_t io;
    io.mem[0x1000] = 5;
    io.mem[0x2000] = 9;
    io.mem[0x3000] = 1;
    io.read_only.insert(0x3000);
    std::vector<watch::entry_t> entries = {
        frozen_u32(1, 0x1000, 5),   // already holds the value
        frozen_u32(2, 0x2000, 5),   // drifted
        frozen_u32(3, 0x3000, 5),   // write rejected
    };
    size_t cursor = 0;
    watch::detail::pass_stats_t st{};
    auto vals = watch::detail::sample_pass(entries, {}, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(vals.size(), 3u);
    REQUIRE_EQ(st.clean_holds, 1u);
    REQUIRE_EQ(st.writes, 2u);
    REQUIRE_EQ(st.write_failures, 1u);
    REQUIRE_EQ(io.mem[0x2000], 5u);

    REQUIRE(vals[0].ok);
    REQUIRE(vals[0].held);
    REQUIRE(!vals[0].hold_failed);
    REQUIRE_EQ(vals[0].bits, 5u);
    REQUIRE(vals[1].ok);
    REQUIRE_EQ(vals[1].bits, 5u);
    REQUIRE(!vals[2].ok);
    REQUIRE(vals[2].hold_failed);
    REQUIRE_STR_EQ(vals[2].text, "-");

    // next pass: everything that can hold is clean, so no writes except the
    // rejected one, which keeps reporting the failure
    io.writes = 0;
    vals = watch::detail::sample_pass(entries, vals, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(io.writes, 1u);
    REQUIRE_EQ(st.clean_holds, 2u);
    REQUIRE(vals[2].hold_failed);

    // the page becomes writable: the hold recovers
    io.read_only.clear();
    vals = watch::detail::sample_pass(entries, vals, io, {64, 16}, cursor, &st);
    REQUIRE(vals[2].ok);
    REQUIRE(!vals[2].hold_failed);
    REQUIRE_EQ(io.mem[0x3000], 5u);

    // narrow widths compare only their bytes (frozen_bits carries junk above)
    io.mem[0x4000] = 0xFFFFFF00000000AAull;
    watch::entry_t b = frozen_u32(4, 0x4000, 0x12345600000000AAull);
    b.width = value_width_t::u8;
    io.writes = 0;
    vals = watch::detail::sample_pass({b}, {}, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(io.writes, 0u);
    REQUIRE_EQ(vals[0].bits, 0xAAu);
}

TEST_CASE(memory_watch_pass_caps_writes_and_rotates) {
    fake_io_t io;
    std::vector<watch::entry_t> entries;
    for (uint64_t i = 0; i < 20; ++i) {
        io.mem[0x10000 + i * 8] = 1;   // all drifted from the hold
        entries.push_back(frozen_u32(i + 1, 0x10000 + i * 8, 7));
    }
    size_t cursor = 0;
    watch::detail::pass_stats_t st{};
    auto vals = watch::detail::sample_pass(entries, {}, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(st.writes, 16u);
    REQUIRE_EQ(st.deferred, 4u);
    REQUIRE_EQ(cursor, 16u);   // next pass starts at the first deferred entry
    REQUIRE_EQ(vals[16].bits, 1u);   // deferred rows show the live (drifted) value
    REQUIRE(vals[16].held);

    vals = watch::detail::sample_pass(entries, vals, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(st.writes, 4u);
    REQUIRE_EQ(st.clean_holds, 16u);
    REQUIRE_EQ(st.deferred, 0u);
    for (uint64_t i = 0; i < 20; ++i) REQUIRE_EQ(io.mem[0x10000 + i * 8], 7u);

    // read budget: unreached rows keep their previous sample and go first next
    std::vector<watch::entry_t> plain;
    for (uint64_t i = 0; i < 100; ++i) {
        io.mem[0x20000 + i * 8] = i;
        watch::entry_t e;
        e.id = 100 + i;
        e.addr = 0x20000 + i * 8;
        e.width = value_width_t::u64;
        plain.push_back(e);
    }
    cursor = 0;
    io.reads = 0;
    vals = watch::detail::sample_pass(plain, {}, io, {64, 16}, cursor, &st);
    REQUIRE_EQ(io.reads, 64u);
    REQUIRE_EQ(cursor, 64u);
    REQUIRE(vals[63].ok);
    REQUIRE(!vals[64].ok);   // never sampled yet
    vals = watch::detail::sample_pass(plain, vals, io, {64, 16}, cursor, &st);
    REQUIRE(vals[99].ok);
    REQUIRE_EQ(vals[99].bits, 99u);
    REQUIRE(vals[0].ok);     // carried / re-read, never blanked
    REQUIRE_EQ(cursor, 28u);
}

TEST_CASE(memory_remote_snapshot_page_granular_holes) {
    fake_reader_t r;
    const uintptr_t base = 0x7000000;
    std::vector<uint8_t> bytes(0x3000);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i ^ 0x5A);
    r.write(base, bytes.data(), bytes.size());
    r.pages.erase(base + 0x1000);   // middle page unreadable

    hinted_reader_t hr(r, remote_reader_hints());
    auto snap = snapshot_capture(hr, base, bytes.size(), cancel_token_t{},
                                 slop::core::infra::limits::max_snapshot_region_bytes);
    REQUIRE(!snap.complete);
    REQUIRE_EQ(snap.bytes.size(), bytes.size());
    REQUIRE(std::equal(bytes.begin(), bytes.begin() + 0x1000, snap.bytes.begin()));
    REQUIRE(std::equal(bytes.begin() + 0x2000, bytes.end(), snap.bytes.begin() + 0x2000));
    for (size_t i = 0x1000; i < 0x2000; ++i) REQUIRE_EQ(snap.bytes[i], 0u);
    // page-granular probing: a handful of wire reads, not a byte bisect
    REQUIRE_LE(hr.call_count(), 8u);
}

// ===========================================================================
// MCP: hex-string addresses everywhere (item 46), pointerscan_verify (43)
// ===========================================================================

namespace {

nlohmann::json mem_call(const nlohmann::json& args, bool& is_err) {
    return slop::core::mcp::call_tool("memory", args, is_err);
}

std::string hex_str(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

} // namespace

TEST_CASE(memory_mcp_watch_accepts_hex_string_addresses) {
    using nlohmann::json;
    bool e = false;
    mem_call({{"action", "watch_clear"}}, e);
    REQUIRE(!e);

    json r = mem_call({{"action", "watch_add"}, {"addr", "0x1234"}, {"width", "u32"}}, e);
    REQUIRE(!e);
    const uint64_t id = r.value("id", uint64_t{0});
    REQUIRE_NE(id, 0u);
    REQUIRE_EQ(r["entries"][0].value("addr", uint64_t{0}), 0x1234u);

    // byte-count width and padded hex
    r = mem_call({{"action", "watch_add"}, {"addr", " 0x20 "}, {"width", 4}}, e);
    REQUIRE(!e);
    REQUIRE_STR_EQ(r["entries"][1].value("width", std::string{}), "u32");

    // garbage gets a readable message, never a raw json type_error
    r = mem_call({{"action", "watch_add"}, {"addr", "player_hp"}}, e);
    REQUIRE(e);
    const std::string msg = r.value("error", std::string{});
    REQUIRE(msg.find("addr") != std::string::npos);
    REQUIRE(msg.find("not a number") != std::string::npos);
    REQUIRE(msg.find("json.exception") == std::string::npos);

    r = mem_call({{"action", "watch_add"}, {"addr", 16}, {"width", 3}}, e);
    REQUIRE(e);
    REQUIRE(r.value("error", std::string{}).find("1, 2, 4 or 8") != std::string::npos);

    // ids accept strings too
    r = mem_call({{"action", "watch_set"}, {"id", hex_str(id)}, {"label", "hp"}}, e);
    REQUIRE(!e);
    r = mem_call({{"action", "watch_remove"}, {"id", std::to_string(id)}}, e);
    REQUIRE(!e);
    REQUIRE_EQ(r["entries"].size(), 1u);

    r = mem_call({{"action", "watch_list"}}, e);
    REQUIRE(!e);
    REQUIRE(r.contains("hold_failures"));
    mem_call({{"action", "watch_clear"}}, e);
}

TEST_CASE(memory_mcp_pointerscan_verify_live_process) {
    using nlohmann::json;
    // two private pages: A holds the static-like root, B the object + target
    auto* base = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    REQUIRE(base != nullptr);
    const uintptr_t A = reinterpret_cast<uintptr_t>(base);
    const uintptr_t B = A + 0x1000;
    const uintptr_t mid = B + 0x100;
    const uintptr_t target = B + 0x800;
    *reinterpret_cast<uint64_t*>(mid) = target - 0x10;   // mid + 0x10 -> target
    *reinterpret_cast<uint64_t*>(A)   = mid - 8;         // root + 8   -> mid

    REQUIRE(slop::core::process::target_attach(GetCurrentProcessId()));
    bool e = false;

    json r = mem_call({{"action", "pointerscan"}, {"target", hex_str(target)},
                       {"begin", hex_str(A)}, {"end", hex_str(A + 0x2000)},
                       {"depth", 2}, {"alignment", 8}, {"min_offset", "-0x1000"},
                       {"limit", 1000}}, e);
    CHECK(!e);
    if (e) std::printf("  pointerscan: %s\n", r.dump().c_str());
    bool has_root_chain = false;
    for (const auto& c : r["chains"]) {
        if (c["addresses"].size() == 2 && c["addresses"][0].get<uint64_t>() == A &&
            c["offsets"][0].get<int64_t>() == 8 && c["offsets"][1].get<int64_t>() == 16)
            has_root_chain = true;
    }
    CHECK(has_root_chain);
    const size_t total = r.value("total", size_t{0});

    // verify the stored list: everything still lands on target
    r = mem_call({{"action", "pointerscan_verify"}, {"samples", 2}, {"interval_ms", 0}}, e);
    CHECK(!e);
    if (e) std::printf("  verify: %s\n", r.dump().c_str());
    CHECK(r.value("kept", size_t{0}) == total);
    CHECK(r.value("samples", 0u) == 2u);
    CHECK(r.value("source", std::string{}) == "last_pointerscan");

    // the root goes stale: every chain that starts at A is dropped
    *reinterpret_cast<uint64_t*>(A) = 0;
    r = mem_call({{"action", "pointerscan_verify"}, {"samples", 1}}, e);
    CHECK(!e);
    CHECK(r.value("kept", size_t{0}) < total);
    for (const auto& c : r["chains"]) CHECK(c["addresses"][0].get<uint64_t>() != A);

    // explicit chains with hex strings, verified against a given target
    *reinterpret_cast<uint64_t*>(A) = mid - 8;
    r = mem_call({{"action", "pointerscan_verify"},
                  {"chains", json::array({json{{"base", hex_str(A)},
                                               {"offsets", json::array({8, "0x10"})}}})},
                  {"target", hex_str(target)}, {"samples", 1}}, e);
    CHECK(!e);
    CHECK(r.value("kept", size_t{0}) == 1u);
    CHECK(r.value("source", std::string{}) == "args");

    r = mem_call({{"action", "pointerscan_verify"},
                  {"chains", json::array({json{{"offsets", json::array({8})}}})},
                  {"target", 1}}, e);
    CHECK(e);
    CHECK(r.value("error", std::string{}).find("addresses[] or base") != std::string::npos);

    slop::core::process::target_detach();
    VirtualFree(base, 0, MEM_RELEASE);
}

TEST_CASE(memory_scan_export_import_roundtrip) {
    // scan persistence: rows survive an engine restart as an address-list scan
    memscan_t engine;
    std::vector<scan_result_t> rows = {
        {0x1000, 0x41, value_width_t::u32},
        {0x2000, 0x42, value_width_t::u32},
        {0x3000, 0x43, value_width_t::u8},
    };
    REQUIRE(engine.import_results(rows, value_width_t::u32));
    REQUIRE(engine.has_results());
    REQUIRE_EQ(engine.results().size(), rows.size());

    std::vector<scan_result_t> out;
    value_width_t width = value_width_t::i8;
    REQUIRE(engine.export_results(out, width));
    REQUIRE_EQ(width, value_width_t::u32);
    REQUIRE_EQ(out.size(), rows.size());
    REQUIRE_EQ(out[0].address, 0x1000u);
    REQUIRE_EQ(out[0].bits, 0x41u);
    REQUIRE_EQ(out[2].matched, value_width_t::u8);

    // an empty row set is not a usable scan state
    REQUIRE(!engine.import_results({}, value_width_t::u32));
}

TEST_CASE(offsets_manifest_is_fingerprint_gated_and_fail_closed) {
    using nlohmann::json;
    std::vector<uint8_t> text(0x400, 0x90);
    const uint8_t anchor[] = {0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44};
    std::memcpy(text.data() + 0x120, anchor, sizeof(anchor));
    text[0x300] = 0x48;   // a near-miss prefix must not count as a second hit
    offsets_input_t in;
    in.title_id = "CUSA00001";
    in.app_ver = "01.02";
    in.text_base = 0x400000;
    in.text = text.data();
    in.text_len = text.size();
    const std::string sha = slop::core::util::sha256_hex(text.data(), text.size());
    REQUIRE(sha.size() == 64);

    json m = {{"title_id", "CUSA00001"}, {"app_ver", "01.02"}, {"module", "eboot.bin"},
              {"text_sha256", sha},
              {"offsets", {{{"name", "player"}, {"rva", "0x123"}, {"aob", "48 8B 05 ?? ?? ?? ??"},
                            {"aob_offset", 3}},
                           {{"name", "fn"}, {"aob", "48 8B 05 11"}}}}};
    json r = verify_offsets(m, in);
    CHECK(r["ok"] == true);
    CHECK(r["resolved"]["player"] == 0x400123u);
    CHECK(r["resolved"]["fn"] == 0x400120u);

    // a different build: hash mismatch, nothing resolved
    auto bad = m;
    bad["text_sha256"] = std::string(64, '0');
    r = verify_offsets(bad, in);
    CHECK(r["ok"] == false);
    CHECK(r["resolved"].empty());

    // wrong title / missing hash both refuse up front
    bad = m;
    bad["title_id"] = "CUSA99999";
    CHECK(verify_offsets(bad, in)["ok"] == false);
    bad = m;
    bad.erase("text_sha256");
    CHECK(verify_offsets(bad, in)["ok"] == false);

    // one bad entry poisons the whole manifest
    bad = m;
    bad["offsets"][0]["rva"] = "0x124";
    r = verify_offsets(bad, in);
    CHECK(r["ok"] == false);
    CHECK(r["resolved"].empty());

    // an anchor that matches twice is rejected
    std::memcpy(text.data() + 0x200, anchor, sizeof(anchor));
    in.text = text.data();
    m["text_sha256"] = slop::core::util::sha256_hex(text.data(), text.size());
    r = verify_offsets(m, in);
    CHECK(r["ok"] == false);
    CHECK(r["errors"].dump().find("not unique") != std::string::npos);
}

TEST_CASE(dissect_classifies_slots) {
    // fake address space: code at 0x1000, a vtable at 0x2000 (slot 0 -> code),
    // an object at 0x3000 (starts with the vtable), a C string at 0x4000
    std::map<uint64_t, std::vector<uint8_t>> mem;
    auto put64 = [&](uint64_t a, uint64_t v) { auto& b = mem[a]; b.resize(8); std::memcpy(b.data(), &v, 8); };
    put64(0x2000, 0x1010);
    put64(0x3000, 0x2000);
    mem[0x4000] = {'h', 'e', 'l', 'l', 'o', 0, 0, 0};
    dissect_env_t env;
    env.readable = [](uint64_t v) { return v >= 0x1000 && v < 0x5000; };
    env.executable = [](uint64_t v) { return v >= 0x1000 && v < 0x2000; };
    env.symbolize = [](uint64_t v) { return v < 0x2000 ? std::string("eboot.bin+") + std::to_string(v) : std::string(); };
    env.read = [&](uint64_t v, void* out, size_t n) -> size_t {
        auto it = mem.find(v);
        if (it == mem.end()) return 0;
        const size_t k = std::min(n, it->second.size());
        std::memset(out, 0, n);
        std::memcpy(out, it->second.data(), k);
        return n;
    };
    uint64_t slots[8];
    float fl[2] = {1.5f, -32.25f};
    double dbl = 1234.5;
    slots[0] = 0;
    slots[1] = 0x1040;   // code
    slots[2] = 0x3000;   // object
    slots[3] = 0x4000;   // char*
    std::memcpy(&slots[4], fl, 8);
    std::memcpy(&slots[5], &dbl, 8);
    slots[6] = 42;
    std::memcpy(&slots[7], "abcdefg", 8);
    auto rows = dissect(0x9000, reinterpret_cast<uint8_t*>(slots), sizeof(slots), env);
    REQUIRE(rows.size() == 8u);
    CHECK(rows[0]["kind"] == "zero");
    CHECK(rows[1]["target"]["kind"] == "code");
    CHECK(rows[2]["target"]["kind"] == "object");
    CHECK(rows[2]["target"]["vtable"] == 0x2000u);
    CHECK(rows[3]["target"]["kind"] == "char*");
    CHECK(rows[3]["target"]["text"] == "hello");
    CHECK(rows[4]["kind"] == "float2");
    CHECK(rows[5]["kind"] == "double");
    CHECK(rows[6]["kind"] == "int64");
    CHECK(rows[7]["kind"] == "text");
}
