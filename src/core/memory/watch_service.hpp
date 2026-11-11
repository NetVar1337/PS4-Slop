#pragma once

// the watchlist with freeze writes, lifted out of the scanner view so the
// ui, agents and front ends all share one list, the app tick services it
// and values go out as a batched event

#include <cstdint>
#include <string>
#include <vector>

#include "core/memory/memscan.hpp"

namespace slop::core::memory::watch {

struct entry_t {
    uint64_t      id          = 0;
    uint64_t      addr        = 0;
    value_width_t width       = value_width_t::u32;
    std::string   label;
    bool          freeze      = false;
    uint64_t      frozen_bits = 0;
};

struct value_t {
    uint64_t    id   = 0;
    uint64_t    addr = 0;
    bool        ok   = false;   // live read succeeded on the last pass
    bool        held = false;   // value is being held by a freeze write
    bool        hold_failed = false; // the freeze write-back was rejected
    uint64_t    bits = 0;
    std::string text;           // format_value_text(width, bits)
};

// Add an entry. Returns its id, or 0 when the watch cap is reached
uint64_t add(uint64_t addr, value_width_t width, std::string label);

bool remove(uint64_t id);
void clear();

// Toggle the freeze hold. Turning it on latches the most recently sampled
// value, matching the ImGui checkbox behaviour it replaces
bool set_freeze(uint64_t id, bool on);

// Overwrite the target now and, when frozen, latch the new value as the hold
bool poke(uint64_t id, uint64_t bits, std::string* err = nullptr);

bool set_width(uint64_t id, value_width_t width);
bool set_label(uint64_t id, std::string label);

std::vector<entry_t> list();

// Values from the most recent service pass (no target reads on this path)
std::vector<value_t> values();

size_t size();

// one service pass, sample values, apply freezes, publish when anything
// moved, rate limited to about 10hz
void tick();

// Drop every entry and forget the sampling clock (app shutdown / detach)
void shutdown();

namespace detail {

// target access for one pass (the session in production, a fake in tests)
class pass_io_t {
public:
    virtual ~pass_io_t() = default;
    virtual bool read(uint64_t addr, void* dst, size_t n) = 0;
    virtual bool write(uint64_t addr, const void* src, size_t n) = 0;
};

// Per-pass budgets. Every read/write is a roundtrip on a remote target, so
// both are capped; long lists are serviced round-robin across passes
struct pass_limits_t {
    size_t max_reads  = 64;
    size_t max_writes = 16;
};

struct pass_stats_t {
    size_t reads          = 0;
    size_t writes         = 0;   // freeze write-backs issued
    size_t clean_holds    = 0;   // frozen value already in place, no write
    size_t deferred       = 0;   // entries left for the next pass (budget)
    size_t write_failures = 0;
};

// One sampling pass over entries (in list order in the result). Unfrozen
// entries are read; frozen entries are read and written back only when the
// target drifted from the hold (dirty check). A rejected write reports
// ok=false + hold_failed. Entries the budgets could not reach this pass keep
// their previous value from `prev` and are serviced first next pass via
// `cursor` (an index into entries, updated in place)
std::vector<value_t> sample_pass(const std::vector<entry_t>& entries,
                                 const std::vector<value_t>& prev,
                                 pass_io_t& io, const pass_limits_t& lim,
                                 size_t& cursor, pass_stats_t* stats = nullptr);

} // namespace detail

} // namespace slop::core::memory::watch
