// src/core/memory/watch_service.cpp

#include "core/memory/watch_service.hpp"

#include <algorithm>
#include <mutex>

#include "core/infra/clock.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/limits.hpp"
#include "core/process/target_service.hpp"

namespace slop::core::memory::watch {

namespace {

using json = nlohmann::json;
namespace bus = infra::event_bus;

// Per-pass target budgets: the watch pane never issued more than 64 reads per
// pass (so a 4096-entry list could not stall the caller), and freeze
// write-backs are capped too, each one is a full roundtrip on a console
constexpr detail::pass_limits_t kPassLimits{64, 16};
constexpr int64_t kSampleIntervalMs = 100;   // ~10 Hz

struct state_t {
    std::mutex           mu;
    std::vector<entry_t> entries;
    std::vector<value_t> last;
    uint64_t             next_id     = 1;
    int64_t              last_pass_ms = 0;
    size_t               cursor       = 0;   // round-robin start for the budgets
};

state_t& st() {
    static state_t s;
    return s;
}

entry_t* find(state_t& s, uint64_t id) {
    auto it = std::find_if(s.entries.begin(), s.entries.end(),
                           [id](const entry_t& e) { return e.id == id; });
    return it == s.entries.end() ? nullptr : &*it;
}

const char* width_name(value_width_t w) noexcept {
    switch (w) {
    case value_width_t::i8:  return "i8";
    case value_width_t::u8:  return "u8";
    case value_width_t::i16: return "i16";
    case value_width_t::u16: return "u16";
    case value_width_t::i32: return "i32";
    case value_width_t::u32: return "u32";
    case value_width_t::i64: return "i64";
    case value_width_t::u64: return "u64";
    case value_width_t::f32: return "f32";
    case value_width_t::f64: return "f64";
    }
    return "?";
}

json entry_json(const entry_t& e) {
    return json{{"id", e.id},
                {"addr", e.addr},
                {"width", width_name(e.width)},
                {"label", e.label},
                {"freeze", e.freeze},
                {"frozen_bits", e.frozen_bits},
                {"frozen_text", format_value_text(e.width, e.frozen_bits)}};
}

void publish_list_locked(const state_t& s) {
    json arr = json::array();
    for (const auto& e : s.entries) arr.push_back(entry_json(e));
    bus::publish("watch.list", json{{"entries", std::move(arr)}});
}

} // namespace

uint64_t add(uint64_t addr, value_width_t width, std::string label) {
    state_t& s = st();
    uint64_t id = 0;
    {
        std::lock_guard lk(s.mu);
        if (s.entries.size() >= infra::limits::max_watch_entries) return 0;
        entry_t e;
        e.id          = s.next_id++;
        e.addr        = addr;
        e.width       = width;
        e.label       = std::move(label);
        e.freeze      = false;
        e.frozen_bits = 0;
        id = e.id;
        s.entries.push_back(std::move(e));
        publish_list_locked(s);
    }
    return id;
}

bool remove(uint64_t id) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    const auto before = s.entries.size();
    s.entries.erase(std::remove_if(s.entries.begin(), s.entries.end(),
                                   [id](const entry_t& e) { return e.id == id; }),
                    s.entries.end());
    if (s.entries.size() == before) return false;
    s.last.erase(std::remove_if(s.last.begin(), s.last.end(),
                                [id](const value_t& v) { return v.id == id; }),
                 s.last.end());
    publish_list_locked(s);
    return true;
}

void clear() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.entries.clear();
    s.last.clear();
    publish_list_locked(s);
}

bool set_freeze(uint64_t id, bool on) {
    state_t& s = st();
    uint64_t addr = 0;
    size_t   n    = 0;
    {
        std::lock_guard lk(s.mu);
        entry_t* e = find(s, id);
        if (!e) return false;
        if (on && !e->freeze) {
            // Latch whatever the last sample saw, exactly like ticking the
            // ImGui checkbox did. A fresh entry has no sample yet, so read the
            // live value below instead of leaving frozen_bits at 0 (which made
            // the next pass write zero over the target).
            auto it = std::find_if(s.last.begin(), s.last.end(),
                                   [id](const value_t& v) { return v.id == id; });
            if (it != s.last.end() && it->ok) {
                e->frozen_bits = it->bits;
                e->pre_freeze_bits = it->bits;
                e->pre_freeze_valid = true;
            } else {
                addr = e->addr;
                n = value_size(e->width);
            }
        }
        e->freeze = on;
        publish_list_locked(s);
    }
    if (on && n != 0) {
        auto session = process::active_session();
        if (!session || !session->valid()) {
            std::lock_guard lk(s.mu);
            if (entry_t* e = find(s, id)) e->freeze = false;
            publish_list_locked(s);
            return false;
        }
        uint64_t live = 0;
        const auto res = session->read(static_cast<uintptr_t>(addr), &live, n);
        std::lock_guard lk(s.mu);
        entry_t* e = find(s, id);
        if (!e || !e->freeze) return false;
        if (!res.ok) {
            e->freeze = false;   // never leave a freeze armed with a zero hold
            publish_list_locked(s);
            return false;
        }
        e->frozen_bits = live & (n >= 8 ? ~uint64_t{0} : ((uint64_t{1} << (n * 8)) - 1));
        e->pre_freeze_bits = e->frozen_bits;
        e->pre_freeze_valid = true;
        publish_list_locked(s);
    }
    return true;
}

bool set_freeze_once(uint64_t id) {
    if (!set_freeze(id, true)) return false;
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    e->freeze_once = true;
    publish_list_locked(s);
    return true;
}

bool undo_freeze(uint64_t id, std::string* err) {
    state_t& s = st();
    uint64_t addr = 0, bits = 0;
    size_t   n = 0;
    {
        std::lock_guard lk(s.mu);
        entry_t* e = find(s, id);
        if (!e) { if (err) *err = "no such watch entry"; return false; }
        if (!e->freeze && !e->pre_freeze_valid) {
            if (err) *err = "this entry has no freeze to undo";
            return false;
        }
        addr = e->addr;
        bits = e->pre_freeze_bits;
        n    = value_size(e->width);
    }
    auto session = process::active_session();
    if (!session || !session->valid()) { if (err) *err = "no target attached"; return false; }
    const auto res = session->write(static_cast<uintptr_t>(addr), &bits, n);
    if (!res.ok) { if (err) *err = "restore write failed"; return false; }
    std::lock_guard lk(s.mu);
    if (entry_t* e = find(s, id)) {
        e->freeze = false;
        e->freeze_once = false;
        e->pre_freeze_valid = false;
    }
    publish_list_locked(s);
    return true;
}

bool poke(uint64_t id, uint64_t bits, std::string* err) {
    state_t& s = st();
    uint64_t  addr  = 0;
    size_t    n     = 0;
    bool      found = false;
    {
        std::lock_guard lk(s.mu);
        entry_t* e = find(s, id);
        if (!e) {
            if (err) *err = "no such watch entry";
            return false;
        }
        addr  = e->addr;
        n     = value_size(e->width);
        found = true;
        e->frozen_bits = bits;   // frozen or not, this is now the held value
    }
    if (!found) return false;

    auto session = process::active_session();
    if (!session || !session->valid()) {
        if (err) *err = "no target attached";
        return false;
    }
    const auto res = session->write(static_cast<uintptr_t>(addr), &bits, n);
    if (!res.ok && err) *err = "write failed";
    if (res.ok) {
        std::lock_guard lk(s.mu);
        publish_list_locked(s);
    }
    return res.ok;
}

bool set_width(uint64_t id, value_width_t width) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    e->width = width;
    publish_list_locked(s);
    return true;
}

bool set_label(uint64_t id, std::string label) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    e->label = std::move(label);
    publish_list_locked(s);
    return true;
}

std::vector<entry_t> list() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.entries;
}

std::vector<value_t> values() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.last;
}

size_t size() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.entries.size();
}

namespace detail {

namespace {

uint64_t width_mask(size_t n) noexcept {
    return n >= 8 ? ~uint64_t{0} : ((uint64_t{1} << (n * 8)) - 1);
}

} // namespace

std::vector<value_t> sample_pass(const std::vector<entry_t>& entries,
                                 const std::vector<value_t>& prev,
                                 pass_io_t& io, const pass_limits_t& lim,
                                 size_t& cursor, pass_stats_t* stats) {
    pass_stats_t local{};
    pass_stats_t& st = stats ? *stats : local;
    st = {};

    const size_t count = entries.size();
    std::vector<value_t> out(count);
    if (count == 0) { cursor = 0; return out; }

    auto previous = [&](uint64_t id) -> const value_t* {
        for (const auto& v : prev) if (v.id == id) return &v;
        return nullptr;
    };

    const size_t start = cursor % count;
    bool   have_next = false;
    size_t next      = start;
    auto defer = [&](size_t idx) {
        ++st.deferred;
        if (!have_next) { have_next = true; next = idx; }
    };

    for (size_t k = 0; k < count; ++k) {
        const size_t   idx = (start + k) % count;
        const entry_t& e   = entries[idx];
        const size_t   n   = value_size(e.width);
        value_t&       v   = out[idx];
        v.id   = e.id;
        v.addr = e.addr;
        v.held = e.freeze;

        if (st.reads >= lim.max_reads) {
            // out of read budget: keep showing what the last pass saw
            if (const value_t* p = previous(e.id)) {
                v.ok = p->ok; v.bits = p->bits; v.hold_failed = p->hold_failed;
            }
            defer(idx);
            v.text = v.ok ? format_value_text(e.width, v.bits) : std::string("-");
            continue;
        }

        uint64_t live = 0;
        ++st.reads;
        const bool read_ok = io.read(e.addr, &live, n);
        live &= width_mask(n);
        v.ok   = read_ok;
        v.bits = read_ok ? live : 0;

        if (e.freeze) {
            const uint64_t hold = e.frozen_bits & width_mask(n);
            if (read_ok && live == hold) {
                // dirty check: the target already holds the value
                ++st.clean_holds;
                v.ok = true;
                v.wrote = true;
                v.bits = hold;
            } else if (st.writes >= lim.max_writes) {
                // drifted but the write budget is spent: next pass starts here
                if (const value_t* p = previous(e.id)) v.hold_failed = p->hold_failed;
                defer(idx);
            } else {
                ++st.writes;
                uint64_t buf = hold;
                if (io.write(e.addr, &buf, n)) {
                    v.ok = true;
                    v.wrote = true;
                    v.bits = hold;
                } else {
                    // the console rejected the hold (read-only page, detached
                    // session...): surface it instead of claiming success
                    ++st.write_failures;
                    v.ok = false;
                    v.hold_failed = true;
                }
            }
        }

        v.text = v.ok ? format_value_text(e.width, v.bits) : std::string("-");
    }

    cursor = have_next ? next : start;
    return out;
}

} // namespace detail

namespace {

class session_io_t final : public detail::pass_io_t {
public:
    explicit session_io_t(runtime::session_t& s) : s_(s) {}
    bool read(uint64_t addr, void* dst, size_t n) override {
        const auto io = s_.read(static_cast<uintptr_t>(addr), dst, n);
        return io.ok && io.bytes == n;
    }
    bool write(uint64_t addr, const void* src, size_t n) override {
        const auto io = s_.write(static_cast<uintptr_t>(addr), src, n);
        return io.ok && io.bytes == n;
    }
private:
    runtime::session_t& s_;
};

} // namespace

void tick() {
    state_t& s = st();

    // Snapshot under the lock, then touch the target outside it: a kernel-path
    // read must never be holding the list mutex that the UI thread wants
    std::vector<entry_t> snap;
    std::vector<value_t> prev;
    size_t cursor = 0;
    {
        std::lock_guard lk(s.mu);
        if (s.entries.empty()) {
            if (!s.last.empty()) s.last.clear();
            return;
        }
        const int64_t now = infra::steady_ms();
        if (now - s.last_pass_ms < kSampleIntervalMs) return;
        s.last_pass_ms = now;
        snap   = s.entries;
        prev   = s.last;
        cursor = s.cursor;
    }

    auto session = process::active_session();
    if (!session || !session->valid()) {
        std::lock_guard lk(s.mu);
        if (!s.last.empty()) {
            s.last.clear();
            bus::publish("watch.values", json{{"attached", false},
                                              {"values", json::array()}});
        }
        return;
    }

    session_io_t io(*session);
    const std::vector<value_t> sampled =
        detail::sample_pass(snap, prev, io, kPassLimits, cursor);

    // Track live values into frozen_bits while unfrozen so that flipping the
    // freeze on latches the value the caller is looking at
    bool changed = false;
    {
        std::lock_guard lk(s.mu);
        s.cursor = cursor;
        for (const auto& v : sampled) {
            entry_t* e = find(s, v.id);
            if (!e) continue;
            if (!e->freeze && v.ok) e->frozen_bits = v.bits;
            // freeze-once: release as soon as the hold actually landed
            if (e->freeze && e->freeze_once && v.wrote) {
                e->freeze = false;
                e->freeze_once = false;
                e->pre_freeze_valid = false;
            }
        }
        changed = s.last.size() != sampled.size();
        if (!changed) {
            for (size_t i = 0; i < sampled.size(); ++i) {
                if (s.last[i].id != sampled[i].id ||
                    s.last[i].ok != sampled[i].ok ||
                    s.last[i].held != sampled[i].held ||
                    s.last[i].hold_failed != sampled[i].hold_failed ||
                    s.last[i].bits != sampled[i].bits) {
                    changed = true;
                    break;
                }
            }
        }
        s.last = sampled;
    }

    if (!changed) return;   // nothing moved: keep the event stream quiet

    json arr = json::array();
    for (const auto& v : sampled)
        arr.push_back(json{{"id", v.id},
                           {"addr", v.addr},
                           {"ok", v.ok},
                           {"held", v.held},
                           {"hold_failed", v.hold_failed},
                           {"bits", v.bits},
                           {"text", v.text}});
    bus::publish("watch.values", json{{"attached", true},
                                      {"values", std::move(arr)}});
}

void shutdown() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.entries.clear();
    s.last.clear();
    s.last_pass_ms = 0;
}

} // namespace slop::core::memory::watch
