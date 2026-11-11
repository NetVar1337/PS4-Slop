// src/core/mcp/tools_analyze.cpp
// tool: analyze (hyperion analysis, packer, signatures, bindiff)

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

namespace {

// async bindiff jobs (analyze.diff_start/diff_job/diff_cancel)
struct diff_job_rec_t {
    std::string path_a, path_b;
    std::string stage = "queued";   // loading|analyzing_a|analyzing_b|comparing|done
    float       progress = -1.0f;   // -1 = indeterminate
    bool        done = false;
    json        result;              // full diff payload on success/partial
    std::string error;               // set when the job failed outright
};
std::mutex g_diff_mu;
std::map<uint64_t, diff_job_rec_t> g_diff_jobs;
constexpr size_t kMaxDiffJobs = 32;

} // namespace

namespace {

// tool: analyze

// Shared bindiff core for sync `diff` and the async diff_start jobs.
// Returns the FULL result (all non-identical diffs); callers slice `diffs`
// to their limit. Throws (fail) on load/analyze failure or when cancelled
// between phases. `cancelled()` is polled between phases and inside the
// compare; `report(stage, progress)` feeds job polling (-1 = indeterminate).
json run_diff_core(const std::string& pa, const std::string& pb,
                   uint32_t timeout_ms, size_t max_pairs,
                   const std::function<bool()>& cancelled,
                   const std::function<void(const std::string&, float)>& report) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    auto ms_left = [&]() -> uint64_t {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now).count());
    };
    auto check_cancel = [&](const char* what) {
        if (cancelled && cancelled()) fail(std::string(what) + " cancelled");
        if (ms_left() == 0)
            fail(std::string(what) + " timed out (timeout_ms exceeded)");
    };

    auto load_bytes = [](const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) fail("cannot open " + path);
        f.seekg(0, std::ios::end);
        const auto sz = f.tellg();
        if (sz <= 0) fail("empty file: " + path);
        if (sz > (256ll << 20)) fail("file too large for diff (>256MB): " + path);
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> bytes(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(bytes.data()), sz);
        if (!f) fail("short read on " + path);
        auto opened = disasm::open_image(std::move(bytes));
        if (!opened.ok) fail("cannot open " + path + ": " + opened.error);
        if (opened.file.size() > (256u << 20))
            fail("analyzed image too large for diff (>256 MiB): " + path);
        return std::move(opened.file);
    };

    report("loading", -1.0f);
    std::vector<uint8_t> bytes_a = load_bytes(pa);
    check_cancel("diff");
    std::vector<uint8_t> bytes_b = load_bytes(pb);
    check_cancel("diff");

    // NOTE: start_sync has no cancel hook, so each side can still take a
    // while on huge binaries; the deadline applies to the compare phase
    // and to the boundary between the two analyses.
    report("analyzing_a", -1.0f);
    auto sa = std::make_unique<hs::session_t>();
    if (cancelled && cancelled()) fail("diff cancelled");
    if (!sa->start_sync(bytes_a.data(), bytes_a.size(), 0)) {
        if (cancelled && cancelled()) fail("diff cancelled");
        fail("hyperion analysis failed for " + pa + ": " + sa->error());
    }
    check_cancel("diff");
    report("analyzing_b", -1.0f);
    auto sb = std::make_unique<hs::session_t>();
    if (cancelled && cancelled()) fail("diff cancelled");
    if (!sb->start_sync(bytes_b.data(), bytes_b.size(), 0)) {
        if (cancelled && cancelled()) fail("diff cancelled");
        fail("hyperion analysis failed for " + pb + ": " + sb->error());
    }
    if (cancelled && cancelled()) fail("diff cancelled");

    report("comparing", 0.0f);
    hype::BinDiff differ;
    hype::BinDiff::options_t opt;
    opt.max_pairs = max_pairs;
    opt.cancel = cancelled ? &cancelled : nullptr;
    // absolute steady-clock deadline in BinDiff::now_ms() terms
    opt.deadline_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) +
        timeout_ms;
    std::function<void(float)> progress_fn = [&](float p) {
        report("comparing", p * 0.95f + 0.05f);
    };
    opt.progress = &progress_fn;
    auto outcome = differ.compare_budgeted(sa->db(), sb->db(), opt);

    json arr = json::array();
    const char* status_name[] = {"added", "removed", "modified", "identical"};
    for (const auto& r : outcome.results) {
        if (r.status == hype::DiffResult::Identical) continue;  // noise
        arr.push_back({{"addr_a", r.addr_a}, {"addr_b", r.addr_b},
                       {"name", r.name},
                       {"similarity", r.similarity},
                       {"status", status_name[r.status]}});
    }
    size_t counts[4] = {0, 0, 0, 0};
    for (const auto& r : outcome.results) ++counts[r.status];
    json out = {{"ok", true}, {"diffs", arr}, {"count", arr.size()},
                {"totals", {{"added", counts[0]}, {"removed", counts[1]},
                            {"modified", counts[2]},
                            {"identical", counts[3]}}},
                {"funcs_a", sa->db().funcs.size()},
                {"funcs_b", sb->db().funcs.size()},
                {"pairs_evaluated", outcome.pairs_evaluated},
                {"pairs_skipped_size", outcome.pairs_skipped_size},
                {"timed_out", outcome.timed_out},
                {"cancelled", outcome.cancelled}};
    if (outcome.timed_out)
        out["note"] = "pair budget/deadline hit: results are partial "
                      "(raise max_pairs/timeout_ms for a fuller diff)";
    if (outcome.cancelled) out["note"] = "diff cancelled: results are partial";
    report("done", 1.0f);
    return out;
}

} // namespace


json tool_analyze(const json& args, const infra::cancel_token_t& cancel) {
    const std::string action = require_action(args);
    if (action != "packer" && action != "signatures" && action != "diff" &&
        action != "diff_start" && action != "diff_job" &&
        action != "diff_cancel")
        fail("analyze: unknown action "
             "(packer|signatures|diff|diff_start|diff_job|diff_cancel)");

    // diff is heavy (two full Hyperion analyses + quadratic compare), so it
    // runs WITHOUT the global tool mutex (see call_tool), honors cancel +
    // timeout_ms, and caps the pair budget instead of hanging the engine.
    // diff_start/diff_job/diff_cancel are the async job flavor with progress.
    if (action == "diff_start") {
        if (!args.contains("path_a") || !args.contains("path_b"))
            fail("missing path_a/path_b");
        const std::string pa = args.at("path_a").get<std::string>();
        const std::string pb = args.at("path_b").get<std::string>();
        const uint32_t timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 600000), 5000, 1800000));
        const size_t max_pairs = std::min<size_t>(
            args.value("max_pairs", 500000u), 10000000u);

        infra::job_desc_t desc;
        desc.label = "bindiff";
        desc.owner = "analyze.diff_start";
        desc.cancellable = true;
        // Placeholder id: replaced with the real job id after submit; the
        // body looks its record up by id captured below.
        std::shared_ptr<std::atomic<uint64_t>> job_id =
            std::make_shared<std::atomic<uint64_t>>(0);
        desc.body = [pa, pb, timeout_ms, max_pairs, job_id](
                        infra::job_context_t& ctx) {
            // submit() assigns the id after spawning us; wait for it.
            uint64_t id = 0;
            for (int i = 0; i < 5000 && id == 0 && !ctx.cancelled(); ++i) {
                id = job_id->load(std::memory_order_acquire);
                if (!id)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!id) { ctx.fail("diff job id never assigned"); return; }
            auto report = [&](const std::string& stage, float p) {
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it == g_diff_jobs.end()) return;
                it->second.stage = stage;
                it->second.progress = p;
            };
            try {
                json res = run_diff_core(
                    pa, pb, timeout_ms, max_pairs,
                    [&]() { return ctx.cancelled(); }, report);
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it != g_diff_jobs.end()) {
                    it->second.result = std::move(res);
                    it->second.stage = "done";
                    it->second.progress = 1.0f;
                    it->second.done = true;
                }
            } catch (const std::exception& e) {
                std::lock_guard lk(g_diff_mu);
                auto it = g_diff_jobs.find(id);
                if (it != g_diff_jobs.end()) {
                    it->second.error = e.what();
                    it->second.stage = "done";
                    it->second.done = true;
                }
                ctx.fail(e.what());
            }
        };
        const uint64_t id = infra::jobs::submit(std::move(desc));
        if (!id) fail("diff job queue full, retry shortly");
        job_id->store(id, std::memory_order_release);
        {
            std::lock_guard lk(g_diff_mu);
            auto& rec = g_diff_jobs[id];
            rec.path_a = pa;
            rec.path_b = pb;
            rec.stage = "queued";
            while (g_diff_jobs.size() > kMaxDiffJobs)
                g_diff_jobs.erase(g_diff_jobs.begin());
        }
        return {{"ok", true}, {"job_id", id},
                {"hint", "poll analyze.diff_job(id) for stage/progress, "
                         "cancel with analyze.diff_cancel(id)"}};
    }

    if (action == "diff_job") {
        const uint64_t id = parse_addr(args, "id");
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 5000u);
        std::lock_guard lk(g_diff_mu);
        const auto it = g_diff_jobs.find(id);
        if (it == g_diff_jobs.end())
            fail("unknown diff job (expired or never submitted)");
        const auto& rec = it->second;
        if (!rec.done) {
            json out = {{"ok", true}, {"job_id", id},
                        {"state", infra::jobs::alive(id) ? "running" : "queued"},
                        {"stage", rec.stage}, {"progress", rec.progress}};
            return out;
        }
        if (!rec.error.empty()) fail(rec.error);
        json res = rec.result;
        if (res.contains("diffs") && res.at("diffs").is_array() &&
            res.at("diffs").size() > limit) {
            json sliced = json::array();
            for (size_t i = 0; i < limit; ++i)
                sliced.push_back(res.at("diffs").at(i));
            res["diffs"] = std::move(sliced);
            res["count"] = res["diffs"].size();
            res["truncated"] = true;
        }
        res["job_id"] = id;
        res["state"] = "succeeded";
        return res;
    }

    if (action == "diff_cancel") {
        const uint64_t id = parse_addr(args, "id");
        if (!infra::jobs::cancel(id)) {
            std::lock_guard lk(g_diff_mu);
            if (g_diff_jobs.find(id) == g_diff_jobs.end())
                fail("unknown diff job");
            // Known but already finished: cancel is a no-op success.
            return {{"job_id", id}, {"cancelled", false},
                    {"note", "job already finished"}};
        }
        return {{"job_id", id}, {"cancelled", true}};
    }

    if (action == "diff") {
        if (!args.contains("path_a") || !args.contains("path_b"))
            fail("missing path_a/path_b");
        const std::string pa = args.at("path_a").get<std::string>();
        const std::string pb = args.at("path_b").get<std::string>();
        const uint32_t timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 120000), 5000, 1800000));
        const size_t max_pairs = std::min<size_t>(
            args.value("max_pairs", 500000u), 10000000u);
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 5000u);
        auto noop = [](const std::string&, float) {};
        json full = run_diff_core(
            pa, pb, timeout_ms, max_pairs,
            [&]() { return cancel.cancelled(); }, noop);
        if (full.contains("diffs") && full.at("diffs").is_array() &&
            full.at("diffs").size() > limit) {
            json sliced = json::array();
            for (size_t i = 0; i < limit; ++i)
                sliced.push_back(full.at("diffs").at(i));
            full["diffs"] = std::move(sliced);
            full["count"] = full["diffs"].size();
            full["truncated"] = true;
        }
        full["hint"] = "for huge binaries prefer async "
                       "analyze.diff_start + diff_job (progress + cancel)";
        return full;
    }

    // explicit path into the private cache, else the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& img = load_image(args.at("path").get<std::string>());
        if (action == "packer") {
            require_x86_image(img.arch, img.format, "analyze.packer", true);
            require_pe_image(img.arch, img.format, "analyze.packer", true);
        }
        pe = &img.pe; file = &img.file;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop "
                 "(see disasm.loaded)");
        if (action == "packer") {
            require_x86_image(bin.arch, bin.format, "analyze.packer");
            require_pe_image(bin.arch, bin.format, "analyze.packer");
        }
        pe = &bin.pe; file = &bin.file;
        img_name = bin.name;
    }

    if (action == "packer") {
        auto v = analysis::packer_analyze(*pe, *file);
        json dets = json::array();
        for (const auto& d : v.detections)
            dets.push_back({{"type", d.type}, {"protector", d.protector},
                            {"detail", d.detail}, {"location", d.location}});
        json secs = json::array();
        for (const auto& s : v.sections)
            secs.push_back({{"name", s.name}, {"rva", s.rva},
                            {"raw_size", s.raw_size}, {"virtual_size", s.virtual_size},
                            {"entropy", s.entropy}, {"writable_exec", s.writable_exec},
                            // raw characteristics here too for consistency
                            {"exec", (s.characteristics & 0x20000000u) != 0},
                            {"writable", (s.characteristics & 0x80000000u) != 0},
                            {"characteristics", s.characteristics}});
        json out = {{"image", img_name}, {"packed", v.packed}, {"family", v.family},
                    {"confidence", v.confidence}, {"file_entropy", v.file_entropy},
                    {"detections", dets}, {"sections", secs}};

        // the hyperion packer verdict rides along when the session is analyzed
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype) {
                hype::PackerDetector det;
                auto infos = det.detect(bin.hype->image());
                json harr = json::array();
                for (const auto& i : infos)
                    harr.push_back({{"name", i.name},
                                    {"confidence", i.confidence},
                                    {"details", i.details}});
                out["hype_packer"] = harr;
            }
        }
        return out;
    }

    const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);

    // raw crypto constants plus analyzer-derived names when available
    if (!args.contains("path")) {
        auto& bin = ds::get();
        if (bin.ready && bin.hype && bin.hype->ready()) {
            auto hits = analysis::crypto_hunt(*pe, *file, limit);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"name", h.name}, {"offset", h.offset},
                          {"in_overlay", h.in_overlay}};
                if (h.va) o["va"] = h.va;
                arr.push_back(std::move(o));
            }

            // analyzer derived names, nothing here is flirt verified
            json named = json::array();
            for (const auto& [va, name] : bin.hype->db().names) {
                if (name.find("j_") == 0 || name.find("__imp_") == 0) continue;
                if (named.size() >= limit) break;
                named.push_back({{"va", va}, {"name", name}});
            }
            return {{"image", img_name}, {"signatures", arr},
                    {"count", arr.size()}, {"named_functions", named},
                    {"named_count", named.size()}};
        }
    }

    auto hits = analysis::crypto_hunt(*pe, *file, limit);
    json arr = json::array();
    for (const auto& h : hits) {
        json o = {{"name", h.name}, {"offset", h.offset},
                  {"in_overlay", h.in_overlay}};
        if (h.va) o["va"] = h.va;
        arr.push_back(std::move(o));
    }
    return {{"image", img_name}, {"signatures", arr}, {"count", arr.size()}};
}

} // namespace slop::core::mcp::detail
