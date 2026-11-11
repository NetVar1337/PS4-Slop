// src/core/mcp/tools_devirt.cpp
// tool: devirt

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

namespace {

// tool: devirt

// Seeded emulation runs for recover_cfg / prove_predicates / invariants. Each
// run builds a fresh unicorn instance and maps the data sections while this
// tool holds g_tool_mu and the binary lock, so the count must stay bounded
size_t devirt_runs(const json& args) {
    constexpr int64_t kMaxRuns = 64;
    return static_cast<size_t>(
        std::clamp<int64_t>(args.value("runs", int64_t{4}), 1, kMaxRuns));
}

} // namespace


json tool_devirt(const json& args) {
    const std::string action = require_action(args);

    const auto pe_json = [](const magicmida::pe_info_t& pe) {
        return json{{"ok", pe.ok}, {"arch", magicmida::arch_name(pe.arch)},
                    {"entry_rva", pe.entry_rva}, {"size_of_image", pe.size_of_image},
                    {"sections", pe.sections}, {"file_size", pe.file_size},
                    {"error", pe.error}};
    };
    const auto job_json = [&pe_json](const magicmida::job_t& job) {
        json out = {{"id", job.id}, {"state", magicmida::state_name(job.state)},
                    {"input_path", job.request.input_path},
                    {"requested_output_path", job.request.output_path}};
        if (job.state == magicmida::state_t::succeeded ||
            job.state == magicmida::state_t::failed ||
            job.state == magicmida::state_t::cancelled) {
            out["result"] = {{"ok", job.result.ok},
                             {"cancelled", job.result.cancelled},
                             {"timed_out", job.result.timed_out},
                             {"exit_code", job.result.exit_code},
                             {"duration_ms", job.result.duration_ms},
                             {"arch", magicmida::arch_name(job.result.arch)},
                             {"generated_path", job.result.generated_path},
                             {"output_path", job.result.output_path},
                             {"output", pe_json(job.result.output)},
                             {"warnings", job.result.warnings},
                             {"error", job.result.error}};
        }
        return out;
    };

    if (action == "themida_status") {
        const auto install = magicmida::installation();
        json running = json::array();
        for (const auto& job : magicmida::jobs()) running.push_back(job_json(job));
        return {{"engine", "Magicmida"}, {"version", SLOP_MAGICMIDA_VERSION},
                {"root", install.root}, {"x86_exe", install.x86_exe},
                {"x64_exe", install.x64_exe},
                {"x86_available", install.x86_available},
                {"x64_available", install.x64_available},
                {"x64_scyllahide_available", install.x64_scyllahide_available},
                {"jobs", std::move(running)}};
    }
    if (action == "themida_start") {
        const std::string path = args.value("path", std::string{});
        if (path.empty()) fail("themida_start requires 'path'");
        magicmida::request_t request;
        request.input_path = path;
        request.output_path = args.value("output_path", std::string{});
        request.timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 300000), 1000, 1800000));
        request.overwrite = args.value("overwrite", false);
        request.load_result = args.value("load", true);
        std::string error;
        const uint64_t id = magicmida::start(std::move(request), error);
        if (id == 0) fail(error);
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job was not registered");
        return job_json(job);
    }
    if (action == "themida_job") {
        const uint64_t id = parse_addr(args, "id");
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job not found");
        return job_json(job);
    }
    if (action == "themida_cancel") {
        const uint64_t id = parse_addr(args, "id");
        return {{"id", id}, {"cancelled", magicmida::cancel(id)}};
    }

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        require_x86_image(cache.arch, cache.format, "devirt." + action, true);
        img.pe = &cache.pe; img.file = &cache.file;
        img.base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        require_x86_image(bin.arch, bin.format, "devirt." + action);
        img.pe = &bin.pe; img.file = &bin.file;
        img.base = bin.base;
        img_name = bin.name;
    }

    auto& engine = shared_engine();
    if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
    img.eng = &engine;

    json out;
    out["image"] = img_name;

    // read only deobfuscation analysis

    if (action == "recover_cfg") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto r = recover::recover_flattened(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["flattened"] = r.flattened;
        out["dispatcher"] = r.dispatcher;
        out["mode"] = r.mode;
        json edges = json::array();
        for (const auto& e : r.dispatch_map)
            edges.push_back({{"state", e.state}, {"target", e.target}});
        out["dispatch_map"] = edges;
        out["real_edges_recovered"] = r.real_edges_recovered;
        out["fake_edges"] = r.fake_edges;
        out["blocks"] = r.blocks;
        out["corroborated"] = r.corroborated;
        out["runs"] = r.runs;
        out["dispatcher_entries_observed"] = r.dispatcher_entries_observed;
        if (!r.note.empty()) out["note"] = r.note;
        return out;
    }

    if (action == "prove_predicates") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto batch = recover::prove_predicates_ex(img, fn_va, runs);
        json arr = json::array();
        for (const auto& p : batch.proofs)
            arr.push_back({{"jcc_va", p.jcc_va}, {"text", p.text},
                           {"static_idiom", p.static_idiom},
                           {"seen_runs", p.seen_runs},
                           {"taken_runs", p.taken_runs},
                           {"total_runs", p.total_runs},
                           {"proven_always_taken", p.proven_always_taken},
                           {"proven_never_taken", p.proven_never_taken}});
        out["predicates"] = arr;
        out["count"] = arr.size();
        out["completed_runs"] = batch.completed_runs;
        out["failed_runs"] = batch.failed_runs;
        out["faulted_runs"] = batch.faulted_runs;
        if (!batch.first_fault.empty()) out["first_fault"] = batch.first_fault;
        if (batch.failed_runs > 0 || batch.faulted_runs > 0)
            out["note"] = "slice emulation faulted on " +
                          std::to_string(batch.failed_runs + batch.faulted_runs) +
                          "/" + std::to_string(runs) + " runs (" +
                          batch.first_fault + "); seen_runs counts observations "
                          "from usable trace prefixes, so seen=0 with faults "
                          "means the branch was never reached (unmapped "
                          "callee/import in the slice), not that it is opaque";
        return out;
    }

    if (action == "invariants") {
        const uint64_t fn_va = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"});
        const size_t runs = devirt_runs(args);
        auto r = recover::observe_invariants(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["instructions_executed"] = r.instructions_executed;
        out["stopped_reason"] = r.stopped_reason;
        json inv = json::array();
        for (const auto& i : r.invariants)
            inv.push_back({{"reg", i.reg}, {"value", i.value}});
        out["invariants"] = inv;
        return out;
    }

    if (action == "iat_audit") {
        uint64_t va = has_any(args, {"addr", "va", "table", "handler_table"})
            ? parse_addr_alias(args, {"addr", "va", "table", "handler_table"}) : 0;
        size_t size = has_any(args, {"size", "len", "length"})
            ? static_cast<size_t>(parse_addr_alias(args, {"size", "len", "length"})) : (1u << 20);
        auto r = recover::iat_audit(img, va, size);
        if (!r.ok) fail(r.error);
        out["slots_scanned"] = r.slots_scanned;
        out["named"] = r.named;
        out["unnamed_valid"] = r.unnamed_valid;
        out["invalid"] = r.invalid;
        json slots = json::array();
        for (const auto& s : r.unnamed)
            slots.push_back({{"slot_va", s.slot_va}, {"target", s.target}});
        out["unnamed_candidates"] = slots;
        out["note"] = r.note.empty()
            ? "default (no addr) audits parsed IAT slots only; pass addr+size "
              "for a targeted range (only image-VA-shaped values count)"
            : r.note;
        return out;
    }

    // devirtualization chain

    if (action == "identify") {
        auto r = devirt::identify(img, parse_addr_alias(args, {"addr", "entry", "va", "start", "address"}));
        if (!r.ok) fail(r.error);
        out["likely_vm"] = r.likely_vm;
        out["confidence_pct"] = r.confidence_pct;
        out["fn_va"] = r.fn_va;
        out["dispatcher"] = r.dispatcher;
        out["handler_table"] = r.handler_table;
        out["table_entry_size"] = r.table_entry_size;
        out["indirect_jumps"] = r.indirect_jumps;
        out["cmp_chain_len"] = r.cmp_chain_len;
        return out;
    }

    if (action == "handlers" || action == "opcode_map") {
        // accept table|handler_table|addr aliases -- agents pass addr=
        const uint64_t table = parse_addr_alias(args, {"table", "handler_table", "addr", "va", "address"});
        uint32_t es = has_any(args, {"entry_size", "stride"})
            ? static_cast<uint32_t>(parse_addr_alias(args, {"entry_size", "stride"})) : 0;
        const size_t maxh = std::min<size_t>(args.value("max_handlers", 256u), 4096u);
        auto r = devirt::classify_handlers(img, table, es, maxh);
        if (!r.ok) fail(r.error);
        out["handler_table"] = r.handler_table;
        out["entry_size"] = r.entry_size;
        out["valid_entries"] = r.valid_entries;
        json hs = json::array();
        for (const auto& h : r.handlers) {
            json o = {{"opcode", h.opcode}, {"va", h.va},
                      {"classification", h.classification},
                      {"instruction_count", h.instruction_count}};
            if (action == "handlers") {
                json texts = json::array();
                for (const auto& t : h.insns) texts.push_back(t);
                o["insns"] = texts;
            }
            hs.push_back(std::move(o));
        }
        out["handlers"] = hs;
        return out;
    }

    if (action == "trace" || action == "lift" || action == "pseudocode") {
        const uint64_t entry = parse_addr_alias(args, {"addr", "entry", "va", "start", "address"}); // VM entry
        const uint64_t dispatcher = has_any(args, {"dispatcher"})
            ? parse_addr_alias(args, {"dispatcher"}) : 0;
        const size_t max_ops = std::min<size_t>(args.value("max_ops", 512u), 4096u);

        // handlers come from a table walk, a caller supplied list, or
        // auto-discovery via identify() when neither is given
        std::vector<uint64_t> handler_vas;
        if (has_any(args, {"handler_table", "table"})) {
            uint64_t table = parse_addr_alias(args, {"handler_table", "table"});
            uint32_t es = has_any(args, {"entry_size", "stride"})
                ? static_cast<uint32_t>(parse_addr_alias(args, {"entry_size", "stride"})) : 8;
            auto cls = devirt::classify_handlers(img, table, es, 256);
            if (!cls.ok) fail(cls.error);
            for (const auto& h : cls.handlers) handler_vas.push_back(h.va);
            out["entry_size"] = cls.entry_size;
            out["valid_entries"] = cls.valid_entries;
        } else if (args.contains("handlers") && args.at("handlers").is_array()) {
            for (const auto& v : args.at("handlers")) {
                if (v.is_string()) {
                    const std::string s = v.get<std::string>();
                    try {
                        handler_vas.push_back(std::stoull(s, nullptr, 0));
                    } catch (...) {
                        fail("bad handlers entry '" + s + "' (hex or decimal integer)");
                    }
                } else if (v.is_number_unsigned()) handler_vas.push_back(v.get<uint64_t>());
                else if (v.is_number_integer() && v.get<int64_t>() >= 0)
                    handler_vas.push_back(static_cast<uint64_t>(v.get<int64_t>()));
                else if (v.is_number_float())
                    handler_vas.push_back(static_cast<uint64_t>(v.get<double>()));
                else fail("bad handlers entry (hex string or integer)");
            }
        } else {
            // no table/list: try identify() so plain addr= works with a
            // clear diagnostic when the function is not VM-shaped
            auto id = devirt::identify(img, entry);
            if (!id.ok) fail(id.error);
            if (id.likely_vm && id.handler_table) {
                auto cls = devirt::classify_handlers(img, id.handler_table,
                                                     id.table_entry_size, 256);
                if (!cls.ok)
                    fail("auto-discovered table " + hex64(id.handler_table) +
                         " unusable: " + cls.error + " (pass handler_table/handlers explicitly)");
                for (const auto& h : cls.handlers) handler_vas.push_back(h.va);
                out["auto_table"] = id.handler_table;
                out["entry_size"] = cls.entry_size;
                out["valid_entries"] = cls.valid_entries;
            } else {
                fail("missing handler_table or handlers list; identify() says " +
                     std::string(id.likely_vm ? "likely_vm" : "not a VM function") +
                     " (confidence " + std::to_string(id.confidence_pct) +
                     "%). Run devirt.identify addr=<fn> first; trace/lift/pseudocode "
                     "require a VM dispatcher (handler_table or handlers list), "
                     "plain functions are not supported");
            }
        }
        if (handler_vas.empty()) fail("no handlers to trace");

        auto tr = devirt::trace_bytecode(img, entry, dispatcher,
                                         handler_vas, max_ops);
        if (!tr.ok && tr.bytecode.empty()) fail(tr.error);
        out["dispatcher_hits"] = tr.dispatcher_hits;
        out["stopped_reason"] = tr.stopped_reason;
        if (!tr.note.empty()) out["note"] = tr.note;

        if (action == "trace") {
            out["bytecode"] = tr.bytecode;
            out["handler_order"] = tr.handler_order;
            return out;
        }

        devirt::classify_result_t cls;
        cls.ok = true;
        for (size_t i = 0; i < handler_vas.size(); ++i) {
            devirt::handler_t h;
            h.opcode = static_cast<uint32_t>(i);
            h.va     = handler_vas[i];
            // classify by decoding each handler
            std::vector<disasm::insn_t> insns;
            uint64_t cur = h.va;
            for (size_t k = 0; k < 128; ++k) {
                uint8_t buf[16];
                if (cur < img.base) break;
                auto off = img.pe->rva_to_offset(
                    static_cast<uint32_t>(cur - img.base));
                if (!off || *off + sizeof(buf) > img.file->size()) break;
                std::memcpy(buf, img.file->data() + *off, sizeof(buf));
                auto in = img.eng->decode(cur, buf, sizeof(buf));
                if (!in || in->length == 0) break;
                insns.push_back(std::move(*in));
                cur += insns.back().length;
            }
            h.instruction_count = insns.size();
            h.classification = devirt::classify_handler_insns(insns);
            cls.handlers.push_back(std::move(h));
        }

        auto lifted = devirt::lift(tr, cls);
        if (!lifted.ok) fail(lifted.error);

        if (action == "lift") {
            json lines = json::array();
            for (const auto& l : lifted.lines)
                lines.push_back({{"opcode", l.opcode},
                                 {"handler_va", l.handler_va},
                                 {"il", l.il}});
            out["lines"] = lines;
            out["covered"] = lifted.covered;
            return out;
        }

        out["pseudocode"] = devirt::pseudocode(lifted);
        return out;
    }

    fail("devirt: unknown action (themida_status|themida_start|themida_job|"
         "themida_cancel|identify|handlers|opcode_map|trace|lift|"
         "pseudocode|recover_cfg|prove_predicates|invariants|iat_audit)");
}

} // namespace slop::core::mcp::detail
