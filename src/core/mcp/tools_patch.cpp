// src/core/mcp/tools_patch.cpp
// tool: patch

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {


// tool: patch

json tool_patch(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    ds::binary_lock_t lk;
    auto& bin = ds::get();
    if (action == "nop_junk" || action == "resolve_opaque" ||
        action == "patch_antidebug" || action == "decode_strings" ||
        action == "full_pass" || action == "rebuild")
        require_x86_image(bin.arch, bin.format, "patch." + action);
    if (action == "patch_antidebug" || action == "full_pass")
        require_pe_image(bin.arch, bin.format, "patch." + action);

    imgpatch::op_result_t r;

    if (action == "nop_junk") {
        const uint64_t fn_va = parse_addr(args, "addr");
        r = imgpatch::nop_junk(bin, fn_va,
                               args.value("aggressive", false),
                               static_cast<size_t>(args.value("nop_threshold", 4u)));
    } else if (action == "resolve_opaque") {
        r = imgpatch::resolve_opaque_predicates(bin, parse_addr(args, "addr"),
                                                args.value("dry_run", false));
    } else if (action == "patch_antidebug") {
        imgpatch::anti_debug_opts_t opts;
        opts.patch_api_calls = args.value("patch_api_calls", true);
        opts.patch_int_traps = args.value("patch_int_traps", true);
        opts.patch_timing    = args.value("patch_timing", true);
        // Per-function operation: no addr scans the entry-point function.
        const bool defaulted_addr = !args.contains("addr");
        const uint64_t ad_va = defaulted_addr
            ? bin.base + bin.pe.entry_rva
            : parse_addr(args, "addr");
        r = imgpatch::patch_anti_debug(bin, ad_va, opts,
                                       args.value("dry_run", false));
        if (defaulted_addr) r.note = "no addr given: scanned entry-point function";
    } else if (action == "unpack_xor") {
        const std::string method = args.value("method", std::string{"auto"});
        if (method == "auto")
            require_x86_image(bin.arch, bin.format, "patch.unpack_xor (method=auto)");
        const uint64_t va = parse_addr(args, "addr");
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size"))
            : 4096;
        r = imgpatch::unpack_xor(bin, va, size,
                                 method,
                                 args.value("key_hex", std::string{}));
    } else if (action == "decode_strings") {
        r = imgpatch::decode_strings(bin, parse_addr(args, "addr"));
    } else if (action == "write_bytes") {
        if (!args.contains("hex")) fail("missing hex payload");
        r = imgpatch::write_bytes(bin, parse_addr(args, "addr"),
                                  hex_decode(args.at("hex").get<std::string>()));
    } else if (action == "revert_all") {
        r = imgpatch::revert_all(bin);
    } else if (action == "journal") {
        json arr = json::array();
        const size_t cap = std::min<size_t>(args.value("limit", 100u), bin.patches.size());
        for (size_t i = 0; i < cap; ++i) {
            const auto& p = bin.patches[i];
            arr.push_back({{"va", p.va}, {"before", p.before}, {"after", p.after}});
        }
        return {{"patches", arr}, {"total", bin.patches.size()},
                {"indexes_dirty", bin.indexes_dirty}};
    } else if (action == "full_pass") {
        auto fp_r = imgpatch::full_pass(bin, parse_addr(args, "addr"),
                                        args.value("dry_run", false));
        if (!fp_r.ok) fail(fp_r.error);
        json steps = json::array();
        for (const auto& s : fp_r.steps)
            steps.push_back({{"step", s.name}, {"success", s.success},
                             {"note", s.note}});
        return {{"ok", true},
                {"dry_run", fp_r.dry_run},
                {"steps", steps},
                {"pre_obfuscation_score", fp_r.pre_score},
                {"post_obfuscation_score", fp_r.post_score},
                {"score_reduction", fp_r.pre_score - fp_r.post_score},
                {"strings_found", fp_r.strings_found},
                {"bytes_changed", fp_r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    } else if (action == "rebuild") {
        auto rb_r = imgpatch::rebuild(bin, parse_addr(args, "addr"));
        if (!rb_r.ok) fail(rb_r.error);
        json insns = json::array();
        for (const auto& [va, text] : rb_r.insns)
            insns.push_back({{"va", va}, {"text", text}});
        return {{"ok", true},
                {"instruction_count", rb_r.instruction_count},
                {"insns", insns},
                {"indexes_dirty", bin.indexes_dirty}};
    } else {
        fail("patch: unknown action (nop_junk|resolve_opaque|patch_antidebug|"
             "unpack_xor|decode_strings|write_bytes|revert_all|journal|"
             "full_pass|rebuild)");
    }

    if (!r.ok) fail(r.error);
    json pats = json::array();
    for (const auto& p : r.patches) {
        json o = {{"va", p.va}, {"action", p.action}};
        if (!p.detail.empty()) o["detail"] = p.detail;
        pats.push_back(std::move(o));
    }
    json out = {{"ok", true},
                {"dry_run", r.dry_run},
                {"patches", pats},
                {"bytes_changed", r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    if (r.detected_key) {
        out["detected_key"] = r.detected_key;
        out["key_confidence"] = r.key_confidence;
    }
    if (r.strings_found) out["strings_found"] = r.strings_found;
    if (!r.note.empty()) out["note"] = r.note;
    return out;
}

} // namespace slop::core::mcp::detail
