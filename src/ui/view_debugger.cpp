// src/ui/view_debugger.cpp
// debugger workspace, controls, registers, breakpoints and the event log

#include "ui/views_core.hpp"

#include "core/debugger/debugger.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/ps4_protocol.hpp"
#include "ui/fonts.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <string>
#include <vector>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace dbg     = slop::core::debugger;

namespace {

dbg::debugger_t g_dbg;

const char* StateName(dbg::dbg_state_t s) noexcept {
    switch (s) {
    case dbg::dbg_state_t::running: return "running";
    case dbg::dbg_state_t::paused:  return "paused";
    default:                        return "idle";
    }
}

void DrawRegisters(const runtime::thread_context_t& c) {
    if (!ImGui::BeginTable("regs", 4,
                           ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit))
        return;
    struct pair_t { const char* n; uint64_t v; };
    const pair_t rows[] = {
        {"rip", c.rip}, {"rsp", c.rsp}, {"rbp", c.rbp}, {"flags", c.flags},
        {"rax", c.rax}, {"rbx", c.rbx}, {"rcx", c.rcx}, {"rdx", c.rdx},
        {"rsi", c.rsi}, {"rdi", c.rdi},
        {"r8",  c.r8},  {"r9",  c.r9},  {"r10", c.r10}, {"r11", c.r11},
        {"r12", c.r12}, {"r13", c.r13}, {"r14", c.r14}, {"r15", c.r15},
    };
    for (size_t i = 0; i < std::size(rows); i += 2) {
        ImGui::TableNextRow();
        for (int k = 0; k < 2 && i + static_cast<size_t>(k) < std::size(rows); ++k) {
            const auto& r = rows[i + static_cast<size_t>(k)];
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%-5s", r.n);
            ImGui::TableNextColumn();
            char hex[24];
            std::snprintf(hex, sizeof(hex), "%016llX",
                          static_cast<unsigned long long>(r.v));
            ImGui::TextUnformatted(hex);
        }
    }
    ImGui::EndTable();
}

// ---- PS4 live debug panel (ps4debug-NG over TCP 744 + events on 755) ------

std::map<uint64_t, uint32_t> g_ps4_bp_slots;                  // addr -> slot
struct ps4_wp_ui_t { uint32_t slot = 0; uint32_t len = 8; uint32_t type = 3; };
std::map<uint64_t, ps4_wp_ui_t> g_ps4_wp_slots;               // addr -> slot info

uint32_t Ps4AllocSlot(const std::map<uint64_t, uint32_t>& used, uint32_t max) {
    for (uint32_t i = 0; i < max; ++i) {
        bool taken = false;
        for (const auto& [a, idx] : used)
            if (idx == i) { taken = true; break; }
        if (!taken) return i;
    }
    return max;
}

void DrawPs4Panel() {
    auto* p = dynamic_cast<runtime::backend_ps4_t*>(&runtime::active());
    if (!p || !p->connected()) {
        ImGui::TextDisabled("no PS4 console connected (see the Targets view).");
        return;
    }
    const auto session = process::active_session();
    const uint32_t pid =
        (session && session->valid()) ? session->pid() : p->ps4_debug_pid();

    static runtime::thread_context_t ps4_ctx{};
    static bool ps4_have_ctx = false;
    static uint32_t ps4_ctx_lwp = 0;

    ImGui::Text("PS4 %s  %s", runtime::registry_ps4_endpoint().c_str(),
                runtime::registry_ps4_branding().c_str());
    ImGui::SameLine();
    if (p->ps4_debug_attached())
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "debug attached pid %u",
                           p->ps4_debug_pid());
    else
        ImGui::TextDisabled("debugger not attached");

    // attach / detach + process controls (all non-blocking command roundtrips)
    if (!p->ps4_debug_attached()) {
        if (ImGui::Button("debug attach (ps4debug)") && pid != 0) {
            std::string err;
            if (!p->ps4_debug_attach(pid, err))
                panels::AppendBootLog("ps4 debug attach failed: " + err);
        }
    } else {
        if (ImGui::Button("debug detach")) p->ps4_debug_detach();
        ImGui::SameLine();
        if (ImGui::Button("continue")) p->ps4_continue(runtime::ps4::kStopResume);
        ImGui::SameLine();
        if (ImGui::Button("step all"))  p->ps4_step(0);
    }
    ImGui::Separator();

    // breakpoints (software, slots 0..29 tracked client-side)
    if (ImGui::CollapsingHeader("ps4 breakpoints", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char bp_addr[24] = {};
        ImGui::SetNextItemWidth(140.0f);
        ImGui::InputTextWithHint("##ps4bpaddr", "va (hex)", bp_addr, sizeof(bp_addr));
        ImGui::SameLine();
        if (ImGui::SmallButton("arm bp") && p->ps4_debug_attached()) {
            unsigned long long addr = 0;
            if (sscanf_s(bp_addr, "%llX", &addr) == 1 && addr != 0) {
                auto it = g_ps4_bp_slots.find(addr);
                const uint32_t idx = it != g_ps4_bp_slots.end()
                    ? it->second : Ps4AllocSlot(g_ps4_bp_slots, 30);
                if (p->ps4_set_breakpoint(idx, true, static_cast<uintptr_t>(addr)).ok)
                    g_ps4_bp_slots[addr] = idx;
                else
                    panels::AppendBootLog("ps4 bp arm failed (slot in use?)");
            }
        }
        for (auto it = g_ps4_bp_slots.begin(); it != g_ps4_bp_slots.end();) {
            char line[64];
            std::snprintf(line, sizeof(line), "slot %2u  @ %llX", it->second,
                          static_cast<unsigned long long>(it->first));
            ImGui::Selectable(line);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(it->first & 0xFFFFFF));
            if (ImGui::SmallButton("del")) {
                p->ps4_set_breakpoint(it->second, false, static_cast<uintptr_t>(it->first));
                it = g_ps4_bp_slots.erase(it);
                ImGui::PopID();
                continue;
            }
            ImGui::PopID();
            ++it;
        }
    }

    // watchpoints (hardware DR slots 0..3)
    if (ImGui::CollapsingHeader("ps4 watchpoints")) {
        static char wp_addr[24] = {};
        static char wp_len[8] = "8";
        static int wp_type = 1;   // 0=exec 1=write 3=rdwr
        ImGui::SetNextItemWidth(140.0f);
        ImGui::InputTextWithHint("##ps4wpaddr", "va (hex)", wp_addr, sizeof(wp_addr));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(48.0f);
        ImGui::InputTextWithHint("##ps4wplen", "len", wp_len, sizeof(wp_len));
        ImGui::SameLine();
        const char* types[] = {"exec", "write", "rdwr"};
        ImGui::SetNextItemWidth(64.0f);
        ImGui::Combo("##ps4wptype", &wp_type, types, 3);
        ImGui::SameLine();
        if (ImGui::SmallButton("arm wp") && p->ps4_debug_attached()) {
            unsigned long long addr = 0, len = 8;
            sscanf_s(wp_len, "%llu", &len);
            if (sscanf_s(wp_addr, "%llX", &addr) == 1 && addr != 0 && len != 0) {
                std::map<uint64_t, uint32_t> used;
                for (const auto& [a, w] : g_ps4_wp_slots) used[a] = w.slot;
                const uint32_t idx = Ps4AllocSlot(used, 4);
                const uint32_t bt = wp_type == 0 ? runtime::ps4::kWpExec
                                  : wp_type == 1 ? runtime::ps4::kWpWrite
                                                 : runtime::ps4::kWpRdWr;
                if (p->ps4_set_watchpoint(idx, true, static_cast<uint32_t>(len), bt,
                                          static_cast<uintptr_t>(addr)).ok)
                    g_ps4_wp_slots[addr] = {idx, static_cast<uint32_t>(len), bt};
                else
                    panels::AppendBootLog("ps4 watchpoint arm failed (DR slot in use?)");
            }
        }
        for (auto it = g_ps4_wp_slots.begin(); it != g_ps4_wp_slots.end();) {
            char line[80];
            std::snprintf(line, sizeof(line), "DR%u  @ %llX  len %u  %s", it->second.slot,
                          static_cast<unsigned long long>(it->first), it->second.len,
                          it->second.type == runtime::ps4::kWpExec ? "exec"
                          : it->second.type == runtime::ps4::kWpWrite ? "write" : "rdwr");
            ImGui::Selectable(line);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(it->first & 0xFFFFFF) + 1000);
            if (ImGui::SmallButton("del")) {
                p->ps4_set_watchpoint(it->second.slot, false, 8,
                                      runtime::ps4::kWpRdWr, 0);
                it = g_ps4_wp_slots.erase(it);
                ImGui::PopID();
                continue;
            }
            ImGui::PopID();
            ++it;
        }
    }

    // event feed: drain whatever the payload pushed on port 755 (never blocks)
    if (ImGui::CollapsingHeader("ps4 events", ImGuiTreeNodeFlags_DefaultOpen)) {
        static std::deque<std::string> feed;
        const auto evs = p->ps4_drain_events(8, true);
        for (const auto& ev : evs) {
            char line[160];
            std::snprintf(line, sizeof(line), "sig %2d  lwp %-5u (%s)  rip %llX", ev.signal,
                          ev.lwpid, ev.thread_name,
                          static_cast<unsigned long long>(ev.ctx.rip));
            feed.push_back(line);
            if (feed.size() > 256) feed.pop_front();
        }
        if (!evs.empty() && p->ps4_debug_attached()) {
            ps4_ctx_lwp = evs.back().lwpid;
            ps4_have_ctx = p->get_thread_context(ps4_ctx_lwp, ps4_ctx).ok;
        }
        ImGui::TextDisabled("pending: %zu", p->ps4_pending_events());
        ImGui::BeginChild("ps4evfeed", ImVec2(0, 110), true);
        for (const auto& l : feed) ImGui::TextUnformatted(l.c_str());
        if (feed.empty()) ImGui::TextDisabled("(no stop events yet - continue/step the target)");
        ImGui::EndChild();
    }

    // registers of the last stopped thread
    if (ImGui::CollapsingHeader("ps4 registers", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char lw_buf[16] = "0";
        ImGui::SetNextItemWidth(80.0f);
        ImGui::InputTextWithHint("##ps4lwp", "lwpid", lw_buf, sizeof(lw_buf));
        ImGui::SameLine();
        if (ImGui::SmallButton("read regs") && p->ps4_debug_attached()) {
            unsigned int lw = 0;
            if (sscanf_s(lw_buf, "%u", &lw) == 1) {
                ps4_ctx_lwp = lw;
                ps4_have_ctx = p->get_thread_context(lw, ps4_ctx).ok;
            }
        }
        if (ps4_have_ctx) {
            ImGui::Text("lwp %u", ps4_ctx_lwp);
            DrawRegisters(ps4_ctx);
        } else {
            ImGui::TextDisabled("(read regs after a stop event)");
        }
    }

    // remote call through the payload rpc stub (installs it once per pid)
    if (ImGui::CollapsingHeader("ps4 remote call")) {
        static char call_addr[24] = {};
        static char call_args[160] = {};
        static uint64_t last_rax = 0;
        static bool have_rax = false;
        static std::string call_err;
        static uint32_t stub_pid = 0;
        static uint64_t rpcstub = 0;
        ImGui::SetNextItemWidth(140.0f);
        ImGui::InputTextWithHint("##ps4calladdr", "fn va (hex)", call_addr, sizeof(call_addr));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(220.0f);
        ImGui::InputTextWithHint("##ps4callargs", "args a0,a1,... (hex)", call_args,
                                 sizeof(call_args));
        ImGui::SameLine();
        if (ImGui::SmallButton("call") && pid != 0) {
            unsigned long long addr = 0;
            have_rax = false;
            call_err.clear();
            if (sscanf_s(call_addr, "%llX", &addr) == 1 && addr != 0) {
                uint64_t fargs[6] = {};
                int nargs = 0;
                char tmp[160];
                std::strncpy(tmp, call_args, sizeof(tmp) - 1);
                tmp[sizeof(tmp) - 1] = '\0';
                char* save = nullptr;
                for (char* tok = strtok_s(tmp, ", ", &save); tok && nargs < 6;
                     tok = strtok_s(nullptr, ", ", &save)) {
                    try { fargs[nargs++] = std::stoull(tok, nullptr, 0); }
                    catch (...) { call_err = "bad arg: " + std::string(tok); break; }
                }
                if (call_err.empty()) {
                    if (stub_pid != pid || rpcstub == 0) {
                        rpcstub = 0;
                        stub_pid = pid;
                        if (!p->ps4_install(pid, rpcstub).ok || rpcstub == 0)
                            call_err = "ps4_install (rpc stub) failed";
                    }
                    if (call_err.empty()) {
                        uint64_t rax = 0;
                        const auto io = p->ps4_call(pid, rpcstub, addr, fargs, rax);
                        if (io.ok) { have_rax = true; last_rax = rax; }
                        else call_err = "ps4_call error " + std::to_string(io.error);
                    }
                }
            } else {
                call_err = "bad fn address";
            }
        }
        if (have_rax)
            ImGui::Text("rax = %llX", static_cast<unsigned long long>(last_rax));
        if (!call_err.empty())
            ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.4f, 1.0f), "%s", call_err.c_str());
    }

    ImGui::Separator();
    ImGui::TextDisabled("MCP/AI: debugger ps4_* actions, one-call target ps4_auto, playbooks via guide get <topic>");
}

} // namespace

namespace debugger_view {

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    // PS4 consoles get their own live-debug panel (ps4debug-NG); the local
    // Windows debug loop below does not apply there
    if (runtime::active_kind() == runtime::backend_kind_t::ps4) {
        DrawPs4Panel();
        if (pushed) ImGui::PopFont();
        return;
    }

    // Backend / driver status card
    {
        const bool kernel_live = runtime::active_kind() == runtime::backend_kind_t::kernel;
        ImGui::Text("backend:");
        ImGui::SameLine();
        if (kernel_live)
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.25f, 1.0f), "KERNEL (slopdrvr)");
        else
            ImGui::TextDisabled("USER-MODE");
        ImGui::SameLine();

        if (ImGui::SmallButton(kernel_live ? "switch to USER" : "switch to KERNEL")) {
            const bool ok = kernel_live
                ? runtime::set_backend_preference(runtime::backend_pref_t::force_user)
                : runtime::set_backend_preference(runtime::backend_pref_t::auto_detect);
            panels::AppendBootLog(ok ? "backend switched"
                                     : "kernel backend unavailable (driver not loaded)");
        }
        if (!kernel_live) {
            ImGui::SameLine();
            ImGui::TextDisabled("load: slop_mapper.exe load build\\driver\\slopdrvr.sys");
        }
        ImGui::Separator();
    }

    // Attach / detach debugger
    const auto session = process::active_session();
    if (!session || !session->valid()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("attach a target first.");
        return;
    }

    const auto state = g_dbg.state();
    if (state == dbg::dbg_state_t::idle) {
        if (ImGui::Button("debug attach")) {
            if (!g_dbg.attach(session->pid()))
                panels::AppendBootLog("debugger: DebugActiveProcess failed (elevated required?)");
        }
    } else {
        if (ImGui::Button("debug detach")) g_dbg.detach();
        ImGui::SameLine();
        ImGui::Text("state: %s", StateName(state));

        // Controls
        if (state == dbg::dbg_state_t::paused) {
            ImGui::SameLine();
            if (ImGui::Button("Go"))          g_dbg.go();
            ImGui::SameLine();
            if (ImGui::Button("Step Into"))   g_dbg.step_into();
            ImGui::SameLine();
            if (ImGui::Button("Step Over"))   g_dbg.step_over();
            ImGui::SameLine();
            if (ImGui::Button("Step Out"))    g_dbg.step_out();
        }
    }
    ImGui::Separator();

    // Registers
    if (ImGui::CollapsingHeader("registers", ImGuiTreeNodeFlags_DefaultOpen)) {
        uint32_t tid = 0;
        if (auto ctx = g_dbg.paused_context(&tid)) {
            ImGui::Text("thread %u", tid);
            DrawRegisters(*ctx);
        } else {
            ImGui::TextDisabled("(paused context only)");
        }
    }

    // Breakpoints
    if (ImGui::CollapsingHeader("breakpoints", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char bp_buf[24] = {};
        ImGui::SetNextItemWidth(160.0f);
        ImGui::InputTextWithHint("##bpaddr", "va (hex)", bp_buf, sizeof(bp_buf));
        ImGui::SameLine();
        if (ImGui::SmallButton("int3") && state != dbg::dbg_state_t::idle) {
            uint64_t addr = 0;
            sscanf_s(bp_buf, "%llX", &addr);
            if (addr && g_dbg.set_sw_breakpoint(addr))
                panels::AppendBootLog("bp armed @ " + std::to_string(addr));
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("hw (kernel)") &&
            runtime::active_kind() == runtime::backend_kind_t::kernel) {
            uint64_t addr = 0;
            sscanf_s(bp_buf, "%llX", &addr);
            if (addr) {
                // DR0 exec breakpoint on every thread of the target
                auto* k = static_cast<runtime::backend_kernel_t*>(&runtime::active());
                k->set_hw_breakpoint(session->pid(), 0, 0, addr, 1);
                panels::AppendBootLog("hw bp DR0 @ " + std::to_string(addr));
            }
        }

        for (const auto& bp : g_dbg.breakpoints()) {
            char line[96];
            std::snprintf(line, sizeof(line), "%011llX  %s  hits=%u",
                          static_cast<unsigned long long>(bp.addr),
                          bp.armed ? "armed" : "disarmed", bp.hits);
            ImGui::Selectable(line);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(bp.addr & 0xFFFFFF));
            if (ImGui::SmallButton("del")) g_dbg.clear_breakpoint(bp.addr);
            ImGui::PopID();
        }
    }

    // Event log
    if (ImGui::CollapsingHeader("events", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (const auto& e : g_dbg.events_snapshot(128)) {
            const char* tag = "?";
            switch (e.kind) {
            case dbg::event_kind_t::attached:     tag = "attached"; break;
            case dbg::event_kind_t::detached:     tag = "detached"; break;
            case dbg::event_kind_t::bp_hit:       tag = "BP HIT"; break;
            case dbg::event_kind_t::single_step:  tag = "step"; break;
            case dbg::event_kind_t::exception:    tag = "exception"; break;
            case dbg::event_kind_t::thread_create:tag = "thread+"; break;
            case dbg::event_kind_t::thread_exit:  tag = "thread-"; break;
            case dbg::event_kind_t::dll_load:     tag = "dll+"; break;
            case dbg::event_kind_t::dll_unload:   tag = "dll-"; break;
            case dbg::event_kind_t::process_exit: tag = "exit"; break;
            default:                              tag = "note"; break;
            }
            ImGui::Text("[%s] tid %u @ %011llX %s",
                        tag, e.tid,
                        static_cast<unsigned long long>(e.address),
                        e.text.c_str());
        }
    }

    if (pushed) ImGui::PopFont();
}

} // namespace debugger_view
} // namespace slop::ui
