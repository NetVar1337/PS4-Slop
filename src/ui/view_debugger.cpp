// src/ui/view_debugger.cpp
// PS4 live-debug workspace: breakpoints, watchpoints, registers, event feed
// and remote calls against a console running ps4debug-NG (TCP 744 + events 755)

#include "ui/views_core.hpp"

#include "core/process/target_service.hpp"
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

namespace {

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
        ImGui::TextDisabled("no PS4 console connected.");
        ImGui::TextDisabled("Connect one from the Targets view (ps4 connect / ps4_auto),");
        ImGui::TextDisabled("or over MCP: target.ps4_auto {\"host\":\"<ps4 ip>\"}.");
        ImGui::TextDisabled("Then this panel drives the live ps4debug-NG session:");
        ImGui::TextDisabled("breakpoints, DR watchpoints, registers, events, remote calls.");
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

    // PS4-only build: the debugger view is the ps4debug-NG live panel
    DrawPs4Panel();

    if (pushed) ImGui::PopFont();
}

} // namespace debugger_view
} // namespace slop::ui
