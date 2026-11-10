// src/ui/view_targets.cpp
// process list and the attach flow

#include "ui/views_core.hpp"

#include "core/infra/clock.hpp"
#include "core/process/module_table.hpp"
#include "core/process/process_list.hpp"
#include "core/process/target_service.hpp"
#include "core/process/module_dump.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/ps4_protocol.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <windows.h>
#include <commdlg.h>

#include <algorithm>
#include <string>
#include <vector>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace infra   = slop::core::infra;

namespace {

using runtime::process_info_t;
using runtime::module_info_t;

std::vector<process_info_t> g_procs;
char                        g_filter_buf[64] = {};
int64_t                     g_last_refresh_ms = 0;
int64_t                     g_procs_sampled_ms = -1;
uint32_t                    g_procs_inaccessible = 0;
bool                        g_dirty           = true;
uint32_t                    g_selected_pid    = 0;
std::vector<module_info_t>  g_modules;
uint32_t                    g_modules_pid = 0;
int64_t                     g_modules_refresh_ms = 0;
int64_t                     g_modules_sampled_ms = -1;

std::string DumpPath(const module_info_t& module) {
    OPENFILENAMEA dialog{};
    char file[MAX_PATH]{};
    std::snprintf(file, sizeof(file), "%s_%016llX.dump%s",
                  module.name.empty() ? "module" : module.name.c_str(),
                  static_cast<unsigned long long>(module.base),
                  module.name.ends_with(".dll") ? ".dll" : ".exe");
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = "PE images\0*.exe;*.dll;*.sys\0All files\0*.*\0";
    dialog.lpstrFile = file;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    return GetSaveFileNameA(&dialog) ? std::string(file) : std::string{};
}

const char* ArchName(runtime::arch_t a) noexcept {
    switch (a) {
    case runtime::arch_t::x64:   return "x64";
    case runtime::arch_t::x86:   return "x86";
    case runtime::arch_t::arm64: return "arm64";
    default:                     return "?";
    }
}

const char* ElevName(runtime::elevation_t e) noexcept {
    switch (e) {
    case runtime::elevation_t::standard: return "user";
    case runtime::elevation_t::elevated: return "admin";
    case runtime::elevation_t::system:   return "system";
    default:                             return "?";
    }
}

bool NameFilterMatch(const process_info_t& p) {
    std::string g_filter(g_filter_buf);
    if (g_filter.empty()) return true;
    const std::string needle = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }(g_filter);

    auto hay = std::string(p.name);
    std::transform(hay.begin(), hay.end(), hay.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (hay.find(needle) != std::string::npos) return true;

    // PID match
    char pidbuf[16]{};
    std::snprintf(pidbuf, sizeof(pidbuf), "%u", p.pid);
    return needle == pidbuf;
}

} // namespace

namespace targets_view {

void Draw() {
    const auto session = process::active_session();
    const bool attached = session && session->valid();

    // Status header
    ImGui::Text("backend: %s", runtime::active_badge());
    ImGui::SameLine();
    if (attached) {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "target: %s (pid %u)",
                           session->name().c_str(), session->pid());
        ImGui::SameLine();
        if (ImGui::SmallButton("Detach")) {
            process::target_detach();
            panels::AppendBootLog("detached");
            g_dirty = true;
        }
    } else {
        ImGui::TextDisabled("no target attached");
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("PS4...")) ImGui::OpenPopup("ps4_connect_popup");
    if (ImGui::BeginPopup("ps4_connect_popup")) {
        static char host_buf[64] = {};
        static int  port_val = runtime::ps4::kDefaultPort;
        if (runtime::registry_ps4_active()) {
            ImGui::Text("connected: %s", runtime::registry_ps4_endpoint().c_str());
            const std::string brand = runtime::registry_ps4_branding();
            if (!brand.empty()) ImGui::TextDisabled("%s", brand.c_str());
            if (ImGui::SmallButton("Disconnect PS4")) {
                process::target_disconnect_ps4();
                panels::AppendBootLog("ps4 disconnected");
                g_dirty = true;
                ImGui::CloseCurrentPopup();
            }
        } else {
            ImGui::TextDisabled("connect to a PS4 running ps4debug-NG");
            ImGui::SetNextItemWidth(200.0f);
            ImGui::InputTextWithHint("##ps4host", "PS4 IP", host_buf, sizeof(host_buf));
            ImGui::SetNextItemWidth(200.0f);
            ImGui::InputInt("port", &port_val);
            if (port_val < 1 || port_val > 0xFFFF) port_val = runtime::ps4::kDefaultPort;
            if (ImGui::SmallButton("Connect") && host_buf[0] != '\0') {
                std::string err;
                if (process::target_connect_ps4(host_buf,
                                                static_cast<uint16_t>(port_val), 0, err)) {
                    panels::AppendBootLog("ps4 connected: " +
                                          runtime::registry_ps4_endpoint());
                    g_dirty = true;
                    ImGui::CloseCurrentPopup();
                } else {
                    panels::AppendBootLog("ps4 connect FAILED: " + err);
                }
            }
        }
        ImGui::EndPopup();
    }
    ImGui::Separator();

    if (attached) {
        const int64_t now = infra::steady_ms();
        if (g_modules_pid != session->pid()) {
            // new target: drop the old table until its snapshot lands
            g_modules.clear();
            g_modules_sampled_ms = -1;
            g_modules_pid = session->pid();
            g_modules_refresh_ms = 0;
        }
        if (now - g_modules_refresh_ms > 3000) {
            process::refresh_modules(); // background job publishes into the shared cache
            g_modules_refresh_ms = now;
        }
        if (auto snap = process::cached_modules();
            snap && snap->sampled_ms != g_modules_sampled_ms) {
            g_modules = snap->items; // already sorted by base
            g_modules_sampled_ms = snap->sampled_ms;
        }

        if (ImGui::Button("Refresh modules")) g_modules_refresh_ms = 0;
        ImGui::SameLine();
        ImGui::TextDisabled("%d loaded modules", static_cast<int>(g_modules.size()));

        if (ImGui::BeginTable("target_modules", 5,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("module", ImGuiTableColumnFlags_WidthStretch, 2.0f);
            ImGui::TableSetupColumn("base", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, 85.0f);
            ImGui::TableSetupColumn("dump", ImGuiTableColumnFlags_WidthFixed, 58.0f);
            ImGui::TableSetupColumn("analyze", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableHeadersRow();
            for (const auto& module : g_modules) {
                ImGui::PushID(reinterpret_cast<const void*>(module.base));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(module.name.c_str());
                if (ImGui::IsItemHovered() && !module.path.empty())
                    ImGui::SetTooltip("%s", module.path.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%016llX", static_cast<unsigned long long>(module.base));
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", module.size);
                ImGui::TableNextColumn();
                const bool dump = ImGui::SmallButton("dump");
                ImGui::TableNextColumn();
                const bool analyze = ImGui::SmallButton("dump+load");
                if (dump || analyze) {
                    const std::string path = DumpPath(module);
                    if (!path.empty()) {
                        auto result = process::dump_module_pe(*session, module, path);
                        if (!result.ok) {
                            panels::AppendBootLog("module dump failed: " + result.error);
                        } else if (analyze &&
                                   !slop::core::disasm::binary_state::load_file(path, module.base)) {
                            panels::AppendBootLog("module dumped but analysis load failed: " + path + ": " +
                                slop::core::disasm::binary_state::last_load_error());
                        } else {
                            panels::AppendBootLog("dumped " + module.name + " to " + path);
                        }
                    }
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        return;
    }

    // Refresh logic: submit a background refresh on the 2s cadence, then adopt
    // whatever immutable snapshot the job published (shared with the mcp tools)
    const int64_t now = infra::steady_ms();
    if (g_dirty || now - g_last_refresh_ms > 2000) {
        process::refresh_processes(true);
        g_last_refresh_ms = now;
        g_dirty = false;
    }
    if (auto snap = process::cached_processes();
        snap && snap->sampled_ms != g_procs_sampled_ms) {
        g_procs.assign(snap->items.begin(), snap->items.end());
        std::sort(g_procs.begin(), g_procs.end(),
                  [](const process_info_t& a, const process_info_t& b) {
                      return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
                  });
        g_procs_sampled_ms = snap->sampled_ms;
        g_procs_inaccessible = snap->inaccessible_count;
    }

    if (ImGui::Button("Refresh")) g_dirty = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##procfilter", "filter name or pid",
                             g_filter_buf, sizeof(g_filter_buf));
    ImGui::SameLine();
    if (g_procs_inaccessible > 0)
        ImGui::TextDisabled("%d processes (%u inaccessible)",
                            static_cast<int>(g_procs.size()), g_procs_inaccessible);
    else
        ImGui::TextDisabled("%d processes", static_cast<int>(g_procs.size()));

    if (ImGui::BeginTable("procs", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("pid", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch, 3.0f);
        ImGui::TableSetupColumn("arch", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("elev", ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupColumn("attach", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        for (const auto& p : g_procs) {
            if (!NameFilterMatch(p)) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%u", p.pid);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.name.c_str());
            if (ImGui::IsItemHovered() && !p.path.empty())
                ImGui::SetTooltip("%s", p.path.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", ArchName(p.arch));
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", ElevName(p.elevation));
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(p.pid));
            if (ImGui::SmallButton("attach")) {
                if (process::target_attach(p.pid))
                    panels::AppendBootLog("attached: " + p.name + " (pid " +
                                          std::to_string(p.pid) + ")");
                else
                    panels::AppendBootLog("attach FAILED: " + p.name + " (pid " +
                                          std::to_string(p.pid) + ")");
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

} // namespace targets_view
} // namespace slop::ui
