// src/tests/test_emu.cpp
// Unicorn emulation engine + dynamic taint propagation. Hermetic: synthetic
// code snippets only, no target processes

#include "harness.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/emu/session.hpp"
#include "core/emu/taint.hpp"
#include "core/mcp/mcp_tools.hpp"

#include "elf_fixture.hpp"
#include "macho_fixture.hpp"

#include <nlohmann/json.hpp>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

using namespace slop::core::emu;

namespace {

run_request_t base_req(std::initializer_list<uint8_t> code,
                       uint64_t code_base = 0x400000) {
    run_request_t req;
    req.code = std::vector<uint8_t>(code.begin(), code.end());
    req.code_base = code_base;
    return req;
}

} // namespace

TEST_CASE(taint_canonical_reg_maps_subregisters) {
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_AL), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_AH), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_EAX), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_RAX), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_R8D), (uint32_t)ZYDIS_REGISTER_R8);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_R15W), (uint32_t)ZYDIS_REGISTER_R15);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_XMM0), 0u);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_CS), 0u);
}

TEST_CASE(taint_shadow_memory_roundtrip) {
    taint_tracker_t t;
    t.mark_memory(0x1000, 4);
    REQUIRE(t.memory_any(0x1000, 4));
    REQUIRE(t.memory_any(0x0FFC, 8));       // spans the marked bytes
    REQUIRE(!t.memory_any(0x1010, 4));

    auto ranges = t.tainted_ranges();
    REQUIRE_EQ(ranges.size(), 1u);
    REQUIRE_EQ(ranges[0].addr, 0x1000ull);
    REQUIRE_EQ(ranges[0].len, 4u);
}

TEST_CASE(emu_add_run_and_return_sentinel) {
    // mov eax,2 / add eax,3 / ret
    auto req = base_req({0xB8, 0x02, 0x00, 0x00, 0x00,
                         0x83, 0xC0, 0x03,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.instructions, 3u);
    REQUIRE_EQ(r.regs["rax"], 5u);
}

TEST_CASE(emu_count_budget_stops_loops) {
    // jmp $  (EB FE)
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 500;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "count");
    REQUIRE_EQ(r.instructions, 500u);
}

TEST_CASE(emu_until_address_stops_before_exec) {
    // nop / nop / ret, stop at the second nop
    const uint64_t base = 0x400000;
    auto req = base_req({0x90, 0x90, 0xC3}, base);
    req.until_addr = base + 1;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "until");
    REQUIRE_EQ(r.instructions, 1u);   // first nop executed; second not reached
}

TEST_CASE(emu_invalid_memory_read_reports_fault) {
    // mov eax,[0xDEAD0000] / ret
    auto req = base_req({0xA1, 0x00, 0x00, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(r.fault.has_value());
    REQUIRE_EQ(r.fault->addr, 0xDEAD0000ull);
}

TEST_CASE(emu_register_seeding_and_data_map) {
    // add rax, rcx / ret ; rcx seeded to 7, rax seeded to 35
    auto req = base_req({0x48, 0x01, 0xC8,
                         0xC3});
    req.regs["rax"] = 35;
    req.regs["rcx"] = 7;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 42u);
}

TEST_CASE(taint_propagates_through_memory_load_store) {
    // mov al,[0x500000]      A0 00 00 30 00 00 00 00 00
    // mov [0x500100],al      88 04 25 00 01 30 00
    // ret                    C3
    auto req = base_req({0xA0, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x88, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x200, 0x41);
    req.maps.push_back(data);

    req.taint_sources.push_back({0x500000, 8});   // input window tainted
    req.watch_addr = 0x500100;
    req.watch_len  = 8;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");

    bool out_marked = false;
    for (const auto& rg : r.taint_ranges) {
        if (rg.addr <= 0x500107 && rg.addr + rg.len > 0x500100)
            out_marked = true;
    }
    REQUIRE(out_marked);
    REQUIRE(r.output_tainted);
    REQUIRE(!r.taint_events.empty());
}

TEST_CASE(taint_propagates_through_registers) {
    // mov cl,[0x500000]      8B 0D ... -> use mov ecx,[..] then xor into eax
    // mov edx,[0x500000]     8B 14 25 00 00 30 00
    // xor eax,edx            31 D0   (eax untainted before, edx tainted after load)
    // mov [0x500200],eax     89 04 25 00 02 30 00
    // ret                    C3
    auto req = base_req({0x8B, 0x14, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x31, 0xD0,
                         0x89, 0x04, 0x25, 0x00, 0x02, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x300, 0);
    req.maps.push_back(data);
    req.regs["rax"] = 0;

    req.taint_sources.push_back({0x500000, 4});
    req.watch_addr = 0x500200;
    req.watch_len  = 4;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.output_tainted);
}

TEST_CASE(taint_zeroing_idiom_clears_flow) {
    // mov edx,[0x500000]     tainted
    // xor edx,edx            zeroing clears
    // mov [0x500200],edx     store must NOT be tainted
    // ret
    auto req = base_req({0x8B, 0x14, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x31, 0xD2,
                         0x89, 0x14, 0x25, 0x00, 0x02, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x300, 0);
    req.maps.push_back(data);

    req.taint_sources.push_back({0x500000, 4});
    req.watch_addr = 0x500200;
    req.watch_len  = 4;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE(!r.output_tainted);
}

TEST_CASE(emu_trace_captures_instruction_text) {
    // inc eax / dec eax / ret
    auto req = base_req({0xFF, 0xC0,
                         0xFF, 0xC8,
                         0xC3});
    req.trace = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_EQ(r.trace.size(), 3u);
    bool saw_inc = false, saw_dec = false;
    for (const auto& t : r.trace) {
        std::string lower = t.text;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower.find("inc") != std::string::npos) saw_inc = true;
        if (lower.find("dec") != std::string::npos) saw_dec = true;
    }
    REQUIRE(saw_inc);
    REQUIRE(saw_dec);
}

TEST_CASE(emu_timeout_reports_timeout_reason) {
    // jmp $ with an instruction budget it can never reach
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 1ull << 40;
    req.timeout_ms = 200;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "timeout");
    REQUIRE_GT(r.instructions, 0u);
}

TEST_CASE(emu_cancel_token_stops_running_loop) {
    // jmp $ with a 20 s budget; cancellation must end it long before that
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 1ull << 40;
    req.timeout_ms = 20000;
    slop::core::infra::cancel_source_t source;
    req.cancel = source.token();

    const auto started = std::chrono::steady_clock::now();
    std::thread canceller([&source] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        source.request();
    });
    auto r = emulate_run(req);
    canceller.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cancelled");
    REQUIRE_LT(elapsed, 5000);
}


namespace {

// Page source over a sparse fake image: page va -> bytes (zero padded)
page_source_t fake_pages(std::map<uint64_t, std::vector<uint8_t>> pages) {
    return [pages = std::move(pages)](uint64_t page, uint8_t* out) {
        auto it = pages.find(page);
        if (it == pages.end()) return false;
        std::memset(out, 0, kPageSize);
        std::memcpy(out, it->second.data(), std::min(it->second.size(), kPageSize));
        return true;
    };
}

} // namespace

TEST_CASE(emu_page_in_follows_call_outside_slice) {
    // call 0x401000 / ret ; the callee page is only in the source
    auto req = base_req({0xE8, 0xFB, 0x0F, 0x00, 0x00,
                         0xC3});
    req.page_in = fake_pages({{0x401000, {0xB8, 0x34, 0x12, 0x00, 0x00,   // mov eax,0x1234
                                          0xC3}}});                       // ret
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x1234u);
    REQUIRE_EQ(r.paged_in, 1u);
    REQUIRE(!r.fault.has_value());
}

TEST_CASE(emu_page_in_completes_partial_code_page) {
    // a 2-byte slice runs on into the source's bytes, not zero fill
    auto req = base_req({0x90, 0x90});
    req.page_in = fake_pages({{0x400000, {0x90, 0x90,
                                          0xB8, 0x07, 0x00, 0x00, 0x00,   // mov eax,7
                                          0xC3}}});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 7u);
    REQUIRE_EQ(r.paged_in, 0u);   // completion is not demand paging
}

TEST_CASE(emu_page_in_refusal_and_budget_still_fault) {
    // mov eax,[0xDEAD0000] / ret, the source has no such page
    auto req = base_req({0xA1, 0x00, 0x00, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
                         0xC3});
    req.page_in = fake_pages({});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(!r.page_in_exhausted);

    // the page exists but the budget is spent
    req.page_in = fake_pages({{0xDEAD0000, {0x11}}});
    req.page_in_max = 0;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(r.page_in_exhausted);

    req.page_in_max = 1;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x11u);
}

namespace {

// mov ecx,0x11 / call [rip+0x1FF5] (IAT slot 0x402000) / add rax,1 / ret
run_request_t import_call_req() {
    auto req = base_req({0xB9, 0x11, 0x00, 0x00, 0x00,
                         0xFF, 0x15, 0xF5, 0x1F, 0x00, 0x00,
                         0x48, 0x83, 0xC0, 0x01,
                         0xC3});
    req.imports.push_back({0x402000, "kernel32.dll!Sleep"});
    req.api_ret = 41;
    req.trace = true;
    return req;
}

void require_one_sleep_call(const run_result_t& r) {
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs.at("rax"), 42u);
    REQUIRE_EQ(r.total_api_calls, 1u);
    REQUIRE_EQ(r.api_calls.size(), 1u);
    REQUIRE_STR_EQ(r.api_calls[0].name.c_str(), "kernel32.dll!Sleep");
    REQUIRE_EQ(r.api_calls[0].ip, 0x400005ull);
    REQUIRE_EQ(r.api_calls[0].ret, 0x40000Bull);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x11ull);
    bool traced = false;
    for (const auto& t : r.trace)
        if (t.text == "api kernel32.dll!Sleep") traced = true;
    REQUIRE(traced);
}

} // namespace

TEST_CASE(emu_import_stub_in_mapped_iat) {
    auto req = import_call_req();
    emu_mem_region_t iat;
    iat.addr = 0x402000;
    iat.bytes.assign(8, 0);
    req.maps.push_back(iat);
    require_one_sleep_call(emulate_run(req));
}

TEST_CASE(emu_import_stub_patched_on_page_in) {
    // the IAT page holds the on-disk hint/name rva until the stub patch lands
    auto req = import_call_req();
    req.page_in = fake_pages({{0x402000, {0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}});
    auto r = emulate_run(req);
    require_one_sleep_call(r);
    REQUIRE_EQ(r.paged_in, 1u);
}

TEST_CASE(emu_teb_peb_behind_gs) {
    // mov rax,gs:[0x30] / mov rcx,gs:[0x60] / mov rdx,[rcx+0x10] /
    // movzx r8d,byte [rcx+2] / ret
    auto req = base_req({0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
                         0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00,
                         0x48, 0x8B, 0x51, 0x10,
                         0x44, 0x0F, 0xB6, 0x41, 0x02,
                         0xC3});
    req.image_base = 0x140000000;
    req.regs["r8"] = 0xFF;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.teb_mapped);
    REQUIRE_EQ(r.regs["rax"], r.regs["gs_base"]);
    REQUIRE_EQ(r.regs["rcx"], r.regs["gs_base"] + 0x2000);
    REQUIRE_EQ(r.regs["rdx"], 0x140000000ull);
    REQUIRE_EQ(r.regs["r8"], 0u);             // BeingDebugged

    // a caller gs_base replaces the fake TEB
    req.regs["gs_base"] = 0x500000;
    emu_mem_region_t teb;
    teb.addr = 0x500000;
    teb.bytes.assign(0x100, 0);
    teb.bytes[0x30] = 0x77;
    req.maps.push_back(teb);
    req.code.resize(9);                       // just the first load
    req.code.push_back(0xC3);
    r = emulate_run(req);
    REQUIRE(!r.teb_mapped);
    REQUIRE_EQ(r.regs["rax"], 0x77u);
}

TEST_CASE(emu_dump_and_write_values) {
    // mov dword [0x500000],0xDEADBEEF / ret
    auto req = base_req({0xC7, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0xEF, 0xBE, 0xAD, 0xDE,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x10, 0);
    req.maps.push_back(data);
    // untouched source page, an unmapped range, and one straddling the end
    req.page_in = fake_pages({{0x600000, {0xAA, 0xBB}}});
    req.dumps = {{0x500000, 8}, {0x600000, 2}, {0x900000, 4}, {0x500FFE, 4}};
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");

    REQUIRE_EQ(r.writes.size(), 1u);
    REQUIRE_EQ(r.writes[0].len, 4u);
    REQUIRE_EQ(r.writes[0].value, 0xDEADBEEFull);

    REQUIRE_EQ(r.memory.size(), 4u);
    const std::vector<uint8_t> want = {0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0};
    REQUIRE(r.memory[0].bytes == want);
    REQUIRE(r.memory[1].bytes == std::vector<uint8_t>({0xAA, 0xBB}));
    REQUIRE(r.memory[2].bytes.empty());
    REQUIRE_EQ(r.memory[3].bytes.size(), 2u);   // cut at the unmapped page
    REQUIRE_EQ(r.paged_in, 0u);                 // dumps never map pages
}

// === SysV / PS4 environment (item 55) ========================================

TEST_CASE(emu_sysv_import_args_use_sysv_registers) {
    // mov edi,0x11 / call [rip+0x1FF5] (IAT slot 0x402000) / add rax,1 / ret
    auto req = base_req({0xBF, 0x11, 0x00, 0x00, 0x00,
                         0xFF, 0x15, 0xF5, 0x1F, 0x00, 0x00,
                         0x48, 0x83, 0xC0, 0x01,
                         0xC3});
    req.abi = abi_t::sysv;
    req.imports.push_back({0x402000, "libkernel!sceKernelUsleep"});
    req.api_ret = 41;
    req.regs["rsi"] = 0x22;
    req.regs["r9"]  = 0x66;
    emu_mem_region_t iat;
    iat.addr = 0x402000;
    iat.bytes.assign(8, 0);
    req.maps.push_back(iat);
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs.at("rax"), 42u);
    REQUIRE_EQ(r.api_calls.size(), 1u);
    REQUIRE_EQ(r.api_calls[0].arg_count, 6u);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x11ull);   // rdi
    REQUIRE_EQ(r.api_calls[0].args[1], 0x22ull);   // rsi
    REQUIRE_EQ(r.api_calls[0].args[5], 0x66ull);   // r9
    REQUIRE_STR_EQ(abi_name(req.abi), "sysv");
}

TEST_CASE(emu_win64_import_args_stay_win64) {
    auto req = import_call_req();
    emu_mem_region_t iat;
    iat.addr = 0x402000;
    iat.bytes.assign(8, 0);
    req.maps.push_back(iat);
    auto r = emulate_run(req);
    REQUIRE_EQ(r.api_calls.size(), 1u);
    REQUIRE_EQ(r.api_calls[0].arg_count, 4u);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x11ull);   // rcx
    REQUIRE_STR_EQ(abi_name(req.abi), "win64");
}

TEST_CASE(emu_sysv_tcb_behind_fs) {
    // mov rax,fs:[0] / mov rcx,fs:[8] / mov rdx,[rcx+0x10] / mov r8,fs:[-8] / ret
    auto req = base_req({0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
                         0x64, 0x48, 0x8B, 0x0C, 0x25, 0x08, 0x00, 0x00, 0x00,
                         0x48, 0x8B, 0x51, 0x10,
                         0x64, 0x4C, 0x8B, 0x04, 0x25, 0xF8, 0xFF, 0xFF, 0xFF,
                         0xC3});
    req.abi = abi_t::sysv;
    req.regs["r8"] = 0xFF;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.tls_mapped);
    REQUIRE_FALSE(r.teb_mapped);
    const uint64_t tp = r.regs.at("fs_base");
    REQUIRE(tp != 0);
    REQUIRE_EQ(r.regs.at("rax"), tp);              // tcb_self
    REQUIRE_EQ(r.regs.at("rdx"), tp - 0x2000);     // dtv[2]: static TLS block
    REQUIRE_EQ(r.regs.at("r8"), 0u);               // static TLS reads zero

    // a caller fs_base replaces the fake TCB
    req.regs["fs_base"] = 0x500000;
    emu_mem_region_t tcb;
    tcb.addr = 0x500000;
    tcb.bytes.assign(0x100, 0);
    tcb.bytes[0] = 0x77;
    req.maps.push_back(tcb);
    req.code.resize(9);
    req.code.push_back(0xC3);
    r = emulate_run(req);
    REQUIRE_FALSE(r.tls_mapped);
    REQUIRE_EQ(r.regs.at("rax"), 0x77u);
}

namespace {

const char* test_syscall_name(uint64_t num) {
    switch (num) {
    case 4:  return "write";
    case 20: return "getpid";
    default: return nullptr;
    }
}

} // namespace

TEST_CASE(emu_syscall_hook_logs_names_args_and_returns) {
    // mov eax,20 / mov edi,7 / mov r10d,9 / syscall / mov rbx,rax /
    // mov eax,4 / stc / syscall / mov eax,99 / syscall / ret
    auto req = base_req({0xB8, 0x14, 0x00, 0x00, 0x00,
                         0xBF, 0x07, 0x00, 0x00, 0x00,
                         0x41, 0xBA, 0x09, 0x00, 0x00, 0x00,
                         0x0F, 0x05,
                         0x48, 0x89, 0xC3,
                         0xB8, 0x04, 0x00, 0x00, 0x00,
                         0xF9,
                         0x0F, 0x05,
                         0x48, 0x89, 0xC6,                 // mov rsi,rax
                         0xB8, 0x63, 0x00, 0x00, 0x00,
                         0x0F, 0x05,
                         0xC3});
    req.abi = abi_t::sysv;
    req.syscall_ret = 0x55;
    req.syscall_returns[20] = 1234;
    req.syscall_name = test_syscall_name;
    req.trace = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.total_syscalls, 3u);
    REQUIRE_EQ(r.syscalls.size(), 3u);

    REQUIRE_EQ(r.syscalls[0].ip, 0x400010ull);
    REQUIRE_EQ(r.syscalls[0].num, 20u);
    REQUIRE_STR_EQ(r.syscalls[0].name.c_str(), "getpid");
    REQUIRE_EQ(r.syscalls[0].args[0], 7u);    // rdi
    REQUIRE_EQ(r.syscalls[0].args[3], 9u);    // r10, the 4th syscall arg
    REQUIRE_EQ(r.syscalls[0].ret, 1234u);
    REQUIRE_EQ(r.regs.at("rbx"), 1234u);

    REQUIRE_STR_EQ(r.syscalls[1].name.c_str(), "write");
    REQUIRE_EQ(r.regs.at("rsi"), 0x55u);
    REQUIRE(r.syscalls[2].name.empty());      // unknown number
    REQUIRE_EQ(r.syscalls[2].num, 99u);

    // rcx = next rip, CF cleared even after stc
    REQUIRE_EQ(r.regs.at("rcx"), 0x400027ull);
    REQUIRE_EQ(r.regs.at("rflags") & 1u, 0u);

    bool named = false;
    for (const auto& t : r.trace)
        if (t.ip == 0x400010 && t.text.find("; getpid") != std::string::npos) named = true;
    REQUIRE(named);
}

// === write log keeps wide stores (item 75) ===================================

TEST_CASE(emu_write_log_keeps_wide_store_values) {
    // movups xmm0,[0x500000] / movups [0x500010],xmm0 / mov qword [0x500020],rcx / ret
    auto req = base_req({0x0F, 0x10, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x0F, 0x11, 0x04, 0x25, 0x10, 0x00, 0x50, 0x00,
                         0x48, 0x89, 0x0C, 0x25, 0x20, 0x00, 0x50, 0x00,
                         0xC3});
    req.regs["rcx"] = 0x1122334455667788ull;
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x40, 0);
    for (uint8_t i = 0; i < 16; ++i) data.bytes[i] = static_cast<uint8_t>(0xA0 + i);
    req.maps.push_back(data);
    req.dumps = {{0x500000, 0x40}};
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.memory.size(), 1u);
    const auto& mem = r.memory[0].bytes;

    size_t vec_bytes = 0;
    bool saw_qword = false;
    for (const auto& w : r.writes) {
        REQUIRE(w.addr >= 0x500000 && w.addr + w.len <= 0x500040);
        // the logged value is the low (up to 8) bytes actually stored
        const size_t n = std::min<size_t>(w.len, 8);
        uint64_t want = 0;
        std::memcpy(&want, mem.data() + (w.addr - 0x500000), n);
        REQUIRE_EQ(w.value, want);
        REQUIRE_EQ(w.truncated, w.len > 8);
        if (w.addr >= 0x500010 && w.addr < 0x500020) vec_bytes += w.len;
        if (w.addr == 0x500020 && w.len == 8) {
            saw_qword = true;
            REQUIRE_EQ(w.value, 0x1122334455667788ull);
        }
    }
    REQUIRE_EQ(vec_bytes, 16u);
    REQUIRE(saw_qword);
    REQUIRE(r.writes.front().value != 0);   // the vector store is not logged as 0
}

// === emulate tool: arch gate on every source (56) and abi selection (55) =====

namespace {

nlohmann::json emulate_call(const nlohmann::json& args, bool& is_error) {
    return slop::core::mcp::call_tool("emulate", args, is_error);
}

} // namespace

TEST_CASE(emu_tool_hex_arch_selection) {
    bool is_error = false;
    auto out = emulate_call({{"action", "run"}, {"hex", "90c3"}, {"arch", "vax"}}, is_error);
    REQUIRE(is_error);

    out = emulate_call({{"action", "run"}, {"hex", "90c3"}, {"arch", "x64"}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("arch", "").c_str(), "x64");
    REQUIRE_STR_EQ(out.value("stopped_reason", "").c_str(), "return");

    // arm64 raw bytes: mov w0,#7 / ret
    out = emulate_call({{"action", "run"}, {"hex", "e0008052c0035fd6"}, {"arch", "arm64"}},
                       is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("arch", "").c_str(), "arm64");
    REQUIRE_STR_EQ(out.value("abi", "").c_str(), "aapcs64");
    REQUIRE_STR_EQ(out.value("stopped_reason", "").c_str(), "return");
    REQUIRE_EQ(out.at("regs").value("x0", 0ull), 7ull);
}

TEST_CASE(emu_tool_abi_selection_and_syscall_log) {
    namespace ds = slop::core::disasm::binary_state;
    ds::unload();
    bool is_error = false;

    // no console, no image: hex defaults to the win64 environment
    auto out = emulate_call({{"action", "run"}, {"hex", "90c3"}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("abi", "").c_str(), "win64");
    REQUIRE(out.value("teb_mapped", false));
    REQUIRE_FALSE(out.contains("tls_mapped"));

    // mov eax,20 (getpid) / mov edi,5 / syscall / ret on the PS4 abi
    const std::string code = "b814000000" "bf05000000" "0f05" "c3";
    out = emulate_call({{"action", "run"}, {"hex", code}, {"abi", "sysv"},
                        {"syscall_returns", {{"getpid", 77}}}, {"trace", true}},
                       is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("abi", "").c_str(), "sysv");
    REQUIRE(out.value("tls_mapped", false));
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 77ull);
    REQUIRE_EQ(out.value("total_syscalls", 0ull), 1ull);
    const auto& sc = out.at("syscalls").at(0);
    REQUIRE_EQ(sc.value("num", 0ull), 20ull);
    REQUIRE_STR_EQ(sc.value("name", "").c_str(), "getpid");
    REQUIRE_EQ(sc.at("args").size(), 6u);
    REQUIRE_EQ(sc.at("args").at(0).get<uint64_t>(), 5ull);

    // numeric keys and the default return
    out = emulate_call({{"action", "run"}, {"hex", code}, {"abi", "sysv"},
                        {"syscall_returns", {{"0x14", 9}}}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 9ull);
    out = emulate_call({{"action", "run"}, {"hex", code}, {"abi", "sysv"},
                        {"syscall_ret", 3}}, is_error);
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 3ull);

    out = emulate_call({{"action", "run"}, {"hex", code}, {"abi", "sysv"},
                        {"syscall_returns", {{"not_a_syscall", 1}}}}, is_error);
    REQUIRE(is_error);
    out = emulate_call({{"action", "run"}, {"hex", code}, {"abi", "vax"}}, is_error);
    REQUIRE(is_error);
}

// === snapshot/restore + persistent sessions (audit 54) ======================

namespace {

// inc dword [0x500000] / mov eax,[0x500000] / jmp 0x400000
run_request_t counter_req() {
    auto req = base_req({0xFF, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0xEB, 0xF0});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x10, 0);
    req.maps.push_back(data);
    return req;
}

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return s;
}

} // namespace

TEST_CASE(emu_session_snapshot_restore_is_deterministic) {
    std::string err;
    auto s = emulation_session_t::create(counter_req(), &err);
    REQUIRE(s != nullptr);
    REQUIRE(s->step(6, 1000, {}, &err));   // two loop iterations
    REQUIRE_EQ(s->state().regs.at("rax"), 2u);
    REQUIRE(s->snapshot(&err));
    REQUIRE_EQ(s->snapshot_pages(), 1u);   // the counter page

    REQUIRE(s->step(6, 1000, {}, &err));
    REQUIRE_EQ(s->state().regs.at("rax"), 4u);
    REQUIRE(s->restore(&err));
    REQUIRE_EQ(s->state().regs.at("rax"), 2u);
    REQUIRE(s->step(6, 1000, {}, &err));
    REQUIRE_EQ(s->state().regs.at("rax"), 4u);

    // a second cycle lands on the same state again
    REQUIRE(s->snapshot(&err));
    REQUIRE(s->step(3, 1000, {}, &err));
    REQUIRE_EQ(s->state().regs.at("rax"), 5u);
    REQUIRE(s->restore(&err));
    REQUIRE(s->step(3, 1000, {}, &err));
    REQUIRE_EQ(s->state().regs.at("rax"), 5u);
}

TEST_CASE(emu_tool_session_actions) {
    bool is_error = false;
    auto out = emulate_call({{"action", "session_create"},
                             {"hex", "ff0425000050008b042500005000ebf0"},
                             {"maps", nlohmann::json::array(
                                          {nlohmann::json{{"addr", 0x500000},
                                                          {"hex", "0000000000000000"}}})}},
                            is_error);
    REQUIRE_FALSE(is_error);
    const uint64_t id = out.value("session", 0ull);
    REQUIRE(id != 0);
    REQUIRE(out.contains("regs"));

    out = emulate_call({{"action", "session_step"}, {"session", id}, {"count", 6}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 2ull);

    out = emulate_call({{"action", "snapshot"}, {"session", id}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_EQ(out.value("pages", 0ull), 1ull);

    out = emulate_call({{"action", "session_step"}, {"session", id}, {"count", 6}}, is_error);
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 4ull);

    out = emulate_call({{"action", "restore"}, {"session", id}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_EQ(out.at("regs").value("rax", 0ull), 2ull);

    out = emulate_call({{"action", "session_destroy"}, {"session", id}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE(out.value("destroyed", false));
    out = emulate_call({{"action", "session_step"}, {"session", id}, {"count", 1}}, is_error);
    REQUIRE(is_error);
}

// === dynamic backward slicing (audit 55) ====================================

TEST_CASE(emu_backward_slice_registers) {
    // mov eax,1 / mov esi,7 / mov ecx,2 / add eax,ecx / ret
    auto req = base_req({0xB8, 0x01, 0x00, 0x00, 0x00,
                         0xBE, 0x07, 0x00, 0x00, 0x00,
                         0xB9, 0x02, 0x00, 0x00, 0x00,
                         0x01, 0xC8,
                         0xC3});
    req.trace = true;
    req.record_slice = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_EQ(r.trace.size(), 5u);

    slice_request_t s;
    s.reg = "rax";
    auto sl = emulate_slice(r, s);
    REQUIRE(sl.ok);
    REQUIRE_EQ(sl.indices.size(), 3u);
    REQUIRE_EQ(sl.indices[0], 0u);   // mov eax,1
    REQUIRE_EQ(sl.indices[1], 2u);   // mov ecx,2
    REQUIRE_EQ(sl.indices[2], 3u);   // add eax,ecx
    REQUIRE_EQ(sl.insns.back().ip, 0x40000Full);

    // at the add: only the mov eax,1 defines the value there
    s.at = 0x40000F;
    sl = emulate_slice(r, s);
    REQUIRE(sl.ok);
    REQUIRE_EQ(sl.indices.size(), 1u);
    REQUIRE_EQ(sl.indices[0], 0u);

    // an unknown target register is an error, not an empty slice
    s = {};
    s.reg = "notareg";
    sl = emulate_slice(r, s);
    REQUIRE_FALSE(sl.ok);
}

TEST_CASE(emu_backward_slice_memory) {
    // mov eax,5 / mov [0x500000],eax / ret
    auto req = base_req({0xB8, 0x05, 0x00, 0x00, 0x00,
                         0x89, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x10, 0);
    req.maps.push_back(data);
    req.trace = true;
    req.record_slice = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);

    slice_request_t s;
    s.addr = 0x500000;
    s.len  = 4;
    auto sl = emulate_slice(r, s);
    REQUIRE(sl.ok);
    REQUIRE_EQ(sl.indices.size(), 2u);
    REQUIRE_EQ(sl.indices[0], 0u);
    REQUIRE_EQ(sl.indices[1], 1u);
}

TEST_CASE(emu_tool_trace_and_slice) {
    bool is_error = false;
    auto out = emulate_call({{"action", "run"},
                             {"hex", "b801000000be07000000b90200000001c8c3"},
                             {"trace", true}},
                            is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE(out.contains("trace_id"));
    const uint64_t id = out.value("trace_id", 0ull);
    REQUIRE(id != 0);

    auto sl = emulate_call({{"action", "slice"}, {"trace_id", id}, {"reg", "rax"}},
                           is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_EQ(sl.value("count", 0ull), 3ull);
    const auto& insns = sl.at("instructions");
    REQUIRE_EQ(insns.at(0).value("ip", 0ull), 0x400000ull);
    REQUIRE_EQ(insns.at(1).value("ip", 0ull), 0x40000Aull);
    REQUIRE_EQ(insns.at(2).value("ip", 0ull), 0x40000Full);

    sl = emulate_call({{"action", "slice"}, {"trace_id", 999999}, {"reg", "rax"}},
                      is_error);
    REQUIRE(is_error);
}

// === Orbis syscall emulation on a synthetic PS4 ELF (audit 56) ==============

TEST_CASE(emu_orbis_syscalls_on_ps4_elf) {
    namespace bs = slop::core::disasm::binary_state;
    bs::unload();
    auto elf = elf_fixture::build_ps4_elf();
    const uint64_t base = 0x10000000;
    const uint64_t str_va = base + elf_fixture::ps4_layout::kString;

    std::vector<uint8_t> code;
    auto b = [&](std::initializer_list<uint8_t> v) { code.insert(code.end(), v); };
    auto d32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) code.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    b({0xB8}); d32(4);                          // mov eax,4 (write)
    b({0x8B, 0x0C, 0x25}); d32(static_cast<uint32_t>(str_va));  // mov ecx,[str]
    b({0xBF}); d32(1);                          // mov edi,1
    b({0xBE}); d32(static_cast<uint32_t>(str_va));
    b({0xBA}); d32(5);                          // mov edx,5
    b({0x0F, 0x05});                            // syscall
    b({0xB8}); d32(20);                         // getpid
    b({0x0F, 0x05});
    b({0xB8}); d32(477);                        // mmap
    b({0x31, 0xFF});                            // xor edi,edi
    b({0xBE}); d32(0x2000);                     // len
    b({0xBA}); d32(3);                          // prot rw
    b({0x41, 0xBA}); d32(0x1002);               // MAP_ANON|MAP_PRIVATE
    b({0x49, 0xC7, 0xC0}); d32(0xFFFFFFFF);     // mov r8,-1
    b({0x45, 0x31, 0xC9});                      // xor r9d,r9d
    b({0x0F, 0x05});
    b({0xB8}); d32(5);                          // open -> ENOSYS
    b({0x0F, 0x05});
    b({0xB8}); d32(1);                          // exit(7)
    b({0xBF}); d32(7);
    b({0x0F, 0x05});

    std::memcpy(elf.data() + elf_fixture::ps4_layout::file_off(elf_fixture::ps4_layout::kEntry),
                code.data(), code.size());
    elf_fixture::temp_file_t tf(elf, "emu_orbis");
    REQUIRE(bs::load_file(tf.path.string(), base));

    bool is_error = false;
    auto out = emulate_call({{"action", "run"},
                             {"file_addr", base + elf_fixture::ps4_layout::kEntry},
                             {"entry", base + elf_fixture::ps4_layout::kEntry},
                             {"code_len", code.size()},
                             {"abi", "sysv"},
                             {"orbis_syscalls", true},
                             {"trace", true}},
                            is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("stopped_reason", "").c_str(), "exit");
    REQUIRE_EQ(out.value("stdout", ""), std::string("hello"));
    REQUIRE_EQ(out.value("exit_code", 0ull), 7ull);
    REQUIRE_EQ(out.value("syscall_enosys", 0ull), 1ull);
    REQUIRE_EQ(out.value("total_syscalls", 0ull), 5ull);

    const auto& sc = out.at("syscalls");
    REQUIRE_STR_EQ(sc.at(0).value("name", "").c_str(), "write");
    REQUIRE_EQ(sc.at(0).value("ret", 0ull), 5ull);
    REQUIRE_STR_EQ(sc.at(1).value("name", "").c_str(), "getpid");
    REQUIRE_EQ(sc.at(1).value("ret", 0ull), 1000ull);
    REQUIRE_STR_EQ(sc.at(2).value("name", "").c_str(), "mmap");
    REQUIRE_GE(sc.at(2).value("ret", 0ull), 0x700000000000ull);
    REQUIRE(sc.at(3).value("enosys", false));
    REQUIRE_EQ(sc.at(3).value("ret", 0ull), 78ull);
    REQUIRE_STR_EQ(sc.at(4).value("name", "").c_str(), "exit");
    bs::unload();
}

// === arm64 emulation (audit 49) =============================================

TEST_CASE(emu_arm64_blob_runs_and_returns) {
    // mov w0,#7 / ret
    run_request_t req;
    req.arch = arch_t::arm64;
    req.code = {0xE0, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6};
    req.code_base = 0x400000;
    req.trace = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs.at("x0"), 7u);
    REQUIRE_EQ(r.trace.size(), 2u);
    REQUIRE(lower_copy(r.trace[0].text).find("mov") != std::string::npos);
    REQUIRE(lower_copy(r.trace[1].text).find("ret") != std::string::npos);
}

TEST_CASE(emu_arm64_macho_function_with_stub_logging) {
    namespace bs = slop::core::disasm::binary_state;
    bs::unload();
    elf_fixture::temp_file_t tf(slop_test::macho::build_arm64_exe(), "emu_macho");
    REQUIRE(bs::load_file(tf.path.string()));
    const auto& L = slop_test::macho::exe_layout;

    bool is_error = false;
    auto out = emulate_call({{"action", "run"},
                             {"file_addr", L.main_va},
                             {"entry", L.main_va},
                             {"code_len", 0x40},
                             {"trace", true}},
                            is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE_STR_EQ(out.value("arch", "").c_str(), "arm64");
    REQUIRE_STR_EQ(out.value("stopped_reason", "").c_str(), "return");
    REQUIRE_EQ(out.value("total_api_calls", 0ull), 1ull);
    const auto& call = out.at("api_calls").at(0);
    REQUIRE(call.value("name", "").find("puts") != std::string::npos);
    REQUIRE_EQ(call.value("ret", 0ull), L.main_va + 0x14);
    // main returns 0 after helper() -> mov w0,#0
    REQUIRE_EQ(out.at("regs").value("x0", 0ull), 0ull);
    bs::unload();
}
