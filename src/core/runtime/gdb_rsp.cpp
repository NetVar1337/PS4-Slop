// src/core/runtime/gdb_rsp.cpp
// GDB Remote Serial Protocol bridge over the shared PS4 debug session
// (ported from PS4-MCP rsp.rs): GDB/LLDB/Binary Ninja attach here and drive
// the same backend_ps4_t the UI and MCP tools use. Every console operation
// runs under broker_gate(), so all clients serialize on the one connection.

#include "core/runtime/gdb_rsp.hpp"

#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/broker.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace slop::core::runtime {

namespace {

constexpr size_t   kMaxPacket = 16384;
constexpr int      kPollMs    = 50;
constexpr uint16_t kDefaultPort = 2331;

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
} g_wsa;

// ---- register layout (same as PS4-MCP REGISTER_LAYOUT) ----
// GDB i386:x86-64 core feature first, then i387_ext, then SSE
struct reg_desc_t {
    const char* name;
    int         bits;
};
constexpr reg_desc_t kRegs[] = {
    {"rax", 64}, {"rbx", 64}, {"rcx", 64}, {"rdx", 64}, {"rsi", 64}, {"rdi", 64},
    {"rbp", 64}, {"rsp", 64}, {"r8", 64}, {"r9", 64}, {"r10", 64}, {"r11", 64},
    {"r12", 64}, {"r13", 64}, {"r14", 64}, {"r15", 64}, {"rip", 64}, {"eflags", 64},
    {"cs", 32}, {"ss", 32}, {"ds", 32}, {"es", 32}, {"fs", 32}, {"gs", 32},
    {"st0", 80}, {"st1", 80}, {"st2", 80}, {"st3", 80},
    {"st4", 80}, {"st5", 80}, {"st6", 80}, {"st7", 80},
    {"fctrl", 32}, {"fstat", 32}, {"ftag", 32}, {"fiseg", 32},
    {"fioff", 32}, {"foseg", 32}, {"fooff", 32}, {"fop", 32},
    {"xmm0", 128}, {"xmm1", 128}, {"xmm2", 128}, {"xmm3", 128},
    {"xmm4", 128}, {"xmm5", 128}, {"xmm6", 128}, {"xmm7", 128},
    {"xmm8", 128}, {"xmm9", 128}, {"xmm10", 128}, {"xmm11", 128},
    {"xmm12", 128}, {"xmm13", 128}, {"xmm14", 128}, {"xmm15", 128},
    {"mxcsr", 32},
};
constexpr size_t kRegCount = sizeof(kRegs) / sizeof(kRegs[0]);

std::string target_xml() {
    std::string core, sse;
    for (size_t i = 0; i < kRegCount; ++i) {
        const auto& r = kRegs[i];
        const char* kind = r.bits == 80 ? "i387_ext" : (r.bits == 128 ? "uint128" : "int");
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "<reg name=\"%s\" bitsize=\"%d\" regnum=\"%zu\" type=\"%s\"/>",
                      r.name, r.bits, i, kind);
        if (i < 40) core += buf; else sse += buf;
    }
    return "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
           "<target><architecture>i386:x86-64</architecture><osabi>FreeBSD</osabi>"
           "<feature name=\"org.gnu.gdb.i386.core\">" + core + "</feature>"
           "<feature name=\"org.gnu.gdb.i386.sse\">" + sse + "</feature></target>";
}

// ---- hex helpers ----
std::string hex_encode(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(h[d[i] >> 4]);
        s.push_back(h[d[i] & 0xF]);
    }
    return s;
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        const int hi = hex_val(s[i]), lo = hex_val(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// GDB hex literal: decimal, 0x hex, or negative; -1 allowed (thread "all")
bool parse_hex(const std::string& t, int64_t& out) {
    std::string s = t;
    bool neg = false;
    if (!s.empty() && s.front() == '-') { neg = true; s.erase(0, 1); }
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s.erase(0, 2);
    if (s.empty()) return false;
    uint64_t v = 0;
    for (char c : s) {
        const int d = hex_val(c);
        if (d < 0) {
            // fall back to decimal
            try {
                size_t pos = 0;
                v = std::stoull(t, &pos, 10);
                if (pos != t.size()) return false;
            } catch (...) { return false; }
            break;
        }
        if (v > (UINT64_MAX >> 4)) return false;
        v = (v << 4) | static_cast<uint64_t>(d);
    }
    out = neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
    return true;
}

std::string u64_le_hex(uint64_t v, int bytes) {
    std::string s;
    for (int i = 0; i < bytes; ++i)
        s += hex_encode(&reinterpret_cast<const uint8_t*>(&v)[i], 1);
    return s;
}

std::string rep(char c, size_t n) { return std::string(n, c); }

// ---- RSP framing ----
struct decoder_t {
    std::vector<uint8_t> buf;
    enum class msg_t { ack, nak, bad, interrupt, packet };
    struct msg_t_ { msg_t kind; std::vector<uint8_t> payload; };
    // returns messages; throws std::string on framing errors
    std::vector<msg_t_> feed(const uint8_t* d, size_t n) {
        buf.insert(buf.end(), d, d + n);
        std::vector<msg_t_> out;
        while (!buf.empty()) {
            const uint8_t first = buf.front();
            if (first == 3) { out.push_back({msg_t::interrupt, {}}); buf.erase(buf.begin()); continue; }
            if (first == '+') { out.push_back({msg_t::ack, {}}); buf.erase(buf.begin()); continue; }
            if (first == '-') { out.push_back({msg_t::nak, {}}); buf.erase(buf.begin()); continue; }
            if (first != '$') throw std::string("invalid RSP framing");
            size_t delim = std::string::npos;
            for (size_t i = 1; i < buf.size(); ++i)
                if (buf[i] == '#') { delim = i; break; }
            if (delim == std::string::npos) {
                if (buf.size() > kMaxPacket) throw std::string("RSP packet exceeds limit");
                break;
            }
            if (delim > kMaxPacket) throw std::string("RSP packet exceeds limit");
            if (buf.size() < delim + 3) break;
            const std::vector<uint8_t> encoded(buf.begin() + 1, buf.begin() + delim);
            const int c1 = hex_val(static_cast<char>(buf[delim + 1]));
            const int c2 = hex_val(static_cast<char>(buf[delim + 2]));
            buf.erase(buf.begin(), buf.begin() + delim + 3);
            if (c1 < 0 || c2 < 0 || (c1 << 4 | c2) !=
                std::accumulate(encoded.begin(), encoded.end(), 0,
                                [](int a, uint8_t b) { return (a + b) & 0xFF; })) {
                out.push_back({msg_t::bad, {}});
                continue;
            }
            std::vector<uint8_t> decoded;
            bool esc = false;
            for (uint8_t b : encoded) {
                if (esc) { decoded.push_back(b ^ 0x20); esc = false; }
                else if (b == '}') esc = true;
                else if (b == '*') throw std::string("run-length encoding unsupported");
                else decoded.push_back(b);
            }
            if (esc) throw std::string("truncated RSP escape");
            out.push_back({msg_t::packet, std::move(decoded)});
        }
        return out;
    }
};

std::vector<uint8_t> frame(const std::string& payload) {
    uint8_t sum = 0;
    std::vector<uint8_t> out;
    out.push_back('$');
    for (char ch : payload) {
        const uint8_t b = static_cast<uint8_t>(ch);
        sum = static_cast<uint8_t>(sum + b);
        if (b == '}') { out.push_back('}'); out.push_back(b ^ 0x20); }
        else out.push_back(b);
    }
    char tail[4];
    std::snprintf(tail, sizeof(tail), "#%02x", sum);
    out.push_back(tail[0]);
    out.push_back(tail[1]);
    out.push_back(tail[2]);
    return out;
}

bool send_all(SOCKET s, const uint8_t* d, size_t n) {
    size_t off = 0;
    while (off < n) {
        const int r = ::send(s, reinterpret_cast<const char*>(d + off),
                             static_cast<int>(n - off), 0);
        if (r == SOCKET_ERROR || r == 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

// ---- per-connection session ----
struct conn_t {
    SOCKET sock = INVALID_SOCKET;
    std::thread th;
    std::atomic<bool> finished{false};
    // RSP session state (guarded by the connection thread only, except
    // awaiting_stop which the poll path reads)
    bool no_ack = false;
    uint64_t thread_id = 0;          // lwpid, 0 = none picked yet
    uint64_t continue_thread = 0;
    std::string last_stop;           // last T.. reply
    std::atomic<bool> awaiting_stop{false};
    std::vector<uint8_t> last_frame; // for retransmit
    std::vector<uint8_t> last_request;
    bool unacknowledged = false;
    std::string map_xml;             // cached at first qXfer:memory-map offset 0
    bool map_cached = false;
    std::string libs_xml;
    bool libs_cached = false;
};

} // namespace

// impl_t is a nested class of gdb_rsp_server_t, so its definition must live
// at namespace scope (an anonymous namespace would make it a different type)
struct gdb_rsp_server_t::impl_t {
    backend_ps4_t* test_backend = nullptr;   // tests inject a direct backend
    SOCKET listen_sock = INVALID_SOCKET;
    std::thread accept_th;
    std::atomic<bool> running{false};
    uint16_t port = 0;
    std::string bind;
    bool allow_writes = false;

    std::mutex clients_mu;
    std::vector<std::shared_ptr<conn_t>> clients;

    target_handle_t mem_handle{};    // cached attach for memory R/W
    uint32_t mem_pid = 0;

    backend_ps4_t* backend() {
        return test_backend ? test_backend : registry_ps4();
    }

    // false when there is no usable console debug session
    bool ensure_session(backend_ps4_t*& p, uint32_t& pid) {
        p = backend();
        if (!p || !p->connected() || !p->ps4_debug_attached()) return false;
        pid = p->ps4_debug_pid();
        return pid != 0;
    }

    target_handle_t handle_for(uint32_t pid) {
        if (mem_handle.valid() && mem_pid == pid) return mem_handle;
        auto* p = backend();
        if (!p) return {};
        mem_handle = p->attach(pid);
        mem_pid = pid;
        return mem_handle;
    }

    std::vector<uint32_t> threads(uint32_t pid) {
        std::vector<uint32_t> out;
        auto* p = backend();
        if (!p) return out;
        auto r = p->enum_threads(pid);
        for (const auto& t : r.items) out.push_back(t.tid);
        return out;
    }

    uint64_t current_thread(uint32_t pid, conn_t& c) {
        if (c.thread_id) return c.thread_id;
        const auto t = threads(pid);
        if (t.empty()) return 0;
        c.thread_id = t.front();
        return c.thread_id;
    }

    // full 'g' register block as hex (LE per register)
    std::string register_block(uint64_t tid) {
        auto* p = backend();
        thread_context_t ctx{};
        if (p && p->get_thread_context(static_cast<uint32_t>(tid), ctx).ok) {}
        uint8_t fp[832]{};
        const bool have_fp = p && p->ps4_get_fpregs(static_cast<uint32_t>(tid), fp).ok;

        std::string out;
        for (size_t i = 0; i < kRegCount; ++i) {
            const auto& r = kRegs[i];
            const int bytes = r.bits / 8;
            const std::string name = r.name;
            uint64_t v = 0;
            bool have = false;
            if (name == "rax") { v = ctx.rax; have = true; }
            else if (name == "rbx") { v = ctx.rbx; have = true; }
            else if (name == "rcx") { v = ctx.rcx; have = true; }
            else if (name == "rdx") { v = ctx.rdx; have = true; }
            else if (name == "rsi") { v = ctx.rsi; have = true; }
            else if (name == "rdi") { v = ctx.rdi; have = true; }
            else if (name == "rbp") { v = ctx.rbp; have = true; }
            else if (name == "rsp") { v = ctx.rsp; have = true; }
            else if (name == "rip") { v = ctx.rip; have = true; }
            else if (name == "eflags") { v = ctx.flags; have = true; }
            else if (name.size() == 2 && name[0] == 'r' && name[1] >= '8' && name[1] <= '9') {
                v = ctx.r8 + (name[1] - '8'); have = true;
            } else if (name.size() == 3 && name[0] == 'r' && name[1] == '1' &&
                       name[2] >= '0' && name[2] <= '5') {
                v = ctx.r10 + (name[2] - '0'); have = true;
            }
            if (have) {
                out += u64_le_hex(v, bytes);
                continue;
            }
            // segment regs: unknown
            if (r.bits == 32 && (name == "cs" || name == "ss" || name == "ds" ||
                                 name == "es" || name == "fs" || name == "gs")) {
                out += rep('x', bytes * 2);
                continue;
            }
            // FPU/SSE from the 832-byte fpregs block (FXSAVE layout in the first 512B)
            if (!have_fp) { out += rep('x', bytes * 2); continue; }
            if (name[0] == 's' && name[1] == 't' && name.size() == 3) {
                const int idx = name[2] - '0';
                out += hex_encode(fp + 16 * idx, 10);
            } else if (name.rfind("xmm", 0) == 0) {
                const int idx = std::stoi(name.substr(3));
                out += hex_encode(fp + 160 + 16 * idx, 16);
            } else if (name == "fctrl") out += hex_encode(fp + 0, 2);
            else if (name == "fstat") out += hex_encode(fp + 2, 2);
            else if (name == "ftag") out += hex_encode(fp + 4, 2);
            else if (name == "fop") out += hex_encode(fp + 6, 2);
            else if (name == "fioff") out += hex_encode(fp + 8, 4);
            else if (name == "foseg") out += hex_encode(fp + 12, 4);
            else if (name == "fooff") out += hex_encode(fp + 16, 4);
            else if (name == "mxcsr") out += hex_encode(fp + 24, 4);
            else out += rep('x', bytes * 2);   // fiseg: not in FXSAVE
        }
        return out;
    }

    int reg_offset(int index) const {
        int off = 0;
        for (int i = 0; i < index; ++i) off += kRegs[i].bits / 4;
        return off;
    }

    std::string stop_reply(const ps4_event_t& ev) {
        // wait4 status: stopped = (status & 0xFF) == 0x7F, signal = (status>>8)&0xFF
        const uint32_t status = ev.status;
        char buf[64];
        if ((status & 0xFF) == 0x7F) {
            int sig = ev.signal;
            if (sig == 19) sig = 17;
            if (!(sig == 2 || sig == 4 || sig == 5 || sig == 8 || sig == 10 ||
                  sig == 11 || sig == 17))
                sig = 5;
            std::snprintf(buf, sizeof(buf), "T%02xthread:%x;", sig, ev.lwpid);
        } else if ((status & 0x7F) == 0) {
            std::snprintf(buf, sizeof(buf), "W%02x;", (status >> 8) & 0xFF);
        } else {
            std::snprintf(buf, sizeof(buf), "T%02xthread:%x;", ev.signal & 0xFF, ev.lwpid);
        }
        return buf;
    }

    // qXfer chunk: 'm' more follows, 'l' last
    std::string xfer_chunk(const std::string& content, size_t off, size_t len) {
        const char marker = (off + len >= content.size()) ? 'l' : 'm';
        const size_t start = std::min(off, content.size());
        const size_t end = std::min(off + len, content.size());
        return std::string(1, marker) + content.substr(start, end - start);
    }

    std::string memory_map_xml(uint32_t pid) {
        auto* p = backend();
        if (!p) return "";
        const auto h = handle_for(pid);
        const auto regs = p->enum_regions(h);
        std::string x = "<?xml version=\"1.0\"?><memory-map>";
        for (const auto& r : regs.items) {
            if (!(r.state & 0x1000)) continue;   // COMMIT only
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                          "<memory type=\"ram\" start=\"0x%llx\" length=\"0x%llx\">"
                          "<property name=\"read\">%d</property>"
                          "<property name=\"write\">%d</property>"
                          "<property name=\"execute\">%d</property></memory>",
                          static_cast<unsigned long long>(r.base),
                          static_cast<unsigned long long>(r.size),
                          (r.protect & 1) ? 1 : 0, (r.protect & 2) ? 1 : 0,
                          (r.protect & 4) ? 1 : 0);
            x += buf;
        }
        x += "</memory-map>";
        return x;
    }

    std::string libraries_xml(uint32_t pid) {
        auto* p = backend();
        if (!p) return "";
        const auto h = handle_for(pid);
        const auto mods = p->enum_modules(h);
        std::string x = "<?xml version=\"1.0\"?><library-list>";
        for (const auto& m : mods.items) {
            char buf[512];
            std::snprintf(buf, sizeof(buf),
                          "<library name=\"%s\"><segment address=\"0x%llx\"/></library>",
                          m.name.c_str(), static_cast<unsigned long long>(m.base));
            x += buf;
        }
        x += "</library-list>";
        return x;
    }

    // handle one decoded packet; returns the reply, or nullopt for "answer
    // asynchronously when the next stop event arrives" (c/s/vCont/?)
    std::optional<std::string> handle(conn_t& c, const std::string& cmd) {
        backend_ps4_t* p = nullptr;
        uint32_t pid = 0;
        auto reply = [](const std::string& s) { return std::optional<std::string>(s); };

        if (cmd.rfind("qSupported", 0) == 0)
            return reply("PacketSize=4000;qXfer:features:read+;qXfer:memory-map:read+;"
                         "qXfer:libraries-svr4:read+;QStartNoAckMode+");
        if (cmd == "QStartNoAckMode") { c.no_ack = true; return reply("OK"); }
        if (cmd == "!") return reply("OK");   // extended mode (radare2)
        if (cmd == "qHostInfo")
            return reply("cputype:16777223;cpusubtype:3;ostype:freebsd;vendor:unknown;"
                         "endian:little;ptrsize:8;");
        if (cmd == "qProcessInfo") {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            char buf[160];
            std::snprintf(buf, sizeof(buf),
                          "pid:%x;cputype:1000007;cpusubtype:3;ostype:freebsd;"
                          "vendor:unknown;endian:little;ptrsize:8;", pid);
            return reply(buf);
        }
        if (cmd.rfind("qXfer:features:read:target.xml:", 0) == 0) {
            const auto pos = cmd.rfind(':');
            const auto range = cmd.substr(pos + 1);
            const auto comma = range.find(',');
            int64_t off = 0, len = 0;
            if (comma == std::string::npos || !parse_hex(range.substr(0, comma), off) ||
                !parse_hex(range.substr(comma + 1), len) || off < 0 || len < 1)
                return reply("E01");
            static const std::string xml = target_xml();
            return reply(xfer_chunk(xml, static_cast<size_t>(off),
                                    std::min<size_t>(static_cast<size_t>(len), kMaxPacket - 1)));
        }
        if (cmd.rfind("qXfer:memory-map:read::", 0) == 0) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            const auto range = cmd.substr(cmd.rfind(':') + 1);
            const auto comma = range.find(',');
            int64_t off = 0, len = 0;
            if (comma == std::string::npos || !parse_hex(range.substr(0, comma), off) ||
                !parse_hex(range.substr(comma + 1), len))
                return reply("E01");
            if (off == 0 || !c.map_cached) { c.map_xml = memory_map_xml(pid); c.map_cached = true; }
            return reply(xfer_chunk(c.map_xml, static_cast<size_t>(off),
                                    std::min<size_t>(static_cast<size_t>(len), kMaxPacket - 1)));
        }
        if (cmd.rfind("qXfer:libraries-svr4:read::", 0) == 0) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            const auto range = cmd.substr(cmd.rfind(':') + 1);
            const auto comma = range.find(',');
            int64_t off = 0, len = 0;
            if (comma == std::string::npos || !parse_hex(range.substr(0, comma), off) ||
                !parse_hex(range.substr(comma + 1), len))
                return reply("E01");
            if (off == 0 || !c.libs_cached) { c.libs_xml = libraries_xml(pid); c.libs_cached = true; }
            return reply(xfer_chunk(c.libs_xml, static_cast<size_t>(off),
                                    std::min<size_t>(static_cast<size_t>(len), kMaxPacket - 1)));
        }
        if (cmd == "?") {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            if (p->ps4_debug_held() && !c.last_stop.empty()) return reply(c.last_stop);
            const auto evs = p->ps4_drain_events(64, true);
            if (!evs.empty()) {
                c.last_stop = stop_reply(evs.back());
                c.thread_id = evs.back().lwpid;
                return reply(c.last_stop);
            }
            c.awaiting_stop = true;
            return std::nullopt;
        }
        if (cmd.rfind("vAttach;", 0) == 0) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            int64_t want = 0;
            if (!parse_hex(cmd.substr(7), want) || static_cast<uint32_t>(want) != pid)
                return reply("E01");
            if (p->ps4_debug_held() && !c.last_stop.empty()) return reply(c.last_stop);
            return reply("S05");
        }
        if (cmd == "qAttached") return reply("1");
        if (cmd == "qC") {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            char buf[32];
            std::snprintf(buf, sizeof(buf), "QC%llx",
                          static_cast<unsigned long long>(current_thread(pid, c)));
            return reply(buf);
        }
        if (cmd == "qfThreadInfo" || cmd == "qsThreadInfo") {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            const auto t = threads(pid);
            if (cmd == "qsThreadInfo" || t.empty()) return reply("l");
            std::string r = "m";
            for (size_t i = 0; i < t.size(); ++i) {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%s%x", i ? "," : "", t[i]);
                r += buf;
            }
            return reply(r);
        }
        if (cmd.rfind("Hg", 0) == 0 || cmd.rfind("Hc", 0) == 0) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            int64_t sel = 0;
            if (!parse_hex(cmd.substr(2), sel)) return reply("E01");
            uint64_t tid = 0;
            if (sel > 0) {
                const auto t = threads(pid);
                if (std::find(t.begin(), t.end(), static_cast<uint32_t>(sel)) == t.end())
                    return reply("E01");
                tid = static_cast<uint64_t>(sel);
            }
            if (cmd[1] == 'g') c.thread_id = tid; else c.continue_thread = tid;
            return reply("OK");
        }
        if (cmd.rfind("T", 0) == 0 && cmd.size() > 1) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            int64_t sel = 0;
            if (!parse_hex(cmd.substr(1), sel)) return reply("E01");
            const auto t = threads(pid);
            return reply(std::find(t.begin(), t.end(), static_cast<uint32_t>(sel)) != t.end()
                             ? "OK" : "E01");
        }
        if (cmd == "g" || (cmd.rfind("p", 0) == 0 && cmd.size() > 1)) {
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            const uint64_t tid = current_thread(pid, c);
            if (!tid) return reply("E01");
            const std::string block = register_block(tid);
            if (cmd == "g") return reply(block);
            int64_t idx = 0;
            if (!parse_hex(cmd.substr(1), idx) || idx < 0 ||
                static_cast<size_t>(idx) >= kRegCount)
                return reply("E01");
            const int off = reg_offset(static_cast<int>(idx));
            return reply(block.substr(static_cast<size_t>(off),
                                      static_cast<size_t>(kRegs[idx].bits / 4)));
        }
        if (cmd.rfind("m", 0) == 0 && cmd.size() > 1) {
            const auto comma = cmd.find(',');
            if (comma == std::string::npos) return reply("E01");
            int64_t addr = 0, len = 0;
            if (!parse_hex(cmd.substr(1, comma - 1), addr) ||
                !parse_hex(cmd.substr(comma + 1), len) || addr < 0 || len < 0 ||
                static_cast<size_t>(len) > kMaxPacket / 2)
                return reply("E01");
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            if (len == 0) return reply("");
            const auto h = handle_for(pid);
            std::vector<uint8_t> buf(static_cast<size_t>(len));
            const auto io = p->read_memory(h, static_cast<uintptr_t>(addr), buf.data(),
                                           buf.size());
            if (!io.ok || io.bytes != buf.size()) return reply("E01");
            return reply(hex_encode(buf.data(), buf.size()));
        }
        // writes need explicit opt-in at server start
        if (cmd.rfind("M", 0) == 0 || cmd.rfind("G", 0) == 0 || cmd.rfind("P", 0) == 0 ||
            cmd.rfind("X", 0) == 0) {
            if (!allow_writes) return reply("E01");
            if (cmd.rfind("X", 0) == 0) return reply("");   // binary write unsupported
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            if (cmd.rfind("M", 0) == 0) {
                const auto colon = cmd.find(':');
                const auto comma = cmd.find(',');
                if (colon == std::string::npos || comma == std::string::npos ||
                    comma > colon)
                    return reply("E01");
                int64_t addr = 0, len = 0;
                if (!parse_hex(cmd.substr(1, comma - 1), addr) ||
                    !parse_hex(cmd.substr(comma + 1, colon - comma - 1), len) ||
                    addr < 0 || len < 0)
                    return reply("E01");
                const auto data = hex_decode(cmd.substr(colon + 1));
                if (static_cast<int64_t>(data.size()) != len) return reply("E01");
                if (len == 0) return reply("OK");
                const auto h = handle_for(pid);
                const auto io = p->write_memory(h, static_cast<uintptr_t>(addr),
                                                data.data(), data.size());
                return reply(io.ok ? "OK" : "E01");
            }
            if (cmd.rfind("P", 0) == 0) {
                const auto eq = cmd.find('=');
                if (eq == std::string::npos) return reply("E01");
                int64_t idx = 0;
                if (!parse_hex(cmd.substr(1, eq - 1), idx) || idx < 0 || idx > 17)
                    return reply("E01");   // GPRs + eflags only
                const auto raw = hex_decode(cmd.substr(eq + 1));
                const int bytes = kRegs[idx].bits / 8;
                if (static_cast<int>(raw.size()) != bytes) return reply("E01");
                uint64_t v = 0;
                std::memcpy(&v, raw.data(), bytes < 8 ? bytes : 8);
                const uint64_t tid = current_thread(pid, c);
                thread_context_t ctx{};
                if (!p->get_thread_context(static_cast<uint32_t>(tid), ctx).ok)
                    return reply("E01");
                const std::string name = kRegs[idx].name;
                if (name == "rax") ctx.rax = v;
                else if (name == "rbx") ctx.rbx = v;
                else if (name == "rcx") ctx.rcx = v;
                else if (name == "rdx") ctx.rdx = v;
                else if (name == "rsi") ctx.rsi = v;
                else if (name == "rdi") ctx.rdi = v;
                else if (name == "rbp") ctx.rbp = v;
                else if (name == "rsp") ctx.rsp = v;
                else if (name == "rip") ctx.rip = v;
                else if (name == "eflags") ctx.flags = v;
                else if (name.size() == 2 && name[0] == 'r') ctx.r8 = v + (name[1] - '8');
                else if (name.size() == 3 && name[0] == 'r' && name[1] == '1')
                    ctx.r10 = v + (name[2] - '0');
                if (!p->set_thread_context(static_cast<uint32_t>(tid), ctx).ok)
                    return reply("E01");
                return reply("OK");
            }
            // G: whole block; GPRs applied, 'x' fields skipped
            {
                const std::string& all = cmd.substr(1);
                const uint64_t tid = current_thread(pid, c);
                thread_context_t ctx{};
                if (!p->get_thread_context(static_cast<uint32_t>(tid), ctx).ok)
                    return reply("E01");
                int off = 0;
                bool any = false;
                for (size_t i = 0; i < 18 && off + kRegs[i].bits / 4 <= static_cast<int>(all.size()); ++i) {
                    const int w = kRegs[i].bits / 4;
                    const std::string slice = all.substr(off, w);
                    off += w;
                    if (slice.find('x') != std::string::npos) continue;
                    const auto raw = hex_decode(slice);
                    if (raw.empty()) continue;
                    uint64_t v = 0;
                    std::memcpy(&v, raw.data(), std::min<size_t>(raw.size(), 8));
                    const std::string name = kRegs[i].name;
                    if (name == "rax") ctx.rax = v;
                    else if (name == "rbx") ctx.rbx = v;
                    else if (name == "rcx") ctx.rcx = v;
                    else if (name == "rdx") ctx.rdx = v;
                    else if (name == "rsi") ctx.rsi = v;
                    else if (name == "rdi") ctx.rdi = v;
                    else if (name == "rbp") ctx.rbp = v;
                    else if (name == "rsp") ctx.rsp = v;
                    else if (name == "rip") ctx.rip = v;
                    else if (name == "eflags") ctx.flags = v;
                    else if (name.size() == 2 && name[0] == 'r') ctx.r8 = v + (name[1] - '8');
                    else if (name.size() == 3 && name[0] == 'r' && name[1] == '1')
                        ctx.r10 = v + (name[2] - '0');
                    any = true;
                }
                if (any && !p->set_thread_context(static_cast<uint32_t>(tid), ctx).ok)
                    return reply("E01");
                return reply("OK");
            }
        }
        if (cmd.rfind("Z", 0) == 0 || cmd.rfind("z", 0) == 0) {
            const bool set = cmd[0] == 'Z';
            const auto parts = [&] {
                std::vector<std::string> v;
                size_t off = 1;
                while (off <= cmd.size()) {
                    const auto comma = cmd.find(',', off);
                    v.push_back(cmd.substr(off, comma == std::string::npos
                                                       ? std::string::npos : comma - off));
                    if (comma == std::string::npos) break;
                    off = comma + 1;
                }
                return v;
            }();
            if (parts.size() != 3) return reply("E01");
            int64_t kind = 0, addr = 0, len = 0;
            if (!parse_hex(parts[0], kind) || !parse_hex(parts[1], addr) ||
                !parse_hex(parts[2], len) || addr < 0)
                return reply("E01");
            if (kind != 0 && kind != 1 && kind != 2 && kind != 3 && kind != 4)
                return reply("");   // unsupported kind: empty = not supported
            std::lock_guard g(broker_gate());
            if (!ensure_session(p, pid)) return reply("E01");
            if (!p->ps4_debug_attached()) return reply("E01");
            io_result_t io{};
            if (kind <= 1) {
                if (set) {
                    uint32_t index = 0;
                    bool reused = false;
                    io = p->ps4_bp_arm(static_cast<uint64_t>(addr),
                                       backend_ps4_t::kAutoSlot, index, &reused);
                } else {
                    io = p->ps4_bp_disarm_addr(static_cast<uint64_t>(addr));
                }
            } else {
                const uint32_t wtype = kind == 2 ? 1u : 3u;   // write / read-write
                if (len != 1 && len != 2 && len != 4 && len != 8) return reply("E01");
                if (set) {
                    uint32_t index = 0;
                    bool reused = false;
                    io = p->ps4_wp_arm(static_cast<uint64_t>(addr),
                                       static_cast<uint32_t>(len), wtype,
                                       backend_ps4_t::kAutoSlot, index, &reused);
                } else {
                    io = p->ps4_wp_disarm_addr(static_cast<uint64_t>(addr));
                }
            }
            return reply(io.ok ? "OK" : "E01");
        }
        if (cmd == "vCont?") return reply("vCont;c;s");
        if (cmd.rfind("vCont;", 0) == 0) {
            std::string rest = cmd.substr(6);
            const auto semi = rest.find(';');
            if (semi != std::string::npos) return reply("");   // mixed actions unsupported
            std::string act = rest;
            uint64_t tid = 0;
            const auto colon = rest.find(':');
            if (colon != std::string::npos) {
                act = rest.substr(0, colon);
                int64_t t = 0;
                if (!parse_hex(rest.substr(colon + 1), t)) return reply("E01");
                tid = t > 0 ? static_cast<uint64_t>(t) : 0;
            }
            if (act != "c" && act != "s") return reply("");
            return resume(c, act == "s", tid);
        }
        if (cmd == "c" || cmd == "s") return resume(c, cmd == "s", 0);
        if (cmd == "D" || (cmd.rfind("D;", 0) == 0)) {
            // detach only closes this RSP connection; the shared console debug
            // session stays up for the UI/MCP clients
            c.finished = true;
            return reply("OK");
        }
        // kill/restart/monitor and friends stay refused
        if (cmd.rfind("k", 0) == 0 || cmd.rfind("vKill", 0) == 0 || cmd.rfind("R", 0) == 0 ||
            cmd.rfind("vRun", 0) == 0 || cmd.rfind("qRcmd", 0) == 0)
            return reply("E01");
        return reply("");   // unknown: empty = unsupported
    }

    std::optional<std::string> resume(conn_t& c, bool step, uint64_t tid) {
        backend_ps4_t* p = nullptr;
        uint32_t pid = 0;
        std::lock_guard g(broker_gate());
        if (!ensure_session(p, pid)) return "E01";
        if (c.last_stop.empty()) return "E01";   // wait for a real stop first
        io_result_t io{};
        if (step) {
            uint32_t t = tid ? static_cast<uint32_t>(tid)
                             : (c.continue_thread ? static_cast<uint32_t>(c.continue_thread)
                                                  : (c.thread_id ? static_cast<uint32_t>(c.thread_id) : 0));
            io = p->ps4_step(t);
        } else {
            if (tid) return "E01";   // thread-specific continue not supported
            io = p->ps4_continue(ps4::kStopResume);
        }
        if (!io.ok) return "E01";
        c.last_stop.clear();
        c.awaiting_stop = true;
        return std::nullopt;   // the stop reply goes out when the event arrives
    }

    // called from the connection loop when awaiting_stop
    std::optional<std::string> poll_stop(conn_t& c) {
        backend_ps4_t* p = nullptr;
        uint32_t pid = 0;
        std::lock_guard g(broker_gate());
        if (!ensure_session(p, pid)) return std::string("E01");
        ps4_event_t ev{};
        if (!p->ps4_wait_event(ev, 0)) return std::nullopt;
        c.last_stop = stop_reply(ev);
        c.thread_id = ev.lwpid;
        c.awaiting_stop = false;
        return c.last_stop;
    }

    void client_loop(std::shared_ptr<conn_t> c) {
        decoder_t dec;
        uint8_t buf[kMaxPacket];
        while (!c->finished) {
            const int n = ::recv(c->sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n == 0) break;
            if (n == SOCKET_ERROR) {
                const int e = ::WSAGetLastError();
                if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK || e == WSAEINTR) {
                    // poll for a pending stop event
                    if (c->awaiting_stop) {
                        const auto r = poll_stop(*c);
                        if (r) {
                            const auto f = frame(*r);
                            if (send_all(c->sock, f.data(), f.size())) {
                                c->last_frame = f;
                                c->unacknowledged = !c->no_ack;
                            }
                        }
                    }
                    continue;
                }
                break;
            }
            std::vector<decoder_t::msg_t_> msgs;
            try {
                msgs = dec.feed(buf, static_cast<size_t>(n));
            } catch (const std::string&) {
                break;
            }
            for (auto& m : msgs) {
                switch (m.kind) {
                case decoder_t::msg_t::ack:
                    c->unacknowledged = false;
                    continue;
                case decoder_t::msg_t::nak:
                    if (!c->last_frame.empty())
                        send_all(c->sock, c->last_frame.data(), c->last_frame.size());
                    continue;
                case decoder_t::msg_t::bad:
                    if (!c->no_ack)
                        send_all(c->sock, reinterpret_cast<const uint8_t*>("-"), 1);
                    continue;
                case decoder_t::msg_t::interrupt: {
                    // Ctrl-C: report the last stop (no async halt on the payload)
                    const std::string r = c->last_stop.empty() ? "S02" : c->last_stop;
                    const auto f = frame(r);
                    if (send_all(c->sock, f.data(), f.size())) {
                        c->last_frame = f;
                        c->unacknowledged = !c->no_ack;
                    }
                    continue;
                }
                case decoder_t::msg_t::packet: break;
                }
                const std::string payload(m.payload.begin(), m.payload.end());
                if (!c->no_ack)
                    send_all(c->sock, reinterpret_cast<const uint8_t*>("+"), 1);
                if (c->unacknowledged && payload.size() == c->last_request.size() &&
                    payload == std::string(c->last_request.begin(), c->last_request.end())) {
                    if (!c->last_frame.empty())
                        send_all(c->sock, c->last_frame.data(), c->last_frame.size());
                    continue;
                }
                std::optional<std::string> out;
                try {
                    out = handle(*c, payload);
                } catch (const std::exception&) {
                    out = std::string("E01");
                } catch (...) {
                    out = std::string("E01");
                }
                if (out) {
                    c->last_request.assign(payload.begin(), payload.end());
                    const auto f = frame(*out);
                    if (send_all(c->sock, f.data(), f.size())) {
                        c->last_frame = f;
                        c->unacknowledged = !c->no_ack;
                    }
                }
            }
        }
        ::closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }

    void accept_loop() {
        while (running) {
            sockaddr_in addr{};
            int alen = sizeof(addr);
            const SOCKET s = ::accept(listen_sock, reinterpret_cast<sockaddr*>(&addr), &alen);
            if (s == INVALID_SOCKET) break;
            auto c = std::make_shared<conn_t>();
            c->sock = s;
            DWORD to = kPollMs;
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to),
                         sizeof(to));
            int one = 1;
            ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one),
                         sizeof(one));
            {
                std::lock_guard lk(clients_mu);
                clients.push_back(c);
            }
            c->th = std::thread([this, c] { client_loop(c); });
        }
    }

    bool start(const std::string& b, uint16_t p, bool writes, std::string& err,
               backend_ps4_t* tb) {
        if (running) {
            err = "already running on " + bind + ":" + std::to_string(port);
            return false;
        }
        test_backend = tb;
        listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            err = "socket failed";
            return false;
        }
        BOOL reuse = TRUE;
        ::setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(p);
        if (b == "0.0.0.0" || b.empty())
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        else if (::inet_pton(AF_INET, b.c_str(), &addr.sin_addr) != 1) {
            ::closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
            err = "bad bind address: " + b;
            return false;
        }
        if (::bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(listen_sock, 8) != 0) {
            err = "bind/listen on " + b + ":" + std::to_string(p) + " failed";
            ::closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
            return false;
        }
        sockaddr_in bound{};
        int bl = sizeof(bound);
        ::getsockname(listen_sock, reinterpret_cast<sockaddr*>(&bound), &bl);
        port = ntohs(bound.sin_port);
        bind = b;
        allow_writes = writes;
        running = true;
        accept_th = std::thread([this] { accept_loop(); });
        broker_client_attach("gdb:" + std::to_string(port));
        return true;
    }

    void stop() {
        if (!running) return;
        running = false;
        if (listen_sock != INVALID_SOCKET) {
            ::shutdown(listen_sock, SD_BOTH);
            ::closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
        }
        if (accept_th.joinable()) accept_th.join();
        std::vector<std::shared_ptr<conn_t>> cs;
        {
            std::lock_guard lk(clients_mu);
            cs = clients;
        }
        for (auto& c : cs) {
            c->finished = true;
            if (c->sock != INVALID_SOCKET) ::shutdown(c->sock, SD_BOTH);
        }
        for (auto& c : cs)
            if (c->th.joinable()) c->th.join();
        {
            std::lock_guard lk(clients_mu);
            clients.clear();
        }
        if (mem_handle.valid()) {
            auto* p = backend();
            if (p) p->detach(mem_handle);
        }
        mem_handle = {};
        mem_pid = 0;
        broker_client_detach("gdb:" + std::to_string(port));
    }
};

gdb_rsp_server_t::gdb_rsp_server_t() : p_(std::make_unique<impl_t>()) {}
gdb_rsp_server_t::~gdb_rsp_server_t() { stop(); }

bool gdb_rsp_server_t::start(const std::string& bind, uint16_t port, bool allow_writes,
                             std::string& err, backend_ps4_t* test_backend) {
    return p_->start(bind, port, allow_writes, err, test_backend);
}
void gdb_rsp_server_t::stop() { p_->stop(); }
bool gdb_rsp_server_t::running() const noexcept { return p_->running; }
uint16_t gdb_rsp_server_t::port() const noexcept { return p_->port; }
bool gdb_rsp_server_t::allow_writes() const noexcept { return p_->allow_writes; }
size_t gdb_rsp_server_t::client_count() const noexcept {
    std::lock_guard lk(p_->clients_mu);
    return p_->clients.size();
}

gdb_rsp_server_t& gdb_rsp() {
    static gdb_rsp_server_t s;
    return s;
}

} // namespace slop::core::runtime
