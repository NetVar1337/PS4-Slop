// src/core/debugger/local_debugger.cpp
// Win32 debug loop on a dedicated thread (WaitForDebugEvent/ContinueDebugEvent
// must run on the thread that called DebugActiveProcess). Callers talk to it
// through a small command queue; stop events flow back through a queue.

#include "core/debugger/local_debugger.hpp"

#include <windows.h>

#include "core/infra/clock.hpp"
#include "core/runtime/context.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <thread>

namespace slop::core::debugger {

namespace {

namespace infra = slop::core::infra;
namespace ps4 = slop::core::runtime::ps4;
using runtime::io_result_t;

constexpr DWORD kWx86Breakpoint = 0x4000001F;   // STATUS_WX86_BREAKPOINT
constexpr DWORD kWx86SingleStep = 0x4000001E;   // STATUS_WX86_SINGLE_STEP
constexpr uint64_t kTrapFlag    = 0x100;
constexpr uint64_t kResumeFlag  = 0x10000;

io_result_t ok_result() { return io_result_t{true, 0, 0}; }
io_result_t err_result(uint32_t code) { return io_result_t{false, 0, code}; }
io_result_t last_error() { return io_result_t{false, 0, GetLastError()}; }

std::string win32_text(DWORD code) {
    return ps4::io_error_str(code);
}

} // namespace

struct local_debugger_t::impl_t {
    std::thread loop_thread; // the debug loop
    std::atomic<bool>     alive{false};    // attached and the loop runs
    std::atomic<bool>     quit{false};
    std::atomic<bool>     held{false};     // a stop event holds the process
    std::atomic<uint32_t> pid{0};
    std::atomic<HANDLE>   proc{nullptr};   // our own handle (not the event's)

    // commands executed on the debug thread
    std::mutex cmd_mu;
    std::condition_variable cmd_cv;
    std::deque<std::packaged_task<io_result_t()>> cmds;

    // stop events
    std::mutex ev_mu;
    std::condition_variable ev_cv;
    std::deque<stop_event_t> evq;

    // slots (read by callers, written on the debug thread)
    struct bp_t { bool used = false; uint64_t addr = 0; uint8_t orig = 0; };
    struct wp_t { bool used = false; uint64_t addr = 0; uint32_t len = 0, type = 0; };
    mutable std::mutex slot_mu;
    std::array<bp_t, kMaxBreakpoints> bps{};
    std::array<wp_t, kMaxWatchpoints> wps{};

    // ---- debug-thread-only state -------------------------------------
    std::map<DWORD, HANDLE> threads;          // event-owned handles, never closed by us
    DEBUG_EVENT pending{};                    // the held stop
    DWORD       pending_cont = DBG_CONTINUE;
    int         pending_bp = -1;              // slot the held stop sits on
    bool        pending_exec_watch = false;   // resume needs RF set
    bool        initial_bp_seen = false;
    std::map<DWORD, uint64_t> stepping_over;  // tid -> bp addr to re-insert after TF trap
    std::set<DWORD> user_step;                // tids with a requested single step

    ~impl_t() { stop_thread(); }

    // ---- queue plumbing ----------------------------------------------
    io_result_t post(std::function<io_result_t()> fn) {
        std::packaged_task<io_result_t()> task(std::move(fn));
        auto fut = task.get_future();
        {
            // alive flips under cmd_mu at teardown, so nothing is queued
            // after the loop dropped its queue
            std::lock_guard lk(cmd_mu);
            if (!alive.load()) return err_result(ps4::kErrNotAttached);
            cmds.push_back(std::move(task));
        }
        cmd_cv.notify_all();
        if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready)
            return err_result(ps4::kErrTimeout);
        try {
            return fut.get();
        } catch (const std::future_error&) {
            return err_result(ps4::kErrNotAttached);   // dropped at teardown
        }
    }

    void run_cmds() {
        std::deque<std::packaged_task<io_result_t()>> batch;
        {
            std::lock_guard lk(cmd_mu);
            batch.swap(cmds);
        }
        for (auto& t : batch) t();
    }

    // teardown: stop accepting commands; queued ones are dropped (their
    // waiters see a broken promise and report "not attached")
    void close_queue() {
        std::deque<std::packaged_task<io_result_t()>> batch;
        {
            std::lock_guard lk(cmd_mu);
            alive = false;
            batch.swap(cmds);
        }
    }

    void push_event(stop_event_t ev) {
        {
            std::lock_guard lk(ev_mu);
            if (evq.size() >= 4096) evq.pop_front();
            evq.push_back(std::move(ev));
        }
        ev_cv.notify_all();
    }

    // ---- thread contexts ---------------------------------------------
    HANDLE thread_handle(DWORD tid) {
        auto it = threads.find(tid);
        return it == threads.end() ? nullptr : it->second;
    }

    static bool get_ctx(HANDLE worker, CONTEXT& c, DWORD flags) {
        std::memset(&c, 0, sizeof(c));
        c.ContextFlags = flags;
        return GetThreadContext(worker, &c) != FALSE;
    }

    stop_event_t make_event(DWORD tid, const char* reason, int signal, uint64_t code) {
        stop_event_t ev;
        ev.tid = tid;
        ev.reason = reason;
        ev.signal = signal;
        ev.status = code;
        if (HANDLE worker = thread_handle(tid)) {
            alignas(16) CONTEXT c;
            if (get_ctx(worker, c, CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS)) {
                runtime::context_from_win(ev.ctx, c);
                ev.dr[0] = c.Dr0; ev.dr[1] = c.Dr1; ev.dr[2] = c.Dr2; ev.dr[3] = c.Dr3;
                ev.dr[6] = c.Dr6; ev.dr[7] = c.Dr7;
            }
        }
        return ev;
    }

    bool set_flags(HANDLE worker, uint64_t set_bits, uint64_t clear_bits) {
        alignas(16) CONTEXT c;
        if (!get_ctx(worker, c, CONTEXT_CONTROL)) return false;
        c.EFlags = static_cast<DWORD>((c.EFlags | set_bits) & ~clear_bits);
        return SetThreadContext(worker, &c) != FALSE;
    }

    // DR0-DR3/DR7 of one thread from the watchpoint table
    void apply_drs(HANDLE worker) {
        std::array<wp_t, kMaxWatchpoints> w;
        {
            std::lock_guard lk(slot_mu);
            w = wps;
        }
        const DWORD sus = SuspendThread(worker);
        alignas(16) CONTEXT c;
        if (get_ctx(worker, c, CONTEXT_DEBUG_REGISTERS)) {
            DWORD64 dr7 = 0;
            DWORD64* drs[4] = {&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
            for (uint32_t i = 0; i < kMaxWatchpoints; ++i) {
                if (!w[i].used) { *drs[i] = 0; continue; }
                *drs[i] = w[i].addr;
                const DWORD64 rw = w[i].type == kWatchExec ? 0 : (w[i].type == kWatchWrite ? 1 : 3);
                const DWORD64 ln = w[i].type == kWatchExec ? 0
                                 : w[i].len == 1 ? 0 : w[i].len == 2 ? 1 : w[i].len == 8 ? 2 : 3;
                dr7 |= DWORD64{1} << (2 * i);
                dr7 |= rw << (16 + 4 * i);
                dr7 |= ln << (18 + 4 * i);
            }
            c.Dr7 = dr7;
            c.Dr6 = 0;
            SetThreadContext(worker, &c);
        }
        if (sus != static_cast<DWORD>(-1)) ResumeThread(worker);
    }

    void apply_drs_all() {
        for (const auto& [tid, worker] : threads) apply_drs(worker);
    }

    // ---- code patching -----------------------------------------------
    bool write_byte(uint64_t addr, uint8_t v) {
        HANDLE h = proc.load();
        SIZE_T n = 0;
        if (WriteProcessMemory(h, reinterpret_cast<LPVOID>(addr), &v, 1, &n) && n == 1) {
            FlushInstructionCache(h, reinterpret_cast<LPCVOID>(addr), 1);
            return true;
        }
        DWORD old = 0;
        if (!VirtualProtectEx(h, reinterpret_cast<LPVOID>(addr), 1, PAGE_EXECUTE_READWRITE, &old))
            return false;
        const BOOL ok = WriteProcessMemory(h, reinterpret_cast<LPVOID>(addr), &v, 1, &n);
        DWORD tmp = 0;
        VirtualProtectEx(h, reinterpret_cast<LPVOID>(addr), 1, old, &tmp);
        FlushInstructionCache(h, reinterpret_cast<LPCVOID>(addr), 1);
        return ok && n == 1;
    }

    int bp_slot_at(uint64_t addr) const {
        std::lock_guard lk(slot_mu);
        for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
            if (bps[i].used && bps[i].addr == addr) return static_cast<int>(i);
        return -1;
    }

    // ---- event handling ----------------------------------------------
    // returns true when the event is held as a stop
    bool on_exception(const DEBUG_EVENT& de, DWORD& cont) {
        const auto& er = de.u.Exception.ExceptionRecord;
        const DWORD code = er.ExceptionCode;
        const uint64_t at = reinterpret_cast<uint64_t>(er.ExceptionAddress);
        const DWORD tid = de.dwThreadId;

        if (code == EXCEPTION_BREAKPOINT || code == kWx86Breakpoint) {
            const int slot = bp_slot_at(at);
            if (slot >= 0) {
                // rewind past the int3 so the stop shows (and resumes at) addr
                if (HANDLE worker = thread_handle(tid)) {
                    alignas(16) CONTEXT c;
                    if (get_ctx(worker, c, CONTEXT_CONTROL)) {
                        c.Rip = at;
                        SetThreadContext(worker, &c);
                    }
                }
                pending_bp = slot;
                pending_exec_watch = false;
                cont = DBG_CONTINUE;
                push_event(make_event(tid, "breakpoint", 5, code));
                return true;
            }
            if (!initial_bp_seen) {   // the attach break-in thread
                initial_bp_seen = true;
                cont = DBG_CONTINUE;
                return false;
            }
            cont = DBG_EXCEPTION_NOT_HANDLED;   // the program's own int3
            return false;
        }

        if (code == EXCEPTION_SINGLE_STEP || code == kWx86SingleStep) {
            bool ours = false, report = false, exec_watch = false;
            const char* reason = "single_step";
            if (auto it = stepping_over.find(tid); it != stepping_over.end()) {
                const uint64_t bp_addr = it->second;
                stepping_over.erase(it);
                if (bp_slot_at(bp_addr) >= 0) write_byte(bp_addr, 0xCC);   // re-insert
                ours = true;
            }
            if (user_step.erase(tid)) { ours = true; report = true; }
            if (HANDLE worker = thread_handle(tid)) {
                alignas(16) CONTEXT c;
                if (get_ctx(worker, c, CONTEXT_DEBUG_REGISTERS) && (c.Dr6 & 0xF)) {
                    std::lock_guard lk(slot_mu);
                    for (uint32_t i = 0; i < kMaxWatchpoints; ++i) {
                        if (!(c.Dr6 & (DWORD64{1} << i)) || !wps[i].used) continue;
                        ours = true;
                        report = true;
                        reason = "watchpoint";
                        if (wps[i].type == kWatchExec) exec_watch = true;
                    }
                }
            }
            if (!ours) { cont = DBG_EXCEPTION_NOT_HANDLED; return false; }
            cont = DBG_CONTINUE;
            if (!report) return false;   // silent step-over finished
            stop_event_t ev = make_event(tid, reason, 5, code);
            if (HANDLE worker = thread_handle(tid)) {   // DR6 is sticky: clear it
                alignas(16) CONTEXT c;
                if (get_ctx(worker, c, CONTEXT_DEBUG_REGISTERS)) { c.Dr6 = 0; SetThreadContext(worker, &c); }
            }
            pending_bp = -1;
            pending_exec_watch = exec_watch;
            push_event(std::move(ev));
            return true;
        }

        // the program's own exceptions: first chance goes to its handlers,
        // a second chance (about to crash) is reported and held
        cont = DBG_EXCEPTION_NOT_HANDLED;
        if (de.u.Exception.dwFirstChance) return false;
        pending_bp = -1;
        pending_exec_watch = false;
        push_event(make_event(tid, "exception", 0, code));
        return true;
    }

    // release the held stop; step_tid != 0 single-steps that thread
    io_result_t continue_held(DWORD step_tid) {
        if (!held.load()) return ok_result();
        if (step_tid && !thread_handle(step_tid)) return err_result(ERROR_INVALID_PARAMETER);
        const DWORD tid = pending.dwThreadId;
        HANDLE worker = thread_handle(tid);
        if (pending_bp >= 0 && worker) {
            uint64_t addr = 0;
            uint8_t orig = 0;
            bool used = false;
            {
                std::lock_guard lk(slot_mu);
                used = bps[static_cast<size_t>(pending_bp)].used;
                addr = bps[static_cast<size_t>(pending_bp)].addr;
                orig = bps[static_cast<size_t>(pending_bp)].orig;
            }
            if (used) {
                // step over the breakpoint: original byte back, one TF trap,
                // then the int3 is re-inserted (see on_exception)
                write_byte(addr, orig);
                set_flags(worker, kTrapFlag, 0);
                stepping_over[tid] = addr;
            }
        }
        if (pending_exec_watch && worker) set_flags(worker, kResumeFlag, 0);   // skip the DR0-3 exec fault once
        if (step_tid) {
            HANDLE sth = thread_handle(step_tid);
            if (!sth) return err_result(ERROR_INVALID_PARAMETER);
            set_flags(sth, kTrapFlag, 0);
            user_step.insert(step_tid);
        }
        if (!ContinueDebugEvent(pending.dwProcessId, tid, pending_cont)) return last_error();
        held = false;
        pending_bp = -1;
        pending_exec_watch = false;
        return ok_result();
    }

    // ---- teardown ------------------------------------------------------
    void unpatch_everything(std::set<uint64_t>& removed) {
        std::array<bp_t, kMaxBreakpoints> b;
        {
            std::lock_guard lk(slot_mu);
            b = bps;
            for (auto& x : bps) x = bp_t{};
            for (auto& x : wps) x = wp_t{};
        }
        for (const auto& x : b) {
            if (!x.used) continue;
            write_byte(x.addr, x.orig);
            removed.insert(x.addr);
        }
        for (const auto& [tid, worker] : threads) {
            apply_drs(worker);                     // all slots empty now
            set_flags(worker, 0, kTrapFlag);       // no step trap may outlive us
        }
        stepping_over.clear();
        user_step.clear();
    }

    // events already queued for breakpoints we just removed would leave a
    // thread one byte past the original instruction: rewind and swallow them
    void drain_after_unpatch(const std::set<uint64_t>& removed) {
        const int64_t until = infra::steady_ms() + 100;
        while (infra::steady_ms() < until) {
            DEBUG_EVENT de{};
            if (!WaitForDebugEvent(&de, 10)) continue;
            DWORD cont = DBG_CONTINUE;
            if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                const auto& er = de.u.Exception.ExceptionRecord;
                const uint64_t at = reinterpret_cast<uint64_t>(er.ExceptionAddress);
                const DWORD code = er.ExceptionCode;
                if ((code == EXCEPTION_BREAKPOINT || code == kWx86Breakpoint) && removed.count(at)) {
                    if (HANDLE worker = thread_handle(de.dwThreadId)) {
                        alignas(16) CONTEXT c;
                        if (get_ctx(worker, c, CONTEXT_CONTROL)) { c.Rip = at; SetThreadContext(worker, &c); }
                    }
                } else if (code == EXCEPTION_SINGLE_STEP || code == kWx86SingleStep) {
                    cont = DBG_CONTINUE;   // a leftover TF trap of ours
                } else {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                }
            } else if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
                       de.u.CreateProcessInfo.hFile) {
                CloseHandle(de.u.CreateProcessInfo.hFile);
            } else if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && de.u.LoadDll.hFile) {
                CloseHandle(de.u.LoadDll.hFile);
            } else if (de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                threads[de.dwThreadId] = de.u.CreateThread.hThread;
            } else if (de.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                threads.erase(de.dwThreadId);
            }
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
        }
    }

    // ---- the loop ------------------------------------------------------
    void loop(uint32_t target, std::promise<std::string> ready) {
        if (!DebugActiveProcess(target)) {
            ready.set_value("DebugActiveProcess(" + std::to_string(target) + ") failed: " +
                            win32_text(GetLastError()));
            return;
        }
        DebugSetProcessKillOnExit(FALSE);
        bool ready_sent = false;
        bool exited = false;
        const int64_t attach_deadline = infra::steady_ms() + 10000;
        while (!quit.load()) {
            run_cmds();
            if (quit.load()) break;
            if (held.load()) {
                std::unique_lock lk(cmd_mu);
                cmd_cv.wait_for(lk, std::chrono::milliseconds(20),
                                [this] { return !cmds.empty() || quit.load(); });
                continue;
            }
            DEBUG_EVENT de{};
            if (!WaitForDebugEvent(&de, 20)) {
                if (!ready_sent && infra::steady_ms() > attach_deadline) {
                    // no break-in arrived: treat the attach as done anyway
                    initial_bp_seen = true;
                    alive = true;
                    ready.set_value("");
                    ready_sent = true;
                }
                continue;
            }
            DWORD cont = DBG_CONTINUE;
            bool hold = false;
            switch (de.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                threads[de.dwThreadId] = de.u.CreateProcessInfo.hThread;
                if (de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                threads[de.dwThreadId] = de.u.CreateThread.hThread;
                apply_drs(de.u.CreateThread.hThread);
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                threads.erase(de.dwThreadId);
                stepping_over.erase(de.dwThreadId);
                user_step.erase(de.dwThreadId);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
                break;
            case EXIT_PROCESS_DEBUG_EVENT: {
                stop_event_t ev;
                ev.tid = de.dwThreadId;
                ev.reason = "exit";
                ev.status = de.u.ExitProcess.dwExitCode;
                push_event(std::move(ev));
                exited = true;
                break;
            }
            case EXCEPTION_DEBUG_EVENT:
                hold = on_exception(de, cont);
                break;
            default:
                break;
            }
            if (hold) {
                pending = de;
                pending_cont = cont;
                held = true;
                continue;
            }
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
            if (!ready_sent && initial_bp_seen) {
                alive = true;
                ready.set_value("");
                ready_sent = true;
            }
            if (exited) break;
        }

        // teardown on the debug thread; no new commands from here on
        close_queue();
        if (!exited) {
            std::set<uint64_t> removed;
            unpatch_everything(removed);
            if (held.load()) {
                ContinueDebugEvent(pending.dwProcessId, pending.dwThreadId,
                                   pending_cont == DBG_EXCEPTION_NOT_HANDLED ? DBG_EXCEPTION_NOT_HANDLED
                                                                             : DBG_CONTINUE);
                held = false;
            }
            drain_after_unpatch(removed);
            DebugActiveProcessStop(target);
        }
        held = false;
        if (!ready_sent) ready.set_value(exited ? "process exited during attach" : "attach aborted");
        threads.clear();
        {
            std::lock_guard lk(slot_mu);
            for (auto& x : bps) x = bp_t{};
            for (auto& x : wps) x = wp_t{};
        }
        ev_cv.notify_all();
    }

    void stop_thread() {
        quit = true;
        cmd_cv.notify_all();
        if (loop_thread.joinable()) loop_thread.join();
        if (HANDLE h = proc.exchange(nullptr)) CloseHandle(h);
        pid = 0;
    }
};

local_debugger_t::local_debugger_t() : m_(std::make_unique<impl_t>()) {}

local_debugger_t::~local_debugger_t() {
    detach();
}

bool local_debugger_t::attach(uint32_t pid, std::string& err) {
    if (attached()) {
        if (m_->pid.load() == pid) return true;
        detach();
    }
    m_->stop_thread();   // a previous loop that ended on its own (exit)
    m_->quit = false;
    m_->held = false;
    m_->initial_bp_seen = false;
    m_->pending_bp = -1;
    {
        std::lock_guard lk(m_->ev_mu);
        m_->evq.clear();
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                           PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) {
        err = "OpenProcess(" + std::to_string(pid) + ") failed: " + win32_text(GetLastError());
        return false;
    }
    m_->proc = h;
    std::promise<std::string> ready;
    auto fut = ready.get_future();
    m_->loop_thread = std::thread([this, pid, p = std::move(ready)]() mutable { m_->loop(pid, std::move(p)); });
    if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
        err = "attach timed out";
        m_->stop_thread();
        return false;
    }
    err = fut.get();
    if (!err.empty()) {
        m_->stop_thread();
        return false;
    }
    m_->pid = pid;
    return true;
}

void local_debugger_t::detach() {
    m_->stop_thread();
    std::lock_guard lk(m_->ev_mu);
    m_->evq.clear();
}

uint32_t local_debugger_t::pid() const noexcept {
    return attached() ? m_->pid.load() : 0;
}

bool local_debugger_t::stopped() const noexcept {
    return m_->held.load();
}

bool local_debugger_t::attached() const {
    return m_->alive.load();
}

std::vector<local_debugger_t::slot_t> local_debugger_t::breakpoints() const {
    std::lock_guard lk(m_->slot_mu);
    std::vector<slot_t> out;
    for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
        if (m_->bps[i].used) out.push_back({i, m_->bps[i].addr, 0, 0});
    return out;
}

std::vector<local_debugger_t::slot_t> local_debugger_t::watchpoints() const {
    std::lock_guard lk(m_->slot_mu);
    std::vector<slot_t> out;
    for (uint32_t i = 0; i < kMaxWatchpoints; ++i)
        if (m_->wps[i].used) out.push_back({i, m_->wps[i].addr, m_->wps[i].len, m_->wps[i].type});
    return out;
}

// the debug-thread lambdas hand the slot back in io_result_t.bytes (index,
// bit 8 = reused) so nothing on the caller's stack is captured by reference
constexpr size_t kReusedBit = 0x100;

io_result_t local_debugger_t::bp_arm(uint64_t addr, uint32_t& index, bool& reused) {
    reused = false;
    if (addr == 0) return err_result(ps4::kErrBadArg);
    io_result_t r = m_->post([this, addr]() -> io_result_t {
        auto& m = *m_;
        int free_slot = -1;
        {
            std::lock_guard lk(m.slot_mu);
            for (uint32_t i = 0; i < kMaxBreakpoints; ++i) {
                if (m.bps[i].used && m.bps[i].addr == addr) return io_result_t{true, i | kReusedBit, 0};
                if (!m.bps[i].used && free_slot < 0) free_slot = static_cast<int>(i);
            }
        }
        if (free_slot < 0) return err_result(ps4::kErrNoSlot);
        uint8_t orig = 0;
        SIZE_T n = 0;
        if (!ReadProcessMemory(m.proc.load(), reinterpret_cast<LPCVOID>(addr), &orig, 1, &n) || n != 1)
            return last_error();
        {
            std::lock_guard lk(m.slot_mu);
            m.bps[static_cast<size_t>(free_slot)] = impl_t::bp_t{true, addr, orig};
        }
        if (!m.write_byte(addr, 0xCC)) {
            const DWORD e = GetLastError();
            std::lock_guard lk(m.slot_mu);
            m.bps[static_cast<size_t>(free_slot)] = impl_t::bp_t{};
            return err_result(e);
        }
        return io_result_t{true, static_cast<size_t>(free_slot), 0};
    });
    if (r.ok) {
        index  = static_cast<uint32_t>(r.bytes & 0xFF);
        reused = (r.bytes & kReusedBit) != 0;
        r.bytes = 0;
    }
    return r;
}

io_result_t local_debugger_t::bp_disarm(uint64_t addr) {
    return m_->post([this, addr]() -> io_result_t {
        auto& m = *m_;
        impl_t::bp_t rec{};
        int slot = -1;
        {
            std::lock_guard lk(m.slot_mu);
            for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
                if (m.bps[i].used && m.bps[i].addr == addr) { slot = static_cast<int>(i); rec = m.bps[i]; break; }
            if (slot < 0) return err_result(ps4::kErrNotArmed);
            m.bps[static_cast<size_t>(slot)] = impl_t::bp_t{};
        }
        if (m.pending_bp == slot) m.pending_bp = -1;   // the held thread already sits on addr
        if (!m.write_byte(rec.addr, rec.orig)) return last_error();
        return ok_result();
    });
}

io_result_t local_debugger_t::wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                     uint32_t& index, bool& reused) {
    reused = false;
    if (len != 1 && len != 2 && len != 4 && len != 8) return err_result(ps4::kErrBadArg);
    if (type != kWatchExec && type != kWatchWrite && type != kWatchReadWrite)
        return err_result(ps4::kErrBadArg);
    if (type != kWatchExec && (addr % len) != 0) return err_result(ps4::kErrBadArg);   // DR alignment
    io_result_t r = m_->post([this, addr, len, type]() -> io_result_t {
        auto& m = *m_;
        size_t out = 0;
        {
            std::lock_guard lk(m.slot_mu);
            int slot = -1;
            for (uint32_t i = 0; i < kMaxWatchpoints; ++i)
                if (m.wps[i].used && m.wps[i].addr == addr) { slot = static_cast<int>(i); out |= kReusedBit; break; }
            if (slot < 0)
                for (uint32_t i = 0; i < kMaxWatchpoints; ++i)
                    if (!m.wps[i].used) { slot = static_cast<int>(i); break; }
            if (slot < 0) return err_result(ps4::kErrNoSlot);
            m.wps[static_cast<size_t>(slot)] = impl_t::wp_t{true, addr, len, type};
            out |= static_cast<size_t>(slot);
        }
        m.apply_drs_all();
        return io_result_t{true, out, 0};
    });
    if (r.ok) {
        index  = static_cast<uint32_t>(r.bytes & 0xFF);
        reused = (r.bytes & kReusedBit) != 0;
        r.bytes = 0;
    }
    return r;
}

io_result_t local_debugger_t::wp_disarm(uint64_t addr) {
    return m_->post([this, addr]() -> io_result_t {
        auto& m = *m_;
        {
            std::lock_guard lk(m.slot_mu);
            bool found = false;
            for (auto& w : m.wps)
                if (w.used && w.addr == addr) { w = impl_t::wp_t{}; found = true; break; }
            if (!found) return err_result(ps4::kErrNotArmed);
        }
        m.apply_drs_all();
        return ok_result();
    });
}

io_result_t local_debugger_t::resume() {
    return m_->post([this]() { return m_->continue_held(0); });
}

io_result_t local_debugger_t::step(uint32_t tid) {
    return m_->post([this, tid]() -> io_result_t {
        auto& m = *m_;
        if (!m.held.load())
            return err_result(ERROR_INVALID_STATE);   // stepping needs a stopped debuggee
        const DWORD t = tid ? tid : m.pending.dwThreadId;
        return m.continue_held(t);
    });
}

bool local_debugger_t::wait_event(stop_event_t& out, int timeout_ms) {
    std::unique_lock lk(m_->ev_mu);
    if (m_->evq.empty())
        m_->ev_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 0),
                           [this] { return !m_->evq.empty(); });
    if (m_->evq.empty()) return false;
    out = std::move(m_->evq.front());
    m_->evq.pop_front();
    return true;
}

bool local_debugger_t::read(uint64_t addr, void* dst, size_t len) {
    HANDLE h = m_->proc.load();
    if (!h || len == 0) return false;
    SIZE_T n = 0;
    if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), dst, len, &n) || n != len)
        return false;
    // show the program's bytes, not our int3s
    std::lock_guard lk(m_->slot_mu);
    auto* out = static_cast<uint8_t*>(dst);
    for (const auto& b : m_->bps)
        if (b.used && b.addr >= addr && b.addr < addr + len) out[b.addr - addr] = b.orig;
    return true;
}

} // namespace slop::core::debugger
