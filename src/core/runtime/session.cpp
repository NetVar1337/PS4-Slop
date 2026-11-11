#include "core/runtime/session.hpp"
#include "core/runtime/backend_registry.hpp"

#include "core/infra/clock.hpp"

namespace slop::core::runtime {

session_t::~session_t() {
    close();
}

session_t::session_t(session_t&& other) noexcept
    : m_backend(other.m_backend)
    , m_handle(other.m_handle)
    , m_info(std::move(other.m_info))
    , m_epoch_ms(other.m_epoch_ms)
{
    other.m_backend = nullptr;
    other.m_handle = {};
    other.m_epoch_ms = 0;
}

session_t& session_t::operator=(session_t&& other) noexcept {
    if (this != &other) {
        close();
        m_backend  = other.m_backend;
        m_handle   = other.m_handle;
        m_info     = std::move(other.m_info);
        m_epoch_ms = other.m_epoch_ms;
        other.m_backend  = nullptr;
        other.m_handle   = {};
        other.m_epoch_ms = 0;
    }
    return *this;
}

bool session_t::open(uint32_t pid) {
    close();
    // bind to the backend that is active now: a later backend swap must not
    // route this handle's reads/writes/detach through a different backend
    backend_t& b = active();
    m_handle = b.attach(pid);
    if (!m_handle.valid()) {
        m_handle = {};
        return false;
    }
    m_backend = &b;
    // the attach already learned name/path; enumerate only when it cannot say
    if (!b.handle_info(m_handle, m_info)) {
        m_info = {};
        if (auto procs = b.enum_processes(); procs.ok) {
            for (const auto& p : procs.items) {
                if (p.pid == pid) { m_info = p; break; }
            }
        }
        if (m_info.arch == arch_t::unknown) m_info.arch = b.query_arch(m_handle);
    }
    m_info.pid = pid;
    m_epoch_ms = infra::steady_ms();
    return true;
}

void session_t::close() {
    if (m_backend && m_handle.native) {
        m_backend->detach(m_handle);
    }
    m_backend = nullptr;
    m_handle = {};
    m_info   = {};
    m_epoch_ms = 0;
}

bool session_t::valid() const noexcept {
    return m_backend != nullptr && m_handle.valid();
}

uint32_t session_t::pid() const noexcept {
    return m_info.pid;
}

const std::string& session_t::name() const noexcept {
    return m_info.name;
}

arch_t session_t::arch() const noexcept {
    return m_info.arch;
}

int64_t session_t::epoch_ms() const noexcept {
    return m_epoch_ms;
}

io_result_t session_t::read(uintptr_t addr, void* buf, size_t len) {
    if (!m_backend) return io_result_t{false, 0, 6 /*ERROR_INVALID_HANDLE*/};
    return m_backend->read_memory(m_handle, addr, buf, len);
}

io_result_t session_t::write(uintptr_t addr, const void* buf, size_t len) {
    if (!m_backend) return io_result_t{false, 0, 6 /*ERROR_INVALID_HANDLE*/};
    return m_backend->write_memory(m_handle, addr, buf, len);
}

const target_handle_t& session_t::handle() const noexcept {
    return m_handle;
}

backend_t* session_t::backend() const noexcept {
    return m_backend;
}

const process_info_t& session_t::info() const noexcept {
    return m_info;
}

} // namespace slop::core::runtime
