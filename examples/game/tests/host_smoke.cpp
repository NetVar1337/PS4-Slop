#include <cassert>
#include <cstdint>
#include <internals/runtime.hpp>
#include <internals/verify.hpp>
extern bool payload_host_start();
extern void payload_host_tick();
extern "C" std::uint64_t payload_rpc_entry(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
int main() {
    assert(!internals::verify_module(1, nullptr, 0));
    assert(payload_rpc_entry(7, 0, 0, 0, 0, 0) == internals::kProtocolDescriptor);
    assert(payload_host_start());
    assert((payload_rpc_entry(0, 0, 0, 0, 0, 0) & 0xff) == 2);
    assert(payload_rpc_entry(6, 0, 0, 0, 0, 0) == 0); // unconfigured target
    payload_rpc_entry(1, 1u << 7, 0, 0, 0, 0); // diagnostics need generated evidence
    payload_host_tick();
    assert(payload_rpc_entry(6, 2, 0, 0, 0, 0) == 0);
    payload_rpc_entry(2, 0, 0, 0, 0, 0);
    payload_host_tick();
    assert((payload_rpc_entry(0, 0, 0, 0, 0, 0) & 0xff) == 4);
}
