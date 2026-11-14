// src/fuzz/fuzz_ps4.cpp
// libFuzzer target: the ps4debug-NG wire format — the fixed-size port-755
// debug-event packet, the stream reassembler that rebuilds packets from
// arbitrary TCP chunking, and a CMD_PROC_LIST reply body.

#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace rt  = slop::core::runtime;
namespace ps4 = slop::core::runtime::ps4;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 1. one debug-event packet straight from the input
    rt::ps4_event_t ev{};
    if (rt::ps4_decode_event(data, size, ev)) {
        volatile uint64_t s = ev.status + ev.signal + ev.lwpid + ev.dr[6];
        (void)s;
    }

    // 2. the port-755 stream: any packet size, any chunking
    if (size > 0) {
        const size_t pkt_size = 1 + (data[0] % ps4::kDebugEventSize);
        rt::ps4_event_reassembler_t ra(pkt_size);
        size_t off = 1;
        while (off < size) {
            const size_t chunk = std::min<size_t>(1 + (data[off] % 97), size - off);
            // decode each delivered packet with its own length: a short
            // packet must be rejected, not read as a full 0x4A0 event
            ra.feed(data + off, chunk, [pkt_size](const uint8_t* pkt) {
                rt::ps4_event_t e{};
                (void)rt::ps4_decode_event(pkt, pkt_size, e);
            });
            off += chunk;
        }
    }

    // 3. a CMD_PROC_LIST reply body
    const auto procs = rt::ps4_parse_proc_list(data, size);
    volatile size_t n = procs.size();
    (void)n;
    return 0;
}
