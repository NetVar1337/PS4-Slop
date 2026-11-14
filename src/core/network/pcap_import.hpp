#pragma once

// src/core/network/pcap_import.hpp
// imports classic pcap (little/big endian, microsecond or nanosecond
// timestamps) and pcapng (SHB/IDB/EPB/SPB) captures into the traffic store so
// streams, dns, stats and deep_inspect work on them. The parser eats untrusted
// input: every length is bounds-checked against the buffer and the record,
// file-size and record-size caps below

#include <cstddef>
#include <string>

#include "core/network/traffic_store.hpp"

namespace slop::core::network::pcap {

struct import_result_t {
    std::string format;              // "pcap" | "pcapng"
    size_t      packets = 0;         // stored
    size_t      skipped = 0;         // not TCP/UDP, fragmented, or unparseable
    size_t      truncated = 0;       // records shorter than their original length
};

// "" on success, otherwise why the file was rejected. Packets already stored
// when a later record is malformed stay in the store
std::string import_file(traffic_store_t& store, const std::string& path,
                        import_result_t* out = nullptr);

} // namespace slop::core::network::pcap
