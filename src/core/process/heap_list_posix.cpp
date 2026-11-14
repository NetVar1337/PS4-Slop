// src/core/process/heap_list_posix.cpp
// Heap enumeration is a Toolhelp feature (Heap32First/Next). Linux exposes no
// equivalent list of a process's heaps, so both calls report that instead of
// returning an empty success that would read as "no heaps".

#include "core/process/heap_list.hpp"

namespace slop::core::process {

std::vector<heap_info_t> list_heaps(uint32_t, std::string* error) {
    if (error) *error = "heap enumeration is a Windows Toolhelp feature";
    return {};
}

std::vector<heap_block_t> walk_heap_blocks(uint32_t, uint64_t, std::string* error, size_t) {
    if (error) *error = "heap enumeration is a Windows Toolhelp feature";
    return {};
}

} // namespace slop::core::process
