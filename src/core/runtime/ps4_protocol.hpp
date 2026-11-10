#pragma once

// src/core/runtime/ps4_protocol.hpp
// ps4debug-NG wire protocol constants and packed structs.
// Source of truth: github.com/Pharaoh2k/ps4debug-NG debugger/include/protocol.h
// and debugger/source/*.c at the pinned commit. Every multi-byte field on the
// wire is little-endian; the payload sends packed structs raw.

#include <cstddef>
#include <cstdint>

namespace slop::core::runtime::ps4 {

constexpr uint32_t kPacketMagic   = 0xFFAABBCC;
constexpr uint16_t kDefaultPort   = 744;    // main command server (TCP)
constexpr uint16_t kDebugPort     = 755;    // server->client debug events (TCP)
constexpr uint32_t kHeaderSize    = 12;     // magic + cmd + datalen
constexpr uint32_t kChunkSize     = 0x10000; // server streams payloads in 64 KiB chunks
constexpr size_t   kMaxIoLen      = 16u * 1024u * 1024u; // sanity cap for one transfer

// info / ping commands (handled inline by the server)
constexpr uint32_t CMD_VERSION       = 0xBD000001;
constexpr uint32_t CMD_FW_VERSION    = 0xBD000500;
constexpr uint32_t CMD_BRANDING      = 0xBD000501;
constexpr uint32_t CMD_PLATFORM_ID   = 0xBD000502;
constexpr uint32_t CMD_PROC_NOP      = 0xBDAACC06;

// process commands
constexpr uint32_t CMD_PROC_LIST         = 0xBDAA0001;
constexpr uint32_t CMD_PROC_READ         = 0xBDAA0002;
constexpr uint32_t CMD_PROC_WRITE        = 0xBDAA0003;
constexpr uint32_t CMD_PROC_MAPS         = 0xBDAA0004;
constexpr uint32_t CMD_PROC_PROTECT      = 0xBDAA0008;
constexpr uint32_t CMD_PROC_INFO         = 0xBDAA000A;
constexpr uint32_t CMD_PROC_ALLOC        = 0xBDAA000B;
constexpr uint32_t CMD_PROC_FREE         = 0xBDAA000C;
constexpr uint32_t CMD_PROC_ALLOC_HINTED = 0xBDAA000E;

// debug commands (require CMD_DEBUG_ATTACH first)
constexpr uint32_t CMD_DEBUG_ATTACH          = 0xBDBB0001;
constexpr uint32_t CMD_DEBUG_DETACH          = 0xBDBB0002;
constexpr uint32_t CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005;
constexpr uint32_t CMD_DEBUG_GETREGS         = 0xBDBB0008;
constexpr uint32_t CMD_DEBUG_SETREGS         = 0xBDBB0009;

// status codes
constexpr uint32_t CMD_SUCCESS       = 0x80000000;
constexpr uint32_t CMD_ERROR         = 0xF0000001;
constexpr uint32_t CMD_TOO_MUCH_DATA = 0xF0000002;
constexpr uint32_t CMD_DATA_NULL     = 0xF0000003;
constexpr uint32_t CMD_ALREADY_DEBUG = 0xF0000004;

// FreeBSD VM_PROT_* flags used by CMD_PROC_PROTECT (not Windows PAGE_*)
constexpr uint32_t kVmProtNone  = 0;
constexpr uint32_t kVmProtRead  = 1;
constexpr uint32_t kVmProtWrite = 2;
constexpr uint32_t kVmProtExec  = 4;
constexpr uint32_t kVmProtAll   = 7;

#pragma pack(push, 1)

struct packet_header_t {
    uint32_t magic;
    uint32_t cmd;
    uint32_t datalen;
};

struct proc_read_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
};

struct proc_write_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
};

struct proc_maps_packet_t {
    uint32_t pid;
};

struct proc_protect_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint32_t newprot;
};

struct proc_info_packet_t {
    uint32_t pid;
};

struct proc_info_response_t {
    uint32_t pid;
    char     name[40];
    char     path[64];
    char     titleid[16];
    char     contentid[64];
};

struct proc_alloc_packet_t {
    uint32_t pid;
    uint32_t length;
};

struct proc_alloc_hinted_packet_t {
    uint32_t pid;
    uint64_t hint;
    uint32_t length;
};

struct proc_alloc_response_t {
    uint64_t address;
};

struct proc_free_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
};

// CMD_PROC_LIST entry, 36 bytes each
struct proc_list_entry_t {
    char    p_comm[32];
    int32_t pid;
};

// CMD_PROC_MAPS entry, 58 bytes each (debugger/include/proc.h, packed)
struct vm_map_entry_t {
    char     name[32];
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t prot;
};

struct debug_attach_packet_t {
    uint32_t pid;
    uint32_t client_ip;   // our IPv4 as sin_addr.s_addr (network-order value)
};

struct debug_lwpid_packet_t {
    uint32_t lwpid;
};

struct debug_setregs_packet_t {
    uint32_t lwpid;
    uint32_t length;
};

// struct __reg64 from debugger/include/debug.h; the server sends exactly 176
// bytes for CMD_DEBUG_GETREGS (debug.c: net_send_all(fd, buf, 176))
struct reg64_t {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint32_t trapno;
    uint16_t fs;
    uint16_t gs;
    uint32_t err;
    uint16_t es;
    uint16_t ds;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

#pragma pack(pop)

static_assert(sizeof(packet_header_t) == 12);
static_assert(sizeof(proc_read_packet_t) == 16);
static_assert(sizeof(proc_write_packet_t) == 16);
static_assert(sizeof(proc_protect_packet_t) == 20);
static_assert(sizeof(proc_info_response_t) == 188);
static_assert(sizeof(proc_alloc_hinted_packet_t) == 16);
static_assert(sizeof(proc_free_packet_t) == 16);
static_assert(sizeof(proc_list_entry_t) == 36);
static_assert(sizeof(vm_map_entry_t) == 58);
static_assert(sizeof(debug_attach_packet_t) == 8);
static_assert(sizeof(debug_setregs_packet_t) == 8);
static_assert(sizeof(reg64_t) == 176);

} // namespace slop::core::runtime::ps4
