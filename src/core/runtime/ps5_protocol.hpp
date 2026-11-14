#pragma once

// src/core/runtime/ps5_protocol.hpp
// ps5debug-NG wire protocol constants and packed structs.
//
// Source of truth: ps5debug-NG v1.3.2 (github.com/Pharaoh2k/ps5debug-NG,
// common/include/protocol.h + PROTOCOL.md, commit a1a6cb2 of 2026-10-22).
// The payload is a PS5 port of ps4debug, so the framing is the ps4debug one:
// a 12-byte {magic, cmd, datalen} header followed by datalen raw body bytes,
// every multi-byte field little-endian, every struct packed.
//
// Where this differs from the ps4debug-NG backend in this tree:
//  - status words are bit-swapped on the wire (net_send_int32 swaps adjacent
//    bit pairs); the constants below are the *wire* values a client compares,
//    which is why CMD_SUCCESS is 0x80000000 and the error words sit one bit
//    apart from the payload's own macros;
//  - CMD_PROC_READ streams its payload in 64 KiB chunks and CMD_PROC_WRITE
//    reads its data phase in 64 KiB chunks (NET_MAX_LENGTH is 8192 in the
//    payload, so the client never needs larger sends);
//  - CMD_DEBUG_ATTACH carries only the pid (the payload takes the client IP
//    from the connection slot);
//  - there is no server-side module list: modules are grouped client-side
//    from CMD_PROC_MAPS;
//  - unknown opcodes answer CMD_ERROR and the payload closes the client, so
//    the backend never probes for commands it does not need.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>

namespace slop::core::runtime::ps5 {

// every packed struct below is sent/received raw; the wire is little-endian
static_assert(std::endian::native == std::endian::little,
              "ps5debug-NG wire structs are sent raw and assume a little-endian host");

// ---------------------------------------------------------------------------
// io_result_t.error codes produced by backend_ps5_t. Same numeric space as
// the ps4 backend's table (0xE000...., above the Win32 range) so one formatter
// (ps4::io_error_str) names errors from either console.
enum io_err_t : uint32_t {
    kErrNone           = 0,
    kErrNotConnected   = 0xE0000001,  // no live console connection
    kErrSendFailed     = 0xE0000002,  // send failed; connection dropped
    kErrRecvFailed     = 0xE0000003,  // receive failed / peer closed; connection dropped
    kErrTimeout        = 0xE0000004,  // per-chunk or whole-command deadline exceeded
    kErrStatus         = 0xE0000005,  // payload answered CMD_ERROR
    kErrProtocol       = 0xE0000006,  // malformed reply (stream desync)
    kErrBadArg         = 0xE0000007,  // rejected client-side before sending
    kErrUnmapped       = 0xE0000008,  // range not mapped / lacks the needed protection
    kErrNotAttached    = 0xE0000009,  // needs a ps5debug debug session
    kErrAlreadyDebug   = 0xE000000A,  // payload answered CMD_ALREADY_DEBUG
    kErrDataNull       = 0xE000000B,  // payload answered CMD_DATA_NULL
    kErrTooMuchData    = 0xE000000C,  // payload answered its over-size status
    kErrNoSlot         = 0xE000000D,  // no free breakpoint/watchpoint slot
    kErrNotArmed       = 0xE000000E,  // slot/address not armed by this client
    kErrStaleHandle    = 0xE000000F,  // handle from an earlier console connection
    kErrInvalidIndex   = 0xE0000010,  // payload answered CMD_INVALID_INDEX
    kErrListen         = 0xE0000011,  // cannot listen on the debug-event port
    kErrDetachFailed   = 0xE0000012,  // previous debuggee could not be detached
};

constexpr uint32_t kPacketMagic   = 0xFFAABBCC;
constexpr uint16_t kDefaultPort   = 744;    // main command server (TCP)
constexpr uint16_t kDebugPort     = 755;    // payload->client debug events (TCP)
constexpr uint16_t kBroadcastPort = 1010;   // UDP discovery listener
constexpr uint32_t kBroadcastMagic = 0xFFFFAAAA;
constexpr uint32_t kHeaderSize    = 12;     // magic + cmd + datalen
constexpr uint32_t kChunkSize     = 0x10000;   // read/write stream chunk
constexpr size_t   kMaxIoLen      = 16u * 1024u * 1024u;  // sanity cap per transfer
// the dispatcher refuses a request body above 1 MiB (PROTOCOL.md 1.4)
constexpr uint32_t kMaxDatalen    = 1u * 1024u * 1024u;
constexpr uint32_t kMaxConsoleMsg = 64u * 1024u;   // client-side cap on print/notify text

// info / ping commands (handled inline by the dispatcher)
constexpr uint32_t CMD_VERSION     = 0xBD000001;
constexpr uint32_t CMD_FW_VERSION  = 0xBD000500;
constexpr uint32_t CMD_BRANDING    = 0xBD000501;
constexpr uint32_t CMD_PLATFORM_ID = 0xBD000502;
constexpr uint32_t CMD_PROC_NOP    = 0xBDAACC06;
constexpr uint16_t kPlatformPs5    = 5;    // CMD_PLATFORM_ID answer

// process commands
constexpr uint32_t CMD_PROC_LIST    = 0xBDAA0001;
constexpr uint32_t CMD_PROC_READ    = 0xBDAA0002;
constexpr uint32_t CMD_PROC_WRITE   = 0xBDAA0003;
constexpr uint32_t CMD_PROC_MAPS    = 0xBDAA0004;
constexpr uint32_t CMD_PROC_PROTECT = 0xBDAA0008;
constexpr uint32_t CMD_PROC_INFO    = 0xBDAA000A;
constexpr uint32_t CMD_PROC_ALLOC   = 0xBDAA000B;
constexpr uint32_t CMD_PROC_FREE    = 0xBDAA000C;
constexpr uint32_t CMD_PROC_ALLOC_HINTED = 0xBDAA000E;
// raw literal upstream: start of the target's first VM map (main image base)
constexpr uint32_t CMD_PROC_BASE    = 0xBDAA000D;

// debug commands (require CMD_DEBUG_ATTACH first)
constexpr uint32_t CMD_DEBUG_ATTACH          = 0xBDBB0001;
constexpr uint32_t CMD_DEBUG_DETACH          = 0xBDBB0002;
constexpr uint32_t CMD_DEBUG_SET_BREAKPOINT  = 0xBDBB0003;
constexpr uint32_t CMD_DEBUG_SET_WATCHPOINT  = 0xBDBB0004;
constexpr uint32_t CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005;
constexpr uint32_t CMD_DEBUG_SUSPEND         = 0xBDBB0006;
constexpr uint32_t CMD_DEBUG_RESUME          = 0xBDBB0007;
constexpr uint32_t CMD_DEBUG_GETREGS         = 0xBDBB0008;
constexpr uint32_t CMD_DEBUG_SETREGS         = 0xBDBB0009;
constexpr uint32_t CMD_DEBUG_CONTINUE        = 0xBDBB0010;
constexpr uint32_t CMD_DEBUG_THREAD_INFO     = 0xBDBB0011;
constexpr uint32_t CMD_DEBUG_STEP            = 0xBDBB0012;
constexpr uint32_t CMD_DEBUG_STEP_THREAD     = 0xBDBB0013;

// console commands (0xBDDD....); REBOOT/END are deliberately not exposed
constexpr uint32_t CMD_CONSOLE_PRINT          = 0xBDDD0003;
constexpr uint32_t CMD_CONSOLE_NOTIFY         = 0xBDDD0004;
constexpr uint32_t CMD_CONSOLE_INFO           = 0xBDDD0005;
constexpr uint32_t CMD_CONSOLE_FOREGROUND_APP = 0xBDDD0006;
constexpr uint32_t kNotifyTypeGeneric         = 222;   // main.c's generic icon

// status words as they arrive on the wire (see the header comment)
constexpr uint32_t CMD_SUCCESS       = 0x80000000;
constexpr uint32_t CMD_ERROR         = 0xF0000001;
constexpr uint32_t CMD_TOO_MUCH_DATA = 0xF0000002;   // over-size guard literal
constexpr uint32_t CMD_DATA_NULL     = 0xF0000003;
constexpr uint32_t CMD_ALREADY_DEBUG = 0xF0000004;
constexpr uint32_t CMD_INVALID_INDEX = 0xF0000005;

constexpr bool is_fatal_status(uint32_t s) { return (s >> 28) == 0xF; }

// readable name for a status word, "" for CMD_SUCCESS / unknown values
constexpr const char* status_name(uint32_t s) {
    switch (s) {
        case CMD_ERROR:         return "CMD_ERROR";
        case CMD_TOO_MUCH_DATA: return "CMD_TOO_MUCH_DATA";
        case CMD_DATA_NULL:     return "CMD_DATA_NULL";
        case CMD_ALREADY_DEBUG: return "CMD_ALREADY_DEBUG";
        case CMD_INVALID_INDEX: return "CMD_INVALID_INDEX";
        default:                return "";
    }
}

// map a non-success payload status word to an io_err_t
constexpr uint32_t status_to_err(uint32_t st) {
    switch (st) {
    case CMD_DATA_NULL:     return kErrDataNull;
    case CMD_TOO_MUCH_DATA: return kErrTooMuchData;
    case CMD_ALREADY_DEBUG: return kErrAlreadyDebug;
    case CMD_INVALID_INDEX: return kErrInvalidIndex;
    case CMD_ERROR:         return kErrStatus;
    default:                return kErrProtocol;   // not a status word at all
    }
}

// FreeBSD VM_PROT_* flags used by CMD_PROC_PROTECT (not Windows PAGE_*)
constexpr uint32_t kVmProtNone  = 0;
constexpr uint32_t kVmProtRead  = 1;
constexpr uint32_t kVmProtWrite = 2;
constexpr uint32_t kVmProtExec  = 4;
constexpr uint32_t kVmProtAll   = 7;

// limits enforced payload-side
constexpr uint32_t kMaxSwBreakpoints = 30;   // software INT3 breakpoints
constexpr uint32_t kMaxWatchpoints   = 4;    // hardware DR0-DR3

// human readable text for any io_result_t.error (ps5 codes above, Win32 codes
// from the local backend otherwise)
std::string io_error_str(uint32_t code);

// CMD_DEBUG_CONTINUE stop argument
constexpr uint32_t kStopResume = 0;   // PT_CONTINUE signal 0
constexpr uint32_t kStopStop   = 1;   // SIGSTOP
constexpr uint32_t kStopKill   = 2;   // SIGKILL

// watchpoint breaktype values (the payload shifts them straight into DR7)
constexpr uint32_t kWpExec  = 0;      // execute
constexpr uint32_t kWpWrite = 1;      // write
constexpr uint32_t kWpRdWr  = 3;      // read/write

// the payload's DR7 length field (not a byte count): 0=1, 1=2, 2=8, 3=4
constexpr uint32_t wp_dr7_length(uint32_t bytes) {
    return bytes == 1 ? 0 : bytes == 2 ? 1 : bytes == 8 ? 2 : bytes == 4 ? 3 : 4;
}

// size of the packed payload->client stop packet on port 755
constexpr size_t kDebugEventSize = 0x4A0;

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
    char    name[32];
    int32_t pid;
};

// CMD_PROC_MAPS entry, 58 bytes each
struct vm_map_entry_t {
    char     name[32];
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t prot;
};

struct debug_attach_packet_t {
    uint32_t pid;
};

struct debug_lwpid_packet_t {
    uint32_t lwpid;
};

// CMD_DEBUG_THREAD_INFO reply body after the status word (40 bytes)
struct debug_thread_info_response_t {
    uint32_t lwpid;
    uint32_t priority;
    char     name[32];
};

struct debug_setregs_packet_t {
    uint32_t lwpid;
    uint32_t length;
};

struct debug_set_breakpoint_packet_t {
    uint32_t index;
    uint32_t enabled;
    uint64_t address;
};

struct debug_set_watchpoint_packet_t {
    uint32_t index;
    uint32_t enabled;
    uint32_t length;     // DR7 length field, see wp_dr7_length()
    uint32_t breaktype;  // kWpExec / kWpWrite / kWpRdWr
    uint64_t address;
};

struct debug_continue_packet_t {
    uint32_t stop;   // kStopResume / kStopStop / kStopKill
};

// struct reg from debug.h; the payload sends exactly 176 bytes for GETREGS
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

// payload->client stop event, sent packed on the port-755 connection whenever
// a debuggee thread stops (debug.c: dispatch_debug_events builds it by hand at
// these fixed offsets; byte-identical to ps4debug's packet)
struct debug_event_packet_t {
    uint32_t lwpid;
    uint32_t status;
    char     tdname[40];
    reg64_t  regs;
    uint8_t  savefpu[832];
    uint8_t  dbregs[128];
};

struct console_print_packet_t {
    uint32_t length;
};

struct console_notify_packet_t {
    uint32_t messageType;
    uint32_t length;
};

struct console_foreground_app_response_t {
    uint32_t pid;
    char     titleid[16];
    char     contentid[64];
    char     name[40];
    char     app_ver[16];
};

#pragma pack(pop)

static_assert(sizeof(packet_header_t) == 12);
static_assert(sizeof(proc_read_packet_t) == 16);
static_assert(sizeof(proc_write_packet_t) == 16);
static_assert(sizeof(proc_protect_packet_t) == 20);
static_assert(sizeof(proc_info_response_t) == 188);
static_assert(sizeof(proc_alloc_packet_t) == 8);
static_assert(sizeof(proc_alloc_hinted_packet_t) == 16);
static_assert(sizeof(proc_free_packet_t) == 16);
static_assert(sizeof(proc_list_entry_t) == 36);
static_assert(sizeof(vm_map_entry_t) == 58);
static_assert(sizeof(debug_attach_packet_t) == 4);
static_assert(sizeof(debug_thread_info_response_t) == 40);
static_assert(sizeof(debug_setregs_packet_t) == 8);
static_assert(sizeof(debug_set_breakpoint_packet_t) == 16);
static_assert(sizeof(debug_set_watchpoint_packet_t) == 24);
static_assert(sizeof(debug_continue_packet_t) == 4);
static_assert(sizeof(reg64_t) == 176);
static_assert(sizeof(debug_event_packet_t) == kDebugEventSize);
static_assert(sizeof(console_notify_packet_t) == 8);
static_assert(sizeof(console_foreground_app_response_t) == 140);

} // namespace slop::core::runtime::ps5
