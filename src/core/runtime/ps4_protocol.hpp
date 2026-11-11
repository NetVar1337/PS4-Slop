#pragma once

// src/core/runtime/ps4_protocol.hpp
// ps4debug-NG wire protocol constants and packed structs.
// Source of truth: github.com/Pharaoh2k/ps4debug-NG debugger/include/protocol.h
// and debugger/source/*.c at the pinned commit. Every multi-byte field on the
// wire is little-endian; the payload sends packed structs raw.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>

namespace slop::core::runtime::ps4 {

// every packed struct below is sent/received raw; the wire is little-endian
static_assert(std::endian::native == std::endian::little,
              "ps4debug-NG wire structs are sent raw and assume a little-endian host");

// ---------------------------------------------------------------------------
// io_result_t.error codes produced by backend_ps4_t. They live above the
// Win32 error range used by the local backend so one table can name both.
// io_error_str() turns any code into text for MCP/UI messages.
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
    kErrNotAttached    = 0xE0000009,  // needs a ps4 debug session
    kErrAlreadyDebug   = 0xE000000A,  // payload answered CMD_ALREADY_DEBUG
    kErrDataNull       = 0xE000000B,  // payload answered CMD_DATA_NULL
    kErrTooMuchData    = 0xE000000C,  // payload answered CMD_TOO_MUCH_DATA
    kErrNoSlot         = 0xE000000D,  // no free breakpoint/watchpoint slot
    kErrNotArmed       = 0xE000000E,  // slot/address not armed by this client
    kErrStaleHandle    = 0xE000000F,  // handle from an earlier console connection
    kErrAsm            = 0xE0000010,  // on-device assembler reported an error
    kErrListen         = 0xE0000011,  // cannot listen on the debug-event port
    kErrDetachFailed   = 0xE0000012,  // previous debuggee could not be detached
    kErrTooMany        = 0xE0000013,  // result larger than the client cap
    kErrSlotBusy       = 0xE0000014,  // slot is being (re)armed by another call
};

// human readable text for any io_result_t.error (ps4 codes above, Win32
// codes from the local backend otherwise)
std::string io_error_str(uint32_t code);

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
constexpr uint32_t CMD_DEBUG_SET_BREAKPOINT  = 0xBDBB0003;
constexpr uint32_t CMD_DEBUG_SET_WATCHPOINT  = 0xBDBB0004;
constexpr uint32_t CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005;
constexpr uint32_t CMD_DEBUG_SUSPEND         = 0xBDBB0006;
constexpr uint32_t CMD_DEBUG_RESUME          = 0xBDBB0007;
constexpr uint32_t CMD_DEBUG_GETREGS         = 0xBDBB0008;
constexpr uint32_t CMD_DEBUG_SETREGS         = 0xBDBB0009;
constexpr uint32_t CMD_DEBUG_GETDBREGS       = 0xBDBB000C;
constexpr uint32_t CMD_DEBUG_CONTINUE        = 0xBDBB0010;
constexpr uint32_t CMD_DEBUG_STEP            = 0xBDBB0012;
constexpr uint32_t CMD_DEBUG_STEP_THREAD     = 0xBDBB0013;
constexpr uint32_t CMD_DEBUG_THREAD_INFO     = 0xBDBB0011;
constexpr uint32_t CMD_DEBUG_PROCESS_STOP    = 0xBDBB0500;

// process RPC: install the payload's rpc stub and call arbitrary code in the
// target (debugger/source/proc.c). INTALL is the payload's own spelling.
constexpr uint32_t CMD_PROC_INTALL = 0xBDAA0005;
constexpr uint32_t CMD_PROC_CALL   = 0xBDAA0006;

// ELF upload: CMD_PROC_ELF loads+relocates+jumps into the entry point,
// CMD_PROC_ELF_RPC does the same but returns the entry address instead
constexpr uint32_t CMD_PROC_ELF     = 0xBDAA0007;
constexpr uint32_t CMD_PROC_ELF_RPC = 0xBDAA0010;

// on-device code analysis (Zydis inside the payload)
constexpr uint32_t CMD_PROC_DISASM_REGION      = 0xBDAA0020;
constexpr uint32_t CMD_PROC_EXTRACT_CODE_XREFS = 0xBDAA0021;
constexpr uint32_t CMD_PROC_FIND_XREFS_TO      = 0xBDAA0022;
constexpr uint32_t CMD_PROC_READ_STACK         = 0xBDAA0023;
constexpr uint32_t CMD_PROC_ASSEMBLE           = 0xBDAA0024;  // raw literal, no macro upstream

// scan family; CMD_PROC_SCAN*/AOB* require auth bit 1 (CMD_PROC_AUTH first)
constexpr uint32_t CMD_PROC_SCAN            = 0xBDAA0009;
constexpr uint32_t CMD_PROC_SCAN_AOB        = 0xBDAA0501;
constexpr uint32_t CMD_PROC_SCAN_AOB_MULTI  = 0xBDAA0502;
constexpr uint32_t CMD_PROC_AUTH            = 0xBDAACCFF;
constexpr uint32_t CMD_PROC_SCAN_START      = 0xBDAACC01;
constexpr uint32_t CMD_PROC_SCAN_COUNT      = 0xBDAACC02;
constexpr uint32_t CMD_PROC_SCAN_GET        = 0xBDAACC03;
constexpr uint32_t CMD_PROC_AUTH_MAGIC      = 0xBB40E64D;

// extra debug register sets / FS,GS base (raw literals 0xBDBB000E/0F upstream)
constexpr uint32_t CMD_DEBUG_GETFPREGS   = 0xBDBB000A;
constexpr uint32_t CMD_DEBUG_SETFPREGS   = 0xBDBB000B;
constexpr uint32_t CMD_DEBUG_SETDBREGS   = 0xBDBB000D;
constexpr uint32_t CMD_DEBUG_GETFSGSBASE = 0xBDBB000E;
constexpr uint32_t CMD_DEBUG_SETFSGSBASE = 0xBDBB000F;

// console commands (0xBDDD....); REBOOT/END are deliberately not exposed
constexpr uint32_t CMD_CONSOLE_PRINT         = 0xBDDD0003;
constexpr uint32_t CMD_CONSOLE_NOTIFY        = 0xBDDD0004;
constexpr uint32_t CMD_CONSOLE_INFO          = 0xBDDD0005;
constexpr uint32_t CMD_CONSOLE_FOREGROUND_APP = 0xBDDD0006;
constexpr uint32_t kNotifyTypeGeneric        = 222;   // main.c's generic icon

// scan value types (cmd_proc_scan_valuetype)
constexpr uint8_t kValU8 = 0, kValI8 = 1, kValU16 = 2, kValI16 = 3;
constexpr uint8_t kValU32 = 4, kValI32 = 5, kValU64 = 6, kValI64 = 7;
constexpr uint8_t kValF32 = 8, kValF64 = 9, kValArrBytes = 10, kValString = 11;

// scan compare types (cmd_proc_scan_comparetype)
constexpr uint8_t kCmpExact = 0, kCmpFuzzy = 1, kCmpBigger = 2, kCmpSmaller = 3;
constexpr uint8_t kCmpBetween = 4, kCmpIncreased = 5, kCmpIncreasedBy = 6;
constexpr uint8_t kCmpDecreased = 7, kCmpDecreasedBy = 8, kCmpChanged = 9;
constexpr uint8_t kCmpUnchanged = 10, kCmpUnknown = 11, kCmpUnknownLow = 12;

// byte width of a scan value type (0 = variable: arrbytes/string use lenData)
constexpr uint32_t scan_value_size(uint8_t vt) {
    switch (vt) {
        case kValU8: case kValI8:   return 1;
        case kValU16: case kValI16: return 2;
        case kValU32: case kValI32: case kValF32: return 4;
        case kValU64: case kValI64: case kValF64: return 8;
        default: return 0;
    }
}
// does this compare type take a seed value in lenData?
constexpr bool scan_cmp_needs_value(uint8_t ct) {
    return ct == kCmpExact || ct == kCmpFuzzy || ct == kCmpBigger ||
           ct == kCmpSmaller || ct == kCmpBetween || ct == kCmpIncreasedBy ||
           ct == kCmpDecreasedBy || ct == kCmpUnknownLow;
}
// does this compare type read the previous value from the entry stream?
constexpr bool scan_cmp_needs_previous(uint8_t ct) {
    return ct >= kCmpIncreased && ct <= kCmpUnchanged;
}

constexpr uint32_t kReadStackMaxDepth  = 64;
constexpr uint32_t kReadStackLocalsCap = 0x1000;
constexpr uint32_t kReadStackCodeOff   = 10;
constexpr uint32_t kReadStackCodeLen   = 200;
constexpr uint32_t kDisasmEntrySize    = 32;
constexpr uint32_t kFpregsSize         = 832;  // savefpu_ymm payload sent by GETFPREGS
constexpr uint32_t kDbregsSize         = 128;  // __dbreg64 sent by GETDBREGS

// limits enforced payload-side
constexpr uint32_t kMaxSwBreakpoints = 30;   // software INT3 breakpoints
constexpr uint32_t kMaxWatchpoints   = 4;    // hardware DR0-DR3

// CMD_DEBUG_CONTINUE stop argument / CMD_DEBUG_PROCESS_STOP state
constexpr uint32_t kStopResume = 0;   // PT_CONTINUE signal 0 (or SIGCONT)
constexpr uint32_t kStopStop   = 1;   // SIGSTOP (17)
constexpr uint32_t kStopKill   = 2;   // SIGKILL (9)

// watchpoint breaktype values (server DR7-encodes breaktype | (4*length))
constexpr uint32_t kWpExec  = 0;      // execute
constexpr uint32_t kWpWrite = 1;      // write
constexpr uint32_t kWpRdWr  = 3;      // read/write

// size of the packed server->client debug event packet sent on port 755
// whenever a debuggee thread stops (debug.c: DEBUG_INTERRUPT_PACKET_SIZE)
constexpr size_t kDebugEventSize = 0x4A0;

// status codes
constexpr uint32_t CMD_SUCCESS       = 0x80000000;
constexpr uint32_t CMD_ERROR         = 0xF0000001;
constexpr uint32_t CMD_TOO_MUCH_DATA = 0xF0000002;
constexpr uint32_t CMD_DATA_NULL     = 0xF0000003;
constexpr uint32_t CMD_ALREADY_DEBUG = 0xF0000004;

// map a non-success payload status word to an io_err_t
constexpr uint32_t status_to_err(uint32_t st) {
    switch (st) {
    case CMD_DATA_NULL:     return kErrDataNull;
    case CMD_TOO_MUCH_DATA: return kErrTooMuchData;
    case CMD_ALREADY_DEBUG: return kErrAlreadyDebug;
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

// CMD_DEBUG_THREAD_INFO reply body after the status word (40 bytes)
struct debug_thread_info_response_t {
    uint32_t lwpid;
    uint32_t priority;
    char     name[32];
};

static_assert(sizeof(debug_thread_info_response_t) == 40, "thread info reply is 40 bytes");

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
    uint32_t length;     // bytes: 1, 2, 4 or 8
    uint32_t breaktype;  // kWpExec / kWpWrite / kWpRdWr
    uint64_t address;
};

struct debug_continue_packet_t {
    uint32_t stop;   // kStopResume / kStopStop / kStopKill
};

struct debug_process_stop_packet_t {
    uint32_t pid;
    uint8_t  state;  // kStopResume / kStopStop / kStopKill
};

struct proc_intall_packet_t {
    uint32_t pid;
};

struct proc_call_packet_t {
    uint32_t pid;
    uint64_t rpcstub;
    uint64_t rip;
    uint64_t rdi, rsi, rdx, rcx, r8, r9;
};

struct proc_call_response_t {
    uint32_t pid;
    uint64_t rax;
};

struct proc_elf_packet_t {
    uint32_t pid;
    uint32_t length;
};

struct proc_elf_rpc_response_t {
    uint64_t entry;
};

struct proc_disasm_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint32_t max_entries;
};

struct proc_xrefs_to_packet_t {
    uint32_t pid;
    uint64_t scan_address;
    uint32_t scan_length;
    uint64_t target_address;
};

// one decoded instruction from CMD_PROC_DISASM_REGION (32 bytes, packed);
// kind bits: 0x01 call, 0x02 ret, 0x04 uncond branch, 0x08 cond branch,
// 0x10 has memory operand, 0x20 rip-relative, 0x40 mem read, 0x80 mem write
struct disasm_instr_entry_t {
    uint64_t addr;
    uint64_t rip_rel_target;
    int64_t  mem_disp;
    uint8_t  length;
    uint8_t  kind;
    uint8_t  mem_base_reg;
    uint8_t  mem_index_reg;
    uint8_t  mem_scale;
    uint8_t  mnemonic_lo;
    uint16_t pad;
};

struct proc_read_stack_packet_t {
    uint32_t pid;
    uint64_t rbp;
    uint64_t rsp;
    uint32_t depth;
};

struct proc_assemble_packet_t {
    uint64_t base_addr;
    uint32_t ks_opt_syntax;   // 0 default/Intel, 1 Intel, 2 ATT, 3 NASM, 4 MASM, 5 GAS
};

struct proc_assemble_ok_t {
    uint32_t byte_len;
    uint32_t insn_count;
};

struct proc_assemble_err_t {
    uint32_t ks_errno;
    uint32_t msg_len;
};

struct proc_scan_packet_t {
    uint32_t pid;
    uint8_t  valueType;
    uint8_t  compareType;
    uint32_t lenData;
};

struct proc_scan_start_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  valueType;
    uint8_t  compareType;
    uint8_t  alignment;
    uint32_t lenData;
};

struct proc_scan_count_packet_t {
    uint32_t pid;
    uint64_t base_address;
    uint8_t  valueType;
    uint8_t  compareType;
    uint32_t lenData;
};

struct proc_scan_get_packet_t {
    uint32_t pid;
    uint32_t count;
};

struct proc_scan_aob_packet_t {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  max_matches;
    uint8_t  stop_flag;   // 1 = invalidate if more than max_matches matches
    uint32_t pattern_length;
};

struct proc_auth_packet_t {
    uint32_t magic;   // CMD_PROC_AUTH_MAGIC
    uint32_t flags;   // bits OR'd into the server's auth word on success
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
    char     app_ver[8];
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

// server->client debug event, sent packed on the port-755 connection whenever
// a debuggee thread stops (debug.c: debug_interrupt_packet). status is the raw
// wait4 status; the signal is (status >> 8) & 0xFF (17 = SIGSTOP is ignored by
// the payload, 9 = SIGKILL tears the session down).
struct debug_event_packet_t {
    uint32_t lwpid;
    uint32_t status;
    char     tdname[40];
    reg64_t  regs;
    uint8_t  savefpu[832];   // struct savefpu_ymm
    uint8_t  dbregs[128];    // struct dbreg64
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
static_assert(sizeof(debug_set_breakpoint_packet_t) == 16);
static_assert(sizeof(debug_set_watchpoint_packet_t) == 24);
static_assert(sizeof(debug_continue_packet_t) == 4);
static_assert(sizeof(debug_process_stop_packet_t) == 5);
static_assert(sizeof(proc_intall_packet_t) == 4);
static_assert(sizeof(proc_call_packet_t) == 68);
static_assert(sizeof(proc_call_response_t) == 12);
static_assert(sizeof(proc_elf_packet_t) == 8);
static_assert(sizeof(proc_elf_rpc_response_t) == 8);
static_assert(sizeof(proc_disasm_packet_t) == 20);
static_assert(sizeof(proc_xrefs_to_packet_t) == 24);
static_assert(sizeof(disasm_instr_entry_t) == kDisasmEntrySize);
static_assert(sizeof(proc_read_stack_packet_t) == 24);
static_assert(sizeof(proc_assemble_packet_t) == 12);
static_assert(sizeof(proc_assemble_ok_t) == 8);
static_assert(sizeof(proc_assemble_err_t) == 8);
static_assert(sizeof(proc_scan_packet_t) == 10);
static_assert(sizeof(proc_scan_start_packet_t) == 23);
static_assert(sizeof(proc_scan_count_packet_t) == 18);
static_assert(sizeof(proc_scan_get_packet_t) == 8);
static_assert(sizeof(proc_scan_aob_packet_t) == 22);
static_assert(sizeof(proc_auth_packet_t) == 8);
static_assert(sizeof(console_notify_packet_t) == 8);
static_assert(sizeof(console_foreground_app_response_t) == 132);
static_assert(sizeof(reg64_t) == 176);
static_assert(sizeof(debug_event_packet_t) == kDebugEventSize);

} // namespace slop::core::runtime::ps4
