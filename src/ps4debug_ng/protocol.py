# SPDX-License-Identifier: GPL-3.0-only
"""Wire protocol constants and struct helpers for ps4debug-NG.

Framing: every request is a 12-byte header {magic, cmd, datalen} followed by
`datalen` body bytes. All integers little-endian. See PROTOCOL.md §1.4.
"""

from __future__ import annotations

import socket
import struct

PACKET_MAGIC = 0xFFAABBCC
BROADCAST_MAGIC = 0xFFFFAAAA
BROADCAST_PORT = 1010
SERVER_PORT = 744
EVENT_PORT = 755

CMD_SUCCESS = 0x80000000
CMD_ERROR = 0xF0000001
CMD_TOO_MUCH_DATA = 0xF0000002
CMD_DATA_NULL = 0xF0000003
CMD_ALREADY_DEBUG = 0xF0000004
CMD_INVALID_INDEX = 0xF0000005

STATUS_NAMES = {
    CMD_SUCCESS: "SUCCESS",
    CMD_ERROR: "ERROR",
    CMD_TOO_MUCH_DATA: "TOO_MUCH_DATA",
    CMD_DATA_NULL: "DATA_NULL",
    CMD_ALREADY_DEBUG: "ALREADY_DEBUG",
    CMD_INVALID_INDEX: "INVALID_INDEX",
}

# Info & ping
CMD_VERSION = 0xBD000001
CMD_FW_VERSION = 0xBD000500
CMD_BRANDING = 0xBD000501
CMD_PLATFORM_ID = 0xBD000502
CMD_PROC_NOP = 0xBDAACC06

# Process
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_DISASM_REGION = 0xBDAA0020
CMD_PROC_EXTRACT_CODE_XREFS = 0xBDAA0021
CMD_PROC_FIND_XREFS_TO = 0xBDAA0022
CMD_PROC_READ_STACK = 0xBDAA0023
CMD_PROC_ASSEMBLE = 0xBDAA0024

# Debug
CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_SET_BREAKPOINT = 0xBDBB0003
CMD_DEBUG_SET_WATCHPOINT = 0xBDBB0004
CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005
CMD_DEBUG_SUSPEND_THREAD = 0xBDBB0006
CMD_DEBUG_RESUME_THREAD = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_GETDBREGS = 0xBDBB000C
CMD_DEBUG_CONTINUE = 0xBDBB0010
CMD_DEBUG_THREAD_INFO = 0xBDBB0011
CMD_DEBUG_STEP = 0xBDBB0012
CMD_DEBUG_STEP_THREAD = 0xBDBB0013
CMD_DEBUG_PROCESS_STOP = 0xBDBB0500
CMD_DEBUG_GETFSGSBASE = 0xBDBB000E

# Kernel
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_KERN_WRITE = 0xBDCC0003

# Console
CMD_CONSOLE_NOTIFY = 0xBDDD0004
CMD_CONSOLE_REBOOT = 0xBDDD0001

MAX_BREAKPOINTS = 30
MAX_WATCHPOINTS = 4

DEBUG_INTERRUPT_PACKET_SIZE = 0x4A0

# struct __reg64 field order (debug.h). Natural alignment gives sizeof = 176
# (PROTOCOL.md says 184 - wrong; debug.c:768 sends 176).
REG64_SIZE = 176
REG64_FIELDS = [
    "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8",
    "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax",
]
# trapno(u32) fs(u16) gs(u16) err(u32) es(u16) ds(u16) then 5 x u64
REG64_TRAIL = ["rip", "cs", "rflags", "rsp", "ss"]
REG64_STRUCT = struct.Struct("<15QIHHIHH5Q")

PROC_LIST_ENTRY = struct.Struct("<32si")
VM_MAP_ENTRY = struct.Struct("<QQQQ32s")
DISASM_ENTRY = struct.Struct("<QQqBBBBBBH")  # 32 bytes; see PROTOCOL.md §2.2
XREF_TO_PACKET = struct.Struct("<IQIQ")
DISASM_PACKET = struct.Struct("<IQII")
READ_PACKET = struct.Struct("<IQI")
WRITE_PACKET = struct.Struct("<IQI")
MAPS_PACKET = struct.Struct("<I")
INFO_PACKET = struct.Struct("<I")
READ_STACK_PACKET = struct.Struct("<IQQI")
ASSEMBLE_HDR = struct.Struct("<QI")
BREAKPT_PACKET = struct.Struct("<IIQ")
WATCHPT_PACKET = struct.Struct("<IIIIQ")
STOPGO_PACKET = struct.Struct("<I")
KERN_RW_PACKET = struct.Struct("<QI")
NOTIFY_PACKET = struct.Struct("<II")
ATTACH_PACKET = struct.Struct("<II")
PROC_STOP_RAW = struct.Struct("<IB")

# disasm_instr_entry.kind bitmask
KIND_CALL = 0x01
KIND_RET = 0x02
KIND_JMP = 0x04
KIND_JCC = 0x08
KIND_HAS_MEM = 0x10
KIND_RIP_REL = 0x20
KIND_MEM_READ = 0x40
KIND_MEM_WRITE = 0x80

DISASM_SENTINEL = b"\xff" * DISASM_ENTRY.size


def ip_to_u32(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def u32_to_ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", v & 0xFFFFFFFF))


def fw_version_str(v: int) -> str:
    # Payload reports major*100 + minor (README: 0x1F4 = 500 = 5.00),
    # despite PROTOCOL.md calling it BCD.
    return f"{v // 100}.{v % 100:02d}"


def parse_reg64(buf: bytes) -> dict:
    """Decode struct __reg64 (184 bytes) into an ordered dict."""
    vals = REG64_STRUCT.unpack(buf[: REG64_STRUCT.size])
    out = dict(zip(REG64_FIELDS, vals[:15], strict=True))
    out["trapno"] = vals[15]
    out["fs"] = vals[16]
    out["gs"] = vals[17]
    out["err"] = vals[18]
    out["es"] = vals[19]
    out["ds"] = vals[20]
    out.update(zip(REG64_TRAIL, vals[21:], strict=True))
    return out


def pack_reg64(regs: dict) -> bytes:
    def _as_int(v, name):
        try:
            return int(v)
        except (TypeError, ValueError) as e:
            raise TypeError(f"register {name} must be an integer, got {v!r}") from e

    vals = [_as_int(regs.get(f, 0), f) for f in REG64_FIELDS]
    vals += [
        _as_int(regs.get("trapno", 0), "trapno") & 0xFFFFFFFF,
        _as_int(regs.get("fs", 0), "fs") & 0xFFFF,
        _as_int(regs.get("gs", 0), "gs") & 0xFFFF,
        _as_int(regs.get("err", 0), "err") & 0xFFFFFFFF,
        _as_int(regs.get("es", 0), "es") & 0xFFFF,
        _as_int(regs.get("ds", 0), "ds") & 0xFFFF,
    ]
    vals += [_as_int(regs.get(f, 0), f) for f in REG64_TRAIL]
    return REG64_STRUCT.pack(*vals)


def parse_interrupt_packet(buf: bytes) -> dict:
    """Decode a 0x4A0-byte debug interrupt packet (PROTOCOL.md §1.9)."""
    lwpid, status = struct.unpack_from("<II", buf, 0)
    tdname = buf[8:48].split(b"\0", 1)[0].decode("ascii", "replace")
    reg64 = parse_reg64(buf[48 : 48 + 184])
    return {"lwpid": lwpid, "status": status, "thread_name": tdname, "registers": reg64}
