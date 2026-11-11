#pragma once
#include "core/types.h"
#include "core/types/type_system.h"
#include "core/disasm/disassembler.h"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <mutex>
#include <set>

namespace hype {

enum class DataSize : u8 { Byte = 1, Word = 2, Dword = 4, Qword = 8 };

enum class DataStyle : u8 { Raw, Pointer, String, Import, Align };

// X64 is the Microsoft x64 convention (rcx, rdx, r8, r9); SysV is the System V
// AMD64 ABI used by PS4/FreeBSD, Linux and macOS (rdi, rsi, rdx, rcx, r8, r9);
// AAPCS64 passes x0-x7, AAPCS (32-bit ARM) r0-r3
enum class CallConv : u8 { Unknown, Cdecl, Stdcall, Fastcall, Thiscall, X64, SysV, AAPCS64, AAPCS };

// Default convention for an image: arch first, then the container's platform
inline CallConv default_callconv(Arch arch, ImageFormat format) {
    switch (arch) {
    case Arch::X64:   return format == ImageFormat::PE ? CallConv::X64 : CallConv::SysV;
    case Arch::ARM64: return CallConv::AAPCS64;
    case Arch::ARM:   return CallConv::AAPCS;
    case Arch::X86:   return CallConv::Cdecl;
    default:          return CallConv::Unknown;
    }
}

inline const char* callconv_name(CallConv c) {
    switch (c) {
    case CallConv::Cdecl:    return "cdecl";
    case CallConv::Stdcall:  return "stdcall";
    case CallConv::Fastcall: return "fastcall";
    case CallConv::Thiscall: return "thiscall";
    case CallConv::X64:      return "win64";
    case CallConv::SysV:     return "sysv_amd64";
    case CallConv::AAPCS64:  return "aapcs64";
    case CallConv::AAPCS:    return "aapcs";
    default:                 return "unknown";
    }
}

struct DataItem {
    va_t      addr;
    DataSize  size;
    DataStyle style = DataStyle::Raw;
    bool      is_string = false;
};

struct BasicBlock {
    va_t              start;
    va_t              end;
    std::vector<Insn> insns;
    std::vector<va_t> succs;
    std::vector<va_t> preds;
};

struct LoopInfo {
    va_t header;
    va_t back_edge_src;
    u16  induction_reg = 0;
};

struct Function {
    va_t                                     entry;
    std::string                              name;
    std::vector<va_t>                        block_addrs;
    std::unordered_map<va_t, BasicBlock>     blocks;
    bool                                     analyzed = false;
    bool                                     noreturn = false;
    CallConv                                 callconv = CallConv::Unknown;
    std::vector<LoopInfo>                    loops;
    std::vector<std::pair<va_t, va_t>>        ranges;
};

enum class XrefType : u8 { CodeCall, CodeJump, DataRead, DataWrite, DataOffset };

struct Xref {
    va_t     from;
    va_t     to;
    XrefType type;
};

struct Vtable {
    va_t              addr;
    std::vector<va_t> entries;
};

struct Global {
    va_t        addr;
    u32         size;
    std::string name;
};

struct FuncSignature {
    std::vector<std::string> param_names;
    std::vector<std::string> param_types;
    std::string return_type = "int64_t";
    int param_count = 0;
};

struct AnalysisDB {
    Arch                                        arch = Arch::X64;
    CallConv                                    abi = CallConv::X64;   // image default, see default_callconv
    va_t                                        image_base = 0;
    std::unordered_map<va_t, Insn>              insns;
    std::unordered_map<va_t, Function>          funcs;
    std::vector<Xref>                           xrefs;
    std::unordered_map<va_t, std::vector<Xref>> xrefs_to;
    std::unordered_map<va_t, std::vector<Xref>> xrefs_from;
    std::unordered_map<va_t, std::string>       names;
    std::unordered_map<va_t, std::string>       comments;
    std::vector<std::pair<va_t, std::string>>   strings;
    std::unordered_map<va_t, DataItem>          data_items;
    std::unordered_set<va_t>                    hex_display;
    std::unordered_map<va_t, std::vector<u8>>   patches;
    std::unordered_map<va_t, u32>              applied_types;
    std::vector<Vtable>                         vtables;
    std::unordered_map<va_t, Global>            globals;
    std::unordered_map<va_t, va_t>              resolved_indirect;
    std::unordered_map<va_t, FuncSignature>     signatures;
    TypeSystem                                  types;
    mutable std::mutex                          mtx;

    void add_xref(const Xref& x) {
        std::lock_guard lk(mtx);
        add_xref_unlocked(x);
    }

    void add_xref_unlocked(const Xref& x) {
        xrefs.push_back(x);
        xrefs_to[x.to].push_back(x);
        xrefs_from[x.from].push_back(x);
    }

    void add_func(Function f) {
        std::lock_guard lk(mtx);
        auto e = f.entry;
        funcs[e] = std::move(f);
    }

    void set_name(va_t addr, std::string n) {
        std::lock_guard lk(mtx);
        names[addr] = std::move(n);
    }

    void define_data(va_t addr, DataSize sz, DataStyle style = DataStyle::Raw) {
        std::lock_guard lk(mtx);
        insns.erase(addr);
        data_items[addr] = {addr, sz, style, false};
    }

    void define_string(va_t addr) {
        std::lock_guard lk(mtx);
        insns.erase(addr);
        data_items[addr] = {addr, DataSize::Byte, DataStyle::String, true};
    }

    void undefine(va_t addr) {
        std::lock_guard lk(mtx);
        insns.erase(addr);
        data_items.erase(addr);
    }

    void toggle_hex(va_t addr) {
        std::lock_guard lk(mtx);
        if (hex_display.count(addr)) hex_display.erase(addr);
        else hex_display.insert(addr);
    }

    void patch_nop(va_t addr, u8 len) {
        std::lock_guard lk(mtx);
        patches[addr] = std::vector<u8>(len, 0x90);
    }
};

}
