#pragma once
#include "core/types.h"
#include "disassembler.h"
#include <memory>
#include <vector>
#include <functional>

namespace hype {

class CapstoneDisasm {
public:
    CapstoneDisasm();
    ~CapstoneDisasm();

    // `thumb` (Arch::ARM only) makes Thumb-2 the default mode. Regardless of
    // it, an ARM decode at an odd address (the interworking convention for a
    // Thumb target, e.g. a symbol or entry with bit 0 set) decodes Thumb at
    // addr & ~1
    void set_arch(Arch arch, bool thumb = false);
    // ops[] holds the first 5 operands; Insn::ops_total says how many the
    // instruction really has (A32 register lists, NEON table lookups)
    bool decode(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len,
                                   const std::function<bool()>& cancelled);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
