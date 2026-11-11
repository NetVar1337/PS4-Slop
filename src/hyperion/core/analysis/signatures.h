#pragma once
#include "core/types.h"
#include "analysis_db.h"
#include "core/loader/pe_loader.h"
#include <vector>
#include <string>

namespace hype {

// Container family a signature set was built from. MSVC CRT prologues only
// mean anything inside PE images, Orbis/FreeBSD code only inside ELF ones
enum class SigFormat : u8 { Any, PE, ELF, MachO };

struct Signature {
    std::string name;
    std::string library;
    std::vector<u8> pattern;
    std::vector<u8> mask;   // 0xFF = exact, 0x00 = wildcard
    Arch        arch   = Arch::X64;
    SigFormat   format = SigFormat::PE;
};

class SignatureMatcher {
public:
    SignatureMatcher();

    // Names functions in `db` whose entry bytes match a signature of the
    // image's arch and container format. Functions that already carry a
    // real name (export, symbol, import thunk) keep it
    int match_functions(AnalysisDB& db, const PEImage& img);
    int sig_count() const { return static_cast<int>(sigs_.size()); }
    // Signatures eligible for an image of this arch and format
    int sig_count(Arch arch, SigFormat format) const;

    // Signature family for the image's container format
    static SigFormat image_format(const PEImage& img);

private:
    bool match_one(const u8* data, size_t len, const Signature& sig) const;
    const u8* func_bytes(va_t addr, const PEImage& img, size_t* out_len) const;
    // Orbis syscall stub at `ptr` (libkernel inline form, or the payload SDK
    // `mov rax, n ; jmp common` form): the stub's name, empty when none
    std::string syscall_stub_name(const u8* ptr, size_t len, va_t entry,
                                  const PEImage& img) const;

    std::vector<Signature> sigs_;
};

}
