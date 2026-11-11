#pragma once
#include "core/loader/pe_loader.h"
#include "analysis_db.h"
#include <vector>
#include <string>

namespace hype {

struct RTTIClass {
    std::string   mangled_name;
    std::string   demangled_name;
    va_t          type_descriptor = 0;    // MSVC TypeDescriptor / Itanium type_info
    va_t          complete_locator = 0;   // MSVC only
    va_t          vtable = 0;             // primary vtable (address point)
    std::vector<va_t> methods;
    std::vector<std::string> bases;       // Itanium: direct bases from the type_info
};

// MSVC RTTI on x64 PE images, Itanium ABI RTTI (core/analysis/itanium_rtti.h)
// on ELF images of any 32/64-bit arch
class RTTIParser {
public:
    void parse(PEImage& img, AnalysisDB& db);
    const std::vector<RTTIClass>& classes() const { return classes_; }
    bool itanium() const { return itanium_; }

private:
    void parse_itanium(PEImage& img, AnalysisDB& db);
    void find_type_descriptors(PEImage& img);
    void find_vtables(PEImage& img, AnalysisDB& db);
    void name_methods(PEImage& img, AnalysisDB& db);

    std::vector<RTTIClass> classes_;
    bool itanium_ = false;
};

}
