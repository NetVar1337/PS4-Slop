#pragma once
#include "core/types.h"
#include "pe_loader.h"
#include <filesystem>
#include <optional>

namespace hype {

class ELFLoader {
public:
    static bool is_elf(const u8* data, size_t size);
    std::optional<PEImage> load(const std::filesystem::path& path);
    std::optional<PEImage> load_buffer(const u8* data, size_t size);

private:
    bool parse_header(PEImage& img);
    bool parse_segments(PEImage& img);
    bool parse_sections(PEImage& img);
    bool parse_symbols(PEImage& img);
    bool parse_dynamic(PEImage& img);
    void parse_sce_dynlibdata(PEImage& img);  // PS4 OELF import resolution

    const u8* base_ = nullptr;
    size_t size_ = 0;
    bool is64_ = false;
    bool le_ = true;
};

}
