// src/tests/test_analysis.cpp
// Packer/protector heuristics + crypto signature hunt against the real
// SlopTarget.exe fixture and patched variants of it

#include "harness.hpp"

#include "core/analysis/packer.hpp"
#include "core/analysis/signatures.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/analysis/signatures.h"   // hyperion SignatureMatcher
#include "core/decompiler/lifter_arm64.h"
#include "core/disasm/capstone_disasm.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <vector>

using namespace slop::core::analysis;
namespace disasm = slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

// Patch section name #index in a PE copy (headers only, layout untouched)
bool patch_section_name(std::vector<uint8_t>& img, size_t index,
                        const char* name) {
    if (img.size() < 0x400) return false;
    const uint32_t e_lfanew =
        *reinterpret_cast<const uint32_t*>(img.data() + 0x3C);
    const uint16_t opt_size = *reinterpret_cast<const uint16_t*>(
        img.data() + e_lfanew + 4 + 16);
    const size_t first_hdr = e_lfanew + 4 + 20 + opt_size;
    const size_t off = first_hdr + index * 40;
    if (off + 8 > img.size()) return false;
    std::memset(img.data() + off, 0, 8);
    std::memcpy(img.data() + off, name, std::min<size_t>(strlen(name), 8));
    return true;
}

} // namespace

TEST_CASE(entropy_basics) {
    std::vector<uint8_t> zeros(4096, 0x00);
    REQUIRE(shannon_entropy(zeros.data(), zeros.size()) < 0.01);

    std::mt19937 rng(1234);
    std::vector<uint8_t> noise(65536);
    for (auto& b : noise) b = static_cast<uint8_t>(rng());
    REQUIRE(shannon_entropy(noise.data(), noise.size()) > 7.9);
}

TEST_CASE(packer_clean_binary_not_flagged) {
    const auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(!v.packed);
    REQUIRE(v.confidence < 0.5);
    REQUIRE(v.family.empty());
}

TEST_CASE(packer_upx_section_names_identify_family) {
    auto bytes = slop_target_bytes();
    REQUIRE(patch_section_name(bytes, 0, "UPX0"));
    REQUIRE(patch_section_name(bytes, 1, "UPX1"));

    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(v.packed);
    REQUIRE_STR_EQ(v.family.c_str(), "UPX");

    bool named_hit = false;
    for (const auto& d : v.detections)
        if (d.type == "section_name" && d.protector == "UPX") named_hit = true;
    REQUIRE(named_hit);
}

TEST_CASE(packer_vmp_names_identify_family) {
    auto bytes = slop_target_bytes();
    REQUIRE(patch_section_name(bytes, 0, ".vmp0"));
    REQUIRE(patch_section_name(bytes, 1, ".vmp1"));

    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(v.packed);
    REQUIRE_STR_EQ(v.family.c_str(), "VMProtect");
}

TEST_CASE(packer_high_entropy_exec_section_flagged) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE(pe.sections.size() > 0);

    // Fill the first executable section's raw payload with PRNG noise
    bool filled = false;
    for (const auto& sec : pe.sections) {
        if (!sec.is_executable() || sec.raw_size < 4096) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bytes.size())
            continue;
        std::mt19937 rng(99);
        for (uint32_t i = 0; i < sec.raw_size; ++i)
            bytes[sec.raw_offset + i] = static_cast<uint8_t>(rng());
        filled = true;
        break;
    }
    REQUIRE(filled);

    auto repacked = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(repacked.ok);
    auto v = packer_analyze(repacked, bytes);

    bool entropy_hit = false;
    for (const auto& d : v.detections)
        if (d.type == "high_entropy") entropy_hit = true;
    REQUIRE(entropy_hit);
}

TEST_CASE(packer_noisy_data_sections_plus_tls_stays_clean) {
    // Regression: clean Rust-style image (.rdata/.rsrc ~7.8 entropy + TLS
    // directory) used to score 0.2+0.2+0.1=0.50 -> packed:Unknown. Weak
    // signals alone must not tip the verdict without a strong indicator.
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Fill from the end so the import table (.rdata, early) survives and no
    // spurious "no imports" signal pollutes the score.
    int filled = 0;
    for (auto it = pe.sections.rbegin(); it != pe.sections.rend(); ++it) {
        const auto& sec = *it;
        if (sec.is_executable() || sec.raw_size < 4096) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bytes.size())
            continue;
        std::mt19937 rng(0xC0FFEE + filled);
        for (uint32_t i = 0; i < sec.raw_size; ++i)
            bytes[sec.raw_offset + i] = static_cast<uint8_t>(rng());
        if (++filled == 2) break;
    }
    REQUIRE_EQ(filled, 2);

    // Set a TLS directory size (weak signal, normal in Rust/MSVC CRT)
    {
        const uint32_t e_lfanew =
            *reinterpret_cast<const uint32_t*>(bytes.data() + 0x3C);
        const size_t oh = e_lfanew + 4 + 20;
        const size_t tls_size_off = oh + 112 + 9 * 8 + 4;
        REQUIRE_LT(tls_size_off + 4, bytes.size());
        const uint32_t tls_size = 0x18;
        std::memcpy(bytes.data() + tls_size_off, &tls_size, 4);
    }

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(reparsed.ok);
    auto v = packer_analyze(reparsed, bytes);
    REQUIRE(!v.packed);
    REQUIRE(v.family.empty());
}

TEST_CASE(crypto_hunt_finds_planted_aes_sbox) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Plant the AES forward S-box prefix into the last raw section
    const uint8_t sbox[16] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                              0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76};
    size_t plant_off = 0;
    bool planted = false;
    for (auto it = pe.sections.rbegin(); it != pe.sections.rend(); ++it) {
        if (it->raw_size < 64) continue;
        if (static_cast<size_t>(it->raw_offset) + it->raw_size > bytes.size())
            continue;
        plant_off = it->raw_offset + it->raw_size - 32;
        std::memcpy(bytes.data() + plant_off, sbox, sizeof(sbox));
        planted = true;
        break;
    }
    REQUIRE(planted);

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    auto hits = crypto_hunt(reparsed, bytes);
    bool found = false;
    for (const auto& h : hits) {
        if (h.name == "AES S-box (forward)" && h.offset == plant_off &&
            !h.in_overlay)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(crypto_hunt_clean_image_no_false_sbox) {
    const auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    auto hits = crypto_hunt(pe, bytes);
    // SlopTarget is a plain MSVC build, no AES tables expected. Base64 may
    // legitimately appear in CRT data; only assert on absence of crypto-core
    // constants here
    for (const auto& h : hits) {
        REQUIRE(h.name.find("AES") == std::string::npos);
        REQUIRE(h.name.find("SHA") == std::string::npos);
    }
}

namespace {

// one executable segment at 0x1000 holding `code`
struct sig_image_t {
    std::vector<uint8_t> raw;
    hype::PEImage        img{};

    sig_image_t(hype::ImageFormat format, hype::Arch arch,
                const std::vector<uint8_t>& code) {
        raw.resize(0x100, 0);
        const size_t code_off = raw.size();
        raw.insert(raw.end(), code.begin(), code.end());
        img.arch   = arch;
        img.format = format;
        img.base   = 0x1000;
        img.entry  = 0x1000;
        img.raw    = raw;
        hype::Segment seg{};
        seg.name     = ".text";
        seg.va       = 0x1000;
        seg.size     = code.size();
        seg.file_off = code_off;
        seg.file_sz  = code.size();
        seg.flags    = 0x60000020;
        seg.data     = std::span<const uint8_t>(raw.data() + code_off, code.size());
        img.segments.push_back(seg);
    }
};

void add_fn(hype::AnalysisDB& db, hype::va_t va) {
    hype::Function f{};
    f.entry = va;
    f.name  = "sub_" + std::to_string(va);
    db.funcs[va] = std::move(f);
}

} // namespace

TEST_CASE(analysis_signatures_orbis_set_is_elf_only) {
    // 0x1000 libkernel getpid stub, 0x1010 payload-sdk mmap stub jumping to
    // the shared `mov r10, rcx ; syscall` tail at 0x1030, 0x1040 FreeBSD bzero
    std::vector<uint8_t> code(0x60, 0xCC);
    const uint8_t getpid[] = {0x48, 0xC7, 0xC0, 0x14, 0x00, 0x00, 0x00,
                              0x49, 0x89, 0xCA, 0x0F, 0x05, 0x72, 0x01, 0xC3};
    std::memcpy(code.data(), getpid, sizeof(getpid));
    const uint8_t mmap_stub[] = {0x48, 0xC7, 0xC0, 0xDD, 0x01, 0x00, 0x00,
                                 0xE9, 0x14, 0x00, 0x00, 0x00};   // -> 0x1030
    std::memcpy(code.data() + 0x10, mmap_stub, sizeof(mmap_stub));
    const uint8_t tail[] = {0x49, 0x89, 0xCA, 0x0F, 0x05, 0xC3};
    std::memcpy(code.data() + 0x30, tail, sizeof(tail));
    const uint8_t bzero[] = {0x48, 0x89, 0xF1, 0x31, 0xC0, 0x48, 0xC1, 0xE9,
                             0x03, 0xFC, 0xF3, 0x48, 0xAB, 0x48, 0x89, 0xF1,
                             0x48, 0x83, 0xE1, 0x07, 0xF3, 0xAA, 0xC3};
    std::memcpy(code.data() + 0x40, bzero, sizeof(bzero));

    hype::SignatureMatcher m;
    REQUIRE_GT(m.sig_count(hype::Arch::X64, hype::SigFormat::ELF), 0);
    REQUIRE_GT(m.sig_count(hype::Arch::X64, hype::SigFormat::PE),
               m.sig_count(hype::Arch::X86, hype::SigFormat::PE));
    REQUIRE_EQ(m.sig_count(hype::Arch::ARM64, hype::SigFormat::MachO), 0);

    {
        sig_image_t elf(hype::ImageFormat::ELF, hype::Arch::X64, code);
        REQUIRE(hype::SignatureMatcher::image_format(elf.img) == hype::SigFormat::ELF);
        hype::AnalysisDB db;
        for (hype::va_t va : {0x1000ull, 0x1010ull, 0x1040ull}) add_fn(db, va);
        db.names[0x1040] = "already_named";
        REQUIRE_EQ(m.match_functions(db, elf.img), 2);
        REQUIRE_STR_EQ(db.names[0x1000].c_str(), "sys_getpid");
        REQUIRE_STR_EQ(db.names[0x1010].c_str(), "sys_mmap");
        REQUIRE_STR_EQ(db.names[0x1040].c_str(), "already_named");

        hype::AnalysisDB db2;
        add_fn(db2, 0x1040);
        REQUIRE_EQ(m.match_functions(db2, elf.img), 1);
        REQUIRE_STR_EQ(db2.names[0x1040].c_str(), "bzero");
    }
    {
        // same bytes inside a PE: neither stubs nor FreeBSD libc apply
        sig_image_t pe(hype::ImageFormat::PE, hype::Arch::X64, code);
        hype::AnalysisDB db;
        for (hype::va_t va : {0x1000ull, 0x1010ull, 0x1040ull}) add_fn(db, va);
        REQUIRE_EQ(m.match_functions(db, pe.img), 0);
    }
    {
        // MSVC x64 CRT prologue matches in a PE, not in an ELF
        std::vector<uint8_t> msvc = {0x48, 0x3B, 0x0D, 0x11, 0x22, 0x33, 0x44,
                                     0x75, 0x02, 0xC3, 0xCC, 0xCC};
        sig_image_t pe(hype::ImageFormat::PE, hype::Arch::X64, msvc);
        hype::AnalysisDB db;
        add_fn(db, 0x1000);
        REQUIRE_EQ(m.match_functions(db, pe.img), 1);
        REQUIRE_STR_EQ(db.names[0x1000].c_str(), "__security_check_cookie");

        sig_image_t elf(hype::ImageFormat::ELF, hype::Arch::X64, msvc);
        hype::AnalysisDB db2;
        add_fn(db2, 0x1000);
        REQUIRE_EQ(m.match_functions(db2, elf.img), 0);

        // arch gate: an ARM64 PE never sees x64 MSVC patterns
        sig_image_t arm(hype::ImageFormat::PE, hype::Arch::ARM64, msvc);
        hype::AnalysisDB db3;
        add_fn(db3, 0x1000);
        REQUIRE_EQ(m.match_functions(db3, arm.img), 0);
    }
}

namespace {

// lift one ARM64 instruction (little-endian word) into pcode
struct arm64_lifted {
    hype::Insn      insn{};
    hype::PcodeFunc pf;

    explicit arm64_lifted(uint32_t word) {
        hype::CapstoneDisasm cs;
        cs.set_arch(hype::Arch::ARM64);
        uint8_t bytes[4];
        std::memcpy(bytes, &word, 4);
        REQUIRE(cs.decode(0x1000, bytes, 4, insn));
        hype::Function fn{};
        fn.entry = 0x1000;
        fn.name = "f";
        hype::BasicBlock bb{};
        bb.start = 0x1000;
        bb.end = 0x1004;
        bb.insns.push_back(insn);
        fn.blocks[0x1000] = bb;
        hype::AnalysisDB db;
        hype::LifterARM64 lifter;
        pf = lifter.lift(fn, db);
        REQUIRE_EQ(pf.blocks.size(), 1u);
    }
    size_t count(hype::PcodeOp op) const {
        size_t n = 0;
        for (const auto& p : pf.blocks[0].ops) n += p.op == op;
        return n;
    }
    bool has_const(hype::PcodeOp op, uint64_t value) const {
        for (const auto& p : pf.blocks[0].ops)
            if (p.op == op)
                for (const auto& in : p.inputs)
                    if (in.is_const() && in.offset == value) return true;
        return false;
    }
    // a COPY into the named register
    bool writes(const char* reg) const {
        for (const auto& p : pf.blocks[0].ops)
            if (p.op == hype::PcodeOp::COPY && p.output.is_reg() && p.output.name == reg)
                return true;
        return false;
    }
};

} // namespace

TEST_CASE(analysis_arm64_lifter_asr_is_arithmetic) {
    arm64_lifted l(0x9343FC20);                     // asr x0, x1, #3
    REQUIRE_STR_EQ(l.insn.mnemonic, "asr");
    REQUIRE_EQ(l.count(hype::PcodeOp::SHIFT_ARIGHT), 1u);
    REQUIRE_EQ(l.count(hype::PcodeOp::SHIFT_RIGHT), 0u);
}

TEST_CASE(analysis_arm64_register_index_scaled_and_extended) {
    arm64_lifted lsl(0xF8627820);                   // ldr x0, [x1, x2, lsl #3]
    REQUIRE_EQ(lsl.insn.ops[1].type, hype::OpType::Mem);
    REQUIRE_EQ(lsl.insn.ops[1].mem.scale, 8);
    REQUIRE(lsl.has_const(hype::PcodeOp::INT_MULT, 8));
    REQUIRE_EQ(lsl.count(hype::PcodeOp::LOAD), 1u);

    arm64_lifted sxtw(0xF862D820);                  // ldr x0, [x1, w2, sxtw #3]
    REQUIRE(sxtw.insn.ops[1].mem.ext == hype::IndexExt::Sxtw);
    REQUIRE_EQ(sxtw.count(hype::PcodeOp::INT_SEXT), 1u);
    REQUIRE(sxtw.has_const(hype::PcodeOp::INT_MULT, 8));
}

TEST_CASE(analysis_arm64_pair_writeback) {
    arm64_lifted pre(0xA9BF7BFD);                   // stp x29, x30, [sp, #-16]!
    REQUIRE(pre.insn.ops[2].writeback());
    REQUIRE(!pre.insn.ops[2].post_index());
    REQUIRE_EQ(pre.count(hype::PcodeOp::STORE), 2u);
    REQUIRE(pre.writes("sp"));
    REQUIRE(pre.has_const(hype::PcodeOp::ADD, static_cast<uint64_t>(-16)));

    arm64_lifted post(0xA8C17BFD);                  // ldp x29, x30, [sp], #16
    REQUIRE(post.insn.ops[2].post_index());
    REQUIRE_EQ(post.count(hype::PcodeOp::LOAD), 2u);
    REQUIRE(post.writes("x29"));
    REQUIRE(post.writes("x30"));
    REQUIRE(post.writes("sp"));
    REQUIRE(post.has_const(hype::PcodeOp::ADD, 16));
    // the first load reads straight from sp (post-index: no offset first)
    const auto& ops = post.pf.blocks[0].ops;
    const auto first_load = std::find_if(ops.begin(), ops.end(), [](const hype::PcodeInsn& p) {
        return p.op == hype::PcodeOp::LOAD;
    });
    REQUIRE(first_load != ops.end());
    REQUIRE(first_load->inputs[0].is_reg());
    REQUIRE(first_load->inputs[0].name == "sp");
}

TEST_CASE(analysis_arm64_movk_lane_from_shift) {
    arm64_lifted l(0xF2A24680);                     // movk x0, #0x1234, lsl #16
    REQUIRE_EQ(l.insn.ops[1].val, 0x12340000ull);
    REQUIRE_EQ(l.insn.ops[1].shift_amount(), 16u);
    REQUIRE(l.has_const(hype::PcodeOp::AND, ~(0xFFFFull << 16)));
    REQUIRE(l.has_const(hype::PcodeOp::OR, 0x12340000ull));
}

TEST_CASE(analysis_capstone_operands_and_thumb) {
    hype::CapstoneDisasm a32;
    a32.set_arch(hype::Arch::ARM);
    // push {r4-r11, lr}: 9 register operands, 5 kept, the rest reported
    const uint8_t push_arm[] = {0xF0, 0x4F, 0x2D, 0xE9};
    hype::Insn in{};
    REQUIRE(a32.decode(0x2000, push_arm, sizeof(push_arm), in));
    REQUIRE_EQ(in.op_count, 5);
    REQUIRE_EQ(in.ops_total, 9);
    REQUIRE(in.ops_truncated());

    // Thumb `push {r4, lr}` (B5 10) at an odd address decodes as Thumb
    const uint8_t thumb[] = {0x10, 0xB5, 0x00, 0xBF};   // push {r4, lr} ; nop
    hype::Insn t{};
    REQUIRE(a32.decode(0x3001, thumb, sizeof(thumb), t));
    REQUIRE_EQ(t.addr, 0x3000ull);
    REQUIRE_EQ(t.len, 2);
    REQUIRE_STR_EQ(t.mnemonic, "push");
    auto range = a32.decode_range(0x3001, thumb, sizeof(thumb));
    REQUIRE_EQ(range.size(), 2u);
    REQUIRE_STR_EQ(range[1].mnemonic, "nop");
    REQUIRE_EQ(range[1].addr, 0x3002ull);

    hype::CapstoneDisasm thumb_default;
    thumb_default.set_arch(hype::Arch::ARM, true);
    hype::Insn d{};
    REQUIRE(thumb_default.decode(0x3000, thumb, sizeof(thumb), d));
    REQUIRE_EQ(d.len, 2);
    REQUIRE_STR_EQ(d.mnemonic, "push");
}
