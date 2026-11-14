// src/core/disasm/hyperion_session.hpp
// the bridge between the vendored hyperion engine and our disasm stack
// analysis runs on its own thread and ready() only flips when its done so
// db reads after that never race a write, decompile is serialized because
// the pipeline objects are not re-entrant

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <list>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/disasm/engine.hpp"

#include "core/analysis/analyzer.h"
#include "core/decompiler/decompiler.h"
#include "core/loader/pe_loader.h"
#include "threading/parallel.h"
#include "threading/worker_pool.h"

namespace slop::core::disasm::hyperion_session {

struct session_t {
    session_t();
    ~session_t();

    session_t(const session_t&)            = delete;
    session_t& operator=(const session_t&) = delete;

    // lifecycle

    // parse and analyze async on a private thread, base_override rebases the image
    bool start(const uint8_t* bytes, size_t len, uint64_t base_override);
    // Synchronous variant (tests / small images): runs on the caller thread
    bool start_sync(const uint8_t* bytes, size_t len, uint64_t base_override);
    // Re-run analysis from an in-memory (possibly patched) copy of the image
    void reanalyze(const std::vector<uint8_t>& patched_bytes);

    // cooperative cancel, flags the analyzer and waits for the worker to land
    void stop();

    // analysis landed but had to stop short of the whole image, see
    // analysis_insn_budget()
    bool        truncated() const;

    bool        ready() const { return ready_.load(std::memory_order_acquire); }
    // True while the background worker is running a pipeline (between
    // start()/reanalyze() and ready()/stop()/failure)
    bool        running() const;
    float       progress() const;
    std::string error() const;   // last analysis failure, "" when healthy

    // analysis results (only meaningful when ready())

    const hype::AnalysisDB&  db() const;       // analyzer_->db()
    hype::AnalysisDB&        db_mut();         // annotation merges (persist.hype_load)
    const hype::RTTIParser&  rtti() const;     // analyzer_->rtti_parser()
    const hype::PEImage&     image() const { return img_; }
    hype::Arch               arch() const { return img_.arch; }   // set by begin()
    const hype::SignatureMatcher& signatures() const;

    // Managed (.NET/CLI) view. is_dotnet() is only true after ready() on a CLI
    // image; dotnet().image() then carries the full type/member/IL model.
    const hype::DotNetDisassembler& dotnet() const;
    bool                            is_dotnet() const;

    // Containing function (any block spans va), or exact-entry lookup
    // function_at uses an interval index built once when analysis completes
    const hype::Function* function_at(uint64_t va) const;
    const hype::Function* function_entry(uint64_t va) const;

    // Decompile the function containing `va` to pseudo-C lines. Results are
    // cached per function entry (LRU, kDecompCacheCapacity functions) and
    // invalidated by reanalysis, renames, or a changed type generation
    bool decompile(uint64_t va, std::vector<hype::PseudoLine>& out,
                   std::string& err);
    static constexpr size_t kDecompCacheCapacity = 256;
    void   set_decomp_cache_capacity(size_t n);   // >= 1; trims on shrink
    size_t decomp_cache_size() const;
    bool   decomp_cached(uint64_t entry) const;

    // Source of the types/names generation the decompile cache stamps entries
    // with (binary_state wires this to re::type_catalog::generation). A
    // changed value re-renders the next decompile instead of serving stale
    // pseudocode. Null source means generation 0 (never invalidates)
    void set_type_generation(std::function<uint64_t()> fn);

    // User renames to apply onto the AnalysisDB once analysis lands (names
    // the analyzer derives would otherwise clobber mid-analysis renames)
    void queue_names(const std::unordered_map<uint64_t, std::string>& names);

    // hyperion decode through the slop insn abi, lossless for everything
    // consumers read, operand flags are heuristic. x86/x64 only: the insn_t
    // mnemonic and register fields are Zydis enums
    static insn_t convert(const hype::Insn& in);

    // One-shot decode of a raw buffer. X86/X64 go through hyperion's Zydis
    // core (convert() above). ARM/ARM64 decode with this thread's Capstone
    // handle: text is "<MNEMONIC> <op_str>", flow comes from the instruction
    // type, rel_target is the last immediate of a direct branch (b.cond/cbz/
    // tbz put the target after the tested operands), operands carry Capstone
    // register ids in operand_t::arm_* (the Zydis enum fields stay NONE)
    static bool decode(uint64_t va, const uint8_t* buf, size_t len,
                       insn_t& out, hype::Arch arch = hype::Arch::X64);
    // Decode `count` instructions starting at va with 1-byte resync on bad
    // bytes (same contract as the old engine-based MCP path)
    static std::vector<insn_t> decode_range(uint64_t va, const uint8_t* buf,
                                             size_t len, size_t count);

private:
    void run_pipeline();          // caller: worker_ or start_sync
    void join_worker();
    bool begin(const uint8_t* bytes, size_t len, uint64_t base_override);
    void set_error(std::string msg);   // err_mu_-guarded
    void build_interval_index();       // after analysis completes
    void invalidate_decomp_cache();

    hype::WorkerPool pool_{hype::worker_thread_count()};
    hype::PEImage    img_;
    uint64_t         base_override_ = 0;
    std::unique_ptr<hype::Analyzer> analyzer_;

    // Immutable after ready_: sorted [start, end) block ranges → function
    struct BlockRange { uint64_t start; uint64_t end; const hype::Function* func; };
    std::vector<BlockRange> block_ranges_;

    // Decompile cache, keyed by function entry, most recent first. Valid
    // until reanalyze/queue_names or a type generation change; guarded by
    // decomp_mu_
    struct decomp_entry_t {
        uint64_t                      entry = 0;
        uint64_t                      gen   = 0;
        std::vector<hype::PseudoLine> lines;
    };
    using decomp_lru_t = std::list<decomp_entry_t>;
    decomp_lru_t decomp_lru_;
    std::unordered_map<uint64_t, decomp_lru_t::iterator> decomp_cache_;
    size_t decomp_cache_cap_ = kDecompCacheCapacity;
    std::function<uint64_t()> type_gen_;   // guarded by decomp_mu_

    std::thread        worker_;
    mutable std::mutex start_mu_;   // serializes start/reanalyze/stop/dtor
    mutable std::mutex err_mu_;     // err_ is read cross-thread
    mutable std::mutex decomp_mu_;  // Decompiler pipeline not re-entrant; decomp cache
    std::mutex         pending_mu_; // pending_names_ (queue_names vs worker)
    std::unordered_map<uint64_t, std::string> pending_names_;
    std::atomic<bool>  ready_{false};
    std::atomic<bool>  running_{false};
    std::string        err_;        // written before ready_ flip / on failure
};

// Shared decode engine (thread-guarded; hyperion's Zydis decoder carries no
// cross-call state, but the C++ wrapper is cheap to lock)
hype::Disassembler& shared_decoder();

// How many instructions a single analysis may put in the database. The DB
// holds one record per instruction plus another per basic block, so a few
// hundred megabytes of code would need tens of gigabytes; past the budget the
// run stops descending and reports truncated() instead of thrashing.
//
// Derived from available RAM, floor 250K, ceiling 2M. SLOP_HYPERION_INSN_BUDGET
// overrides it (0 disables the cap entirely)
size_t analysis_insn_budget();

} // namespace slop::core::disasm::hyperion_session
