// Resident diagnostics entry for a game project scaffolded by game_new.
// Engine enumeration activates only when project_install has installed a
// generated engine.hpp/target.hpp bound to the exact module hash; until then
// the payload stays resident-only and every game feature reports unavailable.
#include <atomic>
#include <internals/runtime.hpp>
#include <internals/verify.hpp>
#include <internals/ue4.hpp>
#include <internals/source.hpp>
#include <internals/platform.hpp>
#include "generated/target.hpp"
#include "generated/engine_config.hpp"
#include "features.hpp"
#if __has_include("generated/engine.hpp")
#include "generated/engine.hpp"
#endif
#if __has_include("generated/research.hpp")
#include "generated/research.hpp"
#endif

namespace {
std::atomic<std::uint64_t> verified{0}, object_count{0};
std::atomic<std::uint32_t> active_features{0};
internals::MemoryReader memory;
bool Initialize(void*) noexcept {
    // Resident diagnostics become ready even when game-specific functionality is
    // unavailable. No reads happen for an empty target contract.
    memory = internals::platform::Reader();
    verified.store(internals::verify_module(memory, target::kModuleBase, target::kVerifyChecks,
                                            target::kVerifyCheckCount), std::memory_order_release);
    return true;
}
bool Features(void*, std::uint32_t bits) noexcept {
    // Disabling is always allowed. Anything active needs a verified target,
    // exact-build evidence, implementation and a satisfied dependency graph.
    if (bits != 0 && (!verified.load(std::memory_order_acquire) || !features::allowed(bits))) return false;
    active_features.store(bits, std::memory_order_release);
    return true;
}
std::uint64_t Telemetry(void*, std::uint32_t index) noexcept {
    if (index == 0) return verified.load(std::memory_order_acquire);
    if (index == 1) return object_count.load(std::memory_order_acquire);
    if (index == 2) return active_features.load(std::memory_order_acquire);
    return internals::kInvalidRpcResult;
}
void Tick(void*) noexcept {
    if ((active_features.load(std::memory_order_acquire) & features::kDiagnostics) == 0) {
        object_count.store(0, std::memory_order_release);
        return;
    }
    if (!verified.load(std::memory_order_acquire) || !memory.read) return;
#if defined(PS4WB_ENGINE_UNREAL) && __has_include("generated/engine.hpp")
    ue4::Store store(target::kModuleBase, game::kUe4Offsets, memory);
    object_count.store(store.for_each([](std::size_t, std::uintptr_t) {}), std::memory_order_release);
#endif
#if defined(PS4WB_ENGINE_SOURCE) && __has_include("generated/engine.hpp")
    static std::size_t cursor = 0, total = 0;
    source::EntityStore store(target::kModuleBase, game::kEntityLayout, memory);
    total += store.for_each(cursor, 256, [](std::size_t, std::uintptr_t, std::uint32_t) {});
    cursor += 256;
    if (cursor >= game::kEntityLayout.count) { object_count.store(total, std::memory_order_release); total = 0; cursor = 0; }
#endif
}
internals::RuntimeCallbacks Callbacks() noexcept {
    internals::RuntimeCallbacks callbacks;
    callbacks.initialize = &Initialize;
    callbacks.tick = &Tick;
    callbacks.features = &Features;
    callbacks.telemetry = &Telemetry;
    return callbacks;
}
internals::Runtime runtime(Callbacks());
}
// A platform adapter can supply refreshed readable mappings from the payload
// thread. The default has no reader and therefore never dereferences heap data.
extern "C" void payload_set_memory_reader(internals::MemoryReader reader) { memory = reader; }
extern "C" __attribute__((visibility("default")))
std::uint64_t payload_rpc_entry(std::uint64_t command, std::uint64_t argument,
                               std::uint64_t argument2, std::uint64_t, std::uint64_t, std::uint64_t) {
    return runtime.Rpc(command, argument, argument2);
}
#ifndef PS4WB_HOST_TEST
extern "C" void scePthreadExit(void*);
int main(int, char**) {
    const int result = runtime.Run();
    scePthreadExit(nullptr);
    return result;
}
#else
bool payload_host_start() { return runtime.Start(); }
void payload_host_tick() { runtime.Tick(); }
#endif
