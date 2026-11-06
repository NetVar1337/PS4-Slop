#pragma once

#include <atomic>
#include <cstdint>

namespace internals {

inline constexpr std::uint32_t kDefaultStatusMagic = 0x5053494E; // "PSIN"
inline constexpr std::uint32_t kMaxConfigWords = 32;
inline constexpr std::uint32_t kMaxTelemetryWords = 16;
inline constexpr std::uint64_t kInvalidRpcResult = ~0ull;

// Command ABI shared by the generic runtime and existing game runtimes.
struct RpcCallbacks {
    void* context = nullptr;
    std::uint64_t (*status)(void*) noexcept = nullptr;
    void (*features)(void*, std::uint32_t) noexcept = nullptr;
    void (*shutdown)(void*) noexcept = nullptr;
    int (*initialization_stage)(void*) noexcept = nullptr;
    void (*write_config)(void*, std::uint32_t, std::uint64_t) noexcept = nullptr;
    std::uint64_t (*read_config)(void*, std::uint32_t) noexcept = nullptr;
    std::uint64_t (*read_telemetry)(void*, std::uint32_t) noexcept = nullptr;
};

std::uint64_t DispatchRpc(const RpcCallbacks& callbacks, std::uint64_t command,
                          std::uint64_t argument, std::uint64_t argument2) noexcept;

enum class Lifecycle : std::uint8_t {
    Absent = 0,
    Starting = 1,
    Ready = 2,
    Failed = 3,
    Disabled = 4,
};

struct RuntimeCallbacks {
    void* context = nullptr;
    std::uint32_t status_magic = kDefaultStatusMagic;
    std::uint32_t config_bytes = 0;
    bool (*initialize)(void*) noexcept = nullptr;
    void (*tick)(void*) noexcept = nullptr;
    bool (*features)(void*, std::uint32_t) noexcept = nullptr;
    bool (*write_config)(void*, std::uint32_t, std::uint64_t, std::uint64_t&) noexcept = nullptr;
    std::uint64_t (*read_config)(void*, std::uint32_t) noexcept = nullptr;
    std::uint64_t (*telemetry)(void*, std::uint32_t) noexcept = nullptr;
    bool (*shutdown)(void*) noexcept = nullptr;
    bool (*shutdown_complete)(void*) noexcept = nullptr;
    void (*lifecycle)(void*, Lifecycle) noexcept = nullptr;
};

// One object is owned by the payload's CRT thread. RPC only reads or writes
// atomics; all callbacks run from Start/Tick on that same thread.
class Runtime {
public:
    explicit Runtime(const RuntimeCallbacks& callbacks) noexcept;

    bool Start() noexcept;
    void Tick() noexcept;
    int Run() noexcept;
    std::uint64_t Rpc(std::uint64_t command, std::uint64_t argument,
                      std::uint64_t argument2) noexcept;

    void RequestFeatures(std::uint32_t features) noexcept;
    void RequestShutdown() noexcept;
    void SetError(std::uint32_t error) noexcept;
    void SetStage(std::uint32_t stage) noexcept;
    std::uint64_t PackStatus() const noexcept;
    bool shutdown_complete() const noexcept;

private:
    void SetLifecycle(Lifecycle lifecycle) noexcept;
    std::uint64_t ReadConfig(std::uint32_t index) const noexcept;

    RuntimeCallbacks callbacks_;
    std::atomic<Lifecycle> lifecycle_{Lifecycle::Absent};
    std::atomic<std::uint32_t> stage_{0};
    std::atomic<std::uint32_t> heartbeat_{0};
    std::atomic<std::uint32_t> requested_features_{0};
    std::atomic<std::uint32_t> active_features_{0};
    std::atomic<std::uint32_t> last_error_{0};
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<bool> shutdown_complete_{false};
    std::atomic<std::uint32_t> pending_config_mask_{0};
    std::atomic<std::uint64_t> pending_config_values_[kMaxConfigWords]{};
    std::atomic<std::uint64_t> config_mirror_[kMaxConfigWords]{};
};

int PayloadMain(Runtime& runtime) noexcept;
std::uint64_t PayloadRpc(Runtime& runtime, std::uint64_t command,
                         std::uint64_t argument, std::uint64_t argument2) noexcept;

// A single atomic domain closes the enter/neutralize race during hook removal.
class CallbackGate {
public:
    bool Enter() noexcept;
    void Leave() noexcept;
    void Neutralize() noexcept;
    std::uint32_t Active() const noexcept;
    bool Neutralized() const noexcept;
    void Reset() noexcept;

private:
    static constexpr std::uint32_t kNeutralized = 0x80000000u;
    static constexpr std::uint32_t kCountMask = ~kNeutralized;
    std::atomic<std::uint32_t> state_{0};
};

} // namespace internals
