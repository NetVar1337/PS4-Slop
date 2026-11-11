#include <internals/runtime.hpp>

#ifdef _WIN32
#include <thread>
#include <chrono>
static void usleep(unsigned int us) { std::this_thread::sleep_for(std::chrono::microseconds(us)); }
#else
#include <unistd.h>
#endif

namespace internals {

std::uint64_t DispatchRpc(const RpcCallbacks& callbacks, std::uint64_t command,
                          std::uint64_t argument, std::uint64_t argument2) noexcept {
    switch (command) {
    case 7: return kProtocolDescriptor;
    case 0:
        return callbacks.status != nullptr ? callbacks.status(callbacks.context) : kInvalidRpcResult;
    case 1:
        if (callbacks.features == nullptr || callbacks.status == nullptr) {
            return kInvalidRpcResult;
        }
        callbacks.features(callbacks.context, static_cast<std::uint32_t>(argument));
        return callbacks.status(callbacks.context);
    case 2:
        if (callbacks.shutdown == nullptr || callbacks.status == nullptr) {
            return kInvalidRpcResult;
        }
        callbacks.shutdown(callbacks.context);
        return callbacks.status(callbacks.context);
    case 3:
        return callbacks.initialization_stage != nullptr
                   ? static_cast<std::uint64_t>(callbacks.initialization_stage(callbacks.context))
                   : kInvalidRpcResult;
    case 4:
        if (callbacks.write_config == nullptr || callbacks.status == nullptr) {
            return kInvalidRpcResult;
        }
        callbacks.write_config(callbacks.context, static_cast<std::uint32_t>(argument), argument2);
        return callbacks.status(callbacks.context);
    case 5:
        return callbacks.read_config != nullptr
                   ? callbacks.read_config(callbacks.context, static_cast<std::uint32_t>(argument))
                   : kInvalidRpcResult;
    case 6:
        return callbacks.read_telemetry != nullptr
                   ? callbacks.read_telemetry(callbacks.context, static_cast<std::uint32_t>(argument))
                   : kInvalidRpcResult;
    default:
        return kInvalidRpcResult;
    }
}

Runtime::Runtime(const RuntimeCallbacks& callbacks) noexcept : callbacks_(callbacks) {}

bool Runtime::Start() noexcept {
    SetLifecycle(Lifecycle::Starting);
    SetStage(0);
    if (callbacks_.initialize != nullptr && !callbacks_.initialize(callbacks_.context)) {
        SetError(1);
        SetLifecycle(Lifecycle::Failed);
        return false;
    }
    SetLifecycle(Lifecycle::Ready);
    for (std::uint32_t i = 0; i < kMaxConfigWords; ++i) {
        if (callbacks_.read_config) config_mirror_[i].store(callbacks_.read_config(callbacks_.context, i), std::memory_order_release);
    }
    for (std::uint32_t i = 0; i < kMaxTelemetryWords; ++i) {
        telemetry_mirror_[i].store(callbacks_.telemetry ? callbacks_.telemetry(callbacks_.context, i) : kInvalidRpcResult, std::memory_order_release);
    }
    return true;
}

void Runtime::Tick() noexcept {
    const std::uint32_t pending = pending_config_mask_.exchange(0, std::memory_order_acq_rel);
    if (pending != 0 && callbacks_.write_config != nullptr) {
        for (std::uint32_t index = 0; index < kMaxConfigWords; ++index) {
            const std::uint32_t bit = std::uint32_t{1} << index;
            if ((pending & bit) == 0) {
                continue;
            }
            const std::uint64_t value = pending_config_values_[index].load(std::memory_order_acquire);
            std::uint64_t applied = 0;
            if (callbacks_.write_config(callbacks_.context, index, value, applied)) {
                config_mirror_[index].store(applied, std::memory_order_release);
            }
        }
    }

    const std::uint32_t requested = requested_features_.load(std::memory_order_acquire);
    if (requested != active_features_.load(std::memory_order_relaxed) && callbacks_.features != nullptr &&
        callbacks_.features(callbacks_.context, requested)) {
        active_features_.store(requested, std::memory_order_release);
    }

    heartbeat_.store((heartbeat_.load(std::memory_order_relaxed) + 1) & 0xffffu,
                     std::memory_order_release);
    if (lifecycle_.load(std::memory_order_acquire) == Lifecycle::Ready && callbacks_.tick != nullptr) {
        callbacks_.tick(callbacks_.context);
    }
    if (callbacks_.telemetry) {
        for (std::uint32_t i = 0; i < kMaxTelemetryWords; ++i) telemetry_mirror_[i].store(callbacks_.telemetry(callbacks_.context, i), std::memory_order_release);
    }

    if (!shutdown_requested_.load(std::memory_order_acquire)) {
        return;
    }
    if (lifecycle_.load(std::memory_order_relaxed) != Lifecycle::Disabled) {
        if (callbacks_.shutdown != nullptr && !callbacks_.shutdown(callbacks_.context)) {
            return;
        }
        SetLifecycle(Lifecycle::Disabled);
    }
    if (callbacks_.shutdown_complete == nullptr || callbacks_.shutdown_complete(callbacks_.context)) {
        shutdown_complete_.store(true, std::memory_order_release);
    }
}

int Runtime::Run() noexcept {
    if (Start()) {
        while (!shutdown_complete() && lifecycle_.load(std::memory_order_acquire) != Lifecycle::Failed) {
            Tick();
            usleep(5000);
        }
    }
    return static_cast<int>(last_error_.load(std::memory_order_acquire));
}

std::uint64_t Runtime::Rpc(std::uint64_t command, std::uint64_t argument,
                           std::uint64_t argument2) noexcept {
    switch (command) {
    case 7: return kProtocolDescriptor;
    case 0:
        return PackStatus();
    case 1:
        RequestFeatures(static_cast<std::uint32_t>(argument));
        return PackStatus();
    case 2:
        RequestShutdown();
        return PackStatus();
    case 3:
        return stage_.load(std::memory_order_acquire);
    case 4:
        if (argument >= kMaxConfigWords) {
            return kInvalidRpcResult;
        }
        pending_config_values_[argument].store(argument2, std::memory_order_release);
        pending_config_mask_.fetch_or(std::uint32_t{1} << argument, std::memory_order_acq_rel);
        return PackStatus();
    case 5:
        return argument < kMaxConfigWords ? ReadConfig(static_cast<std::uint32_t>(argument))
                                          : kInvalidRpcResult;
    case 6:
        return argument < kMaxTelemetryWords
                   ? telemetry_mirror_[argument].load(std::memory_order_acquire)
                   : kInvalidRpcResult;
    default:
        return kInvalidRpcResult;
    }
}

void Runtime::RequestFeatures(std::uint32_t features) noexcept {
    requested_features_.store(features, std::memory_order_release);
}

void Runtime::RequestShutdown() noexcept {
    shutdown_requested_.store(true, std::memory_order_release);
}

void Runtime::SetError(std::uint32_t error) noexcept {
    last_error_.store(error, std::memory_order_release);
}

void Runtime::SetStage(std::uint32_t stage) noexcept {
    stage_.store(stage, std::memory_order_release);
}

std::uint64_t Runtime::PackStatus() const noexcept {
    return (static_cast<std::uint64_t>(callbacks_.status_magic) << 32) |
           (static_cast<std::uint64_t>(heartbeat_.load(std::memory_order_acquire) & 0xffffu) << 16) |
           (static_cast<std::uint64_t>(stage_.load(std::memory_order_acquire) & 0xffu) << 8) |
           static_cast<std::uint8_t>(lifecycle_.load(std::memory_order_acquire));
}

bool Runtime::shutdown_complete() const noexcept {
    return shutdown_complete_.load(std::memory_order_acquire);
}

void Runtime::SetLifecycle(Lifecycle lifecycle) noexcept {
    lifecycle_.store(lifecycle, std::memory_order_release);
    if (callbacks_.lifecycle != nullptr) {
        callbacks_.lifecycle(callbacks_.context, lifecycle);
    }
}

std::uint64_t Runtime::ReadConfig(std::uint32_t index) const noexcept {
    if (index >= kMaxConfigWords) {
        return kInvalidRpcResult;
    }
    return config_mirror_[index].load(std::memory_order_acquire);
}

int PayloadMain(Runtime& runtime) noexcept {
    return runtime.Run();
}

std::uint64_t PayloadRpc(Runtime& runtime, std::uint64_t command,
                         std::uint64_t argument, std::uint64_t argument2) noexcept {
    return runtime.Rpc(command, argument, argument2);
}

bool CallbackGate::Enter() noexcept {
    std::uint32_t state = state_.load(std::memory_order_acquire);
    for (;;) {
        if ((state & kNeutralized) != 0 || (state & kCountMask) == kCountMask) {
            return false;
        }
        if (state_.compare_exchange_weak(state, state + 1, std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            return true;
        }
    }
}

void CallbackGate::Leave() noexcept {
    state_.fetch_sub(1, std::memory_order_acq_rel);
}

void CallbackGate::Neutralize() noexcept {
    state_.fetch_or(kNeutralized, std::memory_order_acq_rel);
}

std::uint32_t CallbackGate::Active() const noexcept {
    return state_.load(std::memory_order_acquire) & kCountMask;
}

bool CallbackGate::Neutralized() const noexcept {
    return (state_.load(std::memory_order_acquire) & kNeutralized) != 0;
}

void CallbackGate::Reset() noexcept {
    state_.store(0, std::memory_order_release);
}

} // namespace internals
