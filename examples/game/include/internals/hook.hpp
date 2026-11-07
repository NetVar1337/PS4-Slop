#pragma once
#include <array>
#include <cstring>
#include <internals/memory.hpp>
#include <internals/runtime.hpp>

namespace internals {
struct HookPlan {
    std::uintptr_t target = 0, trampoline = 0;
    const std::uint8_t* expected = nullptr;
    const std::uint8_t* replacement = nullptr;
    const std::uint8_t* relocated = nullptr;
    std::size_t size = 0, relocated_size = 0;
};
struct HookMemory {
    MemoryReader reader;
    void* context = nullptr;
    bool (*write)(void*, std::uintptr_t, const void*, std::size_t) noexcept = nullptr;
    // enter=true makes precisely this range writable; false restores its exact
    // previous protection. Platform adapter owns page alignment and restoration.
    bool (*protect)(void*, std::uintptr_t, std::size_t, bool) noexcept = nullptr;
    bool (*flush)(void*, std::uintptr_t, std::size_t) noexcept = nullptr;
    bool (*quiescent)(void*) noexcept = nullptr;
};
enum class HookState { Empty, Installed, Restored, Uncertain };
class Hook {
public:
    HookState state() const noexcept { return state_; }
    bool Install(const HookPlan& plan, const HookMemory& memory) noexcept {
        if (state_ != HookState::Empty || !plan.target || !plan.trampoline ||
            !plan.expected || !plan.replacement || !plan.relocated || plan.size < 14 ||
            plan.size > 128 || !plan.relocated_size || plan.relocated_size > 1024 ||
            !memory.write || !memory.protect || !memory.flush || !memory.quiescent ||
            !memory.quiescent(memory.context)) return false;
        if (plan.target > UINTPTR_MAX - plan.size || plan.trampoline > UINTPTR_MAX - plan.relocated_size ||
            (plan.trampoline < plan.target + plan.size && plan.target < plan.trampoline + plan.relocated_size)) return false;
        plan_ = plan; memory_ = memory;
        std::memcpy(original_.data(), plan.expected, plan.size);
        std::memcpy(patch_.data(), plan.replacement, plan.size);
        if (!Equals(plan.target, original_.data(), plan.size)) return false;
        // Trampoline must be allocated and owned by the caller. Publish it fully
        // before changing the entry. A failed entry write leaves ownership intact.
        if (!Write(plan.trampoline, plan.relocated, plan.relocated_size)) { state_ = HookState::Uncertain; return false; }
        state_ = HookState::Uncertain;
        if (!Equals(plan.target, original_.data(), plan.size)) return false;
        state_ = HookState::Uncertain;
        if (!Write(plan.target, patch_.data(), plan.size)) return false;
        state_ = HookState::Installed;
        return true;
    }
    bool Restore(CallbackGate& gate) noexcept {
        if (state_ == HookState::Restored) return true;
        if (state_ != HookState::Installed || !memory_.quiescent(memory_.context)) return false;
        gate.Neutralize();
        if (gate.Active() != 0) return false;
        // A third party may own the entry now. Never overwrite their bytes.
        if (!Equals(plan_.target, patch_.data(), plan_.size)) { state_ = HookState::Uncertain; return false; }
        state_ = HookState::Uncertain;
        if (!Write(plan_.target, original_.data(), plan_.size)) return false;
        state_ = HookState::Restored;
        return true;
    }
private:
    bool Equals(std::uintptr_t at, const void* bytes, std::size_t size) const noexcept {
        std::array<std::uint8_t, 1024> buffer{};
        return size <= buffer.size() && memory_.reader.Read(at, buffer.data(), size) && std::memcmp(buffer.data(), bytes, size) == 0;
    }
    bool Write(std::uintptr_t at, const void* bytes, std::size_t size) const noexcept {
        if (!memory_.protect(memory_.context, at, size, true)) return false;
        const bool written = memory_.write(memory_.context, at, bytes, size);
        const bool flushed = memory_.flush(memory_.context, at, size);
        const bool restored = memory_.protect(memory_.context, at, size, false);
        return written && flushed && restored && Equals(at, bytes, size);
    }
    HookState state_ = HookState::Empty;
    HookPlan plan_;
    HookMemory memory_;
    std::array<std::uint8_t, 128> original_{}, patch_{};
};
} // namespace internals
