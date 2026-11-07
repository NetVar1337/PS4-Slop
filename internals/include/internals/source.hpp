#pragma once
#include <internals/memory.hpp>
namespace source {
struct EntityLayout {
    std::uintptr_t slots = 0;
    std::size_t count = 0, stride = 0, pointer = 0, serial = 0;
};
class EntityStore {
public:
    EntityStore(std::uintptr_t base, EntityLayout layout, internals::MemoryReader reader) noexcept
        : base_(base), layout_(layout), reader_(reader) {}
    bool available() const noexcept {
        return base_ && reader_.read && layout_.slots && layout_.count && layout_.count <= 0x10000 &&
            layout_.stride >= 8 && layout_.stride <= 256 && layout_.pointer <= layout_.stride - 8 &&
            layout_.serial <= layout_.stride - 4;
    }
    template<class F> std::size_t for_each(std::size_t start, std::size_t budget, F&& visitor) const noexcept {
        if (!available() || budget > 1024 || start >= layout_.count || base_ > UINTPTR_MAX - layout_.slots) return 0;
        std::size_t visited = 0;
        for (std::size_t i = start; i < layout_.count && i - start < budget; ++i) {
            const auto offset = i * layout_.stride;
            if (base_ + layout_.slots > UINTPTR_MAX - offset - layout_.stride) break;
            const auto slot = base_ + layout_.slots + offset;
            std::uintptr_t object = 0, again = 0, vtable = 0;
            std::uint32_t serial = 0, serial_again = 0;
            if (!reader_.Get(slot + layout_.serial, serial) || !reader_.Get(slot + layout_.pointer, object) || !object ||
                !reader_.Get(object, vtable) || !vtable || !reader_.Get(slot + layout_.pointer, again) ||
                !reader_.Get(slot + layout_.serial, serial_again) || object != again || serial != serial_again) continue;
            visitor(i, object, serial); ++visited;
        }
        return visited;
    }
private:
    std::uintptr_t base_;
    EntityLayout layout_;
    internals::MemoryReader reader_;
};
}
