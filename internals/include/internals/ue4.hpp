#pragma once
#include <internals/memory.hpp>

namespace ue4 {
enum class NamesKind : std::uint8_t { Unavailable, Pool, Array };
struct Offsets {
    std::uintptr_t gobjects = 0;       // FUObjectArray root RVA
    std::uintptr_t objects_pointer = 0; // TUObjectArray.Objects slot RVA
    std::uintptr_t num_elements = 0;   // NumElements slot RVA (layout dependent)
    std::uintptr_t max_elements = 0;
    std::size_t object_stride = 0;
    std::uintptr_t object_ptr = 0;
    std::uintptr_t object_name_index = 0;
    std::uintptr_t gnames = 0;         // Pool: inline Blocks array RVA; Array: global RVA
    std::uintptr_t blocks_pointer = 0; // relative to gnames; zero is valid
    std::size_t block_shift = 16;
    std::size_t entry_stride = 2;
    std::uintptr_t entry_header = 0;
    std::uintptr_t name_entry_string = 0;
    std::size_t max_objects = 0;
    std::size_t max_names = 0;
    std::size_t max_name_blocks = 8192;
    bool chunked = false;
    bool name_array_indirect = false;
    NamesKind names_kind = NamesKind::Unavailable;
};
inline bool available(const Offsets& o) noexcept {
    return o.gobjects && o.objects_pointer && o.num_elements && o.max_elements &&
        o.object_stride >= sizeof(std::uintptr_t) && o.object_stride <= 256 &&
        o.object_ptr <= o.object_stride - sizeof(std::uintptr_t) && o.gnames &&
        o.max_objects && o.max_objects <= (1u << 20) && o.max_names &&
        o.block_shift > 0 && o.block_shift < 32 && o.max_name_blocks <= 8192 &&
        (o.names_kind == NamesKind::Pool || o.names_kind == NamesKind::Array);
}
class Store {
public:
    Store(std::uintptr_t base, const Offsets& offsets, internals::MemoryReader reader) noexcept
        : base_(base), o_(offsets), reader_(reader) {}
    bool available() const noexcept { return base_ && reader_.read && ue4::available(o_); }
    template<class F> std::size_t for_each(F&& visitor) const noexcept {
        if (!available()) return 0;
        std::uintptr_t items = 0;
        std::int32_t num = 0, max = 0;
        if (!get(base_, o_.objects_pointer, items) || !get(base_, o_.num_elements, num) ||
            !get(base_, o_.max_elements, max) || !items || num < 0 || max < num || max > (1 << 24)) return 0;
        const std::size_t count = static_cast<std::size_t>(num) < o_.max_objects ? num : o_.max_objects;
        std::size_t visited = 0;
        for (std::size_t i = 0; i < count; ++i) {
            std::uintptr_t start = items, object = 0;
            if (o_.chunked && (!get(items, (i >> 16) * 8, start) || !start)) continue;
            const auto within = o_.chunked ? (i & 0xffff) : i;
            if (!get(start, within * o_.object_stride + o_.object_ptr, object) || !object) continue;
            visitor(i, object);
            ++visited;
        }
        return visited;
    }
    bool name_index_of(std::uintptr_t object, std::uint32_t& out) const noexcept {
        return available() && get(object, o_.object_name_index, out);
    }
    std::size_t name_of(std::uint32_t index, char* out, std::size_t capacity) const noexcept {
        if (!out || !capacity) return 0;
        out[0] = 0;
        if (!available() || index >= o_.max_names) return 0;
        std::uintptr_t entry = 0, text = 0;
        std::size_t length = capacity - 1;
        bool wide = false;
        if (o_.names_kind == NamesKind::Pool) {
            const auto block = index >> o_.block_shift;
            if (block >= o_.max_name_blocks || !get(base_, o_.gnames + o_.blocks_pointer + block * 8, entry) || !entry) return 0;
            const auto within = index & ((std::uint32_t{1} << o_.block_shift) - 1);
            std::uint16_t header = 0;
            const auto at = within * o_.entry_stride + o_.entry_header;
            if (!get(entry, at, header)) return 0;
            if (entry > UINTPTR_MAX - at - 2) return 0;
            text = entry + at + 2;
            length = header >> 6;
            wide = (header & 1) != 0;
        } else {
            std::uintptr_t array = 0, chunk = 0;
            if (base_ > UINTPTR_MAX - o_.gnames) return 0;
            array = base_ + o_.gnames;
            if (o_.name_array_indirect && !reader_.Get(array, array)) return 0;
            if (!get(array, (index / 16384) * 8, chunk) || !chunk ||
                !get(chunk, (index % 16384) * 8, entry) || !entry ||
                entry > UINTPTR_MAX - o_.name_entry_string) return 0;
            std::uint32_t flags = 0;
            if (!reader_.Get(entry, flags)) return 0;
            wide = (flags & 1) != 0;
            text = entry + o_.name_entry_string;
        }
        const auto count = length < capacity - 1 ? length : capacity - 1;
        std::size_t written = 0;
        for (; written < count; ++written) {
            std::uint16_t unit = 0;
            if (wide) { if (!get(text, written * 2, unit)) { out[0] = 0; return 0; } }
            else { std::uint8_t byte = 0; if (!get(text, written, byte)) { out[0] = 0; return 0; } unit = byte; }
            if (!unit) break;
            out[written] = unit < 128 ? static_cast<char>(unit) : '?';
        }
        out[written] = 0;
        return written;
    }
private:
    template<class T> bool get(std::uintptr_t base, std::uintptr_t offset, T& out) const noexcept {
        return base && offset <= UINTPTR_MAX - base && reader_.Get(base + offset, out);
    }
    std::uintptr_t base_;
    const Offsets& o_;
    internals::MemoryReader reader_;
};
} // namespace ue4
