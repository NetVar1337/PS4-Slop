#include "core/process/module_table.hpp"

#include <algorithm>

#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/published.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::process {

namespace {

// kept sorted by base so va_to_module can binary search
infra::published_t<module_table_t> g_modules;

} // namespace

uint64_t refresh_modules() {
    auto s = active_session();
    if (!s || !s->valid()) return 0;
    // the job owns a reference to the session: its handle (and the backend
    // it was opened on) stay valid until the job finishes even if the user
    // detaches meanwhile; a result for a session that is no longer current
    // is dropped instead of published
    return infra::jobs::submit({
        "Enumerate modules", "module_table", false,
        [s](infra::job_context_t& ctx) {
            auto r = s->backend()->enum_modules(s->handle());
            auto snap = std::make_shared<module_table_t>();
            snap->sampled_ms = infra::wall_ms();
            if (r.ok) {
                snap->items = std::move(r.items);
                std::sort(snap->items.begin(), snap->items.end(),
                          [](const runtime::module_info_t& a,
                             const runtime::module_info_t& b) {
                              return a.base < b.base;
                          });
            }
            if (ctx.cancelled() || active_session() != s) return;
            g_modules.publish(std::move(snap));
        }});
}

std::shared_ptr<const module_table_t> cached_modules() {
    return g_modules.get();
}

const runtime::module_info_t* va_to_module(uintptr_t va) {
    const auto snap = g_modules.get();
    if (!snap || snap->items.empty()) return nullptr;
    // last module with base <= va, then check the span covers va
    auto it = std::upper_bound(snap->items.begin(), snap->items.end(), va,
        [](uintptr_t v, const runtime::module_info_t& m) { return v < m.base; });
    if (it == snap->items.begin()) return nullptr;
    --it;
    const uint64_t end = static_cast<uint64_t>(it->base) + it->size;
    if (va < end) return &*it;
    return nullptr;
}

} // namespace slop::core::process
