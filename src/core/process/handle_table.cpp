#include "core/process/handle_table.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/published.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::process {

namespace {

infra::published_t<handle_table_t> g_handles;

} // namespace

uint64_t refresh_handles() {
    const auto s = active_session();
    if (!s || !s->valid()) return 0;
    const uint32_t pid = s->pid();
    return infra::jobs::submit({
        "Enumerate handles", "handle_table", false,
        [pid](infra::job_context_t& ctx) {
            auto r = runtime::active().enum_handles(pid);
            auto snap = std::make_shared<handle_table_t>();
            snap->sampled_ms = infra::wall_ms();
            if (r.ok) snap->items = std::move(r.items);
            if (ctx.cancelled()) return;
            g_handles.publish(std::move(snap));
        }});
}

std::shared_ptr<const handle_table_t> cached_handles() {
    return g_handles.get();
}

} // namespace slop::core::process
