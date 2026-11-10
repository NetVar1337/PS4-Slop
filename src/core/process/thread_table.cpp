#include "core/process/thread_table.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/published.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::process {

namespace {

infra::published_t<thread_table_t> g_threads;

} // namespace

uint64_t refresh_threads() {
    // grab the pid now; the session may be replaced while the job runs, the
    // backend is looked up inside the job for the same reason
    const auto s = active_session();
    if (!s || !s->valid()) return 0;
    const uint32_t pid = s->pid();
    return infra::jobs::submit({
        "Enumerate threads", "thread_table", false,
        [pid](infra::job_context_t& ctx) {
            auto r = runtime::active().enum_threads(pid);
            auto snap = std::make_shared<thread_table_t>();
            snap->sampled_ms = infra::wall_ms();
            if (r.ok) snap->items = std::move(r.items);
            if (ctx.cancelled()) return;
            g_threads.publish(std::move(snap));
        }});
}

std::shared_ptr<const thread_table_t> cached_threads() {
    return g_threads.get();
}

} // namespace slop::core::process
