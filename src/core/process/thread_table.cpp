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
    // the job holds the session so the pid is queried on the backend the
    // session was opened on (never a swapped-in one); stale results are
    // dropped instead of published
    auto s = active_session();
    if (!s || !s->valid()) return 0;
    return infra::jobs::submit({
        "Enumerate threads", "thread_table", false,
        [s](infra::job_context_t& ctx) {
            auto r = s->backend()->enum_threads(s->pid());
            auto snap = std::make_shared<thread_table_t>();
            snap->sampled_ms = infra::wall_ms();
            if (r.ok) snap->items = std::move(r.items);
            if (ctx.cancelled() || active_session() != s) return;
            g_threads.publish(std::move(snap));
        }});
}

std::shared_ptr<const thread_table_t> cached_threads() {
    return g_threads.get();
}

} // namespace slop::core::process
