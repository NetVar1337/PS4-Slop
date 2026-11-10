#include "core/process/process_list.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/published.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::process {

namespace {

// latest enumeration, published by the refresh job, read lock-free by the ui
infra::published_t<process_list_t> g_processes;

} // namespace

uint64_t refresh_processes(bool resolve_details) {
    // the backend is looked up inside the job: a ps4 connect/disconnect can
    // swap it between submit and run, and the job must not hold a stale ref
    return infra::jobs::submit({
        "Enumerate processes", "process_list", false,
        [resolve_details](infra::job_context_t& ctx) {
            runtime::backend_t& b = runtime::active();
            auto r = b.enum_processes();
            auto snap = std::make_shared<process_list_t>();
            snap->sampled_ms = infra::wall_ms();
            if (r.ok) {
                snap->items = std::move(r.items);
                // entries the backend could not open come back without a path
                for (const auto& p : snap->items)
                    if (p.path.empty() && !p.name.empty()) ++snap->inaccessible_count;
                if (resolve_details) {
                    const auto el = b.query_elevation();
                    snap->debug_privilege =
                        el == runtime::elevation_t::elevated ||
                        el == runtime::elevation_t::system;
                }
            }
            if (ctx.cancelled()) return;
            g_processes.publish(std::move(snap));
        }});
}

std::shared_ptr<const process_list_t> cached_processes() {
    return g_processes.get();
}

} // namespace slop::core::process
