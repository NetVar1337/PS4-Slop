// src/core/infra/deferred.cpp

#include "core/infra/deferred.hpp"
#include "core/infra/clock.hpp"

#include <algorithm>

namespace slop::core::infra {

deferred_manager_t& deferred_manager_t::get() {
    static deferred_manager_t m;
    return m;
}

bool deferred_manager_t::bind_executor(const std::string& kind,
                                       executor_t fn) {
    std::lock_guard lk(mu_);
    return executors_.emplace(kind, std::move(fn)).second;
}

uint64_t deferred_manager_t::submit(const std::string& kind,
                                    const std::string& params_json) {
    std::lock_guard lk(mu_);
    deferred_action_t a;
    a.id = next_id_++;
    a.kind = kind;
    a.params_json = params_json;
    a.status = "pending";
    a.created_ms = steady_ms();
    actions_.push_back(std::move(a));
    while (actions_.size() > 256) actions_.pop_front();
    return actions_.back().id;
}

std::vector<deferred_action_t> deferred_manager_t::list() const {
    std::lock_guard lk(mu_);
    return {actions_.begin(), actions_.end()};
}

std::optional<deferred_action_t> deferred_manager_t::get(uint64_t id) const {
    std::lock_guard lk(mu_);
    for (const auto& a : actions_)
        if (a.id == id) return a;
    return std::nullopt;
}

size_t deferred_manager_t::execute_pending(const std::string& kind) {
    // claim under the lock, run unlocked: an executor may list/cancel/submit
    // (or simply take long) without blocking every other caller or deadlocking
    struct claimed_t {
        uint64_t    id;
        std::string params;
        executor_t  fn;
    };
    std::vector<claimed_t> work;
    {
        std::lock_guard lk(mu_);
        for (auto& a : actions_) {
            if (a.status != "pending") continue;
            if (!kind.empty() && a.kind != kind) continue;
            const auto it = executors_.find(a.kind);
            if (it == executors_.end()) continue;
            a.status = "running";
            work.push_back({a.id, a.params_json, it->second});
        }
    }
    for (auto& w : work) {
        std::string result;
        bool ok = false;
        try {
            ok = w.fn(w.params, &result);
        } catch (const std::exception& e) {
            result = e.what();
        } catch (...) {
            result = "executor threw";
        }
        std::lock_guard lk(mu_);
        for (auto& a : actions_) {
            if (a.id != w.id) continue;
            a.status      = ok ? "done" : "failed";
            a.result_json = std::move(result);
            break;
        }
    }
    return work.size();
}

bool deferred_manager_t::cancel(uint64_t id) {
    std::lock_guard lk(mu_);
    for (auto& a : actions_) {
        if (a.id == id && a.status == "pending") {
            a.status = "cancelled";
            return true;
        }
    }
    return false;
}

void deferred_manager_t::clear() {
    std::lock_guard lk(mu_);
    actions_.clear();
}

size_t deferred_manager_t::size() const {
    std::lock_guard lk(mu_);
    return actions_.size();
}

} // namespace slop::core::infra
