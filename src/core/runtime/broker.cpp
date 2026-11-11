// src/core/runtime/broker.cpp

#include "core/runtime/broker.hpp"

#include <chrono>
#include <map>

namespace slop::core::runtime {

namespace {

std::recursive_mutex g_gate;

std::mutex g_clients_mu;
std::map<std::string, int64_t> g_clients;   // name -> attached since (epoch ms)

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

std::recursive_mutex& broker_gate() { return g_gate; }

void broker_client_attach(const std::string& name) {
    std::lock_guard lk(g_clients_mu);
    g_clients[name] = now_ms();
}

void broker_client_detach(const std::string& name) {
    std::lock_guard lk(g_clients_mu);
    g_clients.erase(name);
}

std::vector<std::pair<std::string, int64_t>> broker_clients() {
    std::lock_guard lk(g_clients_mu);
    return {g_clients.begin(), g_clients.end()};
}

} // namespace slop::core::runtime
