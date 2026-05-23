// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/dbg.hpp
/// @brief  Env-gated diagnostic logging for ICE FSM internals.
///
/// Gated by env var `ICE_DEBUG=1`. When disabled the macro expands
/// to a no-op so prod builds carry no runtime cost beyond a single
/// `std::atomic_bool` load on first call (cached).
#pragma once

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

namespace gn::link::ice {

inline bool ice_dbg_enabled() {
    static std::atomic<int> cached{-1};
    int v = cached.load(std::memory_order_relaxed);
    if (v < 0) {
        const char* s = std::getenv("ICE_DEBUG");
        v = (s && s[0] == '1') ? 1 : 0;
        cached.store(v, std::memory_order_relaxed);
    }
    return v == 1;
}

inline void ice_dbg_emit(const char* tag, const char* fmt, ...) {
    if (!ice_dbg_enabled()) return;
    using clock = std::chrono::steady_clock;
    static const auto t0 = clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        clock::now() - t0).count();
    std::fprintf(stderr, "[ice-dbg t=%lld.%03llds %s] ",
                 static_cast<long long>(ms / 1000),
                 static_cast<long long>(ms % 1000), tag);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

}  // namespace gn::link::ice

#define ICE_DBG(tag, ...) ::gn::link::ice::ice_dbg_emit((tag), __VA_ARGS__)
