// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/interface_watcher.hpp
/// @brief  Linux netlink (`AF_NETLINK / NETLINK_ROUTE`) subscription
///         for network-interface state changes. Re-gathers host
///         candidates when an interface flaps, a new addr appears,
///         or one disappears.

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

namespace gn::link::ice {

class InterfaceWatcher {
public:
    /// Called on the watcher's io_context strand whenever a debounced
    /// interface event fires. The owning link plugin walks its session
    /// table and re-gathers host candidates.
    using Callback = std::function<void()>;

    InterfaceWatcher(asio::io_context& io,
                     std::chrono::milliseconds debounce,
                     Callback on_change);
    ~InterfaceWatcher();

    InterfaceWatcher(const InterfaceWatcher&)            = delete;
    InterfaceWatcher& operator=(const InterfaceWatcher&) = delete;

    /// Open the AF_NETLINK socket and start the read loop on a
    /// dedicated thread. Returns false if the socket / bind fails or
    /// the platform does not implement netlink. Safe to call once;
    /// subsequent calls are no-ops.
    bool start();
    void stop();

private:
    void run_loop();
    void schedule_callback();

    asio::io_context&               io_;
    std::chrono::milliseconds       debounce_;
    Callback                         on_change_;
    asio::steady_timer               debounce_timer_;

    std::atomic<bool>                running_{false};
    std::atomic<bool>                started_{false};
    /// Netlink fd is touched from two threads: `start` / `stop` on the
    /// owner's thread, `run_loop` on the reader thread. Atomic so the
    /// `sock_ = -1` reset in `stop` does not race with the reader's
    /// `pfd.fd = sock_` snapshot.
    std::atomic<int>                  sock_{-1};
    std::thread                       reader_;
};

}  // namespace gn::link::ice
