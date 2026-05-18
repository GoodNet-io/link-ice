// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/interface_watcher.cpp

#include "interface_watcher.hpp"

#include <asio/bind_executor.hpp>
#include <asio/post.hpp>

#include <cerrno>
#include <cstring>
#include <system_error>

#ifdef __linux__
#  include <linux/netlink.h>
#  include <linux/rtnetlink.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <poll.h>
#  include <fcntl.h>
#endif

namespace gn::link::ice {

InterfaceWatcher::InterfaceWatcher(asio::io_context& io,
                                     std::chrono::milliseconds debounce,
                                     Callback on_change)
    : io_(io),
      debounce_(debounce),
      on_change_(std::move(on_change)),
      debounce_timer_(io) {}

InterfaceWatcher::~InterfaceWatcher() {
    stop();
}

bool InterfaceWatcher::start() {
#ifdef __linux__
    if (started_.exchange(true)) return true;
    const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        started_.store(false);
        return false;
    }

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK
                       | RTMGRP_IPV4_IFADDR
                       | RTMGRP_IPV6_IFADDR;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        sock_.store(-1, std::memory_order_release);
        started_.store(false);
        return false;
    }

    sock_.store(fd, std::memory_order_release);
    running_.store(true, std::memory_order_release);
    reader_ = std::thread([this] { run_loop(); });
    return true;
#else
    (void)on_change_;
    return false;
#endif
}

void InterfaceWatcher::stop() {
#ifdef __linux__
    if (!started_.load()) return;
    running_.store(false, std::memory_order_release);
    /// Swap the fd out atomically so the reader thread's next
    /// `pfd.fd = sock_.load(...)` snapshot sees -1, and `::shutdown` /
    /// `::close` only run once even if `stop` is invoked concurrently.
    const int fd = sock_.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }
    if (reader_.joinable()) reader_.join();
    debounce_timer_.cancel();
    started_.store(false);
#endif
}

#ifdef __linux__
void InterfaceWatcher::run_loop() {
    /// Read in fixed-size chunks; the kernel rounds messages up to
    /// netlink alignment so a single recv may carry multiple events.
    /// We don't need the contents — any RTM_NEW* / RTM_DEL* on the
    /// subscribed groups is enough to trigger a debounced re-gather.
    constexpr std::size_t kBufSize = 8192;
    std::vector<std::uint8_t> buf(kBufSize);

    while (running_.load(std::memory_order_acquire)) {
        const int fd = sock_.load(std::memory_order_acquire);
        if (fd < 0) break;
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, 500);
        if (pr <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        const ssize_t got = ::recv(fd, buf.data(), buf.size(), 0);
        if (got <= 0) continue;

        bool relevant = false;
        auto* nh = reinterpret_cast<struct nlmsghdr*>(buf.data());
        unsigned int remaining = static_cast<unsigned int>(got);
        for (; NLMSG_OK(nh, remaining)
             ; nh = NLMSG_NEXT(nh, remaining)) {
            if (nh->nlmsg_type == NLMSG_DONE) break;
            if (nh->nlmsg_type == NLMSG_ERROR) continue;
            switch (nh->nlmsg_type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                case RTM_NEWADDR:
                case RTM_DELADDR:
                    relevant = true;
                    break;
                default:
                    break;
            }
        }
        if (relevant) {
            schedule_callback();
        }
    }
}

void InterfaceWatcher::schedule_callback() {
    asio::post(io_, [this] {
        if (!running_.load(std::memory_order_acquire)) return;
        debounce_timer_.expires_after(debounce_);
        debounce_timer_.async_wait([this](const std::error_code& wait_ec) {
            if (wait_ec) return;
            if (!running_.load(std::memory_order_acquire)) return;
            if (on_change_) on_change_();
        });
    });
}
#endif

}  // namespace gn::link::ice
