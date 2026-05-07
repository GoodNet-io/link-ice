// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/turn.hpp
/// @brief  TURN client per RFC 5766 — allocation, refresh, permissions.
///
/// Held by `IceSession` through a `shared_ptr`; async refresh and
/// recv closures pin the client through `weak_from_this()` so a
/// session that already tore down silently no-ops the next callback.

#include "stun.hpp"

#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

namespace gn::link::ice {

/// @brief TURN allocation parameters (server URI, credentials, lifetime).
struct TurnConfig {
    std::string server;
    uint16_t    port = 3478;
    std::string username;
    std::string password;
};

/// Callback when data arrives via TURN relay.
using TurnDataCallback = std::function<void(const std::string& peer_ip,
                                             uint16_t peer_port,
                                             std::span<const uint8_t> data)>;

/// Callback when TURN allocation succeeds (relayed address available).
using TurnAllocatedCallback = std::function<void(const std::string& relay_ip,
                                                  uint16_t relay_port)>;

/// TURN client — manages allocation and relay.
/// Owned by `IceSession` through `std::shared_ptr` so async refresh /
/// recv closures can pin the client through `weak_from_this()` and
/// safely no-op if the session has already torn it down.
class TurnClient : public std::enable_shared_from_this<TurnClient> {
public:
    TurnClient(asio::io_context& io, const TurnConfig& cfg,
               TurnDataCallback data_cb,
               TurnAllocatedCallback alloc_cb = nullptr);
    ~TurnClient();

    /// Start allocation. Returns false if config is invalid.
    bool allocate();

    /// Send data through the relay to a peer.
    void send_indication(const std::string& peer_ip, uint16_t peer_port,
                          std::span<const uint8_t> data);

    /// Create permission for a peer IP.
    void create_permission(const std::string& peer_ip);

    /// Refresh allocation lifetime.
    void refresh();

    /// Close allocation (lifetime=0).
    void close();

    /// Get the relayed address (available after allocation success).
    MappedAddress relayed_address() const;
    bool is_allocated() const { return allocated_; }

private:
    asio::io_context& io_;
    TurnConfig cfg_;
    TurnDataCallback data_cb_;
    TurnAllocatedCallback alloc_cb_;

    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint server_ep_;
    asio::steady_timer refresh_timer_;

    std::mutex mu_;
    bool allocated_ = false;
    MappedAddress relayed_{};
    std::string realm_;
    std::string nonce_;
    std::string auth_key_;  // MD5(user:realm:pass)
    uint32_t lifetime_ = 600;

    std::unordered_set<std::string> permissions_;

    std::array<uint8_t, 2048> recv_buf_{};
    asio::ip::udp::endpoint sender_ep_;

    void start_recv();
    void handle_recv(size_t bytes);
    void handle_allocate_response(const StunMessage& msg);
    void handle_data_indication(const StunMessage& msg);
    void compute_auth_key();
    void schedule_refresh();
};

} // namespace gn::link::ice
