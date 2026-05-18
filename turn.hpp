// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/turn.hpp
/// @brief  TURN client per RFC 5766 — allocation, refresh, permissions.
///
/// Held by `IceSession` through a `shared_ptr`; async refresh and
/// recv closures pin the client through `weak_from_this()` so a
/// session that already tore down silently no-ops the next callback.
///
/// I/O model: TURN bytes flow through the shared
/// `gn.link.udp` carrier instead of an inline `asio::ip::udp::socket`.
/// The TURN server endpoint gets a dedicated carrier conn id
/// (`server_cid_`) allocated by the session at construction time;
/// `send_to_server` forwards on that cid and `on_inbound` is called
/// by the session's per-cid data dispatcher.

#include "stun.hpp"

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/types.h>

namespace gn::link::ice {

/// Append a STUN-over-TCP framed envelope (RFC 5389 §7.2.2) for @p
/// payload to @p out: a 2-byte big-endian length prefix followed by
/// the payload bytes. Returns `false` if @p payload exceeds the
/// 16-bit frame budget (65 535 bytes). The same framing applies to
/// TURN-over-TLS, which delegates record encryption to the TLS
/// carrier underneath.
[[nodiscard]] bool encode_stream_frame(std::span<const std::uint8_t> payload,
                                       std::vector<std::uint8_t>& out);

/// Try to consume one complete length-prefixed frame from @p buffer.
/// On success, writes the inner payload bytes into @p out, erases
/// the consumed `2 + payload_size` bytes from the front of
/// @p buffer, and returns `true`. On incomplete input (buffer holds
/// fewer than 2 bytes, or fewer than `2 + payload_size` bytes) the
/// function leaves @p buffer untouched and returns `false`. The
/// caller drives a `while` loop until this returns `false` to drain
/// all complete frames the carrier delivered in a single chunk.
[[nodiscard]] bool try_take_stream_frame(std::vector<std::uint8_t>& buffer,
                                         std::vector<std::uint8_t>& out);

/// @brief TURN allocation parameters (server URI, credentials, lifetime).
struct TurnConfig {
    std::string server;
    uint16_t    port = 3478;
    std::string username;
    std::string password;
    /// RFC 5389 §7.2.2 / RFC 5766 §2.1: TURN over TCP. UDP is the
    /// default per RFC 5766 §2.1, but operators behind UDP-blocked
    /// firewalls (corporate / mobile) frequently fall back to TCP.
    /// When `true`, the session resolves `gn.link.tcp` as the
    /// carrier for the TURN server endpoint and the TurnClient
    /// applies STUN-over-TCP framing (2-byte big-endian length
    /// prefix per message, RFC 5389 §7.2.2).
    bool        tcp_transport = false;
    /// TURN-over-TLS (the `turns://` scheme). When `true`, the
    /// session resolves `gn.link.tls` for the TURN server endpoint
    /// — the TLS plugin handles handshake + record-layer encryption
    /// over a TCP carrier underneath. Framing is the same
    /// length-prefixed STUN as plain TCP. `tls_transport` takes
    /// precedence over `tcp_transport` if both are set. Used in
    /// restrictive corporate firewalls that allow only outbound
    /// 443/TCP.
    bool        tls_transport = false;
    /// Relay-side transport (RFC 6062). Default = UDP (17); set to
    /// TCP (6) to request a TCP-allocated relay. The TCP-allocation
    /// flow uses CONNECT / CONNECTIONBIND in place of CHANNEL-BIND
    /// and is implemented in subsequent commits.
    std::uint8_t requested_transport = REQUESTED_TRANSPORT_UDP;
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
    TurnClient(asio::io_context& io,
               gn::sdk::LinkCarrier* carrier,
               gn_conn_id_t server_cid,
               const TurnConfig& cfg,
               TurnDataCallback data_cb,
               TurnAllocatedCallback alloc_cb = nullptr);
    ~TurnClient();

    /// Start allocation. Returns false if config is invalid or the
    /// carrier handle is missing.
    bool allocate();

    /// Send data through the relay to a peer.
    void send_indication(const std::string& peer_ip, uint16_t peer_port,
                          std::span<const uint8_t> data);

    /// Create permission for a peer IP.
    void create_permission(const std::string& peer_ip);

    /// Bind a TURN channel (RFC 5766 §11) to (peer_ip, peer_port).
    /// Allocates a 16-bit channel number from the 0x4000-0x7FFF
    /// range, sends ChannelBind to the server, and switches
    /// subsequent `send_indication` calls for that peer onto the
    /// ChannelData fast path (4-byte header vs full Send-Indication
    /// envelope ~36 bytes — meaningful saving on small payloads).
    /// Channels expire after 10 minutes per RFC; `schedule_refresh`
    /// re-binds before timeout. Idempotent — second call for the
    /// same peer returns the existing channel.
    void bind_channel(const std::string& peer_ip, uint16_t peer_port);

    /// Refresh allocation lifetime.
    void refresh();

    /// Close allocation (lifetime=0).
    void close();

    /// Get the relayed address (available after allocation success).
    MappedAddress relayed_address() const;
    bool is_allocated() const { return allocated_; }

    /// Health gate for multi-TURN failover. Returns false when the
    /// allocation never completed OR a subsequent refresh round-trip
    /// failed (server stopped answering, 437 stale-allocation, etc).
    /// The backup-probe path in IceSession compares against this
    /// before promoting a backup; a healthy primary blocks failover.
    bool is_healthy() const {
        return allocated_ && refresh_healthy_.load(std::memory_order_acquire);
    }

    /// Test hook: force the health state. Production code never
    /// calls this; mock servers use it to simulate "primary went
    /// dead" in failover unit tests without waiting out the real
    /// refresh timer.
    void mark_unhealthy_for_test() {
        refresh_healthy_.store(false, std::memory_order_release);
    }

    /// Carrier conn id this client uses to talk to the TURN server.
    /// The owning `IceSession` routes inbound bytes from this cid
    /// here via `on_inbound`.
    [[nodiscard]] gn_conn_id_t server_cid() const noexcept {
        return server_cid_;
    }

    /// Feed bytes received on `server_cid_` into the TURN state
    /// machine. Called by `IceSession::on_carrier_data` whenever the
    /// per-cid dispatcher routes inbound bytes destined for TURN.
    void on_inbound(std::span<const uint8_t> bytes);

private:
    asio::io_context& io_;
    gn::sdk::LinkCarrier* carrier_ = nullptr;
    gn_conn_id_t server_cid_ = 0;
    TurnConfig cfg_;
    TurnDataCallback data_cb_;
    TurnAllocatedCallback alloc_cb_;

    asio::steady_timer refresh_timer_;

    std::mutex mu_;
    bool allocated_ = false;
    /// Refresh-loop health. Starts true on construction so the
    /// pre-allocation period (when the client has never refreshed)
    /// is not mis-reported as unhealthy via `is_healthy()` — the
    /// `allocated_` gate covers that window first. Flipped to false
    /// in the refresh path on a missing / 5xx response and reset
    /// to true when a successful refresh round-trip lands.
    std::atomic<bool> refresh_healthy_{true};
    MappedAddress relayed_{};
    std::string realm_;
    std::string nonce_;
    std::string auth_key_;  // MD5(user:realm:pass)
    uint32_t lifetime_ = 600;

    std::unordered_set<std::string> permissions_;

    /// Bound channels keyed by `ip:port`. The forward map drives
    /// outbound (peer → channel for ChannelData encode); the reverse
    /// map drives inbound (channel → peer for surfacing the source
    /// to the data callback). Channels are allocated sequentially
    /// starting at `TURN_CHANNEL_NUMBER_MIN`.
    std::unordered_map<std::string, uint16_t>            peer_to_channel_;
    std::unordered_map<uint16_t, std::pair<std::string,
                                              uint16_t>> channel_to_peer_;
    uint16_t                                              next_channel_ = 0x4000;

    /// TURN-over-TCP reassembly buffer. STUN messages on a TCP
    /// transport ride a 2-byte length prefix (RFC 5389 §7.2.2). The
    /// carrier delivers TCP bytes in arbitrary-sized chunks; we
    /// accumulate them here and extract complete messages whenever
    /// the buffer holds at least a full prefixed envelope. Unused
    /// when `cfg_.tcp_transport == false`.
    std::vector<uint8_t> rx_buffer_;

    void send_to_server(std::span<const std::uint8_t> bytes) noexcept;
    /// Dispatch a single STUN message — shared between the UDP path
    /// (one datagram = one message) and the stream-framing path (one
    /// reassembled frame = one message). Centralising the dispatch
    /// keeps the auth-retry / allocate-response / data-indication
    /// branches in one place; the two transport branches just decide
    /// where the message bytes come from.
    void dispatch_inbound_message(std::span<const std::uint8_t> bytes);
    void handle_allocate_response(const StunMessage& msg);
    void handle_data_indication(const StunMessage& msg);
    void handle_channel_data(std::span<const uint8_t> bytes);
    void compute_auth_key();
    void schedule_refresh();
};

} // namespace gn::link::ice
