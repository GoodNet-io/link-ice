// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/link_ice.hpp
/// @brief  ICE link plugin per `docs/contracts/link.md` — NAT
///         traversal via STUN/TURN with full RFC 8445 connectivity
///         checks.
///
/// Threading model mirrors the UDP link plugin: one `io_context` per
/// plugin runs on a single worker thread; per-peer `IceSession`
/// instances each hold their own strand, so ICE machinery never
/// contends with kernel-side host-API calls.
///
/// Signaling is not on the wire — ICE candidates ride out-of-band
/// through a peer extension `gn.link.ice.signal`. A signaling
/// handler (heartbeat, a future signaling channel, or an SDK
/// helper) calls `offer(peer_pk, blob)` / `answer(peer_pk, blob)`
/// to hand serialized candidate sets to this plugin.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include "session.hpp"

namespace gn::link::ice {

/// MTU floor mirroring UDP's reasoning: ICE packets ride raw UDP
/// datagrams plus the STUN framing, so the payload ceiling matches
/// the `udp` link's default MTU.
inline constexpr std::uint32_t kDefaultMtu = 1200;

/// `gn.link.ice.signal` extension version — bumped only on shape
/// breakage of `gn_link_ice_signal_api_t` below.
inline constexpr std::uint32_t kIceSignalVersion = 0x00010000U;

/// Peer-to-peer ICE signaling extension surfaced as
/// `gn.link.ice.signal`. Handlers that own the signaling channel
/// pass candidate blobs through this vtable; the ICE plugin maps
/// the peer pubkey to an `IceSession` and feeds the blob into the
/// FSM.
extern "C" struct gn_link_ice_signal_api_s {
    std::uint32_t api_size;

    /// Deliver a remote offer (peer is controller). Allocates a new
    /// IceSession in responder role, parses the candidate list, and
    /// drives the FSM toward `Checking` once gathering finishes.
    /// `peer_pk` is GN_PUBLIC_KEY_BYTES bytes. `blob` must hold the
    /// `IceSignalData` envelope from `candidate.hpp`.
    gn_result_t (*offer)(void* ctx,
                          const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                          const std::uint8_t* blob,
                          std::size_t blob_size);

    /// Deliver a remote answer (we are controller). Looks up the
    /// in-flight session for this peer and feeds the candidate set.
    gn_result_t (*answer)(void* ctx,
                           const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                           const std::uint8_t* blob,
                           std::size_t blob_size);

    void* ctx;
    void* _reserved[4];
};
using gn_link_ice_signal_api_t = struct gn_link_ice_signal_api_s;

/// Plugin entry instantiates `IceLink` through `make_shared` and
/// keeps it alive through the `link_plugin.hpp` boilerplate's
/// `LinkPluginInstance<IceLink>`.
class IceLink : public std::enable_shared_from_this<IceLink> {
public:
    IceLink();
    ~IceLink();

    IceLink(const IceLink&)            = delete;
    IceLink& operator=(const IceLink&) = delete;

    /// ICE is peer-to-peer; `listen` is a no-op kept for vtable
    /// symmetry. URI parsing rejects malformed schemes so the kernel
    /// can rely on the contract regardless of plugin behaviour.
    [[nodiscard]] gn_result_t listen(std::string_view uri);

    /// Initiate ICE in controller role. URI form
    /// `ice://<peer-pk-hex>` per `docs/contracts/uri.md`. Returns
    /// once the gather is posted; nomination completes asynchronously
    /// and surfaces through `notify_connect` once the first candidate
    /// pair succeeds.
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    /// Send a single application frame through the nominated pair.
    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    /// Datagram link: each frame keeps its boundary; oversized frames
    /// are rejected per-frame, mirroring `udp::send_batch`.
    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);

    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;

    /// Idempotent. Stops every session, fires `notify_disconnect`
    /// on the caller thread for every published id, and quiesces
    /// the worker.
    void shutdown();

    /// Deliver an ICE offer / answer arriving through the
    /// `gn.link.ice.signal` extension. Public so the extension
    /// thunks in `plugin_entry.cpp` can dispatch into the link
    /// without re-parsing.
    [[nodiscard]] gn_result_t deliver_signal(
        const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        std::uint8_t kind,
        std::span<const std::uint8_t> blob);

    /// Number of live sessions; useful for tests.
    [[nodiscard]] std::size_t session_count() const noexcept;

    /// MTU advertised to senders; ICE adds some STUN-framing overhead
    /// but the figure mirrors UDP for symmetry.
    [[nodiscard]] std::uint32_t mtu() const noexcept {
        return mtu_.load(std::memory_order_relaxed);
    }

    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    /// Static descriptor for the `gn.link.ice` extension. Snapshotted
    /// once at plugin register time per `link.md` §8.
    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

private:
    struct PeerEntry {
        gn_conn_id_t                          id;
        std::shared_ptr<IceSession>           session;
        std::string                            peer_pk_hex;
    };

    /// Strict-checked hex decoder for `ice://<peer-pk-hex>`. Returns
    /// `false` on any non-hex character or wrong length so a
    /// malformed URI never reaches the FSM.
    [[nodiscard]] static bool parse_peer_pk_hex(
        std::string_view hex,
        std::uint8_t out[GN_PUBLIC_KEY_BYTES]);

    [[nodiscard]] static std::string pk_to_hex(
        const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]);

    /// Build the FSM-side callback bundle wired back into
    /// `notify_connect / notify_inbound_bytes / notify_disconnect`.
    [[nodiscard]] IceSessionCallbacks make_callbacks(gn_conn_id_t id);

    /// Reload `ice.*` config keys into `cfg_`. Idempotent; called at
    /// `set_host_api` time and from the config-reload subscription.
    void apply_config() noexcept;

    [[nodiscard]] bool claim_disconnect(gn_conn_id_t id);

    /// Periodic timer that walks `sessions_` and tears down idle
    /// failed sessions so the kernel reclaims the conn ids.
    void start_reaper();
    void reap_sessions();

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::thread                                                      worker_;
    asio::steady_timer                                                reaper_timer_;

    std::atomic<bool>                            shutdown_{false};
    std::atomic<std::uint32_t>                   mtu_{kDefaultMtu};

    /// `cfg_` is read on the worker thread by per-session FSMs and
    /// rewritten on the kernel thread during config reload. The
    /// `cfg_mu_` covers both write operations and the snapshots taken
    /// when allocating a new IceSession.
    mutable std::mutex                            cfg_mu_;
    IceConfig                                     cfg_;

    mutable std::mutex                            sessions_mu_;
    std::unordered_map<gn_conn_id_t, PeerEntry>   sessions_;
    std::unordered_map<std::string, gn_conn_id_t> peer_to_id_;
    std::vector<gn_conn_id_t>                     published_ids_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    std::uint64_t                                 reload_sub_id_ = 0;
    bool                                          reaper_started_ = false;
    const host_api_t*                              api_ = nullptr;
};

}  // namespace gn::link::ice
