// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/link_ice.hpp
/// @brief  ICE link plugin per `docs/contracts/link.en.md` — NAT
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

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include "interface_watcher.hpp"
#include "mdns.hpp"
#include "session.hpp"

namespace gn::link::ice {

/// MTU floor mirroring UDP's reasoning: ICE packets ride raw UDP
/// datagrams plus the STUN framing, so the payload ceiling matches
/// the `udp` link's default MTU.
inline constexpr std::uint32_t kDefaultMtu = 1200;

/// `gn.link.ice.signal` extension version — bumped only on shape
/// breakage of `gn_link_ice_signal_api_t` below.
inline constexpr std::uint32_t kIceSignalVersion = 0x00010000U;

/// `gn.link.ice.path_mtu` extension version. Bump on shape breakage
/// of `gn_link_ice_path_mtu_api_t` below.
inline constexpr std::uint32_t kIcePathMtuVersion = 0x00010000U;

/// Path-MTU query surface for the `gn.link.ice.path_mtu` extension.
/// Upper layers (security session, gnet protocol, app framers) use
/// it to size their outbound frames to the value DPLPMTUD has
/// discovered for the nominated pair. Returns the static configured
/// floor when active probing is off, the conn id is unknown, or the
/// session has not yet nominated a pair.
extern "C" struct gn_link_ice_path_mtu_api_s {
    std::uint32_t api_size;

    /// Snapshot of the effective path MTU in bytes for @p conn.
    /// Result is the conservative static value when no probe data
    /// is available; the discovered MTU otherwise.
    gn_result_t (*get)(void* ctx,
                       gn_conn_id_t conn,
                       std::uint32_t* out_mtu);

    void* ctx;
    void* _reserved[2];
};
using gn_link_ice_path_mtu_api_t = struct gn_link_ice_path_mtu_api_s;

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

    /// RFC 8838 §10 end-of-candidates variants. The signaling
    /// transport emits these on the FINAL trickle batch to tell the
    /// receiver "no more candidates from my side". The receiver
    /// (us) marks the session and, under regular nomination, can
    /// commit to the current best valid pair immediately rather
    /// than waiting for a possibly-higher-priority candidate that
    /// will never arrive.
    gn_result_t (*offer_eoc)(void* ctx,
                              const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                              const std::uint8_t* blob,
                              std::size_t blob_size);
    gn_result_t (*answer_eoc)(void* ctx,
                                const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                                const std::uint8_t* blob,
                                std::size_t blob_size);

    void* ctx;
    void* _reserved[2];
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
    /// `ice://<peer-pk-hex>` per `docs/contracts/uri.en.md`. Returns
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

    /// Snapshot of nomination metrics for `conn`. Used by
    /// `gn.link.ice` metrics extension consumers (strategy plugins
    /// such as `gn.float-send.*`). Returns `nominated == false` if
    /// the conn id is
    /// unknown or its FSM hasn't reached `Connected`.
    [[nodiscard]] NominationMetrics nomination_metrics(
        gn_conn_id_t conn) const noexcept;

    /// RFC 8445 §9 ICE restart for an already-tracked connection.
    /// Regenerates ufrag/pwd and re-enters Gathering. Caller is
    /// responsible for propagating the fresh credentials through
    /// signaling so the peer can match incoming check requests.
    /// Returns `GN_ERR_NOT_FOUND` if the conn id is unknown.
    [[nodiscard]] gn_result_t restart_session(gn_conn_id_t conn);

    /// Number of live sessions; useful for tests.
    [[nodiscard]] std::size_t session_count() const noexcept;

    /// MTU advertised to senders; ICE adds some STUN-framing overhead
    /// but the figure mirrors UDP for symmetry.
    [[nodiscard]] std::uint32_t mtu() const noexcept {
        return mtu_.load(std::memory_order_relaxed);
    }

    /// Largest MTU discovered for @p conn via RFC 8899 DPLPMTUD.
    /// Falls back to `mtu()` when active probing is off, the conn id
    /// is unknown, or the FSM has not yet recorded a result.
    [[nodiscard]] std::uint32_t effective_path_mtu(
        gn_conn_id_t conn) const noexcept;

    /// ── Composer surface ─────────────────────────────────────────
    ///
    /// Layer-2 consumers (QUIC, DTLS) treat a nominated ICE pair as a
    /// NAT-traversed UDP carrier. They `composer_connect("ice://pk")`
    /// to spin up a fresh ICE session in composer-owned mode (bit 63
    /// of the returned conn id marks it as composer-owned), subscribe
    /// to per-cid data callbacks, and receive an accept-bus
    /// notification once the FSM reaches `Connected`. Bytes sent on a
    /// composer-owned cid travel through the same nominated path but
    /// bypass the kernel `notify_*` pipeline — the L2 owns the conn
    /// lifecycle.

    /// composer-bit marks conn ids allocated through the composer
    /// surface so `send` / `disconnect` can route to the composer
    /// map by id range without scanning both sides.
    static constexpr gn_conn_id_t kComposerIdBit = (1ULL << 63);

    [[nodiscard]] gn_result_t composer_listen(std::string_view uri);
    [[nodiscard]] gn_result_t composer_connect(std::string_view uri,
                                                 gn_conn_id_t* out_conn);
    [[nodiscard]] gn_result_t composer_subscribe_data(
        gn_conn_id_t conn,
        ::gn_link_data_cb_t cb,
        void* user_data);
    [[nodiscard]] gn_result_t composer_unsubscribe_data(gn_conn_id_t conn);
    [[nodiscard]] gn_result_t composer_subscribe_accept(
        ::gn_link_accept_cb_t cb,
        void* user_data,
        gn_subscription_id_t* out_token);
    [[nodiscard]] gn_result_t composer_unsubscribe_accept(
        gn_subscription_id_t token);
    /// ICE has no port of its own — surfaces the underlying UDP
    /// carrier's bound port. Returns 0 if no carrier or no listen
    /// has occurred yet.
    [[nodiscard]] gn_result_t composer_listen_port(
        std::uint16_t* out_port) const noexcept;

    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    /// Static descriptor for the `gn.link.ice` extension. Snapshotted
    /// once at plugin register time per `link.en.md` §8.
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

    /// Composer-mode callback bundle: bytes route through the
    /// per-cid data callback installed by `composer_subscribe_data`,
    /// nomination fires the accept-bus subscribers, and failures
    /// erase the composer entry without invoking kernel
    /// `notify_disconnect` (the L2 owns conn lifecycle).
    [[nodiscard]] IceSessionCallbacks make_composer_callbacks(
        gn_conn_id_t cid, const std::string& canonical_uri);

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

    /// UDP carrier handle. Resolved from `gn.link.udp`
    /// extension at `set_host_api` time. Sessions take this as a
    /// borrowed pointer; if `nullopt` the FSM degrades to a no-op
    /// (test fixtures without a UDP provider still get the link
    /// surface but no actual gather / check happens).
    std::optional<gn::sdk::LinkCarrier>           carrier_udp_;
    /// Optional TCP carrier, used only by TURN-over-TCP path when
    /// `cfg_.turn.tcp_transport == true` (RFC 5389 §7.2.2). Resolved
    /// the same way as `carrier_udp_`; nullptr / nullopt is safe
    /// and silently downgrades TURN to UDP.
    std::optional<gn::sdk::LinkCarrier>           carrier_tcp_;
    /// Optional TLS carrier (`turns://` scheme). Used when
    /// `cfg_.turn.tls_transport == true`; the TLS plugin runs on
    /// TCP underneath transparently, so framing matches the plain
    /// TCP path.
    std::optional<gn::sdk::LinkCarrier>           carrier_tls_;

    /// Linux netlink interface-state watcher. Brought up at
    /// `set_host_api` time when `cfg_.reactive_interface_change` is
    /// set (default true). Fires `on_interface_change` after a
    /// debounced flap; on non-Linux the watcher quietly fails its
    /// `start()` and stays inert.
    std::unique_ptr<InterfaceWatcher>             iface_watcher_;
    void on_interface_change();

    /// mDNS responder + resolver shared across every session.
    /// Bound lazily on the first session that needs it (i.e.
    /// `mdns_obfuscate_host_candidates` is true, OR a peer
    /// advertises a HostMdns candidate that needs resolving). One
    /// instance per plugin so the multicast socket is bound once.
    /// nullptr until first use; multiple sessions share the
    /// shared_ptr through the IceSession constructor.
    std::shared_ptr<MdnsManager>                  mdns_;
    [[nodiscard]] std::shared_ptr<MdnsManager> ensure_mdns_manager();

    /// Composer-side state. Lives parallel to the kernel
    /// `sessions_` map so the bit-63 id range lookup picks the right
    /// path. Each entry binds a composer-owned cid to its underlying
    /// IceSession plus per-cid L2 data callback storage.
    struct ComposerEntry {
        std::shared_ptr<IceSession> session;
        std::string                 peer_pk_hex;
        ::gn_link_data_cb_t         data_cb     = nullptr;
        void*                       data_user   = nullptr;
        bool                        nominated   = false;
        std::string                 canonical_uri;
    };

    struct ComposerAcceptSub {
        gn_subscription_id_t token;
        ::gn_link_accept_cb_t cb;
        void*                user_data;
    };

    mutable std::mutex                                    composer_mu_;
    std::unordered_map<gn_conn_id_t, ComposerEntry>       composer_sessions_;
    std::unordered_map<std::string, gn_conn_id_t>         composer_peer_to_id_;
    std::vector<ComposerAcceptSub>                        composer_accept_subs_;
    std::atomic<std::uint64_t>                            next_composer_id_{1};
    std::atomic<gn_subscription_id_t>                     next_accept_token_{1};
};

}  // namespace gn::link::ice
