// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/link_ice.cpp
///
/// Backpressure note: unlike TCP / IPC / TLS / QUIC, the ICE link
/// plugin does not publish `GN_CONN_EVENT_BACKPRESSURE_SOFT` /
/// `_CLEAR`. ICE is a NAT-traversal coordination layer —
/// `IceSession::send` (in `session.cpp:151`) dispatches each
/// chunk through the UDP carrier or TURN relay immediately, with
/// no per-session send queue suitable for high / low watermarks.
/// The UDP carrier underneath handles transport-level congestion;
/// ICE itself has no queue to watermark. `pending_stun_probes_`
/// in `session.cpp` is STUN connectivity-check state, not user-
/// data queueing, so it does not feed the backpressure surface
/// either.

#include "link_ice.hpp"

#include "candidate.hpp"
#include "dns_ext_client.hpp"

#include <sdk/conn_events.h>
#include <sdk/convenience.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gn::link::ice {

namespace {

constexpr std::uint32_t kReaperIntervalSeconds = 30;
constexpr std::uint32_t kIdleSessionLimitSeconds = 60;

constexpr std::array<std::string_view, 1> kDefaultStunServers = {
    "stun.l.google.com:19302"
};

}  // namespace

IceLink::IceLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)),
      reaper_timer_(ioc_) {
    {
        /// Default config snapshot — overwritten by `apply_config`
        /// once `set_host_api` binds the kernel.
        std::lock_guard lk(cfg_mu_);
        for (auto sv : kDefaultStunServers) {
            cfg_.stun_servers.emplace_back(sv);
        }
    }
    /// `weak_from_this()` is unusable until the enclosing
    /// `make_shared` finishes, so the reaper boot has to wait until
    /// the first `set_host_api`. The worker thread spins immediately
    /// because it does not need `shared_from_this()`.
    worker_ = std::thread([this] { ioc_.run(); });
}

IceLink::~IceLink() {
    shutdown();
}

void IceLink::apply_config() noexcept {
    if (api_ == nullptr || api_->config_get == nullptr) return;

    /// Resolve the `gn.dns` extension once per apply_config call.
    /// When present, `stun:<host>` / `turn:<host>` entries without
    /// an explicit port trigger SRV expansion. When absent (the
    /// handler-dns plugin isn't loaded) the entries pass through
    /// unmodified — the operator will see a hostname in the config
    /// that needs OS-resolver lookup at probe time, or one that
    /// never resolves; either way the legacy path is unchanged.
    auto dns_ext = DnsExtClient::query(api_);

    IceConfig cfg;
    /// Default STUN entry — same as constructor; reload that drops
    /// the `ice.stun_servers` key falls back to the public Google
    /// resolver instead of disabling STUN gathering outright.
    for (auto sv : kDefaultStunServers) {
        cfg.stun_servers.emplace_back(sv);
    }

    /// Helper to append one STUN string into cfg, doing SRV
    /// expansion when the input is `stun:<host>` without a port
    /// AND `gn.dns` is reachable. Falls back to push-as-is
    /// otherwise.
    auto push_stun = [&](std::string_view raw) {
        const auto svc = parse_service_uri(raw);
        if (svc && svc->scheme == "stun" && svc->port == 0 && dns_ext) {
            const auto srv =
                dns_ext->resolve_service("stun", "udp", svc->host, 16);
            if (!srv.empty()) {
                for (const auto& r : srv) {
                    cfg.stun_servers.emplace_back(
                        r.target + ":" + std::to_string(r.port));
                }
                return;
            }
            /// SRV lookup yielded nothing — fall through to legacy
            /// form. Common when the operator's DNS plugin is up
            /// but the upstream doesn't publish `_stun._udp` SRV
            /// records (typical for many providers). The host
            /// segment alone, without a port, won't fly through
            /// the rest of ICE — log + push the bare hostname so
            /// the path-not-found shows up as a probe failure
            /// rather than a silent config drop.
        }
        if (svc && svc->scheme == "stun" && svc->port != 0) {
            cfg.stun_servers.emplace_back(
                svc->host + ":" + std::to_string(svc->port));
            return;
        }
        cfg.stun_servers.emplace_back(raw);
    };

    std::size_t arr_size = 0;
    if (gn_config_get_array_size(api_, "ice.stun_servers", &arr_size) == GN_OK) {
        cfg.stun_servers.clear();
        for (std::size_t i = 0; i < arr_size; ++i) {
            const char* value = nullptr;
            void* user_data = nullptr;
            void (*free_fn)(void*, void*) = nullptr;
            if (gn_config_get_array_string(api_, "ice.stun_servers", i,
                                            &value, &user_data, &free_fn) == GN_OK
                && value != nullptr) {
                push_stun(value);
                if (free_fn != nullptr) {
                    free_fn(user_data, const_cast<char*>(value));
                }
            }
        }
    }

    /// Helper that turns one raw TURN config string into a TurnConfig
    /// — accepts `host:port`, `turn:host`, and `turn:host:port`. SRV
    /// expansion fires when `turn:host` arrives without a port AND
    /// `gn.dns` is reachable. Returns nullopt when the string can't
    /// be parsed into a usable entry.
    auto parse_turn_entry = [&](std::string_view raw) -> std::optional<TurnConfig> {
        if (raw.empty()) return std::nullopt;
        TurnConfig t;

        const auto svc = parse_service_uri(raw);
        if (svc && svc->scheme == "turn" && svc->port == 0 && dns_ext) {
            const auto srv =
                dns_ext->resolve_service("turn", "udp", svc->host, 1);
            if (srv.empty()) return std::nullopt;
            t.server = srv[0].target;
            t.port   = srv[0].port;
            return t;
        }
        if (svc && svc->scheme == "turn" && svc->port != 0) {
            t.server = svc->host;
            t.port   = svc->port;
            return t;
        }
        /// Legacy `host:port` string.
        const std::string s(raw);
        const auto colon = s.rfind(':');
        if (colon != std::string::npos) {
            t.server = s.substr(0, colon);
            try {
                const auto p = std::stoul(s.substr(colon + 1));
                if (p == 0 || p > 65535) return std::nullopt;
                t.port = static_cast<std::uint16_t>(p);
            } catch (...) {
                return std::nullopt;
            }
            return t;
        }
        if (s.empty()) return std::nullopt;
        t.server = s;
        return t;
    };

    /// `ice.turn_servers` accepts BOTH a single-string form AND a
    /// string-array. First entry populates `cfg.turn` for session-
    /// side compatibility; every entry lands in
    /// `cfg.turn_servers` ready for allocation-fallover iteration
    /// (RFC 8445 §6.1.4) once the session side picks it up.
    {
        std::size_t turn_arr_size = 0;
        if (gn_config_get_array_size(api_, "ice.turn_servers",
                                      &turn_arr_size) == GN_OK) {
            for (std::size_t i = 0; i < turn_arr_size; ++i) {
                const char* value = nullptr;
                void* user_data = nullptr;
                void (*free_fn)(void*, void*) = nullptr;
                if (gn_config_get_array_string(api_, "ice.turn_servers", i,
                                                &value, &user_data, &free_fn) == GN_OK
                    && value != nullptr) {
                    if (auto t = parse_turn_entry(value)) {
                        cfg.turn_servers.push_back(std::move(*t));
                    }
                    if (free_fn != nullptr) {
                        free_fn(user_data, const_cast<char*>(value));
                    }
                }
            }
        } else {
            /// Single-string legacy form. Same parser, same shape.
            const char* value = nullptr;
            void* user_data = nullptr;
            void (*free_fn)(void*, void*) = nullptr;
            if (gn_config_get_string(api_, "ice.turn_servers",
                                      &value, &user_data, &free_fn) == GN_OK
                && value != nullptr) {
                if (auto t = parse_turn_entry(value)) {
                    cfg.turn_servers.push_back(std::move(*t));
                }
                if (free_fn != nullptr) {
                    free_fn(user_data, const_cast<char*>(value));
                }
            }
        }

        /// Mirror the first entry into `cfg.turn` for session-side
        /// reads. The session FSM consumes the singleton field
        /// today; iteration across `turn_servers` for fallover
        /// is not wired yet.
        if (!cfg.turn_servers.empty()) {
            cfg.turn = cfg.turn_servers.front();
        }
    }
    /// Credentials apply to every TURN entry — same realm in
    /// practice for an operator's TURN fleet. Per-server creds
    /// would need a richer config schema (object array) which
    /// isn't worth the churn until multi-realm fallover is real.
    auto apply_to_all_turns = [&](auto setter) {
        setter(cfg.turn);
        for (auto& t : cfg.turn_servers) setter(t);
    };
    {
        const char* value = nullptr;
        void* user_data = nullptr;
        void (*free_fn)(void*, void*) = nullptr;
        if (gn_config_get_string(api_, "ice.turn_username",
                                  &value, &user_data, &free_fn) == GN_OK
            && value != nullptr) {
            const std::string u(value);
            apply_to_all_turns([&](TurnConfig& t) { t.username = u; });
            if (free_fn != nullptr) {
                free_fn(user_data, const_cast<char*>(value));
            }
        }
    }
    {
        const char* value = nullptr;
        void* user_data = nullptr;
        void (*free_fn)(void*, void*) = nullptr;
        if (gn_config_get_string(api_, "ice.turn_password",
                                  &value, &user_data, &free_fn) == GN_OK
            && value != nullptr) {
            const std::string p(value);
            apply_to_all_turns([&](TurnConfig& t) { t.password = p; });
            if (free_fn != nullptr) {
                free_fn(user_data, const_cast<char*>(value));
            }
        }
    }

    std::int64_t v = 0;
    if (gn_config_get_int64(api_, "ice.session_timeout_s", &v) == GN_OK
        && v > 0 && v < 3600) {
        cfg.session_timeout_s = static_cast<int>(v);
    }
    if (gn_config_get_int64(api_, "ice.keepalive_interval_s", &v) == GN_OK
        && v > 0 && v < 3600) {
        cfg.keepalive_interval_s = static_cast<int>(v);
    }
    if (gn_config_get_int64(api_, "ice.consent_max_failures", &v) == GN_OK
        && v > 0 && v < 100) {
        cfg.consent_max_failures = static_cast<int>(v);
    }
    /// Consent recovery cap — how many `Checking` re-entries the
    /// FSM attempts before declaring the nominated pair dead.
    /// Default 3; 0 means "die at first consent failure". Bounded
    /// at 10 to keep a misconfigured value from holding a session
    /// alive forever.
    if (gn_config_get_int64(api_, "ice.consent_max_recovery", &v) == GN_OK
        && v >= 0 && v <= 10) {
        cfg.consent_max_recovery = static_cast<int>(v);
    }
    if (gn_config_get_int64(api_, "ice.check_interval_ms", &v) == GN_OK
        && v > 0 && v < 60000) {
        cfg.check_interval_ms = static_cast<int>(v);
    }
    /// Operator override for the per-path MTU advertised to senders.
    /// RFC 8899 PMTUD-style probing is future work; for now this is
    /// a static knob — operators in known network environments
    /// (jumbo-frame LANs, deployments behind known-MTU tunnels) can
    /// raise it; restricted deployments (some mobile carriers) can
    /// lower it. Bounded by [576, 65507]: 576 is the IPv4 minimum
    /// reassembly buffer, 65507 is the theoretical max UDP payload
    /// (65535 - IPv4 header - UDP header).
    if (gn_config_get_int64(api_, "ice.path_mtu", &v) == GN_OK
        && v >= 576 && v <= 65507) {
        mtu_.store(static_cast<std::uint32_t>(v),
                    std::memory_order_relaxed);
    }
    /// Toggle aggressive nomination (default = regular per RFC 8445).
    /// Operators that need fastest-possible nomination (single-pair
    /// scenarios, real-time UDP gaming where any path is good enough)
    /// can flip this to true.
    if (gn_config_get_int64(api_, "ice.aggressive_nomination", &v) == GN_OK) {
        cfg.aggressive_nomination = (v != 0);
    }
    /// Operator-side candidate filter tokens (C.6). Array of
    /// string tokens — each token sets one bit in
    /// `cfg.candidate_filter_flags`. Unknown tokens are ignored
    /// silently so an operator can adopt new tokens in a config
    /// file without breaking older kernels that don't recognise
    /// them.
    {
        std::size_t arr = 0;
        if (gn_config_get_array_size(api_, "ice.candidate_filters",
                                      &arr) == GN_OK) {
            for (std::size_t i = 0; i < arr; ++i) {
                const char* value = nullptr;
                void* user_data = nullptr;
                void (*free_fn)(void*, void*) = nullptr;
                if (gn_config_get_array_string(api_, "ice.candidate_filters", i,
                                                &value, &user_data, &free_fn) == GN_OK
                    && value != nullptr) {
                    const std::string_view tok(value);
                    if      (tok == "exclude-ipv4") cfg.candidate_filter_flags |= kCandidateFilterExcludeIpv4;
                    else if (tok == "exclude-ipv6") cfg.candidate_filter_flags |= kCandidateFilterExcludeIpv6;
                    else if (tok == "relay-only")   cfg.candidate_filter_flags |= kCandidateFilterRelayOnly;
                    else if (tok == "host-only")    cfg.candidate_filter_flags |= kCandidateFilterHostOnly;
                    if (free_fn != nullptr) {
                        free_fn(user_data, const_cast<char*>(value));
                    }
                }
            }
        }
    }
    /// TURN-over-TCP toggle (RFC 5389 §7.2.2). When set, sessions
    /// resolve `gn.link.tcp` for the TURN server endpoint and apply
    /// length-prefix framing on STUN messages. Useful behind UDP-
    /// blocked firewalls.
    if (gn_config_get_int64(api_, "ice.turn_tcp", &v) == GN_OK) {
        const bool b = (v != 0);
        apply_to_all_turns([&](TurnConfig& t) { t.tcp_transport = b; });
    }
    /// TURN-over-TLS (RFC 5389 §7.2.2, `turns://` scheme). When
    /// enabled the session resolves `gn.link.tls` for the TURN
    /// server endpoint; framing is the same length-prefixed STUN
    /// as plain TCP. Takes precedence over `ice.turn_tcp` when both
    /// are set — operators behind 443-only firewalls flip this on.
    if (gn_config_get_int64(api_, "ice.turn_tls", &v) == GN_OK) {
        const bool b = (v != 0);
        apply_to_all_turns([&](TurnConfig& t) { t.tls_transport = b; });
    }

    std::lock_guard lk(cfg_mu_);
    cfg_ = std::move(cfg);
}

void IceLink::set_host_api(const host_api_t* api) noexcept {
    if (api_ != nullptr && api_->unsubscribe != nullptr
        && reload_sub_id_ != 0) {
        (void)api_->unsubscribe(api_->host_ctx, reload_sub_id_);
        reload_sub_id_ = 0;
    }

    api_ = api;
    apply_config();

    /// Resolve UDP carrier when the host exposes `gn.link.udp`. The
    /// session and TurnClient drive I/O through this carrier rather
    /// than inline asio sockets. Tests that lack a UDP provider in
    /// their host_api stub simply get `nullopt`; the legacy path
    /// stays unchanged.
    if (api_ != nullptr && !carrier_udp_) {
        carrier_udp_ = gn::sdk::LinkCarrier::query(api_, "udp");
    }
    /// TCP carrier — required only when `cfg_.turn.tcp_transport` is
    /// set. Query is unconditional because the operator can toggle
    /// the config at runtime; missing TCP plugin silently leaves
    /// `carrier_tcp_` empty and gather_relay falls back to UDP.
    if (api_ != nullptr && !carrier_tcp_) {
        carrier_tcp_ = gn::sdk::LinkCarrier::query(api_, "tcp");
    }
    if (api_ != nullptr && !carrier_tls_) {
        carrier_tls_ = gn::sdk::LinkCarrier::query(api_, "tls");
    }

    /// Reaper rides `weak_from_this()`; first `set_host_api` is the
    /// earliest point at which the enclosing `make_shared` has
    /// guaranteed the weak-ptr machinery, so the boot is staged here
    /// rather than in the constructor.
    if (!reaper_started_) {
        reaper_started_ = true;
        start_reaper();
    }

    if (api_ != nullptr && api_->subscribe_config_reload != nullptr) {
        gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
        const auto rc = api_->subscribe_config_reload(
            api_->host_ctx,
            +[](void* user_data) {
                auto* self = static_cast<IceLink*>(user_data);
                self->apply_config();
            },
            this,
            /*ud_destroy*/ nullptr,
            &token);
        if (rc == GN_OK) {
            reload_sub_id_ = token;
        }
    }
}

std::size_t IceLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

IceLink::Stats IceLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t IceLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_DATAGRAM;
    c.max_payload = kDefaultMtu;
    return c;
}

bool IceLink::parse_peer_pk_hex(std::string_view hex,
                                  std::uint8_t out[GN_PUBLIC_KEY_BYTES]) {
    if (hex.size() != GN_PUBLIC_KEY_BYTES * 2) return false;
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        const auto a = hex[i * 2];
        const auto b = hex[i * 2 + 1];
        const auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        const auto hi = digit(a);
        const auto lo = digit(b);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string IceLink::pk_to_hex(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(GN_PUBLIC_KEY_BYTES * 2, '0');
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        out[i * 2]     = digits[pk[i] >> 4];
        out[i * 2 + 1] = digits[pk[i] & 0x0F];
    }
    return out;
}

IceSessionCallbacks IceLink::make_composer_callbacks(
    gn_conn_id_t cid, const std::string& canonical_uri) {
    auto weak_self = std::weak_ptr<IceLink>(shared_from_this());
    return {
        .on_gathered = [weak_self, cid](const std::string&) {
            (void)cid;
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
        },
        /// Nomination — fire composer accept-bus subscribers so the
        /// L2 (QUIC / DTLS) can install per-cid data subscriptions
        /// and start its own handshake on the nominated pair.
        .on_connected = [weak_self, cid, canonical_uri](
                            const std::string&,
                            const std::string& /*ip*/,
                            std::uint16_t /*port*/) {
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            std::vector<ComposerAcceptSub> snapshot;
            {
                std::lock_guard lk(self->composer_mu_);
                auto it = self->composer_sessions_.find(cid);
                if (it != self->composer_sessions_.end()) {
                    if (it->second.nominated) return;
                    it->second.nominated = true;
                }
                snapshot = self->composer_accept_subs_;
            }
            /// Fire accept callbacks outside the lock so a subscriber
            /// that re-enters `composer_subscribe_data` doesn't
            /// recursively grab `composer_mu_`.
            for (const auto& sub : snapshot) {
                if (sub.cb) sub.cb(sub.user_data, cid, canonical_uri.c_str());
            }
        },
        .on_failed = [weak_self, cid](const std::string&, int /*err*/) {
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            std::lock_guard lk(self->composer_mu_);
            auto it = self->composer_sessions_.find(cid);
            if (it == self->composer_sessions_.end()) return;
            self->composer_peer_to_id_.erase(it->second.peer_pk_hex);
            self->composer_sessions_.erase(it);
        },
        /// Application bytes from the nominated pair route through
        /// the per-cid composer data callback installed by
        /// `composer_subscribe_data`. No kernel `notify_inbound_bytes`
        /// — composer-mode bypasses the kernel inbound path.
        .on_data = [weak_self, cid](const std::string&,
                                     std::span<const std::uint8_t> data) {
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            ::gn_link_data_cb_t cb = nullptr;
            void* user = nullptr;
            {
                std::lock_guard lk(self->composer_mu_);
                auto it = self->composer_sessions_.find(cid);
                if (it == self->composer_sessions_.end()) return;
                cb   = it->second.data_cb;
                user = it->second.data_user;
            }
            if (cb) {
                self->bytes_in_.fetch_add(data.size(),
                                            std::memory_order_relaxed);
                self->frames_in_.fetch_add(1, std::memory_order_relaxed);
                cb(user, cid, data.data(), data.size());
            }
        },
    };
}

IceSessionCallbacks IceLink::make_callbacks(gn_conn_id_t id) {
    auto weak_self = std::weak_ptr<IceLink>(shared_from_this());
    return {
        .on_gathered = [weak_self, id](const std::string&) {
            (void)id;
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
        },
        .on_connected = [weak_self, id](const std::string&,
                                          const std::string& /*ip*/,
                                          std::uint16_t /*port*/) {
            (void)id;
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            /// `notify_connect` already fired when the session was
            /// allocated; nomination is just the path coming online.
        },
        .on_failed = [weak_self, id](const std::string&, int /*err*/) {
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            if (!self->claim_disconnect(id)) return;
            if (self->api_ && self->api_->notify_disconnect) {
                (void)self->api_->notify_disconnect(
                    self->api_->host_ctx, id, GN_ERR_NOT_FOUND);
            }
        },
        .on_data = [weak_self, id](const std::string&,
                                     std::span<const std::uint8_t> data) {
            auto self = weak_self.lock();
            if (!self || self->shutdown_.load(std::memory_order_acquire)) return;
            if (!self->api_ || !self->api_->notify_inbound_bytes) return;
            self->bytes_in_.fetch_add(data.size(), std::memory_order_relaxed);
            self->frames_in_.fetch_add(1, std::memory_order_relaxed);
            (void)self->api_->notify_inbound_bytes(
                self->api_->host_ctx, id, data.data(), data.size());
        },
    };
}

gn_result_t IceLink::listen(std::string_view uri) {
    /// ICE is peer-to-peer; the listen surface is shape-only. Reject
    /// anything that does not parse as `ice://...` so a malformed URI
    /// fails fast instead of silently succeeding.
    if (!uri.starts_with("ice://")) {
        gn_log_warn(api_, "ice: listen reject malformed uri "
                          "(expected ice://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    return GN_OK;
}

gn_result_t IceLink::connect(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    if (!uri.starts_with("ice://")) {
        gn_log_warn(api_, "ice: connect reject malformed uri "
                          "(expected ice://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    auto suffix = uri.substr(6);
    /// Strip a trailing `/` for symmetry with WS / TCP URI shapes.
    if (!suffix.empty() && suffix.back() == '/') {
        suffix.remove_suffix(1);
    }

    std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES] = {};
    if (!parse_peer_pk_hex(suffix, peer_pk)) {
        gn_log_warn(api_, "ice: connect peer-pk hex parse failed "
                          "(suffix len=%zu, expected %d hex chars)",
                    suffix.size(), GN_PUBLIC_KEY_BYTES * 2);
        return GN_ERR_INVALID_ENVELOPE;
    }
    const auto peer_hex = std::string(suffix);

    if (!api_ || !api_->notify_connect) {
        gn_log_warn(api_, "ice: connect host_api missing notify_connect "
                          "slot — kernel not bound?");
        return GN_ERR_NOT_IMPLEMENTED;
    }

    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(sessions_mu_);
        if (auto it = peer_to_id_.find(peer_hex); it != peer_to_id_.end()) {
            return GN_OK;
        }

        const std::string canonical = "ice://" + peer_hex;
        const auto rc = api_->notify_connect(
            api_->host_ctx, peer_pk, canonical.c_str(),
            GN_TRUST_UNTRUSTED, GN_ROLE_INITIATOR, &conn);
        if (rc != GN_OK || conn == GN_INVALID_ID) return rc;

        IceConfig cfg_snap;
        {
            std::lock_guard cfg_lk(cfg_mu_);
            cfg_snap = cfg_;
        }
        gn::sdk::LinkCarrier* carrier_ptr =
            carrier_udp_.has_value() ? &*carrier_udp_ : nullptr;
        gn::sdk::LinkCarrier* carrier_tcp_ptr =
            carrier_tcp_.has_value() ? &*carrier_tcp_ : nullptr;
        gn::sdk::LinkCarrier* carrier_tls_ptr =
            carrier_tls_.has_value() ? &*carrier_tls_ : nullptr;
        auto session = std::make_shared<IceSession>(
            ioc_, carrier_ptr, carrier_tcp_ptr, carrier_tls_ptr, cfg_snap, peer_hex,
            /*controlling=*/true, make_callbacks(conn));
        sessions_[conn] = {conn, session, peer_hex};
        peer_to_id_[peer_hex] = conn;
        published_ids_.push_back(conn);

        asio::post(ioc_, [session] { session->gather(); });
    }

    if (api_->kick_handshake) {
        (void)api_->kick_handshake(api_->host_ctx, conn);
    }
    return GN_OK;
}

gn_result_t IceLink::send(gn_conn_id_t conn,
                            std::span<const std::uint8_t> bytes) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    if (bytes.size() > mtu_.load(std::memory_order_relaxed)) {
        gn_log_warn(api_, "ice: send conn=%llu payload=%zu exceeds "
                          "mtu=%u",
                    static_cast<unsigned long long>(conn),
                    bytes.size(),
                    mtu_.load(std::memory_order_relaxed));
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }
    std::shared_ptr<IceSession> session;
    if (conn & kComposerIdBit) {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(conn);
        if (it == composer_sessions_.end()) {
            gn_log_warn(api_, "ice: composer send conn=%llu not found",
                        static_cast<unsigned long long>(conn));
            return GN_ERR_NOT_FOUND;
        }
        session = it->second.session;
    } else {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) {
            gn_log_warn(api_, "ice: send conn=%llu not found "
                              "(disconnected or never allocated)",
                        static_cast<unsigned long long>(conn));
            return GN_ERR_NOT_FOUND;
        }
        session = it->second.session;
    }
    session->send(bytes);
    bytes_out_.fetch_add(bytes.size(), std::memory_order_relaxed);
    frames_out_.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

gn_result_t IceLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    /// Datagram link semantics: pre-validate all frames against MTU
    /// up front so a partial batch never hits the wire when one
    /// frame is malformed.
    const auto cap = mtu_.load(std::memory_order_relaxed);
    for (const auto& f : frames) {
        if (f.size() > cap) return GN_ERR_PAYLOAD_TOO_LARGE;
    }
    for (const auto& f : frames) {
        if (const auto rc = send(conn, f); rc != GN_OK) return rc;
    }
    return GN_OK;
}

gn_result_t IceLink::disconnect(gn_conn_id_t conn) {
    std::shared_ptr<IceSession> session;
    /// Composer-bit ids never travelled through `notify_connect`, so
    /// `notify_disconnect` is omitted on this path — the L2 owns the
    /// composer conn lifecycle.
    if (conn & kComposerIdBit) {
        std::lock_guard lk(composer_mu_);
        auto it = composer_sessions_.find(conn);
        if (it == composer_sessions_.end()) return GN_OK;
        session = it->second.session;
        composer_peer_to_id_.erase(it->second.peer_pk_hex);
        composer_sessions_.erase(it);
        if (session) session->close();
        return GN_OK;
    }

    bool erased = false;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;
        session = it->second.session;
        peer_to_id_.erase(it->second.peer_pk_hex);
        sessions_.erase(it);
        erased = true;
    }
    if (session) session->close();
    if (erased && api_ && api_->notify_disconnect) {
        (void)api_->notify_disconnect(api_->host_ctx, conn, GN_OK);
    }
    return GN_OK;
}

bool IceLink::claim_disconnect(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return false;
    peer_to_id_.erase(it->second.peer_pk_hex);
    sessions_.erase(it);
    return true;
}

NominationMetrics IceLink::nomination_metrics(
    gn_conn_id_t conn) const noexcept {
    std::shared_ptr<IceSession> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return NominationMetrics{};
        session = it->second.session;
    }
    if (!session) return NominationMetrics{};
    return session->nomination_metrics();
}

gn_result_t IceLink::restart_session(gn_conn_id_t conn) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;
    std::shared_ptr<IceSession> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_ERR_NOT_FOUND;
        session = it->second.session;
    }
    if (!session) return GN_ERR_NOT_FOUND;
    session->restart();
    return GN_OK;
}

gn_result_t IceLink::deliver_signal(
    const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
    std::uint8_t kind,
    std::span<const std::uint8_t> blob) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    /// RFC 8838 §10 end-of-candidates variants (`OFFER_EOC` /
    /// `ANSWER_EOC`) are wire-identical to their non-EOC counterparts;
    /// the difference is a sticky flag we forward into the session.
    const bool eoc = (kind == ICE_SIGNAL_OFFER_EOC
                       || kind == ICE_SIGNAL_ANSWER_EOC);
    const bool is_offer = (kind == ICE_SIGNAL_OFFER
                            || kind == ICE_SIGNAL_OFFER_EOC);
    const bool is_answer = (kind == ICE_SIGNAL_ANSWER
                             || kind == ICE_SIGNAL_ANSWER_EOC);
    if (!is_offer && !is_answer) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (blob.size() < sizeof(IceSignalData)) return GN_ERR_INVALID_ENVELOPE;

    IceSignalData hdr{};
    std::vector<Candidate> candidates;
    if (!deserialize_signal(blob, hdr, candidates)) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    std::string ufrag(hdr.ufrag, ::strnlen(hdr.ufrag, sizeof(hdr.ufrag)));
    std::string pwd(hdr.pwd, ::strnlen(hdr.pwd, sizeof(hdr.pwd)));

    const auto peer_hex = pk_to_hex(peer_pk);

    if (is_offer) {
        if (!api_ || !api_->notify_connect) return GN_ERR_NOT_IMPLEMENTED;
        gn_conn_id_t conn = GN_INVALID_ID;
        std::shared_ptr<IceSession> session;
        {
            std::lock_guard lk(sessions_mu_);
            if (auto it = peer_to_id_.find(peer_hex); it != peer_to_id_.end()) {
                /// Already gathering / checking against this peer —
                /// fold the freshly arrived candidates into the
                /// existing session.
                auto sit = sessions_.find(it->second);
                if (sit != sessions_.end()) {
                    session = sit->second.session;
                }
            } else {
                const std::string canonical = "ice://" + peer_hex;
                const auto rc = api_->notify_connect(
                    api_->host_ctx, peer_pk, canonical.c_str(),
                    GN_TRUST_UNTRUSTED, GN_ROLE_RESPONDER, &conn);
                if (rc != GN_OK || conn == GN_INVALID_ID) return rc;

                IceConfig cfg_snap;
                {
                    std::lock_guard cfg_lk(cfg_mu_);
                    cfg_snap = cfg_;
                }
                gn::sdk::LinkCarrier* carrier_ptr =
                    carrier_udp_.has_value() ? &*carrier_udp_ : nullptr;
                gn::sdk::LinkCarrier* carrier_tcp_ptr =
                    carrier_tcp_.has_value() ? &*carrier_tcp_ : nullptr;
                gn::sdk::LinkCarrier* carrier_tls_ptr =
                    carrier_tls_.has_value() ? &*carrier_tls_ : nullptr;
                session = std::make_shared<IceSession>(
                    ioc_, carrier_ptr, carrier_tcp_ptr, carrier_tls_ptr, cfg_snap, peer_hex,
                    /*controlling=*/false,
                    make_callbacks(conn));
                sessions_[conn] = {conn, session, peer_hex};
                peer_to_id_[peer_hex] = conn;
                published_ids_.push_back(conn);
            }
        }
        if (session) {
            /// Trickle ICE (RFC 8838): first OFFER allocates the session
            /// and kicks the local gather; subsequent OFFER blobs for
            /// the same peer just merge incremental candidates without
            /// resetting in-flight checks. The merge logic inside
            /// `add_remote_candidates` is idempotent on duplicate input
            /// and falls through into `build_check_list` once we have
            /// both sides' candidate sets.
            const bool fresh_session = (conn != GN_INVALID_ID);
            asio::post(ioc_,
                [session, fresh_session, eoc,
                 ufrag = std::move(ufrag),
                 pwd = std::move(pwd),
                 cands = std::move(candidates)]() mutable {
                    session->add_remote_candidates(
                        ufrag, pwd, std::move(cands), eoc);
                    if (fresh_session) session->gather();
                });
        }
        return GN_OK;
    }

    /// ANSWER path — must correlate to an existing controller-role
    /// session. A stray answer with no in-flight session is
    /// `GN_ERR_NOT_FOUND` rather than spawning a fresh responder.
    std::shared_ptr<IceSession> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = peer_to_id_.find(peer_hex);
        if (it == peer_to_id_.end()) return GN_ERR_NOT_FOUND;
        auto sit = sessions_.find(it->second);
        if (sit == sessions_.end()) return GN_ERR_NOT_FOUND;
        session = sit->second.session;
    }
    if (session) {
        /// Trickle-friendly: ANSWER blobs merge into the existing
        /// remote candidate set rather than overwriting. Subsequent
        /// trickle candidates from the responder ride the same path.
        asio::post(ioc_,
            [session, eoc,
             ufrag = std::move(ufrag),
             pwd = std::move(pwd),
             cands = std::move(candidates)]() mutable {
                session->add_remote_candidates(
                    ufrag, pwd, std::move(cands), eoc);
            });
    }
    return GN_OK;
}

void IceLink::start_reaper() {
    reaper_timer_.expires_after(std::chrono::seconds(kReaperIntervalSeconds));
    reaper_timer_.async_wait([weak = std::weak_ptr<IceLink>(shared_from_this())](
                                  const std::error_code& ec) {
        auto self = weak.lock();
        if (!self) return;
        if (ec) return;
        if (self->shutdown_.load(std::memory_order_acquire)) return;
        self->reap_sessions();
        self->start_reaper();
    });
}

void IceLink::reap_sessions() {
    auto now = std::chrono::steady_clock::now();
    auto idle_limit = std::chrono::seconds(kIdleSessionLimitSeconds);

    std::vector<gn_conn_id_t> to_drop;
    {
        std::lock_guard lk(sessions_mu_);
        for (auto& [id, entry] : sessions_) {
            if (entry.session->state() != SessionState::Connected
                && now - entry.session->last_activity() > idle_limit) {
                to_drop.push_back(id);
            }
        }
    }
    for (const auto id : to_drop) {
        (void)disconnect(id);
    }
}

gn_result_t IceLink::composer_listen(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    if (!uri.starts_with("ice://")) {
        gn_log_warn(api_, "ice: composer_listen reject malformed uri "
                          "(expected ice://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    return GN_OK;
}

gn_result_t IceLink::composer_connect(std::string_view uri,
                                          gn_conn_id_t* out_conn) {
    if (!out_conn) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    if (!uri.starts_with("ice://")) {
        gn_log_warn(api_, "ice: composer_connect reject malformed uri "
                          "(expected ice://, got %.*s)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    auto suffix = uri.substr(6);
    if (!suffix.empty() && suffix.back() == '/') {
        suffix.remove_suffix(1);
    }
    std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES] = {};
    if (!parse_peer_pk_hex(suffix, peer_pk)) {
        gn_log_warn(api_, "ice: composer_connect peer-pk hex parse "
                          "failed (suffix len=%zu)",
                    suffix.size());
        return GN_ERR_INVALID_ENVELOPE;
    }
    const auto peer_hex = std::string(suffix);
    const auto canonical = "ice://" + peer_hex;

    /// Composer-owned conn ids carry bit 63 so subsequent `send` /
    /// `disconnect` dispatch routes to `composer_sessions_` without
    /// scanning both maps.
    const gn_conn_id_t cid =
        next_composer_id_.fetch_add(1, std::memory_order_acq_rel)
        | kComposerIdBit;

    std::shared_ptr<IceSession> session;
    {
        std::lock_guard lk(composer_mu_);
        if (auto it = composer_peer_to_id_.find(peer_hex);
            it != composer_peer_to_id_.end()) {
            *out_conn = it->second;
            return GN_OK;
        }

        IceConfig cfg_snap;
        {
            std::lock_guard cfg_lk(cfg_mu_);
            cfg_snap = cfg_;
        }
        gn::sdk::LinkCarrier* carrier_ptr =
            carrier_udp_.has_value() ? &*carrier_udp_ : nullptr;
        gn::sdk::LinkCarrier* carrier_tcp_ptr =
            carrier_tcp_.has_value() ? &*carrier_tcp_ : nullptr;
        gn::sdk::LinkCarrier* carrier_tls_ptr =
            carrier_tls_.has_value() ? &*carrier_tls_ : nullptr;
        session = std::make_shared<IceSession>(
            ioc_, carrier_ptr, carrier_tcp_ptr, carrier_tls_ptr, cfg_snap, peer_hex,
            /*controlling=*/true,
            make_composer_callbacks(cid, canonical));

        ComposerEntry entry{};
        entry.session       = session;
        entry.peer_pk_hex   = peer_hex;
        entry.canonical_uri = canonical;
        composer_sessions_[cid]      = std::move(entry);
        composer_peer_to_id_[peer_hex] = cid;
    }

    asio::post(ioc_, [session] { session->gather(); });
    *out_conn = cid;
    return GN_OK;
}

gn_result_t IceLink::composer_subscribe_data(gn_conn_id_t conn,
                                                  ::gn_link_data_cb_t cb,
                                                  void* user_data) {
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::lock_guard lk(composer_mu_);
    auto it = composer_sessions_.find(conn);
    if (it == composer_sessions_.end()) return GN_ERR_NOT_FOUND;
    it->second.data_cb   = cb;
    it->second.data_user = user_data;
    return GN_OK;
}

gn_result_t IceLink::composer_unsubscribe_data(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::lock_guard lk(composer_mu_);
    auto it = composer_sessions_.find(conn);
    if (it == composer_sessions_.end()) return GN_OK;
    it->second.data_cb   = nullptr;
    it->second.data_user = nullptr;
    return GN_OK;
}

gn_result_t IceLink::composer_subscribe_accept(
    ::gn_link_accept_cb_t cb, void* user_data,
    gn_subscription_id_t* out_token) {
    if (!out_token || !cb) return GN_ERR_NULL_ARG;
    const auto token =
        next_accept_token_.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard lk(composer_mu_);
    composer_accept_subs_.push_back({token, cb, user_data});
    *out_token = token;
    return GN_OK;
}

gn_result_t IceLink::composer_unsubscribe_accept(
    gn_subscription_id_t token) {
    std::lock_guard lk(composer_mu_);
    auto it = std::find_if(
        composer_accept_subs_.begin(), composer_accept_subs_.end(),
        [token](const ComposerAcceptSub& s) { return s.token == token; });
    if (it == composer_accept_subs_.end()) return GN_OK;
    composer_accept_subs_.erase(it);
    return GN_OK;
}

gn_result_t IceLink::composer_listen_port(
    std::uint16_t* out_port) const noexcept {
    if (!out_port) return GN_ERR_NULL_ARG;
    *out_port = carrier_udp_.has_value() ? carrier_udp_->listen_port() : 0;
    return GN_OK;
}

void IceLink::shutdown() {
    /// Cancel the reaper before we invalidate `weak_from_this()` —
    /// the timer's bound shared_ptr captures the link, not the kernel,
    /// so a fired-while-quiescing handler is benign but wasteful.
    /// Standalone Asio's cancel() returns `size_t` (handlers cancelled)
    /// without an error_code overload — the call cannot fail in a way
    /// the caller can act on, so the value is discarded.
    (void)reaper_timer_.cancel();

    std::vector<gn_conn_id_t> ids_to_emit;
    std::vector<std::shared_ptr<IceSession>> live_sessions;
    {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;
        ids_to_emit = std::move(published_ids_);
        published_ids_.clear();
        live_sessions.reserve(sessions_.size());
        for (auto& [_id, entry] : sessions_) {
            live_sessions.push_back(entry.session);
        }
        sessions_.clear();
        peer_to_id_.clear();
    }
    {
        std::lock_guard lk(composer_mu_);
        live_sessions.reserve(live_sessions.size() + composer_sessions_.size());
        for (auto& [_id, entry] : composer_sessions_) {
            live_sessions.push_back(entry.session);
        }
        composer_sessions_.clear();
        composer_peer_to_id_.clear();
        composer_accept_subs_.clear();
    }
    for (auto& s : live_sessions) {
        if (s) s->close();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : ids_to_emit) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

}  // namespace gn::link::ice
