// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/session.cpp
/// @brief  ICE session FSM implementation per RFC 8445.
///
/// Threading model:
/// - Every state mutation runs on `strand_` (or during the synchronous
///   prefix of `gather()` before any strand work has been posted).
/// - `nominated_mu_` guards the nominated-pair tuple so the hot send
///   path can sample without bouncing off the strand.
/// - `close()` is safe from any thread; it drops carrier subscriptions
///   and cancels timers without touching FSM state on the strand.
///
/// I/O routes through `carrier_` (a borrowed `gn::sdk::LinkCarrier*`
/// resolved by the parent `IceLink`). Each remote endpoint we talk to
/// gets its own carrier conn id via `ensure_remote_cid`; the per-cid
/// `on_data` callback drives `on_carrier_data` which feeds the STUN
/// parsing path.

#include "session.hpp"
#include "dbg.hpp"

#include <asio/bind_executor.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>

#include <sdk/cpp/uri.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium/randombytes.h>

namespace gn::link::ice {

namespace {

std::string endpoint_key(const std::string& ip, uint16_t port) {
    return ip + ":" + std::to_string(port);
}

std::string endpoint_uri(const std::string& ip, uint16_t port) {
    return "udp://" + ip + ":" + std::to_string(port);
}

std::string endpoint_uri_tcp(const std::string& ip, uint16_t port) {
    return "tcp://" + ip + ":" + std::to_string(port);
}

/// Split a `cfg_.stun_servers` entry (always bare `host:port` per the
/// `link_ice.cpp` normalisation pipeline; see `push_stun`) into its
/// host + port halves through the SDK's canonical URI parser. Prepends
/// `stun://` so `gn::parse_uri` (sdk/cpp/uri.hpp) handles the
/// `host:port` split, port-range, and trailing-garbage rejection.
/// Symmetric with `parse_service_uri` (dns_ext_client.cpp) — same
/// parser for every form of STUN-server input.
///
/// When the entry carries no `:` at all, fall back to the historic
/// default-port behaviour (`3478`, RFC 5389 §9) so an operator that
/// configured only a hostname still gets a working probe.
///
/// Returns nullopt on every failure the SDK parser rejects: empty
/// host, malformed port, port > 65535, trailing garbage, control
/// bytes. Callers `continue` past such entries.
std::optional<std::pair<std::string, std::uint16_t>>
split_stun_host_port(std::string_view server) {
    if (server.empty()) return std::nullopt;
    if (server.find(':') == std::string_view::npos) {
        return std::make_pair(std::string(server),
                              static_cast<std::uint16_t>(3478));
    }
    std::string canonical;
    canonical.reserve(7 + server.size());
    canonical.append("stun://").append(server);
    const auto parts = gn::parse_uri(canonical);
    if (!parts || parts->host.empty() || parts->port == 0) {
        return std::nullopt;
    }
    return std::make_pair(parts->host, parts->port);
}

}  // namespace

static std::string random_string(size_t len) {
    static constexpr char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    static constexpr uint32_t nchars = sizeof(chars) - 1;
    std::string out(len, '\0');
    for (size_t i = 0; i < len; ++i)
        out[i] = chars[randombytes_uniform(nchars)];
    return out;
}

std::string IceSession::generate_ufrag() { return random_string(8); }
std::string IceSession::generate_pwd()   { return random_string(24); }

IceSession::IceSession(asio::io_context& io,
                         gn::sdk::LinkCarrier* carrier,
                         gn::sdk::LinkCarrier* carrier_tcp,
                         gn::sdk::LinkCarrier* carrier_tls,
                         const IceConfig& cfg,
                         const std::string& peer_id, bool controlling,
                         IceSessionCallbacks callbacks,
                         std::shared_ptr<MdnsManager> mdns,
                         IcePortmapClient* portmap_ext)
    : io_(io), strand_(asio::make_strand(io.get_executor())),
      carrier_(carrier), carrier_tcp_(carrier_tcp),
      carrier_tls_(carrier_tls),
      portmap_ext_(portmap_ext), cfg_(cfg),
      peer_id_(peer_id),
      controlling_(cfg.lite_mode ? false : controlling),
      callbacks_(std::move(callbacks)),
      check_timer_(strand_),
      gather_timer_(strand_),
      keepalive_timer_(strand_),
      turn_allocate_timer_(strand_),
      turn_backup_timer_(strand_),
      mdns_(std::move(mdns)),
      last_activity_(std::chrono::steady_clock::now()),
      pmtu_probe_timer_(strand_) {
    /// Constructor: no observers exist yet, so the mutex isn't
    /// strictly required, but locking keeps the publication pattern
    /// uniform and lets TSan reason about all writes through the
    /// same edge as the public accessors.
    std::lock_guard lk(local_state_mu_);
    local_ufrag_ = generate_ufrag();
    local_pwd_   = generate_pwd();

    randombytes_buf(&tiebreaker_, sizeof(tiebreaker_));

    /// Seed the effective MTU with the conservative configured floor.
    /// Active probing replaces this on the first successful ACK once
    /// the FSM reaches `Connected`.
    effective_mtu_.store(static_cast<std::uint32_t>(cfg_.path_mtu),
                          std::memory_order_release);
}

IceSession::~IceSession() {
    /// Strand-bound work has already been cancelled by `close()` in
    /// the typical teardown path. The dtor's only remaining duty is
    /// to release per-cid carrier subscriptions; the carrier itself
    /// outlives the session (owned by IceLink) so the unsubscribe
    /// calls are safe even if the session is being unwound after the
    /// io_context has stopped.
    state_.store(SessionState::Failed, std::memory_order_release);
    std::error_code ec;
    check_timer_.cancel();
    keepalive_timer_.cancel();
    gather_timer_.cancel();
    turn_allocate_timer_.cancel();
    turn_backup_timer_.cancel();
    pmtu_probe_timer_.cancel();
    if (turn_) turn_->close();
    if (turn_backup_probe_) turn_backup_probe_->close();
    if (mdns_ && !mdns_local_hostname_.empty()) {
        mdns_->unregister_name(mdns_local_hostname_);
        mdns_local_hostname_.clear();
    }
    /// Best-effort portmap release. Matches the TURN-deallocation
    /// pattern above: ignore failure since the router will time the
    /// mapping out on its own once `lifetime_s` elapses without a
    /// renewal.
    release_portmap_mapping();
    for (auto& [cid, ep] : cid_to_endpoint_udp_) {
        if (!carrier_) continue;
        (void)carrier_->unsubscribe_data(cid);
        (void)carrier_->disconnect(cid);
    }
    for (auto& [cid, ep] : cid_to_endpoint_tcp_) {
        if (!carrier_tcp_) continue;
        (void)carrier_tcp_->unsubscribe_data(cid);
        (void)carrier_tcp_->disconnect(cid);
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

void IceSession::gather() {
    ICE_DBG("gather", "peer=%s controlling=%d stun_srvs=%zu",
            peer_id_.c_str(), controlling_ ? 1 : 0,
            cfg_.stun_servers.size());
    /// Synchronous prefix runs on the caller before any strand work is
    /// posted, so direct `local_candidates_` mutation is race-free.
    state_.store(SessionState::Gathering, std::memory_order_release);
    gather_host_candidates();
    ICE_DBG("gather", "peer=%s after host_gather local_cands=%zu",
            peer_id_.c_str(), local_candidates_.size());

    /// Optional NAT mapping via the `gn.link.portmap` extension. Runs
    /// after host gather so `local_port_` is known. The portmap
    /// extension is synchronous (request returns the mapping or
    /// fails); the srflx candidate is pushed inline and ready before
    /// the FSM moves on to TURN / STUN. Missing extension or
    /// zero-protocol mask is a transparent no-op.
    gather_portmap();

    /// TURN allocation runs in parallel with STUN; the relay candidate
    /// arrives via callback once `gn.ice.turn` answers.
    gather_relay();

    if (cfg_.stun_servers.empty()) {
        if (!turn_gathering_) {
            on_gathering_complete();
        }
        /// else: TURN allocation is in flight; it will call
        /// on_gathering_complete() when done (or on its timeout).
    } else {
        asio::post(strand_, [this, self = shared_from_this()] {
            start_multi_stun_probes();
            /// RFC 6544 §4.4 TCP srflx probes ride the same pending
            /// transaction set as UDP probes so a single gather
            /// timeout covers both. No-op when no TCP carrier is
            /// wired or `tcp_candidates_enabled` is false.
            gather_tcp_server_reflexive();
        });
    }
}

void IceSession::set_remote(const std::string& ufrag, const std::string& pwd,
                              std::vector<Candidate> candidates) {
    /// Caller dispatches to the strand; this body assumes single-writer.
    remote_ufrag_ = ufrag;
    remote_pwd_ = pwd;
    remote_candidates_ = std::move(candidates);
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);

    auto cur = state_.load(std::memory_order_acquire);
    if (cur == SessionState::WaitingRemote || cur == SessionState::Gathering) {
        if (!local_candidates_.empty()) {
            state_.store(SessionState::Checking, std::memory_order_release);
            build_check_list();
            begin_checks();
        }
    }

    /// Kick off mDNS resolution for any HostMdns entries the peer
    /// advertised. Resolutions complete asynchronously and fold
    /// resolved IPs back into the check list via the callback path
    /// in `resolve_remote_mdns_candidates`. The pairs built above
    /// against the non-HostMdns subset start checking immediately.
    resolve_remote_mdns_candidates();
}

void IceSession::send(std::span<const uint8_t> data) {
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);

    auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
    ICE_DBG("send-app-enq", "peer=%s len=%zu state=%d",
            peer_id_.c_str(), buf->size(),
            (int)state_.load(std::memory_order_acquire));
    asio::post(strand_, [this, self = shared_from_this(), buf] {
        const auto st = state_.load(std::memory_order_acquire);
        if (st != SessionState::Connected) {
            if (pending_app_data_.size() >= kPendingAppDataMaxFrames) {
                pending_app_data_.pop_front();
            }
            pending_app_data_.push_back(std::move(*buf));
            ICE_DBG("send-app-park", "peer=%s state=%d pending=%zu",
                    peer_id_.c_str(), (int)st, pending_app_data_.size());
            return;
        }
        send_on_strand(*buf);
    });
}

void IceSession::send_on_strand(const std::vector<uint8_t>& buf) {
    std::string ip;
    uint16_t port;
    bool relay;
    {
        std::lock_guard lk(nominated_mu_);
        ip = nominated_ip_;
        port = nominated_port_;
        relay = uses_relay_;
    }

    if (relay && turn_) {
        ICE_DBG("send-app-out", "peer=%s len=%zu dst=%s:%u relay=1",
                peer_id_.c_str(), buf.size(), ip.c_str(), port);
        turn_->send_indication(ip, port, buf);
        return;
    }

    auto cid = nominated_cid_.load(std::memory_order_acquire);
    if (cid == 0) {
        cid = ensure_remote_cid(ip, port);
        if (cid == 0) {
            ICE_DBG("send-app-drop", "peer=%s reason=no-cid dst=%s:%u",
                    peer_id_.c_str(), ip.c_str(), port);
            return;
        }
        nominated_cid_.store(cid, std::memory_order_release);
    }
    const auto tx = nominated_transport_.load(std::memory_order_acquire);
    ICE_DBG("send-app-out", "peer=%s len=%zu dst=%s:%u cid=%llu tcp=%d carrier=%d",
            peer_id_.c_str(), buf.size(), ip.c_str(), port,
            static_cast<unsigned long long>(cid),
            (int)transport_is_tcp(tx),
            (int)(transport_is_tcp(tx) ? (carrier_tcp_ != nullptr) : (carrier_ != nullptr)));
    if (transport_is_tcp(tx)) {
        if (carrier_tcp_) {
            const auto framed = frame_tcp_stun(buf);
            (void)carrier_tcp_->send(cid, framed);
        }
    } else {
        if (carrier_) (void)carrier_->send(cid, buf);
    }
}

void IceSession::flush_pending_app_data() {
    if (!pending_app_data_.empty()) {
        ICE_DBG("flush-app", "peer=%s count=%zu",
                peer_id_.c_str(), pending_app_data_.size());
    }
    while (!pending_app_data_.empty()) {
        auto buf = std::move(pending_app_data_.front());
        pending_app_data_.pop_front();
        send_on_strand(buf);
    }
}

void IceSession::add_remote_candidates(const std::string& ufrag,
                                         const std::string& pwd,
                                         std::vector<Candidate> cands,
                                         bool end_of_candidates) {
    asio::dispatch(strand_, [self = shared_from_this(),
                              ufrag, pwd,
                              cands = std::move(cands),
                              end_of_candidates]() mutable {
        ICE_DBG("add-remote",
                "peer=%s ufrag=%s incoming=%zu eoc=%d existing_remote=%zu",
                self->peer_id_.c_str(), ufrag.c_str(), cands.size(),
                end_of_candidates ? 1 : 0,
                self->remote_candidates_.size());
        for (const auto& c : cands) {
            ICE_DBG("add-remote.cand",
                    "peer=%s type=%d tx=%d %s:%u prio=%u",
                    self->peer_id_.c_str(), static_cast<int>(c.type),
                    static_cast<int>(c.transport),
                    c.address_str().c_str(), c.port, c.priority);
        }
        const bool creds_changed =
            !self->remote_ufrag_.empty() && self->remote_ufrag_ != ufrag;
        if (creds_changed) {
            /// Peer signalled new credentials — RFC 8445 §9 restart on
            /// their side. Drop our cached remote state so the next
            /// build_check_list operates on the fresh set only.
            self->remote_candidates_.clear();
            self->check_list_.clear();
            self->current_check_ = 0;
        }
        self->remote_ufrag_ = ufrag;
        self->remote_pwd_   = pwd;

        /// EOC is sticky once set — even if a later batch arrives
        /// (operator bug, retransmission of trailing trickle frame)
        /// we keep treating the candidate set as complete. Under
        /// regular nomination an EOC arrival speeds up the commit:
        /// the controller no longer waits for a possibly-higher
        /// priority pair to appear later via trickle, and picks the
        /// best valid pair right now.
        if (end_of_candidates) {
            self->remote_end_of_candidates_ = true;
            if (self->controlling_
                && !self->cfg_.aggressive_nomination
                && !self->nominee_selected_) {
                CheckPair* best = nullptr;
                for (auto& p : self->check_list_) {
                    if (p.valid && (!best || p.priority > best->priority)) {
                        best = &p;
                    }
                }
                if (best) {
                    self->nominee_selected_ = true;
                    best->nominee_check_sent = true;
                    self->send_check(*best);
                }
            }
        }

        /// Merge each new candidate, deduping by (ip, port, type,
        /// transport). The transport key matters: a UDP host
        /// candidate at 10.0.0.1:40000 is a different reachable
        /// endpoint from a TCP-active host candidate at the same
        /// (ip, port) — they ride distinct sockets on both ends,
        /// produce distinct check pairs, and route via
        /// `carrier_udp_` vs `carrier_tcp_`. Without the transport
        /// component a TCP fallback set (RFC 6544) collapses into
        /// a single UDP entry and the FSM never tries the TCP
        /// pairs. Address comparison goes through `address_str()`
        /// to keep IPv4 / IPv6 logic in one place.
        for (auto& c : cands) {
            const auto ip = c.address_str();
            const bool dup = std::any_of(
                self->remote_candidates_.begin(),
                self->remote_candidates_.end(),
                [&](const Candidate& e) {
                    return e.address_str() == ip
                        && e.port == c.port
                        && e.type == c.type
                        && e.transport == c.transport;
                });
            if (!dup) {
                /// Install a TURN CreatePermission entry for the peer
                /// IP before the merge so the relay-local check pair
                /// produced by the next `build_check_list` can fire
                /// SendIndication packets at this peer without the
                /// server dropping them as "no permission". The
                /// TurnClient dedupes via `permissions_`, so duplicate
                /// calls (same IP across multiple candidates) are
                /// harmless. When the allocation isn't up yet the
                /// `on_alloc` callback in `gather_relay` does the
                /// same sweep across the current remote set.
                if (self->turn_ && self->turn_->is_allocated()) {
                    self->turn_->create_permission(ip);
                }
                self->remote_candidates_.push_back(std::move(c));
            }
        }

        const auto cur = self->state_.load(std::memory_order_acquire);
        if (self->remote_candidates_.empty()) return;

        if (cur == SessionState::WaitingRemote ||
            cur == SessionState::Gathering) {
            if (!self->local_candidates_.empty()) {
                /// Trickle ICE: publish the local candidate set the
                /// moment we have one alongside the remote OFFER —
                /// BEFORE state transition + checks. This way the
                /// ANSWER goes out even if begin_checks blocks or
                /// the strand gets tied up with the connectivity
                /// check loop afterwards. srflx candidates trickle
                /// out as later deltas under the same outbound
                /// queue.
                /// Only the responder (controlled agent) emits a signal
                /// here — this produces the ANSWER.  The initiator
                /// (controlling) must NOT re-emit; doing so would send
                /// a second OFFER to the peer and restart their session.
                ///
                /// Send the answer immediately with whatever candidates
                /// are available (host + srflx at minimum).  If a TURN
                /// allocation is still in flight, the relay candidate
                /// will be trickled once on_alloc fires (trickle ICE,
                /// RFC 8838), so the peer's check list gets updated
                /// without blocking the initial answer.
                if (self->callbacks_.on_gathered && !self->controlling_) {
                    self->gathered_signal_fired_ = true;
                    self->callbacks_.on_gathered(self->peer_id_);
                }
                self->state_.store(SessionState::Checking,
                                    std::memory_order_release);
                self->build_check_list();
                self->begin_checks();
            }
            return;
        }

        if (cur == SessionState::Checking) {
            /// Rebuild includes both old pairs (will resend checks —
            /// harmless because txn ids match the freshly generated
            /// ones) and new pairs from the trickle batch. Sorting by
            /// pair priority keeps the highest-quality fresh candidate
            /// at the head of the queue.
            self->build_check_list();
            self->current_check_ = 0;
            self->run_next_check();
        }

        /// Trickle batches may carry fresh HostMdns entries — resolve
        /// them after the immediate build_check_list so non-mDNS
        /// pairs start probing without waiting on resolver latency.
        self->resolve_remote_mdns_candidates();
    });
}

void IceSession::set_peer_signal_flags(std::uint32_t flags) {
    asio::dispatch(strand_, [self = shared_from_this(), flags] {
        const auto prev = self->peer_signal_flags_.exchange(
            flags, std::memory_order_acq_rel);
        const bool symmetric_changed =
            ((prev ^ flags) & ICE_SIGNAL_FLAG_SYMMETRIC) != 0;
        if (symmetric_changed
            && self->state_.load(std::memory_order_acquire)
                 == SessionState::Checking
            && !self->remote_candidates_.empty()
            && !self->local_candidates_.empty()) {
            /// Predicted-port pairs depend on the peer flag; rebuild
            /// the list so the freshly-known stride lands in the
            /// queue.
            self->build_check_list();
            self->current_check_ = 0;
            self->run_next_check();
        }
    });
}

std::uint32_t IceSession::local_signal_flags() const noexcept {
    std::uint32_t f = 0;
    if (cfg_.lite_mode) f |= ICE_SIGNAL_FLAG_LITE;
    if (symmetric_stride_.load(std::memory_order_acquire) != 0) {
        f |= ICE_SIGNAL_FLAG_SYMMETRIC;
    }
    return f;
}

void IceSession::restart() {
    /// All state mutations are serialised on the strand; the call site
    /// usually arrives off-strand from the operator or kernel thread.
    asio::dispatch(strand_, [self = shared_from_this()] {
        auto cur = self->state_.load(std::memory_order_acquire);
        if (cur == SessionState::Failed) return;

        /// Cancel all in-flight timers + drop pending state. The
        /// keepalive on a Connected session also stops because it
        /// short-circuits on state != Connected.
        self->check_timer_.cancel();
        self->keepalive_timer_.cancel();
        self->gather_timer_.cancel();
        self->turn_allocate_timer_.cancel();
        self->turn_backup_timer_.cancel();
        if (self->turn_) self->turn_->close();
        if (self->turn_backup_probe_) self->turn_backup_probe_->close();
        self->turn_.reset();
        self->turn_backup_probe_.reset();
        self->turn_backups_.clear();
        self->turn_attempt_idx_ = 0;
        self->turn_backup_probe_idx_ = 0;
        self->turn_last_failover_ = std::chrono::steady_clock::time_point{};

        {
            /// Publish credential + candidate-set wipe to off-strand
            /// readers (`local_ufrag()`, `local_pwd()`,
            /// `local_candidates()`).
            std::lock_guard lk(self->local_state_mu_);
            self->local_ufrag_ = IceSession::generate_ufrag();
            self->local_pwd_   = IceSession::generate_pwd();
            self->local_candidates_.clear();
        }

        /// Drop the previous mDNS registration so the post-restart
        /// gather can mint a fresh `<uuid>.local` per the draft.
        /// The new gather phase calls `register_name` again under
        /// `gather_host_candidates`.
        if (self->mdns_ && !self->mdns_local_hostname_.empty()) {
            self->mdns_->unregister_name(self->mdns_local_hostname_);
            self->mdns_local_hostname_.clear();
        }

        self->remote_candidates_.clear();
        self->remote_ufrag_.clear();
        self->remote_pwd_.clear();
        self->check_list_.clear();
        self->pending_stun_probes_.clear();
        self->current_check_ = 0;
        self->consent_missed_.store(0, std::memory_order_release);
        self->consent_recovery_attempts_ = 0;
        self->nominee_selected_ = false;
        self->remote_end_of_candidates_ = false;
        self->gathered_signal_fired_ = false;
        self->stun_gathered_  = false;
        self->turn_gathering_ = false;
        self->nominated_cid_.store(0, std::memory_order_release);
        self->peer_signal_flags_.store(0, std::memory_order_release);
        self->symmetric_stride_.store(0, std::memory_order_release);
        self->first_observed_srflx_port_ = 0;
        self->have_first_srflx_port_     = false;
        {
            std::lock_guard lk(self->nominated_mu_);
            self->nominated_ip_.clear();
            self->nominated_port_ = 0;
            self->uses_relay_     = false;
        }

        /// Drop carrier conn ids accumulated during the previous
        /// gather/check phases. The local listen port (shared with
        /// IceLink's other sessions) stays bound — only the per-peer
        /// mappings are torn down so the next gather negotiates fresh
        /// composer_connect's for the new candidate set.
        for (auto& [cid, t] : self->tcp_connect_timers_) {
            if (t) t->cancel();
        }
        self->tcp_connect_timers_.clear();
        for (auto& [cid, ep] : self->cid_to_endpoint_udp_) {
            if (!self->carrier_) continue;
            (void)self->carrier_->unsubscribe_data(cid);
            (void)self->carrier_->disconnect(cid);
        }
        for (auto& [cid, ep] : self->cid_to_endpoint_tcp_) {
            if (!self->carrier_tcp_) continue;
            (void)self->carrier_tcp_->unsubscribe_data(cid);
            (void)self->carrier_tcp_->disconnect(cid);
        }
        self->endpoint_to_cid_.clear();
        self->cid_to_endpoint_udp_.clear();
        self->cid_to_endpoint_tcp_.clear();
        self->tcp_rx_buffers_.clear();
        self->carrier_initialized_ = false;
        self->local_port_ = 0;

        self->state_.store(SessionState::New, std::memory_order_release);
        self->gather();
    });
}

void IceSession::close() {
    /// Mark the FSM dead synchronously so concurrent `send` calls
    /// stop touching the carrier immediately. The actual subscription
    /// teardown runs on the strand to avoid racing the carrier
    /// dispatcher with our own unsubscribe call.
    state_.store(SessionState::Failed, std::memory_order_release);
    asio::dispatch(strand_, [self = shared_from_this()] {
        self->check_timer_.cancel();
        self->keepalive_timer_.cancel();
        self->gather_timer_.cancel();
        self->turn_allocate_timer_.cancel();
        self->turn_backup_timer_.cancel();
        if (self->turn_) self->turn_->close();
        if (self->turn_backup_probe_) self->turn_backup_probe_->close();
        if (self->mdns_ && !self->mdns_local_hostname_.empty()) {
            self->mdns_->unregister_name(self->mdns_local_hostname_);
            self->mdns_local_hostname_.clear();
        }
        /// Tear down any portmap mapping we punched during gather so
        /// the router reclaims the external port the moment we go
        /// away. Mirrors the TURN deallocation above — best-effort,
        /// the renewal table inside the portmap plugin clears even
        /// when the router's reply never arrives.
        self->release_portmap_mapping();
        for (auto& [cid, t] : self->tcp_connect_timers_) {
            if (t) t->cancel();
        }
        self->tcp_connect_timers_.clear();
        for (auto& [cid, ep] : self->cid_to_endpoint_udp_) {
            if (!self->carrier_) continue;
            (void)self->carrier_->unsubscribe_data(cid);
            (void)self->carrier_->disconnect(cid);
        }
        for (auto& [cid, ep] : self->cid_to_endpoint_tcp_) {
            if (!self->carrier_tcp_) continue;
            (void)self->carrier_tcp_->unsubscribe_data(cid);
            (void)self->carrier_tcp_->disconnect(cid);
        }
        self->endpoint_to_cid_.clear();
        self->cid_to_endpoint_udp_.clear();
        self->cid_to_endpoint_tcp_.clear();
        self->tcp_rx_buffers_.clear();
        self->nominated_cid_.store(0, std::memory_order_release);
    });
}

// ── Gathering (strand or synchronous) ───────────────────────────────────────

void IceSession::gather_host_candidates() {
    /// The shared UDP carrier is bound lazily on the first session
    /// that needs it; subsequent sessions on the same `IceLink` just
    /// learn the existing local port. A missing carrier (test stub
    /// without `gn.link.udp`) leaves us with port 0 and zero host
    /// candidates — gather still completes, the FSM just transitions
    /// straight to WaitingRemote with nothing to advertise.
    if (carrier_ && !carrier_initialized_) {
        (void)carrier_->listen("udp://0.0.0.0:0");
        local_port_ = carrier_->listen_port();
        carrier_initialized_ = true;
    }
    if (local_port_ == 0) return;

    /// draft-ietf-mmusic-mdns-ice-candidates §3.1: when host
    /// obfuscation is enabled, the link advertises a SINGLE
    /// `<uuid>.local` per session (the IP family on the wire is
    /// IPv4 by convention — peers don't try to match on family for
    /// HostMdns candidates, the resolver fans out to whatever A /
    /// AAAA records the responder returns). The mDNS manager
    /// records the name → local-IP mapping; remote peers query for
    /// the name and discover the IP only if they're on the same
    /// LAN segment.
    const bool obfuscate = cfg_.mdns_obfuscate_host_candidates
                            && mdns_ != nullptr;
    if (obfuscate) {
        mdns_local_hostname_ = generate_uuid_v4() + ".local";
        mdns_->register_name(mdns_local_hostname_);

        Candidate c{};
        c.type     = CandidateType::HostMdns;
        c.family   = AddressFamily::IPv4;
        c.port     = local_port_;
        c.priority = compute_priority(CandidateType::HostMdns, 65535, 1);
        c.hostname = mdns_local_hostname_;
        if (candidate_allowed(CandidateType::Host, c.family,
                               cfg_.candidate_filter_flags)) {
            std::lock_guard lk(local_state_mu_);
            local_candidates_.push_back(c);
        }
        /// Skip raw-IP host candidates: the whole point of mDNS
        /// obfuscation is to NOT leak interior addresses. The IPv4
        /// HostMdns above stands in for the entire host candidate
        /// set; the resolver on the peer side discovers v4 + v6 via
        /// the responder's A / AAAA records.
        return;
    }

    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return;

    for (auto* ifa = iflist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        Candidate c{};
        c.type = CandidateType::Host;
        c.port = local_port_;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            c.family = AddressFamily::IPv4;
            std::memcpy(c.addr.data(), &sin->sin_addr, 4);
            c.priority = compute_priority(CandidateType::Host, 65535, 1);
            if (candidate_allowed(c.type, c.family,
                                   cfg_.candidate_filter_flags)) {
                std::lock_guard lk(local_state_mu_);
                local_candidates_.push_back(c);
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) continue;
            c.family = AddressFamily::IPv6;
            std::memcpy(c.addr.data(), &sin6->sin6_addr, 16);
            c.priority = compute_priority(CandidateType::Host, 65534, 1);
            if (candidate_allowed(c.type, c.family,
                                   cfg_.candidate_filter_flags)) {
                std::lock_guard lk(local_state_mu_);
                local_candidates_.push_back(c);
            }
        }
    }
    freeifaddrs(iflist);

    gather_tcp_host_candidates();
}

void IceSession::gather_portmap() {
    /// Skip every short-circuit case the user-facing contract calls
    /// out as a graceful-degradation point.
    if (portmap_ext_ == nullptr)               return;
    if (local_port_ == 0)                       return;
    /// Honour the same operator filter mask that gates host / srflx
    /// / relay gather. Portmap candidates are emitted with type
    /// `Srflx`, so a `host-only` filter drops them; a `relay-only`
    /// filter also drops them. The `exclude-ipv4` flag drops them
    /// because the portmap protocols answer with an IPv4 external
    /// address by convention (PCP supports v6 but the in-tree plugin
    /// currently surfaces v4 mappings only).
    const auto filter = cfg_.candidate_filter_flags;
    if ((filter & kCandidateFilterHostOnly)  != 0) return;
    if ((filter & kCandidateFilterRelayOnly) != 0) return;

    /// Probe the supported-protocols mask first. Zero means no
    /// portmap protocol is reachable from this network — the
    /// extension is present but every probe came back silent. Skip
    /// the request entirely so we don't hammer the underlying
    /// discovery loop on every gather.
    const std::uint32_t supported = portmap_ext_->supported_protocols();
    if ((supported & (GN_PORTMAP_PROTO_UPNP
                        | GN_PORTMAP_PROTO_PCP
                        | GN_PORTMAP_PROTO_NATPMP)) == 0) {
        return;
    }

    /// Ask the router for a UDP mapping with the conventional ICE
    /// hint values: lifetime 3600 s (matches the typical NAT-PMP
    /// default before the plugin's own renewal cadence kicks in),
    /// no external-port hint (let the router pick — symmetric NATs
    /// will refuse a fixed external port and we don't want to bias
    /// the choice).
    gn_portmap_mapping_t mapping{};
    const bool ok = portmap_ext_->request(GN_PORTMAP_UDP,
                                            local_port_,
                                            /*external_port_hint=*/0,
                                            /*lifetime_hint_s=*/3600,
                                            &mapping);
    if (!ok) return;
    /// Defensive parse of the router-reported ext_ip — a malformed
    /// blob (NUL-terminated dotted-decimal that doesn't lex as v4 or
    /// v6) is treated as a failed mapping. The plugin contract says
    /// the field is NUL-terminated; trust but verify.
    if (mapping.ext_port == 0) return;
    const std::string ext_ip(mapping.ext_ip);
    if (ext_ip.empty()) return;

    Candidate c{};
    c.type     = CandidateType::Srflx;
    c.port     = mapping.ext_port;
    c.set_address(ext_ip);
    if (c.family != AddressFamily::IPv4
        && c.family != AddressFamily::IPv6) {
        /// `set_address` leaves `family` unset when the string lexes
        /// as neither v4 nor v6 — drop the mapping rather than push
        /// a garbage candidate. We do NOT call release here: the
        /// underlying plugin still has a valid renewal entry and
        /// will time it out on its own.
        return;
    }
    /// Operator-filter gate (exclude-ipv4 / exclude-ipv6). Run after
    /// the address parse so the family check is authoritative.
    if (!candidate_allowed(c.type, c.family, filter)) {
        return;
    }

    /// Priority — RFC 8445 §5.1.2.1 type-preference 100 for Srflx.
    /// The local-pref slot is set to 65534 (one rung below the
    /// STUN-srflx default of 65535) so STUN-discovered srflx
    /// candidates outrank the portmap entry on identical
    /// (component, type) tuples. Component id stays at 2 — the
    /// (type_pref, local_pref, component) triple gives the portmap
    /// candidate a distinct priority slot so the check-list ordering
    /// is deterministic.
    c.priority = compute_priority(CandidateType::Srflx, 65534, 2);
    /// Foundation — RFC 8445 §5.1.1.3. The synthetic server string
    /// `"portmap"` distinguishes portmap-allocated srflx from
    /// STUN-allocated srflx so the foundation tuple stays unique.
    /// Peers compute their own foundations from the wire-recovered
    /// fields; the foundation is intentionally not on the wire.
    c.foundation = compute_foundation(CandidateType::Srflx,
                                        ext_ip,
                                        /*server=*/"portmap",
                                        c.transport);

    {
        std::lock_guard lk(local_state_mu_);
        local_candidates_.push_back(std::move(c));
    }
    /// Stash the mapping for release on teardown. We track only the
    /// most-recent mapping per session because a gather cycle issues
    /// exactly one portmap request for `local_port_`; an ICE
    /// restart re-runs gather and overwrites the slot after the
    /// previous mapping is released.
    portmap_mapping_ = mapping;
}

void IceSession::release_portmap_mapping() noexcept {
    if (portmap_ext_ == nullptr) return;
    if (!portmap_mapping_.has_value()) return;
    const auto m = *portmap_mapping_;
    portmap_mapping_.reset();
    /// Best-effort — the underlying plugin handles router-side
    /// failure (lifetime expiry, router reboot) on its own.
    (void)portmap_ext_->release(m.protocol, m.int_port);
}

void IceSession::gather_tcp_host_candidates() {
    /// RFC 6544 emits one TCP candidate per interface IP per transport
    /// flavour (active / passive / simultaneous-open). The TCP carrier
    /// is wired separately from UDP; absent carrier means no usable
    /// TCP fallback, so the gather skips the TCP slot entirely. The
    /// candidate filter flags (host-only / relay-only / exclude-ipv4
    /// / exclude-ipv6) reuse the same gate as UDP candidates so an
    /// operator that excludes host candidates also drops the TCP
    /// host slot.
    if (!cfg_.tcp_candidates_enabled) return;
    if (carrier_tcp_ == nullptr) return;
    if (local_port_ == 0) return;

    /// Walk the freshly-emitted UDP host candidates, mirroring each
    /// as TCP active / passive / simultaneous-open. `push_back` on
    /// `local_candidates_` may reallocate and invalidate references
    /// — so the iteration copies the source candidate by value
    /// before pushing into the same vector.
    std::lock_guard lk(local_state_mu_);
    const std::size_t udp_end = local_candidates_.size();
    static constexpr std::array<TransportType, 3> kTcpVariants = {
        TransportType::TcpActive,
        TransportType::TcpPassive,
        TransportType::TcpSimultaneousOpen,
    };
    for (std::size_t i = 0; i < udp_end; ++i) {
        Candidate src = local_candidates_[i];
        if (src.type != CandidateType::Host) continue;
        if (src.transport != TransportType::Udp) continue;
        for (auto variant : kTcpVariants) {
            Candidate c = src;
            c.transport = variant;
            local_candidates_.push_back(std::move(c));
        }
    }
}

void IceSession::resolve_remote_mdns_candidates() {
    /// Walk the remote set for HostMdns entries that still hold an
    /// unresolved hostname (`!c.hostname.empty()` && IP all zeroes).
    /// Each gets a one-shot mDNS query through the shared manager;
    /// the resolver callback dispatches back onto this strand,
    /// rewrites the entry in place with the resolved IP, and rebuilds
    /// the check list so the new pair joins the queue.
    if (!mdns_) return;
    /// Snapshot indices to avoid mutating remote_candidates_ during
    /// iteration; resolution callbacks land on the strand later and
    /// mutate the vector then.
    std::vector<std::pair<std::size_t, std::string>> queue;
    for (std::size_t i = 0; i < remote_candidates_.size(); ++i) {
        const auto& c = remote_candidates_[i];
        if (c.type != CandidateType::HostMdns) continue;
        if (c.hostname.empty()) continue;
        if (!is_mdns_local_name(c.hostname)) continue;
        queue.emplace_back(i, c.hostname);
    }
    if (queue.empty()) return;

    const auto timeout = std::chrono::milliseconds(
        cfg_.mdns_resolve_timeout_ms > 0
            ? cfg_.mdns_resolve_timeout_ms : 5000);

    for (auto& [idx, hostname] : queue) {
        auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
        /// The resolver invokes the callback on its own strand. Hop
        /// back to ours before touching `remote_candidates_`.
        mdns_->resolve(hostname, timeout,
            [weak_self, idx, hostname](const MdnsResolveResult& r) {
                auto self = weak_self.lock();
                if (!self) return;
                asio::post(self->strand_,
                    [self, idx, hostname, r] {
                        if (self->state_.load(std::memory_order_acquire)
                            == SessionState::Failed) return;
                        if (idx >= self->remote_candidates_.size()) return;
                        auto& slot = self->remote_candidates_[idx];
                        if (slot.type != CandidateType::HostMdns) return;
                        if (slot.hostname != hostname) return;

                        if (!r.resolved
                            || (r.ipv4.empty() && r.ipv6.empty())) {
                            /// Drop the unresolved entry. Erasing
                            /// shifts subsequent indices but every
                            /// queued callback captures its own
                            /// `idx`; since we used the index AT
                            /// THE TIME the query was issued and
                            /// the vector may have been mutated by
                            /// earlier callbacks, we identify the
                            /// slot by (idx, hostname) and bail if
                            /// either no longer matches.
                            slot.hostname.clear();
                            slot.type = CandidateType::Host;
                            return;
                        }
                        /// Rewrite the slot with the first resolved
                        /// IPv4; append any additional A / AAAA
                        /// records as separate Host candidates so
                        /// every reachable interface gets a pair.
                        auto first_ipv4 =
                            !r.ipv4.empty() ? r.ipv4.front() : std::string{};
                        auto first_ipv6 =
                            !r.ipv6.empty() ? r.ipv6.front() : std::string{};
                        slot.type = CandidateType::Host;
                        slot.hostname.clear();
                        if (!first_ipv4.empty()) {
                            slot.set_address(first_ipv4);
                        } else {
                            slot.set_address(first_ipv6);
                        }
                        slot.priority = compute_priority(
                            CandidateType::Host, 65535, 1);

                        auto append_extra =
                            [&](const std::string& ip,
                                AddressFamily fam) {
                            (void)fam;
                            Candidate extra{};
                            extra.type     = CandidateType::Host;
                            extra.port     = slot.port;
                            extra.priority = compute_priority(
                                CandidateType::Host, 65535, 1);
                            extra.set_address(ip);
                            self->remote_candidates_.push_back(extra);
                        };
                        for (std::size_t k = 1; k < r.ipv4.size(); ++k) {
                            append_extra(r.ipv4[k], AddressFamily::IPv4);
                        }
                        for (std::size_t k = (first_ipv4.empty() ? 1 : 0);
                              k < r.ipv6.size(); ++k) {
                            append_extra(r.ipv6[k], AddressFamily::IPv6);
                        }

                        /// Fold the freshly-resolved candidate(s)
                        /// into the check list and kick off checks
                        /// if we were waiting on this.
                        const auto st = self->state_.load(
                            std::memory_order_acquire);
                        if (st == SessionState::WaitingRemote
                            || st == SessionState::Gathering) {
                            if (!self->local_candidates_.empty()) {
                                self->state_.store(
                                    SessionState::Checking,
                                    std::memory_order_release);
                                self->build_check_list();
                                self->begin_checks();
                            }
                        } else if (st == SessionState::Checking) {
                            self->build_check_list();
                            self->current_check_ = 0;
                            self->run_next_check();
                        }
                    });
            });
    }
}

gn_conn_id_t IceSession::ensure_remote_cid(const std::string& ip,
                                              uint16_t port) {
    if (!carrier_) return 0;
    const auto key = endpoint_key(ip, port);
    if (auto it = endpoint_to_cid_.find(key); it != endpoint_to_cid_.end()) {
        return it->second;
    }
    gn_conn_id_t cid = GN_INVALID_ID;
    const auto uri = endpoint_uri(ip, port);
    if (carrier_->connect(uri, &cid) != GN_OK || cid == GN_INVALID_ID) {
        return 0;
    }
    /// Install per-cid data dispatch back into this session. The
    /// callback re-enters `on_carrier_data` on whatever thread the
    /// UDP producer's strand uses; we marshal back onto our own
    /// strand inside that handler to keep the FSM single-threaded.
    auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
    (void)carrier_->on_data(
        cid,
        [weak_self](gn_conn_id_t c, std::span<const std::uint8_t> bytes) {
            auto self = weak_self.lock();
            if (!self) return;
            std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
            asio::post(self->strand_,
                [self, c, copy = std::move(copy)] {
                    self->on_carrier_data(c, copy);
                });
        });
    endpoint_to_cid_[key] = cid;
    cid_to_endpoint_udp_[cid] = EndpointInfo{ip, port, TransportType::Udp};
    return cid;
}

gn_conn_id_t IceSession::relay_cid_for_endpoint(const std::string& ip,
                                                    std::uint16_t port) {
    const auto key = endpoint_key(ip, port);
    if (auto it = relay_endpoint_to_cid_.find(key);
        it != relay_endpoint_to_cid_.end()) {
        return it->second;
    }
    const auto cid = next_relay_cid_++;
    relay_endpoint_to_cid_[key] = cid;
    relay_cids_.insert(cid);
    /// Stamp the synthetic cid into the UDP endpoint map so the
    /// response/triggered-check path in `on_carrier_data` recovers the
    /// peer (ip, port) via the existing `ep_map.find(cid)` lookup.
    cid_to_endpoint_udp_[cid] = EndpointInfo{ip, port, TransportType::Udp};
    return cid;
}

gn_conn_id_t IceSession::ensure_remote_tcp_cid(const std::string& ip,
                                                  uint16_t port) {
    if (!carrier_tcp_) return 0;
    /// TCP cids are not deduplicated by endpoint key: each check pair
    /// needs an independent socket because the framing reassembly
    /// buffer + connection state is per-cid. Repeated calls open
    /// repeated sockets — caller owns the lifetime via
    /// `endpoint_to_cid_`'s map of (ip,port) → cid for the latest
    /// attempt only.
    gn_conn_id_t cid = GN_INVALID_ID;
    const auto uri = endpoint_uri_tcp(ip, port);
    if (carrier_tcp_->connect(uri, &cid) != GN_OK || cid == GN_INVALID_ID) {
        return 0;
    }
    auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
    (void)carrier_tcp_->on_data(
        cid,
        [weak_self](gn_conn_id_t c, std::span<const std::uint8_t> bytes) {
            auto self = weak_self.lock();
            if (!self) return;
            std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
            asio::post(self->strand_,
                [self, c, copy = std::move(copy)] {
                    self->on_tcp_carrier_data(c, copy);
                });
        });
    cid_to_endpoint_tcp_[cid] = EndpointInfo{ip, port, TransportType::TcpActive};
    auto timer = std::make_unique<asio::steady_timer>(io_);
    timer->expires_after(
        std::chrono::milliseconds(cfg_.tcp_connect_timeout_ms));
    timer->async_wait(asio::bind_executor(strand_,
        [weak_self, cid](const std::error_code& ec) {
            if (ec == asio::error::operation_aborted) return;
            auto self = weak_self.lock();
            if (!self) return;
            self->on_tcp_connect_timeout(cid);
        }));
    tcp_connect_timers_[cid] = std::move(timer);
    return cid;
}

std::vector<std::uint8_t> IceSession::frame_tcp_stun(
    std::span<const std::uint8_t> msg) {
    /// RFC 5389 §7.2.2: 16-bit big-endian length prefix in front of
    /// the STUN message. Padding the length field with anything other
    /// than the message body size breaks the framing on the peer side.
    std::vector<std::uint8_t> out;
    out.reserve(msg.size() + 2);
    const auto len = static_cast<std::uint16_t>(msg.size());
    out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(len & 0xFFu));
    out.insert(out.end(), msg.begin(), msg.end());
    return out;
}

void IceSession::on_tcp_carrier_data(gn_conn_id_t cid,
                                         std::span<const std::uint8_t> bytes) {
    /// TCP carriers deliver arbitrary byte chunks. The reassembly
    /// buffer holds the in-progress STUN frame across delivery
    /// boundaries; the inner loop drains every complete frame the
    /// buffer currently holds before returning. Underflow on the
    /// length prefix or the body simply leaves the bytes in place
    /// for the next callback.
    if (auto it = tcp_connect_timers_.find(cid);
        it != tcp_connect_timers_.end()) {
        if (it->second) it->second->cancel();
        tcp_connect_timers_.erase(it);
    }
    auto& buf = tcp_rx_buffers_[cid];
    buf.insert(buf.end(), bytes.begin(), bytes.end());
    while (buf.size() >= 2) {
        const std::uint16_t len =
            (static_cast<std::uint16_t>(buf[0]) << 8)
            | static_cast<std::uint16_t>(buf[1]);
        if (buf.size() < static_cast<std::size_t>(2) + len) break;
        std::vector<std::uint8_t> frame(buf.begin() + 2,
                                          buf.begin() + 2 + len);
        buf.erase(buf.begin(), buf.begin() + 2 + len);
        on_carrier_data(cid, frame, /*from_tcp=*/true);
    }
}

void IceSession::on_tcp_connect_timeout(gn_conn_id_t cid) {
    tcp_connect_timers_.erase(cid);
    auto ep_it = cid_to_endpoint_tcp_.find(cid);
    if (ep_it == cid_to_endpoint_tcp_.end()) return;
    const auto ep = ep_it->second;
    if (!transport_is_tcp(ep.transport)) return;
    if (carrier_tcp_) {
        (void)carrier_tcp_->unsubscribe_data(cid);
        (void)carrier_tcp_->disconnect(cid);
    }
    cid_to_endpoint_tcp_.erase(ep_it);
    tcp_rx_buffers_.erase(cid);
    for (auto& p : check_list_) {
        if (p.state != PairState::InProgress) continue;
        if (!transport_is_tcp(p.transport_type)) continue;
        if (p.remote.address_str() != ep.ip
            || p.remote.port      != ep.port) continue;
        p.state = PairState::Failed;
        ICE_DBG("pair-failed-tcp-timeout",
                "peer=%s lfnd=%s rfnd=%s cid=%llu",
                peer_id_.c_str(),
                p.local.foundation.c_str(),
                p.remote.foundation.c_str(),
                static_cast<unsigned long long>(cid));
        unfreeze_siblings(p.local.foundation, p.remote.foundation);
    }
}

void IceSession::gather_tcp_server_reflexive() {
    /// RFC 6544 §4.4 TCP server-reflexive gather. Fires one STUN
    /// binding request per configured STUN server through the TCP
    /// carrier; the response's XOR-MAPPED-ADDRESS surfaces a TCP
    /// srflx candidate. Reuses the same `pending_stun_probes_`
    /// transaction-id set as the UDP path so a UDP and a TCP probe
    /// to the same server don't collide on the txid.
    ///
    /// TCP-TURN per RFC 6062 is roadmap; this commit covers host +
    /// srflx TCP only.
    if (!cfg_.tcp_candidates_enabled) return;
    if (carrier_tcp_ == nullptr) return;
    if (cfg_.stun_servers.empty()) return;

    for (auto& server : cfg_.stun_servers) {
        const auto split = split_stun_host_port(server);
        if (!split) continue;
        const auto& host = split->first;
        const auto  port = split->second;
        auto cid = ensure_remote_tcp_cid(host, port);
        if (cid == 0) continue;
        auto txn = generate_txn_id();
        auto msg = StunBuilder(STUN_BINDING_REQUEST).set_txn_id(txn).build();
        pending_stun_probes_.push_back(txn);
        const auto framed = frame_tcp_stun(msg);
        if (carrier_tcp_) (void)carrier_tcp_->send(cid, framed);
    }
}

void IceSession::start_multi_stun_probes() {
    ICE_DBG("stun-probe.start",
            "peer=%s servers=%zu controlling=%d",
            peer_id_.c_str(), cfg_.stun_servers.size(),
            controlling_ ? 1 : 0);
    pending_stun_probes_.clear();
    /// Resolve + send one Binding Request per configured STUN server in
    /// a single batch. All probes share the same UDP source port (the
    /// host candidate carrier) so any response routes back to this
    /// session's per-cid `on_carrier_data`. First valid
    /// XOR-MAPPED-ADDRESS wins; remaining probes' responses arrive
    /// later and are dropped because `pending_stun_probes_` is cleared
    /// on first success.
    for (auto& server : cfg_.stun_servers) {
        const auto split = split_stun_host_port(server);
        if (!split) continue;
        const auto& host = split->first;
        const auto  port = split->second;

        auto cid = ensure_remote_cid(host, port);
        if (cid == 0) continue;

        auto txn = generate_txn_id();
        auto msg = StunBuilder(STUN_BINDING_REQUEST).set_txn_id(txn).build();
        pending_stun_probes_.push_back(txn);
        ICE_DBG("stun-probe.send", "peer=%s -> %s:%u cid=%llu",
                peer_id_.c_str(), host.c_str(), port,
                static_cast<unsigned long long>(cid));
        if (carrier_) (void)carrier_->send(cid, msg);
    }

    if (pending_stun_probes_.empty()) {
        /// Every configured server was unresolvable / had no carrier.
        /// Skip srflx and fall back on host + relay only.
        on_gathering_complete();
        return;
    }

    /// Single timeout covers every probe in this batch. RFC 8445
    /// §14.3 transaction TO defaults to several hundred ms with up to
    /// 7 retries; we use `session_timeout_s` (default 10 s) as the
    /// hard ceiling — any probe that hasn't replied by then is treated
    /// as unreachable.
    gather_timer_.expires_after(
        std::chrono::seconds(cfg_.session_timeout_s));
    gather_timer_.async_wait(asio::bind_executor(strand_,
        [this, self = shared_from_this()](const std::error_code& ec) {
            if (ec) return;
            /// Every probe timed out — proceed without srflx. host +
            /// relay candidates (if any) still drive connectivity
            /// checks; nomination will succeed if peers can reach each
            /// other directly or through TURN. We deliberately do NOT
            /// short-circuit on `state != Gathering`: the responder
            /// flow flips state to Checking the moment OFFER arrival
            /// merges remote candidates, but the gather-side STUN
            /// probes still need to fire `on_gathered` so the local
            /// candidate set (host + any srflx that DID return) is
            /// serialised into the outbound signal queue. Without
            /// this, the peer never sees an ANSWER and the harness
            /// stalls until its own deadline.
            pending_stun_probes_.clear();
            on_gathering_complete();
        }));
}

void IceSession::handle_gather_response(const StunMessage& msg,
                                            TransportType src_transport) {
    ICE_DBG("gather-resp",
            "peer=%s src_tx=%d xor=%s:%u pending=%zu",
            peer_id_.c_str(), static_cast<int>(src_transport),
            msg.xor_mapped ? msg.xor_mapped->ip.c_str() : "(none)",
            msg.xor_mapped ? msg.xor_mapped->port : 0,
            pending_stun_probes_.size());
    /// Match by transaction id. Linear scan is fine — `cfg_.stun_servers`
    /// is operator-bounded (single-digit).
    auto it = std::find(pending_stun_probes_.begin(),
                         pending_stun_probes_.end(), msg.txn_id);
    if (it == pending_stun_probes_.end()) return;
    if (!msg.xor_mapped) return;

    /// Drop the matched transaction from the pending set so a
    /// duplicate response doesn't get processed twice. Subsequent
    /// responses from OTHER STUN servers still arrive and feed the
    /// symmetric-NAT stride detector below — without that, a single-
    /// STUN deployment would never observe stride.
    pending_stun_probes_.erase(it);

    Candidate c{};
    c.type     = CandidateType::Srflx;
    c.priority = compute_priority(CandidateType::Srflx, 65535, 1);
    c.transport = transport_is_tcp(src_transport)
        ? TransportType::TcpActive : TransportType::Udp;

    struct in_addr addr4;
    if (inet_pton(AF_INET, msg.xor_mapped->ip.c_str(), &addr4) == 1) {
        c.family = AddressFamily::IPv4;
        std::memcpy(c.addr.data(), &addr4, 4);
    } else {
        struct in6_addr addr6;
        inet_pton(AF_INET6, msg.xor_mapped->ip.c_str(), &addr6);
        c.family = AddressFamily::IPv6;
        std::memcpy(c.addr.data(), &addr6, 16);
    }
    c.port = msg.xor_mapped->port;

    /// Symmetric-NAT detection: two responses from the SAME local port
    /// reporting DIFFERENT external ports prove the NAT is rewriting
    /// per-destination. Record the stride so check-list construction
    /// can probe predicted ports beyond the peer's advertised srflx.
    if (cfg_.symmetric_port_prediction_enabled) {
        if (!have_first_srflx_port_) {
            first_observed_srflx_port_ = c.port;
            have_first_srflx_port_ = true;
        } else if (c.port != first_observed_srflx_port_
                    && symmetric_stride_.load(std::memory_order_relaxed) == 0) {
            const auto a = first_observed_srflx_port_;
            const auto b = c.port;
            const std::uint16_t stride =
                static_cast<std::uint16_t>(
                    a < b ? (b - a) : (a - b));
            if (stride > 0) {
                symmetric_stride_.store(stride, std::memory_order_release);
            }
        }
    }

    /// First response wins the srflx slot; subsequent responses still
    /// contribute to stride detection (above) but don't add another
    /// srflx candidate — the IP is the same per local port, the wire
    /// difference is purely on the destination side. UDP and TCP
    /// srflx slots are tracked independently so a TCP probe response
    /// doesn't shadow a pre-existing UDP srflx candidate (and vice
    /// versa).
    const bool want_tcp_slot = transport_is_tcp(c.transport);
    bool already_have_srflx = false;
    for (const auto& existing : local_candidates_) {
        if (existing.type != CandidateType::Srflx) continue;
        if (transport_is_tcp(existing.transport) == want_tcp_slot) {
            already_have_srflx = true;
            break;
        }
    }
    if (!already_have_srflx
        && candidate_allowed(c.type, c.family,
                              cfg_.candidate_filter_flags)) {
        std::lock_guard lk(local_state_mu_);
        local_candidates_.push_back(c);
    }

    /// Drive the FSM forward on the first STUN response — decouple
    /// from already_have_srflx so a portmap-srflx added by gather_portmap()
    /// before STUN completes doesn't suppress gather coordination.
    /// If a TURN allocation is still in flight, arm a 500ms safety
    /// fallback timer so a slow/unresponsive TURN server doesn't
    /// stall the whole gather phase.
    if (!stun_gathered_) {
        gather_timer_.cancel();
        stun_gathered_ = true;
        if (!turn_gathering_) {
            on_gathering_complete();
        } else {
            gather_timer_.expires_after(std::chrono::milliseconds(500));
            gather_timer_.async_wait(asio::bind_executor(strand_,
                [this, self = shared_from_this()](
                        const std::error_code& ec) {
                    if (ec) return;
                    on_gathering_complete();
                }));
        }
    }
}

void IceSession::gather_relay() {
    /// Operator may have disabled relay candidates via
    /// `ice.candidate_filters = ["host-only"]` etc. Short-circuit
    /// the entire TURN allocation in that case — saves a STUN
    /// request roundtrip and avoids holding a TURN refresh timer
    /// for a candidate we'd just drop.
    if ((cfg_.candidate_filter_flags & kCandidateFilterHostOnly) != 0) return;

    /// Single-server callers (legacy config that set only `turn`
    /// without expanding it into the array) get folded into
    /// `turn_servers` here so the iteration walk has a uniform input
    /// shape. The link-side `apply_config` already mirrors entries
    /// into both fields; this branch covers in-tree fixtures that
    /// construct an `IceConfig` directly.
    if (cfg_.turn_servers.empty() && !cfg_.turn.server.empty()) {
        cfg_.turn_servers.push_back(cfg_.turn);
    }
    if (cfg_.turn_servers.empty()) return;

    turn_gathering_ = true;
    turn_attempt_idx_ = 0;
    try_next_turn_attempt();
}

std::shared_ptr<TurnClient> IceSession::build_turn_client(
    const TurnConfig& cfg,
    TurnAllocatedCallback on_alloc,
    TurnDataCallback on_data,
    gn_conn_id_t& out_cid) {
    out_cid = 0;
    /// Pick the carrier scheme for the TURN server endpoint. Order
    /// of precedence: TLS > TCP > UDP. Each higher tier requires its
    /// own carrier resolved by IceLink; if missing, we silently fall
    /// back so a misconfigured operator still gets a working relay
    /// path instead of a hard failure.
    const bool want_tls = cfg.tls_transport
                            && carrier_tls_ != nullptr;
    const bool want_tcp = !want_tls
                            && cfg.tcp_transport
                            && carrier_tcp_ != nullptr;
    const bool want_stream = want_tls || want_tcp;
    auto* turn_carrier = want_tls ? carrier_tls_
                          : want_tcp ? carrier_tcp_
                          : carrier_;
    if (!turn_carrier) return nullptr;

    gn_conn_id_t turn_cid = 0;
    if (!want_stream) {
        /// UDP path: share the session's cid maps so on_carrier_data
        /// routes inbound bytes through the same dispatcher that
        /// serves STUN / check traffic.
        turn_cid = ensure_remote_cid(cfg.server, cfg.port);
        if (turn_cid == 0) return nullptr;
    } else {
        /// TCP path: bypass the dispatcher and route bytes directly
        /// to the per-client `on_inbound`. Cid namespaces differ
        /// between carriers (each composer allocates from its own
        /// counter), so a shared dispatcher would risk collision
        /// with UDP cids.
        const auto uri = endpoint_uri(cfg.server, cfg.port);
        if (turn_carrier->connect(uri, &turn_cid) != GN_OK
            || turn_cid == GN_INVALID_ID) {
            return nullptr;
        }
    }
    out_cid = turn_cid;

    auto client = std::make_shared<TurnClient>(
        io_, turn_carrier, turn_cid, cfg,
        std::move(on_data), std::move(on_alloc));

    if (want_stream) {
        auto weak_client = std::weak_ptr<TurnClient>(client);
        auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
        (void)turn_carrier->on_data(
            turn_cid,
            [weak_self, weak_client](gn_conn_id_t /*c*/,
                                       std::span<const std::uint8_t> bytes) {
                auto self = weak_self.lock();
                if (!self) return;
                auto cli = weak_client.lock();
                if (!cli) return;
                std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
                asio::post(self->strand_,
                    [cli, copy = std::move(copy)] {
                        cli->on_inbound(copy);
                    });
            });
    }
    return client;
}

void IceSession::try_next_turn_attempt() {
    /// Sequential walk through `cfg_.turn_servers`. Each entry gets
    /// a deadline-bounded ALLOCATE; on timeout / construction
    /// failure the FSM advances to the next entry. List exhaustion
    /// leaves `turn_` null — the session proceeds with host + srflx
    /// candidates only.
    turn_allocate_timer_.cancel();
    if (turn_) {
        turn_->close();
        turn_.reset();
    }
    if (turn_attempt_idx_ >= cfg_.turn_servers.size()) {
        /// All TURN attempts exhausted without a successful allocation.
        /// Clear the in-flight flag; if STUN already gathered (or there
        /// is no STUN), fire on_gathering_complete so the offer goes
        /// out with host + srflx only.  The safety gather_timer_ is
        /// cancelled to prevent a duplicate on_gathering_complete call.
        turn_gathering_ = false;
        if (stun_gathered_ || cfg_.stun_servers.empty()) {
            gather_timer_.cancel();
            on_gathering_complete();
        }
        return;
    }

    const auto& attempt_cfg = cfg_.turn_servers[turn_attempt_idx_];
    if (attempt_cfg.server.empty()) {
        ++turn_attempt_idx_;
        asio::post(strand_, [self = shared_from_this()] {
            self->try_next_turn_attempt();
        });
        return;
    }

    auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
    auto on_alloc = [weak_self](const std::string& relay_ip, uint16_t relay_port) {
        auto self = weak_self.lock();
        if (!self) return;
        Candidate c{};
        c.type = CandidateType::Relay;
        c.port = relay_port;
        c.set_address(relay_ip);
        c.priority = compute_priority(CandidateType::Relay, 65535, 1);

        asio::post(self->strand_, [self, c = std::move(c)]() mutable {
            self->turn_allocate_timer_.cancel();
            if (!candidate_allowed(c.type, c.family,
                                    self->cfg_.candidate_filter_flags)) {
                return;
            }
            {
                std::lock_guard lk(self->local_state_mu_);
                self->local_candidates_.push_back(std::move(c));
            }

            /// TURN allocation just came up — install CreatePermission
            /// entries for every remote candidate already known. The
            /// server drops Send-Indications targeting peers without
            /// a permission; without this, the very first connectivity
            /// check fired through the relay never reaches the peer
            /// and the FSM times out. The TurnClient internally
            /// dedupes via its `permissions_` set, so this is safe to
            /// call before later remote-candidate arrivals trigger
            /// their own create_permission in `add_remote_candidates`.
            if (self->turn_) {
                for (const auto& rc : self->remote_candidates_) {
                    self->turn_->create_permission(rc.address_str());
                }
            }

            /// Successful attempt — stash the remaining entries as
            /// backups and arm the periodic probe.
            self->turn_backups_.clear();
            for (std::size_t i = self->turn_attempt_idx_ + 1;
                 i < self->cfg_.turn_servers.size(); ++i) {
                self->turn_backups_.push_back(self->cfg_.turn_servers[i]);
            }
            if (!self->turn_backups_.empty()
                && self->cfg_.turn_backup_interval_s > 0) {
                self->turn_backup_probe_idx_ = 0;
                self->turn_backup_timer_.expires_after(
                    std::chrono::seconds(self->cfg_.turn_backup_interval_s));
                self->turn_backup_timer_.async_wait(
                    asio::bind_executor(self->strand_,
                        [self](const std::error_code& ec) {
                            if (ec) return;
                            self->on_turn_backup_tick();
                        }));
            }

            /// TURN allocation complete — clear the in-flight flag and
            /// drive gathering forward.  If STUN has already resolved
            /// (or there are no STUN servers), fire on_gathering_complete
            /// now so the offer/answer includes the relay candidate.
            /// The gather_timer_ (500ms safety timer) is cancelled first
            /// to avoid a redundant on_gathering_complete() from it.
            self->turn_gathering_ = false;
            if (self->stun_gathered_ || self->cfg_.stun_servers.empty()) {
                self->gather_timer_.cancel();
                self->on_gathering_complete();
            }

            /// If remote candidates already arrived and we are
            /// already in the checking phase, fold the freshly-
            /// minted relay candidate into the check list and
            /// restart from the highest-priority pair.
            if (!self->remote_candidates_.empty() &&
                self->state_.load(std::memory_order_acquire) ==
                    SessionState::Checking) {
                self->build_check_list();
                self->current_check_ = 0;
                self->run_next_check();
                /// Trickle the relay candidate to the peer (RFC 8838).
                /// The initial answer was already sent in
                /// add_remote_candidates; fire on_gathered again so
                /// the peer's check list includes the relay endpoint.
                /// Only the responder does this — the initiator's
                /// gather coordination already delays the OFFER until
                /// TURN resolves so the relay is in the initial offer.
                if (!self->controlling_ && self->callbacks_.on_gathered) {
                    self->callbacks_.on_gathered(self->peer_id_);
                }
            }
        });
    };

    auto on_data = [weak_self](const std::string& ip,
                                uint16_t port,
                                std::span<const uint8_t> data) {
        auto self = weak_self.lock();
        if (!self) return;
        self->last_activity_.store(std::chrono::steady_clock::now(),
                                     std::memory_order_release);
        /// Peek at the payload to distinguish a STUN connectivity
        /// check / response from raw application bytes. RFC 5389 §6:
        /// every STUN message starts with two zero bits in the first
        /// byte and carries the 4-byte magic cookie 0x2112A442 at
        /// offset [4..8). Application data is forwarded straight to
        /// the upper layer; STUN messages are re-injected into the
        /// regular per-cid dispatch path through a synthetic relay
        /// cid keyed by (peer_ip, peer_port) so the existing FSM
        /// (response correlation, integrity check, triggered-check)
        /// works unmodified.
        const bool is_stun = data.size() >= 20
            && (data[0] & 0xC0) == 0
            && data[4] == 0x21 && data[5] == 0x12
            && data[6] == 0xA4 && data[7] == 0x42;
        if (is_stun) {
            std::vector<std::uint8_t> copy(data.begin(), data.end());
            asio::post(self->strand_,
                [self, ip, port, copy = std::move(copy)] {
                    const auto synth_cid =
                        self->relay_cid_for_endpoint(ip, port);
                    self->on_carrier_data(synth_cid, copy,
                                              /*from_tcp=*/false);
                });
            return;
        }
        if (self->callbacks_.on_data)
            self->callbacks_.on_data(self->peer_id_, data);
    };

    gn_conn_id_t cid = 0;
    auto client = build_turn_client(attempt_cfg, std::move(on_alloc),
                                      std::move(on_data), cid);
    if (!client) {
        ++turn_attempt_idx_;
        asio::post(strand_, [self = shared_from_this()] {
            self->try_next_turn_attempt();
        });
        return;
    }

    turn_ = std::move(client);
    turn_->allocate();

    const int timeout_s = cfg_.turn_allocate_timeout_s > 0
                            ? cfg_.turn_allocate_timeout_s : 5;
    turn_allocate_timer_.expires_after(std::chrono::seconds(timeout_s));
    turn_allocate_timer_.async_wait(asio::bind_executor(strand_,
        [self = shared_from_this()](const std::error_code& ec) {
            if (ec) return;
            /// Deadline elapsed without an alloc callback firing.
            /// Discard this attempt and advance.
            if (self->turn_ && self->turn_->is_allocated()) return;
            ++self->turn_attempt_idx_;
            self->try_next_turn_attempt();
        }));
}

void IceSession::on_turn_backup_tick() {
    /// Pick the next backup index, wrapping around so a long-lived
    /// session repeatedly samples every backup. Probing one server
    /// per tick (instead of all-in-parallel) keeps memory + cid
    /// pressure flat and matches libnice's behaviour.
    if (turn_backups_.empty()
        || cfg_.turn_backup_interval_s <= 0) {
        return;
    }
    if (state_.load(std::memory_order_acquire) == SessionState::Failed) {
        return;
    }
    if (turn_backup_probe_) {
        turn_backup_probe_->close();
        turn_backup_probe_.reset();
    }
    if (turn_backup_probe_idx_ >= turn_backups_.size()) {
        turn_backup_probe_idx_ = 0;
    }
    const auto idx = turn_backup_probe_idx_;
    const auto probe_cfg = turn_backups_[idx];
    ++turn_backup_probe_idx_;

    /// Re-arm the periodic timer up front so a slow ALLOCATE doesn't
    /// stretch the gap between ticks.
    turn_backup_timer_.expires_after(
        std::chrono::seconds(cfg_.turn_backup_interval_s));
    turn_backup_timer_.async_wait(asio::bind_executor(strand_,
        [self = shared_from_this()](const std::error_code& ec) {
            if (ec) return;
            self->on_turn_backup_tick();
        }));

    auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
    auto on_alloc = [weak_self, idx, probe_cfg](
                        const std::string& /*relay_ip*/,
                        uint16_t /*relay_port*/) {
        auto self = weak_self.lock();
        if (!self) return;
        asio::post(self->strand_, [self, idx, probe_cfg] {
            (void)idx;
            /// Promotion gate: only fail over if the primary is
            /// unhealthy AND the rate-limit interval has elapsed.
            if (!self->turn_backup_probe_) return;
            const bool primary_healthy =
                self->turn_ && self->turn_->is_healthy();
            const auto now = std::chrono::steady_clock::now();
            const auto since = self->turn_last_failover_
                == std::chrono::steady_clock::time_point{}
                ? std::chrono::seconds(self->cfg_.turn_failover_min_interval_s)
                : std::chrono::duration_cast<std::chrono::seconds>(
                    now - self->turn_last_failover_);
            const bool interval_ok =
                since >= std::chrono::seconds(
                    self->cfg_.turn_failover_min_interval_s);
            if (primary_healthy || !interval_ok) {
                /// Healthy primary or too soon — close the probe and
                /// keep the backup queued for the next tick.
                if (self->turn_backup_probe_) {
                    self->turn_backup_probe_->close();
                    self->turn_backup_probe_.reset();
                }
                return;
            }
            auto promoted = std::move(self->turn_backup_probe_);
            self->turn_backup_probe_.reset();
            self->promote_turn_backup(std::move(promoted), probe_cfg);
        });
    };

    auto on_data = [](const std::string& /*ip*/,
                      uint16_t /*port*/,
                      std::span<const uint8_t> /*data*/) {
        /// Pre-promotion data on a backup is dropped; the peer
        /// shouldn't be sending here until we publish the candidate.
    };

    gn_conn_id_t cid = 0;
    turn_backup_probe_ = build_turn_client(
        probe_cfg, std::move(on_alloc), std::move(on_data), cid);
    if (turn_backup_probe_) {
        turn_backup_probe_->allocate();
    }
}

void IceSession::promote_turn_backup(std::shared_ptr<TurnClient> client,
                                       TurnConfig new_cfg) {
    if (!client) return;
    turn_last_failover_ = std::chrono::steady_clock::now();

    /// Drop the failed primary's relay candidate from the local set
    /// and tear it down. Subsequent sends fall back to host / srflx
    /// pairs until the new relay candidate trickles in.
    if (turn_) {
        turn_->close();
    }
    {
        std::lock_guard lk(local_state_mu_);
        std::erase_if(local_candidates_, [](const Candidate& cnd) {
            return cnd.type == CandidateType::Relay;
        });
    }

    turn_ = std::move(client);
    cfg_.turn = new_cfg;
    const auto relay = turn_->relayed_address();

    Candidate c{};
    c.type = CandidateType::Relay;
    c.port = relay.port;
    c.set_address(relay.ip);
    c.priority = compute_priority(CandidateType::Relay, 65535, 1);
    if (candidate_allowed(c.type, c.family, cfg_.candidate_filter_flags)) {
        std::lock_guard lk(local_state_mu_);
        local_candidates_.push_back(c);
    }

    /// Fold the fresh relay candidate into checks. Trickle-side
    /// integration with `OFFER_EOC`-style candidate emit lives on
    /// the IceLink — sessions expose the new candidate via
    /// `local_candidates()`.
    if (!remote_candidates_.empty()
        && state_.load(std::memory_order_acquire) == SessionState::Checking) {
        build_check_list();
        current_check_ = 0;
        run_next_check();
    } else if (state_.load(std::memory_order_acquire) == SessionState::Connected) {
        /// Active session degradation: drop into Checking against the
        /// refreshed candidate set so the new relay path becomes
        /// nominatable.
        state_.store(SessionState::Checking, std::memory_order_release);
        build_check_list();
        current_check_ = 0;
        run_next_check();
    }
}

void IceSession::on_gathering_complete() {
    ICE_DBG("gather-done",
            "peer=%s state=%d local=%zu remote=%zu pending_stun=%zu",
            peer_id_.c_str(),
            static_cast<int>(state_.load(std::memory_order_acquire)),
            local_candidates_.size(), remote_candidates_.size(),
            pending_stun_probes_.size());
    /// Drop any still-pending STUN probes and cancel the umbrella
    /// timeout — irrelevant whether the gather succeeded (first
    /// XOR-MAPPED-ADDRESS arrived) or timed out / had no servers.
    pending_stun_probes_.clear();
    gather_timer_.cancel();

    if (state_.load(std::memory_order_acquire) == SessionState::Gathering) {
        if (!remote_candidates_.empty()) {
            ICE_DBG("state", "peer=%s Gathering -> Checking", peer_id_.c_str());
            state_.store(SessionState::Checking, std::memory_order_release);
            build_check_list();
            begin_checks();
        } else {
            ICE_DBG("state", "peer=%s Gathering -> WaitingRemote",
                    peer_id_.c_str());
            state_.store(SessionState::WaitingRemote, std::memory_order_release);
        }
    }
    /// Always fire — each completion event may carry a new candidate
    /// (srflx on STUN response, relay on TURN alloc) that the peer
    /// hasn't seen yet.  Trickle ICE (RFC 8838) tolerates multiple
    /// signals per session; duplicates are deduplicated by the
    /// add_remote_candidates idempotency on the remote side.
    if (callbacks_.on_gathered)
        callbacks_.on_gathered(peer_id_);
}

// ── Connectivity checks (strand) ────────────────────────────────────────────

void IceSession::build_check_list() {
    ICE_DBG("build-cl", "peer=%s local=%zu remote=%zu", peer_id_.c_str(),
            local_candidates_.size(), remote_candidates_.size());
    for (const auto& c : local_candidates_) {
        ICE_DBG("build-cl.local", "peer=%s type=%d tx=%d %s:%u prio=%u",
                peer_id_.c_str(), static_cast<int>(c.type),
                static_cast<int>(c.transport),
                c.address_str().c_str(), c.port, c.priority);
    }
    for (const auto& c : remote_candidates_) {
        ICE_DBG("build-cl.remote", "peer=%s type=%d tx=%d %s:%u prio=%u",
                peer_id_.c_str(), static_cast<int>(c.type),
                static_cast<int>(c.transport),
                c.address_str().c_str(), c.port, c.priority);
    }
    check_list_.clear();
    /// Port-prediction precondition: peer advertised symmetric, and
    /// the operator left prediction on. Stride is taken from the
    /// peer's wire flag (we don't know the peer's stride numerically,
    /// so we assume the typical +1 step unless our own gather has
    /// recorded a different stride — which still hints at the local
    /// NAT's behaviour and is a reasonable starting heuristic). The
    /// `attempts` cap bounds the check-list blow-up.
    const auto peer_flags =
        peer_signal_flags_.load(std::memory_order_acquire);
    const bool peer_symmetric =
        (peer_flags & ICE_SIGNAL_FLAG_SYMMETRIC) != 0;
    const std::uint16_t stride = [&]() -> std::uint16_t {
        if (!peer_symmetric
            || !cfg_.symmetric_port_prediction_enabled) return 0;
        const auto own = symmetric_stride_.load(std::memory_order_acquire);
        return own != 0 ? own : static_cast<std::uint16_t>(1);
    }();
    const int prediction_attempts =
        (stride != 0 && cfg_.symmetric_port_prediction_attempts > 0)
            ? cfg_.symmetric_port_prediction_attempts : 0;

    /// RFC 6544 §5.1 pairing rule: a TCP candidate pairs only with
    /// a TCP candidate of the COMPLEMENTARY active/passive role —
    /// active with passive, simultaneous-open with simultaneous-open.
    /// Two passive candidates would both wait for connect(), two
    /// active would both initiate without an acceptor.
    auto tcp_transport_pairs =
        [](TransportType l, TransportType r) noexcept -> bool {
            if (l == TransportType::TcpActive)
                return r == TransportType::TcpPassive;
            if (l == TransportType::TcpPassive)
                return r == TransportType::TcpActive;
            if (l == TransportType::TcpSimultaneousOpen)
                return r == TransportType::TcpSimultaneousOpen;
            return false;
        };

    /// RFC 8445 §5.1.1.3: ensure every local candidate has a stable
    /// foundation before we start grouping pairs. Remote foundations
    /// arrive through trickle; we synthesise one here when the peer
    /// didn't supply it so the foundation tuple is always well-formed.
    assign_local_foundations();
    for (auto& r : remote_candidates_) {
        if (r.foundation.empty()) {
            /// We don't know the peer's STUN/TURN topology, so the
            /// best we can do is hash the wire-visible tuple. Different
            /// (ip, type, transport) yields a different foundation
            /// which is sufficient for the pacing logic — peers that
            /// gather the same remote candidate twice (Trickle dedup)
            /// will land on the same string.
            r.foundation = compute_foundation(
                r.type, r.address_str(), /*server=*/{}, r.transport);
        }
    }

    for (auto& local : local_candidates_) {
        /// Local HostMdns candidates carry only a hostname; the
        /// matching `local_port_` + interface IPs live in the mDNS
        /// responder's registration. For pair construction we use
        /// the actual interface IPs by skipping the HostMdns entry
        /// — the peer's check will arrive at our UDP carrier on
        /// whichever interface answers their mDNS query, and the
        /// triggered-check path mints a Prflx pair from the source
        /// endpoint anyway.
        if (local.type == CandidateType::HostMdns) continue;
        for (auto& remote : remote_candidates_) {
            /// Remote HostMdns entries with an unresolved hostname
            /// have no usable IP yet; the resolver callback rewrites
            /// the slot and calls `build_check_list` again so the
            /// pair lands here in the resolved form.
            if (remote.type == CandidateType::HostMdns
                && !remote.hostname.empty()) {
                continue;
            }
            if (local.family != remote.family) continue;
            /// Transport must agree. UDP-UDP is the default; TCP-TCP
            /// follows the active/passive complementarity rule above.
            const bool both_udp = local.transport == TransportType::Udp
                                   && remote.transport == TransportType::Udp;
            if (!both_udp
                && !tcp_transport_pairs(local.transport, remote.transport)) {
                continue;
            }
            CheckPair pair;
            pair.local = local;
            pair.remote = remote;
            pair.transport_type = local.transport;
            pair.priority = pair_priority(local.priority, remote.priority, controlling_);
            pair.txn_id = generate_txn_id();
            check_list_.push_back(pair);

            /// Stride-predicted pairs: probe `peer.port + stride * k`
            /// for k in 1..N alongside the canonical pair. Only
            /// srflx peer candidates are interesting — host
            /// candidates ride a direct path that prediction cannot
            /// help with, relay candidates already have the TURN
            /// server's stable port. Priority dropped by one rung so
            /// the canonical pair wins when both succeed.
            if (prediction_attempts > 0
                && remote.type == CandidateType::Srflx) {
                for (int k = 1; k <= prediction_attempts; ++k) {
                    const std::uint32_t predicted =
                        static_cast<std::uint32_t>(remote.port)
                        + static_cast<std::uint32_t>(stride) * static_cast<std::uint32_t>(k);
                    if (predicted > 65535) break;
                    CheckPair pp = pair;
                    pp.remote.port = static_cast<std::uint16_t>(predicted);
                    pp.txn_id = generate_txn_id();
                    pp.priority = pair.priority > 0 ? pair.priority - 1 : 0;
                    /// Predicted-port pairs probe a DIFFERENT endpoint
                    /// than the canonical pair — even though the IP /
                    /// type / transport quadruple matches, the actual
                    /// reachable port differs. Give each predicted
                    /// pair a port-distinguished remote foundation so
                    /// the Frozen → Waiting pacing treats them as a
                    /// separate group and races them alongside the
                    /// canonical pair instead of parking them behind
                    /// it (the canonical pair against a wrong port
                    /// will never succeed → predicted pairs would
                    /// never unfreeze).
                    pp.remote.foundation = remote.foundation
                        + ":p"
                        + std::to_string(predicted);
                    check_list_.push_back(pp);
                }
            }
        }
    }
    std::ranges::sort(check_list_, [](const auto& a, const auto& b) {
        return a.priority > b.priority;
    });

    /// RFC 8445 §6.1.2.6 initial states: per foundation tuple
    /// `(local.foundation, remote.foundation)`, the highest-priority
    /// pair starts in Waiting and the remaining pairs sharing that
    /// tuple start in Frozen. The sort above guarantees the first
    /// pair we see for each tuple is the highest-priority one, so a
    /// single pass over the list suffices.
    std::unordered_map<std::string, bool> seen_tuple;
    for (auto& p : check_list_) {
        const auto& lfnd = p.local.foundation;
        const auto& rfnd = p.remote.foundation;
        const std::string key = lfnd + "|" + rfnd;
        auto [it, inserted] = seen_tuple.try_emplace(key, true);
        if (inserted) {
            /// First (highest-priority) pair for this foundation tuple
            /// becomes the representative — Waiting from the start.
            p.state = PairState::Waiting;
        } else {
            /// Sibling for an already-represented foundation tuple.
            /// Frozen until the representative succeeds + unfreezes.
            p.state = PairState::Frozen;
        }
    }
    current_check_ = 0;
}

void IceSession::begin_checks() {
    /// RFC 8445 §2.7 lite agents never initiate connectivity checks.
    /// Stay in Checking so inbound BINDING_REQUEST traffic can still
    /// drive `on_carrier_data` → `on_nominated` once the controller
    /// commits a pair with USE-CANDIDATE.
    if (cfg_.lite_mode) return;

    /// Per-cid data subscriptions are already in place from
    /// `gather_relay` and `start_multi_stun_probes`. New peer
    /// endpoints get their subscriptions installed lazily by
    /// `send_check → ensure_remote_cid`.

    /// RFC 8305 happy-eyeballs at the ICE check layer. Dual-stack
    /// hosts often have IPv6 candidates ranked higher than IPv4 via
    /// the priority formula, so a plain priority-ordered run would
    /// wait `check_interval_ms × N` before reaching the v4 pair —
    /// terrible if the v6 path is broken (no global v6 reachability,
    /// fragmented MTU). Pre-firing one check per family up front
    /// races both stacks so the first one that gets through wins
    /// nomination. We do NOT pre-fire MORE than one per family
    /// (that's what the regular `run_next_check` loop does); the
    /// goal is initial parallelism, not full broadcast.
    bool fired_v4 = false;
    bool fired_v6 = false;
    for (auto& p : check_list_) {
        if (fired_v4 && fired_v6) break;
        /// Happy-eyeballs only pre-fires pairs that are already in
        /// Waiting per the foundation-tuple initial split — Frozen
        /// pairs stay parked until a sibling succeeds.
        if (p.state != PairState::Waiting) continue;
        if (p.local.family == AddressFamily::IPv4 && !fired_v4) {
            p.state = PairState::InProgress;
            send_check(p);
            fired_v4 = true;
        } else if (p.local.family == AddressFamily::IPv6 && !fired_v6) {
            p.state = PairState::InProgress;
            send_check(p);
            fired_v6 = true;
        }
    }

    run_next_check();
}

void IceSession::run_next_check() {
    const auto st_enter = state_.load(std::memory_order_acquire);
    if (st_enter != SessionState::Checking) {
        ICE_DBG("run-check", "peer=%s skip state=%d cl=%zu",
                peer_id_.c_str(), static_cast<int>(st_enter),
                check_list_.size());
        return;
    }
    /// RFC 8445 §6.1.2.6 fallback: rescue any Frozen pair whose
    /// foundation-tuple representative completed without unfreezing it
    /// (defensive — every Failed/Succeeded transition site already
    /// calls `unfreeze_siblings`, but a stuck Frozen pair would silently
    /// dead-end the check list, so we recompute on every tick).
    unfreeze_stuck_pairs();
    ICE_DBG("run-check", "peer=%s cl=%zu inflight=%zu",
            peer_id_.c_str(), check_list_.size(), in_progress_count());

    /// First pass: walk InProgress pairs. RFC 5389 §7.2.1 STUN
    /// retransmits keep firing on the same txn id until the response
    /// arrives or the retry budget is spent — retransmits do NOT
    /// count as new pairs entering the in-progress set, so the
    /// concurrency cap doesn't gate them. A pair whose retries are
    /// exhausted transitions to Failed and yields its slot to a
    /// Waiting sibling.
    ///
    /// RFC 5389 §7.2.1 RTO backoff: a retransmit only fires once the
    /// per-attempt RTO has elapsed since the last send, with RTO
    /// doubling per retry. Pacing tick (`check_interval_ms`) is the
    /// FSM heartbeat; the base RTO is a small multiple of it so the
    /// budget stays in the seconds range where real NAT RTTs live.
    const auto now_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    const uint64_t base_rto_us =
        static_cast<uint64_t>(cfg_.check_interval_ms) * 5 * 1000ull;
    for (auto& p : check_list_) {
        if (p.state != PairState::InProgress) continue;
        if (p.retries >= static_cast<uint8_t>(cfg_.max_check_retries)) {
            if (p.txn_send_us != 0
                && (now_us - p.txn_send_us)
                       < (base_rto_us << (cfg_.max_check_retries - 1))) {
                continue;
            }
            p.state = PairState::Failed;
            ICE_DBG("pair-failed", "peer=%s lfnd=%s rfnd=%s retries=%u — unfreezing siblings",
                    peer_id_.c_str(), p.local.foundation.c_str(),
                    p.remote.foundation.c_str(),
                    static_cast<unsigned>(p.retries));
            unfreeze_siblings(p.local.foundation, p.remote.foundation);
            continue;
        }
        if (p.txn_send_us != 0) {
            const uint64_t rto_us = base_rto_us
                << std::min<uint8_t>(p.retries, 5);
            if ((now_us - p.txn_send_us) < rto_us) continue;
        }
        send_check(p);
    }

    /// Second pass: promote Waiting pairs to InProgress until the
    /// concurrency cap (RFC §6.1.2.5) is hit. Frozen pairs stay
    /// parked until a sibling on the same foundation tuple completes
    /// (`unfreeze_siblings` is called on both Succeeded AND Failed
    /// transitions per RFC 8445 §6.1.2.6). Succeeded / Failed are
    /// terminal.
    bool any_pending = false;
    for (auto& p : check_list_) {
        if (p.state == PairState::Frozen
            || p.state == PairState::Waiting
            || p.state == PairState::InProgress) {
            any_pending = true;
        }
        if (in_progress_count() >= kCheckConcurrencyCap) break;
        if (p.state == PairState::Waiting
            && p.retries < static_cast<uint8_t>(cfg_.max_check_retries)) {
            p.state = PairState::InProgress;
            send_check(p);
        }
    }

    ICE_DBG("run-check.exit", "peer=%s any_pending=%d cl=%zu inflight=%zu",
            peer_id_.c_str(), any_pending ? 1 : 0,
            check_list_.size(), in_progress_count());
    if (!any_pending) {
        if (state_.load(std::memory_order_acquire) == SessionState::Connected)
            return;
        ICE_DBG("state", "peer=%s Checking -> Failed (no pending pairs)",
                peer_id_.c_str());
        state_.store(SessionState::Failed, std::memory_order_release);
        if (callbacks_.on_failed)
            callbacks_.on_failed(peer_id_, ETIMEDOUT);
        return;
    }

    ICE_DBG("check-timer", "peer=%s arm interval_ms=%d any_pending=1",
            peer_id_.c_str(), cfg_.check_interval_ms);
    check_timer_.expires_after(std::chrono::milliseconds(cfg_.check_interval_ms));
    check_timer_.async_wait(asio::bind_executor(strand_,
        [this, self = shared_from_this()](const std::error_code& ec) {
            ICE_DBG("check-timer", "peer=%s fire ec=%d",
                    peer_id_.c_str(), ec.value());
            if (!ec) run_next_check();
        }));
}

std::size_t IceSession::in_progress_count() const noexcept {
    std::size_t n = 0;
    for (const auto& p : check_list_) {
        if (p.state == PairState::InProgress) ++n;
    }
    return n;
}

void IceSession::unfreeze_siblings(const std::string& local_fnd,
                                       const std::string& remote_fnd) {
    /// RFC 8445 §6.1.2.6: when a check pair COMPLETES (Succeeded OR
    /// Failed), every Frozen pair sharing its `(local.foundation,
    /// remote.foundation)` tuple becomes Waiting. Called from both the
    /// success path AND every Failed-transition site so a dead-end
    /// pair (e.g. cross-LAN-unreachable HOST candidate) doesn't strand
    /// its siblings (the routable SRFLX sibling) in Frozen forever.
    /// Foundation strings are non-empty in pairs built through
    /// `build_check_list` — but triggered-check pairs minted by
    /// `maybe_trigger_check_from_peer` skip foundation computation and
    /// start Waiting directly, so an empty foundation here is a no-op
    /// rather than a global unfreeze.
    if (local_fnd.empty() || remote_fnd.empty()) return;
    for (auto& p : check_list_) {
        if (p.state != PairState::Frozen) continue;
        if (p.local.foundation == local_fnd
            && p.remote.foundation == remote_fnd) {
            p.state = PairState::Waiting;
        }
    }
}

void IceSession::unfreeze_stuck_pairs() {
    /// RFC 8445 §6.1.2.6 recompute-states fallback: when no Waiting
    /// or InProgress pair remains but Frozen pairs are still parked,
    /// the foundation-tuple representative they were waiting on must
    /// have transitioned without matching this tuple. Promote one
    /// representative per remaining foundation tuple so the check
    /// list isn't stranded.
    bool has_active = false;
    for (const auto& p : check_list_) {
        if (p.state == PairState::Waiting
            || p.state == PairState::InProgress) {
            has_active = true;
            break;
        }
    }
    if (has_active) return;
    std::unordered_set<std::string> promoted;
    for (auto& p : check_list_) {
        if (p.state != PairState::Frozen) continue;
        const std::string key = p.local.foundation + "|" + p.remote.foundation;
        if (promoted.insert(key).second) {
            p.state = PairState::Waiting;
            ICE_DBG("unfreeze-stuck",
                    "peer=%s lfnd=%s rfnd=%s — RFC 6.1.2.6 fallback promote",
                    peer_id_.c_str(),
                    p.local.foundation.c_str(),
                    p.remote.foundation.c_str());
        }
    }
}

void IceSession::assign_local_foundations() {
    /// Foundations are derived from `(type, base_address,
    /// server_address, transport)`. For host candidates the base IS
    /// the interface IP; we lack the originating STUN/TURN server
    /// here (the carrier learns the local mapped address from the
    /// response, the candidate just records the local IP), so we
    /// use the candidate IP as the base and leave the server side
    /// empty for host candidates. Srflx/relay candidates ideally
    /// carry their backing server — until the gather path threads
    /// that through, all srflx candidates from the same STUN server
    /// collapse to one foundation (which is the RFC-conforming
    /// behaviour: two srflx candidates from the same STUN server
    /// SHARE a foundation).
    std::lock_guard lk(local_state_mu_);
    for (auto& c : local_candidates_) {
        if (!c.foundation.empty()) continue;
        c.foundation = compute_foundation(
            c.type, c.address_str(), /*server=*/{}, c.transport);
    }
}

std::vector<PairState> IceSession::check_list_states_for_test() const {
    /// Snapshot under the strand-side state mutex. Pairs live in
    /// `check_list_` which is strand-only on the write path; we don't
    /// add a dedicated mutex for it because production reads happen
    /// only on the strand. Tests synchronise externally by waiting
    /// for state transitions before sampling.
    std::vector<PairState> out;
    out.reserve(check_list_.size());
    for (const auto& p : check_list_) out.push_back(p.state);
    return out;
}

bool IceSession::handle_role_conflict_for_test(bool sender_controlling,
                                                  uint64_t sender_tiebreaker) {
    /// Forwarder — tests call this synchronously rather than forging
    /// a STUN frame and waiting for the strand dispatch to land.
    return handle_role_conflict(sender_controlling, sender_tiebreaker);
}

bool IceSession::handle_role_conflict(bool sender_controlling,
                                          uint64_t sender_tiebreaker) {
    /// RFC 8445 §7.3.1.1: only call this when the sender's role
    /// attribute MATCHES our claimed role (both controlling, or both
    /// controlled). Mismatched roles are the no-conflict path and
    /// resolve without comparing tiebreakers.
    if (sender_controlling != controlling_) return false;

    /// Tie-break: receiver with the LARGER tie-breaker keeps its
    /// role; the smaller-tie-breaker side switches. Equal values
    /// can't happen unless the RNG repeats, which we treat as the
    /// sender losing (deterministic resolution, no infinite ping-pong).
    if (tiebreaker_ >= sender_tiebreaker) {
        /// We win — sender loses, must switch. From our perspective
        /// we keep `controlling_` as-is and the caller emits a 487
        /// error response so the peer flips.
        return false;
    }

    /// We lose — switch role + rebuild the check list under the new
    /// role so the priority formula reflects the swap (controlling
    /// vs controlled half of `pair_priority`).
    controlling_ = !controlling_;
    if (state_.load(std::memory_order_acquire) == SessionState::Checking
        && !local_candidates_.empty()
        && !remote_candidates_.empty()) {
        build_check_list();
        current_check_ = 0;
        run_next_check();
    }
    return true;
}

void IceSession::send_check(CheckPair& pair) {
    /// RFC 8445 §6.1.2.6 Failed state — a pair whose retry budget is
    /// exhausted before any response arrives transitions out of
    /// InProgress so `run_next_check` can promote a sibling. The
    /// caller already flipped the state to InProgress before invoking
    /// us; we only flip to Failed here when the budget is already
    /// spent on entry (defensive — `run_next_check` filters this case
    /// out, but `begin_checks` and `add_remote_candidates` reach
    /// `send_check` directly and need the same guarantee).
    if (pair.retries >= static_cast<uint8_t>(cfg_.max_check_retries)) {
        pair.state = PairState::Failed;
        unfreeze_siblings(pair.local.foundation, pair.remote.foundation);
        return;
    }
    pair.retries++;
    /// Record the most-recent send timestamp so the matching response
    /// gives us an RTT sample. STUN retransmits reuse the same txn id
    /// per RFC 5389 §7.2.1, so we only see one response per pair and
    /// the delta is bounded by the LAST retry.
    pair.txn_send_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    std::string username = remote_ufrag_ + ":" + local_ufrag_;

    auto builder = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(pair.txn_id)
        .add_username(username)
        .add_priority(pair.local.priority);

    if (controlling_) {
        builder.add_ice_controlling(tiebreaker_);
        /// USE-CANDIDATE policy: aggressive nominates every check;
        /// regular nominates only the chosen pair on its dedicated
        /// follow-up check. `pair.nominee_check_sent` is set BEFORE
        /// this call when the controller picks the nominee, so the
        /// builder gates on it directly.
        if (cfg_.aggressive_nomination || pair.nominee_check_sent) {
            builder.add_use_candidate();
        }
    } else {
        builder.add_ice_controlled(tiebreaker_);
    }

    auto msg = builder.add_integrity(remote_pwd_)
                      .add_fingerprint()
                      .build();

    if (transport_is_tcp(pair.transport_type)) {
        /// RFC 6544 TCP check path. Active and SO variants both
        /// initiate `connect()`; passive locals never reach
        /// `send_check` from our side (the peer's active end opens
        /// the socket and our reply rides whatever cid lands in
        /// `on_carrier_data`). SO uses `arm_tcp_so_connect` which
        /// also arms the bounded coordination timer.
        gn_conn_id_t cid = 0;
        if (pair.transport_type == TransportType::TcpSimultaneousOpen) {
            cid = arm_tcp_so_connect(pair.remote.address_str(),
                                       pair.remote.port);
        } else if (pair.transport_type == TransportType::TcpActive) {
            cid = ensure_remote_tcp_cid(pair.remote.address_str(),
                                          pair.remote.port);
        } else {
            /// TcpPassive — wait for the peer to initiate. The
            /// triggered-check path handles the eventual reply via
            /// `on_carrier_data` once the peer's connect lands.
            return;
        }
        if (cid == 0 || !carrier_tcp_) return;
        const auto framed = frame_tcp_stun(msg);
        (void)carrier_tcp_->send(cid, framed);
        return;
    }

    /// Relay-local UDP pair: route the connectivity check through the
    /// TURN allocation. The STUN payload is identical to the direct-
    /// carrier case — only the wire path changes. `send_indication`
    /// wraps the STUN message in a TURN Send-Indication envelope; the
    /// server unwraps and forwards it as a Data-Indication to the
    /// peer's allocation. Without this, the binding request would land
    /// at the TURN-server's allocated port directly, which discards
    /// non-TURN traffic and the check never reaches the peer. The
    /// synthetic relay cid is stamped so the inbound response (which
    /// surfaces through `TurnDataCallback` → `on_carrier_data` with the
    /// synthetic cid) can recover the peer endpoint via the standard
    /// `cid_to_endpoint_udp_` lookup.
    if (pair.local.type == CandidateType::Relay
        && pair.transport_type == TransportType::Udp
        && turn_ && turn_->is_allocated()) {
        const auto synth_cid = relay_cid_for_endpoint(
            pair.remote.address_str(), pair.remote.port);
        ICE_DBG("send-check.relay",
                "peer=%s -> %s:%u via TURN cid=%llu retry=%u nominee=%d",
                peer_id_.c_str(), pair.remote.address_str().c_str(),
                pair.remote.port,
                static_cast<unsigned long long>(synth_cid),
                pair.retries, pair.nominee_check_sent ? 1 : 0);
        turn_->send_indication(pair.remote.address_str(),
                                  pair.remote.port, msg);
        return;
    }

    auto cid = ensure_remote_cid(pair.remote.address_str(), pair.remote.port);
    ICE_DBG("send-check",
            "peer=%s -> %s:%u tx=%d cid=%llu retry=%u nominee=%d",
            peer_id_.c_str(), pair.remote.address_str().c_str(),
            pair.remote.port, static_cast<int>(pair.transport_type),
            static_cast<unsigned long long>(cid), pair.retries,
            pair.nominee_check_sent ? 1 : 0);
    if (cid == 0 || !carrier_) return;
    (void)carrier_->send(cid, msg);
}

gn_conn_id_t IceSession::arm_tcp_so_connect(const std::string& ip,
                                                std::uint16_t port) {
    /// RFC 6544 §6: simultaneous-open fires `connect()` toward the
    /// peer's TCP-SO candidate within `cfg_.tcp_so_timeout_ms`. We
    /// reuse `ensure_remote_tcp_cid` for the actual connect call;
    /// the kernel TCP stack performs the SYN-SYN exchange on its
    /// own once both ends issue the connect inside the window. A
    /// failed connect yields cid 0 — the caller treats that as a
    /// check failure and the priority queue advances.
    return ensure_remote_tcp_cid(ip, port);
}

// ── Receive + dispatch (strand) ─────────────────────────────────────────────

void IceSession::on_carrier_data(gn_conn_id_t cid,
                                    std::span<const std::uint8_t> data,
                                    bool from_tcp) {
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);
    ICE_DBG("rx-bytes", "peer=%s cid=%llu len=%zu controlling=%d from_tcp=%d",
            peer_id_.c_str(),
            static_cast<unsigned long long>(cid),
            data.size(),
            controlling_ ? 1 : 0,
            from_tcp ? 1 : 0);
    auto& ep_map = from_tcp ? cid_to_endpoint_tcp_ : cid_to_endpoint_udp_;

    /// TURN owns its own server cid. Route every inbound byte from
    /// that cid straight into the TURN state machine — it deframes
    /// the data-indication envelope and surfaces the inner payload
    /// through the `TurnDataCallback` we installed in `gather_relay`.
    if (turn_ && turn_->server_cid() != 0 && cid == turn_->server_cid()) {
        turn_->on_inbound(data);
        return;
    }
    /// Same routing for the in-flight backup probe — the carrier
    /// uses one cid per remote endpoint, so a backup against a
    /// different TURN host lands here on its own cid. STUN-mode
    /// (UDP carrier) shares this dispatcher; stream-mode clients
    /// install their own per-cid subscriber in `build_turn_client`.
    if (turn_backup_probe_ && turn_backup_probe_->server_cid() != 0
        && cid == turn_backup_probe_->server_cid()) {
        turn_backup_probe_->on_inbound(data);
        return;
    }

    auto parsed = parse_stun(data);
    if (parsed) {
        const auto st = state_.load(std::memory_order_acquire);
        ICE_DBG("rx-stun", "peer=%s cid=%llu msg_type=0x%x has_integrity=%d "
                "use_cand=%d xor_mapped=%d state=%d",
                peer_id_.c_str(),
                static_cast<unsigned long long>(cid),
                static_cast<unsigned>(parsed->msg_type),
                parsed->has_integrity ? 1 : 0,
                parsed->use_candidate ? 1 : 0,
                parsed->xor_mapped.has_value() ? 1 : 0,
                static_cast<int>(st));

        /// Gather-phase responses come from operator-configured STUN
        /// servers that do NOT share our local pwd, so they carry no
        /// MESSAGE-INTEGRITY. The transaction-id match against
        /// `pending_stun_probes_` is the gate: an attacker would
        /// have to guess a 12-byte transaction id to inject a fake
        /// srflx, which is the same off-path protection the standard
        /// STUN BINDING-REQUEST/RESPONSE pair relies on.
        ///
        /// Gate on `pending_stun_probes_` rather than `state`. The
        /// responder flow flips state to Checking the moment the
        /// peer's OFFER merges remote candidates, but the gather-
        /// side STUN probes are still in flight against the
        /// operator's STUN servers — their responses must still
        /// feed the srflx candidate set. A state-based gate
        /// dropped those silently because BINDING_RESPONSE without
        /// MESSAGE-INTEGRITY then fails the peer-side integrity
        /// check below.
        if (parsed->msg_type == STUN_BINDING_RESPONSE
            && !pending_stun_probes_.empty()
            && std::find(pending_stun_probes_.begin(),
                          pending_stun_probes_.end(),
                          parsed->txn_id)
                != pending_stun_probes_.end()) {
            TransportType src_tx = TransportType::Udp;
            if (auto eit = ep_map.find(cid); eit != ep_map.end()) {
                src_tx = eit->second.transport;
            }
            handle_gather_response(*parsed, src_tx);
            return;
        }
        (void)st;

        /// STUN messages from a peer must carry a MESSAGE-INTEGRITY
        /// attribute and pass HMAC verification. Without this an
        /// unauthenticated UDP attacker who knows the ICE port can
        /// answer/initiate binding checks, hijack nomination, and
        /// redirect post-handshake traffic. Drop anything that lacks
        /// integrity OR fails the HMAC.
        ///
        /// Key selection follows RFC 8489 §14.1.4 (short-term
        /// credentials): a Response MUST use the same key as the
        /// Request it answers. For ICE that resolves to:
        ///   * inbound Request  → signed by peer with OUR pwd
        ///                        (peer learned `local_pwd_` from
        ///                        our OFFER) → verify with local_pwd_
        ///   * inbound Response → answers a Request WE sent, which
        ///                        we signed with `remote_pwd_`; per
        ///                        the same-key rule, peer signed the
        ///                        Response with the same remote_pwd_
        ///                        → verify with remote_pwd_
        ///   * inbound Error    → same rule as Response.
        ///
        /// The previous implementation verified everything with
        /// local_pwd_ which silently dropped every Success/Error
        /// Response to our own checks, stranding the FSM at
        /// `inflight = N` until the RFC 5389 retry budget expired
        /// and the pair was marked Failed.
        const bool is_response =
            (parsed->msg_type == STUN_BINDING_RESPONSE
             || parsed->msg_type == STUN_BINDING_ERROR);
        const std::string& integrity_key =
            is_response ? remote_pwd_ : local_pwd_;
        if (!parsed->has_integrity
            || !verify_integrity(data, integrity_key)) {
            ICE_DBG("rx-stun.drop",
                    "peer=%s integrity_fail has=%d msg_type=0x%x",
                    peer_id_.c_str(),
                    parsed->has_integrity ? 1 : 0,
                    static_cast<unsigned>(parsed->msg_type));
            return;
        }

        if (parsed->msg_type == STUN_BINDING_ERROR) {
            /// RFC 8445 §7.3.1.1: a 487 Role Conflict on a check we
            /// sent tells us the peer rejected our role claim. Flip
            /// the local role + rebuild the check list so subsequent
            /// checks ride the new role's STUN attributes. Other
            /// error codes mark just THIS pair as failed; sibling
            /// foundation members stay in their existing state.
            if (parsed->error_code && *parsed->error_code == 487) {
                controlling_ = !controlling_;
                if (state_.load(std::memory_order_acquire)
                        == SessionState::Checking
                    && !local_candidates_.empty()
                    && !remote_candidates_.empty()) {
                    build_check_list();
                    current_check_ = 0;
                    run_next_check();
                }
                return;
            }
            /// Generic error — mark the originating pair as Failed
            /// so `run_next_check` can advance, then unfreeze same-
            /// foundation siblings per RFC 8445 §6.1.2.6.
            for (auto& pair : check_list_) {
                if (pair.txn_id == parsed->txn_id) {
                    pair.state = PairState::Failed;
                    unfreeze_siblings(pair.local.foundation,
                                      pair.remote.foundation);
                    break;
                }
            }
            return;
        }
        if (parsed->msg_type == STUN_BINDING_RESPONSE) {
            /// DPLPMTUD probe correlation. A response whose txid
            /// matches the most recent probe is the wire ACK for the
            /// candidate MTU; cancel the timer and advance the
            /// search. Probe responses also implicitly refresh
            /// consent, so the keepalive counter resets alongside.
            if (pmtu_inflight_ && parsed->txn_id == pmtu_inflight_txn_) {
                pmtu_inflight_ = false;
                pmtu_probe_timer_.cancel();
                if (pmtu_probe_) {
                    pmtu_probe_->on_probe_ack();
                    effective_mtu_.store(
                        static_cast<std::uint32_t>(pmtu_probe_->effective_mtu()),
                        std::memory_order_release);
                    if (!pmtu_probe_->is_complete()) {
                        start_path_mtu_probe();
                    }
                }
                consent_missed_.store(0, std::memory_order_release);
                return;
            }
            if (st == SessionState::Connected) {
                consent_missed_.store(0, std::memory_order_release);
            } else {
                handle_check_response(*parsed);
            }
        } else if (parsed->msg_type == STUN_BINDING_REQUEST) {
            /// RFC 8445 §7.3.1.1 role-conflict check. The sender's
            /// role attribute (ICE-CONTROLLING / ICE-CONTROLLED) MUST
            /// be the opposite of ours; otherwise we have to break the
            /// tie via tiebreaker comparison.
            const bool sender_controlling = parsed->ice_controlling.has_value();
            const bool sender_controlled  = parsed->ice_controlled.has_value();
            const uint64_t sender_tb = sender_controlling
                ? *parsed->ice_controlling
                : (sender_controlled ? *parsed->ice_controlled : 0);
            const bool role_attr_present = sender_controlling || sender_controlled;
            const bool same_role =
                role_attr_present
                && ((sender_controlling && controlling_)
                    || (sender_controlled && !controlling_));
            if (same_role) {
                const bool we_switched =
                    handle_role_conflict(sender_controlling, sender_tb);
                if (!we_switched) {
                    /// We won the tie-break: emit a 487 Role Conflict
                    /// error response so the peer switches. Encode
                    /// with our local pwd integrity so they verify
                    /// the response against the same key they used
                    /// to integrity-protect their request.
                    auto err = StunBuilder(STUN_BINDING_ERROR)
                        .set_txn_id(parsed->txn_id)
                        .add_error_code(487, kStunErrorReasonRoleConflict)
                        .add_integrity(local_pwd_)
                        .add_fingerprint()
                        .build();
                    /// Synthetic relay cid: route the error response
                    /// back through TURN so the peer receives it via
                    /// the same allocation path the request used.
                    /// `relay_cids_` is the authoritative membership
                    /// check — the carrier's own cids also have the
                    /// high bit set so a bit-mask test would collide.
                    const bool via_turn = !from_tcp && turn_
                        && relay_cids_.contains(cid);
                    if (from_tcp) {
                        if (carrier_tcp_) {
                            const auto framed = frame_tcp_stun(err);
                            (void)carrier_tcp_->send(cid, framed);
                        }
                    } else if (via_turn) {
                        std::string rip;
                        std::uint16_t rport = 0;
                        if (auto eit = cid_to_endpoint_udp_.find(cid);
                            eit != cid_to_endpoint_udp_.end()) {
                            rip = eit->second.ip;
                            rport = eit->second.port;
                        }
                        if (!rip.empty()) {
                            turn_->send_indication(rip, rport, err);
                        }
                    } else {
                        if (carrier_) (void)carrier_->send(cid, err);
                    }
                    return;
                }
                /// We switched roles: fall through to send the
                /// normal binding-response so the peer's request
                /// still gets ack'd. The next outgoing check rides
                /// the new role's ICE-CONTROLLED/CONTROLLING attribute.
            }

            auto resp = StunBuilder(STUN_BINDING_RESPONSE)
                .set_txn_id(parsed->txn_id)
                .add_integrity(local_pwd_)
                .add_fingerprint()
                .build();
            /// Reply rides the same cid the request arrived on — that
            /// is exactly the peer's endpoint regardless of NAT
            /// rewriting between announced candidate and actual src.
            /// TCP cids need the 16-bit length-prefix wrap before
            /// the byte stream hits the wire (RFC 5389 §7.2.2).
            std::string resp_ip;
            std::uint16_t resp_port = 0;
            if (auto eit = ep_map.find(cid); eit != ep_map.end()) {
                resp_ip = eit->second.ip;
                resp_port = eit->second.port;
            }
            int send_rc = -2;  // -2 = no carrier
            /// Synthetic relay cid: the request arrived via the TURN
            /// allocation, so the matching response goes back the same
            /// way. `send_indication` wraps the STUN response in a
            /// Send-Indication envelope; the server forwards it as a
            /// Data-Indication to the peer's allocation.
            const bool resp_via_turn = !from_tcp && turn_
                && relay_cids_.contains(cid);
            if (from_tcp) {
                if (carrier_tcp_) {
                    const auto framed = frame_tcp_stun(resp);
                    send_rc = static_cast<int>(
                        carrier_tcp_->send(cid, framed));
                }
            } else if (resp_via_turn) {
                if (!resp_ip.empty()) {
                    turn_->send_indication(resp_ip, resp_port, resp);
                    send_rc = 0;
                }
            } else {
                if (carrier_) {
                    send_rc = static_cast<int>(
                        carrier_->send(cid, resp));
                }
            }
            ICE_DBG("send-resp",
                    "peer=%s cid=%llu dst=%s:%u from_tcp=%d "
                    "via_turn=%d resp_bytes=%zu rc=%d",
                    peer_id_.c_str(),
                    static_cast<unsigned long long>(cid),
                    resp_ip.c_str(), resp_port,
                    from_tcp ? 1 : 0,
                    resp_via_turn ? 1 : 0,
                    resp.size(), send_rc);

            std::string peer_ip = resp_ip;
            std::uint16_t peer_port = resp_port;

            if (parsed->use_candidate && !controlling_) {
                /// Use the endpoint info stashed by the per-cid map;
                /// that is the address composer_connect was called
                /// with, which matches the peer's announced candidate.
                if (!peer_ip.empty()) {
                    const auto nom_tx = from_tcp
                        ? TransportType::TcpActive
                        : TransportType::Udp;
                    /// Synthetic cid → the request arrived via TURN,
                    /// so the nominated pair is relay-mediated.
                    /// `send_on_strand` checks `uses_relay_` and falls
                    /// through to `turn_->send_indication` instead of
                    /// the direct carrier path.
                    const bool nom_relay = !from_tcp
                        && relay_cids_.contains(cid);
                    on_nominated(peer_ip, peer_port, nom_relay, cid,
                                 nom_tx);
                }
            }

            /// RFC 8445 §7.3.1.4 triggered check. The inbound binding
            /// request proves the peer can reach us at this (local,
            /// peer) tuple; we mirror that by checking the path back
            /// even if our gathered candidate list never produced
            /// that pair (typically because the peer sees us through
            /// a NAT we didn't probe via STUN). Triggered checks
            /// short-cut nomination on the controlled side too —
            /// without them a one-sided NAT'd flow would only succeed
            /// when our own scheduled checks rotate around to the
            /// same pair, costing several `check_interval_ms` ticks.
            maybe_trigger_check_from_peer(peer_ip, peer_port);
        }
        return;
    }

    if (state_.load(std::memory_order_acquire) == SessionState::Connected
        && callbacks_.on_data) {
        callbacks_.on_data(peer_id_, data);
    }
}

void IceSession::handle_check_response(const StunMessage& msg) {
    if (state_.load(std::memory_order_acquire) != SessionState::Checking) {
        ICE_DBG("check-resp", "peer=%s skip not-Checking state=%d",
                peer_id_.c_str(),
                static_cast<int>(state_.load(std::memory_order_acquire)));
        return;
    }
    bool matched = false;
    for (auto& pair : check_list_) {
        if (pair.txn_id == msg.txn_id) {
            matched = true;
            ICE_DBG("check-resp.match",
                    "peer=%s pair=%s:%u tx=%d valid=%d nominee=%d",
                    peer_id_.c_str(), pair.remote.address_str().c_str(),
                    pair.remote.port, static_cast<int>(pair.transport_type),
                    pair.valid ? 1 : 0,
                    pair.nominee_check_sent ? 1 : 0);
            /// Capture RTT sample if we have a recorded send time.
            /// EWMA alpha = 1/8 (RFC 6298 §2 SRTT default) — same
            /// curve the TCP stack uses; rapidly weights recent
            /// samples but resists single-spike noise.
            if (pair.txn_send_us != 0) {
                const auto now_us = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now()
                            .time_since_epoch()).count());
                const uint64_t sample = now_us - pair.txn_send_us;
                uint64_t cur = rtt_ewma_us_.load(std::memory_order_relaxed);
                const uint64_t next = (cur == 0)
                    ? sample
                    : (cur * 7 + sample) / 8;
                rtt_ewma_us_.store(next, std::memory_order_relaxed);
            }
            /// RFC 8445 §7.2.5.3: discover peer reflexive candidates
            /// from XOR-MAPPED-ADDRESS in the binding response. This
            /// is the actual mapped address the peer sees — critical
            /// for symmetric NAT.
            std::string nom_ip = pair.remote.address_str();
            uint16_t nom_port = pair.remote.port;
            /// "uses_relay" gates the OUTBOUND send path. When the
            /// LOCAL candidate is a Relay, outbound bytes must ride
            /// `turn_->send_indication`; the remote's candidate type
            /// only matters for picking the carrier on the remote
            /// side, which is their decision. Either local or remote
            /// being Relay forces the relay flag because the data
            /// plane has at least one TURN hop in front of it.
            bool nom_relay = pair.local.type == CandidateType::Relay
                || pair.remote.type == CandidateType::Relay;
            nominated_local_type_  = pair.local.type;
            nominated_remote_type_ = pair.remote.type;

            if (msg.xor_mapped) {
                auto& mapped = *msg.xor_mapped;
                auto local_ip = pair.local.address_str();

                /// If mapped address differs from local candidate, we
                /// discovered a peer reflexive candidate (our
                /// NAT-translated address).
                if (mapped.ip != local_ip || mapped.port != pair.local.port) {
                    Candidate prflx{};
                    prflx.type = CandidateType::Prflx;
                    prflx.set_address(mapped.ip);
                    prflx.port = mapped.port;
                    prflx.priority = compute_priority(CandidateType::Prflx, 65535, 1);
                    std::lock_guard lk(local_state_mu_);
                    local_candidates_.push_back(prflx);
                }
            }

            const bool was_valid_before = pair.valid;
            pair.valid = true;
            /// RFC 8445 §6.1.2.4 pair state on success: InProgress →
            /// Succeeded, then unfreeze every Frozen pair sharing the
            /// foundation tuple so dependent pairs can run.
            pair.state = PairState::Succeeded;
            unfreeze_siblings(pair.local.foundation,
                                pair.remote.foundation);

            if (controlling_) {
                if (cfg_.aggressive_nomination
                    || pair.nominee_check_sent) {
                    /// Aggressive: every successful check nominates.
                    /// Regular: only the nominee follow-up commits.
                    /// The nominated cid must match the pair's transport:
                    /// a TCP pair needs a TCP cid (opened via
                    /// `ensure_remote_tcp_cid`), a UDP pair needs the
                    /// UDP one. Mixing the two leaves `send_on_strand`
                    /// driving the wrong carrier.
                    const bool nom_tcp = transport_is_tcp(pair.transport_type);
                    /// Relay-local UDP pair: the synthetic relay cid is
                    /// the right value to stamp into `nominated_cid_`
                    /// so the receive-side `on_carrier_data` dispatch
                    /// recovers the peer endpoint; outbound bytes route
                    /// through `turn_->send_indication` based on
                    /// `uses_relay_`, not the cid.
                    const bool nom_via_turn =
                        pair.local.type == CandidateType::Relay
                        && pair.transport_type == TransportType::Udp
                        && turn_ && turn_->is_allocated();
                    const auto cid = nom_tcp
                        ? ensure_remote_tcp_cid(nom_ip, nom_port)
                        : (nom_via_turn
                            ? relay_cid_for_endpoint(nom_ip, nom_port)
                            : ensure_remote_cid(nom_ip, nom_port));
                    on_nominated(nom_ip, nom_port, nom_relay, cid,
                                 pair.transport_type);
                } else if (!nominee_selected_ && !was_valid_before) {
                    /// Regular nomination: pick the highest-priority
                    /// valid pair as the nominee. Re-scan because the
                    /// pair that just succeeded may not be the best
                    /// one we've seen (a higher-priority pair could
                    /// have responded earlier).
                    CheckPair* best = nullptr;
                    for (auto& p : check_list_) {
                        if (p.valid && (!best || p.priority > best->priority)) {
                            best = &p;
                        }
                    }
                    if (best) {
                        nominee_selected_ = true;
                        best->nominee_check_sent = true;
                        send_check(*best);
                    }
                }
            }
            return;
        }
    }
    if (!matched) {
        ICE_DBG("check-resp.nomatch",
                "peer=%s no pair with txn cl_size=%zu",
                peer_id_.c_str(), check_list_.size());
    }
}

void IceSession::maybe_trigger_check_from_peer(
    const std::string& peer_ip, std::uint16_t peer_port) {
    if (peer_ip.empty() || local_candidates_.empty()) return;
    /// Lite agents per RFC 8445 §2.7 never send connectivity checks.
    /// The reply to the inbound BINDING_REQUEST has already gone out
    /// through `on_carrier_data`; that is the lite agent's only
    /// active role on the wire.
    if (cfg_.lite_mode) return;

    /// Already covered by an existing check pair — nothing to do.
    for (const auto& p : check_list_) {
        if (p.remote.address_str() == peer_ip
            && p.remote.port == peer_port) {
            return;
        }
    }

    CheckPair pair{};
    pair.remote.set_address(peer_ip);
    pair.remote.port = peer_port;
    pair.remote.type = CandidateType::Prflx;
    pair.remote.priority = compute_priority(CandidateType::Prflx, 65535, 1);
    pair.triggered = true;

    /// Pick a local candidate of the matching family. Mixed-family
    /// pairs can't connect; without a match we silently skip — the
    /// peer's check will still get a response and they will fall
    /// back to a different candidate.
    auto local_it = std::find_if(
        local_candidates_.begin(), local_candidates_.end(),
        [&](const Candidate& l) { return l.family == pair.remote.family; });
    if (local_it == local_candidates_.end()) return;
    pair.local = *local_it;
    pair.priority = pair_priority(pair.local.priority,
                                    pair.remote.priority, controlling_);
    pair.txn_id = generate_txn_id();
    /// RFC 8445 §7.3.1.4 triggered checks bypass the Frozen → Waiting
    /// pacing — they ride InProgress directly because we fire them
    /// immediately below. A foundation hash isn't strictly required
    /// for them (they will never have siblings to unfreeze), but
    /// computing one keeps the future possibility of foundation-based
    /// dedup open.
    pair.state = PairState::InProgress;
    if (pair.local.foundation.empty()) {
        pair.local.foundation = compute_foundation(
            pair.local.type, pair.local.address_str(),
            /*server=*/{}, pair.local.transport);
    }
    if (pair.remote.foundation.empty()) {
        pair.remote.foundation = compute_foundation(
            pair.remote.type, pair.remote.address_str(),
            /*server=*/{}, pair.remote.transport);
    }
    check_list_.push_back(pair);

    /// Fire the check immediately so this triggered pair doesn't have
    /// to wait for `run_next_check` to drain whatever is ahead of it
    /// in the priority queue.
    const auto st = state_.load(std::memory_order_acquire);
    if (st == SessionState::Checking || st == SessionState::Connected) {
        send_check(check_list_.back());
    }
}

// ── Nomination + keepalive (strand) ─────────────────────────────────────────

NominationMetrics IceSession::nomination_metrics() const noexcept {
    NominationMetrics m{};
    if (state_.load(std::memory_order_acquire) != SessionState::Connected) {
        return m;
    }
    /// Local/remote type + relay flag live behind the nominated_mu_;
    /// RTT is atomic. Snap the lock-guarded fields under the mutex
    /// then release before the atomic read to keep the critical
    /// section minimal.
    {
        std::lock_guard lk(nominated_mu_);
        m.uses_relay    = uses_relay_;
        m.local_type    = nominated_local_type_;
        m.remote_type   = nominated_remote_type_;
    }
    m.transport = nominated_transport_.load(std::memory_order_acquire);
    m.rtt_us    = rtt_ewma_us_.load(std::memory_order_relaxed);
    m.nominated = true;
    return m;
}

IceSession::CandidateCounts IceSession::candidate_counts() const {
    CandidateCounts c{};
    /// Tally local under `local_state_mu_` (publishes strand-writes).
    {
        std::lock_guard lk(local_state_mu_);
        for (const auto& cand : local_candidates_) {
            switch (cand.type) {
                case CandidateType::Host:
                case CandidateType::HostMdns: ++c.local_host;  break;
                case CandidateType::Srflx:    ++c.local_srflx; break;
                case CandidateType::Relay:    ++c.local_relay; break;
                case CandidateType::Prflx:    ++c.local_prflx; break;
            }
        }
    }
    /// `remote_candidates_` is strand-only; bounce a counting lambda
    /// onto the strand and block on the future. Callers must not
    /// invoke from the strand itself — see header doc.
    std::promise<void> p;
    auto fut = p.get_future();
    asio::post(strand_, [&]() {
        for (const auto& cand : remote_candidates_) {
            switch (cand.type) {
                case CandidateType::Host:
                case CandidateType::HostMdns: ++c.remote_host;  break;
                case CandidateType::Srflx:    ++c.remote_srflx; break;
                case CandidateType::Relay:    ++c.remote_relay; break;
                case CandidateType::Prflx:    ++c.remote_prflx; break;
            }
        }
        p.set_value();
    });
    fut.wait();
    return c;
}

void IceSession::on_nominated(const std::string& ip, uint16_t port, bool relay,
                                 gn_conn_id_t cid, TransportType transport) {
    ICE_DBG("nominated", "peer=%s %s:%u relay=%d cid=%llu tx=%d",
            peer_id_.c_str(), ip.c_str(), port, relay ? 1 : 0,
            static_cast<unsigned long long>(cid),
            static_cast<int>(transport));
    check_timer_.cancel();
    state_.store(SessionState::Connected, std::memory_order_release);
    consent_missed_.store(0, std::memory_order_release);
    consent_recovery_attempts_ = 0;
    /// Successful nomination clears the auto-restart budget — a session
    /// that recovered after a transient outage gets a fresh attempt
    /// allowance for the next one.
    auto_restart_attempts_ = 0;
    auto_restart_last_     = std::chrono::steady_clock::time_point{};
    nominated_cid_.store(cid, std::memory_order_release);
    /// Look up the cid's transport so subsequent `send()` /
    /// `on_keepalive` drives the correct carrier. The cid was opened
    /// by `ensure_remote_cid` or `ensure_remote_tcp_cid` during
    /// gather / checks; both stamp the transport into
    /// `cid_to_endpoint_`.
    /// Transport is dictated by the winning CheckPair, not derived by
    /// looking the cid up in `cid_to_endpoint_*_` maps. The composer
    /// wrapping that owns `carrier_` and `carrier_tcp_` can hand the
    /// same cid value back from both `connect()` paths — they are
    /// composer-side ids tagged with the high bit, not the underlying
    /// link's UDP/TCP socket id — so the lookup is ambiguous when both
    /// maps have entries for the value. The caller (the per-pair
    /// handler in `handle_check_response` / triggered-check / agressive-
    /// nomination paths) has the unambiguous answer in
    /// `pair.transport_type`.
    nominated_transport_.store(transport, std::memory_order_release);
    {
        std::lock_guard lk(nominated_mu_);
        nominated_ip_ = ip;
        nominated_port_ = port;
        uses_relay_ = relay;
    }

    /// RFC 5766 §11 fast path: if the nominated pair routes through
    /// TURN, request a channel binding for the peer endpoint. After
    /// the server confirms the bind, subsequent application data on
    /// this path rides ChannelData (4-byte header) instead of full
    /// Send-Indication wrappers (~36 bytes). Per-packet savings
    /// matter most for small payloads and high-frequency streams
    /// (audio, gaming) — exactly the workloads operators tend to
    /// route through TURN.
    if (relay && turn_) {
        turn_->bind_channel(ip, port);
    }

    /// Drain any app payloads the L2 buffered through `send()` while
    /// we were still gathering / checking. Must happen AFTER state_ is
    /// flipped to Connected and `nominated_cid_` is stamped: the body
    /// of `send_on_strand` reads both. Run BEFORE `on_connected` so
    /// the L2's CONN_UP-driven traffic queues behind anything that
    /// rode the initial connect surface.
    flush_pending_app_data();

    if (callbacks_.on_connected)
        callbacks_.on_connected(peer_id_, ip, port);

    start_keepalive();

    if (cfg_.pmtu_active_probing && !pmtu_probe_) {
        pmtu_probe_ = std::make_unique<PathMtuProbe>(
            static_cast<std::size_t>(cfg_.path_mtu),
            cfg_.pmtu_search_steps);
        start_path_mtu_probe();
    }
}

void IceSession::start_path_mtu_probe() {
    if (!pmtu_probe_) return;
    if (state_.load(std::memory_order_acquire) != SessionState::Connected) return;
    if (pmtu_inflight_) return;

    const auto next = pmtu_probe_->next_probe_size();
    if (!next) {
        effective_mtu_.store(static_cast<std::uint32_t>(pmtu_probe_->effective_mtu()),
                              std::memory_order_release);
        return;
    }

    auto cid = nominated_cid_.load(std::memory_order_acquire);
    if (cid == 0 || !carrier_) return;

    /// Probe payload: STUN binding request padded to the candidate
    /// wire size with UNKNOWN-ATTRIBUTES filler. MESSAGE-INTEGRITY +
    /// FINGERPRINT keep the response routable through the per-cid
    /// dispatcher's integrity gate. Username is the standard ICE
    /// `<remote-ufrag>:<local-ufrag>` form so the peer treats the
    /// probe as an ordinary connectivity check.
    auto txn = generate_txn_id();
    pmtu_inflight_txn_ = txn;
    pmtu_inflight_     = true;

    StunBuilder builder(STUN_BINDING_REQUEST);
    builder.set_txn_id(txn)
            .add_username(remote_ufrag_ + ":" + local_ufrag_)
            .add_priority(0);
    if (controlling_) {
        builder.add_ice_controlling(tiebreaker_);
    } else {
        builder.add_ice_controlled(tiebreaker_);
    }
    builder.add_padding_to(*next)
            .add_integrity(remote_pwd_)
            .add_fingerprint();
    auto msg = builder.build();
    (void)carrier_->send(cid, msg);

    pmtu_probe_timer_.expires_after(
        std::chrono::milliseconds(cfg_.pmtu_probe_timeout_ms));
    pmtu_probe_timer_.async_wait(asio::bind_executor(strand_,
        [this, self = shared_from_this()](const std::error_code& ec) {
            if (ec) return;
            on_path_mtu_probe_timeout();
        }));
}

void IceSession::on_path_mtu_probe_timeout() {
    if (!pmtu_probe_ || !pmtu_inflight_) return;
    pmtu_inflight_ = false;
    pmtu_probe_->on_probe_loss();
    effective_mtu_.store(static_cast<std::uint32_t>(pmtu_probe_->effective_mtu()),
                          std::memory_order_release);
    if (!pmtu_probe_->is_complete()) {
        start_path_mtu_probe();
    }
}

void IceSession::start_keepalive() {
    on_keepalive();
}

bool IceSession::notify_consent_loss_for_test() {
    /// Consent recovery exhausted. Before declaring Failed, give
    /// `auto_restart_on_consent_loss` a turn: regenerate the
    /// ufrag/pwd pair, drop pending state, and re-enter Gathering.
    /// The backoff coalesces a burst of missed keepalives into one
    /// restart so a single network blip does not chew through the
    /// attempt budget.
    if (cfg_.auto_restart_on_consent_loss &&
        auto_restart_attempts_ <
            static_cast<uint32_t>(cfg_.auto_restart_max_attempts)) {
        const auto now = std::chrono::steady_clock::now();
        const auto since_last = now - auto_restart_last_;
        const auto backoff = std::chrono::milliseconds(
            cfg_.auto_restart_backoff_ms);
        if (auto_restart_last_ == std::chrono::steady_clock::time_point{}
            || since_last >= backoff) {
            ++auto_restart_attempts_;
            auto_restart_last_ = now;
            consent_missed_.store(0, std::memory_order_release);
            /// Surface a CONN_DOWN-equivalent path event to the
            /// strategy chain before the restart fires. Carries
            /// the reason token + attempt counters so consumers
            /// can decide whether to deprioritise this conn or
            /// fire an upper-layer reconnect.
            if (callbacks_.on_auto_restart) {
                callbacks_.on_auto_restart(
                    peer_id_, "consent-loss",
                    auto_restart_attempts_,
                    static_cast<std::uint32_t>(
                        cfg_.auto_restart_max_attempts));
            }
            /// `restart()` schedules its body via dispatch on the
            /// strand. We are already on the strand here (keepalive
            /// timer handler), but `dispatch` short-circuits to a
            /// direct call when invoked from inside the executor
            /// so the reset still happens before we return.
            restart();
            return true;
        }
        /// Inside the backoff window — silently drop this consent
        /// loss; the in-flight restart already covers the burst.
        consent_missed_.store(0, std::memory_order_release);
        return true;
    }

    state_.store(SessionState::Failed, std::memory_order_release);
    if (callbacks_.on_failed)
        callbacks_.on_failed(peer_id_, ETIMEDOUT);
    return false;
}

void IceSession::on_keepalive() {
    if (state_.load(std::memory_order_acquire) != SessionState::Connected) return;
    /// Lite agents per RFC 8445 §2.7 do not run consent freshness
    /// (RFC 7675 §5.1 exempts them). Skip the probe + counter advance;
    /// the controller drives liveness from its side.
    if (cfg_.lite_mode) return;

    auto missed = consent_missed_.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (missed >= static_cast<uint32_t>(cfg_.consent_max_failures)) {
        if (consent_recovery_attempts_ <
                static_cast<uint32_t>(cfg_.consent_max_recovery)) {
            ++consent_recovery_attempts_;
            consent_missed_.store(0, std::memory_order_release);

            state_.store(SessionState::Checking, std::memory_order_release);
            build_check_list();
            begin_checks();
            return;
        }

        (void)notify_consent_loss_for_test();
        return;
    }

    auto cid = nominated_cid_.load(std::memory_order_acquire);
    if (cid != 0) {
        auto txn = generate_txn_id();
        auto msg = StunBuilder(STUN_BINDING_REQUEST)
            .set_txn_id(txn)
            .build();
        const auto tx = nominated_transport_.load(std::memory_order_acquire);
        if (transport_is_tcp(tx)) {
            if (carrier_tcp_) {
                const auto framed = frame_tcp_stun(msg);
                (void)carrier_tcp_->send(cid, framed);
            }
        } else if (carrier_) {
            (void)carrier_->send(cid, msg);
        }
    }

    keepalive_timer_.expires_after(std::chrono::seconds(cfg_.keepalive_interval_s));
    auto self = shared_from_this();
    keepalive_timer_.async_wait(asio::bind_executor(strand_,
        [this, self](const std::error_code& ec) {
            if (!ec) on_keepalive();
        }));
}

// ── Candidate address helpers ───────────────────────────────────────────────

std::string Candidate::address_str() const {
    /// HostMdns candidates carry the `.local` name as their
    /// human-readable identifier until the resolver fills in the IP.
    /// Returning the hostname keeps logs / dedup keys
    /// (`endpoint_key`) stable across the unresolved → resolved
    /// transition: a deduplication key built from an empty-IP
    /// candidate would collapse multiple distinct names down to
    /// `0.0.0.0:<port>`.
    if (type == CandidateType::HostMdns && !hostname.empty()) {
        return hostname;
    }
    if (family == AddressFamily::IPv4) {
        struct in_addr in;
        std::memcpy(&in, addr.data(), 4);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in, buf, sizeof(buf));
        return buf;
    } else {
        struct in6_addr in6;
        std::memcpy(&in6, addr.data(), 16);
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
        return buf;
    }
}

void Candidate::set_address(const std::string& addr_str) {
    struct in_addr in4;
    struct in6_addr in6;
    if (inet_pton(AF_INET, addr_str.c_str(), &in4) == 1) {
        family = AddressFamily::IPv4;
        std::memcpy(addr.data(), &in4, 4);
    } else if (inet_pton(AF_INET6, addr_str.c_str(), &in6) == 1) {
        family = AddressFamily::IPv6;
        std::memcpy(addr.data(), &in6, 16);
    }
}

} // namespace gn::link::ice
