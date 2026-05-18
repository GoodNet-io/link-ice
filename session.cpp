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

#include <asio/bind_executor.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
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
                         std::shared_ptr<MdnsManager> mdns)
    : io_(io), strand_(asio::make_strand(io.get_executor())),
      carrier_(carrier), carrier_tcp_(carrier_tcp),
      carrier_tls_(carrier_tls), cfg_(cfg),
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
    if (carrier_) {
        for (auto& [cid, _ep] : cid_to_endpoint_) {
            (void)carrier_->unsubscribe_data(cid);
            (void)carrier_->disconnect(cid);
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

void IceSession::gather() {
    /// Synchronous prefix runs on the caller before any strand work is
    /// posted, so direct `local_candidates_` mutation is race-free.
    state_.store(SessionState::Gathering, std::memory_order_release);
    gather_host_candidates();

    /// TURN allocation runs in parallel with STUN; the relay candidate
    /// arrives via callback once `gn.ice.turn` answers.
    gather_relay();

    if (cfg_.stun_servers.empty()) {
        on_gathering_complete();
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
    if (state_.load(std::memory_order_acquire) != SessionState::Connected) return;
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);

    auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
    asio::post(strand_, [this, self = shared_from_this(), buf] {
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
            turn_->send_indication(ip, port, *buf);
            return;
        }

        auto cid = nominated_cid_.load(std::memory_order_acquire);
        if (cid == 0) {
            cid = ensure_remote_cid(ip, port);
            if (cid == 0) return;
            nominated_cid_.store(cid, std::memory_order_release);
        }
        if (carrier_) (void)carrier_->send(cid, *buf);
    });
}

void IceSession::add_remote_candidates(const std::string& ufrag,
                                         const std::string& pwd,
                                         std::vector<Candidate> cands,
                                         bool end_of_candidates) {
    asio::dispatch(strand_, [self = shared_from_this(),
                              ufrag, pwd,
                              cands = std::move(cands),
                              end_of_candidates]() mutable {
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

        /// Merge each new candidate, deduping by (ip, port, type).
        /// Address comparison goes through `address_str()` to keep
        /// IPv4 / IPv6 logic in one place.
        for (auto& c : cands) {
            const auto ip = c.address_str();
            const bool dup = std::any_of(
                self->remote_candidates_.begin(),
                self->remote_candidates_.end(),
                [&](const Candidate& e) {
                    return e.address_str() == ip
                        && e.port == c.port
                        && e.type == c.type;
                });
            if (!dup) self->remote_candidates_.push_back(std::move(c));
        }

        const auto cur = self->state_.load(std::memory_order_acquire);
        if (self->remote_candidates_.empty()) return;

        if (cur == SessionState::WaitingRemote ||
            cur == SessionState::Gathering) {
            if (!self->local_candidates_.empty()) {
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

        self->local_ufrag_ = IceSession::generate_ufrag();
        self->local_pwd_   = IceSession::generate_pwd();

        /// Drop the previous mDNS registration so the post-restart
        /// gather can mint a fresh `<uuid>.local` per the draft.
        /// The new gather phase calls `register_name` again under
        /// `gather_host_candidates`.
        if (self->mdns_ && !self->mdns_local_hostname_.empty()) {
            self->mdns_->unregister_name(self->mdns_local_hostname_);
            self->mdns_local_hostname_.clear();
        }

        self->local_candidates_.clear();
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
        if (self->carrier_) {
            for (auto& [cid, _ep] : self->cid_to_endpoint_) {
                (void)self->carrier_->unsubscribe_data(cid);
                (void)self->carrier_->disconnect(cid);
            }
        }
        self->endpoint_to_cid_.clear();
        self->cid_to_endpoint_.clear();
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
        if (self->carrier_) {
            for (auto& [cid, _ep] : self->cid_to_endpoint_) {
                (void)self->carrier_->unsubscribe_data(cid);
                (void)self->carrier_->disconnect(cid);
            }
        }
        self->endpoint_to_cid_.clear();
        self->cid_to_endpoint_.clear();
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
                local_candidates_.push_back(c);
            }
        }
    }
    freeifaddrs(iflist);

    gather_tcp_host_candidates();
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

    /// Walk the freshly-emitted UDP host candidates, mirroring each as
    /// TCP active / passive / simultaneous-open. Iteration uses an
    /// index snapshot because the loop body grows the same vector.
    const std::size_t udp_end = local_candidates_.size();
    static constexpr std::array<TransportType, 3> kTcpVariants = {
        TransportType::TcpActive,
        TransportType::TcpPassive,
        TransportType::TcpSimultaneousOpen,
    };
    for (std::size_t i = 0; i < udp_end; ++i) {
        const auto& src = local_candidates_[i];
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
    cid_to_endpoint_[cid] = EndpointInfo{ip, port, TransportType::Udp};
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
    cid_to_endpoint_[cid] = EndpointInfo{ip, port, TransportType::TcpActive};
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
        on_carrier_data(cid, frame);
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
        std::string host = server;
        std::uint16_t port = 3478;
        auto colon = server.rfind(':');
        if (colon != std::string::npos) {
            host = server.substr(0, colon);
            try {
                auto port_val = std::stoul(server.substr(colon + 1));
                if (port_val > 65535) continue;
                port = static_cast<std::uint16_t>(port_val);
            } catch (...) {
                continue;
            }
        }
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
    pending_stun_probes_.clear();
    /// Resolve + send one Binding Request per configured STUN server in
    /// a single batch. All probes share the same UDP source port (the
    /// host candidate carrier) so any response routes back to this
    /// session's per-cid `on_carrier_data`. First valid
    /// XOR-MAPPED-ADDRESS wins; remaining probes' responses arrive
    /// later and are dropped because `pending_stun_probes_` is cleared
    /// on first success.
    for (auto& server : cfg_.stun_servers) {
        std::string host = server;
        uint16_t    port = 3478;
        auto colon = server.rfind(':');
        if (colon != std::string::npos) {
            host = server.substr(0, colon);
            try {
                auto port_val = std::stoul(server.substr(colon + 1));
                if (port_val > 65535) continue;
                port = static_cast<uint16_t>(port_val);
            } catch (...) {
                continue;
            }
        }

        auto cid = ensure_remote_cid(host, port);
        if (cid == 0) continue;

        auto txn = generate_txn_id();
        auto msg = StunBuilder(STUN_BINDING_REQUEST).set_txn_id(txn).build();
        pending_stun_probes_.push_back(txn);
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
            if (state_.load(std::memory_order_acquire) !=
                SessionState::Gathering) {
                return;
            }
            /// Every probe timed out — proceed without srflx. host +
            /// relay candidates (if any) still drive connectivity
            /// checks; nomination will succeed if peers can reach each
            /// other directly or through TURN.
            pending_stun_probes_.clear();
            on_gathering_complete();
        }));
}

void IceSession::handle_gather_response(const StunMessage& msg,
                                            TransportType src_transport) {
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
        local_candidates_.push_back(c);
    }

    /// Drive the FSM forward as soon as the first valid srflx lands —
    /// the stride-detection batch fills in afterwards on the strand.
    if (!already_have_srflx) {
        gather_timer_.cancel();
        on_gathering_complete();
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
                auto client = weak_client.lock();
                if (!client) return;
                std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
                asio::post(self->strand_,
                    [client, copy = std::move(copy)] {
                        client->on_inbound(copy);
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
        /// Last attempt failed and there are no more servers. The
        /// gather phase has already moved on (host + STUN paths run
        /// concurrently with TURN) so no further action needed beyond
        /// surfacing the empty relay slot.
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
            self->local_candidates_.push_back(std::move(c));
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
            }
        });
    };

    auto on_data = [weak_self](const std::string& /*ip*/,
                                uint16_t /*port*/,
                                std::span<const uint8_t> data) {
        auto self = weak_self.lock();
        if (!self) return;
        self->last_activity_.store(std::chrono::steady_clock::now(),
                                     std::memory_order_release);
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
    std::erase_if(local_candidates_, [](const Candidate& c) {
        return c.type == CandidateType::Relay;
    });

    turn_ = std::move(client);
    cfg_.turn = new_cfg;
    const auto relay = turn_->relayed_address();

    Candidate c{};
    c.type = CandidateType::Relay;
    c.port = relay.port;
    c.set_address(relay.ip);
    c.priority = compute_priority(CandidateType::Relay, 65535, 1);
    if (candidate_allowed(c.type, c.family, cfg_.candidate_filter_flags)) {
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
    /// Drop any still-pending STUN probes and cancel the umbrella
    /// timeout — irrelevant whether the gather succeeded (first
    /// XOR-MAPPED-ADDRESS arrived) or timed out / had no servers.
    pending_stun_probes_.clear();
    gather_timer_.cancel();

    if (state_.load(std::memory_order_acquire) == SessionState::Gathering) {
        if (!remote_candidates_.empty()) {
            state_.store(SessionState::Checking, std::memory_order_release);
            build_check_list();
            begin_checks();
        } else {
            state_.store(SessionState::WaitingRemote, std::memory_order_release);
        }
    }
    if (callbacks_.on_gathered)
        callbacks_.on_gathered(peer_id_);
}

// ── Connectivity checks (strand) ────────────────────────────────────────────

void IceSession::build_check_list() {
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
            CheckPair pair;
            pair.local = local;
            pair.remote = remote;
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
                    check_list_.push_back(pp);
                }
            }
        }
    }
    std::ranges::sort(check_list_, [](const auto& a, const auto& b) {
        return a.priority > b.priority;
    });
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
        if (p.local.family == AddressFamily::IPv4 && !fired_v4) {
            send_check(p);
            fired_v4 = true;
        } else if (p.local.family == AddressFamily::IPv6 && !fired_v6) {
            send_check(p);
            fired_v6 = true;
        }
    }

    run_next_check();
}

void IceSession::run_next_check() {
    if (state_.load(std::memory_order_acquire) != SessionState::Checking) return;

    if (current_check_ >= check_list_.size()) {
        state_.store(SessionState::Failed, std::memory_order_release);
        if (callbacks_.on_failed)
            callbacks_.on_failed(peer_id_, ETIMEDOUT);
        return;
    }

    auto& pair = check_list_[current_check_];
    if (pair.retries >= static_cast<uint8_t>(cfg_.max_check_retries)) {
        current_check_++;
        asio::post(strand_, [this, self = shared_from_this()] { run_next_check(); });
        return;
    }

    send_check(pair);

    check_timer_.expires_after(std::chrono::milliseconds(cfg_.check_interval_ms));
    check_timer_.async_wait(asio::bind_executor(strand_,
        [this, self = shared_from_this()](const std::error_code& ec) {
            if (!ec) run_next_check();
        }));
}

void IceSession::send_check(CheckPair& pair) {
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

    auto cid = ensure_remote_cid(pair.remote.address_str(), pair.remote.port);
    if (cid == 0 || !carrier_) return;
    (void)carrier_->send(cid, msg);
}

// ── Receive + dispatch (strand) ─────────────────────────────────────────────

void IceSession::on_carrier_data(gn_conn_id_t cid,
                                    std::span<const std::uint8_t> data) {
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);

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

        /// Gather-phase responses come from operator-configured STUN
        /// servers that do NOT share our local pwd, so they carry no
        /// MESSAGE-INTEGRITY. The transaction-id match in
        /// `handle_gather_response` provides the necessary
        /// off-path protection (attacker must guess a 12-byte id to
        /// inject a fake srflx). Peer-side messages — checks, consent,
        /// nomination — still pass through the integrity gate below.
        if (st == SessionState::Gathering &&
            parsed->msg_type == STUN_BINDING_RESPONSE) {
            TransportType src_tx = TransportType::Udp;
            if (auto eit = cid_to_endpoint_.find(cid);
                eit != cid_to_endpoint_.end()) {
                src_tx = eit->second.transport;
            }
            handle_gather_response(*parsed, src_tx);
            return;
        }

        /// STUN messages from a peer must carry a MESSAGE-INTEGRITY
        /// attribute and pass HMAC verification with our local pwd.
        /// Without this an unauthenticated UDP attacker who knows the
        /// ICE port can answer/initiate binding checks, hijack
        /// nomination, and redirect post-handshake traffic. Drop
        /// anything that lacks integrity OR fails the HMAC.
        if (!parsed->has_integrity || !verify_integrity(data, local_pwd_)) {
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
            auto resp = StunBuilder(STUN_BINDING_RESPONSE)
                .set_txn_id(parsed->txn_id)
                .add_integrity(local_pwd_)
                .add_fingerprint()
                .build();
            /// Reply rides the same cid the request arrived on — that
            /// is exactly the peer's endpoint regardless of NAT
            /// rewriting between announced candidate and actual src.
            if (carrier_) (void)carrier_->send(cid, resp);

            std::string peer_ip;
            std::uint16_t peer_port = 0;
            if (auto eit = cid_to_endpoint_.find(cid);
                eit != cid_to_endpoint_.end()) {
                peer_ip   = eit->second.ip;
                peer_port = eit->second.port;
            }

            if (parsed->use_candidate && !controlling_) {
                /// Use the endpoint info stashed by the per-cid map;
                /// that is the address composer_connect was called
                /// with, which matches the peer's announced candidate.
                if (!peer_ip.empty()) {
                    on_nominated(peer_ip, peer_port, /*relay=*/false, cid);
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
    if (state_.load(std::memory_order_acquire) != SessionState::Checking) return;

    for (auto& pair : check_list_) {
        if (pair.txn_id == msg.txn_id) {
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
            bool nom_relay = pair.remote.type == CandidateType::Relay;
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
                    local_candidates_.push_back(prflx);
                }
            }

            const bool was_valid_before = pair.valid;
            pair.valid = true;

            if (controlling_) {
                if (cfg_.aggressive_nomination
                    || pair.nominee_check_sent) {
                    /// Aggressive: every successful check nominates.
                    /// Regular: only the nominee follow-up commits.
                    const auto cid = ensure_remote_cid(nom_ip, nom_port);
                    on_nominated(nom_ip, nom_port, nom_relay, cid);
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
    m.rtt_us    = rtt_ewma_us_.load(std::memory_order_relaxed);
    m.nominated = true;
    return m;
}

void IceSession::on_nominated(const std::string& ip, uint16_t port, bool relay,
                                 gn_conn_id_t cid) {
    check_timer_.cancel();
    state_.store(SessionState::Connected, std::memory_order_release);
    consent_missed_.store(0, std::memory_order_release);
    consent_recovery_attempts_ = 0;
    nominated_cid_.store(cid, std::memory_order_release);
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

        state_.store(SessionState::Failed, std::memory_order_release);
        if (callbacks_.on_failed)
            callbacks_.on_failed(peer_id_, ETIMEDOUT);
        return;
    }

    auto cid = nominated_cid_.load(std::memory_order_acquire);
    if (cid != 0 && carrier_) {
        auto txn = generate_txn_id();
        auto msg = StunBuilder(STUN_BINDING_REQUEST)
            .set_txn_id(txn)
            .build();
        (void)carrier_->send(cid, msg);
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
