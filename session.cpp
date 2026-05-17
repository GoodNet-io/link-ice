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
                         IceSessionCallbacks callbacks)
    : io_(io), strand_(asio::make_strand(io.get_executor())),
      carrier_(carrier), carrier_tcp_(carrier_tcp),
      carrier_tls_(carrier_tls), cfg_(cfg),
      peer_id_(peer_id), controlling_(controlling),
      callbacks_(std::move(callbacks)),
      check_timer_(strand_),
      gather_timer_(strand_),
      keepalive_timer_(strand_),
      last_activity_(std::chrono::steady_clock::now()) {
    local_ufrag_ = generate_ufrag();
    local_pwd_   = generate_pwd();

    randombytes_buf(&tiebreaker_, sizeof(tiebreaker_));
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
    if (turn_) turn_->close();
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
    });
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

        self->local_ufrag_ = IceSession::generate_ufrag();
        self->local_pwd_   = IceSession::generate_pwd();

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
        if (self->turn_) self->turn_->close();
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
    cid_to_endpoint_[cid] = EndpointInfo{ip, port};
    return cid;
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

void IceSession::handle_gather_response(const StunMessage& msg) {
    /// Match by transaction id. Linear scan is fine — `cfg_.stun_servers`
    /// is operator-bounded (single-digit).
    auto it = std::find(pending_stun_probes_.begin(),
                         pending_stun_probes_.end(), msg.txn_id);
    if (it == pending_stun_probes_.end()) return;
    if (!msg.xor_mapped) return;

    /// First response wins. Drop the rest by clearing the pending set
    /// + cancel the umbrella timeout.
    pending_stun_probes_.clear();
    gather_timer_.cancel();

    Candidate c{};
    c.type     = CandidateType::Srflx;
    c.priority = compute_priority(CandidateType::Srflx, 65535, 1);

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

    if (candidate_allowed(c.type, c.family,
                           cfg_.candidate_filter_flags)) {
        local_candidates_.push_back(c);
    }
    on_gathering_complete();
}

void IceSession::gather_relay() {
    if (cfg_.turn.server.empty()) return;
    /// Operator may have disabled relay candidates via
    /// `ice.candidate_filters = ["host-only"]` etc. Short-circuit
    /// the entire TURN allocation in that case — saves a STUN
    /// request roundtrip and avoids holding a TURN refresh timer
    /// for a candidate we'd just drop.
    if ((cfg_.candidate_filter_flags & kCandidateFilterHostOnly) != 0) return;

    /// Pick the carrier scheme for the TURN server endpoint. Order
    /// of precedence: TLS > TCP > UDP. Each higher tier requires its
    /// own carrier resolved by IceLink; if missing, we silently fall
    /// back so a misconfigured operator still gets a working relay
    /// path instead of a hard failure.
    const bool want_tls = cfg_.turn.tls_transport
                            && carrier_tls_ != nullptr;
    const bool want_tcp = !want_tls
                            && cfg_.turn.tcp_transport
                            && carrier_tcp_ != nullptr;
    const bool want_stream = want_tls || want_tcp;
    auto* turn_carrier = want_tls ? carrier_tls_
                          : want_tcp ? carrier_tcp_
                          : carrier_;
    if (!turn_carrier) return;

    gn_conn_id_t turn_cid = 0;
    if (!want_stream) {
        /// UDP path: share the session's cid maps so on_carrier_data
        /// routes inbound bytes through the same dispatcher that
        /// serves STUN / check traffic.
        turn_cid = ensure_remote_cid(cfg_.turn.server, cfg_.turn.port);
        if (turn_cid == 0) return;
    } else {
        /// TCP path: bypass the dispatcher and route bytes directly
        /// to `turn_->on_inbound`. Cid namespaces differ between
        /// carriers (each composer allocates from its own counter),
        /// so a shared dispatcher would risk collision with UDP
        /// cids. Direct routing also keeps the TCP carrier's
        /// subscribe_data lifetime scoped to TURN's needs.
        const auto uri = endpoint_uri(cfg_.turn.server, cfg_.turn.port);
        if (turn_carrier->connect(uri, &turn_cid) != GN_OK
            || turn_cid == GN_INVALID_ID) {
            return;
        }
        auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
        (void)turn_carrier->on_data(
            turn_cid,
            [weak_self](gn_conn_id_t /*c*/,
                         std::span<const std::uint8_t> bytes) {
                auto self = weak_self.lock();
                if (!self) return;
                std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
                asio::post(self->strand_,
                    [self, copy = std::move(copy)] {
                        if (self->turn_) self->turn_->on_inbound(copy);
                    });
            });
    }

    auto weak_self = std::weak_ptr<IceSession>(shared_from_this());
    turn_ = std::make_shared<TurnClient>(
        io_, turn_carrier, turn_cid, cfg_.turn,
        // Data callback — relay'd data from peer.
        [weak_self](const std::string& /*ip*/,
                     uint16_t /*port*/,
                     std::span<const uint8_t> data) {
            auto self = weak_self.lock();
            if (!self) return;
            self->last_activity_.store(std::chrono::steady_clock::now(),
                                         std::memory_order_release);
            if (self->callbacks_.on_data)
                self->callbacks_.on_data(self->peer_id_, data);
        },
        // Allocate callback — relay address available, add as candidate.
        [weak_self](const std::string& relay_ip, uint16_t relay_port) {
            auto self = weak_self.lock();
            if (!self) return;
            Candidate c{};
            c.type = CandidateType::Relay;
            c.port = relay_port;
            c.set_address(relay_ip);
            c.priority = compute_priority(CandidateType::Relay, 65535, 1);

            asio::post(self->strand_, [self, c = std::move(c)]() mutable {
                if (!candidate_allowed(c.type, c.family,
                                        self->cfg_.candidate_filter_flags)) {
                    return;
                }
                self->local_candidates_.push_back(std::move(c));

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
        });
    turn_->allocate();
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
    for (auto& local : local_candidates_) {
        for (auto& remote : remote_candidates_) {
            if (local.family != remote.family) continue;
            CheckPair pair;
            pair.local = local;
            pair.remote = remote;
            pair.priority = pair_priority(local.priority, remote.priority, controlling_);
            pair.txn_id = generate_txn_id();
            check_list_.push_back(pair);
        }
    }
    std::ranges::sort(check_list_, [](const auto& a, const auto& b) {
        return a.priority > b.priority;
    });
    current_check_ = 0;
}

void IceSession::begin_checks() {
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
            handle_gather_response(*parsed);
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
}

void IceSession::start_keepalive() {
    on_keepalive();
}

void IceSession::on_keepalive() {
    if (state_.load(std::memory_order_acquire) != SessionState::Connected) return;

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
