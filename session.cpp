// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/session.cpp
/// @brief  ICE session FSM implementation per RFC 8445.
///
/// Threading model:
/// - Every state mutation runs on `strand_` (or during the synchronous
///   prefix of `gather()` before any strand work has been posted).
/// - `nominated_mu_` guards the nominated-pair tuple so the hot send
///   path can sample without bouncing off the strand.
/// - `close()` is safe from any thread; it cancels timers and closes
///   the socket without touching FSM state on the strand.

#include "session.hpp"

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
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

IceSession::IceSession(asio::io_context& io, const IceConfig& cfg,
                         const std::string& peer_id, bool controlling,
                         IceSessionCallbacks callbacks)
    : io_(io), strand_(asio::make_strand(io.get_executor())),
      cfg_(cfg), peer_id_(peer_id), controlling_(controlling),
      callbacks_(std::move(callbacks)),
      check_timer_(strand_), socket_(strand_),
      keepalive_timer_(strand_),
      last_activity_(std::chrono::steady_clock::now()) {
    local_ufrag_ = generate_ufrag();
    local_pwd_   = generate_pwd();

    randombytes_buf(&tiebreaker_, sizeof(tiebreaker_));
}

IceSession::~IceSession() {
    /// If `close()` was already routed through the strand we are
    /// running on a fully-quiesced session and there is nothing
    /// async left to cancel; only the synchronous strand-free
    /// fallback below remains. Using `shared_from_this()` from a
    /// dtor would raise `bad_weak_ptr`, so the dtor takes the
    /// best-effort path: cancel timers and close the socket
    /// synchronously, accepting that an FD-close racing an in-flight
    /// reactor poll is harmless when the io_context has stopped.
    state_.store(SessionState::Failed, std::memory_order_release);
    std::error_code ec;
    check_timer_.cancel();
    keepalive_timer_.cancel();
    socket_.close(ec);
    if (turn_) turn_->close();
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
        stun_server_idx_ = 0;
        asio::post(strand_, [this, self = shared_from_this()] {
            try_next_stun_server();
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
        } else {
            asio::ip::udp::endpoint ep;
            std::error_code ec;
            auto addr = asio::ip::make_address(ip, ec);
            if (ec) return;
            ep = asio::ip::udp::endpoint(addr, port);

            socket_.async_send_to(asio::buffer(*buf), ep,
                asio::bind_executor(strand_,
                    [buf](const std::error_code&, size_t) {}));
        }
    });
}

void IceSession::close() {
    /// Mark the FSM dead synchronously so concurrent `send` calls
    /// stop touching the socket immediately. The actual cancel /
    /// close runs on the strand to avoid racing the worker's
    /// in-flight async ops on the socket file descriptor — TSan
    /// flags any `socket_ops::close` that races with a reactor-level
    /// poll on the same FD.
    state_.store(SessionState::Failed, std::memory_order_release);
    /// Capture a strong reference so the destructor cannot run while
    /// the strand-bound close work is queued; the work_guard the
    /// owning link holds keeps `ioc_.run()` draining until the
    /// dispatch completes.
    asio::dispatch(strand_, [self = shared_from_this()] {
        std::error_code ec;
        self->check_timer_.cancel();
        self->keepalive_timer_.cancel();
        self->socket_.close(ec);
        if (self->turn_) self->turn_->close();
    });
}

// ── Gathering (strand or synchronous) ───────────────────────────────────────

void IceSession::gather_host_candidates() {
    /// `socket_` is default-constructed in the ctor on the
    /// caller's thread; opening it on the strand here keeps every
    /// state-mutating syscall on the same executor so TSan's
    /// reactor-service contract holds. The constructor's only
    /// pre-condition is that the strand machinery exists.
    std::error_code open_ec;
    if (!socket_.is_open()) {
        socket_.open(asio::ip::udp::v4(), open_ec);
        if (open_ec) return;
    }
    std::error_code bind_ec;
    socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), bind_ec);
    /// `bind` is best-effort: a port already bound (re-gather after
    /// consent recovery) is fine, the existing port stays.
    std::uint16_t local_port = 0;
    std::error_code lep_ec;
    auto lep = socket_.local_endpoint(lep_ec);
    if (!lep_ec) local_port = lep.port();

    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return;

    for (auto* ifa = iflist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        Candidate c{};
        c.type = CandidateType::Host;
        c.port = local_port;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            c.family = AddressFamily::IPv4;
            std::memcpy(c.addr.data(), &sin->sin_addr, 4);
            c.priority = compute_priority(CandidateType::Host, 65535, 1);
            local_candidates_.push_back(c);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) continue;
            c.family = AddressFamily::IPv6;
            std::memcpy(c.addr.data(), &sin6->sin6_addr, 16);
            c.priority = compute_priority(CandidateType::Host, 65534, 1);
            local_candidates_.push_back(c);
        }
    }
    freeifaddrs(iflist);
}

void IceSession::try_next_stun_server() {
    if (stun_server_idx_ >= cfg_.stun_servers.size()) {
        on_gathering_complete();
        return;
    }

    auto& server = cfg_.stun_servers[stun_server_idx_];
    std::string host = server;
    uint16_t port = 3478;

    auto colon = server.rfind(':');
    if (colon != std::string::npos) {
        host = server.substr(0, colon);
        try {
            auto port_val = std::stoul(server.substr(colon + 1));
            if (port_val > 65535) {
                stun_server_idx_++;
                try_next_stun_server();
                return;
            }
            port = static_cast<uint16_t>(port_val);
        } catch (...) {
            stun_server_idx_++;
            try_next_stun_server();
            return;
        }
    }

    asio::ip::udp::resolver resolver(io_);
    std::error_code ec;
    auto results = resolver.resolve(host, std::to_string(port), ec);
    if (ec || results.begin() == results.end()) {
        stun_server_idx_++;
        try_next_stun_server();
        return;
    }

    auto stun_ep = *results.begin();
    auto txn = generate_txn_id();
    auto msg = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(txn)
        .build();

    socket_.async_send_to(asio::buffer(msg), stun_ep,
        asio::bind_executor(strand_,
            [](const std::error_code&, size_t) {}));

    auto timer = std::make_shared<asio::steady_timer>(strand_);
    timer->expires_after(std::chrono::seconds(stun_backoff_s_));

    auto self = shared_from_this();
    socket_.async_receive_from(
        asio::buffer(recv_buf_), sender_ep_,
        asio::bind_executor(strand_,
        [this, self, txn, timer](const std::error_code& recv_ec, size_t bytes) {
            timer->cancel();
            if (recv_ec) return;

            auto parsed = parse_stun(std::span(recv_buf_.data(), bytes));
            if (parsed && parsed->msg_type == STUN_BINDING_RESPONSE &&
                parsed->txn_id == txn && parsed->xor_mapped) {

                Candidate c{};
                c.type = CandidateType::Srflx;
                c.priority = compute_priority(CandidateType::Srflx, 65535, 1);

                struct in_addr addr4;
                if (inet_pton(AF_INET, parsed->xor_mapped->ip.c_str(), &addr4) == 1) {
                    c.family = AddressFamily::IPv4;
                    std::memcpy(c.addr.data(), &addr4, 4);
                } else {
                    struct in6_addr addr6;
                    inet_pton(AF_INET6, parsed->xor_mapped->ip.c_str(), &addr6);
                    c.family = AddressFamily::IPv6;
                    std::memcpy(c.addr.data(), &addr6, 16);
                }
                c.port = parsed->xor_mapped->port;

                local_candidates_.push_back(c);
                on_gathering_complete();
            }
        }));

    timer->async_wait(asio::bind_executor(strand_,
        [this, self](const std::error_code& timer_ec) {
            if (!timer_ec) {
                socket_.cancel();
                stun_backoff_s_ = std::min(stun_backoff_s_ * 2, MAX_STUN_BACKOFF_S);
                stun_server_idx_++;
                try_next_stun_server();
            }
        }));
}

void IceSession::gather_relay() {
    if (cfg_.turn.server.empty()) return;

    turn_ = std::make_shared<TurnClient>(
        io_, cfg_.turn,
        // Data callback — relay'd data from peer.
        [this, self = shared_from_this()](const std::string& /*ip*/,
                                           uint16_t /*port*/,
                                           std::span<const uint8_t> data) {
            last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);
            if (callbacks_.on_data)
                callbacks_.on_data(peer_id_, data);
        },
        // Allocate callback — relay address available, add as candidate.
        [this, self = shared_from_this()](const std::string& relay_ip, uint16_t relay_port) {
            Candidate c{};
            c.type = CandidateType::Relay;
            c.port = relay_port;
            c.set_address(relay_ip);
            c.priority = compute_priority(CandidateType::Relay, 65535, 1);

            asio::post(strand_, [this, self, c = std::move(c)]() mutable {
                local_candidates_.push_back(std::move(c));

                /// If remote candidates already arrived and we are
                /// already in the checking phase, fold the freshly-
                /// minted relay candidate into the check list and
                /// restart from the highest-priority pair.
                if (!remote_candidates_.empty() &&
                    state_.load(std::memory_order_acquire) == SessionState::Checking) {
                    build_check_list();
                    current_check_ = 0;
                    run_next_check();
                }
            });
        });
    turn_->allocate();
}

void IceSession::on_gathering_complete() {
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
    start_recv();
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
    std::string username = remote_ufrag_ + ":" + local_ufrag_;

    auto builder = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(pair.txn_id)
        .add_username(username)
        .add_priority(pair.local.priority);

    if (controlling_) {
        builder.add_ice_controlling(tiebreaker_);
        builder.add_use_candidate();
    } else {
        builder.add_ice_controlled(tiebreaker_);
    }

    auto msg = builder.add_integrity(remote_pwd_)
                      .add_fingerprint()
                      .build();

    auto addr_str = pair.remote.address_str();
    asio::ip::udp::endpoint ep;
    if (pair.remote.family == AddressFamily::IPv4) {
        ep = asio::ip::udp::endpoint(
            asio::ip::make_address_v4(addr_str), pair.remote.port);
    } else {
        ep = asio::ip::udp::endpoint(
            asio::ip::make_address_v6(addr_str), pair.remote.port);
    }

    socket_.async_send_to(asio::buffer(msg), ep,
        asio::bind_executor(strand_,
            [](const std::error_code&, size_t) {}));
}

// ── Receive + dispatch (strand) ─────────────────────────────────────────────

void IceSession::start_recv() {
    auto self = shared_from_this();
    socket_.async_receive_from(
        asio::buffer(recv_buf_), sender_ep_,
        asio::bind_executor(strand_,
        [this, self](const std::error_code& ec, size_t bytes) {
            if (!ec) {
                handle_recv(bytes);
                start_recv();
            }
        }));
}

void IceSession::handle_recv(size_t bytes) {
    last_activity_.store(std::chrono::steady_clock::now(), std::memory_order_release);

    auto data = std::span(recv_buf_.data(), bytes);

    auto parsed = parse_stun(data);
    if (parsed) {
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
            if (state_.load(std::memory_order_acquire) == SessionState::Connected) {
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
            socket_.async_send_to(asio::buffer(resp), sender_ep_,
                asio::bind_executor(strand_,
                    [](const std::error_code&, size_t) {}));

            if (parsed->use_candidate && !controlling_) {
                auto ip = sender_ep_.address().to_string();
                auto port = sender_ep_.port();
                on_nominated(ip, port, false);
            }
        }
        return;
    }

    if (state_.load(std::memory_order_acquire) == SessionState::Connected && callbacks_.on_data) {
        callbacks_.on_data(peer_id_, data);
    }
}

void IceSession::handle_check_response(const StunMessage& msg) {
    if (state_.load(std::memory_order_acquire) != SessionState::Checking) return;

    for (auto& pair : check_list_) {
        if (pair.txn_id == msg.txn_id) {
            /// RFC 8445 §7.2.5.3: discover peer reflexive candidates
            /// from XOR-MAPPED-ADDRESS in the binding response. This
            /// is the actual mapped address the peer sees — critical
            /// for symmetric NAT.
            std::string nom_ip = pair.remote.address_str();
            uint16_t nom_port = pair.remote.port;
            bool nom_relay = pair.remote.type == CandidateType::Relay;

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

            if (controlling_) {
                on_nominated(nom_ip, nom_port, nom_relay);
            }
            return;
        }
    }
}

// ── Nomination + keepalive (strand) ─────────────────────────────────────────

void IceSession::on_nominated(const std::string& ip, uint16_t port, bool relay) {
    check_timer_.cancel();
    state_.store(SessionState::Connected, std::memory_order_release);
    consent_missed_.store(0, std::memory_order_release);
    consent_recovery_attempts_ = 0;
    {
        std::lock_guard lk(nominated_mu_);
        nominated_ip_ = ip;
        nominated_port_ = port;
        uses_relay_ = relay;
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
        if (consent_recovery_attempts_ < MAX_CONSENT_RECOVERY) {
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

    std::string ip;
    uint16_t port;
    {
        std::lock_guard lk(nominated_mu_);
        ip = nominated_ip_;
        port = nominated_port_;
    }

    auto txn = generate_txn_id();
    auto msg = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(txn)
        .build();

    std::error_code make_addr_ec;
    auto addr = asio::ip::make_address(ip, make_addr_ec);
    if (make_addr_ec) return;
    asio::ip::udp::endpoint ep(addr, port);
    socket_.async_send_to(asio::buffer(msg), ep,
        asio::bind_executor(strand_,
            [](const std::error_code&, size_t) {}));

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
