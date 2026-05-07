// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/session.hpp
/// @brief  ICE session FSM per RFC 8445 — gathering, checks, nomination,
///         consent freshness.
///
/// Threading model: every state mutation runs on `strand_`; reads of
/// `state_` are atomic so `IceLink::send` can sample without a strand
/// hop. The nominated-pair tuple (ip / port / relay) is guarded by a
/// dedicated mutex so the hot send path doesn't hop strands either.

#include "candidate.hpp"
#include "stun.hpp"
#include "turn.hpp"

#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace gn::link::ice {

enum class SessionState : uint8_t {
    New,
    Gathering,
    WaitingRemote,
    Checking,
    Connected,
    Failed
};

constexpr const char* session_state_name(SessionState s) {
    switch (s) {
        case SessionState::New:           return "NEW";
        case SessionState::Gathering:     return "GATHERING";
        case SessionState::WaitingRemote: return "WAITING_REMOTE";
        case SessionState::Checking:      return "CHECKING";
        case SessionState::Connected:     return "CONNECTED";
        case SessionState::Failed:        return "FAILED";
    }
    return "UNKNOWN";
}

/// @brief ICE session configuration: STUN/TURN servers, timeouts, keepalive.
struct IceConfig {
    std::vector<std::string> stun_servers{};
    TurnConfig turn;
    int  session_timeout_s      = 10;
    int  keepalive_interval_s   = 20;
    int  consent_max_failures   = 3;
    int  check_interval_ms      = 50;
    int  max_check_retries      = 4;
};

/// @brief ICE candidate pair under connectivity check.
struct CheckPair {
    Candidate local;
    Candidate remote;
    uint64_t  priority;
    uint8_t   retries   = 0;
    bool      nominated = false;
    TransactionId txn_id;
};

/// Callbacks from ICE session to transport layer.
struct IceSessionCallbacks {
    std::function<void(const std::string& peer_id)> on_gathered;
    std::function<void(const std::string& peer_id,
                       const std::string& remote_ip, uint16_t remote_port)> on_connected;
    std::function<void(const std::string& peer_id, int error)> on_failed;
    std::function<void(const std::string& peer_id,
                       std::span<const uint8_t> data)> on_data;
};

/// @brief Per-peer ICE state machine — gathers candidates, runs
///        connectivity checks, owns the data path.
class IceSession : public std::enable_shared_from_this<IceSession> {
public:
    IceSession(asio::io_context& io, const IceConfig& cfg,
               const std::string& peer_id, bool controlling,
               IceSessionCallbacks callbacks);
    ~IceSession();

    /// Start candidate gathering.
    void gather();

    /// Set remote candidates (from signaling).
    void set_remote(const std::string& ufrag, const std::string& pwd,
                     std::vector<Candidate> candidates);

    /// Send data through the nominated pair.
    void send(std::span<const uint8_t> data);

    /// Close the session.
    void close();

    // Accessors
    SessionState state() const { return state_.load(std::memory_order_acquire); }
    const std::string& peer_id() const { return peer_id_; }
    bool is_controlling() const { return controlling_; }

    const std::vector<Candidate>& local_candidates() const { return local_candidates_; }
    const std::string& local_ufrag() const { return local_ufrag_; }
    const std::string& local_pwd() const { return local_pwd_; }

    std::chrono::steady_clock::time_point last_activity() const {
        return last_activity_.load(std::memory_order_acquire);
    }

private:
    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    IceConfig cfg_;
    std::string peer_id_;
    bool controlling_;
    IceSessionCallbacks callbacks_;

    std::atomic<SessionState> state_{SessionState::New};

    // ── State machine data (strand-only access) ─────────────────────────────
    std::string local_ufrag_;
    std::string local_pwd_;
    std::vector<Candidate> local_candidates_;

    std::string remote_ufrag_;
    std::string remote_pwd_;
    std::vector<Candidate> remote_candidates_;

    std::vector<CheckPair> check_list_;
    asio::steady_timer check_timer_;
    size_t current_check_ = 0;

    // ── Nominated pair (read from send(), written on strand) ────────────────
    mutable std::mutex nominated_mu_;
    std::string nominated_ip_;
    uint16_t nominated_port_ = 0;
    bool uses_relay_ = false;

    // UDP socket
    asio::ip::udp::socket socket_;
    std::array<uint8_t, 2048> recv_buf_{};
    asio::ip::udp::endpoint sender_ep_;

    // STUN binding for srflx
    size_t stun_server_idx_ = 0;
    uint32_t stun_backoff_s_ = 1;
    static constexpr uint32_t MAX_STUN_BACKOFF_S = 30;

    // Keepalive / consent
    asio::steady_timer keepalive_timer_;
    std::atomic<uint32_t> consent_missed_{0};
    uint32_t consent_recovery_attempts_ = 0;
    static constexpr uint32_t MAX_CONSENT_RECOVERY = 3;

    // TURN
    std::shared_ptr<TurnClient> turn_;

    // Tiebreaker
    uint64_t tiebreaker_ = 0;

    std::atomic<std::chrono::steady_clock::time_point> last_activity_;

    // ── State machine (all run on strand or during synchronous gather) ────
    void gather_host_candidates();
    void try_next_stun_server();
    void gather_relay();
    void on_gathering_complete();
    void begin_checks();
    void run_next_check();
    void build_check_list();
    void send_check(CheckPair& pair);
    void handle_check_response(const StunMessage& msg);
    void on_nominated(const std::string& ip, uint16_t port, bool relay);

    void start_recv();
    void handle_recv(size_t bytes);
    void start_keepalive();
    void on_keepalive();

    static std::string generate_ufrag();
    static std::string generate_pwd();
};

} // namespace gn::link::ice
