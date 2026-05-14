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
///
/// I/O model: the session does not own a UDP socket.
/// Inbound and outbound bytes flow through a shared `gn.link.udp`
/// carrier resolved by the parent `IceLink`. Each remote endpoint
/// (STUN server, peer candidate, TURN relay, nominated peer) gets
/// its own carrier conn id allocated via `composer_connect`; the
/// session keeps a small `endpoint → cid` map for outbound and a
/// `cid → endpoint` map so accept-bus arrivals can be routed back
/// to the right code path. A null `carrier_` means the host did not
/// expose `gn.link.udp` — the session degrades to a no-op FSM in
/// that case so test fixtures without a real UDP plugin still get
/// notify_connect / notify_disconnect surface coverage.

#include "candidate.hpp"
#include "stun.hpp"
#include "turn.hpp"

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/types.h>

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

/// Bit flags for `IceConfig::candidate_filter_flags`. Operators
/// reach them through the `ice.candidate_filters` config array of
/// string tokens — `"exclude-ipv4"`, `"exclude-ipv6"`,
/// `"relay-only"`, `"host-only"`. Combinations make sense (e.g.
/// `relay-only` + `exclude-ipv6` keeps only IPv4 relay candidates
/// for an operator running through TURN on a v4-only carrier);
/// contradictions (`relay-only` + `host-only`) silently drop both
/// kinds so no candidate is generated — useful for diagnostics
/// where you want a session to ICE-fail deliberately.
inline constexpr std::uint32_t kCandidateFilterExcludeIpv4 = 1u << 0;
inline constexpr std::uint32_t kCandidateFilterExcludeIpv6 = 1u << 1;
inline constexpr std::uint32_t kCandidateFilterRelayOnly   = 1u << 2;
inline constexpr std::uint32_t kCandidateFilterHostOnly    = 1u << 3;

/// @brief ICE session configuration: STUN/TURN servers, timeouts, keepalive.
struct IceConfig {
    std::vector<std::string> stun_servers{};
    /// Active TURN allocation parameters. When `turn_servers` carries
    /// more than one entry `turn` mirrors the first; session-side
    /// iteration across the fallback list lands in a follow-up
    /// commit. Kept as a top-level field for read-site compatibility
    /// with the rest of the FSM.
    TurnConfig turn;
    /// RFC 8445 §6.1.4 (TURN as fallback) — array of TURN
    /// allocations the operator wants to try. The first
    /// non-empty entry populates `turn` above so existing
    /// allocation paths keep working; the rest are reserved
    /// for follow-up multi-TURN fallover. Empty array means
    /// no relay candidate is generated.
    std::vector<TurnConfig> turn_servers{};
    int  session_timeout_s      = 10;
    int  keepalive_interval_s   = 20;
    int  consent_max_failures   = 3;
    /// RFC 7675 consent freshness: when `consent_max_failures`
    /// keepalive STUN binding requests in a row go unanswered the
    /// session restarts connectivity checks against the current
    /// candidate set (resets to `Checking`, rebuilds the check
    /// list, re-probes). The session attempts at most
    /// `consent_max_recovery` such restarts before declaring the
    /// nominated pair dead and transitioning to `Failed`. Default
    /// 3 — the FSM goes through three round-trips of re-checks
    /// before giving up, which covers ~30 s of transient network
    /// loss for the typical 50 ms check interval. Drop to 0 for a
    /// session that should die at the first consent failure
    /// (real-time gaming where stale state hurts more than a fresh
    /// session); raise it for slow-changing networks where ICE
    /// restart cost is prohibitive.
    int  consent_max_recovery   = 3;
    int  check_interval_ms      = 50;
    int  max_check_retries      = 4;
    /// Nomination strategy per RFC 8445 §8.1.1. `false` (default) =
    /// regular nomination: the controller runs all checks without
    /// USE-CANDIDATE first, picks the highest-priority valid pair,
    /// then sends ONE final check with USE-CANDIDATE to commit it.
    /// `true` = aggressive nomination: USE-CANDIDATE on every check;
    /// the first pair that succeeds becomes the nominated pair.
    /// Regular yields a better pair on multi-candidate setups
    /// (e.g. dual-stack hosts where v4 wins the race but v6 has
    /// higher priority); aggressive nominates faster.
    bool aggressive_nomination  = false;
    /// Operator-side candidate filtering. OR-ed combination of the
    /// `kCandidateFilter*` flags above. Default 0 = no filtering;
    /// every host / srflx / relay candidate is gathered as usual.
    std::uint32_t candidate_filter_flags = 0;
};

/// Decide whether a candidate of `(type, family)` survives the
/// operator's filter mask. Called at push sites in the session
/// FSM so a filter-out candidate never enters the check list.
[[nodiscard]] constexpr bool candidate_allowed(
        CandidateType type, AddressFamily family,
        std::uint32_t filter_flags) noexcept {
    if ((filter_flags & kCandidateFilterExcludeIpv4) != 0 &&
        family == AddressFamily::IPv4) return false;
    if ((filter_flags & kCandidateFilterExcludeIpv6) != 0 &&
        family == AddressFamily::IPv6) return false;
    if ((filter_flags & kCandidateFilterRelayOnly) != 0 &&
        type != CandidateType::Relay) return false;
    if ((filter_flags & kCandidateFilterHostOnly) != 0 &&
        type != CandidateType::Host) return false;
    return true;
}

/// @brief ICE candidate pair under connectivity check.
struct CheckPair {
    Candidate local;
    Candidate remote;
    uint64_t  priority;
    uint8_t   retries   = 0;
    bool      nominated = false;
    /// RFC 8445 §7.3 valid pair: set true when the matching binding
    /// response arrives and integrity verifies. The controller's
    /// regular-nomination logic walks the check list looking at this
    /// flag to pick the nominee.
    bool      valid     = false;
    /// Controller-side flag: true once we have selected this pair as
    /// the nominee and sent the final USE-CANDIDATE check on it.
    /// Set before the nominee send so a delayed retry doesn't double
    /// the count, and read by `handle_check_response` to know whether
    /// a successful binding response transitions the FSM to
    /// `Connected`.
    bool      nominee_check_sent = false;
    /// Triggered checks (RFC 8445 §7.3.1.4) bypass the normal queue
    /// position — they are sent as soon as the inbound binding
    /// request that discovered the peer-reflexive source is parsed.
    /// We still record them in the check list so the response routes
    /// back through `handle_check_response`.
    bool      triggered = false;
    TransactionId txn_id;
    /// Monotonic microseconds at most-recent `send_check` call. Used
    /// to derive per-check RTT when the matching response arrives.
    /// Zero means "no send yet" or the pair never reached Checking.
    uint64_t  txn_send_us = 0;
};

/// Nomination snapshot exposed to strategy plugins (`gn.link.ice`
/// extension consumers — `gn.float-send.*` is the reference
/// consumer). Filled
/// post-nomination; reads before nomination return defaults.
struct NominationMetrics {
    uint64_t      rtt_us       = 0;
    CandidateType local_type   = CandidateType::Host;
    CandidateType remote_type  = CandidateType::Host;
    bool          uses_relay   = false;
    bool          nominated    = false;
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
    IceSession(asio::io_context& io,
               gn::sdk::LinkCarrier* carrier,
               gn::sdk::LinkCarrier* carrier_tcp,
               gn::sdk::LinkCarrier* carrier_tls,
               const IceConfig& cfg,
               const std::string& peer_id, bool controlling,
               IceSessionCallbacks callbacks);
    ~IceSession();

    /// Start candidate gathering.
    void gather();

    /// Set remote candidates (from signaling).
    void set_remote(const std::string& ufrag, const std::string& pwd,
                     std::vector<Candidate> candidates);

    /// RFC 8838 trickle ICE — merge an incremental candidate batch
    /// into the existing remote set without dropping pairs already
    /// under check. If `ufrag` differs from the current remote
    /// credentials, the peer just performed an ICE restart and we
    /// rebuild from scratch. Otherwise duplicates (same ip+port+type)
    /// are silently skipped and the check list is extended with the
    /// fresh pairs. Safe to call from any thread; work runs on strand.
    /// @param end_of_candidates RFC 8838 §10: the peer signalled this
    /// batch as final. Subsequent checks that exhaust the list with
    /// no valid pair transition the FSM to Failed immediately
    /// instead of waiting out `session_timeout_s` — operators get
    /// fast-fail behaviour on dead paths.
    void add_remote_candidates(const std::string& ufrag,
                                const std::string& pwd,
                                std::vector<Candidate> candidates,
                                bool end_of_candidates = false);

    /// Send data through the nominated pair.
    void send(std::span<const uint8_t> data);

    /// Close the session.
    void close();

    /// RFC 8445 §9 ICE restart. Regenerates ufrag/pwd, drops every
    /// check pair and remote candidate (peer must re-signal with the
    /// new credentials), and re-enters the Gathering state. Local
    /// host/srflx/relay candidates are re-collected; on_gathered
    /// fires once the new credential set is announceable to the peer.
    /// Caller must propagate the new `local_ufrag()` / `local_pwd()`
    /// through the signalling channel — the FSM has no opinion on
    /// how the new credentials reach the peer.
    void restart();

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

    /// Snapshot of the nominated pair's metrics. Strategy plugins
    /// (multi-path / float_send) call this through the future
    /// `gn.link.ice` metrics extension to compare paths by RTT and
    /// candidate type. Pre-nomination reads return defaults with
    /// `nominated == false`.
    NominationMetrics nomination_metrics() const noexcept;

private:
    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    gn::sdk::LinkCarrier* carrier_ = nullptr;
    /// Optional second carrier for TURN-over-TCP (RFC 5389 §7.2.2).
    /// Resolved from `gn.link.tcp` by `IceLink::set_host_api` and
    /// passed in if `cfg_.turn.tcp_transport == true`. nullptr means
    /// we have no TCP carrier — the session silently downgrades to
    /// UDP TURN.
    gn::sdk::LinkCarrier* carrier_tcp_ = nullptr;
    /// Optional TLS carrier (`gn.link.tls`) for TURN-over-TLS — the
    /// `turns://` scheme. Same framing as TCP; the TLS plugin
    /// handles handshake + record encryption transparently. Passed
    /// in when `cfg_.turn.tls_transport == true`.
    gn::sdk::LinkCarrier* carrier_tls_ = nullptr;
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
    /// Last RTT sample for the nominated pair (microseconds, EWMA).
    /// Atomic for lock-free reads from `nomination_metrics`; written
    /// on the strand only.
    std::atomic<uint64_t> rtt_ewma_us_{0};
    CandidateType nominated_local_type_  = CandidateType::Host;
    CandidateType nominated_remote_type_ = CandidateType::Host;

    /// Carrier-managed local port — set by `gather_host_candidates`
    /// after `carrier_->listen("udp://0.0.0.0:0")`. Shared across all
    /// sessions on the same `IceLink` because UdpLink composer keeps
    /// one socket per plugin instance.
    std::uint16_t local_port_ = 0;
    bool          carrier_initialized_ = false;

    /// Endpoint ↔ carrier conn id maps. The session does its own
    /// `composer_connect` for every remote endpoint it must talk to
    /// (STUN servers, peer candidates, nominated pair). Inbound bytes
    /// from a known endpoint surface through the per-cid `on_data`
    /// callback; the cid is the routing key. Stays strand-only.
    struct EndpointInfo {
        std::string ip;
        std::uint16_t port = 0;
    };
    std::unordered_map<std::string, gn_conn_id_t> endpoint_to_cid_;
    std::unordered_map<gn_conn_id_t, EndpointInfo> cid_to_endpoint_;
    /// The cid currently selected as the nominated outbound path.
    /// Used by `send()` for application data and `on_keepalive`. Zero
    /// before nomination.
    std::atomic<gn_conn_id_t> nominated_cid_{0};

    /// Multi-STUN parallel fallback (RFC 8445 §5.1.1.2). Instead of
    /// probing STUN servers sequentially with exponential backoff,
    /// every configured server gets a Binding Request fired
    /// simultaneously. The first valid XOR-MAPPED-ADDRESS response
    /// wins the srflx candidate slot; remaining responses arrive
    /// later and are dropped because `pending_stun_probes_` is
    /// cleared on first hit. Total gather latency is bounded by the
    /// fastest reachable STUN server, not the sum of failed retries.
    std::vector<TransactionId>  pending_stun_probes_;
    asio::steady_timer          gather_timer_;

    // Keepalive / consent
    asio::steady_timer keepalive_timer_;
    std::atomic<uint32_t> consent_missed_{0};
    uint32_t consent_recovery_attempts_ = 0;

    // TURN
    std::shared_ptr<TurnClient> turn_;

    // Tiebreaker
    uint64_t tiebreaker_ = 0;

    std::atomic<std::chrono::steady_clock::time_point> last_activity_;

    // ── State machine (all run on strand or during synchronous gather) ────
    void gather_host_candidates();
    void start_multi_stun_probes();
    void handle_gather_response(const StunMessage& msg);
    void gather_relay();
    void on_gathering_complete();
    void begin_checks();
    void run_next_check();
    void build_check_list();
    void send_check(CheckPair& pair);
    void handle_check_response(const StunMessage& msg);
    void on_nominated(const std::string& ip, uint16_t port, bool relay,
                       gn_conn_id_t cid);

    /// Dispatch entry for bytes arriving on a per-endpoint cid. Called
    /// from the per-conn `on_data` callback installed by
    /// `ensure_remote_cid`. Drives the same STUN parsing / FSM the
    /// inline socket recv loop used to.
    void on_carrier_data(gn_conn_id_t cid,
                          std::span<const std::uint8_t> bytes);

    /// composer_connect → cid mapping; reuses an existing cid if the
    /// endpoint has been seen before. Returns 0 on failure. Strand-only.
    gn_conn_id_t ensure_remote_cid(const std::string& ip, uint16_t port);

    /// RFC 8445 §7.3.1.4 triggered check. Called from
    /// `on_carrier_data` after a valid inbound BINDING_REQUEST.
    /// If the peer's source endpoint is not yet covered by any pair
    /// in the check list, a fresh pair with a peer-reflexive remote
    /// candidate is appended and an immediate check is sent so we
    /// don't have to wait for the next gather batch / scheduled
    /// check to validate paths the peer just opened on their side.
    void maybe_trigger_check_from_peer(const std::string& peer_ip,
                                         uint16_t peer_port);

    /// Regular-nomination state — set true once the controller has
    /// dispatched its USE-CANDIDATE follow-up on whatever pair won
    /// the priority race. Prevents re-nomination if a later valid
    /// pair overtakes (RFC says pick once, stick with it). Strand-
    /// only; ignored when `aggressive_nomination` is on.
    bool nominee_selected_ = false;

    /// RFC 8838 §10: peer indicated their trickle batch is complete.
    /// When set, `run_next_check` transitions the FSM to Failed as
    /// soon as the check list is exhausted with no valid pair — no
    /// need to wait the `session_timeout_s` ceiling. Set by
    /// `add_remote_candidates` when invoked with `end_of_candidates`.
    bool remote_end_of_candidates_ = false;

    void start_keepalive();
    void on_keepalive();

    static std::string generate_ufrag();
    static std::string generate_pwd();
};

} // namespace gn::link::ice
