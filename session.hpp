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
#include "mdns.hpp"
#include "path_mtu.hpp"
#include "portmap_ext_client.hpp"
#include "stun.hpp"
#include "turn.hpp"

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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
    /// Active TURN allocation parameters. Mirrors the first entry of
    /// `turn_servers` for read-site compatibility (single-server hot
    /// path). The session FSM walks `turn_servers` in priority order
    /// (RFC 8445 §6.1.4 fallback); see `turn_allocate_timeout_s`.
    TurnConfig turn;
    /// RFC 8445 §6.1.4 TURN-as-fallback list. Iterated sequentially
    /// during gather: each entry is allocated against in turn, the
    /// first ALLOCATE success becomes the relay candidate, the
    /// remainder stay queued for failover. Empty array means no
    /// relay candidate is emitted.
    std::vector<TurnConfig> turn_servers{};
    int  session_timeout_s      = 10;
    int  keepalive_interval_s   = 20;
    int  consent_max_failures   = 3;
    /// Per-attempt TURN ALLOCATE deadline. The multi-TURN fallback
    /// path in `IceSession::gather_relay` walks `turn_servers` in
    /// order and abandons each entry that does not surface a relay
    /// address within this many seconds.
    int  turn_allocate_timeout_s = 5;
    /// Cadence of backup-TURN probing after a successful primary
    /// allocation. Every tick the session attempts one ALLOCATE
    /// against the next entry in `turn_servers` past the active
    /// one; on success and an unhealthy primary the session fails
    /// over. Zero disables backup probing.
    int  turn_backup_interval_s = 30;
    /// Minimum wall-clock gap between two consecutive failovers.
    /// Bounds oscillation when both primary and backup are flapping.
    int  turn_failover_min_interval_s = 60;
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

    /// draft-ietf-mmusic-mdns-ice-candidates host-candidate
    /// obfuscation. When `true`, host candidates ride the wire as
    /// `<uuid>.local` names registered with the local mDNS
    /// responder; remote peers resolve those names via multicast
    /// DNS to recover the IP. This prevents leaking interior
    /// addresses to peers off the LAN. Defaults to `false` because
    /// browsers turning this on broke existing media-server
    /// integrations — operators that need privacy parity with
    /// browsers flip it on; everyone else stays on raw host
    /// candidates.
    bool mdns_obfuscate_host_candidates = false;

    /// Timeout for resolving a remote `<uuid>.local` candidate via
    /// mDNS. The draft suggests 5 seconds for the typical case.
    /// Bounded by `session_timeout_s` at the session level — a
    /// resolution that exceeds the session deadline is treated as
    /// a candidate drop.
    int  mdns_resolve_timeout_ms = 5000;

    /// Conservative path-MTU floor in bytes, propagated from
    /// `IceLink::mtu_` (read from `ice.path_mtu`, default 1200).
    /// Doubles as the starting `effective_mtu` when active probing
    /// is disabled or before the first probe ACK arrives.
    int  path_mtu = 1200;
    /// RFC 8899 DPLPMTUD active path-MTU discovery. When `true`, the
    /// session probes upward from `path_mtu` along `pmtu_search_steps`
    /// once the FSM enters `Connected`. Discovered values surface
    /// through `effective_path_mtu()` and the `gn.link.ice.path_mtu`
    /// extension. With probing disabled the effective MTU equals the
    /// static config value.
    bool pmtu_active_probing = true;
    /// Ascending ladder of candidate MTU sizes in bytes. Probe-loss
    /// halving converges to the largest size below the lowest failing
    /// rung. The starting `path_mtu` is the conservative floor that
    /// the FSM does not regress below.
    std::vector<int> pmtu_search_steps{1200, 1400, 1500, 4000, 9000};
    /// Per-probe deadline. A probe with no matching response within
    /// this window is treated as a loss; two consecutive losses at
    /// the same size collapse the search per RFC 8899 §5.2.
    int  pmtu_probe_timeout_ms = 500;
    /// Maximum number of in-flight probes. 1 is conservative and
    /// matches RFC 8899 §5.1.4 reference recommendation.
    int  pmtu_probe_concurrency = 1;

    /// RFC 8445 §2.7 ICE-lite agent. A lite agent never initiates
    /// connectivity checks; it only responds to incoming checks and
    /// accepts the controller's nomination. Used by media gateways
    /// and IoT endpoints with a single well-known public address
    /// where running full ICE would be redundant. A lite agent is
    /// always controlled — when set, `controlling_` is forced false
    /// regardless of how the session was constructed.
    bool lite_mode = false;

    /// Linux netlink (RTM_NEWLINK / RTM_NEWADDR / RTM_DELADDR /
    /// RTM_DELLINK) subscription. When true, the session opens an
    /// `AF_NETLINK / NETLINK_ROUTE` socket and re-gathers host
    /// candidates after a debounced interface state change. Off
    /// silently on non-Linux platforms.
    bool reactive_interface_change = true;

    /// Symmetric-NAT port prediction. When ICE gather detects that
    /// the local NAT assigns different external ports for STUN
    /// requests to different destinations from the same internal
    /// port, the FSM records the stride and tries
    /// `(peer.ip, peer.port + stride * k)` for k in 1..N alongside
    /// the canonical peer endpoint. Purely additive — every standard
    /// ICE check still runs.
    bool symmetric_port_prediction_enabled = true;
    /// Max consecutive predicted ports to probe past the advertised
    /// `peer.port` when the peer is marked symmetric. Capped to keep
    /// the check list from blowing up against a wide NAT pool.
    int  symmetric_port_prediction_attempts = 8;

    /// RFC 6544 TCP candidate emission. When `true` and a TCP carrier
    /// is wired, `gather_host` emits one TCP host candidate per
    /// interface IP per transport variant (active / passive /
    /// simultaneous-open), and `gather_server_reflexive` fires a STUN
    /// binding request over TCP to surface a TCP srflx candidate.
    /// Defaults to `true` so deployments behind UDP-blocked
    /// firewalls get TCP fallback without a config toggle; operators
    /// in pure-UDP environments can flip it off to shrink the
    /// candidate set.
    bool tcp_candidates_enabled = true;
    /// Coordination window (milliseconds) for RFC 6544
    /// simultaneous-open: both peers must fire `connect()` toward
    /// each other's TCP-SO candidate inside this window for the
    /// kernel's SYN-SYN exchange to land. Outside the window the
    /// check is abandoned and the next pair in the list runs.
    int  tcp_so_timeout_ms = 5000;
    /// Per-socket TCP handshake deadline for connectivity-check
    /// candidates. Linux kernel SYN-retry budget runs ~127 s on
    /// defaults — far longer than the ICE pair-state machine wants
    /// to wait on an unroutable cross-LAN candidate. When the timer
    /// fires without an inbound byte, the session drops the L1
    /// socket and marks every in-progress pair on this endpoint
    /// Failed so a sibling pair can promote.
    int  tcp_connect_timeout_ms = 3000;

    /// Auto-restart the ICE session when consent-freshness recovery is
    /// exhausted instead of transitioning to `Failed`. A transient
    /// network outage (wifi flap, cellular handoff) drops keepalive
    /// responses past `consent_max_recovery`; with this on the FSM
    /// regenerates ufrag/pwd and re-enters Gathering, giving the peer
    /// a chance to re-signal and recover without an app-level
    /// reconnect. `false` preserves the strict RFC 7675 behaviour
    /// where the session dies on consent loss.
    bool auto_restart_on_consent_loss = true;
    /// Upper bound on consecutive auto-restarts before the session
    /// gives up and transitions to `Failed`. Prevents an unreachable
    /// peer from holding the session in a restart loop indefinitely.
    /// 0 disables auto-restart entirely (equivalent to flipping
    /// `auto_restart_on_consent_loss` off).
    int  auto_restart_max_attempts = 3;
    /// Minimum gap between two consecutive auto-restarts. A second
    /// consent-loss landing inside this window is coalesced into the
    /// in-flight restart — the FSM does not re-enter Gathering twice
    /// for the same network blip.
    int  auto_restart_backoff_ms = 500;
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

/// RFC 8445 §6.1.2.6 candidate pair state. Pacing transitions:
/// - `Frozen`     : pair exists but has not been picked up yet because
///                   another pair sharing its foundation tuple
///                   `(local.foundation, remote.foundation)` is still
///                   the active representative; promoted to `Waiting`
///                   when that representative succeeds.
/// - `Waiting`    : ready to be scheduled by `run_next_check`.
/// - `InProgress` : a STUN binding-request is on the wire; counted
///                   against `kCheckConcurrencyCap` per RFC §6.1.2.5.
/// - `Succeeded`  : matching binding-response with valid integrity.
///                   Triggers sibling unfreeze on the foundation
///                   tuple so dependent pairs can run.
/// - `Failed`     : retries exhausted, ICMP unreachable, or
///                   integrity mismatch. Pair stays out of rotation
///                   but its sibling foundation members keep going.
enum class PairState : uint8_t {
    Frozen     = 0,
    Waiting    = 1,
    InProgress = 2,
    Succeeded  = 3,
    Failed     = 4,
};

/// RFC 8445 §6.1.2.5 concurrent-check cap. The reference value is
/// "around 5" and the FSM honours it strictly so a check list with
/// dozens of pairs doesn't burst-storm STUN probes onto the wire
/// (sender-side rate clamp on top of the retry-driven pacing).
inline constexpr std::size_t kCheckConcurrencyCap = 5;

/// @brief ICE candidate pair under connectivity check.
struct CheckPair {
    Candidate local;
    Candidate remote;
    uint64_t  priority;
    uint8_t   retries   = 0;
    bool      nominated = false;
    /// RFC 8445 §6.1.2.6 pair state. Drives `run_next_check`'s
    /// Frozen → Waiting → InProgress pacing; see PairState above.
    PairState state     = PairState::Frozen;
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
    /// RFC 6544 transport flavour for this pair. Mirrors
    /// `local.transport` so the check driver does not need to walk
    /// the candidate field on every dispatch. UDP pairs ride the
    /// existing UDP carrier; TCP variants route through `carrier_tcp_`
    /// with 16-bit length-prefix framing per RFC 5389 §7.2.2.
    TransportType transport_type = TransportType::Udp;
};

/// Nomination snapshot exposed to strategy plugins (`gn.link.ice`
/// extension consumers — `gn.float-send.*` is the reference
/// consumer). Filled
/// post-nomination; reads before nomination return defaults.
struct NominationMetrics {
    uint64_t      rtt_us       = 0;
    CandidateType local_type   = CandidateType::Host;
    CandidateType remote_type  = CandidateType::Host;
    TransportType transport    = TransportType::Udp;
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
    /// Fired when the session decides to auto-restart on consent loss.
    /// `reason` is a short stable token (e.g. `"consent-loss"`) the
    /// transport layer can forward to strategy plugins so they
    /// deprioritise the conn or trigger an upper-layer reconnect. The
    /// kernel `gn.strategy.*` extension currently exposes
    /// `GN_PATH_EVENT_CONN_DOWN`; the ICE link translates this callback
    /// into a CONN_DOWN notification on its side without requiring a
    /// new kernel enum value.
    std::function<void(const std::string& peer_id,
                       std::string_view reason,
                       std::uint32_t attempt,
                       std::uint32_t max_attempts)> on_auto_restart;
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
               IceSessionCallbacks callbacks,
               std::shared_ptr<MdnsManager> mdns = nullptr,
               IcePortmapClient* portmap_ext = nullptr);
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

    /// Wire-level flags advertised by the remote peer in the most
    /// recent OFFER / ANSWER envelope (`ICE_SIGNAL_FLAG_*`). The
    /// link plugin extracts them from `deserialize_signal` and
    /// forwards them here so the FSM can adjust nomination (peer
    /// lite → we drive checks) and port prediction (peer symmetric
    /// → expand the check list with stride-predicted ports). Safe
    /// to call from any thread; the strand re-entry is cheap.
    void set_peer_signal_flags(std::uint32_t flags);

    /// Local-side wire flags this session contributes to outgoing
    /// signals. Currently surfaces `ICE_SIGNAL_FLAG_LITE` when the
    /// agent is configured lite, and `ICE_SIGNAL_FLAG_SYMMETRIC`
    /// when gather detected a symmetric NAT. Read by the link
    /// plugin when assembling outbound trickle batches.
    [[nodiscard]] std::uint32_t local_signal_flags() const noexcept;

    /// RFC 8445 §9 ICE restart. Regenerates ufrag/pwd, drops every
    /// check pair and remote candidate (peer must re-signal with the
    /// new credentials), and re-enters the Gathering state. Local
    /// host/srflx/relay candidates are re-collected; on_gathered
    /// fires once the new credential set is announceable to the peer.
    /// Caller must propagate the new `local_ufrag()` / `local_pwd()`
    /// through the signalling channel — the FSM has no opinion on
    /// how the new credentials reach the peer.
    void restart();

    /// Trigger the consent-loss decision point synchronously. Mirrors
    /// what the keepalive handler does when consent recovery is
    /// exhausted: depending on `cfg_.auto_restart_on_consent_loss` and
    /// the remaining attempt budget, either re-enters Gathering
    /// through `restart()` or transitions to Failed. Returns true when
    /// the call decided to auto-restart, false when it transitioned
    /// (or would transition) to Failed. Public so that test fixtures
    /// can exercise the policy without driving a full STUN exchange to
    /// Connected; production callers should not invoke this directly —
    /// the FSM does the right thing from `on_keepalive`.
    bool notify_consent_loss_for_test();

    // Accessors
    SessionState state() const { return state_.load(std::memory_order_acquire); }
    const std::string& peer_id() const { return peer_id_; }
    bool is_controlling() const { return controlling_; }

    /// RFC 8445 §7.3.1.1 tie-breaker exposed for diagnostics + tests.
    /// Generated once at construction via libsodium `randombytes_buf`
    /// and never rotated for the lifetime of the session; an ICE
    /// restart (`restart()`) keeps the same value so a concurrent peer
    /// running in parallel still resolves the same conflict ordering.
    uint64_t tie_breaker() const noexcept { return tiebreaker_; }

    /// Test seam: lift the strand-only check list onto the calling
    /// thread under `local_state_mu_`. Tests need this to assert the
    /// initial Frozen / Waiting partition produced by `build_check_list`
    /// without driving a full STUN exchange. Production callers must
    /// not depend on this — the snapshot is taken under a lock and
    /// reads of in-flight RTT / retries are intentionally lossy.
    std::vector<PairState> check_list_states_for_test() const;

    /// Test seam: same role-conflict path the STUN dispatcher exercises
    /// on inbound BINDING_REQUEST, lifted to a synchronous call so a
    /// fixture can assert the resolution without forging a full STUN
    /// frame. Returns true when the local role flipped as a result of
    /// the conflict, false when we kept our role (and would have
    /// emitted a 487 response on the wire). Strand-safe.
    bool handle_role_conflict_for_test(bool sender_controlling,
                                         uint64_t sender_tiebreaker);

    /// Snapshots taken under `local_state_mu_`. The previous
    /// reference-returning form raced with strand-side mutators
    /// (`restart`, TURN-allocate callbacks, gather) because off-strand
    /// callers (tests, signaling) hold the reference while the strand
    /// reallocates the vector or reassigns the string.
    std::vector<Candidate> local_candidates() const {
        std::lock_guard lk(local_state_mu_);
        return local_candidates_;
    }
    std::string local_ufrag() const {
        std::lock_guard lk(local_state_mu_);
        return local_ufrag_;
    }
    std::string local_pwd() const {
        std::lock_guard lk(local_state_mu_);
        return local_pwd_;
    }

    std::chrono::steady_clock::time_point last_activity() const {
        return last_activity_.load(std::memory_order_acquire);
    }

    /// Snapshot of the nominated pair's metrics. Strategy plugins
    /// (multi-path / float_send) call this through the future
    /// `gn.link.ice` metrics extension to compare paths by RTT and
    /// candidate type. Pre-nomination reads return defaults with
    /// `nominated == false`.
    NominationMetrics nomination_metrics() const noexcept;

    /// Per-type candidate count snapshot. `local_candidates_` is
    /// already serialised through `local_state_mu_` (see
    /// `local_candidates()`); `remote_candidates_` is strand-only
    /// so the count is gathered by posting onto the strand and
    /// blocking on the future. Safe to call from any thread *except*
    /// the strand itself — strand callers would deadlock.
    struct CandidateCounts {
        std::uint32_t local_host  = 0;
        std::uint32_t local_srflx = 0;
        std::uint32_t local_relay = 0;
        std::uint32_t local_prflx = 0;
        std::uint32_t remote_host  = 0;
        std::uint32_t remote_srflx = 0;
        std::uint32_t remote_relay = 0;
        std::uint32_t remote_prflx = 0;
    };
    CandidateCounts candidate_counts() const;

    /// Largest MTU known to ride the nominated pair end-to-end. When
    /// `pmtu_active_probing` is on this reflects the latest probe
    /// outcome; otherwise it returns the static configured floor.
    /// Reads are lock-free; the value is updated on the strand after
    /// each probe ACK/loss.
    std::uint32_t effective_path_mtu() const noexcept {
        return effective_mtu_.load(std::memory_order_acquire);
    }

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
    /// Optional `gn.link.portmap` extension client. Borrowed from the
    /// parent `IceLink` (one instance per plugin so multiple sessions
    /// share the renewal table inside the portmap plugin). nullptr
    /// means the extension was not exposed by the host — gather skips
    /// the portmap step and falls back to STUN-srflx / TURN-relay
    /// without further work.
    IcePortmapClient* portmap_ext_ = nullptr;
    /// Active portmap mapping for this session's `local_port_`. Filled
    /// by `gather_portmap()` on success; released on session teardown
    /// (`close()` / dtor) by issuing `portmap_ext_->release()`. Match
    /// the TURN deallocation lifecycle: best-effort, ignore failure.
    std::optional<gn_portmap_mapping_t> portmap_mapping_;
    IceConfig cfg_;
    std::string peer_id_;
    bool controlling_;
    IceSessionCallbacks callbacks_;

    std::atomic<SessionState> state_{SessionState::New};

    // ── State machine data (strand-only access) ─────────────────────────────
    /// `local_ufrag_`, `local_pwd_`, and `local_candidates_` are
    /// strand-only on the write path but are also sampled
    /// cross-thread through the public accessors (tests poll them
    /// from the main thread; signaling plugins read them from their
    /// own dispatcher). The mutex publishes strand-side writes to
    /// off-strand readers; strand-side readers stay lock-free.
    mutable std::mutex local_state_mu_;
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
        /// Carrier flavour the cid was opened on. UDP cids dispatch
        /// through the existing per-cid path; TCP cids carry STUN
        /// inside the 16-bit length-prefix framing per RFC 5389
        /// §7.2.2 and route through `on_tcp_carrier_data` which
        /// deframes before handing bytes to `on_carrier_data`.
        TransportType transport = TransportType::Udp;
    };
    std::unordered_map<std::string, gn_conn_id_t> endpoint_to_cid_;
    /// Per-transport cid → endpoint maps. The two link plugins
    /// (`gn.link.udp`, `gn.link.tcp`) assign cids from independent
    /// counters so the same numeric cid can refer to a UDP connection
    /// in one map and an unrelated TCP connection in the other. Keeping
    /// them in separate maps is the only way to disambiguate carrier
    /// ownership at the dispatch site.
    std::unordered_map<gn_conn_id_t, EndpointInfo> cid_to_endpoint_udp_;
    std::unordered_map<gn_conn_id_t, EndpointInfo> cid_to_endpoint_tcp_;
    /// Synthetic cid map for TURN-mediated STUN dispatch. A relay-local
    /// check pair sends its binding request via `turn_->send_indication`
    /// instead of `carrier_->send`, so there is no real carrier cid the
    /// receive path can use to route the inbound STUN response back to
    /// `on_carrier_data`. We mint a synthetic cid keyed by the peer's
    /// `(ip,port)` and stamp it into `cid_to_endpoint_udp_` so the
    /// EndpointInfo lookup that the response handler / triggered-check
    /// path performs continues to work.
    ///
    /// The UDP composer's `kComposerIdBit` is bit 63, so we cannot
    /// disambiguate synthetic cids from real ones via a bit mask. The
    /// `relay_cids_` set is the authoritative membership check used
    /// by the response paths to decide between `carrier_->send` and
    /// `turn_->send_indication`.
    std::unordered_map<std::string, gn_conn_id_t> relay_endpoint_to_cid_;
    std::unordered_set<gn_conn_id_t>              relay_cids_;
    /// Counter starts well above any plausible composer cid stream
    /// (the composer increments from 1 OR-ed with bit 63). Set membership
    /// in `relay_cids_` is the actual disambiguation gate; this is just
    /// the seed.
    gn_conn_id_t next_relay_cid_ = 0xC000000000000000ULL;
    /// Reassembly buffer for inbound STUN-over-TCP bytes per cid.
    /// TCP carriers deliver arbitrary chunks; the 16-bit length
    /// prefix lets us slice them back into STUN messages without
    /// assuming one carrier read == one frame.
    std::unordered_map<gn_conn_id_t, std::vector<std::uint8_t>>
        tcp_rx_buffers_;
    /// Per-cid TCP handshake deadline. Armed by
    /// `ensure_remote_tcp_cid` at the moment a fresh L1 socket is
    /// opened; cancelled by `on_tcp_carrier_data` on the first
    /// inbound byte (proof TCP is alive and the peer is responsive).
    /// On expiry, `on_tcp_connect_timeout` drops the L1 socket and
    /// marks every in-progress pair using this endpoint as Failed.
    /// `unique_ptr` so the timer object lives in a stable address —
    /// the strand-bound async_wait callback holds a raw pointer
    /// would race with map rehash.
    std::unordered_map<gn_conn_id_t,
                       std::unique_ptr<asio::steady_timer>>
        tcp_connect_timers_;
    /// The cid currently selected as the nominated outbound path.
    /// Used by `send()` for application data and `on_keepalive`. Zero
    /// before nomination.
    std::atomic<gn_conn_id_t> nominated_cid_{0};
    /// Transport flavour of the nominated cid. UDP (default) routes
    /// outbound bytes through `carrier_`; TCP variants go through
    /// `carrier_tcp_`. Read-mostly: written once by `on_nominated`
    /// and sampled by `send` / `on_keepalive`.
    std::atomic<TransportType> nominated_transport_{TransportType::Udp};

    /// Application payloads handed to `send()` before nomination
    /// completes. Strand-only — pushed when `state_ != Connected` and
    /// drained inline at the head of `on_nominated`. Cap is in frames
    /// rather than bytes so a chatty L2 cannot OOM the session while
    /// ICE is still negotiating; over-cap pushes drop the oldest
    /// frame (the FIFO already saw the application accept that send).
    std::deque<std::vector<uint8_t>> pending_app_data_;
    static constexpr std::size_t     kPendingAppDataMaxFrames = 64;

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

    // Auto-restart accounting — number of consent-loss-driven restarts
    // already fired, and the wall-clock timestamp of the last one. Both
    // strand-only. The counter is reset only by an explicit operator
    // `restart()` (callers reaching for a fresh ICE round) so a long
    // sequence of transient blips ultimately exhausts the cap.
    uint32_t                              auto_restart_attempts_ = 0;
    std::chrono::steady_clock::time_point auto_restart_last_{};

    // TURN
    std::shared_ptr<TurnClient> turn_;

    /// Current attempt index into `cfg_.turn_servers` during the
    /// sequential ALLOCATE walk. Reset to 0 on `restart_session`.
    std::size_t turn_attempt_idx_ = 0;
    /// Per-attempt deadline; on expiry the in-flight TurnClient is
    /// torn down and `try_next_turn_attempt` advances.
    asio::steady_timer turn_allocate_timer_;
    /// Entries in `cfg_.turn_servers` past the active primary —
    /// these get periodic ALLOCATE probes via `turn_backup_timer_`
    /// and stand by for failover when the primary degrades.
    std::vector<TurnConfig> turn_backups_;
    asio::steady_timer      turn_backup_timer_;
    /// Most-recently-probed backup client; pinned across one probe
    /// cycle so a successful ALLOCATE can be promoted to the active
    /// relay. Reset between probes.
    std::shared_ptr<TurnClient> turn_backup_probe_;
    std::size_t                  turn_backup_probe_idx_ = 0;
    /// Wall-clock of the last failover commit. Compared against
    /// `cfg_.turn_failover_min_interval_s` to rate-limit oscillation.
    std::chrono::steady_clock::time_point turn_last_failover_{};

    // mDNS responder + resolver. Borrowed from the parent `IceLink`
    // (one instance per plugin), so multiple sessions share the
    // same multicast socket and registered-name table. nullptr
    // when the parent link did not bind a manager — typically
    // because `mdns_obfuscate_host_candidates` is `false` for
    // every session, or the platform-specific bind failed.
    std::shared_ptr<MdnsManager> mdns_;

    // Hostname registered for THIS session's host obfuscation.
    // Empty when mDNS host candidates are disabled. Held so the
    // session can `unregister_name` on close and avoid leaking
    // registrations across ICE restarts.
    std::string  mdns_local_hostname_;

    // Tiebreaker
    uint64_t tiebreaker_ = 0;

    std::atomic<std::chrono::steady_clock::time_point> last_activity_;

    // ── State machine (all run on strand or during synchronous gather) ────
    void gather_host_candidates();
    /// RFC 6544 TCP host gather. For each interface IP already
    /// emitted as a UDP host candidate, push three TCP host
    /// candidates — one per transport variant (active / passive /
    /// simultaneous-open). The same `local_port_` is reused; ICE
    /// peers distinguish UDP vs TCP entries via the wire-encoded
    /// transport nibble. No-op when the TCP carrier is missing or
    /// `cfg_.tcp_candidates_enabled` is false.
    void gather_tcp_host_candidates();
    /// RFC 6544 TCP srflx gather. Fires one STUN binding request per
    /// configured STUN server over the TCP carrier and emits a
    /// `Srflx` candidate with `TcpActive` transport on the first
    /// XOR-MAPPED-ADDRESS response. TCP-TURN per RFC 6062 is
    /// roadmap; this commit covers host + srflx TCP only.
    void gather_tcp_server_reflexive();
    void start_multi_stun_probes();
    void handle_gather_response(const StunMessage& msg,
                                  TransportType src_transport);
    void gather_relay();
    /// Optional NAT-mapping gather step driven by the `gn.link.portmap`
    /// extension. When the host exposes UPnP IGD / PCP / NAT-PMP via
    /// the extension, this asks the router for an explicit
    /// `(ext_ip, ext_port)` mapping for `local_port_` and pushes a
    /// dedicated srflx candidate (`server = "portmap"` in the
    /// foundation hash so the entry is distinct from STUN-discovered
    /// srflx) into `local_candidates_`. No-op when the extension is
    /// missing, the supported-protocols mask is zero, or
    /// `local_port_ == 0`. Strand-safe — all candidate-vector
    /// mutations grab `local_state_mu_` like the other gather paths.
    void gather_portmap();
    /// Release any portmap-allocated mapping held by this session.
    /// Idempotent and best-effort: matches the TURN-deallocation
    /// pattern in `close()` / dtor. Safe to call when no mapping was
    /// ever requested.
    void release_portmap_mapping() noexcept;
    /// Start the next ALLOCATE attempt against
    /// `cfg_.turn_servers[turn_attempt_idx_]`. Arms
    /// `turn_allocate_timer_` for `cfg_.turn_allocate_timeout_s`.
    /// On exhaustion of the list the relay slot stays empty and the
    /// FSM proceeds without a relay candidate.
    void try_next_turn_attempt();
    /// Periodic backup-probe tick — fires ALLOCATE against the next
    /// entry in `turn_backups_`. On success and an unhealthy primary
    /// the session fails over.
    void on_turn_backup_tick();
    /// Tear down the active TURN allocation and bring up @p client as
    /// the new primary. Drops the old relay candidate and pushes the
    /// new one into `local_candidates_`. Rate-limited by
    /// `turn_last_failover_` + `cfg_.turn_failover_min_interval_s`.
    void promote_turn_backup(std::shared_ptr<TurnClient> client,
                              TurnConfig new_cfg);
    /// Build a `TurnClient` against @p cfg. Resolves the carrier per
    /// the cfg's transport flags (TLS / TCP / UDP), allocates a cid,
    /// and returns the client without calling `allocate()` on it
    /// (caller decides when to start the round-trip). Returns
    /// nullptr if no suitable carrier exists.
    std::shared_ptr<TurnClient> build_turn_client(
        const TurnConfig& cfg,
        TurnAllocatedCallback on_alloc,
        TurnDataCallback on_data,
        gn_conn_id_t& out_cid);
    void on_gathering_complete();
    void begin_checks();
    void run_next_check();
    void build_check_list();
    void send_check(CheckPair& pair);
    /// RFC 6544 §6 simultaneous-open: when checking a TCP-SO pair,
    /// both peers fire `connect()` toward the peer's TCP-SO
    /// candidate within `cfg_.tcp_so_timeout_ms`. The kernel TCP
    /// stack performs the SYN-SYN exchange; on success the resulting
    /// socket becomes the carrier for STUN-framed checks. This
    /// helper allocates the TCP cid (the connect alone counts as the
    /// SO contribution from our side), arms a timeout, and falls
    /// back to UDP-style framing once the cid is up. Returns the
    /// cid or 0 on failure.
    gn_conn_id_t arm_tcp_so_connect(const std::string& ip,
                                      std::uint16_t port);
    void handle_check_response(const StunMessage& msg);
    void on_nominated(const std::string& ip, uint16_t port, bool relay,
                       gn_conn_id_t cid, TransportType transport);

    /// Strand-only carrier dispatch for one application payload.
    /// Extracted out of `send()` so it can be reused by
    /// `flush_pending_app_data()` after nomination completes; takes
    /// the buf by const ref because the caller (`flush_*` /
    /// `send_on_strand` lambda) already owns the storage.
    void send_on_strand(const std::vector<std::uint8_t>& buf);

    /// Drain `pending_app_data_` through `send_on_strand`. Called
    /// from `on_nominated` once `state_` is set to Connected and the
    /// nominated cid is published; safe-by-construction because the
    /// FIFO is strand-only.
    void flush_pending_app_data();

    /// RFC 8445 §7.3.1.1 role-conflict resolution. Called from the
    /// inbound BINDING_REQUEST path when the peer's role attribute
    /// matches our own claimed role. Returns true when the local
    /// agent switched role (sender wins, no 487 sent), false when we
    /// kept our role (sender loses, caller must emit a 487 error
    /// response). Strand-only.
    bool handle_role_conflict(bool sender_controlling,
                                uint64_t sender_tiebreaker);

    /// Count of pairs currently in `PairState::InProgress`. Used by
    /// `run_next_check` to clamp at `kCheckConcurrencyCap` (RFC §6.1.2.5).
    std::size_t in_progress_count() const noexcept;

    /// RFC 8445 §6.1.2.6 sibling unfreeze. After a pair sharing
    /// foundation tuple `(local_fnd, remote_fnd)` transitions to
    /// Succeeded OR Failed, every Frozen pair with the same tuple
    /// flips to Waiting so `run_next_check` can pick them up.
    /// Strand-only.
    void unfreeze_siblings(const std::string& local_fnd,
                             const std::string& remote_fnd);

    /// RFC 8445 §6.1.2.6 recompute-states fallback. Called from
    /// `run_next_check` when the check list has no Waiting or
    /// InProgress pair remaining but Frozen pairs are still parked.
    /// Promotes one Frozen pair per remaining foundation tuple to
    /// Waiting so progress is not stranded. Strand-only.
    void unfreeze_stuck_pairs();

    /// Populate the foundation field on every local candidate from
    /// `(type, base, server, transport)` so post-gather code paths
    /// can look it up without recomputing. Strand-only.
    void assign_local_foundations();

    /// Dispatch entry for bytes arriving on a per-endpoint cid. Called
    /// from the per-conn `on_data` callback installed by
    /// `ensure_remote_cid`. Drives the STUN parsing / FSM.
    ///
    /// `from_tcp` distinguishes UDP- vs TCP-carrier delivery. UDP and
    /// TCP carrier plugins issue cids from independent counters that
    /// can numerically collide (both set high bit, start at 1); the
    /// flag tells the FSM which carrier owns this cid so reply paths
    /// don't route through the wrong vtable.
    void on_carrier_data(gn_conn_id_t cid,
                          std::span<const std::uint8_t> bytes,
                          bool from_tcp = false);

    /// composer_connect → cid mapping; reuses an existing cid if the
    /// endpoint has been seen before. Returns 0 on failure. Strand-only.
    gn_conn_id_t ensure_remote_cid(const std::string& ip, uint16_t port);

    /// Lazily mint a synthetic cid for a (peer_ip, peer_port) endpoint
    /// reachable only through the TURN allocation. First call stamps
    /// `cid_to_endpoint_udp_[cid] = {ip, port, Udp}` so the response
    /// path in `on_carrier_data` can recover the peer endpoint via the
    /// usual `ep_map.find(cid)` lookup. Subsequent calls for the same
    /// endpoint return the same cid (idempotent). High bit is set so
    /// the values do not collide with carrier-assigned cids — the
    /// dispatch site checks `cid >= 0x8000000000000000ULL` to spot a
    /// synthetic cid and route the response back via
    /// `turn_->send_indication`. Strand-only.
    gn_conn_id_t relay_cid_for_endpoint(const std::string& ip,
                                          std::uint16_t port);

    /// TCP variant of `ensure_remote_cid` — opens the endpoint on the
    /// `gn.link.tcp` carrier (`carrier_tcp_`). Each invocation
    /// allocates a fresh cid; TCP sockets are not reused across
    /// pairs because the framing state is per-connection. Returns 0
    /// when no TCP carrier is wired or `connect` fails. Strand-only.
    gn_conn_id_t ensure_remote_tcp_cid(const std::string& ip,
                                          uint16_t port);

    /// RFC 5389 §7.2.2 STUN-over-TCP framing. Prepends a 16-bit
    /// big-endian length prefix to @p msg so the peer can split STUN
    /// messages out of the byte stream. The wire form is
    /// `<2 bytes length><STUN message>`.
    static std::vector<std::uint8_t> frame_tcp_stun(
        std::span<const std::uint8_t> msg);

    /// Drains as many complete STUN messages as the reassembly buffer
    /// for @p cid contains, dispatching each through
    /// `on_carrier_data`. Strand-only. TCP carriers may chunk bytes
    /// arbitrarily; this routine handles short reads and split-frame
    /// boundaries without losing alignment.
    void on_tcp_carrier_data(gn_conn_id_t cid,
                              std::span<const std::uint8_t> bytes);

    /// Application-level TCP handshake deadline expired for @p cid
    /// without a single inbound byte arriving. Drops the L1 socket
    /// (composer_disconnect closes the kernel descriptor), demotes
    /// every in-progress pair using this endpoint to `Failed`, and
    /// unfreezes their siblings so the FSM advances to the next
    /// candidate without waiting out the kernel SYN-retry budget.
    /// Strand-only.
    void on_tcp_connect_timeout(gn_conn_id_t cid);

    /// Replace HostMdns entries in `remote_candidates_` with their
    /// resolved IP equivalents. For each `<uuid>.local` candidate,
    /// query the mDNS resolver, replace the entry with a regular
    /// Host candidate using the resolved IP if successful, or drop
    /// it if resolution times out. The replacement happens in-place
    /// and is followed by `build_check_list` / `run_next_check` so
    /// pairs against the resolved IPs enter the check queue. Safe
    /// to call before the FSM has reached Checking — the resolution
    /// completes asynchronously and the result is folded in via
    /// `add_remote_candidates`-like logic.
    void resolve_remote_mdns_candidates();

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

    /// Guard: fire callbacks_.on_gathered at most once per gather cycle.
    /// Reset by restart() so the next gather cycle can emit a fresh signal.
    bool gathered_signal_fired_ = false;

    /// Gather-coordination flags: STUN and TURN phases run concurrently.
    /// on_gathering_complete() is held until both are resolved so the
    /// offer/answer always includes relay candidates when a TURN server
    /// is configured. Reset by restart().
    bool stun_gathered_  = false;   ///< srflx arrived (or no STUN servers)
    bool turn_gathering_ = false;   ///< TURN allocation in flight

    /// Peer-advertised wire flags from the most recent signal envelope.
    /// Atomic so `local_signal_flags()` style read sites stay
    /// lock-free; writes happen on the strand.
    std::atomic<std::uint32_t> peer_signal_flags_{0};

    /// Symmetric NAT detection — observed external port stride during
    /// gather. Non-zero stride enables port prediction in
    /// `build_check_list` when the peer also advertises
    /// `ICE_SIGNAL_FLAG_SYMMETRIC`. Recorded when multiple STUN
    /// probes from the same local port report different external
    /// ports.
    std::atomic<std::uint16_t> symmetric_stride_{0};
    /// First observed external port from a STUN binding response.
    /// Used to compute the stride when a second response from a
    /// different server arrives with a different port. Reset on
    /// restart.
    std::uint16_t              first_observed_srflx_port_ = 0;
    bool                       have_first_srflx_port_     = false;

    void start_keepalive();
    void on_keepalive();

    /// RFC 8899 DPLPMTUD: fire the next probe queued by `pmtu_probe_`
    /// if the FSM is in `Searching`. Arms `pmtu_probe_timer_` for
    /// `cfg_.pmtu_probe_timeout_ms`. Stops when the probe machine
    /// reports `SearchComplete`.
    void start_path_mtu_probe();
    void on_path_mtu_probe_timeout();

    static std::string generate_ufrag();
    static std::string generate_pwd();

    /// PathMtuProbe instance — present only when active probing is
    /// enabled by the operator. nullptr otherwise, in which case
    /// `effective_mtu_` stays pinned at the static config floor.
    std::unique_ptr<PathMtuProbe>   pmtu_probe_;
    /// Most recent probe transaction id; matched on the inbound
    /// path so a legitimate binding-response routes back into the
    /// probe machine rather than the consent counter.
    TransactionId                  pmtu_inflight_txn_{};
    bool                            pmtu_inflight_       = false;
    /// Timer covering the in-flight probe; fires
    /// `on_path_mtu_probe_timeout` if no ACK arrives in time.
    asio::steady_timer              pmtu_probe_timer_;
    /// Discovered MTU surfaced through `effective_path_mtu()` and
    /// the `gn.link.ice.path_mtu` extension. Atomic so callers can
    /// read without entering the strand.
    std::atomic<std::uint32_t>      effective_mtu_{0};
};

} // namespace gn::link::ice
