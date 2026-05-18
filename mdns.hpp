// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/mdns.hpp
/// @brief  Minimal multicast DNS responder + resolver for ICE host
///         candidate obfuscation per draft-ietf-mmusic-mdns-ice-candidates
///         and RFC 6762 (mDNS).
///
/// The responder registers `<uuid>.local` hostnames and answers A/AAAA
/// queries from the local link with the host's interface addresses.
/// The resolver issues a one-shot multicast query for a `.local`
/// hostname and returns the IP(s) within a configurable timeout.
///
/// Linux-first implementation. macOS / Windows can use the system
/// mDNS daemon (`mDNSResponder` on macOS, Bonjour on Windows); those
/// paths are marked `#ifdef` and currently fall back to the local
/// responder if the platform-native path is not wired in.
///
/// Threading model: every public method posts to `strand_`; the
/// multicast socket lives on the same strand so there is no internal
/// concurrency. Callers may invoke `register_name` / `resolve` from
/// any thread.

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>

namespace gn::link::ice {

/// IANA-assigned mDNS multicast addresses and port (RFC 6762 §3).
inline constexpr const char* kMdnsIPv4MulticastAddr = "224.0.0.251";
inline constexpr const char* kMdnsIPv6MulticastAddr = "ff02::fb";
inline constexpr std::uint16_t kMdnsPort           = 5353;

/// Result of a successful mDNS resolution.
struct MdnsResolveResult {
    /// All A and AAAA records collected before timeout. Empty when
    /// the resolver gave up without a reply.
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    /// True when at least one answer arrived before timeout.
    bool resolved = false;
};

/// Generate an RFC 4122 v4 UUID as a 36-character lowercase string
/// (8-4-4-4-12 hex with dashes, version nibble 0x4, variant 0b10xx).
/// Uses libsodium's `randombytes_buf` so the entropy source is the
/// same one ICE already trusts for ufrag / pwd / tiebreaker.
[[nodiscard]] std::string generate_uuid_v4();

/// Returns true if `name` looks like a `.local` mDNS hostname per
/// RFC 6762 §3 (case-insensitive `.local` suffix, at least one
/// label before it, total length within DNS label limits).
[[nodiscard]] bool is_mdns_local_name(std::string_view name) noexcept;

using MdnsResolveCallback = std::function<void(const MdnsResolveResult&)>;

/// In-process mDNS responder + resolver.
///
/// One instance per ICE link plugin. Responder registers `.local`
/// names with the IPs of the host's non-loopback interfaces;
/// resolver issues a single multicast query for a `.local` name
/// and collects A/AAAA replies until timeout.
class MdnsManager : public std::enable_shared_from_this<MdnsManager> {
public:
    explicit MdnsManager(asio::io_context& io);
    ~MdnsManager();

    MdnsManager(const MdnsManager&)            = delete;
    MdnsManager& operator=(const MdnsManager&) = delete;

    /// Bind multicast socket(s) and start listening. Idempotent.
    /// Returns false when the OS refused to join the multicast
    /// group (typical on locked-down containers); the manager then
    /// degrades to resolver-only mode using unicast retransmit.
    bool start();

    /// Stop responder + resolver. Idempotent. Safe from any thread.
    void stop();

    /// Register `hostname` so the responder replies with the local
    /// host's interface addresses. `hostname` must end in `.local`
    /// (case-insensitive). Quiet when start() has not succeeded;
    /// the name is still recorded so future inbound queries are
    /// answered if start() succeeds later.
    void register_name(std::string hostname);

    /// Stop answering queries for `hostname`.
    void unregister_name(const std::string& hostname);

    /// Issue a one-shot multicast query for `hostname`. The callback
    /// fires exactly once — either with the accumulated answers
    /// when `timeout` expires, or earlier if a satisfactory answer
    /// arrived. `resolve` is safe from any thread; the callback is
    /// invoked on the manager's strand.
    void resolve(std::string hostname,
                  std::chrono::milliseconds timeout,
                  MdnsResolveCallback cb);

    /// Convenience: synchronous resolve with default 5 s timeout.
    /// Spawns a temporary event loop step on the manager's io
    /// context. Returns empty result on timeout. Caller MUST be
    /// off the manager's strand; otherwise the call dead-locks.
    [[nodiscard]] MdnsResolveResult resolve_sync(
        const std::string& hostname,
        std::chrono::milliseconds timeout = std::chrono::seconds{5});

    /// True after start() succeeded. Read-mostly snapshot;
    /// callers usually do not need this.
    [[nodiscard]] bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

private:
    /// One pending resolver record per outstanding `resolve` call.
    /// Outlives the strand work that posted it because the timeout
    /// timer holds a reference.
    struct PendingQuery {
        std::string                    hostname_lc;
        MdnsResolveCallback            cb;
        asio::steady_timer             timer;
        MdnsResolveResult              accumulated;
        std::chrono::milliseconds      timeout;
        std::uint16_t                  txn_id = 0;
        std::atomic<bool>              fired{false};

        PendingQuery(asio::strand<asio::io_context::executor_type>& s,
                       std::chrono::milliseconds t)
            : timer(s), timeout(t) {}
    };

    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    /// One v4 socket bound to 5353 with multicast group joined.
    /// IPv6 path is wired the same way under `__linux__` when the
    /// kernel supports it; query path also accepts the v6 group.
    asio::ip::udp::socket    socket_v4_;
    asio::ip::udp::endpoint  recv_endpoint_;
    std::array<std::uint8_t, 2048> rx_buf_{};

    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    /// Registered names → set of local interface IP strings. Built
    /// at register_name time so the answer path does not re-walk
    /// `getifaddrs` on every inbound query.
    struct NameRecord {
        std::vector<std::string> ipv4;
        std::vector<std::string> ipv6;
    };
    std::unordered_map<std::string, NameRecord> names_;

    /// Outstanding resolver queries keyed by lowercase hostname.
    /// Many concurrent queries on the same name share one batch;
    /// each gets its own timer + callback.
    std::unordered_map<std::string, std::vector<std::shared_ptr<PendingQuery>>>
        pending_;

    /// Collected local interface IPs — refreshed once on start().
    /// Sufficient for the typical link-local lifetime; an interface
    /// going up or down mid-session requires `stop()` + `start()`.
    std::vector<std::string> local_v4_;
    std::vector<std::string> local_v6_;

    void async_receive();
    void on_packet(std::span<const std::uint8_t> bytes,
                    const asio::ip::udp::endpoint& src);

    void send_query(const std::string& hostname_lc, std::uint16_t txn_id);
    void send_answer(const std::string& hostname,
                      const NameRecord& rec,
                      std::uint16_t txn_id,
                      const asio::ip::udp::endpoint& dst);

    static std::string to_lower(std::string s);
    static void enumerate_local_addresses(std::vector<std::string>& v4,
                                            std::vector<std::string>& v6);
};

// ── Wire-level helpers (exposed for tests) ──────────────────────────────

/// Encode a DNS message: header + one question for `hostname` of
/// type A (IPv4) or AAAA (IPv6). Returns the binary on-wire form.
std::vector<std::uint8_t> encode_dns_query(std::string_view hostname,
                                              std::uint16_t txn_id,
                                              bool want_aaaa);

/// Encode an mDNS response: one A or AAAA answer per IP in `ipv4` /
/// `ipv6` for `hostname`. The transaction id mirrors the query's
/// per RFC 6762 §6 (informational; mDNS responses are matched by
/// name, not txn id).
std::vector<std::uint8_t> encode_dns_response(std::string_view hostname,
                                                 std::uint16_t txn_id,
                                                 const std::vector<std::string>& ipv4,
                                                 const std::vector<std::string>& ipv6);

/// Parsed DNS message slice. Only the fields the responder /
/// resolver actually consume are surfaced.
struct DnsParsedMessage {
    bool                       is_response = false;
    std::uint16_t              txn_id      = 0;
    /// Lowercase question name (empty when the message has no
    /// question section).
    std::string                question;
    /// `qtype` of the first question (1 = A, 28 = AAAA).
    std::uint16_t              qtype       = 0;
    /// One entry per answer record, in wire order. Keeps name +
    /// IP type-tagged so the consumer can route A/AAAA per-name.
    struct Answer {
        std::string name;  // lowercase
        std::string ipv4;  // populated when this is an A record
        std::string ipv6;  // populated when this is an AAAA record
    };
    std::vector<Answer>        answers;
};

/// Returns nullopt on malformed input. Length / offset checks are
/// strict — pointer-loop attacks and oversize labels are rejected.
std::optional<DnsParsedMessage> parse_dns_message(
    std::span<const std::uint8_t> bytes);

}  // namespace gn::link::ice
