// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/dns_ext_client.hpp
/// @brief  Thin C++ wrapper over the `gn.dns` extension. Lets the
///         ICE plugin expand `stun:<hostname>` / `turn:<hostname>`
///         configs by asking the handler-dns plugin for
///         `_stun._udp.<host>` / `_turn._<proto>.<host>` SRV
///         records — the SRV-driven STUN / TURN config path.
///
/// Pattern mirrors `sdk/cpp/link_carrier.hpp:58-75`: query the
/// host_api for a versioned extension, hold the returned vtable
/// for the lifetime of the owning plugin, provide typed C++
/// wrappers around the C ABI slots. Graceful degradation when
/// `gn.dns` is not registered — `query()` returns `nullopt` and
/// the caller falls back to IP-literal / explicit-port configs.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/extensions/dns.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::link::ice {

/// One SRV target after RFC 2782 priority + weight sorting.
struct ResolvedSrv {
    std::string   target;     ///< host or IP literal
    std::uint16_t port    = 0;
    std::uint16_t priority = 0;
    std::uint16_t weight   = 0;
    std::uint32_t ttl_s   = 0;
};

/// Proxy over the `gn.dns` extension. Construct through `query`.
class DnsExtClient {
public:
    /// Look up `gn.dns` at `GN_EXT_DNS_VERSION`. Returns nullopt
    /// when the extension is absent or its version disagrees so
    /// the caller can degrade gracefully.
    [[nodiscard]] static std::optional<DnsExtClient>
    query(const host_api_t* api);

    DnsExtClient(const DnsExtClient&)            = delete;
    DnsExtClient& operator=(const DnsExtClient&) = delete;
    DnsExtClient(DnsExtClient&&) noexcept        = default;
    DnsExtClient& operator=(DnsExtClient&&) noexcept = default;

    /// Resolve `_stun._udp.<host>` (proto = "udp") or any other
    /// SRV name. Records are RFC 2782 sorted: lower priority
    /// first; within a priority class the weight controls the
    /// order via the random selection algorithm. The wrapper
    /// returns a deterministic ordering — callers that want true
    /// RFC 2782 randomised weight selection sort themselves.
    [[nodiscard]] std::vector<ResolvedSrv>
    resolve_srv(std::string_view srv_name,
                std::uint32_t max_results = 16) const;

    /// SRV helper for STUN/TURN-style service discovery. Builds
    /// `_<service>._<proto>.<host>` and calls `resolve_srv`.
    /// `service` is typically "stun" or "turn"; `proto` is "udp"
    /// or "tcp".
    [[nodiscard]] std::vector<ResolvedSrv>
    resolve_service(std::string_view service,
                    std::string_view proto,
                    std::string_view host,
                    std::uint32_t max_results = 16) const;

    [[nodiscard]] const gn_dns_api_t* vtable() const noexcept { return vt_; }

private:
    DnsExtClient(const host_api_t* api, const gn_dns_api_t* vt) noexcept
        : api_(api), vt_(vt) {}

    const host_api_t*    api_;
    const gn_dns_api_t*  vt_;
};

/// Lightweight URI-shape probe — true when @p s looks like
/// `stun:<host>` or `turn:<host>` (possibly with `:port` after
/// the host). Returns the parsed parts; `port == 0` means
/// "operator wants SRV expansion".
struct ServiceUri {
    std::string  scheme;   ///< "stun" or "turn"; empty when not a service URI
    std::string  host;
    std::uint16_t port = 0; ///< 0 means "no explicit port, use SRV"
};

[[nodiscard]] std::optional<ServiceUri>
parse_service_uri(std::string_view raw);

}  // namespace gn::link::ice
