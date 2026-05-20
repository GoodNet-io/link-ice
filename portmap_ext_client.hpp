// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/portmap_ext_client.hpp
/// @brief  Thin C++ wrapper over the `gn.link.portmap` extension. Lets
///         the ICE plugin punch explicit (ext_ip, ext_port) mappings
///         through UPnP IGD / PCP / NAT-PMP and emit them as srflx
///         candidates alongside STUN-discovered ones.
///
/// Pattern mirrors `DnsExtClient` (see `dns_ext_client.hpp`): query the
/// host_api for a versioned extension, hold the returned vtable for
/// the lifetime of the owning plugin, provide typed C++ wrappers around
/// the C ABI slots. Graceful degradation when `gn.link.portmap` is not
/// registered — `query()` returns `nullopt` and the caller falls back
/// to the STUN-srflx / TURN-relay path unchanged.

#pragma once

#include <cstdint>
#include <optional>

#include <sdk/extensions/portmap.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::link::ice {

/// Proxy over the `gn.link.portmap` extension. Construct through
/// `query`; an absent / version-mismatched extension surfaces as
/// `std::nullopt` so the caller can degrade gracefully.
class IcePortmapClient {
public:
    [[nodiscard]] static std::optional<IcePortmapClient>
    query(const host_api_t* api);

    IcePortmapClient(const IcePortmapClient&)            = delete;
    IcePortmapClient& operator=(const IcePortmapClient&) = delete;
    IcePortmapClient(IcePortmapClient&&) noexcept        = default;
    IcePortmapClient& operator=(IcePortmapClient&&) noexcept = default;

    /// Bitmask of `GN_PORTMAP_PROTO_*` bits supported by the
    /// underlying router probe. Zero when no portmap protocol is
    /// reachable — callers MUST treat that the same as a missing
    /// extension (skip the mapping step entirely).
    [[nodiscard]] std::uint32_t supported_protocols() const noexcept;

    /// Ask the router for a new (protocol, int_port) → (ext_ip,
    /// ext_port) mapping. `external_port_hint == 0` lets the router
    /// pick; `lifetime_hint_s == 0` accepts the protocol default.
    /// Returns `true` on success and fills @p out — caller owns the
    /// storage. On failure (no router, refused, protocol unsupported)
    /// `out` is left untouched and the return is `false`.
    [[nodiscard]] bool request(gn_portmap_protocol_t protocol,
                                std::uint16_t int_port,
                                std::uint16_t external_port_hint,
                                std::uint32_t lifetime_hint_s,
                                gn_portmap_mapping_t* out) const noexcept;

    /// Release a previously-requested mapping. Best effort: the
    /// underlying plugin emits the protocol's "delete" request and
    /// drops the renewal entry regardless of the router's reply.
    /// Returning `false` only indicates that the C ABI call itself
    /// surfaced an error — callers should treat the mapping as gone
    /// either way and never block on the result.
    bool release(gn_portmap_protocol_t protocol,
                  std::uint16_t int_port) const noexcept;

    [[nodiscard]] const gn_portmap_api_t* vtable() const noexcept {
        return vt_;
    }

private:
    IcePortmapClient(const host_api_t* api,
                       const gn_portmap_api_t* vt) noexcept
        : api_(api), vt_(vt) {}

    const host_api_t*        api_ = nullptr;
    const gn_portmap_api_t*  vt_  = nullptr;
};

}  // namespace gn::link::ice
