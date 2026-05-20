// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#include "portmap_ext_client.hpp"

#include <cstring>

namespace gn::link::ice {

std::optional<IcePortmapClient>
IcePortmapClient::query(const host_api_t* api) {
    if (api == nullptr || api->query_extension_checked == nullptr) {
        return std::nullopt;
    }
    const void* raw = nullptr;
    const gn_result_t rc = api->query_extension_checked(
        api->host_ctx, GN_EXT_PORTMAP,
        GN_EXT_PORTMAP_VERSION, &raw);
    if (rc != GN_OK || raw == nullptr) return std::nullopt;
    const auto* vt = static_cast<const gn_portmap_api_t*>(raw);
    /// Reject undersized vtables — a producer compiled against an
    /// older header would advertise the same name + version but
    /// publish a struct missing the slots we want to call. The
    /// `api_size` discipline from `sdk/abi.h` is the agreed contract.
    if (vt->api_size < sizeof(gn_portmap_api_t)) return std::nullopt;
    if (vt->supported_protocols == nullptr)      return std::nullopt;
    if (vt->request == nullptr)                  return std::nullopt;
    if (vt->release == nullptr)                  return std::nullopt;
    return IcePortmapClient(api, vt);
}

std::uint32_t IcePortmapClient::supported_protocols() const noexcept {
    if (vt_ == nullptr || vt_->supported_protocols == nullptr) return 0;
    return vt_->supported_protocols(vt_->ctx);
}

bool IcePortmapClient::request(gn_portmap_protocol_t protocol,
                                  std::uint16_t int_port,
                                  std::uint16_t external_port_hint,
                                  std::uint32_t lifetime_hint_s,
                                  gn_portmap_mapping_t* out) const noexcept {
    if (vt_ == nullptr || vt_->request == nullptr) return false;
    if (out == nullptr) return false;
    /// Producer fills `api_size` itself, but it is polite to scrub the
    /// caller-allocated slab first so a partially-written struct can
    /// be detected post-call by a future debug build.
    std::memset(out, 0, sizeof(*out));
    const int rc = vt_->request(vt_->ctx, protocol, int_port,
                                  external_port_hint, lifetime_hint_s, out);
    return rc == 0;
}

bool IcePortmapClient::release(gn_portmap_protocol_t protocol,
                                  std::uint16_t int_port) const noexcept {
    if (vt_ == nullptr || vt_->release == nullptr) return false;
    return vt_->release(vt_->ctx, protocol, int_port) == 0;
}

}  // namespace gn::link::ice
