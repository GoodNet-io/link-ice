// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#include "dns_ext_client.hpp"

#include <sdk/cpp/uri.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace gn::link::ice {

namespace {

/// Big-endian readers for the wire-encoded SRV body. Mirrors what
/// `gn::handler::dns::encode_srv` produces — 2B priority + 2B
/// weight + 2B port + RFC 1035 name (length-prefixed labels,
/// terminated by a zero octet). The codecs intentionally avoid
/// the compression pointers (RFC 1035 §4.1.4) so we never need a
/// surrounding message context to decode.
std::uint16_t read_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

/// Decode an RFC 1035 name from @p src, returning the dotted form
/// and the number of bytes consumed. Pointer-form labels (top 2
/// bits of a length octet) are rejected — handler-dns never
/// encodes them in stored rdata.
struct NameView {
    std::string name;
    std::size_t consumed = 0;
    bool        ok       = false;
};

NameView decode_name(const std::uint8_t* src, std::size_t len) {
    NameView out;
    std::size_t cursor = 0;
    while (cursor < len) {
        const std::uint8_t lb = src[cursor++];
        if ((lb & 0xC0) != 0) return out;       // compression pointer
        if (lb == 0) {                          // root terminator
            out.consumed = cursor;
            out.ok = true;
            return out;
        }
        if (lb > 63)                  return out; // RFC 1035 §2.3.4
        if (cursor + lb > len)        return out; // truncated label
        if (!out.name.empty()) out.name.push_back('.');
        out.name.append(reinterpret_cast<const char*>(src + cursor), lb);
        cursor += lb;
    }
    return out;
}

/// Parse one SRV rdata blob into a `ResolvedSrv`. Returns nullopt
/// on malformed input.
std::optional<ResolvedSrv>
parse_srv_blob(const std::uint8_t* rdata, std::size_t rdata_len) {
    if (rdata_len < 7) return std::nullopt;   // 6-byte header + min 1-byte name
    ResolvedSrv r;
    r.priority = read_be16(rdata + 0);
    r.weight   = read_be16(rdata + 2);
    r.port     = read_be16(rdata + 4);
    auto nv = decode_name(rdata + 6, rdata_len - 6);
    if (!nv.ok) return std::nullopt;
    r.target = std::move(nv.name);
    return r;
}

/// Sink struct passed to the extension's emit callback. The C
/// thunk converts borrowed `gn_dns_record_t` views into owned
/// `ResolvedSrv` entries.
struct SrvSink {
    std::vector<ResolvedSrv> out;
};

void srv_emit(void* user, const gn_dns_record_t* rec) {
    if (user == nullptr || rec == nullptr) return;
    if (rec->type != static_cast<std::uint16_t>(GN_DNS_RR_SRV)) return;
    if (auto p = parse_srv_blob(rec->rdata, rec->rdata_len)) {
        p->ttl_s = rec->ttl_s;
        static_cast<SrvSink*>(user)->out.push_back(std::move(*p));
    }
}

}  // namespace

// ── parse_service_uri ──────────────────────────────────────────────────────

std::optional<ServiceUri> parse_service_uri(std::string_view raw) {
    /// Thin wrapper over `gn::parse_uri` (sdk/cpp/uri.hpp). The SDK
    /// parser is the single canonical URI parser shared by every
    /// transport plugin; ICE-specific quirks (RFC 7064's optional
    /// `//` authority delimiter, RFC 7065's `user[:pass]@` userinfo,
    /// the SRV-expansion "no port" form) are handled here as
    /// preprocessing + post-extraction so the SDK parser stays the
    /// one source of truth for control-byte rejection, port-overflow
    /// rejection, and `host:port` splitting.
    ///
    /// Accepted shapes (rejected → nullopt):
    ///   stun:host                       — SRV expansion (port == 0)
    ///   stun:host:port                  — RFC 7064 canonical
    ///   stun://host[:port]              — colloquial / WebRTC `urls`
    ///   turn://user[:pass]@host:port    — RFC 7065 with credentials
    /// Bracketed IPv6 literals, "https:…", and bare "host:port" all
    /// fall through to nullopt — caller treats those as legacy.

    /// Run the SDK's control-byte gate first so smuggled CR/LF can
    /// never reach the rest of this function (uri.en.md §5 #10).
    if (gn::uri_has_control_bytes(raw)) return std::nullopt;

    const auto scheme_end = raw.find(':');
    if (scheme_end == std::string_view::npos) return std::nullopt;
    const auto scheme = raw.substr(0, scheme_end);
    if (scheme != "stun" && scheme != "turn") return std::nullopt;
    auto rest = raw.substr(scheme_end + 1);
    if (rest.empty()) return std::nullopt;

    /// Strip the optional `//` authority-delimiter — RFC 7064 says
    /// `stun:` (no slashes) is canonical, but every WebRTC config
    /// shipped in the wild emits `stun://` so we tolerate both.
    if (rest.size() >= 2 && rest[0] == '/' && rest[1] == '/') {
        rest.remove_prefix(2);
        if (rest.empty()) return std::nullopt;
    }

    /// Drop the optional `user[:pass]@` userinfo segment. RFC 7065
    /// §3 lets credentials ride in the URI; our config schema feeds
    /// them out-of-band through `ice.turn_username` / `turn_password`,
    /// so we silently discard whatever's before the rightmost `@`.
    if (auto at = rest.rfind('@'); at != std::string_view::npos) {
        rest.remove_prefix(at + 1);
        if (rest.empty()) return std::nullopt;
    }

    /// Bracketed IPv6 literal — operator picked an explicit address
    /// and SRV expansion can't apply. Bounce back to the legacy
    /// path so the caller falls through to its IP-literal branch.
    if (rest.front() == '[') return std::nullopt;

    ServiceUri u;
    u.scheme = std::string(scheme);

    /// No `:` in the authority → SRV-expansion request, no port.
    /// The SDK parser refuses missing ports by design (uri.en.md §5 #4),
    /// so this branch is the one piece the SDK can't validate for us
    /// — we still validated control bytes above.
    if (rest.find(':') == std::string_view::npos) {
        u.host = std::string(rest);
        u.port = 0;
        return u;
    }

    /// Hand the normalised `scheme://host:port` form to the SDK
    /// parser. `gn::parse_uri` owns host/port splitting + port-range
    /// + trailing-garbage rejection from this point on.
    std::string canonical;
    canonical.reserve(u.scheme.size() + 3 + rest.size());
    canonical.append(u.scheme).append("://").append(rest);

    const auto parts = gn::parse_uri(canonical);
    if (!parts || parts->host.empty() || parts->port == 0) {
        return std::nullopt;
    }

    u.host = parts->host;
    u.port = parts->port;
    return u;
}

// ── DnsExtClient ───────────────────────────────────────────────────────────

std::optional<DnsExtClient> DnsExtClient::query(const host_api_t* api) {
    if (api == nullptr || api->query_extension_checked == nullptr) {
        return std::nullopt;
    }
    const void* raw = nullptr;
    const gn_result_t rc = api->query_extension_checked(
        api->host_ctx, GN_EXT_DNS,
        GN_EXT_DNS_VERSION, &raw);
    if (rc != GN_OK || raw == nullptr) return std::nullopt;
    const auto* vt = static_cast<const gn_dns_api_t*>(raw);
    if (vt->api_size < sizeof(gn_dns_api_t)) return std::nullopt;
    if (vt->resolve == nullptr)              return std::nullopt;
    return DnsExtClient(api, vt);
}

std::vector<ResolvedSrv>
DnsExtClient::resolve_srv(std::string_view srv_name,
                           std::uint32_t max_results) const {
    SrvSink sink;
    if (vt_ == nullptr || vt_->resolve == nullptr) return {};

    (void)vt_->resolve(vt_->ctx,
                       srv_name.data(), srv_name.size(),
                       static_cast<std::uint16_t>(GN_DNS_RR_SRV),
                       max_results,
                       &srv_emit, &sink);

    /// RFC 2782: sort ascending by priority; within a priority
    /// class targets share weight slots. We don't run the
    /// randomised weight-bucket pick here — the ICE check list
    /// will probe every target anyway, and the order primarily
    /// affects which probe fires first. Deterministic ordering
    /// keeps tests stable.
    std::sort(sink.out.begin(), sink.out.end(),
              [](const ResolvedSrv& a, const ResolvedSrv& b) {
                  if (a.priority != b.priority) return a.priority < b.priority;
                  if (a.weight   != b.weight)   return a.weight   > b.weight;
                  return a.target < b.target;
              });
    return std::move(sink.out);
}

std::vector<ResolvedSrv>
DnsExtClient::resolve_service(std::string_view service,
                                std::string_view proto,
                                std::string_view host,
                                std::uint32_t max_results) const {
    /// _service._proto.host — leading underscores per RFC 2782.
    std::string srv_name;
    srv_name.reserve(2 + service.size() + 2 + proto.size() + 1 + host.size());
    srv_name.push_back('_');
    srv_name.append(service);
    srv_name.push_back('.');
    srv_name.push_back('_');
    srv_name.append(proto);
    srv_name.push_back('.');
    srv_name.append(host);
    return resolve_srv(srv_name, max_results);
}

}  // namespace gn::link::ice
