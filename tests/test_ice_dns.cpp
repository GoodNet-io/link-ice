// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_dns.cpp
/// @brief  link-ice consuming the gn.dns extension for SRV-driven
///         `stun:<host>` / `turn:<host>` configs.
///         Covers `parse_service_uri`, `DnsExtClient::resolve_srv`
///         (priority/weight ordering), and a stubbed gn.dns
///         extension end-to-end.

#include <gtest/gtest.h>

#include <candidate.hpp>
#include <dns_ext_client.hpp>
#include <session.hpp>

#include <sdk/extensions/dns.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

// NOLINTBEGIN(bugprone-unchecked-optional-access)

namespace gn::link::ice {
namespace {

// ── candidate filter helper ────────────────────────────────────────────────

TEST(CandidateFilter, DefaultAllowsEverything) {
    /// flags == 0 → no filtering, every kind survives.
    EXPECT_TRUE(candidate_allowed(CandidateType::Host,  AddressFamily::IPv4, 0));
    EXPECT_TRUE(candidate_allowed(CandidateType::Srflx, AddressFamily::IPv6, 0));
    EXPECT_TRUE(candidate_allowed(CandidateType::Relay, AddressFamily::IPv4, 0));
    EXPECT_TRUE(candidate_allowed(CandidateType::Prflx, AddressFamily::IPv6, 0));
}

TEST(CandidateFilter, ExcludeIpv6) {
    const auto f = kCandidateFilterExcludeIpv6;
    EXPECT_TRUE (candidate_allowed(CandidateType::Host, AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Host, AddressFamily::IPv6, f));
}

TEST(CandidateFilter, ExcludeIpv4) {
    const auto f = kCandidateFilterExcludeIpv4;
    EXPECT_FALSE(candidate_allowed(CandidateType::Host, AddressFamily::IPv4, f));
    EXPECT_TRUE (candidate_allowed(CandidateType::Host, AddressFamily::IPv6, f));
}

TEST(CandidateFilter, RelayOnly) {
    const auto f = kCandidateFilterRelayOnly;
    EXPECT_FALSE(candidate_allowed(CandidateType::Host,  AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Srflx, AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Prflx, AddressFamily::IPv4, f));
    EXPECT_TRUE (candidate_allowed(CandidateType::Relay, AddressFamily::IPv4, f));
}

TEST(CandidateFilter, HostOnly) {
    const auto f = kCandidateFilterHostOnly;
    EXPECT_TRUE (candidate_allowed(CandidateType::Host,  AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Srflx, AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Relay, AddressFamily::IPv4, f));
}

TEST(CandidateFilter, CombinedRelayOnlyExcludeIpv6) {
    /// Operator running TURN over a v4-only carrier and wanting
    /// nothing else — relay + IPv4 survives, everything else
    /// drops.
    const auto f = kCandidateFilterRelayOnly | kCandidateFilterExcludeIpv6;
    EXPECT_FALSE(candidate_allowed(CandidateType::Host,  AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Relay, AddressFamily::IPv6, f));
    EXPECT_TRUE (candidate_allowed(CandidateType::Relay, AddressFamily::IPv4, f));
}

TEST(CandidateFilter, ContradictoryFlagsDropEverything) {
    /// `relay-only` + `host-only` is a diagnostic mode — the
    /// session generates no candidates and ICE fails
    /// deliberately. Verifies the AND-semantics of the two
    /// type-filters.
    const auto f = kCandidateFilterRelayOnly | kCandidateFilterHostOnly;
    EXPECT_FALSE(candidate_allowed(CandidateType::Host,  AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Srflx, AddressFamily::IPv4, f));
    EXPECT_FALSE(candidate_allowed(CandidateType::Relay, AddressFamily::IPv4, f));
}

// ── parse_service_uri ──────────────────────────────────────────────────────

TEST(ParseServiceUri, RejectsLegacyHostPort) {
    /// `stun.example.com:3478` has no scheme prefix — leave it
    /// alone and let the legacy config path consume it.
    EXPECT_FALSE(parse_service_uri("stun.example.com:3478").has_value());
    EXPECT_FALSE(parse_service_uri("1.2.3.4:3478").has_value());
}

TEST(ParseServiceUri, RejectsBracketedIpv6) {
    /// Operator passed a literal — no SRV expansion needed.
    EXPECT_FALSE(parse_service_uri("stun:[2001:db8::1]:3478").has_value());
}

TEST(ParseServiceUri, StunWithoutPortRequestsSrv) {
    auto u = parse_service_uri("stun:stun.example.com");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "stun");
    EXPECT_EQ(u.value().host,   "stun.example.com");
    EXPECT_EQ(u.value().port,   0u);
}

TEST(ParseServiceUri, TurnWithoutPortRequestsSrv) {
    auto u = parse_service_uri("turn:turn.example.com");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "turn");
    EXPECT_EQ(u.value().host,   "turn.example.com");
    EXPECT_EQ(u.value().port,   0u);
}

TEST(ParseServiceUri, StunWithExplicitPort) {
    auto u = parse_service_uri("stun:stun.example.com:3478");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "stun");
    EXPECT_EQ(u.value().host,   "stun.example.com");
    EXPECT_EQ(u.value().port,   3478u);
}

TEST(ParseServiceUri, StunWithAuthorityPrefix) {
    /// `stun://host:port` is the colloquial form (RFC 7064 says just
    /// `stun:` without the slashes, but every config-by-example
    /// shipped on the WebRTC docs and every operator handing the
    /// kernel a `stun://...` URL expects it to work). The parser
    /// strips the optional `//` and treats the rest the same way.
    auto u = parse_service_uri("stun://10.10.0.10:3478");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "stun");
    EXPECT_EQ(u.value().host,   "10.10.0.10");
    EXPECT_EQ(u.value().port,   3478u);
}

TEST(ParseServiceUri, TurnWithAuthorityAndUserinfo) {
    /// `turn://user:pass@host:port` carries credentials in the URI
    /// per RFC 7065 §3. Our config schema passes the credentials
    /// out-of-band (`ice.turn_username` / `ice.turn_password`),
    /// so the URI parser drops the userinfo segment and surfaces
    /// only the host + port.
    auto u = parse_service_uri(
        "turn://goodnet:bench-only-credentials@10.10.0.11:3478");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "turn");
    EXPECT_EQ(u.value().host,   "10.10.0.11");
    EXPECT_EQ(u.value().port,   3478u);
}

TEST(ParseServiceUri, StunWithAuthorityNoPort) {
    /// `stun://host` (no port) preserves the SRV-expansion request
    /// path. Same shape as `stun:host`.
    auto u = parse_service_uri("stun://stun.example.com");
    ASSERT_TRUE(u.has_value());
    EXPECT_EQ(u.value().scheme, "stun");
    EXPECT_EQ(u.value().host,   "stun.example.com");
    EXPECT_EQ(u.value().port,   0u);
}

TEST(ParseServiceUri, UnknownSchemeRejected) {
    EXPECT_FALSE(parse_service_uri("https:example.com").has_value());
}

TEST(ParseServiceUri, EmptyHostRejected) {
    EXPECT_FALSE(parse_service_uri("stun:").has_value());
}

// ── stub gn.dns extension + DnsExtClient ───────────────────────────────────

/// Scripted SRV table — the test populates it before each case.
struct ScriptedSrv {
    std::string   srv_name;
    std::uint16_t priority;
    std::uint16_t weight;
    std::uint16_t port;
    std::string   target;
    std::uint32_t ttl_s;
};

/// SRV rdata writer matching gn::handler::dns::encode_srv.
std::vector<std::uint8_t> encode_srv_blob(
        std::uint16_t prio, std::uint16_t w, std::uint16_t port,
        std::string_view target) {
    std::vector<std::uint8_t> b;
    b.reserve(6 + target.size() + 2);
    auto push_be16 = [&](std::uint16_t v) {
        b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        b.push_back(static_cast<std::uint8_t>(v & 0xFF));
    };
    push_be16(prio);
    push_be16(w);
    push_be16(port);
    /// RFC 1035 §3.1 name encoding — same as gn::handler::dns::encode_name.
    std::size_t start = 0;
    while (start < target.size()) {
        const auto dot = target.find('.', start);
        const auto end = (dot == std::string_view::npos)
                            ? target.size() : dot;
        const auto len = end - start;
        if (len == 0) break;
        b.push_back(static_cast<std::uint8_t>(len));
        b.insert(b.end(),
                 target.begin() + static_cast<std::ptrdiff_t>(start),
                 target.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    b.push_back(0);  // root terminator
    return b;
}

struct StubDns {
    std::vector<ScriptedSrv> srvs;

    gn_dns_api_t make_vtable() {
        gn_dns_api_t vt{};
        vt.api_size      = sizeof(gn_dns_api_t);
        vt.resolve       = &StubDns::on_resolve;
        vt.put_record    = nullptr;
        vt.delete_record = nullptr;
        vt.ctx           = this;
        return vt;
    }

private:
    static int on_resolve(void* ctx,
                          const char* name, size_t name_len,
                          std::uint16_t type, std::uint32_t /*max*/,
                          gn_dns_emit_cb_t emit, void* emit_user) {
        if (ctx == nullptr || emit == nullptr) return 0;
        if (type != static_cast<std::uint16_t>(GN_DNS_RR_SRV)) return 0;
        auto* s = static_cast<StubDns*>(ctx);
        const std::string q(name, name_len);
        int count = 0;
        /// Storage that has to outlive the emit callback — each
        /// scripted row's blob is encoded into a heap buffer the
        /// test releases at the end of `on_resolve`.
        std::vector<std::vector<std::uint8_t>> blobs;
        std::vector<std::string> names;
        std::vector<gn_dns_record_t> views;
        for (const auto& r : s->srvs) {
            if (r.srv_name != q) continue;
            blobs.push_back(
                encode_srv_blob(r.priority, r.weight, r.port, r.target));
            names.push_back(q);
            gn_dns_record_t v{};
            v.type         = static_cast<std::uint16_t>(GN_DNS_RR_SRV);
            v.name         = names.back().data();
            v.name_len     = names.back().size();
            v.rdata        = blobs.back().data();
            v.rdata_len    = blobs.back().size();
            v.ttl_s        = r.ttl_s;
            v.timestamp_us = 0;
            v.flags        = 0;
            views.push_back(v);
        }
        for (const auto& v : views) {
            emit(emit_user, &v);
            ++count;
        }
        return count;
    }
};

struct ExtensionHost {
    std::unordered_map<std::string,
                       std::pair<std::uint32_t, const void*>> extensions;
    static gn_result_t on_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out_vtable) {
        auto* h = static_cast<ExtensionHost*>(host_ctx);
        if (name == nullptr || out_vtable == nullptr) return GN_ERR_NULL_ARG;
        auto it = h->extensions.find(name);
        if (it == h->extensions.end()) return GN_ERR_NOT_FOUND;
        if (it->second.first < version) return GN_ERR_VERSION_MISMATCH;
        *out_vtable = it->second.second;
        return GN_OK;
    }
};

host_api_t make_api(ExtensionHost& host) {
    host_api_t api{};
    api.host_ctx                = &host;
    api.query_extension_checked = &ExtensionHost::on_query;
    return api;
}

// ── tests ──────────────────────────────────────────────────────────────────

TEST(DnsExtClient_Query, NulloptWhenExtensionAbsent) {
    ExtensionHost host;
    auto api = make_api(host);
    EXPECT_FALSE(DnsExtClient::query(&api).has_value());
}

TEST(DnsExtClient_Resolve, EmptyWhenNoMatch) {
    ExtensionHost host;
    StubDns stub;
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_DNS] = {GN_EXT_DNS_VERSION, &vt};

    auto api = make_api(host);
    auto client = DnsExtClient::query(&api);
    ASSERT_TRUE(client.has_value());

    auto records = client.value().resolve_srv("_stun._udp.absent.example.com");
    EXPECT_TRUE(records.empty());
}

TEST(DnsExtClient_Resolve, PriorityAscendingOrder) {
    ExtensionHost host;
    StubDns stub;
    /// Three records with priorities 30 / 10 / 20 to verify sort.
    stub.srvs = {
        {"_stun._udp.example.com", 30, 100, 3478, "stun3.example.com", 60},
        {"_stun._udp.example.com", 10,  50, 3478, "stun1.example.com", 60},
        {"_stun._udp.example.com", 20,  20, 3478, "stun2.example.com", 60},
    };
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_DNS] = {GN_EXT_DNS_VERSION, &vt};

    auto api = make_api(host);
    auto client = DnsExtClient::query(&api);
    ASSERT_TRUE(client.has_value());

    auto records = client.value().resolve_srv("_stun._udp.example.com");
    ASSERT_EQ(records.size(), 3u);
    EXPECT_EQ(records[0].priority, 10);
    EXPECT_EQ(records[1].priority, 20);
    EXPECT_EQ(records[2].priority, 30);
    EXPECT_EQ(records[0].target, "stun1.example.com");
    EXPECT_EQ(records[0].port,   3478u);
}

TEST(DnsExtClient_Resolve, WeightDescendingWithinPriority) {
    ExtensionHost host;
    StubDns stub;
    /// Same priority, different weights — higher weight first.
    stub.srvs = {
        {"_stun._udp.cluster.local", 10, 10, 3478, "low.cluster.local",  60},
        {"_stun._udp.cluster.local", 10, 80, 3478, "high.cluster.local", 60},
        {"_stun._udp.cluster.local", 10, 50, 3478, "mid.cluster.local",  60},
    };
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_DNS] = {GN_EXT_DNS_VERSION, &vt};

    auto api = make_api(host);
    auto client = DnsExtClient::query(&api);
    auto records = client.value().resolve_srv("_stun._udp.cluster.local");
    ASSERT_EQ(records.size(), 3u);
    EXPECT_EQ(records[0].target, "high.cluster.local");
    EXPECT_EQ(records[1].target, "mid.cluster.local");
    EXPECT_EQ(records[2].target, "low.cluster.local");
}

TEST(DnsExtClient_ResolveService, BuildsSrvName) {
    ExtensionHost host;
    StubDns stub;
    /// Verify the helper assembles `_stun._udp.<host>` correctly.
    stub.srvs = {
        {"_stun._udp.discovery.example.com", 5, 0, 3478, "primary", 30},
    };
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_DNS] = {GN_EXT_DNS_VERSION, &vt};

    auto api = make_api(host);
    auto client = DnsExtClient::query(&api);
    auto records = client.value().resolve_service(
        "stun", "udp", "discovery.example.com", 4);
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].target, "primary");
}

TEST(DnsExtClient_Resolve, ResolveOverTurnTcp) {
    ExtensionHost host;
    StubDns stub;
    stub.srvs = {
        {"_turn._tcp.relays.example.com", 10, 0, 5349, "relay1.example.com", 300},
        {"_turn._tcp.relays.example.com", 20, 0, 5349, "relay2.example.com", 300},
    };
    auto vt = stub.make_vtable();
    host.extensions[GN_EXT_DNS] = {GN_EXT_DNS_VERSION, &vt};

    auto api = make_api(host);
    auto client = DnsExtClient::query(&api);
    auto records = client.value().resolve_service(
        "turn", "tcp", "relays.example.com", 8);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].target, "relay1.example.com");
    EXPECT_EQ(records[0].port,   5349u);
}

}  // namespace
}  // namespace gn::link::ice

// NOLINTEND(bugprone-unchecked-optional-access)
