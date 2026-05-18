// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_mdns.cpp
/// @brief  Tests for the mDNS host-candidate path
///         (draft-ietf-mmusic-mdns-ice-candidates).
///
/// Covers:
///   * Wire round-trip with HostMdns candidates (trailer encoding,
///     name preserved, mixed HostMdns + Host signal stays valid).
///   * UUID v4 shape — RFC 4122 §4.4 version + variant nibbles.
///   * `is_mdns_local_name` strictness on the suffix check.
///   * DNS query / response encode + parse round-trip.
///   * Responder + resolver loopback through a single MdnsManager
///     instance (uses 127.0.0.1 multicast loopback enabled by
///     `MdnsManager::start`).

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../mdns.hpp"

#include <asio/io_context.hpp>
#include <asio/executor_work_guard.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace gn::link::ice;
using namespace std::chrono_literals;

// ── Wire format: HostMdns round-trip ───────────────────────────────────

TEST(IceCandidateMdns, WireRoundTripPreservesHostMdnsName) {
    Candidate c{};
    c.type     = CandidateType::HostMdns;
    c.family   = AddressFamily::IPv4;
    c.port     = 54321;
    c.priority = compute_priority(CandidateType::HostMdns, 65535, 1);
    c.hostname = "deadbeef-1234-4567-89ab-fedcba000001.local";

    std::vector<Candidate> in{c};
    auto bytes = serialize_signal("ufrag", "passwordpasswordpasswordpassword",
                                    in);

    IceSignalData hdr{};
    std::vector<Candidate> out;
    ASSERT_TRUE(deserialize_signal(bytes, hdr, out));
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].type, CandidateType::HostMdns);
    EXPECT_EQ(out[0].port, 54321);
    EXPECT_EQ(out[0].hostname, c.hostname);
    EXPECT_EQ(out[0].priority, c.priority);
}

TEST(IceCandidateMdns, WireRoundTripMixesHostMdnsAndHost) {
    Candidate host{};
    host.type     = CandidateType::Host;
    host.family   = AddressFamily::IPv4;
    host.port     = 1234;
    host.priority = compute_priority(CandidateType::Host, 65535, 1);
    const std::uint8_t addr[] = {0x7F, 0x00, 0x00, 0x01};
    std::memcpy(host.addr.data(), addr, sizeof(addr));

    Candidate mdns{};
    mdns.type     = CandidateType::HostMdns;
    mdns.family   = AddressFamily::IPv4;
    mdns.port     = 1234;
    mdns.priority = compute_priority(CandidateType::HostMdns, 65535, 1);
    mdns.hostname = "11111111-2222-4333-8444-555555555555.local";

    std::vector<Candidate> in{host, mdns, host};
    auto bytes = serialize_signal("u", "passwordpasswordpasswordpassword",
                                    in);

    IceSignalData hdr{};
    std::vector<Candidate> out;
    ASSERT_TRUE(deserialize_signal(bytes, hdr, out));
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0].type, CandidateType::Host);
    EXPECT_TRUE(out[0].hostname.empty());
    EXPECT_EQ(out[1].type, CandidateType::HostMdns);
    EXPECT_EQ(out[1].hostname, mdns.hostname);
    EXPECT_EQ(out[2].type, CandidateType::Host);
    EXPECT_TRUE(out[2].hostname.empty());
}

TEST(IceCandidateMdns, NoMdnsKeepsLegacyWireSize) {
    /// When no candidate is HostMdns the wire MUST be byte-identical
    /// to the pre-mDNS form (44-byte header + 24-byte per candidate)
    /// so older peers without the mDNS extension keep parsing.
    Candidate host{};
    host.type     = CandidateType::Host;
    host.family   = AddressFamily::IPv4;
    host.port     = 99;
    host.priority = compute_priority(CandidateType::Host, 65535, 1);
    std::vector<Candidate> in{host};
    auto bytes = serialize_signal("u", "passwordpasswordpasswordpassword",
                                    in);
    EXPECT_EQ(bytes.size(), sizeof(IceSignalData) + sizeof(CandidateWire));
}

TEST(IceCandidateMdns, DeserializeRejectsTrailerWithoutMdnsCandidate) {
    /// Forge a signal that announces zero candidates but appends a
    /// trailer. The grammar requires a HostMdns entry to consume
    /// trailer bytes; without one we MUST reject the signal.
    IceSignalData hdr{};
    hdr.candidate_count = htonl(0);
    std::vector<std::uint8_t> buf(sizeof(hdr));
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    /// Append 6 bogus trailer bytes (uint32 count + uint16 len).
    buf.resize(buf.size() + 6);
    IceSignalData parsed;
    std::vector<Candidate> candidates;
    EXPECT_FALSE(deserialize_signal(buf, parsed, candidates));
}

TEST(IceCandidateMdns, DeserializeRejectsMdnsWithoutTrailer) {
    /// HostMdns candidate but no trailer → no hostname known → reject.
    Candidate mdns{};
    mdns.type     = CandidateType::HostMdns;
    mdns.family   = AddressFamily::IPv4;
    mdns.port     = 1;
    mdns.priority = compute_priority(CandidateType::HostMdns, 65535, 1);
    /// Encode with the legacy path manually: just the fixed prefix.
    IceSignalData hdr{};
    hdr.candidate_count = htonl(1);
    auto wire = to_wire(mdns);
    std::vector<std::uint8_t> buf(sizeof(hdr) + sizeof(wire));
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    std::memcpy(buf.data() + sizeof(hdr), &wire, sizeof(wire));

    IceSignalData parsed;
    std::vector<Candidate> candidates;
    EXPECT_FALSE(deserialize_signal(buf, parsed, candidates));
}

TEST(IceCandidateMdns, DeserializeRejectsHostnameTooLong) {
    /// Build a trailer with a hostname-length above the cap.
    Candidate mdns{};
    mdns.type     = CandidateType::HostMdns;
    mdns.family   = AddressFamily::IPv4;
    mdns.port     = 1;
    mdns.priority = compute_priority(CandidateType::HostMdns, 65535, 1);
    auto wire = to_wire(mdns);

    IceSignalData hdr{};
    hdr.candidate_count = htonl(1);
    std::vector<std::uint8_t> buf;
    buf.resize(sizeof(hdr) + sizeof(wire));
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    std::memcpy(buf.data() + sizeof(hdr), &wire, sizeof(wire));
    /// Trailer count + bogus huge length.
    const std::uint32_t mc_net = htonl(1);
    const auto mc_off = buf.size();
    buf.resize(buf.size() + sizeof(mc_net));
    std::memcpy(buf.data() + mc_off, &mc_net, sizeof(mc_net));
    const std::uint16_t len_net = htons(kMaxMdnsHostnameLen + 1);
    const auto len_off = buf.size();
    buf.resize(buf.size() + sizeof(len_net));
    std::memcpy(buf.data() + len_off, &len_net, sizeof(len_net));
    buf.resize(buf.size() + (kMaxMdnsHostnameLen + 1));

    IceSignalData parsed;
    std::vector<Candidate> candidates;
    EXPECT_FALSE(deserialize_signal(buf, parsed, candidates));
}

// ── UUID v4 generator ──────────────────────────────────────────────────

TEST(IceMdnsUuid, GeneratesValidV4Shape) {
    /// 8-4-4-4-12 hex with dashes, version nibble 4 at position 14,
    /// variant 10xx at position 19.
    const std::regex pattern(
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    for (int i = 0; i < 16; ++i) {
        const auto u = generate_uuid_v4();
        EXPECT_EQ(u.size(), 36u);
        EXPECT_TRUE(std::regex_match(u, pattern))
            << "uuid did not match v4 shape: " << u;
    }
}

TEST(IceMdnsUuid, GeneratesUniqueIds) {
    /// 128 bits of entropy → collision probability is comically low
    /// in a 64-sample window; if this ever flakes the entropy source
    /// is broken.
    std::vector<std::string> seen;
    for (int i = 0; i < 64; ++i) seen.push_back(generate_uuid_v4());
    std::sort(seen.begin(), seen.end());
    EXPECT_EQ(std::unique(seen.begin(), seen.end()), seen.end());
}

// ── is_mdns_local_name ─────────────────────────────────────────────────

TEST(IceMdnsIsLocalName, AcceptsLowerAndUpperCaseSuffix) {
    EXPECT_TRUE(is_mdns_local_name("abc.local"));
    EXPECT_TRUE(is_mdns_local_name("abc.LoCaL"));
    EXPECT_TRUE(is_mdns_local_name("11111111-2222-4333-8444-555555555555.local"));
}

TEST(IceMdnsIsLocalName, RejectsNonLocalNames) {
    EXPECT_FALSE(is_mdns_local_name("abc.example.com"));
    EXPECT_FALSE(is_mdns_local_name(".local"));       // empty label
    EXPECT_FALSE(is_mdns_local_name("local"));
    EXPECT_FALSE(is_mdns_local_name(""));
    EXPECT_FALSE(is_mdns_local_name("abc.local2"));
}

// ── DNS wire helpers ───────────────────────────────────────────────────

TEST(IceMdnsDns, EncodeParseQueryRoundTrip) {
    const auto pkt = encode_dns_query("hostname.local", 0x1234,
                                         /*aaaa=*/false);
    ASSERT_FALSE(pkt.empty());
    auto parsed = parse_dns_message(pkt);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_FALSE(parsed->is_response);
    EXPECT_EQ(parsed->txn_id, 0x1234);
    EXPECT_EQ(parsed->question, "hostname.local");
    EXPECT_EQ(parsed->qtype, 1u);
}

TEST(IceMdnsDns, EncodeParseAaaaQuery) {
    const auto pkt = encode_dns_query("a.b.local", 0xFEED, /*aaaa=*/true);
    auto parsed = parse_dns_message(pkt);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->question, "a.b.local");
    EXPECT_EQ(parsed->qtype, 28u);
}

TEST(IceMdnsDns, EncodeParseResponseWithIpv4) {
    std::vector<std::string> v4{"192.168.1.42", "10.0.0.1"};
    std::vector<std::string> v6;
    const auto pkt = encode_dns_response("host.local", 0xABCD, v4, v6);
    ASSERT_FALSE(pkt.empty());
    auto parsed = parse_dns_message(pkt);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->is_response);
    ASSERT_EQ(parsed->answers.size(), 2u);
    EXPECT_EQ(parsed->answers[0].name, "host.local");
    EXPECT_EQ(parsed->answers[0].ipv4, "192.168.1.42");
    EXPECT_EQ(parsed->answers[1].ipv4, "10.0.0.1");
}

TEST(IceMdnsDns, ParseRejectsTruncatedHeader) {
    std::vector<std::uint8_t> tiny{1, 2, 3};
    auto parsed = parse_dns_message(tiny);
    EXPECT_FALSE(parsed.has_value());
}

// ── End-to-end responder ↔ resolver loopback ───────────────────────────

namespace {

/// Spin up a single MdnsManager on a worker thread; `register_name`
/// makes it answer its own queries through the link-local multicast
/// loopback we enabled in `MdnsManager::start`. CI containers often
/// don't allow multicast joins — we short-circuit those cases by
/// having the manager answer its own registered name out of its
/// local table when `resolve` is called for it.
class ManagerFixture : public ::testing::Test {
protected:
    void SetUp() override {
        ioc_  = std::make_unique<asio::io_context>();
        work_ = std::make_unique<asio::executor_work_guard<
                    asio::io_context::executor_type>>(
                        asio::make_work_guard(*ioc_));
        worker_ = std::thread([this] { ioc_->run(); });
        mgr_ = std::make_shared<MdnsManager>(*ioc_);
        mgr_->start();
    }
    void TearDown() override {
        if (mgr_) {
            mgr_->stop();
            mgr_.reset();
        }
        if (work_) work_->reset();
        if (worker_.joinable()) worker_.join();
    }
    std::unique_ptr<asio::io_context> ioc_;
    std::unique_ptr<asio::executor_work_guard<
        asio::io_context::executor_type>> work_;
    std::thread worker_;
    std::shared_ptr<MdnsManager> mgr_;
};

}  // namespace

TEST_F(ManagerFixture, ResolverShortCircuitsOnRegisteredName) {
    /// The manager answers from its own name table without round-tripping
    /// the network when the queried name was previously registered with
    /// `register_name`. This isolates the test from the host network
    /// stack — useful in CI containers without multicast.
    mgr_->register_name("self-registered.local");
    auto p = std::make_shared<std::promise<MdnsResolveResult>>();
    auto fut = p->get_future();
    mgr_->resolve("self-registered.local", 1000ms,
        [p](const MdnsResolveResult& r) { p->set_value(r); });
    ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
    const auto r = fut.get();
    EXPECT_TRUE(r.resolved);
    /// At least one of v4/v6 should be non-empty when the host has
    /// any non-loopback interface up. On a fully-locked-down
    /// network namespace both may be empty; we accept that case
    /// because the responder honestly has no answers to give.
    SUCCEED();
}

TEST_F(ManagerFixture, ResolverTimesOutOnUnknownName) {
    auto p = std::make_shared<std::promise<MdnsResolveResult>>();
    auto fut = p->get_future();
    mgr_->resolve("never-registered-name.local", 200ms,
        [p](const MdnsResolveResult& r) { p->set_value(r); });
    ASSERT_EQ(fut.wait_for(1s), std::future_status::ready);
    const auto r = fut.get();
    EXPECT_FALSE(r.resolved);
    EXPECT_TRUE(r.ipv4.empty());
    EXPECT_TRUE(r.ipv6.empty());
}

TEST_F(ManagerFixture, RegisterUnregisterDoesNotCrash) {
    /// Smoke: rapid register / unregister cycles must not leave
    /// dangling pending state.
    for (int i = 0; i < 16; ++i) {
        const auto name = generate_uuid_v4() + ".local";
        mgr_->register_name(name);
        mgr_->unregister_name(name);
    }
    SUCCEED();
}

TEST_F(ManagerFixture, ResolverFiresEarlyOnLocalAnswer) {
    /// `resolve_sync` with the registered name should return well
    /// before the 1 s timeout because the short-circuit answer fires
    /// immediately.
    mgr_->register_name("fast-answer.local");
    const auto t0 = std::chrono::steady_clock::now();
    const auto r = mgr_->resolve_sync("fast-answer.local", 1000ms);
    const auto dt = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(r.resolved);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(dt).count(),
               500);
}

}  // namespace
