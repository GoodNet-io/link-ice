// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_pmtu.cpp
/// @brief  Coverage for RFC 8899 DPLPMTUD active path-MTU discovery.

#include <gtest/gtest.h>

#include "../link_ice.hpp"
#include "../path_mtu.hpp"
#include "../session.hpp"
#include "../stun.hpp"

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;

// ── PathMtuProbe state machine ──────────────────────────────────────────

TEST(PmtuStateMachine, PmtuDiscoversLargerThanBase) {
    /// Three-rung ladder above the 1200-byte base. ACK every probe
    /// the FSM proposes — the search walks linearly through the
    /// ladder and the final `effective_mtu` matches the top rung.
    PathMtuProbe probe(1200, std::vector<int>{1200, 1400, 1500});
    ASSERT_EQ(probe.state(), PathMtuState::Searching);
    /// 1200 is the base and is filtered out of the ladder; the first
    /// probe size starts at the next rung above the base.
    auto next = probe.next_probe_size();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, 1400u);
    probe.on_probe_ack();
    EXPECT_EQ(probe.effective_mtu(), 1400u);

    next = probe.next_probe_size();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, 1500u);
    probe.on_probe_ack();
    EXPECT_EQ(probe.effective_mtu(), 1500u);

    EXPECT_TRUE(probe.is_complete());
    EXPECT_FALSE(probe.next_probe_size().has_value());
}

TEST(PmtuStateMachine, PmtuHalvesOnConsecutiveLoss) {
    /// ACK the 1400-byte rung (path supports it), then lose the
    /// 1500-byte rung twice in a row. Two losses at the same size
    /// collapse the candidate to the binary-search midpoint between
    /// the last good size and the failing one. With a 100-byte gap
    /// and 8-byte granularity, the FSM bisects once and converges.
    PathMtuProbe probe(1200, std::vector<int>{1200, 1400, 1500});
    auto next = probe.next_probe_size();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, 1400u);
    probe.on_probe_ack();
    EXPECT_EQ(probe.effective_mtu(), 1400u);

    next = probe.next_probe_size();
    ASSERT_EQ(*next, 1500u);
    probe.on_probe_loss();
    /// First loss alone does not halve; the FSM is still SEARCHING.
    EXPECT_EQ(probe.state(), PathMtuState::Searching);
    probe.on_probe_loss();

    /// Effective MTU stays pinned at the highest acked size; the
    /// search either converges within the granularity window or
    /// proposes a midpoint between 1400 and 1500.
    EXPECT_GE(probe.effective_mtu(), 1400u);
    EXPECT_LT(probe.effective_mtu(), 1500u);
}

// ── IceSession: probing disabled path ───────────────────────────────────

TEST(PmtuSession, PmtuDisabledFallsBackToStatic) {
    asio::io_context ioc;
    asio::executor_work_guard<asio::io_context::executor_type> work{
        asio::make_work_guard(ioc)};
    std::thread worker([&] { ioc.run(); });

    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.path_mtu              = 1200;
    cfg.pmtu_active_probing   = false;
    IceSessionCallbacks cbs;
    auto session = std::make_shared<IceSession>(
        ioc, /*carrier=*/nullptr, nullptr, nullptr,
        cfg, /*peer_id=*/"abcdef0123456789",
        /*controlling=*/true, cbs, /*mdns=*/nullptr);

    EXPECT_EQ(session->effective_path_mtu(), 1200u);

    session->close();
    work.reset();
    ioc.stop();
    worker.join();
}

TEST(PmtuSession, PmtuSeedsEffectiveFromStaticPathMtu) {
    /// Even with active probing on, the initial `effective_path_mtu`
    /// before the FSM reaches `Connected` returns the configured
    /// floor. Probe ACKs only happen after nomination, so consumers
    /// querying early always see the conservative value.
    asio::io_context ioc;
    asio::executor_work_guard<asio::io_context::executor_type> work{
        asio::make_work_guard(ioc)};
    std::thread worker([&] { ioc.run(); });

    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.path_mtu              = 1400;
    cfg.pmtu_active_probing   = true;
    IceSessionCallbacks cbs;
    auto session = std::make_shared<IceSession>(
        ioc, /*carrier=*/nullptr, nullptr, nullptr,
        cfg, /*peer_id=*/"abcdef0123456789",
        /*controlling=*/true, cbs, /*mdns=*/nullptr);

    EXPECT_EQ(session->effective_path_mtu(), 1400u);

    session->close();
    work.reset();
    ioc.stop();
    worker.join();
}

// ── IceLink extension surface ────────────────────────────────────────────

TEST(PmtuExtension, PmtuQueryableViaExtension) {
    /// The C ABI extension wraps `IceLink::effective_path_mtu`; this
    /// test exercises that surface directly. Unknown conn ids fall
    /// back to the static configured floor rather than failing — the
    /// extension is a snapshot accessor, not an error channel.
    auto link = std::make_shared<IceLink>();
    ::gn::sdk::test::LinkStub stub;
    auto api = ::gn::sdk::test::make_link_host_api(stub);
    link->set_host_api(&api);

    const auto mtu = link->effective_path_mtu(/*conn=*/0xdeadbeefULL);
    EXPECT_EQ(mtu, link->mtu());

    link->shutdown();
}

// ── STUN padding helper ─────────────────────────────────────────────────

TEST(PmtuStunPadding, PadsToRequestedSize) {
    /// `add_padding_to` extends the build buffer to the requested
    /// wire size with an UNKNOWN-ATTRIBUTES filler. Target sizes are
    /// 4-byte aligned; non-aligned requests round down to the nearest
    /// multiple of 4 (the STUN attribute length field cannot encode
    /// non-aligned values).
    StunBuilder b(STUN_BINDING_REQUEST);
    b.add_padding_to(1200);
    auto msg = b.build();
    EXPECT_EQ(msg.size(), 1200u);

    /// Padding below the current build is a no-op.
    StunBuilder b2(STUN_BINDING_REQUEST);
    b2.add_padding_to(8);
    auto msg2 = b2.build();
    EXPECT_EQ(msg2.size(), 20u);
}

TEST(PmtuStunPadding, PaddedMessageRoundTripsThroughParser) {
    /// The padded message must still parse — the filler attribute is
    /// a comprehension-optional UNKNOWN-ATTRIBUTES that receivers
    /// silently skip per RFC 5389 §15.
    StunBuilder b(STUN_BINDING_REQUEST);
    b.add_username("ufrag1:ufrag2");
    b.add_padding_to(1500);
    auto msg = b.build();
    EXPECT_EQ(msg.size(), 1500u);

    auto parsed = parse_stun(msg);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->msg_type, STUN_BINDING_REQUEST);
    ASSERT_TRUE(parsed->username.has_value());
    EXPECT_EQ(*parsed->username, std::string("ufrag1:ufrag2"));
}

}  // namespace
}  // namespace gn::link::ice::test
