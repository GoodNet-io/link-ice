// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_composer.cpp
/// @brief  Composer-surface coverage for IceLink.
///
/// Tests exercise the L2 composer entry points — `composer_listen` /
/// `composer_connect` / `composer_subscribe_data` /
/// `composer_subscribe_accept` / `composer_listen_port` — at the C++
/// class level. The host_api stub does not expose a real `gn.link.udp`
/// extension, so the FSM degrades to a no-op gather and never reaches
/// nomination; the surface-level invariants (id allocation, bit-63
/// dispatch, idempotent disconnect, subscription tokens) are still
/// observable and that is what these tests pin.
///
/// End-to-end QUIC-over-ICE composition is covered by a separate
/// integration test that wires up a real UdpLink carrier; that lives
/// outside this plugin's unit tree because it pulls a second plugin
/// into the link surface.

#include <gtest/gtest.h>

#include "../link_ice.hpp"

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

namespace {

using namespace std::chrono_literals;
using gn::link::ice::IceLink;
using StubHost = ::gn::sdk::test::LinkStub;

inline host_api_t make_stub_api(StubHost& h) noexcept {
    return ::gn::sdk::test::make_link_host_api(h);
}

constexpr const char* kPeerPkHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

constexpr const char* kPeerPkHexAlt =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

}  // namespace

// ── composer_listen / composer_listen_port ───────────────────────────────

TEST(IceComposer, ListenAcceptsIceScheme) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    EXPECT_EQ(t->composer_listen("ice://"), GN_OK);
    t->shutdown();
}

TEST(IceComposer, ListenRejectsForeignScheme) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    EXPECT_EQ(t->composer_listen("tcp://0.0.0.0:0"), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(t->composer_listen("garbage"), GN_ERR_INVALID_ENVELOPE);
    t->shutdown();
}

TEST(IceComposer, ListenPortReturnsZeroWithoutCarrier) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// LinkStub does not expose `gn.link.udp`, so the carrier never
    /// binds and `composer_listen_port` reports 0 with GN_OK rather
    /// than failing — surface contract is "the slot exists and
    /// answers with a stable shape regardless of carrier state".
    std::uint16_t port = 0xFFFF;
    EXPECT_EQ(t->composer_listen_port(&port), GN_OK);
    EXPECT_EQ(port, 0);
    t->shutdown();
}

TEST(IceComposer, ListenPortRejectsNullArg) {
    auto t = std::make_shared<IceLink>();
    EXPECT_EQ(t->composer_listen_port(nullptr), GN_ERR_NULL_ARG);
    t->shutdown();
}

// ── composer_connect ────────────────────────────────────────────────────

TEST(IceComposer, ConnectRejectsMalformedUri) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect("garbage", &cid),
               GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(t->composer_connect("tcp://x", &cid),
               GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(t->composer_connect("ice://", &cid),
               GN_ERR_INVALID_ENVELOPE);  // empty pk
    EXPECT_EQ(t->composer_connect("ice://abcd", &cid),
               GN_ERR_INVALID_ENVELOPE);  // wrong length
    EXPECT_EQ(t->composer_connect("ice://notthex_filling_up_to_64",
                                    &cid),
               GN_ERR_INVALID_ENVELOPE);  // not hex
    /// Composer-mode must NOT fire kernel notify_connect: the L2
    /// owns the conn lifecycle, the kernel never knows about it.
    EXPECT_EQ(h.connects.load(), 0);
    t->shutdown();
}

TEST(IceComposer, ConnectRejectsNullOutPtr) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    EXPECT_EQ(t->composer_connect(uri, nullptr), GN_ERR_NULL_ARG);
    t->shutdown();
}

TEST(IceComposer, ConnectAllocatesComposerBitCid) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid = GN_INVALID_ID;
    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->composer_connect(uri, &cid), GN_OK);
    EXPECT_NE(cid, GN_INVALID_ID);
    /// Bit 63 marks composer-owned conn ids so subsequent send /
    /// disconnect dispatch routes to the composer map by id range.
    EXPECT_NE(cid & IceLink::kComposerIdBit, 0u);
    /// Composer-mode bypasses kernel notify_connect entirely.
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(h.connects.load(), 0);
    t->shutdown();
}

TEST(IceComposer, ConnectIsIdempotentForSamePeer) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid_a = GN_INVALID_ID;
    gn_conn_id_t cid_b = GN_INVALID_ID;
    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->composer_connect(uri, &cid_a), GN_OK);
    ASSERT_EQ(t->composer_connect(uri, &cid_b), GN_OK);
    /// Same peer pk returns the same composer cid — no fresh session
    /// is spun up.
    EXPECT_EQ(cid_a, cid_b);
    t->shutdown();
}

TEST(IceComposer, KernelAndComposerCidsCoexist) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Kernel-mode connect to peer A allocates a regular conn id
    /// (no bit 63). Composer-mode connect to peer B allocates a
    /// composer cid. Both paths coexist on the same IceLink.
    const std::string kernel_uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(kernel_uri), GN_OK);
    if (!::gn::sdk::test::wait_for(
            [&] { return h.connects.load() >= 1; }, 1s)) {
        FAIL() << "kernel notify_connect timeout";
    }
    gn_conn_id_t kernel_cid = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        kernel_cid = h.conns.front();
    }
    EXPECT_EQ(kernel_cid & IceLink::kComposerIdBit, 0u);

    gn_conn_id_t composer_cid = GN_INVALID_ID;
    const std::string composer_uri = std::string("ice://") + kPeerPkHexAlt;
    ASSERT_EQ(t->composer_connect(composer_uri, &composer_cid), GN_OK);
    EXPECT_NE(composer_cid & IceLink::kComposerIdBit, 0u);
    /// Second connect (composer) must not affect kernel-side counters.
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(h.connects.load(), 1);
    t->shutdown();
}

// ── composer_subscribe_data ─────────────────────────────────────────────

TEST(IceComposer, SubscribeDataOnNonComposerCidIsNotFound) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// A plain kernel-side conn id (bit 63 unset) is not valid for
    /// composer subscribe; the surface must reject it without
    /// touching kernel state.
    EXPECT_EQ(t->composer_subscribe_data(
                  /*conn=*/42, /*cb=*/nullptr, /*user_data=*/nullptr),
              GN_ERR_NOT_FOUND);
    t->shutdown();
}

TEST(IceComposer, SubscribeDataOnUnknownComposerCidIsNotFound) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Bit 63 set but no matching session — still NOT_FOUND.
    EXPECT_EQ(t->composer_subscribe_data(
                  /*conn=*/IceLink::kComposerIdBit | 999,
                  /*cb=*/nullptr, /*user_data=*/nullptr),
              GN_ERR_NOT_FOUND);
    t->shutdown();
}

TEST(IceComposer, SubscribeDataInstallsAndUnsubscribesCleanly) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid = GN_INVALID_ID;
    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->composer_connect(uri, &cid), GN_OK);

    static std::atomic<int> calls{0};
    auto cb = [](void*, gn_conn_id_t, const std::uint8_t*,
                  std::size_t) noexcept {
        calls.fetch_add(1);
    };
    EXPECT_EQ(t->composer_subscribe_data(cid, cb, nullptr), GN_OK);
    /// No real carrier in the stub → no bytes ever flow, callback
    /// count stays at 0. The point of this test is the surface call
    /// shape: GN_OK on a known composer cid, idempotent unsubscribe.
    EXPECT_EQ(t->composer_unsubscribe_data(cid), GN_OK);
    EXPECT_EQ(t->composer_unsubscribe_data(cid), GN_OK);  // idempotent
    EXPECT_EQ(calls.load(), 0);
    t->shutdown();
}

// ── composer_subscribe_accept ───────────────────────────────────────────

TEST(IceComposer, SubscribeAcceptReturnsValidToken) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    static std::atomic<int> accept_calls{0};
    auto cb = [](void*, gn_conn_id_t, const char*) noexcept {
        accept_calls.fetch_add(1);
    };

    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(t->composer_subscribe_accept(cb, nullptr, &token), GN_OK);
    EXPECT_NE(token, GN_INVALID_SUBSCRIPTION_ID);

    /// Stacking — two subscribers, two tokens.
    gn_subscription_id_t token_b = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(t->composer_subscribe_accept(cb, nullptr, &token_b), GN_OK);
    EXPECT_NE(token, token_b);

    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
    EXPECT_EQ(t->composer_unsubscribe_accept(token_b), GN_OK);
    /// Stale unsubscribe is idempotent.
    EXPECT_EQ(t->composer_unsubscribe_accept(token), GN_OK);
    t->shutdown();
}

TEST(IceComposer, SubscribeAcceptRejectsNullArgs) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    auto cb = [](void*, gn_conn_id_t, const char*) noexcept {};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    EXPECT_EQ(t->composer_subscribe_accept(nullptr, nullptr, &token),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(t->composer_subscribe_accept(cb, nullptr, nullptr),
              GN_ERR_NULL_ARG);
    t->shutdown();
}

// ── composer disconnect / shutdown ──────────────────────────────────────

TEST(IceComposer, DisconnectIsIdempotent) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid = GN_INVALID_ID;
    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->composer_connect(uri, &cid), GN_OK);
    /// `disconnect` dispatches by bit 63 to the composer map, never
    /// hits kernel `notify_disconnect`.
    EXPECT_EQ(t->disconnect(cid), GN_OK);
    EXPECT_EQ(t->disconnect(cid), GN_OK);
    EXPECT_EQ(h.disconnects.load(), 0);
    t->shutdown();
}

TEST(IceComposer, ShutdownClearsComposerState) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn_conn_id_t cid_a = GN_INVALID_ID;
    gn_conn_id_t cid_b = GN_INVALID_ID;
    ASSERT_EQ(
        t->composer_connect(std::string("ice://") + kPeerPkHex, &cid_a),
        GN_OK);
    ASSERT_EQ(
        t->composer_connect(std::string("ice://") + kPeerPkHexAlt, &cid_b),
        GN_OK);

    t->shutdown();
    /// Post-shutdown the composer map is gone — send / subscribe /
    /// connect all fail-fast.
    EXPECT_EQ(t->send(cid_a, std::span<const std::uint8_t>{}),
              GN_ERR_NULL_ARG);
    gn_conn_id_t cid_c = GN_INVALID_ID;
    EXPECT_EQ(t->composer_connect(std::string("ice://") + kPeerPkHex, &cid_c),
              GN_ERR_NULL_ARG);
}
