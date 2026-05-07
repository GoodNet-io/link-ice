// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice.cpp
/// @brief  IceLink smoke tests — listen / connect URI parsing,
///         signal delivery, idempotent shutdown, MTU enforcement.
///
/// ICE actually doing NAT traversal requires both a STUN server and
/// a peer that responds with binding requests; that's outside the
/// scope of an in-tree gtest. These cases exercise the kernel-facing
/// surface (`gn_link_vtable_t` shape), the signaling extension entry
/// points, and the teardown protocol from `link.md` §9.

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../link_ice.hpp"
#include "../session.hpp"
#include "../stun.hpp"

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::ice::IceLink;

struct StubHost {
    std::atomic<int>                          connects{0};
    std::atomic<int>                          disconnects{0};
    std::mutex                                 mu;
    std::vector<gn_conn_id_t>                  conns;
    std::vector<gn_handshake_role_t>           roles;
    std::atomic<gn_conn_id_t>                  next_id{1};

    static gn_result_t on_connect(void* host_ctx,
                                    const std::uint8_t /*remote_pk*/[GN_PUBLIC_KEY_BYTES],
                                    const char* /*uri*/,
                                    gn_trust_class_t /*trust*/,
                                    gn_handshake_role_t role,
                                    gn_conn_id_t* out_conn) {
        auto* h = static_cast<StubHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->conns.push_back(id);
            h->roles.push_back(role);
        }
        *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_inbound(void*, gn_conn_id_t,
                                    const std::uint8_t*, std::size_t) {
        return GN_OK;
    }

    static gn_result_t on_disconnect(void* host_ctx, gn_conn_id_t /*conn*/,
                                       gn_result_t /*reason*/) {
        auto* h = static_cast<StubHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_kick(void*, gn_conn_id_t) { return GN_OK; }
};

host_api_t make_stub_api(StubHost& h) {
    host_api_t api{};
    api.api_size              = sizeof(host_api_t);
    api.host_ctx              = &h;
    api.notify_connect        = &StubHost::on_connect;
    api.notify_inbound_bytes  = &StubHost::on_inbound;
    api.notify_disconnect     = &StubHost::on_disconnect;
    api.kick_handshake        = &StubHost::on_kick;
    return api;
}

constexpr const char* kPeerPkHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> peer_pk_bytes() {
    std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk{};
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        const auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            return 0;
        };
        pk[i] = static_cast<std::uint8_t>(
            (digit(kPeerPkHex[i * 2]) << 4) |
             digit(kPeerPkHex[i * 2 + 1]));
    }
    return pk;
}

void wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout,
              const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return;
        std::this_thread::sleep_for(5ms);
    }
    FAIL() << "timeout waiting for: " << what;
}

}  // namespace

// ── listen surface ──────────────────────────────────────────────────────

TEST(IceLink, ListenAcceptsSchemePrefix) {
    auto t = std::make_shared<IceLink>();
    EXPECT_EQ(t->listen("ice://"), GN_OK);
    t->shutdown();
}

TEST(IceLink, ListenRejectsForeignScheme) {
    auto t = std::make_shared<IceLink>();
    EXPECT_NE(t->listen("garbage"), GN_OK);
    EXPECT_NE(t->listen("tcp://127.0.0.1:0"), GN_OK);
    t->shutdown();
}

TEST(IceLink, ShutdownIsIdempotent) {
    auto t = std::make_shared<IceLink>();
    t->shutdown();
    t->shutdown();
}

TEST(IceLink, CapabilitiesAdvertiseDatagram) {
    const auto caps = IceLink::capabilities();
    EXPECT_NE(caps.flags & GN_LINK_CAP_DATAGRAM, 0u);
    EXPECT_GT(caps.max_payload, 0u);
}

// ── connect URI parsing ─────────────────────────────────────────────────

TEST(IceLink, ConnectRejectsMalformedUri) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    EXPECT_NE(t->connect("ice://"), GN_OK);            // empty pk
    EXPECT_NE(t->connect("ice://garbage"), GN_OK);     // not hex
    EXPECT_NE(t->connect("ice://abcd"), GN_OK);        // wrong length
    EXPECT_NE(t->connect("tcp://127.0.0.1:80"), GN_OK); // wrong scheme
    EXPECT_EQ(h.connects.load(), 0);

    t->shutdown();
}

TEST(IceLink, ConnectAllocatesConnRecord) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "initiator notify_connect");

    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.roles.size(), 1u);
        EXPECT_EQ(h.roles[0], GN_ROLE_INITIATOR);
    }

    t->shutdown();
    EXPECT_EQ(h.disconnects.load(), 1);
}

TEST(IceLink, ConnectIsIdempotentForSamePeer) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "initiator notify_connect");
    ASSERT_EQ(t->connect(uri), GN_OK);  // dedup, no new record
    /// Give scheduler a chance — second connect must NOT mint a
    /// second conn record.
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(h.connects.load(), 1);

    t->shutdown();
}

// ── signal extension ────────────────────────────────────────────────────

TEST(IceLink, DeliverOfferAllocatesResponder) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Build a minimal IceSignalData with zero candidates.
    gn::link::ice::IceSignalData hdr{};
    const char ufrag[] = "ABCDufra";
    std::memcpy(hdr.ufrag, ufrag, sizeof(hdr.ufrag));
    const char pwd[] = "PWDtestpwd_secret_value_here";
    std::memcpy(hdr.pwd, pwd, std::min(sizeof(hdr.pwd), sizeof(pwd)));
    hdr.candidate_count = 0;  // wire-encoded as htonl(0) == 0

    std::vector<std::uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    auto pk = peer_pk_bytes();
    EXPECT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_OFFER,
                                  std::span<const std::uint8_t>(blob.data(),
                                                                blob.size())),
              GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "responder notify_connect");
    {
        std::lock_guard lk(h.mu);
        EXPECT_EQ(h.roles[0], GN_ROLE_RESPONDER);
    }

    t->shutdown();
    EXPECT_EQ(h.disconnects.load(), 1);
}

TEST(IceLink, DeliverAnswerWithoutSessionFails) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn::link::ice::IceSignalData hdr{};
    std::vector<std::uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    auto pk = peer_pk_bytes();
    /// A stray ANSWER with no in-flight controller-role session is
    /// `GN_ERR_NOT_FOUND`, not a fresh allocation.
    EXPECT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_ANSWER,
                                  std::span<const std::uint8_t>(blob.data(),
                                                                blob.size())),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(h.connects.load(), 0);

    t->shutdown();
}

TEST(IceLink, DeliverInvalidKindRejected) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    gn::link::ice::IceSignalData hdr{};
    std::vector<std::uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    auto pk = peer_pk_bytes();
    EXPECT_EQ(t->deliver_signal(pk.data(), 99,
                                  std::span<const std::uint8_t>(blob.data(),
                                                                blob.size())),
              GN_ERR_INVALID_ENVELOPE);

    t->shutdown();
}

TEST(IceLink, DeliverShortBlobRejected) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Truncated to less than `IceSignalData` header — must reject
    /// before allocating anything.
    std::vector<std::uint8_t> blob(8, 0);
    auto pk = peer_pk_bytes();
    EXPECT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_OFFER,
                                  std::span<const std::uint8_t>(blob.data(),
                                                                blob.size())),
              GN_ERR_INVALID_ENVELOPE);

    t->shutdown();
}

// ── send / disconnect ──────────────────────────────────────────────────

TEST(IceLink, SendToUnknownConnIsNotFound) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::uint8_t payload[] = {0x42};
    EXPECT_EQ(t->send(/*never registered*/ 99,
                       std::span<const std::uint8_t>(payload)),
              GN_ERR_NOT_FOUND);
    t->shutdown();
}

TEST(IceLink, SendOversizedRejected) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s, "connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    std::vector<std::uint8_t> oversized(t->mtu() + 1, 0xAA);
    EXPECT_EQ(t->send(conn, std::span<const std::uint8_t>(oversized)),
              GN_ERR_PAYLOAD_TOO_LARGE);

    t->shutdown();
}

TEST(IceLink, DisconnectIsIdempotent) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s, "connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    EXPECT_EQ(t->disconnect(conn), GN_OK);
    EXPECT_EQ(t->disconnect(conn), GN_OK);
    EXPECT_EQ(h.disconnects.load(), 1);

    t->shutdown();
}

// ── candidate / wire helpers ────────────────────────────────────────────

TEST(IceCandidate, WireRoundTripPreservesShape) {
    using namespace gn::link::ice;
    Candidate c{};
    c.type     = CandidateType::Host;
    c.family   = AddressFamily::IPv4;
    c.port     = 12345;
    c.priority = compute_priority(CandidateType::Host, 65535, 1);
    const std::uint8_t addr[] = {0x7F, 0x00, 0x00, 0x01};  // 127.0.0.1
    std::memcpy(c.addr.data(), addr, sizeof(addr));

    auto wire = to_wire(c);
    auto back = from_wire(wire);
    EXPECT_EQ(back.type, c.type);
    EXPECT_EQ(back.family, c.family);
    EXPECT_EQ(back.port, c.port);
    EXPECT_EQ(back.priority, c.priority);
    EXPECT_EQ(std::memcmp(back.addr.data(), c.addr.data(), 16), 0);
}

TEST(IceCandidate, DeserializeRejectsOutOfRangeCount) {
    using namespace gn::link::ice;
    /// Forge a header with `candidate_count = MAX + 1` after htonl
    /// — must reject before any allocation.
    IceSignalData hdr{};
    hdr.candidate_count = htonl(MAX_ICE_CANDIDATES + 1);
    std::vector<std::uint8_t> buf(sizeof(hdr));
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    IceSignalData parsed;
    std::vector<Candidate> candidates;
    EXPECT_FALSE(deserialize_signal(buf, parsed, candidates));
}

TEST(IceCandidate, DeserializeRejectsTrailingGarbage) {
    using namespace gn::link::ice;
    IceSignalData hdr{};
    hdr.candidate_count = htonl(0);
    /// One byte of trailing garbage breaks the strict-equality
    /// length check in `deserialize_signal`.
    std::vector<std::uint8_t> buf(sizeof(hdr) + 1);
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    IceSignalData parsed;
    std::vector<Candidate> candidates;
    EXPECT_FALSE(deserialize_signal(buf, parsed, candidates));
}

// ── STUN encode / parse ────────────────────────────────────────────────

TEST(IceStun, BindingRequestParsesRoundTrip) {
    using namespace gn::link::ice;
    auto txn = generate_txn_id();
    auto msg = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(txn)
        .build();
    EXPECT_GE(msg.size(), 20u);
    auto parsed = parse_stun(msg);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->msg_type, STUN_BINDING_REQUEST);
    EXPECT_EQ(parsed->txn_id, txn);
}

TEST(IceStun, ParseRejectsBadMagicCookie) {
    using namespace gn::link::ice;
    /// 20-byte buffer with cookie field flipped — must fail parse.
    std::vector<std::uint8_t> buf(20, 0);
    buf[0] = 0x00; buf[1] = 0x01;  // BINDING_REQUEST
    buf[4] = 0xff;                 // not magic cookie
    EXPECT_FALSE(parse_stun(buf).has_value());
}
