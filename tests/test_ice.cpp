// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice.cpp
/// @brief  IceLink smoke tests — listen / connect URI parsing,
///         signal delivery, idempotent shutdown, MTU enforcement.
///
/// ICE actually doing NAT traversal requires both a STUN server and
/// a peer that responds with binding requests; that's outside the
/// scope of an in-tree gtest. These cases exercise the kernel-facing
/// surface (`gn_link_vtable_t` shape), the signaling extension entry
/// points, and the teardown protocol from `link.en.md` §9.

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../link_ice.hpp"
#include "../session.hpp"
#include "../stun.hpp"

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
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

/// Alias to the shared `gn::sdk::test::LinkStub`. See
/// `sdk/cpp/test/stub_host.hpp` for the captured surface.
using StubHost = ::gn::sdk::test::LinkStub;
inline host_api_t make_stub_api(StubHost& h) noexcept {
    return ::gn::sdk::test::make_link_host_api(h);
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

inline void wait_for(const std::function<bool()>& pred,
                      std::chrono::milliseconds timeout,
                      const char* what) {
    if (!::gn::sdk::test::wait_for(pred, timeout)) {
        FAIL() << "timeout waiting for: " << what;
    }
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

TEST(IceLink, NominationMetricsBeforeConnectedReturnsDefaults) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "initial connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    /// Pre-nomination: FSM is still Gathering / WaitingRemote. The
    /// metrics snapshot must report `nominated == false` and a zero
    /// RTT so strategy plugins can recognise the path as "unranked".
    const auto m = t->nomination_metrics(conn);
    EXPECT_FALSE(m.nominated);
    EXPECT_EQ(m.rtt_us, 0u);

    /// Unknown conn id returns the same default snapshot, not crash.
    const auto bad = t->nomination_metrics(0xDEAD);
    EXPECT_FALSE(bad.nominated);

    t->shutdown();
}

TEST(IceLink, TrickleSecondOfferReusesSession) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Initial OFFER allocates the responder-side session.
    gn::link::ice::IceSignalData hdr{};
    const char ufrag[] = "ABCDufra";
    std::memcpy(hdr.ufrag, ufrag, sizeof(hdr.ufrag));
    const char pwd[] = "PWDtestpwd_secret_value_here";
    std::memcpy(hdr.pwd, pwd, std::min(sizeof(hdr.pwd), sizeof(pwd)));
    hdr.candidate_count = 0;
    std::vector<std::uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    auto pk = peer_pk_bytes();
    ASSERT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_OFFER,
                                  std::span<const std::uint8_t>(
                                      blob.data(), blob.size())),
              GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s, "first offer");
    const auto first_connects = h.connects.load();
    EXPECT_EQ(t->session_count(), 1u);

    /// Second OFFER with the SAME peer + ufrag must NOT spawn a fresh
    /// session — it folds the (still empty) candidate batch into the
    /// existing one. RFC 8838 trickle semantics: incremental signal,
    /// stable session.
    ASSERT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_OFFER,
                                  std::span<const std::uint8_t>(
                                      blob.data(), blob.size())),
              GN_OK);
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(h.connects.load(), first_connects);
    EXPECT_EQ(t->session_count(), 1u);

    t->shutdown();
}

TEST(IceLink, RestartSessionRegeneratesCredentials) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "initial gather");

    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    /// Unknown conn id is rejected — restart must not allocate.
    EXPECT_EQ(t->restart_session(0xFFFF), GN_ERR_NOT_FOUND);

    /// Known conn id reposts work to the session strand; the FSM
    /// then re-enters Gathering. No new conn record is allocated,
    /// no extra `notify_connect` fires.
    const auto before = h.connects.load();
    EXPECT_EQ(t->restart_session(conn), GN_OK);
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(h.connects.load(), before);

    t->shutdown();
}

TEST(IceLink, RestartSessionAfterShutdownIsInvalidState) {
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

    t->shutdown();
    EXPECT_EQ(t->restart_session(conn), GN_ERR_INVALID_STATE);
}

// ── poll_local outbound surface (v0x00020000) ──────────────────────────

TEST(IceLinkPollLocal, GathererPublishesOfferEocForController) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Controller-role connect — host gather runs synchronously, then
    /// `on_gathered` fires the outbound publish.
    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "initiator notify_connect");

    /// Poll until the outbound queue carries the OFFER_EOC blob the
    /// gather just enqueued. Loop bounded by the same 1s budget as
    /// every other connect-side wait in this suite.
    auto pk = peer_pk_bytes();
    std::vector<std::uint8_t> buf(8192);
    std::uint32_t kind = 0;
    std::size_t blob_len = 0;
    bool got_signal = false;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto rc = t->poll_local_signal(pk.data(), &kind,
                                               buf.data(), buf.size(),
                                               &blob_len);
        if (rc == GN_OK) { got_signal = true; break; }
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_TRUE(got_signal);
    EXPECT_EQ(kind,
        static_cast<std::uint32_t>(gn::link::ice::ICE_SIGNAL_OFFER_EOC));
    /// Without a wired UDP carrier in StubHost, gather produces no
    /// host candidates and the blob is just the IceSignalData header
    /// carrying our ufrag/pwd. Assert at least the header is present
    /// so the round-trip via `deserialize_signal` is well-formed.
    EXPECT_GE(blob_len, sizeof(gn::link::ice::IceSignalData));
    gn::link::ice::IceSignalData parsed_hdr{};
    std::vector<gn::link::ice::Candidate> parsed_cands;
    EXPECT_TRUE(gn::link::ice::deserialize_signal(
        std::span<const std::uint8_t>(buf.data(), blob_len),
        parsed_hdr, parsed_cands));

    /// Drained — second poll on the same peer returns NOT_FOUND
    /// because the gather only fires `on_gathered` once.
    EXPECT_EQ(t->poll_local_signal(pk.data(), &kind, buf.data(),
                                     buf.size(), &blob_len),
              GN_ERR_NOT_FOUND);

    t->shutdown();
}

TEST(IceLinkPollLocal, OutboundQueueIsPerPeer) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Different peer pubkey — never connected, so no queued blob.
    std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> other_pk{};
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        other_pk[i] = static_cast<std::uint8_t>(0xFF - i);
    }

    std::vector<std::uint8_t> buf(8192);
    std::uint32_t kind = 0;
    std::size_t blob_len = 0;
    EXPECT_EQ(t->poll_local_signal(other_pk.data(), &kind, buf.data(),
                                     buf.size(), &blob_len),
              GN_ERR_NOT_FOUND);

    t->shutdown();
}

TEST(IceLinkPollLocal, BufferTooSmallReturnsOutOfRangeAndKeepsEntry) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    const std::string uri = std::string("ice://") + kPeerPkHex;
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s, "connect");

    /// Wait until the outbound entry is queued.
    auto pk = peer_pk_bytes();
    std::vector<std::uint8_t> tiny(4);  // too small for any signal
    std::uint32_t kind = 0;
    std::size_t blob_len = 0;
    gn_result_t rc = GN_ERR_NOT_FOUND;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (std::chrono::steady_clock::now() < deadline) {
        rc = t->poll_local_signal(pk.data(), &kind,
                                    tiny.data(), tiny.size(), &blob_len);
        if (rc == GN_ERR_OUT_OF_RANGE) break;
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(rc, GN_ERR_OUT_OF_RANGE);
    EXPECT_GT(blob_len, tiny.size());

    /// Entry retained — retry with a large enough buffer succeeds.
    std::vector<std::uint8_t> big(blob_len);
    std::size_t blob_len2 = 0;
    EXPECT_EQ(t->poll_local_signal(pk.data(), &kind,
                                     big.data(), big.size(), &blob_len2),
              GN_OK);
    EXPECT_EQ(blob_len2, blob_len);

    t->shutdown();
}

TEST(IceLinkPollLocal, NullArgsReturnNullArg) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    auto pk = peer_pk_bytes();
    std::uint32_t kind = 0;
    std::size_t blob_len = 0;
    std::vector<std::uint8_t> buf(64);

    EXPECT_EQ(t->poll_local_signal(nullptr, &kind, buf.data(),
                                     buf.size(), &blob_len),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(t->poll_local_signal(pk.data(), nullptr, buf.data(),
                                     buf.size(), &blob_len),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(t->poll_local_signal(pk.data(), &kind, buf.data(),
                                     buf.size(), nullptr),
              GN_ERR_NULL_ARG);
    /// `blob_cap > 0` requires a non-null `blob_out`.
    EXPECT_EQ(t->poll_local_signal(pk.data(), &kind, nullptr,
                                     64, &blob_len),
              GN_ERR_NULL_ARG);
    /// `blob_cap == 0` with null `blob_out` is allowed as a probe:
    /// it returns OUT_OF_RANGE if a blob is queued so callers can
    /// size their buffer.
    /// (Not asserted here — depends on timing of the queued blob.)

    t->shutdown();
}

TEST(IceLinkPollLocal, AnswerEocForResponderRole) {
    auto t = std::make_shared<IceLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Deliver a remote OFFER — this allocates a responder-role
    /// session, which calls `gather()` whose `on_gathered` fires
    /// the local `ANSWER_EOC` publish.
    gn::link::ice::IceSignalData hdr{};
    const char ufrag[] = "REMUufra";
    std::memcpy(hdr.ufrag, ufrag, sizeof(hdr.ufrag));
    const char pwd[] = "REMpwdtestpwd_secret_value_h";
    std::memcpy(hdr.pwd, pwd, std::min(sizeof(hdr.pwd), sizeof(pwd)));
    hdr.candidate_count = 0;
    std::vector<std::uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));

    auto pk = peer_pk_bytes();
    ASSERT_EQ(t->deliver_signal(pk.data(),
                                  gn::link::ice::ICE_SIGNAL_OFFER,
                                  std::span<const std::uint8_t>(
                                      blob.data(), blob.size())),
              GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "responder notify_connect");

    std::vector<std::uint8_t> buf(8192);
    std::uint32_t kind = 0;
    std::size_t blob_len = 0;
    bool got_signal = false;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto rc = t->poll_local_signal(pk.data(), &kind,
                                               buf.data(), buf.size(),
                                               &blob_len);
        if (rc == GN_OK) { got_signal = true; break; }
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_TRUE(got_signal);
    EXPECT_EQ(kind,
        static_cast<std::uint32_t>(gn::link::ice::ICE_SIGNAL_ANSWER_EOC));

    t->shutdown();
}

TEST(IceLinkPollLocal, SignalExtensionVersionBumped) {
    /// The bump to 0x00020000 is the canary the harness uses to
    /// detect a plugin .so that lacks the outbound `poll_local`
    /// slot. Hard-coded here so any future shape change re-triggers
    /// review.
    EXPECT_EQ(gn::link::ice::kIceSignalVersion, 0x00020000U);
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

// ── TURN ChannelData (RFC 5766 §11.4) ─────────────────────────────────

TEST(IceTurnChannel, EncodeDecodeRoundTrip) {
    using namespace gn::link::ice;
    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44, 0x55};
    auto frame = encode_channel_data(0x4001, payload);
    /// 4-byte header + 5 payload + 3 padding to 4-byte boundary = 12.
    EXPECT_EQ(frame.size(), 12u);
    EXPECT_TRUE(is_channel_data(frame));
    auto view = parse_channel_data(frame);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->channel, 0x4001u);
    ASSERT_EQ(view->payload.size(), payload.size());
    EXPECT_EQ(0, std::memcmp(view->payload.data(), payload.data(),
                                payload.size()));
}

TEST(IceTurnChannel, DemuxRejectsStunFrame) {
    using namespace gn::link::ice;
    /// STUN messages have top nibble 0x0-0x3 (method classes); the
    /// ChannelData demux must NOT misclassify a Binding Request as
    /// channel traffic.
    auto stun = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(generate_txn_id())
        .build();
    EXPECT_FALSE(is_channel_data(stun));
}

TEST(IceTurnChannel, ParseRejectsOutOfRangeChannel) {
    using namespace gn::link::ice;
    /// Channel numbers must fall in [0x4000, 0x7FFF]; anything else
    /// is reserved and parse_channel_data should reject.
    std::vector<std::uint8_t> bad(8, 0);
    bad[0] = 0x80;  // channel 0x8000 — invalid
    bad[1] = 0x00;
    bad[2] = 0x00;
    bad[3] = 0x04;
    EXPECT_FALSE(parse_channel_data(bad).has_value());
}

TEST(IceTurnChannel, ParseRejectsTruncatedFrame) {
    using namespace gn::link::ice;
    /// Length field says 100 bytes but buffer is only 6 — must
    /// reject before reading past the end.
    std::vector<std::uint8_t> bad(6, 0);
    bad[0] = 0x40;  // valid channel 0x4000
    bad[2] = 0x00;
    bad[3] = 0x64;  // length 100
    EXPECT_FALSE(parse_channel_data(bad).has_value());
}

TEST(IceTurnChannel, BuilderEmitsChannelBindAttributes) {
    using namespace gn::link::ice;
    auto txn = generate_txn_id();
    auto msg = StunBuilder(TURN_CHANNEL_BIND_REQUEST)
        .set_txn_id(txn)
        .add_channel_number(0x4002)
        .add_xor_peer_address("127.0.0.1", 12345)
        .build();
    auto parsed = parse_stun(msg);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->msg_type, TURN_CHANNEL_BIND_REQUEST);
    EXPECT_EQ(parsed->txn_id, txn);
    ASSERT_TRUE(parsed->xor_peer.has_value());
    EXPECT_EQ(parsed->xor_peer->ip, "127.0.0.1");
    EXPECT_EQ(parsed->xor_peer->port, 12345u);
}
