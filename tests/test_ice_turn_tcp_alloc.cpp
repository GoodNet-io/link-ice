// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_turn_tcp_alloc.cpp
/// @brief  RFC 6062 TCP-allocation coverage: REQUESTED-TRANSPORT=6
///         in ALLOCATE, Connect issuing XOR-PEER-ADDRESS, and the
///         ConnectionBind data-connection handshake.
///
/// The TurnClient consumes a `gn::sdk::LinkCarrier*` for I/O. We
/// build a single-process fake carrier that captures outbound STUN
/// frames per cid and lets the test deliver pre-cooked responses
/// through the carrier's per-cid data callback. This mirrors the
/// pattern in test_ice_multi_turn.cpp but talks directly to a
/// TurnClient instance instead of driving a full IceSession.

#include <gtest/gtest.h>

#include "../stun.hpp"
#include "../turn.hpp"

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/extensions/link.h>
#include <sdk/types.h>

#include <asio/io_context.hpp>
#include <asio/executor_work_guard.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;

/// Fake stream carrier — captures outbound writes per cid and
/// dispatches inbound bytes back through the registered per-cid
/// data callback. Sized for RFC 6062 unit tests where every TURN
/// data flow is stream-framed (control connection + N data
/// connections).
struct FakeStreamCarrier {
    struct Conn {
        std::vector<std::vector<std::uint8_t>> outbound;
        gn_link_data_cb_t                       data_cb = nullptr;
        void*                                   data_user = nullptr;
    };

    std::mutex                                       mu;
    std::unordered_map<gn_conn_id_t, Conn>           conns;
    std::atomic<gn_conn_id_t>                        next_id{1};
    /// Hook fires on every `send` so the test can inspect bytes
    /// and synthesise replies.
    std::function<void(gn_conn_id_t,
                        std::span<const std::uint8_t>)> on_send;
    gn_link_api_t                                    vt{};

    FakeStreamCarrier() {
        vt.api_size           = sizeof(vt);
        vt.get_capabilities   = &s_caps;
        vt.send               = &s_send;
        vt.close              = &s_close;
        vt.listen             = &s_listen;
        vt.connect            = &s_connect;
        vt.subscribe_data     = &s_sub_data;
        vt.unsubscribe_data   = &s_unsub_data;
        vt.subscribe_accept   = &s_sub_accept;
        vt.unsubscribe_accept = &s_unsub_accept;
        vt.ctx                = this;
    }

    /// Allocate a fresh cid without an explicit `connect` URI. Used
    /// for the control connection where the harness wires the
    /// TurnClient to a pre-existing cid.
    gn_conn_id_t allocate_cid() {
        std::lock_guard lk(mu);
        const auto cid = next_id.fetch_add(1);
        conns[cid] = Conn{};
        return cid;
    }

    void deliver(gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
        gn_link_data_cb_t cb = nullptr;
        void* user = nullptr;
        {
            std::lock_guard lk(mu);
            auto it = conns.find(cid);
            if (it == conns.end()) return;
            cb = it->second.data_cb;
            user = it->second.data_user;
        }
        if (cb) cb(user, cid, bytes.data(), bytes.size());
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        out->flags = GN_LINK_CAP_STREAM;
        out->max_payload = 65535;
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t cid,
                                const std::uint8_t* bytes,
                                std::size_t size) {
        auto* self = static_cast<FakeStreamCarrier*>(ctx);
        std::function<void(gn_conn_id_t,
                            std::span<const std::uint8_t>)> hook;
        {
            std::lock_guard lk(self->mu);
            auto it = self->conns.find(cid);
            if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
            it->second.outbound.emplace_back(bytes, bytes + size);
            hook = self->on_send;
        }
        if (hook) hook(cid, std::span<const std::uint8_t>(bytes, size));
        return GN_OK;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t cid, int) {
        auto* self = static_cast<FakeStreamCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        self->conns.erase(cid);
        return GN_OK;
    }
    static gn_result_t s_listen(void*, const char*) { return GN_OK; }
    static gn_result_t s_connect(void* ctx, const char*,
                                   gn_conn_id_t* out_conn) {
        auto* self = static_cast<FakeStreamCarrier*>(ctx);
        const auto cid = self->next_id.fetch_add(1);
        {
            std::lock_guard lk(self->mu);
            self->conns[cid] = Conn{};
        }
        if (out_conn) *out_conn = cid;
        return GN_OK;
    }
    static gn_result_t s_sub_data(void* ctx, gn_conn_id_t cid,
                                    gn_link_data_cb_t cb, void* user) {
        auto* self = static_cast<FakeStreamCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
        it->second.data_cb = cb;
        it->second.data_user = user;
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t cid) {
        auto* self = static_cast<FakeStreamCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_OK;
        it->second.data_cb = nullptr;
        it->second.data_user = nullptr;
        return GN_OK;
    }
    static gn_result_t s_sub_accept(void*, gn_link_accept_cb_t,
                                      void*, gn_subscription_id_t* tok) {
        if (tok) *tok = 1;
        return GN_OK;
    }
    static gn_result_t s_unsub_accept(void*, gn_subscription_id_t) {
        return GN_OK;
    }
};

/// Bundles the io_context worker + carrier wrapper + the carrier
/// vtable so each test can spawn fresh state without per-test
/// boilerplate. The LinkCarrier is constructed from a temporary
/// host_api wired to expose `gn.link.tcp`.
struct TurnTcpHarness {
    asio::io_context                              ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>          work{
            asio::make_work_guard(ioc)};
    std::thread                                   worker;
    FakeStreamCarrier                             fake;
    host_api_t                                    api{};
    std::optional<gn::sdk::LinkCarrier>           carrier;

    TurnTcpHarness() {
        worker = std::thread([this] { ioc.run(); });
        api.api_size = sizeof(api);
        api.host_ctx = this;
        api.query_extension_checked = &s_query;
        carrier = gn::sdk::LinkCarrier::query(&api, "tcp");
    }
    ~TurnTcpHarness() {
        carrier.reset();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* self = static_cast<TurnTcpHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.tcp") {
            *out = &self->fake.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

/// Decode a length-prefixed STUN frame from raw outbound bytes
/// captured by the fake carrier. Returns the inner STUN payload
/// (without the 2-byte length prefix).
std::vector<std::uint8_t> strip_frame(
    std::span<const std::uint8_t> framed) {
    if (framed.size() < 2) return {};
    const std::size_t len =
        (static_cast<std::size_t>(framed[0]) << 8) |
        static_cast<std::size_t>(framed[1]);
    if (framed.size() < 2 + len) return {};
    return std::vector<std::uint8_t>(framed.begin() + 2,
                                       framed.begin() + 2 + len);
}

}  // namespace

// ── RFC 6062 ALLOCATE shape ───────────────────────────────────────

TEST(TurnTcpAlloc, RequestedTransportTcpInAllocate) {
    TurnTcpHarness h;
    ASSERT_TRUE(h.carrier.has_value());

    const auto control_cid = h.fake.allocate_cid();

    TurnConfig cfg;
    cfg.server               = "turn.example";
    cfg.port                 = 3478;
    cfg.tcp_transport        = true;
    cfg.requested_transport  = REQUESTED_TRANSPORT_TCP;
    auto client = std::make_shared<TurnClient>(
        h.ioc, &*h.carrier, control_cid, cfg,
        TurnDataCallback{}, TurnAllocatedCallback{});
    ASSERT_TRUE(client->allocate());

    /// Wait briefly for the send to complete. The fake carrier is
    /// synchronous on s_send so the bytes land before allocate()
    /// returns, but `allocate` posts no async work.
    std::vector<std::vector<std::uint8_t>> outbound;
    {
        std::lock_guard lk(h.fake.mu);
        outbound = h.fake.conns[control_cid].outbound;
    }
    ASSERT_EQ(outbound.size(), 1u);

    /// Strip the 2-byte length prefix added by stream framing.
    const auto stun_bytes = strip_frame(outbound[0]);
    ASSERT_GE(stun_bytes.size(), 20u);

    /// Locate REQUESTED-TRANSPORT (0x0019) in the attribute area.
    bool found_rt = false;
    std::uint8_t proto = 0;
    std::size_t off = 20;
    const std::size_t end =
        20u + ((static_cast<std::size_t>(stun_bytes[2]) << 8) |
                static_cast<std::size_t>(stun_bytes[3]));
    while (off + 4 <= end && off + 4 <= stun_bytes.size()) {
        const auto at = static_cast<std::uint16_t>(
            (stun_bytes[off] << 8) | stun_bytes[off + 1]);
        const auto al = static_cast<std::uint16_t>(
            (stun_bytes[off + 2] << 8) | stun_bytes[off + 3]);
        if (at == TURN_ATTR_REQUESTED_TRANSPORT && al >= 1) {
            found_rt = true;
            proto = stun_bytes[off + 4];
            break;
        }
        off += 4 + al;
        while (off % 4 != 0) ++off;
    }
    ASSERT_TRUE(found_rt) << "REQUESTED-TRANSPORT attribute missing";
    EXPECT_EQ(proto, REQUESTED_TRANSPORT_TCP);
}

// ── RFC 6062 §4.3 Connect request shape ───────────────────────────

TEST(TurnTcpAlloc, ConnectIssuesPeerOpen) {
    TurnTcpHarness h;
    ASSERT_TRUE(h.carrier.has_value());

    const auto control_cid = h.fake.allocate_cid();
    TurnConfig cfg;
    cfg.server              = "turn.example";
    cfg.port                = 3478;
    cfg.tcp_transport       = true;
    cfg.requested_transport = REQUESTED_TRANSPORT_TCP;
    auto client = std::make_shared<TurnClient>(
        h.ioc, &*h.carrier, control_cid, cfg,
        TurnDataCallback{}, TurnAllocatedCallback{});

    /// Skip the ALLOCATE round-trip by calling connect_to_peer
    /// directly — the test pin is the on-wire Connect-request
    /// shape, not the allocation handshake.
    client->connect_to_peer("198.51.100.42", 5555);

    /// Snapshot outbound after the synchronous send completes.
    std::vector<std::vector<std::uint8_t>> outbound;
    {
        std::lock_guard lk(h.fake.mu);
        outbound = h.fake.conns[control_cid].outbound;
    }
    ASSERT_EQ(outbound.size(), 1u);
    const auto stun_bytes = strip_frame(outbound[0]);
    ASSERT_GE(stun_bytes.size(), 20u);

    /// Message type at bytes 0..2 must be Connect (0x000A).
    const auto msg_type = static_cast<std::uint16_t>(
        (stun_bytes[0] << 8) | stun_bytes[1]);
    EXPECT_EQ(msg_type, TURN_CONNECT_REQUEST);

    /// The Connect carries XOR-PEER-ADDRESS for the target peer.
    /// Decode via parse_stun and re-check the peer matches.
    auto parsed = parse_stun(stun_bytes);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(parsed->xor_peer.has_value());
    EXPECT_EQ(parsed->xor_peer->ip, "198.51.100.42");
    EXPECT_EQ(parsed->xor_peer->port, 5555);
}

// ── RFC 6062 §4.5 ConnectionBind round-trip + raw data ───────────

TEST(TurnTcpAlloc, DataConnectionBindRoundTrip) {
    TurnTcpHarness h;
    ASSERT_TRUE(h.carrier.has_value());

    const auto control_cid = h.fake.allocate_cid();
    TurnConfig cfg;
    cfg.server              = "turn.example";
    cfg.port                = 3478;
    cfg.tcp_transport       = true;
    cfg.requested_transport = REQUESTED_TRANSPORT_TCP;

    /// Capture (peer_ip, peer_port, payload) tuples that arrive
    /// through the data callback after the bind handshake
    /// completes.
    std::mutex                                       data_mu;
    std::vector<std::tuple<std::string, std::uint16_t,
                            std::vector<std::uint8_t>>>  received;
    auto data_cb = [&](const std::string& ip, std::uint16_t port,
                        std::span<const std::uint8_t> b) {
        std::lock_guard lk(data_mu);
        received.emplace_back(ip, port,
            std::vector<std::uint8_t>(b.begin(), b.end()));
    };

    auto client = std::make_shared<TurnClient>(
        h.ioc, &*h.carrier, control_cid, cfg,
        std::move(data_cb), TurnAllocatedCallback{});

    /// Stack-owned storage for the `std::weak_ptr<TurnClient>`
    /// wrappers handed to subscription callbacks as `void* user`.
    /// The wrappers must outlive every cid subscription they back,
    /// so the test owns them in a vector that gets torn down at
    /// scope exit — after `client` resets and after every cid has
    /// been unsubscribed via the harness destructor.
    std::vector<std::unique_ptr<std::weak_ptr<TurnClient>>>
        weak_holders;
    auto make_weak_user = [&](const std::shared_ptr<TurnClient>& sp)
        -> std::weak_ptr<TurnClient>* {
        weak_holders.push_back(
            std::make_unique<std::weak_ptr<TurnClient>>(sp));
        return weak_holders.back().get();
    };

    /// Wire the control connection's inbound bytes back into the
    /// TurnClient. Production code does this through the session
    /// dispatcher; the unit test bypasses the session so the
    /// subscription is set up directly here.
    FakeStreamCarrier::s_sub_data(
        &h.fake, control_cid,
        +[](void* user, gn_conn_id_t /*cc*/,
             const std::uint8_t* b, std::size_t n) {
            auto* wptr =
                static_cast<std::weak_ptr<TurnClient>*>(user);
            if (auto sp = wptr->lock()) {
                sp->on_inbound(std::span(b, n));
            }
        },
        make_weak_user(client));

    /// Track the freshly opened data carrier cid so the test can
    /// route the BindResponse + raw bytes onto the right cid.
    std::atomic<gn_conn_id_t> data_cid{0};
    client->set_data_carrier_factory(
        [&]() -> gn_conn_id_t {
            const auto cid = h.fake.allocate_cid();
            data_cid.store(cid);
            /// Wire inbound bytes for this cid back into the
            /// TurnClient — emulates the session-side per-cid
            /// subscription that production code installs.
            FakeStreamCarrier::s_sub_data(
                &h.fake, cid,
                +[](void* user, gn_conn_id_t cc,
                     const std::uint8_t* b, std::size_t n) {
                    auto* wptr =
                        static_cast<std::weak_ptr<TurnClient>*>(user);
                    if (auto sp = wptr->lock()) {
                        sp->on_data_connection_inbound(
                            cc, std::span(b, n));
                    }
                },
                make_weak_user(client));
            return cid;
        });

    std::atomic<bool> bound{false};
    std::string       bound_peer_ip;
    std::uint16_t     bound_peer_port = 0;
    client->set_data_connection_callback(
        [&](std::uint32_t /*cid32*/, gn_conn_id_t /*cid*/,
             const std::string& ip, std::uint16_t port) {
            bound_peer_ip   = ip;
            bound_peer_port = port;
            bound.store(true);
        });

    /// Synthesise a ConnectionAttempt indication on the control
    /// connection. The TurnClient will allocate a fresh data
    /// carrier, send ConnectionBind, and wait for a response.
    constexpr std::uint32_t kConnId = 0x1234ABCD;
    auto attempt = StunBuilder(TURN_CONNECTION_ATTEMPT_INDICATION)
        .add_xor_peer_address("203.0.113.10", 4321)
        .add_connection_id(kConnId)
        .build();
    std::vector<std::uint8_t> framed_attempt;
    ASSERT_TRUE(encode_stream_frame(attempt, framed_attempt));
    h.fake.deliver(control_cid, framed_attempt);

    /// Wait until the TurnClient has spawned the data carrier and
    /// emitted ConnectionBind on it. The factory sets `data_cid`
    /// synchronously inside the carrier's `send` path.
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (data_cid.load() == 0
            && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(data_cid.load(), 0u)
        << "data carrier was never opened in response to "
           "ConnectionAttempt";

    /// Pull the ConnectionBind frame off the data cid and verify
    /// its message type + CONNECTION-ID attribute.
    std::vector<std::vector<std::uint8_t>> data_outbound;
    {
        std::lock_guard lk(h.fake.mu);
        data_outbound = h.fake.conns[data_cid.load()].outbound;
    }
    ASSERT_EQ(data_outbound.size(), 1u);
    const auto bind_payload = strip_frame(data_outbound[0]);
    ASSERT_GE(bind_payload.size(), 20u);
    auto parsed_bind = parse_stun(bind_payload);
    ASSERT_TRUE(parsed_bind.has_value());
    EXPECT_EQ(parsed_bind->msg_type, TURN_CONNECTION_BIND_REQUEST);
    ASSERT_TRUE(parsed_bind->connection_id.has_value());
    EXPECT_EQ(*parsed_bind->connection_id, kConnId);

    /// Deliver a BindResponse echoing the txn id. The TurnClient
    /// should transition the data cid to "bound" and fire the
    /// data-connection callback.
    auto bind_resp = StunBuilder(TURN_CONNECTION_BIND_RESPONSE)
        .set_txn_id(parsed_bind->txn_id)
        .add_connection_id(kConnId)
        .build();
    std::vector<std::uint8_t> framed_resp;
    ASSERT_TRUE(encode_stream_frame(bind_resp, framed_resp));
    h.fake.deliver(data_cid.load(), framed_resp);

    const auto bound_deadline =
        std::chrono::steady_clock::now() + 1s;
    while (!bound.load()
            && std::chrono::steady_clock::now() < bound_deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(bound.load())
        << "ConnectionBind response did not flip the data carrier "
           "into bound state";
    EXPECT_EQ(bound_peer_ip, "203.0.113.10");
    EXPECT_EQ(bound_peer_port, 4321);

    /// Round-trip raw peer bytes on the bound data carrier. After
    /// the handshake the carrier delivers application payload
    /// without any STUN framing.
    const std::vector<std::uint8_t> raw_payload{
        'h', 'e', 'l', 'l', 'o', '-', 't', 'c', 'p'};
    h.fake.deliver(data_cid.load(), raw_payload);

    /// Drain the data callback queue and check the surfaced
    /// payload.
    const auto rx_deadline =
        std::chrono::steady_clock::now() + 1s;
    bool got_payload = false;
    while (std::chrono::steady_clock::now() < rx_deadline) {
        {
            std::lock_guard lk(data_mu);
            if (!received.empty()) {
                got_payload = true;
                EXPECT_EQ(std::get<0>(received[0]), "203.0.113.10");
                EXPECT_EQ(std::get<1>(received[0]), 4321);
                EXPECT_EQ(std::get<2>(received[0]), raw_payload);
                break;
            }
        }
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_TRUE(got_payload)
        << "raw bytes on the bound data carrier never surfaced";
}

}  // namespace gn::link::ice::test
