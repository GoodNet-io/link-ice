// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_portmap_gather.cpp
/// @brief  IceSession integration with the `gn.link.portmap` extension —
///         srflx candidate emission, mapping release on teardown, and
///         foundation distinctness against STUN srflx.

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../portmap_ext_client.hpp"
#include "../session.hpp"

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/extensions/portmap.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;
using StubHost = ::gn::sdk::test::LinkStub;

/// Fake UDP carrier — minimal slice of the `gn.link.udp` extension
/// surface needed to drive `IceSession::gather_host_candidates` past
/// the `local_port_ == 0` short-circuit. Mirrors the existing
/// `test_ice_lite_and_pred.cpp` fixture shape but trimmed to the
/// listen-port slot since portmap gather does not require outbound
/// I/O.
struct FakeUdpCarrier {
    std::mutex                 mu;
    std::atomic<gn_conn_id_t>  next_id{1};
    std::atomic<std::uint16_t> listen_port_val{40123};
    std::unordered_map<gn_conn_id_t, std::pair<std::string,std::uint16_t>>
                                conns;

    gn_link_api_t              vt{};

    FakeUdpCarrier() {
        vt.api_size             = sizeof(vt);
        vt.get_capabilities     = &s_caps;
        vt.send                 = &s_send;
        vt.close                = &s_close;
        vt.listen               = &s_listen;
        vt.connect              = &s_connect;
        vt.subscribe_data       = &s_sub_data;
        vt.unsubscribe_data     = &s_unsub_data;
        vt.subscribe_accept     = &s_sub_accept;
        vt.unsubscribe_accept   = &s_unsub_accept;
        vt.composer_listen_port = &s_listen_port;
        vt.ctx                  = this;
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        out->flags       = GN_LINK_CAP_DATAGRAM;
        out->max_payload = 1500;
        return GN_OK;
    }
    static gn_result_t s_send(void*, gn_conn_id_t,
                                const std::uint8_t*, std::size_t) {
        return GN_OK;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t cid, int) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        self->conns.erase(cid);
        return GN_OK;
    }
    static gn_result_t s_listen(void*, const char*) { return GN_OK; }
    static gn_result_t s_connect(void* ctx, const char* /*uri*/,
                                   gn_conn_id_t* out_conn) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        const auto cid = self->next_id.fetch_add(1);
        if (out_conn) *out_conn = cid;
        std::lock_guard lk(self->mu);
        self->conns[cid] = {"", 0};
        return GN_OK;
    }
    static gn_result_t s_sub_data(void*, gn_conn_id_t,
                                    gn_link_data_cb_t, void*) {
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void*, gn_conn_id_t) {
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
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = static_cast<FakeUdpCarrier*>(ctx)
                  ->listen_port_val.load(std::memory_order_acquire);
        return GN_OK;
    }
};

/// Fake portmap plugin — tracks request/release lifecycle so the test
/// can assert on emission and teardown without bringing the real
/// portmap plugin into the process. Behaviour is steered through the
/// public fields before `query` resolves the extension.
struct FakePortmapPlugin {
    /// `supported_protocols` mask returned to the client. Zero is the
    /// "no portmap protocol reachable" branch — the client treats it
    /// the same as a missing extension.
    std::atomic<std::uint32_t> protocols_mask{GN_PORTMAP_PROTO_PCP};
    /// Forced request outcome. `should_succeed == false` simulates a
    /// router refusal; the session must skip the candidate emission
    /// without crashing.
    std::atomic<bool>           should_succeed{true};
    /// Mapping returned by the fake on success.
    std::string                 ext_ip{"203.0.113.42"};
    std::atomic<std::uint16_t>  ext_port{55555};
    std::atomic<std::uint32_t>  lifetime_s{3600};

    /// Telemetry — incremented by every entry into the corresponding
    /// vtable slot so tests can pin the call count.
    std::atomic<std::size_t>    request_calls{0};
    std::atomic<std::size_t>    release_calls{0};
    /// Last `(protocol, int_port)` argument pair passed to release,
    /// captured so the release-on-teardown test can prove the session
    /// reused the original mapping's protocol + internal port rather
    /// than passing zeroes or stale state.
    std::atomic<gn_portmap_protocol_t> last_release_proto{
        static_cast<gn_portmap_protocol_t>(0)};
    std::atomic<std::uint16_t>  last_release_int_port{0};

    gn_portmap_api_t            vt{};

    FakePortmapPlugin() {
        vt.api_size            = sizeof(vt);
        vt.request             = &s_request;
        vt.release             = &s_release;
        vt.supported_protocols = &s_supported_protocols;
        vt.ctx                 = this;
    }

    static int s_request(void* ctx, gn_portmap_protocol_t protocol,
                         std::uint16_t int_port,
                         std::uint16_t /*ext_port_hint*/,
                         std::uint32_t /*lifetime_hint*/,
                         gn_portmap_mapping_t* out) {
        auto* self = static_cast<FakePortmapPlugin*>(ctx);
        self->request_calls.fetch_add(1, std::memory_order_relaxed);
        if (!self->should_succeed.load(std::memory_order_acquire)) return -1;
        if (out == nullptr) return -1;
        std::memset(out, 0, sizeof(*out));
        out->api_size = sizeof(*out);
        const auto& ip = self->ext_ip;
        const auto copy_len = std::min(sizeof(out->ext_ip) - 1, ip.size());
        std::memcpy(out->ext_ip, ip.data(), copy_len);
        out->ext_ip[copy_len] = '\0';
        out->ext_port  = self->ext_port.load(std::memory_order_acquire);
        out->int_port  = int_port;
        out->lifetime_s = self->lifetime_s.load(std::memory_order_acquire);
        out->protocol  = protocol;
        return 0;
    }
    static int s_release(void* ctx, gn_portmap_protocol_t protocol,
                         std::uint16_t int_port) {
        auto* self = static_cast<FakePortmapPlugin*>(ctx);
        self->release_calls.fetch_add(1, std::memory_order_relaxed);
        self->last_release_proto.store(protocol,
                                          std::memory_order_release);
        self->last_release_int_port.store(int_port,
                                              std::memory_order_release);
        return 0;
    }
    static std::uint32_t s_supported_protocols(void* ctx) {
        return static_cast<FakePortmapPlugin*>(ctx)
            ->protocols_mask.load(std::memory_order_acquire);
    }
};

/// Harness that publishes both `gn.link.udp` (carrier) and
/// `gn.link.portmap` (extension) through a single host_api facade.
/// Mirrors `UdpHarness` in `test_ice_lite_and_pred.cpp` extended with
/// a portmap branch in `query_extension_checked`.
struct PortmapHarness {
    StubHost            link_stub;
    FakeUdpCarrier      carrier;
    FakePortmapPlugin   portmap;
    host_api_t          api{};
    bool                expose_portmap = true;

    PortmapHarness() {
        api = ::gn::sdk::test::make_link_host_api(link_stub);
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        auto* self = static_cast<PortmapHarness*>(host_ctx);
        const std::string_view sv(name);
        if (sv == "gn.link.udp") {
            if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
            *out = &self->carrier.vt;
            return GN_OK;
        }
        if (sv == GN_EXT_PORTMAP) {
            if (!self->expose_portmap) return GN_ERR_NOT_FOUND;
            if (version != GN_EXT_PORTMAP_VERSION) return GN_ERR_NOT_FOUND;
            *out = &self->portmap.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

/// Spin until @p pred or timeout. Used to wait out the strand-posted
/// gather work the session schedules.
template <typename F>
bool wait_until(F pred, std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

/// Driver shared by every gather-side case. Spins an io_context
/// worker, resolves the portmap client (optional) and the UDP carrier
/// through the harness, builds an IceSession and runs `gather`
/// synchronously up to the first idle-state observation.
struct SessionFixture {
    asio::io_context                                ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>            work{asio::make_work_guard(ioc)};
    std::thread                                     worker;
    PortmapHarness                                  harness;
    std::optional<gn::sdk::LinkCarrier>             carrier;
    std::optional<IcePortmapClient>                 portmap;
    std::shared_ptr<IceSession>                     session;

    SessionFixture() {
        worker = std::thread([this] { ioc.run(); });
        carrier = gn::sdk::LinkCarrier::query(&harness.api, "udp");
        portmap = IcePortmapClient::query(&harness.api);
    }

    ~SessionFixture() {
        if (session) session->close();
        /// Drain any teardown work the strand may have posted before
        /// joining the worker.
        std::this_thread::sleep_for(10ms);
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        carrier.reset();
        portmap.reset();
    }

    void start(bool with_portmap = true,
                IceConfig cfg = IceConfig{}) {
        cfg.stun_servers.clear();
        cfg.turn_servers.clear();
        auto* carrier_ptr = carrier.has_value() ? &*carrier : nullptr;
        IcePortmapClient* pm_ptr = nullptr;
        if (with_portmap && portmap.has_value()) pm_ptr = &*portmap;
        IceSessionCallbacks cbs;
        session = std::make_shared<IceSession>(
            ioc, carrier_ptr, /*tcp=*/nullptr, /*tls=*/nullptr,
            cfg, /*peer_id=*/"abcdef0123456789",
            /*controlling=*/true, cbs,
            /*mdns=*/nullptr,
            pm_ptr);
        session->gather();
    }
};

// ── extension client unit ──────────────────────────────────────────

TEST(PortmapExtClient, QueryReturnsNullOnMissingExtension) {
    /// LinkStub publishes no extensions out of the box — the wrapper
    /// must surface that as `nullopt` so the rest of the FSM degrades
    /// gracefully.
    StubHost stub;
    auto api = ::gn::sdk::test::make_link_host_api(stub);
    auto pm = IcePortmapClient::query(&api);
    EXPECT_FALSE(pm.has_value());
}

TEST(PortmapExtClient, QueryReturnsClientWhenExposed) {
    PortmapHarness h;
    auto pm = IcePortmapClient::query(&h.api);
    ASSERT_TRUE(pm.has_value());
    EXPECT_EQ(pm->supported_protocols(), GN_PORTMAP_PROTO_PCP);
}

TEST(PortmapExtClient, RequestAndReleaseRoundTrip) {
    PortmapHarness h;
    auto pm = IcePortmapClient::query(&h.api);
    ASSERT_TRUE(pm.has_value());

    gn_portmap_mapping_t m{};
    EXPECT_TRUE(pm->request(GN_PORTMAP_UDP, /*int_port=*/40123,
                              /*ext_port_hint=*/0,
                              /*lifetime_hint=*/3600, &m));
    EXPECT_EQ(std::string(m.ext_ip), "203.0.113.42");
    EXPECT_EQ(m.ext_port, 55555);
    EXPECT_EQ(m.int_port, 40123);
    EXPECT_EQ(m.protocol, GN_PORTMAP_UDP);
    EXPECT_EQ(h.portmap.request_calls.load(), 1u);

    pm->release(GN_PORTMAP_UDP, /*int_port=*/40123);
    EXPECT_EQ(h.portmap.release_calls.load(), 1u);
    EXPECT_EQ(h.portmap.last_release_int_port.load(), 40123u);
}

TEST(PortmapExtClient, RequestSurfacesPluginFailureAsFalse) {
    PortmapHarness h;
    h.portmap.should_succeed.store(false);
    auto pm = IcePortmapClient::query(&h.api);
    ASSERT_TRUE(pm.has_value());

    gn_portmap_mapping_t m{};
    EXPECT_FALSE(pm->request(GN_PORTMAP_UDP, /*int_port=*/40123,
                                /*ext_port_hint=*/0,
                                /*lifetime_hint=*/0, &m));
}

// ── gather_portmap behaviour through IceSession ─────────────────────

TEST(IceSessionPortmap, GatherEmitsSrflxCandidateForMapping) {
    SessionFixture fix;
    fix.start(/*with_portmap=*/true);

    /// gather() schedules nothing else on the strand for portmap (the
    /// extension is synchronous), but it still races with the main
    /// thread on `local_candidates_` because the gather body posts a
    /// strand task when stun_servers is empty. Wait until the srflx
    /// candidate appears.
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    bool seen_portmap = false;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto cands = fix.session->local_candidates();
        for (const auto& c : cands) {
            if (c.type == CandidateType::Srflx
                && c.address_str() == "203.0.113.42"
                && c.port == 55555) {
                seen_portmap = true;
                break;
            }
        }
        if (seen_portmap) break;
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_TRUE(seen_portmap) << "expected srflx candidate from portmap";
    EXPECT_GE(fix.harness.portmap.request_calls.load(), 1u);

    /// Priority follows the type-preference scheme — type_pref 100 in
    /// the top byte. Sanity-check that we did NOT push a host (126)
    /// or relay (0) priority into the srflx slot.
    const auto cands = fix.session->local_candidates();
    for (const auto& c : cands) {
        if (c.type == CandidateType::Srflx
            && c.address_str() == "203.0.113.42") {
            EXPECT_EQ((c.priority >> 24) & 0xFF, 100u);
        }
    }
}

TEST(IceSessionPortmap, GatherWithoutExtensionEmitsNoPortmapCandidate) {
    SessionFixture fix;
    fix.start(/*with_portmap=*/false);

    /// Wait briefly so the gather strand task has a chance to run.
    std::this_thread::sleep_for(30ms);
    const auto cands = fix.session->local_candidates();
    for (const auto& c : cands) {
        EXPECT_FALSE(c.type == CandidateType::Srflx
                       && c.address_str() == "203.0.113.42")
            << "portmap candidate leaked despite missing extension";
    }
    /// And the fake portmap plugin must have seen zero calls — proves
    /// the session bypassed the request path entirely.
    EXPECT_EQ(fix.harness.portmap.request_calls.load(), 0u);
}

TEST(IceSessionPortmap, ZeroSupportedProtocolsSkipsRequest) {
    SessionFixture fix;
    fix.harness.portmap.protocols_mask.store(0);
    fix.start(/*with_portmap=*/true);

    std::this_thread::sleep_for(30ms);
    /// The session called `supported_protocols()` but must not have
    /// issued the request — same fallback path as a missing
    /// extension.
    EXPECT_EQ(fix.harness.portmap.request_calls.load(), 0u);
    const auto cands = fix.session->local_candidates();
    for (const auto& c : cands) {
        EXPECT_FALSE(c.type == CandidateType::Srflx
                       && c.address_str() == "203.0.113.42");
    }
}

TEST(IceSessionPortmap, RequestFailureSkipsCandidateEmission) {
    SessionFixture fix;
    fix.harness.portmap.should_succeed.store(false);
    fix.start(/*with_portmap=*/true);

    std::this_thread::sleep_for(30ms);
    EXPECT_GE(fix.harness.portmap.request_calls.load(), 1u);
    /// On failure the session must not push the synthetic srflx
    /// candidate AND must not have queued a mapping for release.
    const auto cands = fix.session->local_candidates();
    for (const auto& c : cands) {
        EXPECT_FALSE(c.type == CandidateType::Srflx
                       && c.address_str() == "203.0.113.42");
    }
    fix.session->close();
    std::this_thread::sleep_for(30ms);
    EXPECT_EQ(fix.harness.portmap.release_calls.load(), 0u);
}

TEST(IceSessionPortmap, CloseReleasesMapping) {
    SessionFixture fix;
    fix.start(/*with_portmap=*/true);

    EXPECT_TRUE(wait_until(
        [&] { return fix.harness.portmap.request_calls.load() >= 1; }));

    fix.session->close();
    /// `close()` dispatches onto the strand; wait until the release
    /// call is observed.
    EXPECT_TRUE(wait_until(
        [&] { return fix.harness.portmap.release_calls.load() >= 1; }));
    EXPECT_EQ(fix.harness.portmap.last_release_proto.load(),
              GN_PORTMAP_UDP);
    /// `local_port_` was 40123 (set by the fake carrier's
    /// listen_port_val); the release must reuse that same int port
    /// so the router-side renewal table clears the right entry.
    EXPECT_EQ(fix.harness.portmap.last_release_int_port.load(), 40123u);
}

TEST(IceSessionPortmap, FoundationDistinctFromStunSrflx) {
    /// Direct comparison at the foundation-hash level: the two srflx
    /// candidates (portmap vs. STUN) MUST hash to different
    /// foundations even when ext_ip / port collide, because the
    /// `server` component of the tuple differs ("portmap" vs the STUN
    /// server's IP).
    const auto portmap_foundation = compute_foundation(
        CandidateType::Srflx, "203.0.113.42",
        /*server=*/"portmap", TransportType::Udp);
    const auto stun_foundation = compute_foundation(
        CandidateType::Srflx, "203.0.113.42",
        /*server=*/"74.125.250.129", TransportType::Udp);
    EXPECT_NE(portmap_foundation, stun_foundation)
        << "portmap srflx and STUN srflx must produce distinct "
            "foundations so the pacing groups stay separate";

    /// And the actual emitted candidate carries the portmap-derived
    /// foundation. This is the integration-level check that
    /// `gather_portmap` doesn't accidentally collapse onto the STUN
    /// branch.
    SessionFixture fix;
    fix.start(/*with_portmap=*/true);

    EXPECT_TRUE(wait_until([&] {
        for (const auto& c : fix.session->local_candidates()) {
            if (c.type == CandidateType::Srflx
                && c.address_str() == "203.0.113.42") {
                return c.foundation == portmap_foundation;
            }
        }
        return false;
    })) << "portmap srflx candidate did not carry the synthetic "
           "\"portmap\" foundation";
}

}  // namespace
}  // namespace gn::link::ice::test
