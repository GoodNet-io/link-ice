// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_tcp.cpp
/// @brief  Coverage for RFC 6544 TCP candidate gather, connectivity
///         checks, simultaneous-open, and the disable flag.

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../link_ice.hpp"
#include "../session.hpp"
#include "../stun.hpp"

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;
using StubHost = ::gn::sdk::test::LinkStub;

/// Synthetic transport carrier shared by the UDP and TCP slots in
/// these tests. The carrier captures outbound sends per cid, exposes
/// per-endpoint hooks for response injection, and tracks the scheme
/// prefix on `connect()` URIs so the TCP-specific tests can confirm
/// the session reached for the TCP carrier rather than the UDP one.
struct FakeCarrier {
    enum class Scheme : std::uint8_t { Udp, Tcp };

    struct Endpoint {
        Scheme                       scheme = Scheme::Udp;
        std::string                  host;
        std::uint16_t                port = 0;
        gn_link_data_cb_t            data_cb = nullptr;
        void*                         data_user = nullptr;
        std::vector<std::vector<std::uint8_t>> outbound;
    };

    std::mutex                                       mu;
    std::unordered_map<gn_conn_id_t, Endpoint>       conns;
    std::unordered_map<std::string,
                       std::function<void(gn_conn_id_t,
                                          std::span<const std::uint8_t>)>> hooks;
    std::atomic<gn_conn_id_t>                        next_id{1};
    std::atomic<std::uint16_t>                       listen_port_val{40000};

    Scheme                                           default_scheme = Scheme::Udp;
    gn_link_api_t                                    vt{};

    explicit FakeCarrier(Scheme s = Scheme::Udp) : default_scheme(s) {
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

    void set_hook(const std::string& host, std::uint16_t port,
                   std::function<void(gn_conn_id_t,
                                       std::span<const std::uint8_t>)> h) {
        std::lock_guard lk(mu);
        hooks[host + ":" + std::to_string(port)] = std::move(h);
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

    std::vector<std::vector<std::uint8_t>>
    outbound_for(const std::string& host, std::uint16_t port) {
        std::lock_guard lk(mu);
        std::vector<std::vector<std::uint8_t>> out;
        for (const auto& [_id, ep] : conns) {
            if (ep.host == host && ep.port == port) {
                out.insert(out.end(), ep.outbound.begin(), ep.outbound.end());
            }
        }
        return out;
    }

    std::size_t connects_to(const std::string& host, std::uint16_t port) {
        std::lock_guard lk(mu);
        std::size_t n = 0;
        for (const auto& [_id, ep] : conns) {
            if (ep.host == host && ep.port == port) ++n;
        }
        return n;
    }

    std::vector<gn_conn_id_t> cids_for(const std::string& host,
                                          std::uint16_t port) {
        std::lock_guard lk(mu);
        std::vector<gn_conn_id_t> out;
        for (const auto& [id, ep] : conns) {
            if (ep.host == host && ep.port == port) out.push_back(id);
        }
        return out;
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        out->flags = GN_LINK_CAP_DATAGRAM;
        out->max_payload = 1500;
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t cid,
                                const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<FakeCarrier*>(ctx);
        std::function<void(gn_conn_id_t,
                            std::span<const std::uint8_t>)> hook;
        std::string host;
        std::uint16_t port = 0;
        {
            std::lock_guard lk(self->mu);
            auto it = self->conns.find(cid);
            if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
            it->second.outbound.emplace_back(bytes, bytes + size);
            host = it->second.host;
            port = it->second.port;
            const auto key = host + ":" + std::to_string(port);
            auto hit = self->hooks.find(key);
            if (hit != self->hooks.end()) hook = hit->second;
        }
        if (hook) hook(cid, std::span<const std::uint8_t>(bytes, size));
        return GN_OK;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t cid, int) {
        auto* self = static_cast<FakeCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        self->conns.erase(cid);
        return GN_OK;
    }
    static gn_result_t s_listen(void*, const char*) { return GN_OK; }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                   gn_conn_id_t* out_conn) {
        auto* self = static_cast<FakeCarrier*>(ctx);
        std::string_view u(uri);
        Endpoint ep;
        ep.scheme = self->default_scheme;
        const auto udp_pfx = std::string_view("udp://");
        const auto tcp_pfx = std::string_view("tcp://");
        if (u.starts_with(udp_pfx)) {
            ep.scheme = Scheme::Udp;
            u.remove_prefix(udp_pfx.size());
        } else if (u.starts_with(tcp_pfx)) {
            ep.scheme = Scheme::Tcp;
            u.remove_prefix(tcp_pfx.size());
        }
        const auto colon = u.rfind(':');
        if (colon != std::string_view::npos) {
            ep.host = std::string(u.substr(0, colon));
            try {
                ep.port = static_cast<std::uint16_t>(
                    std::stoul(std::string(u.substr(colon + 1))));
            } catch (...) {
                return GN_ERR_INVALID_ENVELOPE;
            }
        } else {
            ep.host = std::string(u);
            ep.port = 0;
        }
        const auto cid = self->next_id.fetch_add(1);
        {
            std::lock_guard lk(self->mu);
            self->conns[cid] = std::move(ep);
        }
        if (out_conn) *out_conn = cid;
        return GN_OK;
    }
    static gn_result_t s_sub_data(void* ctx, gn_conn_id_t cid,
                                    gn_link_data_cb_t cb, void* user) {
        auto* self = static_cast<FakeCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
        it->second.data_cb = cb;
        it->second.data_user = user;
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t cid) {
        auto* self = static_cast<FakeCarrier*>(ctx);
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
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = static_cast<FakeCarrier*>(ctx)
                  ->listen_port_val.load(std::memory_order_acquire);
        return GN_OK;
    }
};

struct TcpHarness {
    StubHost                  link_stub;
    FakeCarrier               udp_carrier{FakeCarrier::Scheme::Udp};
    FakeCarrier               tcp_carrier{FakeCarrier::Scheme::Tcp};
    host_api_t                api{};

    TcpHarness() {
        api = ::gn::sdk::test::make_link_host_api(link_stub);
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* self = static_cast<TcpHarness*>(host_ctx);
        const std::string_view nm(name);
        if (nm == "gn.link.udp") {
            *out = &self->udp_carrier.vt;
            return GN_OK;
        }
        if (nm == "gn.link.tcp") {
            *out = &self->tcp_carrier.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

struct SessionFixture {
    asio::io_context                              ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>          work{asio::make_work_guard(ioc)};
    std::thread                                   worker;
    TcpHarness                                    harness;
    std::optional<gn::sdk::LinkCarrier>           udp_carrier;
    std::optional<gn::sdk::LinkCarrier>           tcp_carrier;
    std::shared_ptr<IceSession>                   session;

    SessionFixture() {
        worker = std::thread([this] { ioc.run(); });
        udp_carrier = gn::sdk::LinkCarrier::query(&harness.api, "udp");
        tcp_carrier = gn::sdk::LinkCarrier::query(&harness.api, "tcp");
    }

    ~SessionFixture() {
        if (session) session->close();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        udp_carrier.reset();
        tcp_carrier.reset();
    }

    void start(const IceConfig& cfg, bool controlling = true,
                bool with_tcp = true) {
        auto* udp_ptr = udp_carrier.has_value() ? &*udp_carrier : nullptr;
        auto* tcp_ptr = (with_tcp && tcp_carrier.has_value())
                            ? &*tcp_carrier : nullptr;
        IceSessionCallbacks cbs;
        session = std::make_shared<IceSession>(
            ioc, udp_ptr, tcp_ptr, /*tls=*/nullptr,
            cfg, /*peer_id=*/"abcdef0123456789", controlling,
            cbs, /*mdns=*/nullptr);
        session->gather();
    }
};

template <typename F>
bool wait_until(F pred, std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

}  // namespace

// ── T6.1 gather emits TCP host candidates ────────────────────────────────

TEST(IceTcpCandidates, GatherEmitsTcpHostCandidates) {
    /// With tcp_candidates_enabled on and a TCP carrier wired, the
    /// session must mirror every UDP host candidate as three TCP
    /// variants — active, passive, simultaneous-open.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.tcp_candidates_enabled = true;
    fx.start(cfg);

    /// Give gather time to walk getifaddrs + emit TCP mirrors.
    ASSERT_TRUE(wait_until([&] {
        const auto& cands = fx.session->local_candidates();
        bool any_udp_host = false;
        for (const auto& c : cands) {
            if (c.type == CandidateType::Host
                && c.transport == TransportType::Udp) {
                any_udp_host = true;
                break;
            }
        }
        return any_udp_host;
    }, 2s));

    std::size_t udp_hosts = 0;
    std::size_t tcp_active = 0;
    std::size_t tcp_passive = 0;
    std::size_t tcp_so = 0;
    for (const auto& c : fx.session->local_candidates()) {
        if (c.type != CandidateType::Host) continue;
        switch (c.transport) {
            case TransportType::Udp: ++udp_hosts; break;
            case TransportType::TcpActive: ++tcp_active; break;
            case TransportType::TcpPassive: ++tcp_passive; break;
            case TransportType::TcpSimultaneousOpen: ++tcp_so; break;
        }
    }

    EXPECT_GE(udp_hosts, 1u);
    EXPECT_EQ(tcp_active, udp_hosts);
    EXPECT_EQ(tcp_passive, udp_hosts);
    EXPECT_EQ(tcp_so, udp_hosts);
}

// ── T6.2 check succeeds over TCP-passive pair (active/passive) ──────────

TEST(IceTcpCandidates, CheckSucceedsOverTcpPassivePair) {
    /// Build a local TcpActive host candidate, hand the session a
    /// remote TcpPassive candidate, and confirm `send_check` reaches
    /// for the TCP carrier with a length-prefixed STUN frame. The
    /// active local pairs with the passive remote per RFC 6544 §5.1.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.tcp_candidates_enabled = true;
    cfg.check_interval_ms = 20;
    fx.start(cfg, /*controlling=*/true);

    ASSERT_TRUE(wait_until([&] {
        for (const auto& c : fx.session->local_candidates()) {
            if (c.type == CandidateType::Host
                && c.transport == TransportType::TcpActive) return true;
        }
        return false;
    }, 2s));

    Candidate remote{};
    remote.type = CandidateType::Host;
    remote.family = AddressFamily::IPv4;
    remote.port = 51001;
    remote.transport = TransportType::TcpPassive;
    remote.priority = compute_priority(CandidateType::Host, 65535, 1);
    remote.set_address("192.0.2.10");
    fx.session->add_remote_candidates(
        "remoteu", "remotepwdremotepwdremotepwd",
        std::vector<Candidate>{remote}, /*eoc=*/true);

    EXPECT_TRUE(wait_until([&] {
        return fx.harness.tcp_carrier.connects_to("192.0.2.10", 51001) >= 1;
    }, 3s)) << "TCP connect to passive peer never issued";

    const auto frames =
        fx.harness.tcp_carrier.outbound_for("192.0.2.10", 51001);
    ASSERT_FALSE(frames.empty()) << "no STUN frame sent over TCP carrier";

    /// First two bytes are the RFC 5389 §7.2.2 length prefix; the
    /// declared length must match the rest of the frame.
    const auto& f = frames.front();
    ASSERT_GE(f.size(), 22u);
    const std::uint16_t declared =
        (static_cast<std::uint16_t>(f[0]) << 8)
        | static_cast<std::uint16_t>(f[1]);
    EXPECT_EQ(declared + 2u, f.size());

    /// The UDP carrier should NOT have seen a check for the passive
    /// endpoint — TCP and UDP paths are disjoint.
    const auto udp_frames =
        fx.harness.udp_carrier.outbound_for("192.0.2.10", 51001);
    EXPECT_TRUE(udp_frames.empty());
}

// ── T6.3 simultaneous-open bidirectional connect ────────────────────────

TEST(IceTcpCandidates, SimultaneousOpenBidirectionalConnect) {
    /// Both peers' TCP-SO candidates pair together; the local side
    /// fires `connect()` toward the remote SO candidate within the
    /// configured window. The TCP carrier records the connect call;
    /// without a real peer the SYN-SYN exchange never completes, but
    /// the local `connect()` is the contribution our agent owes the
    /// kernel under RFC 6544 §6.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.tcp_candidates_enabled = true;
    cfg.check_interval_ms = 20;
    cfg.tcp_so_timeout_ms = 1000;
    fx.start(cfg, /*controlling=*/true);

    ASSERT_TRUE(wait_until([&] {
        for (const auto& c : fx.session->local_candidates()) {
            if (c.type == CandidateType::Host
                && c.transport == TransportType::TcpSimultaneousOpen) {
                return true;
            }
        }
        return false;
    }, 2s));

    Candidate remote{};
    remote.type = CandidateType::Host;
    remote.family = AddressFamily::IPv4;
    remote.port = 51002;
    remote.transport = TransportType::TcpSimultaneousOpen;
    remote.priority = compute_priority(CandidateType::Host, 65535, 1);
    remote.set_address("192.0.2.20");
    fx.session->add_remote_candidates(
        "remoteu", "remotepwdremotepwdremotepwd",
        std::vector<Candidate>{remote}, /*eoc=*/true);

    /// The local side's `connect()` is the SO contribution from us.
    /// The carrier records every connect; a matching SO from the peer
    /// would land on its end and the kernel would complete the
    /// handshake.
    EXPECT_TRUE(wait_until([&] {
        return fx.harness.tcp_carrier.connects_to("192.0.2.20", 51002) >= 1;
    }, 3s)) << "local SO connect never fired";
}

// ── T6.4 disabled flag suppresses emission ─────────────────────────────

TEST(IceTcpCandidates, DisabledFlagSuppressesEmission) {
    /// With the flag flipped off, gather must NEVER produce a TCP
    /// candidate even when a TCP carrier is wired and reachable.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.tcp_candidates_enabled = false;
    fx.start(cfg);

    ASSERT_TRUE(wait_until([&] {
        const auto& cands = fx.session->local_candidates();
        for (const auto& c : cands) {
            if (c.type == CandidateType::Host
                && c.transport == TransportType::Udp) return true;
        }
        return false;
    }, 2s));

    for (const auto& c : fx.session->local_candidates()) {
        EXPECT_EQ(c.transport, TransportType::Udp)
            << "candidate with TCP transport leaked despite disabled flag";
    }
}

}  // namespace gn::link::ice::test
