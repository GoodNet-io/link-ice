// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_nomination.cpp
/// @brief  Regression tests for RFC 8445 §8.1.2 — controlled agent deferred
///         nomination.  USE-CANDIDATE on a non-Succeeded pair must not
///         immediately transition to Connected; the session must wait for the
///         connectivity-check response before calling on_nominated.

#include <gtest/gtest.h>

#include "../candidate.hpp"
#include "../session.hpp"
#include "../stun.hpp"

#include <sdk/cpp/link_carrier.hpp>
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
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;
using StubHost = ::gn::sdk::test::LinkStub;

// ── Helpers ───────────────────────────────────────────────────────────────

template <typename F>
bool wait_until(F pred, std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

// ── FakeUdpCarrier ────────────────────────────────────────────────────────
//
// Tracks outbound bytes per endpoint and lets the test inject inbound bytes
// via the registered data_cb (which the session wires up via subscribe_data
// when it calls ensure_remote_cid).  A per-endpoint send-hook can be installed
// so the test receives a notification the moment the session sends the first
// check, at which point the cid IS registered and deliver() works.

struct FakeUdpCarrier {
    struct Endpoint {
        std::string                            host;
        std::uint16_t                          port      = 0;
        gn_link_data_cb_t                      data_cb   = nullptr;
        void*                                  data_user = nullptr;
        std::vector<std::vector<std::uint8_t>> outbound;
    };

    std::mutex                               mu;
    std::unordered_map<gn_conn_id_t, Endpoint> conns;
    std::unordered_map<std::string,
        std::function<void(gn_conn_id_t,
                           std::span<const std::uint8_t>)>> hooks;
    std::atomic<gn_conn_id_t>  next_id{1};
    std::atomic<std::uint16_t> listen_port_val{40000};
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

    /// Install a hook called whenever the session sends to (host, port).
    /// The hook receives the cid the session opened for that endpoint, so
    /// the test can call deliver() on it immediately — at that point
    /// subscribe_data has already registered the callback.
    void set_hook(const std::string& host, std::uint16_t port,
                  std::function<void(gn_conn_id_t,
                                     std::span<const std::uint8_t>)> h) {
        std::lock_guard lk(mu);
        hooks[host + ":" + std::to_string(port)] = std::move(h);
    }

    /// Deliver inbound bytes to the session through its registered data_cb.
    /// Only works after the session has called subscribe_data for this cid
    /// (i.e., after ensure_remote_cid was called for the matching endpoint).
    void deliver(gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
        gn_link_data_cb_t cb   = nullptr;
        void*             user = nullptr;
        {
            std::lock_guard lk(mu);
            auto it = conns.find(cid);
            if (it == conns.end()) return;
            cb   = it->second.data_cb;
            user = it->second.data_user;
        }
        if (cb) cb(user, cid, bytes.data(), bytes.size());
    }

    std::optional<gn_conn_id_t> cid_for(const std::string& host,
                                          std::uint16_t port) {
        std::lock_guard lk(mu);
        for (const auto& [id, ep] : conns) {
            if (ep.host == host && ep.port == port) return id;
        }
        return std::nullopt;
    }

    std::vector<std::vector<std::uint8_t>>
    outbound_for(const std::string& host, std::uint16_t port) {
        std::lock_guard lk(mu);
        std::vector<std::vector<std::uint8_t>> out;
        for (const auto& [_id, ep] : conns) {
            if (ep.host == host && ep.port == port)
                out.insert(out.end(), ep.outbound.begin(), ep.outbound.end());
        }
        return out;
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        out->flags       = GN_LINK_CAP_DATAGRAM;
        out->max_payload = 1500;
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t cid,
                               const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::function<void(gn_conn_id_t,
                           std::span<const std::uint8_t>)> hook;
        {
            std::lock_guard lk(self->mu);
            auto it = self->conns.find(cid);
            if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
            it->second.outbound.emplace_back(bytes, bytes + size);
            const auto key = it->second.host + ":" +
                             std::to_string(it->second.port);
            auto hit = self->hooks.find(key);
            if (hit != self->hooks.end()) hook = hit->second;
        }
        if (hook) hook(cid, std::span<const std::uint8_t>(bytes, size));
        return GN_OK;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t cid, int) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        self->conns.erase(cid);
        return GN_OK;
    }
    static gn_result_t s_listen(void*, const char*) { return GN_OK; }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out_conn) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::string_view u(uri);
        const auto pfx = std::string_view("udp://");
        if (u.starts_with(pfx)) u.remove_prefix(pfx.size());
        const auto colon = u.rfind(':');
        Endpoint ep;
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
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
        it->second.data_cb   = cb;
        it->second.data_user = user;
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t cid) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_OK;
        it->second.data_cb   = nullptr;
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
        *out = static_cast<FakeUdpCarrier*>(ctx)
                   ->listen_port_val.load(std::memory_order_acquire);
        return GN_OK;
    }
};

// ── Fixture ───────────────────────────────────────────────────────────────

struct NominationFixture {
    asio::io_context ioc;
    asio::executor_work_guard<asio::io_context::executor_type> work{
        asio::make_work_guard(ioc)};
    std::thread worker;

    StubHost       stub;
    FakeUdpCarrier carrier;
    host_api_t     api{};
    std::optional<gn::sdk::LinkCarrier> link_carrier;
    std::optional<exec::timed_thread_context> timer_ctx_p2300{std::in_place};
    std::shared_ptr<IceSession>         session;

    std::atomic<bool> connected{false};
    std::atomic<bool> failed{false};

    NominationFixture() {
        worker = std::thread([this] { ioc.run(); });
        api    = ::gn::sdk::test::make_link_host_api(stub);
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
        link_carrier = gn::sdk::LinkCarrier::query(&api, "udp");
    }

    ~NominationFixture() {
        if (session) session->close();
        timer_ctx_p2300.reset();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        link_carrier.reset();
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                std::uint32_t version, const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* self = static_cast<NominationFixture*>(host_ctx);
        if (std::string_view(name) == "gn.link.udp") {
            *out = &self->carrier.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    void start(bool controlling = false) {
        IceConfig cfg;
        cfg.stun_servers.clear();
        cfg.check_interval_ms = 50;
        cfg.max_check_retries = 3;

        IceSessionCallbacks cbs;
        cbs.on_connected = [this](const std::string&,
                                   const std::string&, std::uint16_t) {
            connected.store(true, std::memory_order_release);
        };
        cbs.on_failed = [this](const std::string&, int) {
            failed.store(true, std::memory_order_release);
        };

        auto* cp = link_carrier.has_value() ? &*link_carrier : nullptr;
        session  = std::make_shared<IceSession>(
            ioc, cp, nullptr, nullptr, cfg,
            /*peer_id=*/"controller_peer_0123456789ab",
            controlling, cbs, nullptr,
            /*portmap=*/nullptr, &*timer_ctx_p2300);
        session->gather();
    }
};

}  // namespace

// ── Tests ─────────────────────────────────────────────────────────────────

/// §8.1.2: USE-CANDIDATE on a non-Succeeded pair must NOT immediately
/// transition to Connected.
///
/// Strategy: wait for the session to send the first check to the remote
/// candidate (at which point the session has registered a data_cb on that
/// cid via ensure_remote_cid). Then deliver USE-CANDIDATE via that cid.
/// With the fix, the session defers nomination and stays in Checking.
/// With the old buggy code, it calls on_nominated immediately → Connected.
TEST(IceNomination, UseCandidateBeforeCheckSucceedsDoesNotImmediatelyConnect) {
    NominationFixture fx;
    fx.start(/*controlling=*/false);

    const bool gathered = wait_until([&] {
        return !fx.session->local_candidates().empty();
    }, 3s);
    ASSERT_TRUE(gathered) << "session never gathered a local candidate";

    const std::string peer_ip   = "192.0.2.77";
    const std::uint16_t peer_port = 53001;

    Candidate r{};
    r.type     = CandidateType::Host;
    r.family   = AddressFamily::IPv4;
    r.port     = peer_port;
    r.priority = compute_priority(CandidateType::Host, 65535, 1);
    r.set_address(peer_ip);

    const auto local_ufrag = fx.session->local_ufrag();
    const auto local_pwd   = fx.session->local_pwd();

    /// Build the USE-CANDIDATE message up-front so the hook body can
    /// capture it by value without accessing session state on an alien thread.
    auto txn = generate_txn_id();
    auto use_cand_msg = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(txn)
        .add_username(local_ufrag + ":remoteu")
        .add_priority(r.priority)
        .add_ice_controlling(0xC0FFEEC0FFEEULL)
        .add_use_candidate()
        .add_integrity(local_pwd)
        .add_fingerprint()
        .build();

    /// Install a one-shot hook: the moment the session sends its first
    /// check to peer_ip:peer_port, it has registered data_cb on that cid
    /// via subscribe_data — so deliver() will reach on_carrier_data.
    std::atomic<bool> use_cand_delivered{false};
    fx.carrier.set_hook(peer_ip, peer_port,
        [&](gn_conn_id_t cid, std::span<const std::uint8_t>) {
            if (use_cand_delivered.exchange(true)) return;
            fx.carrier.deliver(cid, use_cand_msg);
        });

    fx.session->add_remote_candidates(
        "remoteu", "remotepwdremotepwdremotepwd",
        std::vector<Candidate>{r}, /*end_of_candidates=*/true);

    const bool delivered = wait_until([&] {
        return use_cand_delivered.load(std::memory_order_acquire);
    }, 3s);
    ASSERT_TRUE(delivered) << "session never sent a check to remote candidate";

    /// Give the session one check_interval to process the USE-CANDIDATE.
    std::this_thread::sleep_for(150ms);

    EXPECT_FALSE(fx.connected.load(std::memory_order_acquire))
        << "session transitioned to Connected immediately after receiving "
           "USE-CANDIDATE for a non-Succeeded pair — violates RFC 8445 §8.1.2";
}

/// §8.1.2: after USE-CANDIDATE on a non-Succeeded pair, when the
/// connectivity-check eventually succeeds the session MUST call on_connected.
///
/// We forge a valid STUN binding response matching the check the session
/// sent, which makes the pair Succeeded and fires the deferred nomination.
TEST(IceNomination, UseCandidateDeferredNominationCompletesAfterCheckSuccess) {
    NominationFixture fx;
    fx.start(/*controlling=*/false);

    const bool gathered = wait_until([&] {
        return !fx.session->local_candidates().empty();
    }, 3s);
    ASSERT_TRUE(gathered) << "session never gathered a local candidate";

    const std::string peer_ip    = "192.0.2.88";
    const std::uint16_t peer_port = 54001;

    Candidate r{};
    r.type     = CandidateType::Host;
    r.family   = AddressFamily::IPv4;
    r.port     = peer_port;
    r.priority = compute_priority(CandidateType::Host, 65535, 1);
    r.set_address(peer_ip);

    const auto local_ufrag = fx.session->local_ufrag();
    const auto local_pwd   = fx.session->local_pwd();

    auto use_txn = generate_txn_id();
    auto use_cand_msg = StunBuilder(STUN_BINDING_REQUEST)
        .set_txn_id(use_txn)
        .add_username(local_ufrag + ":remoteu2")
        .add_priority(r.priority)
        .add_ice_controlling(0xDEADBEEFDEADULL)
        .add_use_candidate()
        .add_integrity(local_pwd)
        .add_fingerprint()
        .build();

    const std::string remote_pwd = "remotepwdremotepwdremote2";

    /// The hook fires when the session sends a binding-request check.
    /// We capture the check's transaction-id so we can forge a matching
    /// success response that makes the pair Succeeded.  We deliver both
    /// USE-CANDIDATE and the forged response in one shot.
    std::atomic<bool> hook_fired{false};
    fx.carrier.set_hook(peer_ip, peer_port,
        [&](gn_conn_id_t cid, std::span<const std::uint8_t> outbound) {
            if (hook_fired.exchange(true)) return;

            /// First deliver USE-CANDIDATE so the session sets pending_nomination.
            fx.carrier.deliver(cid, use_cand_msg);

            /// Parse the check the session just sent to extract its txn_id,
            /// then forge a matching success response signed with remote_pwd.
            auto parsed = parse_stun(outbound);
            if (!parsed) return;

            auto success = StunBuilder(STUN_BINDING_RESPONSE)
                .set_txn_id(parsed->txn_id)
                .add_xor_peer_address(peer_ip, peer_port)
                .add_integrity(remote_pwd)
                .add_fingerprint()
                .build();
            fx.carrier.deliver(cid, success);
        });

    fx.session->add_remote_candidates(
        "remoteu2", remote_pwd,
        std::vector<Candidate>{r}, /*end_of_candidates=*/true);

    const bool became_connected = wait_until([&] {
        return fx.connected.load(std::memory_order_acquire);
    }, 3s);

    EXPECT_TRUE(became_connected)
        << "session never called on_connected after USE-CANDIDATE + successful "
           "check response — deferred §8.1.2 nomination did not complete";
}

}  // namespace gn::link::ice::test
