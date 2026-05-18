// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_auto_restart.cpp
/// @brief  Coverage for the auto-restart-on-consent-loss policy:
///         enable / disable / max-attempts / backoff.

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
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gn::link::ice::test {
namespace {

using namespace std::chrono_literals;
using StubHost = ::gn::sdk::test::LinkStub;

/// Minimal UDP carrier stub — same shape as the lite / symmetric-NAT
/// fixtures. The auto-restart tests do not exercise the wire, but the
/// session still needs a carrier resolved or `gather_host_candidates`
/// short-circuits before the strand is wired up.
struct FakeUdpCarrier {
    struct Endpoint {
        std::string                  host;
        std::uint16_t                port = 0;
        gn_link_data_cb_t            data_cb = nullptr;
        void*                         data_user = nullptr;
    };

    std::mutex                                       mu;
    std::unordered_map<gn_conn_id_t, Endpoint>       conns;
    std::atomic<gn_conn_id_t>                        next_id{1};
    std::atomic<std::uint16_t>                       listen_port_val{40000};

    gn_link_api_t                                    vt{};

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
        out->flags = GN_LINK_CAP_DATAGRAM;
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
        it->second.data_cb = cb;
        it->second.data_user = user;
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t cid) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
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
        *out = static_cast<FakeUdpCarrier*>(ctx)
                  ->listen_port_val.load(std::memory_order_acquire);
        return GN_OK;
    }
};

struct UdpHarness {
    StubHost                  link_stub;
    FakeUdpCarrier            carrier;
    host_api_t                api{};

    UdpHarness() {
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
        auto* self = static_cast<UdpHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.udp") {
            *out = &self->carrier.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

/// Captures every on_auto_restart + on_failed surface the session
/// emits so a test can assert which branch the policy picked.
struct RestartObserver {
    std::atomic<int>                  restart_count{0};
    std::atomic<int>                  failed_count{0};
    std::atomic<std::uint32_t>        last_attempt{0};
    std::atomic<std::uint32_t>        last_max_attempts{0};

    IceSessionCallbacks make() {
        IceSessionCallbacks cbs;
        cbs.on_failed = [this](const std::string&, int) {
            failed_count.fetch_add(1, std::memory_order_acq_rel);
        };
        cbs.on_auto_restart = [this](const std::string&,
                                       std::string_view,
                                       std::uint32_t attempt,
                                       std::uint32_t max_attempts) {
            restart_count.fetch_add(1, std::memory_order_acq_rel);
            last_attempt.store(attempt, std::memory_order_release);
            last_max_attempts.store(max_attempts, std::memory_order_release);
        };
        return cbs;
    }
};

struct SessionFixture {
    asio::io_context                              ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>          work{asio::make_work_guard(ioc)};
    std::thread                                   worker;
    UdpHarness                                    harness;
    std::optional<gn::sdk::LinkCarrier>           carrier;
    RestartObserver                               observer;
    std::shared_ptr<IceSession>                   session;

    SessionFixture() {
        worker = std::thread([this] { ioc.run(); });
        carrier = gn::sdk::LinkCarrier::query(&harness.api, "udp");
    }

    ~SessionFixture() {
        if (session) session->close();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        carrier.reset();
    }

    void start(const IceConfig& cfg) {
        auto* carrier_ptr = carrier.has_value() ? &*carrier : nullptr;
        session = std::make_shared<IceSession>(
            ioc, carrier_ptr, nullptr, nullptr,
            cfg, /*peer_id=*/"abcdef0123456789",
            /*controlling=*/true,
            observer.make(), /*mdns=*/nullptr);
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

TEST(IceAutoRestart, RestartsOnConsentLossWhenEnabled) {
    /// With the policy enabled a single consent-loss event flips the
    /// session through restart() back into a non-Failed state and
    /// surfaces an on_auto_restart callback.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.auto_restart_on_consent_loss = true;
    cfg.auto_restart_max_attempts    = 3;
    cfg.auto_restart_backoff_ms      = 0;
    fx.start(cfg);

    const auto pre_ufrag = fx.session->local_ufrag();
    const bool decided = fx.session->notify_consent_loss_for_test();
    EXPECT_TRUE(decided);

    EXPECT_TRUE(wait_until([&] {
        return fx.observer.restart_count.load(std::memory_order_acquire)
               >= 1;
    }, 1s));
    EXPECT_EQ(fx.observer.failed_count.load(std::memory_order_acquire), 0);
    EXPECT_EQ(fx.observer.last_attempt.load(std::memory_order_acquire),
              1u);

    /// restart() regenerates ufrag / pwd on the strand; wait for the
    /// new credentials to land and confirm the session is NOT Failed.
    EXPECT_TRUE(wait_until([&] {
        return fx.session->local_ufrag() != pre_ufrag;
    }, 1s));
    EXPECT_NE(fx.session->state(), SessionState::Failed);
}

TEST(IceAutoRestart, DoesNotRestartWhenDisabled) {
    /// Flipping the policy off preserves the strict RFC 7675
    /// behaviour: consent-loss transitions straight to Failed and
    /// fires on_failed.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.auto_restart_on_consent_loss = false;
    cfg.auto_restart_max_attempts    = 3;
    cfg.auto_restart_backoff_ms      = 0;
    fx.start(cfg);

    const bool decided = fx.session->notify_consent_loss_for_test();
    EXPECT_FALSE(decided);

    EXPECT_TRUE(wait_until([&] {
        return fx.observer.failed_count.load(std::memory_order_acquire)
               >= 1;
    }, 1s));
    EXPECT_EQ(fx.observer.restart_count.load(std::memory_order_acquire),
              0);
    EXPECT_EQ(fx.session->state(), SessionState::Failed);
}

TEST(IceAutoRestart, RespectsMaxAttempts) {
    /// After `auto_restart_max_attempts` restarts the session must
    /// fall through to Failed on the next consent-loss instead of
    /// firing yet another restart. Backoff is zeroed so the loop
    /// exercises the cap, not the rate limit.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.auto_restart_on_consent_loss = true;
    cfg.auto_restart_max_attempts    = 2;
    cfg.auto_restart_backoff_ms      = 0;
    fx.start(cfg);

    /// First two consent-loss events should restart.
    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    EXPECT_TRUE(wait_until([&] {
        return fx.observer.restart_count.load(std::memory_order_acquire)
               >= 1;
    }, 1s));
    /// Wait for the previous restart() body to settle on the strand
    /// before issuing the next one; restart() dispatches its body
    /// back through the strand and may not have completed yet.
    std::this_thread::sleep_for(50ms);

    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    EXPECT_TRUE(wait_until([&] {
        return fx.observer.restart_count.load(std::memory_order_acquire)
               >= 2;
    }, 1s));
    std::this_thread::sleep_for(50ms);

    /// Third event must NOT restart — counter is exhausted. The
    /// session transitions to Failed and fires on_failed instead.
    const bool decided = fx.session->notify_consent_loss_for_test();
    EXPECT_FALSE(decided);
    EXPECT_EQ(fx.observer.restart_count.load(std::memory_order_acquire),
              2);
    EXPECT_TRUE(wait_until([&] {
        return fx.observer.failed_count.load(std::memory_order_acquire)
               >= 1;
    }, 1s));
    EXPECT_EQ(fx.session->state(), SessionState::Failed);
}

TEST(IceAutoRestart, BackoffEnforcedBetweenRestarts) {
    /// Two consent-loss events landing within `auto_restart_backoff_ms`
    /// must be coalesced into a single restart — the FSM does not
    /// double-restart for one network blip.
    SessionFixture fx;
    IceConfig cfg;
    cfg.stun_servers.clear();
    cfg.auto_restart_on_consent_loss = true;
    cfg.auto_restart_max_attempts    = 5;
    cfg.auto_restart_backoff_ms      = 250;
    fx.start(cfg);

    /// First event fires immediately (no prior timestamp set).
    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    EXPECT_TRUE(wait_until([&] {
        return fx.observer.restart_count.load(std::memory_order_acquire)
               >= 1;
    }, 1s));

    /// Second event inside the backoff window — must be swallowed.
    /// The decision still returns true (we did not fall through to
    /// Failed) but the restart counter must not advance.
    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(fx.observer.restart_count.load(std::memory_order_acquire),
              1);

    /// After the backoff window expires another event MUST restart.
    std::this_thread::sleep_for(300ms);
    EXPECT_TRUE(fx.session->notify_consent_loss_for_test());
    EXPECT_TRUE(wait_until([&] {
        return fx.observer.restart_count.load(std::memory_order_acquire)
               >= 2;
    }, 1s));
}

}  // namespace gn::link::ice::test
