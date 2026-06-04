// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_multi_turn.cpp
/// @brief  Multi-TURN fallback coverage: `gather_relay` walks
///         `turn_servers` and fails over to a backup when the
///         primary degrades.
///
/// Fixture: a fake `gn.link.udp` carrier exposed through
/// `host_api->query_extension_checked`. The carrier captures
/// outbound bytes per `(host, port)` endpoint and lets the test
/// deliver responses by invoking the registered per-cid data
/// callback. The session sees a working UDP layer; the test plays
/// the role of every TURN server entry in the config and decides
/// whether ALLOCATE succeeds or fails.

#include <gtest/gtest.h>

#include "../link_ice.hpp"
#include "../session.hpp"
#include "../stun.hpp"
#include "../turn.hpp"

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

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
using StubHost = ::gn::sdk::test::LinkStub;

/// Fake UDP carrier. Captures `connect` / `send` / `subscribe_data`
/// per cid and lets the test drive responses through `deliver`.
struct FakeUdpCarrier {
    struct Endpoint {
        std::string                  host;
        std::uint16_t                port = 0;
        gn_link_data_cb_t            data_cb = nullptr;
        void*                         data_user = nullptr;
        std::vector<std::vector<std::uint8_t>> outbound;
    };

    std::mutex                                       mu;
    std::unordered_map<gn_conn_id_t, Endpoint>       conns;
    /// Per-endpoint hook: when bytes are sent on a cid mapped to
    /// `(host, port)`, the hook fires with the bytes so the test can
    /// inspect / craft a reply. Hooks are keyed by `host:port`.
    std::unordered_map<std::string,
                       std::function<void(gn_conn_id_t,
                                          std::span<const std::uint8_t>)>> hooks;
    std::atomic<gn_conn_id_t>                        next_id{1};
    std::atomic<std::uint16_t>                       listen_port_val{12345};

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

    void set_hook(const std::string& host, std::uint16_t port,
                   std::function<void(gn_conn_id_t,
                                       std::span<const std::uint8_t>)> hook) {
        std::lock_guard lk(mu);
        hooks[host + ":" + std::to_string(port)] = std::move(hook);
    }

    void clear_hook(const std::string& host, std::uint16_t port) {
        std::lock_guard lk(mu);
        hooks.erase(host + ":" + std::to_string(port));
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
        out->flags = GN_LINK_CAP_DATAGRAM;
        out->max_payload = 1500;
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t cid,
                                const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
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
        if (hook) {
            hook(cid, std::span<const std::uint8_t>(bytes, size));
        }
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

/// Couples LinkStub + FakeUdpCarrier through `query_extension_checked`
/// so `IceLink::set_host_api` finds the fake `gn.link.udp`.
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

/// Drive the session's gather flow through a direct IceSession
/// construction. IceLink would also work but the unit-test pin is
/// on the relay-candidate emit + multi-attempt walk, so going
/// straight at IceSession keeps the noise low.
struct SessionFixture {
    asio::io_context                              ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>          work{asio::make_work_guard(ioc)};
    std::thread                                   worker;
    UdpHarness                                    harness;
    std::optional<gn::sdk::LinkCarrier>           carrier;
    std::optional<exec::timed_thread_context>      timer_ctx_p2300{std::in_place};
    std::shared_ptr<IceSession>                   session;
    /// captures the local relay candidates that the session emits.
    /// Sampled from session->local_candidates() under the strand
    /// quiescence; multi_turn tests poll on this snapshot.
    std::mutex                                    cb_mu;
    std::vector<std::string>                      relay_ips;

    SessionFixture() {
        worker = std::thread([this] { ioc.run(); });
        carrier = gn::sdk::LinkCarrier::query(&harness.api, "udp");
    }

    ~SessionFixture() {
        if (session) session->close();
        timer_ctx_p2300.reset();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        carrier.reset();
    }

    void start(const IceConfig& cfg) {
        auto* carrier_ptr = carrier.has_value() ? &*carrier : nullptr;
        IceSessionCallbacks cbs;
        session = std::make_shared<IceSession>(
            ioc, carrier_ptr, nullptr, nullptr,
            cfg, /*peer_id=*/"abcdef0123456789", /*controlling=*/true,
            cbs, /*mdns=*/nullptr, /*portmap=*/nullptr,
            &*timer_ctx_p2300);
        session->gather();
    }

    /// Wait until @p pred holds (sampling local_candidates_) or
    /// timeout. Returns true on satisfaction, false on timeout.
    bool wait_for_relay(const std::function<bool(const std::vector<Candidate>&)>& pred,
                         std::chrono::milliseconds timeout = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                if (session && pred(session->local_candidates())) return true;
            }
            std::this_thread::sleep_for(10ms);
        }
        return false;
    }
};

/// Helpers to craft TURN ALLOCATE responses.
std::vector<std::uint8_t>
build_401(const TransactionId& txn,
           const std::string& realm,
           const std::string& nonce) {
    return StunBuilder(TURN_ALLOCATE_ERROR)
        .set_txn_id(txn)
        .add_error_code(401, "Unauthorized")
        .add_realm(realm)
        .add_nonce(nonce)
        .build();
}

std::vector<std::uint8_t>
build_500(const TransactionId& txn) {
    return StunBuilder(TURN_ALLOCATE_ERROR)
        .set_txn_id(txn)
        .add_error_code(500, "Server Error")
        .build();
}

std::vector<std::uint8_t>
build_allocate_response(const TransactionId& txn,
                          const std::string& relay_ip,
                          std::uint16_t relay_port) {
    /// MESSAGE-INTEGRITY / FINGERPRINT are not required for the
    /// allocate-response parse path in turn.cpp — it reads
    /// `xor_relayed` directly. Skip both to keep the test fixture
    /// independent of the production HMAC key derivation.
    return StunBuilder(TURN_ALLOCATE_RESPONSE)
        .set_txn_id(txn)
        .add_xor_relayed_address(relay_ip, relay_port)
        .add_lifetime(600)
        .build();
}

TransactionId txn_from_message(std::span<const std::uint8_t> bytes) {
    TransactionId t{};
    if (bytes.size() >= 20) {
        std::memcpy(t.data(), bytes.data() + 8, 12);
    }
    return t;
}

}  // namespace

// ── M4: multi-TURN tests ──────────────────────────────────────────────

TEST(IceMultiTurn, MultiTurnFallsOverToSecondOnPrimaryFailure) {
    SessionFixture fx;

    /// Primary always 500-errors on ALLOCATE; secondary answers
    /// 401-challenge then 200 with a relay address.
    fx.harness.carrier.set_hook(
        "primary.example", 3478,
        [&fx](gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
            auto parsed = parse_stun(bytes);
            if (!parsed) return;
            if (parsed->msg_type != TURN_ALLOCATE_REQUEST) return;
            const auto resp = build_500(parsed->txn_id);
            fx.harness.carrier.deliver(cid, resp);
        });
    fx.harness.carrier.set_hook(
        "secondary.example", 3478,
        [&fx](gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
            auto parsed = parse_stun(bytes);
            if (!parsed) return;
            if (parsed->msg_type != TURN_ALLOCATE_REQUEST) return;
            /// First ALLOCATE has no MESSAGE-INTEGRITY; respond 401.
            /// Second carries the credentials; respond 200 with a
            /// concrete relay address.
            if (!parsed->has_integrity) {
                fx.harness.carrier.deliver(
                    cid, build_401(parsed->txn_id, "secondary-realm",
                                      "nonce-2"));
                return;
            }
            fx.harness.carrier.deliver(
                cid, build_allocate_response(parsed->txn_id,
                                                "203.0.113.7", 49152));
        });

    IceConfig cfg;
    cfg.stun_servers.clear();  // skip STUN for this test
    TurnConfig primary{};
    primary.server = "primary.example";
    primary.port = 3478;
    primary.username = "u1";
    primary.password = "p1";
    TurnConfig secondary{};
    secondary.server = "secondary.example";
    secondary.port = 3478;
    secondary.username = "u2";
    secondary.password = "p2";
    cfg.turn_servers = {primary, secondary};
    cfg.turn = primary;
    cfg.turn_allocate_timeout_s = 1;
    cfg.turn_backup_interval_s = 0;  // disable backup-probe noise
    fx.start(cfg);

    /// Expect a Relay candidate with the secondary's relay IP to
    /// land in `local_candidates_` once the FSM advances past the
    /// 500-failing primary. Need >`turn_allocate_timeout_s` of slack
    /// for the per-attempt deadline to fire on the primary plus the
    /// 401 + 200 round-trip on the secondary.
    const bool got = fx.wait_for_relay(
        [](const std::vector<Candidate>& cs) {
            for (const auto& c : cs) {
                if (c.type == CandidateType::Relay
                    && c.address_str() == "203.0.113.7"
                    && c.port == 49152) {
                    return true;
                }
            }
            return false;
        },
        3s);
    EXPECT_TRUE(got)
        << "relay candidate from secondary.example never emitted";
}

TEST(IceMultiTurn, MultiTurnBackupReattemptedAfterInterval) {
    SessionFixture fx;

    std::atomic<int> primary_allocate_calls{0};
    std::atomic<int> backup_allocate_calls{0};

    /// Primary answers a successful ALLOCATE immediately, then
    /// `mark_unhealthy_for_test` simulates the server going dark
    /// (no refresh response). The backup is set to answer
    /// successfully whenever it gets probed.
    fx.harness.carrier.set_hook(
        "primary.example", 3478,
        [&fx, &primary_allocate_calls](
            gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
            auto parsed = parse_stun(bytes);
            if (!parsed) return;
            if (parsed->msg_type != TURN_ALLOCATE_REQUEST) return;
            primary_allocate_calls.fetch_add(1);
            if (!parsed->has_integrity) {
                fx.harness.carrier.deliver(
                    cid, build_401(parsed->txn_id, "primary-realm",
                                      "nonce-1"));
                return;
            }
            fx.harness.carrier.deliver(
                cid, build_allocate_response(parsed->txn_id,
                                                "192.0.2.10", 49100));
        });
    fx.harness.carrier.set_hook(
        "backup.example", 3478,
        [&fx, &backup_allocate_calls](
            gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
            auto parsed = parse_stun(bytes);
            if (!parsed) return;
            if (parsed->msg_type != TURN_ALLOCATE_REQUEST) return;
            backup_allocate_calls.fetch_add(1);
            if (!parsed->has_integrity) {
                fx.harness.carrier.deliver(
                    cid, build_401(parsed->txn_id, "backup-realm",
                                      "nonce-2"));
                return;
            }
            fx.harness.carrier.deliver(
                cid, build_allocate_response(parsed->txn_id,
                                                "198.51.100.20", 49200));
        });

    IceConfig cfg;
    cfg.stun_servers.clear();
    TurnConfig primary{};
    primary.server = "primary.example";
    primary.port = 3478;
    primary.username = "u1";
    primary.password = "p1";
    TurnConfig backup{};
    backup.server = "backup.example";
    backup.port = 3478;
    backup.username = "u2";
    backup.password = "p2";
    cfg.turn_servers = {primary, backup};
    cfg.turn = primary;
    cfg.turn_allocate_timeout_s = 2;
    /// Aggressive backup cadence so the probe fires within the test
    /// window. Two probes within a second cover both the
    /// "primary still healthy → keep" tick and the "primary
    /// degraded → probe again" tick.
    cfg.turn_backup_interval_s = 1;
    cfg.turn_failover_min_interval_s = 0;
    fx.start(cfg);

    /// Wait for primary's relay to land.
    ASSERT_TRUE(fx.wait_for_relay(
        [](const std::vector<Candidate>& cs) {
            for (const auto& c : cs) {
                if (c.type == CandidateType::Relay
                    && c.address_str() == "192.0.2.10") {
                    return true;
                }
            }
            return false;
        }))
        << "primary relay candidate never appeared";

    /// Wait long enough for at least one backup probe tick to fire.
    /// The probe runs unconditionally — even if the primary is
    /// healthy, the backup ALLOCATE happens; promotion is gated but
    /// the probe count is what this test pins.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline
            && backup_allocate_calls.load() == 0) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_GE(backup_allocate_calls.load(), 1)
        << "backup probe never fired against backup.example";
}

}  // namespace gn::link::ice::test
