// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/turn.cpp

#include "turn.hpp"

#include <asio/buffer.hpp>
#include <asio/ip/udp.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <openssl/evp.h>
#include <sodium/utils.h>

namespace gn::link::ice {

TurnClient::TurnClient(asio::io_context& io, const TurnConfig& cfg,
                         TurnDataCallback data_cb,
                         TurnAllocatedCallback alloc_cb)
    : io_(io), cfg_(cfg), data_cb_(std::move(data_cb)),
      alloc_cb_(std::move(alloc_cb)),
      socket_(io, asio::ip::udp::v4()),
      refresh_timer_(io) {
    // Resolve server.
    asio::ip::udp::resolver resolver(io);
    std::error_code ec;
    auto results = resolver.resolve(cfg_.server, std::to_string(cfg_.port), ec);
    if (!ec && results.begin() != results.end())
        server_ep_ = *results.begin();
}

TurnClient::~TurnClient() {
    close();
    sodium_memzero(auth_key_.data(), auth_key_.size());
}

void TurnClient::compute_auth_key() {
    /// MD5(user:realm:pass) per RFC 5389 §15.4. Plain MD5 is the
    /// long-term-credential KDF the spec mandates; do not "modernise"
    /// to SHA-256 — it would silently break interop with every TURN
    /// server in the wild.
    std::string input = cfg_.username + ":" + realm_ + ":" + cfg_.password;
    uint8_t digest[16];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, digest, nullptr);
    EVP_MD_CTX_free(ctx);
    auth_key_ = std::string(reinterpret_cast<char*>(digest), 16);
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(input.data(), input.size());
}

bool TurnClient::allocate() {
    if (cfg_.server.empty()) return false;

    /// Speculative unauthenticated request. RFC 5766 §6.2 says the
    /// server replies with 401 carrying realm/nonce; we then retry
    /// with `MESSAGE-INTEGRITY` from `compute_auth_key`.
    auto msg = StunBuilder(TURN_ALLOCATE_REQUEST)
        .add_requested_transport(17)  // UDP
        .build();
    std::error_code ec;
    socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
    start_recv();
    return true;
}

void TurnClient::start_recv() {
    socket_.async_receive_from(
        asio::buffer(recv_buf_), sender_ep_,
        [weak_self = weak_from_this()](
            const std::error_code& ec, size_t bytes) {
            auto self = weak_self.lock();
            if (!self) return;
            if (!ec) self->handle_recv(bytes);
            if (!ec || ec == asio::error::would_block)
                self->start_recv();
        });
}

void TurnClient::handle_recv(size_t bytes) {
    auto parsed = parse_stun(std::span(recv_buf_.data(), bytes));
    if (!parsed) return;

    if (parsed->msg_type == TURN_ALLOCATE_ERROR) {
        if (parsed->error_code == 401 || parsed->error_code == 438) {
            // Need auth or stale nonce
            if (parsed->realm) realm_ = *parsed->realm;
            if (parsed->nonce) nonce_ = *parsed->nonce;
            compute_auth_key();

            // Retry with credentials
            auto msg = StunBuilder(TURN_ALLOCATE_REQUEST)
                .add_requested_transport(17)
                .add_username(cfg_.username)
                .add_realm(realm_)
                .add_nonce(nonce_)
                .add_integrity(auth_key_)
                .add_fingerprint()
                .build();
            std::error_code ec;
            socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
        }
    } else if (parsed->msg_type == TURN_ALLOCATE_RESPONSE) {
        handle_allocate_response(*parsed);
    } else if (parsed->msg_type == TURN_DATA_INDICATION) {
        handle_data_indication(*parsed);
    }
}

void TurnClient::handle_allocate_response(const StunMessage& msg) {
    std::lock_guard lk(mu_);
    if (msg.xor_relayed) {
        relayed_ = *msg.xor_relayed;
        allocated_ = true;
        if (msg.lifetime) lifetime_ = *msg.lifetime;
        schedule_refresh();

        // Notify session that relay address is available.
        if (alloc_cb_)
            alloc_cb_(relayed_.ip, relayed_.port);
    }
}

void TurnClient::handle_data_indication(const StunMessage& msg) {
    if (msg.xor_peer && !msg.data.empty()) {
        data_cb_(msg.xor_peer->ip, msg.xor_peer->port, msg.data);
    }
}

void TurnClient::send_indication(const std::string& peer_ip, uint16_t peer_port,
                                   std::span<const uint8_t> data) {
    auto msg = StunBuilder(TURN_SEND_INDICATION)
        .add_xor_peer_address(peer_ip, peer_port)
        .add_data(data)
        .build();
    std::error_code ec;
    socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
}

void TurnClient::create_permission(const std::string& peer_ip) {
    std::lock_guard lk(mu_);
    if (permissions_.contains(peer_ip)) return;
    permissions_.insert(peer_ip);

    auto msg = StunBuilder(TURN_CREATE_PERM_REQUEST)
        .add_xor_peer_address(peer_ip, 0)
        .add_username(cfg_.username)
        .add_realm(realm_)
        .add_nonce(nonce_)
        .add_integrity(auth_key_)
        .add_fingerprint()
        .build();
    std::error_code ec;
    socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
}

void TurnClient::refresh() {
    auto msg = StunBuilder(TURN_REFRESH_REQUEST)
        .add_lifetime(lifetime_)
        .add_username(cfg_.username)
        .add_realm(realm_)
        .add_nonce(nonce_)
        .add_integrity(auth_key_)
        .add_fingerprint()
        .build();
    std::error_code ec;
    socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
}

void TurnClient::close() {
    std::error_code ec;
    refresh_timer_.cancel();
    if (!allocated_) return;

    auto msg = StunBuilder(TURN_REFRESH_REQUEST)
        .add_lifetime(0)  // Deallocation
        .add_username(cfg_.username)
        .add_realm(realm_)
        .add_nonce(nonce_)
        .add_integrity(auth_key_)
        .add_fingerprint()
        .build();

    socket_.send_to(asio::buffer(msg), server_ep_, 0, ec);
    allocated_ = false;
}

void TurnClient::schedule_refresh() {
    refresh_timer_.expires_after(std::chrono::seconds(lifetime_ / 2));
    refresh_timer_.async_wait(
        [weak_self = weak_from_this()](const std::error_code& ec) {
        auto self = weak_self.lock();
        if (!self) return;
        if (!ec && self->allocated_) {
            self->refresh();
            self->schedule_refresh();
        }
    });
}

MappedAddress TurnClient::relayed_address() const {
    return relayed_;
}

} // namespace gn::link::ice
