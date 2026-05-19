// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/turn.cpp
///
/// I/O routes through a `gn::sdk::LinkCarrier` (UDP) over a single
/// pre-allocated conn id (`server_cid_`) that the owning IceSession
/// reserves at construction. Outbound sends call `carrier_->send`;
/// inbound bytes are pushed in via `on_inbound` from the session's
/// per-cid dispatcher.

#include "turn.hpp"

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

bool encode_stream_frame(std::span<const std::uint8_t> payload,
                          std::vector<std::uint8_t>& out) {
    /// 16-bit length field caps each STUN message at 65 535 bytes on
    /// a TCP transport. STUN headers + attributes fit comfortably
    /// (the wire-protocol cap is well below this) but a malformed
    /// caller-side oversize is rejected here so the framing path
    /// never silently truncates.
    if (payload.size() > 0xFFFFu) return false;
    out.reserve(out.size() + 2 + payload.size());
    out.push_back(static_cast<std::uint8_t>(payload.size() >> 8));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xFFu));
    out.insert(out.end(), payload.begin(), payload.end());
    return true;
}

bool try_take_stream_frame(std::vector<std::uint8_t>& buffer,
                            std::vector<std::uint8_t>& out) {
    if (buffer.size() < 2) return false;
    const std::size_t msg_len =
        (static_cast<std::size_t>(buffer[0]) << 8)
        | static_cast<std::size_t>(buffer[1]);
    if (buffer.size() < 2 + msg_len) return false;
    out.assign(buffer.begin() + 2, buffer.begin() + 2 + msg_len);
    buffer.erase(buffer.begin(), buffer.begin() + 2 + msg_len);
    return true;
}

TurnClient::TurnClient(asio::io_context& io,
                         gn::sdk::LinkCarrier* carrier,
                         gn_conn_id_t server_cid,
                         const TurnConfig& cfg,
                         TurnDataCallback data_cb,
                         TurnAllocatedCallback alloc_cb)
    : io_(io), carrier_(carrier), server_cid_(server_cid),
      cfg_(cfg), data_cb_(std::move(data_cb)),
      alloc_cb_(std::move(alloc_cb)),
      refresh_timer_(io) {}

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

void TurnClient::send_to_server(std::span<const std::uint8_t> bytes) noexcept {
    if (!carrier_ || server_cid_ == 0) return;
    /// Both TCP-direct and TLS-over-TCP transports use the same
    /// 2-byte length-prefix framing (RFC 5389 §7.2.2 / RFC 4571).
    /// The TLS plugin wraps record-layer encryption around the
    /// framed bytes transparently — TurnClient sees an opaque
    /// ordered byte stream either way.
    const bool stream_framing = cfg_.tcp_transport || cfg_.tls_transport;
    if (stream_framing) {
        std::vector<std::uint8_t> framed;
        if (encode_stream_frame(bytes, framed)) {
            (void)carrier_->send(server_cid_, framed);
        }
        return;
    }
    (void)carrier_->send(server_cid_, bytes);
}

bool TurnClient::allocate() {
    if (cfg_.server.empty()) return false;
    if (!carrier_ || server_cid_ == 0) return false;

    /// Speculative unauthenticated request. RFC 5766 §6.2 says the
    /// server replies with 401 carrying realm/nonce; we then retry
    /// with `MESSAGE-INTEGRITY` from `compute_auth_key`. The
    /// REQUESTED-TRANSPORT attribute carries the IANA transport
    /// number — UDP (17) per RFC 5766, TCP (6) per RFC 6062.
    auto msg = StunBuilder(TURN_ALLOCATE_REQUEST)
        .add_requested_transport(cfg_.requested_transport)
        .build();
    send_to_server(msg);
    return true;
}

void TurnClient::on_inbound(std::span<const uint8_t> bytes) {
    /// Stream-mode transport (plain TCP or TLS-over-TCP): both
    /// deliver arbitrary-sized chunks from the carrier. Accumulate
    /// into `rx_buffer_` and extract complete length-prefixed
    /// messages whenever we have enough bytes. UDP transport
    /// delivers whole datagrams in a single callback; no reassembly
    /// needed.
    const bool stream_framing = cfg_.tcp_transport || cfg_.tls_transport;
    if (stream_framing) {
        rx_buffer_.insert(rx_buffer_.end(), bytes.begin(), bytes.end());
        std::vector<std::uint8_t> frame;
        while (try_take_stream_frame(rx_buffer_, frame)) {
            dispatch_inbound_message(frame);
        }
        return;
    }
    dispatch_inbound_message(bytes);
}

void TurnClient::dispatch_inbound_message(std::span<const std::uint8_t> bytes) {
    /// ChannelData frames coexist with STUN/TURN messages on the same
    /// transport — demux on the first byte's top nibble (RFC 5766
    /// §11.5). ChannelData has 0x4-0x7 in the top nibble; STUN is
    /// 0x0-0x3. The check rejects ambiguous buffers without parsing.
    if (is_channel_data(bytes)) {
        handle_channel_data(bytes);
        return;
    }
    auto parsed = parse_stun(bytes);
    if (!parsed) return;

    if (parsed->msg_type == TURN_ALLOCATE_ERROR) {
        if (parsed->error_code == 401 || parsed->error_code == 438) {
            // Need auth or stale nonce
            if (parsed->realm) realm_ = *parsed->realm;
            if (parsed->nonce) nonce_ = *parsed->nonce;
            compute_auth_key();

            // Retry with credentials
            auto msg = StunBuilder(TURN_ALLOCATE_REQUEST)
                .add_requested_transport(cfg_.requested_transport)
                .add_username(cfg_.username)
                .add_realm(realm_)
                .add_nonce(nonce_)
                .add_integrity(auth_key_)
                .add_fingerprint()
                .build();
            send_to_server(msg);
        }
    } else if (parsed->msg_type == TURN_ALLOCATE_RESPONSE) {
        handle_allocate_response(*parsed);
    } else if (parsed->msg_type == TURN_DATA_INDICATION) {
        handle_data_indication(*parsed);
    } else if (parsed->msg_type == TURN_CHANNEL_BIND_RESPONSE) {
        /// Successful ChannelBind — the channel is already live in
        /// `peer_to_channel_` from `bind_channel`. Nothing to do here
        /// besides accept the response; future sends on that peer will
        /// take the ChannelData fast path automatically.
    } else if (parsed->msg_type == TURN_CHANNEL_BIND_ERROR) {
        /// Bind error — we leave the optimistic mapping in place
        /// because (a) we don't track pending binds by txn_id, and
        /// (b) Send-Indication is a safe fallback if the channel
        /// turns out unusable. Real-world bind failures are rare
        /// (channel space exhaustion or stale nonce); v1 trades
        /// strict bookkeeping for simpler code.
    } else if (parsed->msg_type == TURN_CONNECTION_ATTEMPT_INDICATION) {
        handle_connection_attempt(*parsed);
    } else if (parsed->msg_type == TURN_CONNECT_RESPONSE) {
        handle_connect_response(*parsed);
    }
}

void TurnClient::handle_channel_data(std::span<const uint8_t> bytes) {
    auto frame = parse_channel_data(bytes);
    if (!frame) return;
    std::string peer_ip;
    uint16_t    peer_port = 0;
    {
        std::lock_guard lk(mu_);
        auto it = channel_to_peer_.find(frame->channel);
        if (it == channel_to_peer_.end()) return;
        peer_ip   = it->second.first;
        peer_port = it->second.second;
    }
    if (data_cb_) data_cb_(peer_ip, peer_port, frame->payload);
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
    /// Fast path: if the peer has a bound channel, send ChannelData
    /// (4-byte header) instead of a Send-Indication (~36 bytes plus
    /// the TURN STUN framing). Channels live for 10 min and are
    /// rebound by `schedule_refresh`; falling back to
    /// Send-Indication if the channel hasn't been bound yet keeps
    /// the first packet flowing while the bind round-trip races.
    uint16_t channel = 0;
    const auto key = peer_ip + ":" + std::to_string(peer_port);
    {
        std::lock_guard lk(mu_);
        auto it = peer_to_channel_.find(key);
        if (it != peer_to_channel_.end()) channel = it->second;
    }
    if (channel != 0) {
        auto frame = encode_channel_data(channel, data);
        send_to_server(frame);
        return;
    }
    auto msg = StunBuilder(TURN_SEND_INDICATION)
        .add_xor_peer_address(peer_ip, peer_port)
        .add_data(data)
        .build();
    send_to_server(msg);
}

void TurnClient::bind_channel(const std::string& peer_ip,
                                uint16_t peer_port) {
    /// RFC 6062 §4.3: CHANNEL-BIND is not used on TCP allocations.
    /// Drop the call before any state mutates so the session layer
    /// can call bind_channel unconditionally on every peer without
    /// special-casing the transport.
    if (cfg_.requested_transport == REQUESTED_TRANSPORT_TCP) return;
    const auto key = peer_ip + ":" + std::to_string(peer_port);
    uint16_t channel = 0;
    {
        std::lock_guard lk(mu_);
        if (auto it = peer_to_channel_.find(key);
            it != peer_to_channel_.end()) {
            return;  /// already bound — idempotent
        }
        channel = next_channel_++;
        if (channel > TURN_CHANNEL_NUMBER_MAX) {
            /// Channel space exhaustion is extremely unlikely
            /// (16383 channels per allocation) but we still bound
            /// it — fall back to Send-Indication for new peers.
            return;
        }
        peer_to_channel_[key]      = channel;
        channel_to_peer_[channel]  = {peer_ip, peer_port};
        permissions_.insert(peer_ip);
    }

    auto msg = StunBuilder(TURN_CHANNEL_BIND_REQUEST)
        .add_channel_number(channel)
        .add_xor_peer_address(peer_ip, peer_port)
        .add_username(cfg_.username)
        .add_realm(realm_)
        .add_nonce(nonce_)
        .add_integrity(auth_key_)
        .add_fingerprint()
        .build();
    send_to_server(msg);
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
    send_to_server(msg);
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
    send_to_server(msg);
}

void TurnClient::close() {
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

    send_to_server(msg);
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

// ── RFC 6062 TCP-allocation data flow ──────────────────────────────

void TurnClient::set_connection_attempt_callback(
    TurnConnectionAttemptCallback cb) {
    conn_attempt_cb_ = std::move(cb);
}

void TurnClient::set_data_connection_callback(
    TurnDataConnectionCallback cb) {
    data_conn_cb_ = std::move(cb);
}

void TurnClient::set_data_carrier_factory(TurnDataCarrierFactory factory) {
    data_carrier_factory_ = std::move(factory);
}

void TurnClient::connect_to_peer(const std::string& peer_ip,
                                   uint16_t peer_port) {
    /// Connect is only legal on TCP allocations. The session layer
    /// guards the caller side; this gate keeps a misconfigured call
    /// from putting a stray Connect request on the wire.
    if (cfg_.requested_transport != REQUESTED_TRANSPORT_TCP) return;

    /// Build the Connect request first so we have its transaction
    /// id to key the pending-connect map. The server reply (RFC
    /// 6062 §4.4) only carries CONNECTION-ID; the peer address is
    /// re-paired from the txn id on this side.
    StunBuilder b(TURN_CONNECT_REQUEST);
    b.add_xor_peer_address(peer_ip, peer_port);
    if (!realm_.empty()) {
        b.add_username(cfg_.username)
         .add_realm(realm_)
         .add_nonce(nonce_)
         .add_integrity(auth_key_)
         .add_fingerprint();
    }
    auto msg = b.build();

    /// Bytes 8..20 of the STUN header carry the 12-byte txn id.
    /// Pull them out without re-parsing — the layout is fixed.
    std::string txn_key;
    if (msg.size() >= 20) {
        txn_key.assign(reinterpret_cast<const char*>(msg.data() + 8), 12);
    }
    {
        std::lock_guard lk(mu_);
        pending_connects_[txn_key] = {peer_ip, peer_port};
    }
    send_to_server(msg);
}

void TurnClient::handle_connect_response(const StunMessage& msg) {
    if (!msg.connection_id) return;
    PendingConnect pc{};
    {
        std::lock_guard lk(mu_);
        std::string key(reinterpret_cast<const char*>(msg.txn_id.data()), 12);
        auto it = pending_connects_.find(key);
        if (it == pending_connects_.end()) return;
        pc = it->second;
        pending_connects_.erase(it);
    }
    open_data_connection(*msg.connection_id, pc.peer_ip, pc.peer_port);
}

void TurnClient::handle_connection_attempt(const StunMessage& msg) {
    /// RFC 6062 §4.4: server-pushed indication that a remote peer
    /// has connected to the relay. The client opens a fresh TCP
    /// data carrier to the TURN server and binds it to the
    /// announced CONNECTION-ID. The peer address is informational
    /// for the session-side callback — the server already has the
    /// connection state.
    if (!msg.connection_id || !msg.xor_peer) return;
    const auto cid = *msg.connection_id;
    const auto& peer = *msg.xor_peer;
    if (conn_attempt_cb_) {
        conn_attempt_cb_(peer.ip, peer.port, cid);
    }
    open_data_connection(cid, peer.ip, peer.port);
}

void TurnClient::open_data_connection(std::uint32_t connection_id,
                                         const std::string& peer_ip,
                                         uint16_t peer_port) {
    if (!data_carrier_factory_) return;
    /// Session-side factory opens the TCP carrier conn AND
    /// registers a per-cid inbound subscription that funnels bytes
    /// back through `on_data_connection_inbound`. Returning the cid
    /// hands ownership of the lifetime back here.
    gn_conn_id_t cid = data_carrier_factory_();
    if (cid == 0) return;

    {
        std::lock_guard lk(mu_);
        pending_binds_[cid] = {connection_id, peer_ip, peer_port};
    }

    /// Send ConnectionBind on the new data carrier. After success
    /// the carrier transitions to raw byte-stream mode and STUN
    /// framing no longer applies on its inbound stream.
    StunBuilder b(TURN_CONNECTION_BIND_REQUEST);
    b.add_connection_id(connection_id);
    if (!realm_.empty()) {
        b.add_username(cfg_.username)
         .add_realm(realm_)
         .add_nonce(nonce_)
         .add_integrity(auth_key_)
         .add_fingerprint();
    }
    auto bind_msg = b.build();
    send_framed_on_data_cid(cid, bind_msg);
}

void TurnClient::send_framed_on_data_cid(
    gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
    if (!carrier_ || cid == 0) return;
    /// Data connections always ride TCP (RFC 6062), so STUN
    /// framing applies — same length-prefix as the control channel.
    std::vector<std::uint8_t> framed;
    if (encode_stream_frame(bytes, framed)) {
        (void)carrier_->send(cid, framed);
    }
}

void TurnClient::on_data_connection_inbound(
    gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
    /// Determine whether the data connection is still in the
    /// ConnectionBind handshake (length-prefixed STUN) or already
    /// transitioned to raw bytes. A bound entry in `bound_peers_`
    /// indicates the latter.
    std::string peer_ip;
    uint16_t    peer_port = 0;
    bool bound = false;
    {
        std::lock_guard lk(mu_);
        auto it = bound_peers_.find(cid);
        if (it != bound_peers_.end()) {
            bound = true;
            peer_ip   = it->second.first;
            peer_port = it->second.second;
        }
    }
    if (bound) {
        if (data_cb_) {
            data_cb_(peer_ip, peer_port, bytes);
        }
        return;
    }

    /// Pre-bind state: STUN-framed response stream. The accumulated
    /// rx buffer lives in `data_conn_rx_buffers_[cid]` until the
    /// carrier transitions to bound, at which point
    /// `dispatch_data_conn_message` removes it from the map. The
    /// dispatch sits beneath `try_take_stream_frame` on the same
    /// stack, so the buffer is moved out and drained from a local
    /// — any tail is moved back only while the carrier is still
    /// pre-bind, since bound carriers route raw bytes through
    /// `data_cb_` and don't consult this map.
    std::vector<std::uint8_t> buf;
    {
        std::lock_guard lk(mu_);
        auto it = data_conn_rx_buffers_.find(cid);
        if (it != data_conn_rx_buffers_.end()) {
            buf = std::move(it->second);
            data_conn_rx_buffers_.erase(it);
        }
    }
    buf.insert(buf.end(), bytes.begin(), bytes.end());
    std::vector<std::uint8_t> frame;
    while (try_take_stream_frame(buf, frame)) {
        dispatch_data_conn_message(cid, frame);
    }
    if (!buf.empty()) {
        std::lock_guard lk(mu_);
        if (bound_peers_.find(cid) == bound_peers_.end()) {
            data_conn_rx_buffers_[cid] = std::move(buf);
        }
    }
}

void TurnClient::dispatch_data_conn_message(
    gn_conn_id_t cid, std::span<const std::uint8_t> bytes) {
    auto parsed = parse_stun(bytes);
    if (!parsed) return;
    if (parsed->msg_type == TURN_CONNECTION_BIND_RESPONSE) {
        PendingBind pb{};
        bool have_pending = false;
        {
            std::lock_guard lk(mu_);
            auto it = pending_binds_.find(cid);
            if (it != pending_binds_.end()) {
                pb = it->second;
                pending_binds_.erase(it);
                data_connections_[pb.connection_id] = cid;
                bound_peers_[cid] = {pb.peer_ip, pb.peer_port};
                data_conn_rx_buffers_.erase(cid);
                have_pending = true;
            }
        }
        if (have_pending && data_conn_cb_) {
            data_conn_cb_(pb.connection_id, cid, pb.peer_ip, pb.peer_port);
        }
        return;
    }
    if (parsed->msg_type == TURN_CONNECTION_BIND_ERROR) {
        /// Bind failed — drop the pending entry. The carrier conn
        /// is left to the session-side factory caller to tear down.
        std::lock_guard lk(mu_);
        pending_binds_.erase(cid);
        data_conn_rx_buffers_.erase(cid);
    }
}

} // namespace gn::link::ice
