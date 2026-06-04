// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/stun.cpp

#include "stun.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

namespace gn::link::ice {

TransactionId generate_txn_id() {
    TransactionId id;
    randombytes_buf(id.data(), id.size());
    return id;
}

// ── Endian helpers ──────────────────────────────────────────────────────────

static uint16_t read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static uint32_t read32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           p[3];
}

static void write16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

static void write32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

static void write64(uint8_t* p, uint64_t v) {
    write32(p, static_cast<uint32_t>(v >> 32));
    write32(p + 4, static_cast<uint32_t>(v));
}

// ── XOR-MAPPED-ADDRESS encode/decode ────────────────────────────────────────

static std::vector<uint8_t> encode_xor_addr(const std::string& ip, uint16_t port,
                                              const TransactionId& txn) {
    std::vector<uint8_t> buf;
    buf.push_back(0); // reserved

    uint16_t xport = port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        buf.push_back(0x01); // IPv4
        uint8_t p[2]; write16(p, xport);
        buf.insert(buf.end(), p, p + 2);
        uint32_t xaddr = ntohl(addr4.s_addr) ^ STUN_MAGIC_COOKIE;
        uint8_t a[4]; write32(a, xaddr);
        buf.insert(buf.end(), a, a + 4);
    } else if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        buf.push_back(0x02); // IPv6
        uint8_t p[2]; write16(p, xport);
        buf.insert(buf.end(), p, p + 2);
        // XOR with magic cookie + transaction ID
        uint8_t xor_key[16];
        write32(xor_key, STUN_MAGIC_COOKIE);
        std::memcpy(xor_key + 4, txn.data(), 12);
        for (int i = 0; i < 16; ++i)
            buf.push_back(addr6.s6_addr[i] ^ xor_key[i]);
    }
    return buf;
}

static std::optional<MappedAddress> decode_xor_addr(const uint8_t* data, size_t len,
                                                      const TransactionId& txn) {
    if (len < 4) return std::nullopt;
    uint8_t family = data[1];
    uint16_t xport = read16(data + 2);
    uint16_t port = xport ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);

    MappedAddress addr;
    addr.port = port;

    if (family == 0x01 && len >= 8) { // IPv4
        uint32_t xaddr = read32(data + 4);
        uint32_t real = xaddr ^ STUN_MAGIC_COOKIE;
        struct in_addr in;
        in.s_addr = htonl(real);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in, buf, sizeof(buf));
        addr.ip = buf;
    } else if (family == 0x02 && len >= 20) { // IPv6
        uint8_t xor_key[16];
        write32(xor_key, STUN_MAGIC_COOKIE);
        std::memcpy(xor_key + 4, txn.data(), 12);
        struct in6_addr in6;
        for (int i = 0; i < 16; ++i)
            in6.s6_addr[i] = data[4 + i] ^ xor_key[i];
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
        addr.ip = buf;
    } else {
        return std::nullopt;
    }
    return addr;
}

// ── CRC32 for FINGERPRINT ──────────────────────────────────────────────────

static uint32_t stun_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return crc ^ 0xFFFFFFFF;
}

// ── StunBuilder ─────────────────────────────────────────────────────────────

StunBuilder::StunBuilder(uint16_t msg_type)
    : msg_type_(msg_type), txn_id_(generate_txn_id()) {}

StunBuilder& StunBuilder::set_txn_id(const TransactionId& id) {
    txn_id_ = id;
    return *this;
}

void StunBuilder::add_attr(uint16_t type, std::span<const uint8_t> value) {
    uint8_t hdr[4];
    write16(hdr, type);
    write16(hdr + 2, static_cast<uint16_t>(value.size()));
    attrs_.insert(attrs_.end(), hdr, hdr + 4);
    attrs_.insert(attrs_.end(), value.begin(), value.end());
    // Pad to 4-byte boundary
    while (attrs_.size() % 4 != 0) attrs_.push_back(0);
}

void StunBuilder::add_attr_u32(uint16_t type, uint32_t value) {
    uint8_t buf[4];
    write32(buf, value);
    add_attr(type, buf);
}

void StunBuilder::add_attr_u64(uint16_t type, uint64_t value) {
    uint8_t buf[8];
    write64(buf, value);
    add_attr(type, buf);
}

StunBuilder& StunBuilder::add_username(const std::string& username) {
    add_attr(STUN_ATTR_USERNAME,
        std::span(reinterpret_cast<const uint8_t*>(username.data()), username.size()));
    return *this;
}

StunBuilder& StunBuilder::add_priority(uint32_t priority) {
    add_attr_u32(STUN_ATTR_PRIORITY, priority);
    return *this;
}

StunBuilder& StunBuilder::add_use_candidate() {
    add_attr(STUN_ATTR_USE_CANDIDATE, {});
    return *this;
}

StunBuilder& StunBuilder::add_ice_controlling(uint64_t tiebreaker) {
    add_attr_u64(STUN_ATTR_ICE_CONTROLLING, tiebreaker);
    return *this;
}

StunBuilder& StunBuilder::add_ice_controlled(uint64_t tiebreaker) {
    add_attr_u64(STUN_ATTR_ICE_CONTROLLED, tiebreaker);
    return *this;
}

StunBuilder& StunBuilder::add_xor_peer_address(const std::string& ip, uint16_t port) {
    auto enc = encode_xor_addr(ip, port, txn_id_);
    add_attr(TURN_ATTR_XOR_PEER_ADDRESS, enc);
    return *this;
}

StunBuilder& StunBuilder::add_xor_relayed_address(const std::string& ip,
                                                    uint16_t port) {
    auto enc = encode_xor_addr(ip, port, txn_id_);
    add_attr(TURN_ATTR_XOR_RELAYED_ADDRESS, enc);
    return *this;
}

StunBuilder& StunBuilder::add_error_code(uint16_t code,
                                          const std::string& reason) {
    /// RFC 5389 §15.6 ERROR-CODE layout: 2 bytes reserved (zero),
    /// 1 byte class (hundreds digit), 1 byte number (modulo 100),
    /// followed by UTF-8 reason phrase.
    std::vector<uint8_t> buf;
    buf.reserve(4 + reason.size());
    buf.push_back(0);
    buf.push_back(0);
    buf.push_back(static_cast<uint8_t>(code / 100));
    buf.push_back(static_cast<uint8_t>(code % 100));
    buf.insert(buf.end(), reason.begin(), reason.end());
    add_attr(STUN_ATTR_ERROR_CODE, buf);
    return *this;
}

StunBuilder& StunBuilder::add_data(std::span<const uint8_t> data) {
    add_attr(TURN_ATTR_DATA, data);
    return *this;
}

StunBuilder& StunBuilder::add_channel_number(uint16_t channel) {
    /// CHANNEL-NUMBER attribute (RFC 5766 §14.1): 16-bit channel
    /// followed by 16-bit RFFU (Reserved For Future Use; zeros).
    uint8_t buf[4] = {
        static_cast<uint8_t>(channel >> 8),
        static_cast<uint8_t>(channel & 0xFF),
        0, 0
    };
    add_attr(TURN_ATTR_CHANNEL_NUMBER, buf);
    return *this;
}

StunBuilder& StunBuilder::add_requested_transport(uint8_t proto) {
    uint8_t buf[4] = {proto, 0, 0, 0};
    add_attr(TURN_ATTR_REQUESTED_TRANSPORT, buf);
    return *this;
}

StunBuilder& StunBuilder::add_lifetime(uint32_t seconds) {
    add_attr_u32(TURN_ATTR_LIFETIME, seconds);
    return *this;
}

StunBuilder& StunBuilder::add_realm(const std::string& realm) {
    add_attr(TURN_ATTR_REALM,
        std::span(reinterpret_cast<const uint8_t*>(realm.data()), realm.size()));
    return *this;
}

StunBuilder& StunBuilder::add_nonce(const std::string& nonce) {
    add_attr(TURN_ATTR_NONCE,
        std::span(reinterpret_cast<const uint8_t*>(nonce.data()), nonce.size()));
    return *this;
}

StunBuilder& StunBuilder::add_connection_id(uint32_t connection_id) {
    add_attr_u32(TURN_ATTR_CONNECTION_ID, connection_id);
    return *this;
}

StunBuilder& StunBuilder::add_integrity(const std::string& key) {
    // Build temporary header to compute HMAC over
    // Length includes the MESSAGE-INTEGRITY attribute (24 bytes: 4 hdr + 20 HMAC)
    std::vector<uint8_t> msg(20 + attrs_.size());
    write16(msg.data(), msg_type_);
    write16(msg.data() + 2, static_cast<uint16_t>(attrs_.size() + 24));
    write32(msg.data() + 4, STUN_MAGIC_COOKIE);
    std::memcpy(msg.data() + 8, txn_id_.data(), 12);
    if (!attrs_.empty()) {
        std::memcpy(msg.data() + 20, attrs_.data(), attrs_.size());
    }

    unsigned int hmac_len = 20;
    uint8_t hmac[20];
    HMAC(EVP_sha1(),
         key.data(), static_cast<int>(key.size()),
         msg.data(), msg.size(),
         hmac, &hmac_len);

    add_attr(STUN_ATTR_MESSAGE_INTEGRITY, std::span(hmac, 20));
    return *this;
}

StunBuilder& StunBuilder::add_fingerprint() {
    // Build temporary message up to this point
    std::vector<uint8_t> msg(20 + attrs_.size());
    write16(msg.data(), msg_type_);
    write16(msg.data() + 2, static_cast<uint16_t>(attrs_.size() + 8)); // +8 for fingerprint attr
    write32(msg.data() + 4, STUN_MAGIC_COOKIE);
    std::memcpy(msg.data() + 8, txn_id_.data(), 12);
    if (!attrs_.empty()) {
        std::memcpy(msg.data() + 20, attrs_.data(), attrs_.size());
    }

    uint32_t crc = stun_crc32(msg.data(), msg.size()) ^ 0x5354554E; // XOR with "STUN"
    add_attr_u32(STUN_ATTR_FINGERPRINT, crc);
    return *this;
}

StunBuilder& StunBuilder::add_padding_to(std::size_t target_total_bytes) {
    /// Current wire size = 20-byte header + accumulated attrs.
    const std::size_t cur = 20 + attrs_.size();
    if (target_total_bytes <= cur) return *this;

    /// One TLV slot = 4-byte header + value (rounded up to a 4-byte
    /// boundary). Minimum extra cost is 4 bytes (header alone, zero
    /// value); the gap between `cur` and `target_total_bytes` must be
    /// at least 4 for any padding to fit, and the leftover after the
    /// header is the value payload. STUN attribute lengths are
    /// 4-byte aligned on the wire, so the achievable target is the
    /// caller's value rounded down to the nearest multiple of 4.
    if (target_total_bytes - cur < 4) return *this;
    const std::size_t aligned = target_total_bytes & ~static_cast<std::size_t>(0x3);
    if (aligned <= cur) return *this;
    const std::size_t value_len = aligned - cur - 4;
    /// STUN attribute length field is 16 bits — cap accordingly.
    if (value_len > 0xFFFFu) return *this;
    std::vector<uint8_t> filler(value_len, 0);
    add_attr(STUN_ATTR_UNKNOWN_ATTRIBUTES, filler);
    return *this;
}

std::vector<uint8_t> StunBuilder::build() {
    std::vector<uint8_t> msg(20 + attrs_.size());
    write16(msg.data(), msg_type_);
    write16(msg.data() + 2, static_cast<uint16_t>(attrs_.size()));
    write32(msg.data() + 4, STUN_MAGIC_COOKIE);
    std::memcpy(msg.data() + 8, txn_id_.data(), 12);
    /// `vector::data()` is allowed to return null when the vector is
    /// empty, and `memcpy(_, null, 0)` triggers UB even though the
    /// length is zero. Guard the call so a header-only STUN message
    /// (binding-request without ICE attributes) round-trips cleanly
    /// under UBSan.
    if (!attrs_.empty()) {
        std::memcpy(msg.data() + 20, attrs_.data(), attrs_.size());
    }
    return msg;
}

// ── StunParser ──────────────────────────────────────────────────────────────

std::optional<StunMessage> parse_stun(std::span<const uint8_t> data) {
    if (data.size() < 20) return std::nullopt;

    uint16_t msg_type = read16(data.data());
    uint16_t msg_len  = read16(data.data() + 2);
    uint32_t cookie   = read32(data.data() + 4);

    if (cookie != STUN_MAGIC_COOKIE) return std::nullopt;
    if (20u + msg_len > data.size()) return std::nullopt;

    StunMessage msg;
    msg.msg_type = msg_type;
    std::memcpy(msg.txn_id.data(), data.data() + 8, 12);

    size_t offset = 20;
    while (offset + 4 <= 20u + msg_len) {
        uint16_t attr_type = read16(data.data() + offset);
        uint16_t attr_len  = read16(data.data() + offset + 2);
        size_t attr_start = offset + 4;

        if (attr_start + attr_len > data.size()) break;

        auto attr_data = data.data() + attr_start;

        switch (attr_type) {
        case STUN_ATTR_XOR_MAPPED_ADDRESS:
            msg.xor_mapped = decode_xor_addr(attr_data, attr_len, msg.txn_id);
            break;
        case TURN_ATTR_XOR_PEER_ADDRESS:
            msg.xor_peer = decode_xor_addr(attr_data, attr_len, msg.txn_id);
            break;
        case TURN_ATTR_XOR_RELAYED_ADDRESS:
            msg.xor_relayed = decode_xor_addr(attr_data, attr_len, msg.txn_id);
            break;
        case STUN_ATTR_PRIORITY:
            if (attr_len >= 4) msg.priority = read32(attr_data);
            break;
        case TURN_ATTR_LIFETIME:
            if (attr_len >= 4) msg.lifetime = read32(attr_data);
            break;
        case STUN_ATTR_USE_CANDIDATE:
            msg.use_candidate = true;
            break;
        case STUN_ATTR_ICE_CONTROLLING:
            /// RFC 8445 §7.3.1.1 tie-breaker comparison requires the
            /// numeric value, not just attribute presence. Carry the
            /// 64-bit int verbatim — the FSM compares against its own
            /// tiebreaker to decide which side wins a role conflict.
            if (attr_len >= 8) {
                const uint64_t hi = read32(attr_data);
                const uint64_t lo = read32(attr_data + 4);
                msg.ice_controlling = (hi << 32) | lo;
            }
            break;
        case STUN_ATTR_ICE_CONTROLLED:
            if (attr_len >= 8) {
                const uint64_t hi = read32(attr_data);
                const uint64_t lo = read32(attr_data + 4);
                msg.ice_controlled = (hi << 32) | lo;
            }
            break;
        case STUN_ATTR_ERROR_CODE:
            if (attr_len >= 4) {
                uint16_t code = static_cast<uint16_t>(
                    static_cast<unsigned>(attr_data[2]) * 100u +
                    static_cast<unsigned>(attr_data[3]));
                msg.error_code = code;
            }
            break;
        case STUN_ATTR_USERNAME:
            msg.username = std::string(reinterpret_cast<const char*>(attr_data), attr_len);
            break;
        case TURN_ATTR_REALM:
            msg.realm = std::string(reinterpret_cast<const char*>(attr_data), attr_len);
            break;
        case TURN_ATTR_NONCE:
            msg.nonce = std::string(reinterpret_cast<const char*>(attr_data), attr_len);
            break;
        case TURN_ATTR_CONNECTION_ID:
            if (attr_len >= 4) msg.connection_id = read32(attr_data);
            break;
        case TURN_ATTR_DATA:
            msg.data.assign(attr_data, attr_data + attr_len);
            break;
        case STUN_ATTR_MESSAGE_INTEGRITY:
            msg.has_integrity = true;
            break;
        case STUN_ATTR_FINGERPRINT:
            msg.has_fingerprint = true;
            break;
        }

        // Advance to next attribute (4-byte aligned)
        offset = attr_start + attr_len;
        while (offset % 4 != 0) ++offset;
    }

    return msg;
}

bool verify_integrity(std::span<const uint8_t> raw, const std::string& key) {
    if (raw.size() < 44) return false; // 20 header + 24 integrity attr min

    // Find MESSAGE-INTEGRITY offset
    size_t mi_offset = 0;
    size_t offset = 20;
    uint16_t msg_len = read16(raw.data() + 2);
    while (offset + 4 <= 20u + msg_len) {
        uint16_t at = read16(raw.data() + offset);
        uint16_t al = read16(raw.data() + offset + 2);
        if (at == STUN_ATTR_MESSAGE_INTEGRITY) {
            mi_offset = offset;
            break;
        }
        offset += 4 + al;
        while (offset % 4 != 0) ++offset;
    }
    if (mi_offset == 0) return false;

    // Rewrite length to include up to MESSAGE-INTEGRITY
    // Temporarily set length
    std::vector<uint8_t> hdr(raw.begin(), raw.begin() + 20);
    write16(hdr.data() + 2, static_cast<uint16_t>(mi_offset - 20 + 24));

    std::vector<uint8_t> msg;
    msg.insert(msg.end(), hdr.begin(), hdr.end());
    msg.insert(msg.end(), raw.begin() + 20, raw.begin() + mi_offset);

    unsigned int hmac_len = 20;
    uint8_t computed[20];
    HMAC(EVP_sha1(),
         key.data(), static_cast<int>(key.size()),
         msg.data(), msg.size(),
         computed, &hmac_len);

    // Compare with stored HMAC (constant-time to prevent timing attacks)
    return sodium_memcmp(computed, raw.data() + mi_offset + 4, 20) == 0;
}

// ── ChannelData framing (RFC 5766 §11.4) ───────────────────────────────────

std::vector<uint8_t> encode_channel_data(uint16_t channel,
                                          std::span<const uint8_t> payload) {
    /// 4-byte header: 16-bit channel + 16-bit length. Wire is padded
    /// to a 4-byte boundary so receivers can scan a stream of frames
    /// without a separate length signal — the length field still
    /// reports the unpadded application byte count.
    const uint16_t len = static_cast<uint16_t>(payload.size());
    const std::size_t pad = (4 - (payload.size() & 3)) & 3;
    std::vector<uint8_t> out;
    out.reserve(4 + payload.size() + pad);
    out.push_back(static_cast<uint8_t>(channel >> 8));
    out.push_back(static_cast<uint8_t>(channel & 0xFF));
    out.push_back(static_cast<uint8_t>(len >> 8));
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.insert(out.end(), payload.begin(), payload.end());
    out.insert(out.end(), pad, 0);
    return out;
}

std::optional<ChannelDataView> parse_channel_data(
    std::span<const uint8_t> raw) {
    if (raw.size() < TURN_CHANNEL_DATA_HEADER_SIZE) return std::nullopt;
    const uint16_t channel =
        (static_cast<uint16_t>(raw[0]) << 8) | static_cast<uint16_t>(raw[1]);
    if (channel < TURN_CHANNEL_NUMBER_MIN
        || channel > TURN_CHANNEL_NUMBER_MAX) {
        return std::nullopt;
    }
    const std::size_t len =
        (static_cast<std::size_t>(raw[2]) << 8) | static_cast<std::size_t>(raw[3]);
    if (4 + len > raw.size()) return std::nullopt;
    return ChannelDataView{
        channel,
        raw.subspan(4, len),
    };
}

} // namespace gn::link::ice
