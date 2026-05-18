// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/stun.hpp
/// @brief  STUN message builder/parser per RFC 5389 with ICE extensions
///         and the TURN allocation slice from RFC 5766.
///
/// The builder is fluent (`add_*` returns `*this`) so call sites read
/// like the on-wire structure. Parser populates a flat
/// `StunMessage` with `optional<>` per attribute; absent attributes
/// are nullopt rather than zero-default to keep "missing" and "zero"
/// distinguishable at the call site.

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace gn::link::ice {

// ── STUN constants ──────────────────────────────────────────────────────────

constexpr uint16_t STUN_BINDING_REQUEST     = 0x0001;
constexpr uint16_t STUN_BINDING_INDICATION  = 0x0011;
constexpr uint16_t STUN_BINDING_RESPONSE    = 0x0101;
constexpr uint16_t STUN_BINDING_ERROR       = 0x0111;

constexpr uint32_t STUN_MAGIC_COOKIE        = 0x2112A442;

// STUN attributes
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS     = 0x0001;
constexpr uint16_t STUN_ATTR_USERNAME           = 0x0006;
constexpr uint16_t STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY  = 0x0008;
constexpr uint16_t STUN_ATTR_ERROR_CODE         = 0x0009;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t STUN_ATTR_PRIORITY           = 0x0024;
constexpr uint16_t STUN_ATTR_USE_CANDIDATE      = 0x0025;
constexpr uint16_t STUN_ATTR_ICE_CONTROLLING    = 0x802A;
constexpr uint16_t STUN_ATTR_ICE_CONTROLLED     = 0x8029;
constexpr uint16_t STUN_ATTR_FINGERPRINT        = 0x8028;

// TURN message types
constexpr uint16_t TURN_ALLOCATE_REQUEST    = 0x0003;
constexpr uint16_t TURN_ALLOCATE_RESPONSE   = 0x0103;
constexpr uint16_t TURN_ALLOCATE_ERROR      = 0x0113;
constexpr uint16_t TURN_REFRESH_REQUEST     = 0x0004;
constexpr uint16_t TURN_REFRESH_RESPONSE    = 0x0104;
constexpr uint16_t TURN_CREATE_PERM_REQUEST = 0x0008;
constexpr uint16_t TURN_CREATE_PERM_RESPONSE= 0x0108;
constexpr uint16_t TURN_SEND_INDICATION     = 0x0016;
constexpr uint16_t TURN_DATA_INDICATION     = 0x0017;
constexpr uint16_t TURN_CHANNEL_BIND_REQUEST  = 0x0009;
constexpr uint16_t TURN_CHANNEL_BIND_RESPONSE = 0x0109;
constexpr uint16_t TURN_CHANNEL_BIND_ERROR    = 0x0119;

/// ChannelData per RFC 5766 §11.4 — efficient binary framing for
/// data sent over a TURN-bound channel. First 2 bytes are the
/// channel number (0x4000-0x7FFF); next 2 bytes are payload length;
/// payload follows. Total minimum frame = 4 bytes. The first byte's
/// top nibble (0x4-0x7) lets receivers demux ChannelData vs STUN
/// messages (top nibble 0x0 / 0x1 for STUN methods).
constexpr uint16_t TURN_CHANNEL_NUMBER_MIN  = 0x4000;
constexpr uint16_t TURN_CHANNEL_NUMBER_MAX  = 0x7FFF;
constexpr std::size_t TURN_CHANNEL_DATA_HEADER_SIZE = 4;

// TURN attributes
constexpr uint16_t TURN_ATTR_CHANNEL_NUMBER      = 0x000C;
constexpr uint16_t TURN_ATTR_LIFETIME             = 0x000D;
constexpr uint16_t TURN_ATTR_XOR_PEER_ADDRESS     = 0x0012;
constexpr uint16_t TURN_ATTR_DATA                 = 0x0013;
constexpr uint16_t TURN_ATTR_XOR_RELAYED_ADDRESS  = 0x0016;
constexpr uint16_t TURN_ATTR_REQUESTED_TRANSPORT  = 0x0019;
constexpr uint16_t TURN_ATTR_REALM                = 0x0014;
constexpr uint16_t TURN_ATTR_NONCE                = 0x0015;

/// Parsed XOR-MAPPED-ADDRESS.
struct MappedAddress {
    std::string ip;
    uint16_t    port;
};

/// Transaction ID (12 bytes).
using TransactionId = std::array<uint8_t, 12>;

/// Generate a random transaction ID.
TransactionId generate_txn_id();

// ── STUN Builder ────────────────────────────────────────────────────────────

/// @brief STUN message builder — append attributes, finalise, integrity check.
class StunBuilder {
public:
    explicit StunBuilder(uint16_t msg_type);

    StunBuilder& set_txn_id(const TransactionId& id);
    StunBuilder& add_username(const std::string& username);
    StunBuilder& add_priority(uint32_t priority);
    StunBuilder& add_use_candidate();
    StunBuilder& add_ice_controlling(uint64_t tiebreaker);
    StunBuilder& add_ice_controlled(uint64_t tiebreaker);
    StunBuilder& add_xor_peer_address(const std::string& ip, uint16_t port);
    /// XOR-RELAYED-ADDRESS attribute (RFC 5766 §14.5). Same XOR
    /// encoding as XOR-PEER-ADDRESS but distinct attribute type.
    StunBuilder& add_xor_relayed_address(const std::string& ip, uint16_t port);
    /// ERROR-CODE attribute (RFC 5389 §15.6). @p code must be in
    /// [300, 699]; @p reason is at most 763 bytes UTF-8.
    StunBuilder& add_error_code(uint16_t code,
                                  const std::string& reason);
    StunBuilder& add_channel_number(uint16_t channel);
    StunBuilder& add_data(std::span<const uint8_t> data);
    StunBuilder& add_requested_transport(uint8_t proto);
    StunBuilder& add_lifetime(uint32_t seconds);
    StunBuilder& add_realm(const std::string& realm);
    StunBuilder& add_nonce(const std::string& nonce);

    /// Add MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC32).
    StunBuilder& add_integrity(const std::string& key);
    StunBuilder& add_fingerprint();

    /// Append an UNKNOWN-ATTRIBUTES filler so the finalised message
    /// reaches exactly @p target_total_bytes on the wire. The filler
    /// is a single STUN attribute of type 0x000A whose value is zero
    /// bytes; receivers ignore unknown comprehension-optional
    /// attributes per RFC 5389 §15. Used by the DPLPMTUD prober to
    /// size a binding-request to the candidate MTU under test.
    /// No-op when the current build is already at or above
    /// @p target_total_bytes.
    StunBuilder& add_padding_to(std::size_t target_total_bytes);

    std::vector<uint8_t> build();

private:
    uint16_t msg_type_;
    TransactionId txn_id_;
    std::vector<uint8_t> attrs_;

    void add_attr(uint16_t type, std::span<const uint8_t> value);
    void add_attr_u32(uint16_t type, uint32_t value);
    void add_attr_u64(uint16_t type, uint64_t value);
};

// ── STUN Parser ─────────────────────────────────────────────────────────────

/// @brief Parsed STUN message — type, transaction id, attribute view.
struct StunMessage {
    uint16_t      msg_type;
    TransactionId txn_id;

    std::optional<MappedAddress> xor_mapped;
    std::optional<MappedAddress> xor_peer;
    std::optional<MappedAddress> xor_relayed;
    std::optional<uint32_t>      priority;
    std::optional<uint32_t>      lifetime;
    std::optional<uint16_t>      error_code;
    std::optional<std::string>   username;
    std::optional<std::string>   realm;
    std::optional<std::string>   nonce;
    std::vector<uint8_t>         data;
    bool use_candidate = false;

    bool has_integrity  = false;
    bool has_fingerprint = false;
};

/// Parse a STUN/TURN message. Returns nullopt if invalid.
std::optional<StunMessage> parse_stun(std::span<const uint8_t> data);

/// Verify MESSAGE-INTEGRITY.
bool verify_integrity(std::span<const uint8_t> raw, const std::string& key);

/// Encode a ChannelData frame (RFC 5766 §11.4). Result has the
/// 4-byte header prepended to the payload. The wire is padded to
/// a 4-byte boundary per the RFC; padding bytes are not part of
/// the application payload.
std::vector<uint8_t> encode_channel_data(uint16_t channel,
                                          std::span<const uint8_t> payload);

/// Demux helper: a buffer starts with a ChannelData frame if the
/// top nibble of the first byte is in [0x4, 0x7]. STUN messages
/// have top nibble in [0x0, 0x3] for the method class encoding.
inline bool is_channel_data(std::span<const uint8_t> raw) noexcept {
    if (raw.size() < TURN_CHANNEL_DATA_HEADER_SIZE) return false;
    const uint8_t top = static_cast<uint8_t>(raw[0] & 0xC0);
    return top == 0x40;
}

/// Parsed ChannelData view — `channel` is the 16-bit channel number,
/// `payload` is the unpadded application bytes inside the frame.
/// Returns nullopt for malformed frames (short header, length
/// overflow).
struct ChannelDataView {
    uint16_t                    channel;
    std::span<const uint8_t>    payload;
};
std::optional<ChannelDataView> parse_channel_data(
    std::span<const uint8_t> raw);

} // namespace gn::link::ice
