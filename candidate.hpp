// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/candidate.hpp
/// @brief  ICE candidate types and binary wire format per RFC 8445 §5.1.2.
///
/// The wire form (`CandidateWire`, 24 bytes) and the signal envelope
/// (`IceSignalData`) are interop-stable: bridges to legacy or to a
/// future SDP-based signaling layer can copy bytes through this
/// header without re-parsing semantics.

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gn::link::ice {

enum class CandidateType : uint8_t {
    Host     = 0,
    Srflx    = 1,   // Server Reflexive
    Relay    = 2,   // TURN relay
    Prflx    = 3,   // Peer Reflexive (learned from check response)
    /// draft-ietf-mmusic-mdns-ice-candidates §3 — host candidate
    /// whose IP is hidden behind a multicast-DNS `.local` name.
    /// Treated as a Host-priority candidate for pair-priority
    /// computation; the IP is discovered by querying the
    /// hostname over multicast 224.0.0.251 / FF02::FB.
    HostMdns = 4
};

enum class AddressFamily : uint8_t {
    IPv4 = 1,
    IPv6 = 2
};

/// Transport flavour for an ICE candidate per RFC 6544. UDP is the
/// historical default; the three TCP variants govern who opens the
/// underlying TCP socket:
///   - `TcpActive`           — local end only initiates `connect()`,
///                              never accepts.
///   - `TcpPassive`          — local end only accepts, never connects.
///   - `TcpSimultaneousOpen` — both ends fire `connect()` toward each
///                              other inside a coordinated window so
///                              NAT/firewall state permits the
///                              simultaneous SYN exchange.
/// Encoded on the wire in the previously-reserved high nibble of the
/// `CandidateWire::type` byte so older peers that read only the low
/// nibble see the candidate as a vanilla UDP host / srflx / relay.
enum class TransportType : uint8_t {
    Udp                 = 0,
    TcpActive           = 1,
    TcpPassive          = 2,
    TcpSimultaneousOpen = 3
};

[[nodiscard]] constexpr bool transport_is_tcp(TransportType t) noexcept {
    return t == TransportType::TcpActive
        || t == TransportType::TcpPassive
        || t == TransportType::TcpSimultaneousOpen;
}

/// Maximum on-wire length of an mDNS hostname carried by a
/// HostMdns candidate. The draft uses RFC 4122 v4 UUIDs (36
/// characters, lowercase hex with dashes) plus the ".local"
/// suffix — 42 bytes total. The ceiling is generous enough to
/// allow alternative naming schemes (random base32 etc.) without
/// reserving an unreasonable chunk of the wire.
inline constexpr std::size_t kMaxMdnsHostnameLen = 64;

/// @brief ICE candidate (host/srflx/relay/host-mdns).
struct Candidate {
    CandidateType  type;
    AddressFamily  family;
    uint16_t       port;
    uint32_t       priority;
    std::array<uint8_t, 16> addr{};  // IPv4 in first 4 bytes, or full IPv6
    /// Populated only for HostMdns candidates. Non-mDNS candidates
    /// carry an empty hostname; the address-only fields above
    /// remain authoritative. Limited to `kMaxMdnsHostnameLen`
    /// bytes by the wire format.
    std::string    hostname{};
    /// RFC 6544 transport flavour. Defaults to UDP so existing call
    /// sites that build a Candidate via aggregate init continue to
    /// behave as plain-UDP. TCP-flavoured candidates carry the
    /// active / passive / simultaneous-open role here.
    TransportType  transport = TransportType::Udp;
    /// RFC 8445 §5.1.1.3 candidate foundation. Decimal string derived
    /// from `(type, base-address, server-address, transport)`. Two
    /// candidates share a foundation iff all four components match —
    /// the FSM groups pairs by `(local.foundation, remote.foundation)`
    /// so the Frozen → Waiting → In-Progress pacing in `run_next_check`
    /// can unfreeze sibling pairs once any pair of the group succeeds.
    /// Computed by `compute_foundation()` at gather time; the wire
    /// format does not carry the foundation field (peers compute their
    /// own foundations from the wire-recovered components).
    std::string    foundation{};

    std::string address_str() const;
    void set_address(const std::string& addr_str);
};

/// RFC 8445 §5.1.1.3 foundation hash. Stable FNV-1a-64 over the
/// `(type, base-address, server-address, transport)` quadruple, then
/// rendered as a decimal string so the value round-trips through any
/// text-based diagnostic surface. Two candidates with byte-identical
/// inputs always produce the same string; a change in any component
/// (different STUN server, different interface IP, different
/// transport) yields a different foundation. `base_address` is the
/// candidate's own interface IP for host candidates and the local
/// interface IP used to reach the STUN/TURN server for srflx/relay
/// candidates. `server_address` is empty for host candidates and the
/// peer-side STUN/TURN server IP for srflx/relay.
[[nodiscard]] inline std::string compute_foundation(
        CandidateType type,
        std::string_view base_address,
        std::string_view server_address,
        TransportType transport) noexcept {
    /// FNV-1a-64 keeps the implementation header-only and avoids a
    /// dependency on the (process-randomised) std::hash. Stability
    /// across processes matters for log diffing and cross-test
    /// comparison; std::hash is unspecified between runs.
    uint64_t h = 0xcbf29ce484222325ULL;
    constexpr uint64_t prime = 0x100000001b3ULL;
    auto mix = [&](uint8_t b) noexcept {
        h ^= static_cast<uint64_t>(b);
        h *= prime;
    };
    mix(static_cast<uint8_t>(type));
    mix(0xFF);
    for (char c : base_address) mix(static_cast<uint8_t>(c));
    mix(0xFF);
    for (char c : server_address) mix(static_cast<uint8_t>(c));
    mix(0xFF);
    mix(static_cast<uint8_t>(transport));
    return std::to_string(h);
}

/// Binary wire format for signaling (24 bytes per candidate).
#pragma pack(push, 1)
struct CandidateWire {
    uint8_t  type;       // CandidateType
    uint8_t  family;     // AddressFamily
    uint16_t port;
    uint32_t priority;
    uint8_t  addr[16];
};
#pragma pack(pop)
static_assert(sizeof(CandidateWire) == 24);

/// ICE signaling packet (binary, replaces SDP).
#pragma pack(push, 1)
struct IceSignalData {
    char     ufrag[8];
    char     pwd[32];
    uint32_t candidate_count;
};
#pragma pack(pop)
static_assert(sizeof(IceSignalData) == 44);

constexpr uint8_t ICE_SIGNAL_OFFER  = 0;
constexpr uint8_t ICE_SIGNAL_ANSWER = 1;
/// RFC 8838 §10 end-of-candidates indication. A signaling sender
/// emits OFFER_EOC / ANSWER_EOC instead of plain OFFER / ANSWER on
/// the FINAL trickle batch to tell the receiver "no more candidates
/// will arrive on my side". The receiver can then fail the
/// connection faster once its check list is exhausted with no
/// valid pair — without EOC the session has to wait the full
/// `session_timeout_s` ceiling before declaring failure. EOC
/// variants are wire-identical to their non-EOC counterparts;
/// older peers that don't know the kind simply reject the
/// envelope and the sender falls back to plain OFFER / ANSWER on
/// the next batch.
constexpr uint8_t ICE_SIGNAL_OFFER_EOC  = 2;
constexpr uint8_t ICE_SIGNAL_ANSWER_EOC = 3;

/// Wire-level signal flag bits packed into the upper 16 bits of
/// `IceSignalData::candidate_count`. The low 16 bits remain the
/// candidate array length; with `MAX_ICE_CANDIDATES = 256` this is
/// always representable. Older peers that never set flags emit
/// `candidate_count` < 256, so a new receiver simply masks the
/// upper bits and reads zero. New senders that set any flag emit
/// `candidate_count > 65535` on the wire; older receivers reject
/// the signal as malformed and the sender must downgrade (lite-mode
/// and symmetric peers learn this through configuration, not
/// through the wire).
inline constexpr uint32_t ICE_SIGNAL_FLAG_MASK   = 0xFFFF0000u;
inline constexpr uint32_t ICE_SIGNAL_COUNT_MASK  = 0x0000FFFFu;
/// RFC 8445 §2.7 lite agent. The sender will never initiate
/// connectivity checks; the receiver must take the controller role
/// or the FSM cannot progress.
inline constexpr uint32_t ICE_SIGNAL_FLAG_LITE      = 1u << 16;
/// Sender's gather detected a symmetric NAT. Receiver may apply
/// port prediction (try `peer.port + stride * k`) alongside the
/// canonical pair when running connectivity checks.
inline constexpr uint32_t ICE_SIGNAL_FLAG_SYMMETRIC = 1u << 17;

/// Compute candidate priority per RFC 8445. HostMdns shares the
/// host type-preference per draft-ietf-mmusic-mdns-ice-candidates
/// §3.2: it IS a host candidate, just with the IP replaced by a
/// `.local` hostname for privacy.
inline uint32_t compute_priority(CandidateType type, uint16_t local_pref, uint8_t component) {
    uint32_t type_pref = 0;
    switch (type) {
        case CandidateType::Host:     type_pref = 126; break;
        case CandidateType::HostMdns: type_pref = 126; break;
        case CandidateType::Prflx:    type_pref = 110; break;
        case CandidateType::Srflx:    type_pref = 100; break;
        case CandidateType::Relay:    type_pref = 0;   break;
    }
    return (type_pref << 24) | (static_cast<uint32_t>(local_pref) << 8) |
           (256 - component);
}

/// Compute pair priority per RFC 8445.
inline uint64_t pair_priority(uint32_t controlling_prio, uint32_t controlled_prio,
                               bool is_controlling) {
    auto g = is_controlling ? controlling_prio : controlled_prio;
    auto d = is_controlling ? controlled_prio : controlling_prio;
    return (static_cast<uint64_t>(std::min(g, d)) << 32) +
           2 * static_cast<uint64_t>(std::max(g, d)) +
           (g > d ? 1 : 0);
}

// ── Serialization ───────────────────────────────────────────────────────────

/// Wire-level packing of `CandidateType` + `TransportType` inside the
/// 8-bit `CandidateWire::type` slot. Low 5 bits hold the candidate
/// type (HostMdns = 4 fits in 3 bits, leaving slack for future
/// additions); bits 5-6 hold the transport variant (4 values, 2
/// bits). Bit 7 is reserved. Older peers that mask with 0xFF and
/// switch on the result will see a TCP-flavoured candidate as a
/// completely unknown type and drop it gracefully; peers compiled
/// against this header isolate the candidate type with
/// `kCandidateTypeMask` and the transport with `kTransportShift`.
inline constexpr uint8_t kCandidateTypeMask = 0x1F;
inline constexpr uint8_t kTransportShift    = 5;
inline constexpr uint8_t kTransportMask     = 0x03;

inline CandidateWire to_wire(const Candidate& c) {
    CandidateWire w{};
    const uint8_t type_bits = static_cast<uint8_t>(c.type) & kCandidateTypeMask;
    const uint8_t tx_bits =
        (static_cast<uint8_t>(c.transport) & kTransportMask) << kTransportShift;
    w.type = static_cast<uint8_t>(type_bits | tx_bits);
    w.family = static_cast<uint8_t>(c.family);
    w.port = htons(c.port);
    w.priority = htonl(c.priority);
    std::memcpy(w.addr, c.addr.data(), 16);
    return w;
}

inline Candidate from_wire(const CandidateWire& w) {
    Candidate c{};
    c.type = static_cast<CandidateType>(w.type & kCandidateTypeMask);
    c.transport = static_cast<TransportType>(
        (w.type >> kTransportShift) & kTransportMask);
    c.family = static_cast<AddressFamily>(w.family);
    c.port = ntohs(w.port);
    c.priority = ntohl(w.priority);
    std::memcpy(c.addr.data(), w.addr, 16);
    return c;
}

/// On-wire trailer carrying `.local` hostnames for HostMdns
/// candidates per draft-ietf-mmusic-mdns-ice-candidates.
///
/// The trailer is APPENDED after the fixed `CandidateWire` array
/// only when at least one candidate in the set is of type
/// HostMdns. A signal that carries zero HostMdns candidates is
/// byte-identical to the legacy wire format — so older peers
/// that predate the mDNS extension keep parsing such signals
/// unchanged, and the wire stays backward-compatible for the
/// common case where the operator has not enabled mDNS host
/// obfuscation.
///
/// Layout (network byte order throughout):
///   uint32_t mdns_count;          // number of hostnames in the
///                                 // trailer; matches the count of
///                                 // HostMdns candidates above
///   repeat mdns_count times:
///       uint16_t hostname_len;    // 1..kMaxMdnsHostnameLen
///       uint8_t  hostname[hostname_len];
///
/// Hostnames appear in the same order as the HostMdns candidates
/// in the candidate array — the Nth HostMdns candidate maps to
/// the Nth hostname in the trailer. Non-HostMdns candidates
/// occupy the same `CandidateWire` slot they always did.
inline std::vector<uint8_t> serialize_signal(
    const char* ufrag, const char* pwd,
    const std::vector<Candidate>& candidates,
    uint32_t flags = 0) {
    IceSignalData hdr{};
    std::memset(hdr.ufrag, 0, sizeof(hdr.ufrag));
    auto ufrag_len = std::min(std::strlen(ufrag), sizeof(hdr.ufrag));
    std::memcpy(hdr.ufrag, ufrag, ufrag_len);
    std::memset(hdr.pwd, 0, sizeof(hdr.pwd));
    auto pwd_len = std::min(std::strlen(pwd), sizeof(hdr.pwd));
    std::memcpy(hdr.pwd, pwd, pwd_len);
    const uint32_t packed =
        (flags & ICE_SIGNAL_FLAG_MASK)
        | (static_cast<uint32_t>(candidates.size()) & ICE_SIGNAL_COUNT_MASK);
    hdr.candidate_count = htonl(packed);

    /// Count HostMdns candidates so we can size the trailer.
    uint32_t mdns_count = 0;
    size_t   trailer_bytes = 0;
    for (const auto& c : candidates) {
        if (c.type == CandidateType::HostMdns && !c.hostname.empty()) {
            ++mdns_count;
            trailer_bytes += sizeof(uint16_t)
                + std::min<size_t>(c.hostname.size(), kMaxMdnsHostnameLen);
        }
    }
    /// Backward-compat: emit zero trailer bytes when no HostMdns
    /// candidates are present.
    const size_t header_bytes = sizeof(hdr);
    const size_t fixed_bytes  = candidates.size() * sizeof(CandidateWire);
    const size_t trailer_hdr  = (mdns_count > 0) ? sizeof(uint32_t) : 0;
    std::vector<uint8_t> out(header_bytes + fixed_bytes + trailer_hdr + trailer_bytes);
    std::memcpy(out.data(), &hdr, header_bytes);

    for (size_t i = 0; i < candidates.size(); ++i) {
        auto w = to_wire(candidates[i]);
        std::memcpy(out.data() + header_bytes + i * sizeof(w), &w, sizeof(w));
    }

    if (mdns_count > 0) {
        size_t off = header_bytes + fixed_bytes;
        const uint32_t mc_net = htonl(mdns_count);
        std::memcpy(out.data() + off, &mc_net, sizeof(mc_net));
        off += sizeof(mc_net);
        for (const auto& c : candidates) {
            if (c.type != CandidateType::HostMdns || c.hostname.empty()) continue;
            const auto len = static_cast<uint16_t>(
                std::min<size_t>(c.hostname.size(), kMaxMdnsHostnameLen));
            const uint16_t len_net = htons(len);
            std::memcpy(out.data() + off, &len_net, sizeof(len_net));
            off += sizeof(len_net);
            std::memcpy(out.data() + off, c.hostname.data(), len);
            off += len;
        }
    }
    return out;
}

/// Hard cap on advertised candidates per signal. 256 is comfortably above
/// any realistic ICE candidate set (host + reflexive + relay × IPv4/IPv6
/// usually fits in <16). a malicious peer could send
/// candidate_count = 0xFFFFFFFF and have us resize() into ~100 GB before
/// std::bad_alloc → terminate(). Reject before allocating.
inline constexpr uint32_t MAX_ICE_CANDIDATES = 256;

inline bool deserialize_signal(std::span<const uint8_t> data,
                                IceSignalData& hdr,
                                std::vector<Candidate>& candidates,
                                uint32_t* out_flags = nullptr) {
    if (data.size() < sizeof(IceSignalData)) return false;
    std::memcpy(&hdr, data.data(), sizeof(hdr));
    const uint32_t packed = ntohl(hdr.candidate_count);
    const uint32_t flags = packed & ICE_SIGNAL_FLAG_MASK;
    hdr.candidate_count = packed & ICE_SIGNAL_COUNT_MASK;
    if (out_flags) *out_flags = flags;

    if (hdr.candidate_count > MAX_ICE_CANDIDATES) return false;

    /// Strict equality on the fixed prefix used to be the whole
    /// check. The mDNS trailer (draft-ietf-mmusic-mdns-ice-candidates)
    /// adds optional trailing bytes when at least one candidate is
    /// HostMdns — so the check now splits in two: the fixed prefix
    /// must be present, and any trailing bytes must parse into
    /// length-prefixed hostnames that match the HostMdns candidates
    /// in order. Anything that doesn't fit that grammar is rejected
    /// the same way trailing garbage was before.
    const size_t fixed_size =
        sizeof(hdr) + hdr.candidate_count * sizeof(CandidateWire);
    if (data.size() < fixed_size) return false;

    candidates.resize(hdr.candidate_count);
    uint32_t mdns_candidate_count = 0;
    for (uint32_t i = 0; i < hdr.candidate_count; ++i) {
        CandidateWire w;
        std::memcpy(&w, data.data() + sizeof(hdr) + i * sizeof(w), sizeof(w));
        candidates[i] = from_wire(w);
        if (candidates[i].type == CandidateType::HostMdns) {
            ++mdns_candidate_count;
        }
    }

    if (data.size() == fixed_size) {
        /// No trailer — legacy wire form. Reject if HostMdns
        /// candidates were advertised but no hostnames followed;
        /// otherwise the FSM has nothing to resolve and would
        /// silently treat them as 0.0.0.0 host pairs.
        return mdns_candidate_count == 0;
    }

    if (mdns_candidate_count == 0) {
        /// Trailer present but no HostMdns candidate that would
        /// consume it. Treat as malformed.
        return false;
    }

    size_t off = fixed_size;
    if (off + sizeof(uint32_t) > data.size()) return false;
    uint32_t trailer_count = 0;
    std::memcpy(&trailer_count, data.data() + off, sizeof(trailer_count));
    trailer_count = ntohl(trailer_count);
    off += sizeof(trailer_count);
    if (trailer_count != mdns_candidate_count) return false;

    /// Walk hostnames in lock-step with HostMdns candidates.
    uint32_t hn_index = 0;
    for (uint32_t i = 0; i < hdr.candidate_count; ++i) {
        if (candidates[i].type != CandidateType::HostMdns) continue;
        if (off + sizeof(uint16_t) > data.size()) return false;
        uint16_t len_net = 0;
        std::memcpy(&len_net, data.data() + off, sizeof(len_net));
        off += sizeof(len_net);
        const uint16_t len = ntohs(len_net);
        if (len == 0 || len > kMaxMdnsHostnameLen) return false;
        if (off + len > data.size()) return false;
        candidates[i].hostname.assign(
            reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        ++hn_index;
    }
    /// All bytes accounted for — same strict-equality discipline as
    /// before.
    if (off != data.size()) return false;
    if (hn_index != trailer_count) return false;
    return true;
}

} // namespace gn::link::ice
