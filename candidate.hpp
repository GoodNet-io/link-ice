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
#include <vector>

namespace gn::link::ice {

enum class CandidateType : uint8_t {
    Host  = 0,
    Srflx = 1,   // Server Reflexive
    Relay = 2,   // TURN relay
    Prflx = 3    // Peer Reflexive (learned from check response)
};

enum class AddressFamily : uint8_t {
    IPv4 = 1,
    IPv6 = 2
};

/// @brief ICE candidate (host/srflx/relay) — address + priority + foundation.
struct Candidate {
    CandidateType  type;
    AddressFamily  family;
    uint16_t       port;
    uint32_t       priority;
    std::array<uint8_t, 16> addr{};  // IPv4 in first 4 bytes, or full IPv6

    std::string address_str() const;
    void set_address(const std::string& addr_str);
};

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

/// Compute candidate priority per RFC 8445.
inline uint32_t compute_priority(CandidateType type, uint16_t local_pref, uint8_t component) {
    uint32_t type_pref = 0;
    switch (type) {
        case CandidateType::Host:  type_pref = 126; break;
        case CandidateType::Prflx: type_pref = 110; break;
        case CandidateType::Srflx: type_pref = 100; break;
        case CandidateType::Relay: type_pref = 0;   break;
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

inline CandidateWire to_wire(const Candidate& c) {
    CandidateWire w{};
    w.type = static_cast<uint8_t>(c.type);
    w.family = static_cast<uint8_t>(c.family);
    w.port = htons(c.port);
    w.priority = htonl(c.priority);
    std::memcpy(w.addr, c.addr.data(), 16);
    return w;
}

inline Candidate from_wire(const CandidateWire& w) {
    Candidate c{};
    c.type = static_cast<CandidateType>(w.type);
    c.family = static_cast<AddressFamily>(w.family);
    c.port = ntohs(w.port);
    c.priority = ntohl(w.priority);
    std::memcpy(c.addr.data(), w.addr, 16);
    return c;
}

inline std::vector<uint8_t> serialize_signal(
    const char* ufrag, const char* pwd,
    const std::vector<Candidate>& candidates) {
    IceSignalData hdr{};
    std::memset(hdr.ufrag, 0, sizeof(hdr.ufrag));
    auto ufrag_len = std::min(std::strlen(ufrag), sizeof(hdr.ufrag));
    std::memcpy(hdr.ufrag, ufrag, ufrag_len);
    std::memset(hdr.pwd, 0, sizeof(hdr.pwd));
    auto pwd_len = std::min(std::strlen(pwd), sizeof(hdr.pwd));
    std::memcpy(hdr.pwd, pwd, pwd_len);
    hdr.candidate_count = htonl(static_cast<uint32_t>(candidates.size()));

    std::vector<uint8_t> out(sizeof(hdr) + candidates.size() * sizeof(CandidateWire));
    std::memcpy(out.data(), &hdr, sizeof(hdr));

    for (size_t i = 0; i < candidates.size(); ++i) {
        auto w = to_wire(candidates[i]);
        std::memcpy(out.data() + sizeof(hdr) + i * sizeof(w), &w, sizeof(w));
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
                                std::vector<Candidate>& candidates) {
    if (data.size() < sizeof(IceSignalData)) return false;
    std::memcpy(&hdr, data.data(), sizeof(hdr));
    hdr.candidate_count = ntohl(hdr.candidate_count);

    if (hdr.candidate_count > MAX_ICE_CANDIDATES) return false;

    // Strict equality — trailing garbage means a malformed signal, not a
    // permissively-truncated one. The previous `<` test let an attacker
    // pad the buffer arbitrarily.
    size_t expected = sizeof(hdr) + hdr.candidate_count * sizeof(CandidateWire);
    if (data.size() != expected) return false;

    candidates.resize(hdr.candidate_count);
    for (uint32_t i = 0; i < hdr.candidate_count; ++i) {
        CandidateWire w;
        std::memcpy(&w, data.data() + sizeof(hdr) + i * sizeof(w), sizeof(w));
        candidates[i] = from_wire(w);
    }
    return true;
}

} // namespace gn::link::ice
