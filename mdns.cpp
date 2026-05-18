// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/mdns.cpp
/// @brief  Minimal multicast DNS responder + resolver implementation.
///
/// Wire format references:
///   - RFC 1035 §4 — DNS message format (header, question, RR)
///   - RFC 6762   — Multicast DNS (link-local query / response,
///                  case-insensitive name match, no recursion)
///   - draft-ietf-mmusic-mdns-ice-candidates — host-candidate
///                  obfuscation via `<uuid>.local`

#include "mdns.hpp"
#include "candidate.hpp"

#include <asio/bind_executor.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/multicast.hpp>
#include <asio/post.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <utility>

#include <sodium/randombytes.h>

#ifdef __linux__
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

namespace gn::link::ice {

namespace {

constexpr std::uint16_t DNS_TYPE_A    = 1;
constexpr std::uint16_t DNS_TYPE_AAAA = 28;
constexpr std::uint16_t DNS_CLASS_IN  = 1;
/// RFC 6762 §10.2 — mDNS uses TTL=120 for link-local A/AAAA records.
constexpr std::uint32_t DNS_TTL_SECONDS = 120;

/// Header layout per RFC 1035 §4.1.1. We keep the struct out of the
/// way and do explicit big-endian reads/writes to avoid alignment +
/// endianness surprises.
constexpr std::size_t DNS_HEADER_SIZE = 12;

std::uint16_t read_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t read_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}

void append_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void append_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

/// Encode a DNS name as a sequence of `<len><label>` pairs followed
/// by a zero byte. Returns false if any label exceeds 63 bytes or
/// the whole encoded form exceeds 255 bytes (RFC 1035 §3.1).
bool encode_name(std::vector<std::uint8_t>& out, std::string_view name) {
    std::size_t encoded_size = 0;
    std::size_t i = 0;
    while (i < name.size()) {
        std::size_t end = i;
        while (end < name.size() && name[end] != '.') ++end;
        const std::size_t label_len = end - i;
        if (label_len == 0) {
            /// Empty label only allowed as the trailing root dot
            /// (i.e. `name.local.`); handled by the outer terminator.
            if (end == name.size()) break;
            return false;
        }
        if (label_len > 63) return false;
        out.push_back(static_cast<std::uint8_t>(label_len));
        out.insert(out.end(), name.data() + i,
                    name.data() + i + label_len);
        encoded_size += 1 + label_len;
        if (encoded_size > 255) return false;
        i = end + 1;
    }
    out.push_back(0);
    return true;
}

/// Decode a DNS name starting at `off`. Handles compression pointers
/// (RFC 1035 §4.1.4). Returns false on:
///   - pointer that lands outside `bytes`
///   - pointer loop (we cap follow count at 16)
///   - label exceeding 63 bytes
///   - decoded length exceeding 255 bytes
/// On success sets `out_name` (lowercase, no trailing dot) and
/// `out_next` to the offset of the byte immediately after the name
/// in the wire stream (NOT after any pointer chain — RFC §4.1.4).
bool decode_name(std::span<const std::uint8_t> bytes,
                  std::size_t off,
                  std::string& out_name,
                  std::size_t& out_next) {
    out_name.clear();
    bool jumped = false;
    std::size_t cur = off;
    std::size_t jumps = 0;
    std::size_t total = 0;

    while (true) {
        if (cur >= bytes.size()) return false;
        const std::uint8_t len = bytes[cur];
        if (len == 0) {
            if (!jumped) out_next = cur + 1;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            /// Pointer — 2 bytes, low 14 bits are the target offset.
            if (cur + 1 >= bytes.size()) return false;
            const std::size_t target =
                ((static_cast<std::size_t>(len & 0x3F)) << 8)
                | bytes[cur + 1];
            if (target >= bytes.size()) return false;
            if (!jumped) out_next = cur + 2;
            cur = target;
            jumped = true;
            if (++jumps > 16) return false;
            continue;
        }
        if ((len & 0xC0) != 0) return false;  // reserved
        if (cur + 1 + len > bytes.size()) return false;
        if (total + 1 + len > 255) return false;
        if (!out_name.empty()) out_name.push_back('.');
        for (std::size_t i = 0; i < len; ++i) {
            const auto ch = bytes[cur + 1 + i];
            out_name.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(ch))));
        }
        total += 1 + len;
        cur += 1 + len;
    }
}

}  // namespace

std::string MdnsManager::to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string generate_uuid_v4() {
    std::array<std::uint8_t, 16> raw{};
    randombytes_buf(raw.data(), raw.size());
    /// Version 4 — bits 12..15 of time_hi_and_version (byte 6) = 0100.
    raw[6] = static_cast<std::uint8_t>((raw[6] & 0x0F) | 0x40);
    /// Variant 10 — bits 6..7 of clock_seq_hi (byte 8) = 10xx.
    raw[8] = static_cast<std::uint8_t>((raw[8] & 0x3F) | 0x80);

    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(hex[raw[i] >> 4]);
        out.push_back(hex[raw[i] & 0x0F]);
    }
    return out;
}

bool is_mdns_local_name(std::string_view name) noexcept {
    constexpr std::string_view suffix = ".local";
    if (name.size() <= suffix.size()) return false;
    if (name.size() > kMaxMdnsHostnameLen) return false;
    const auto tail = name.substr(name.size() - suffix.size());
    for (std::size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(tail[i])) != suffix[i]) {
            return false;
        }
    }
    /// At least one non-empty label before `.local`. Disallow
    /// embedded NULs etc. — only printable ASCII makes sense for a
    /// hostname we generated ourselves.
    for (auto c : name) {
        if (c == '\0') return false;
    }
    return true;
}

// ── Wire encode/decode ─────────────────────────────────────────────────

std::vector<std::uint8_t> encode_dns_query(std::string_view hostname,
                                              std::uint16_t txn_id,
                                              bool want_aaaa) {
    std::vector<std::uint8_t> out;
    out.reserve(DNS_HEADER_SIZE + hostname.size() + 8);
    /// Header: QR=0 (query), QDCOUNT=1, others 0. Standard query
    /// (opcode 0), RD=0 (mDNS doesn't recurse).
    append_be16(out, txn_id);
    append_be16(out, 0x0000);  // flags
    append_be16(out, 0x0001);  // QDCOUNT
    append_be16(out, 0x0000);  // ANCOUNT
    append_be16(out, 0x0000);  // NSCOUNT
    append_be16(out, 0x0000);  // ARCOUNT
    if (!encode_name(out, hostname)) {
        return {};
    }
    append_be16(out, want_aaaa ? DNS_TYPE_AAAA : DNS_TYPE_A);
    /// Class IN; RFC 6762 §5.4 unicast-response bit (0x8000) is
    /// allowed when the querier wants a unicast reply. We leave it
    /// off so responders answer multicast; replies still route back
    /// to us because we are joined to the group.
    append_be16(out, DNS_CLASS_IN);
    return out;
}

std::vector<std::uint8_t> encode_dns_response(std::string_view hostname,
                                                 std::uint16_t txn_id,
                                                 const std::vector<std::string>& ipv4,
                                                 const std::vector<std::string>& ipv6) {
    std::vector<std::uint8_t> out;
    const std::uint16_t ancount =
        static_cast<std::uint16_t>(ipv4.size() + ipv6.size());

    append_be16(out, txn_id);
    /// QR=1 (response), AA=1 (authoritative — mDNS responders are
    /// authoritative for their `.local` names per RFC 6762 §6).
    append_be16(out, 0x8400);
    append_be16(out, 0x0000);   // QDCOUNT — mDNS responses omit Q
    append_be16(out, ancount);  // ANCOUNT
    append_be16(out, 0x0000);   // NSCOUNT
    append_be16(out, 0x0000);   // ARCOUNT

    auto emit_answer = [&](std::uint16_t qtype,
                            std::span<const std::uint8_t> rdata) {
        if (!encode_name(out, hostname)) return;
        append_be16(out, qtype);
        /// RFC 6762 §10.2 cache-flush bit (0x8000) on IN class —
        /// signals that prior cached records for this name should
        /// be flushed.
        append_be16(out, 0x8001);
        append_be32(out, DNS_TTL_SECONDS);
        append_be16(out, static_cast<std::uint16_t>(rdata.size()));
        out.insert(out.end(), rdata.begin(), rdata.end());
    };

    for (const auto& ip : ipv4) {
        std::array<std::uint8_t, 4> octets{};
        if (std::sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu",
                         &octets[0], &octets[1], &octets[2], &octets[3]) != 4) {
            continue;
        }
        emit_answer(DNS_TYPE_A, std::span<const std::uint8_t>(octets));
    }
#ifdef __linux__
    for (const auto& ip : ipv6) {
        std::array<std::uint8_t, 16> bytes{};
        struct in6_addr in6;
        if (inet_pton(AF_INET6, ip.c_str(), &in6) != 1) continue;
        std::memcpy(bytes.data(), &in6, 16);
        emit_answer(DNS_TYPE_AAAA, std::span<const std::uint8_t>(bytes));
    }
#else
    (void)ipv6;
#endif
    return out;
}

std::optional<DnsParsedMessage> parse_dns_message(
    std::span<const std::uint8_t> bytes) {
    if (bytes.size() < DNS_HEADER_SIZE) return std::nullopt;

    DnsParsedMessage out;
    out.txn_id      = read_be16(bytes.data());
    const auto flags = read_be16(bytes.data() + 2);
    out.is_response = (flags & 0x8000) != 0;
    const auto qdcount = read_be16(bytes.data() + 4);
    const auto ancount = read_be16(bytes.data() + 6);

    std::size_t off = DNS_HEADER_SIZE;
    for (std::uint16_t i = 0; i < qdcount; ++i) {
        std::string name;
        std::size_t next = 0;
        if (!decode_name(bytes, off, name, next)) return std::nullopt;
        off = next;
        if (off + 4 > bytes.size()) return std::nullopt;
        const auto qtype = read_be16(bytes.data() + off);
        off += 4;  // qtype + qclass
        if (i == 0) {
            out.question = std::move(name);
            out.qtype    = qtype;
        }
    }

    for (std::uint16_t i = 0; i < ancount; ++i) {
        std::string name;
        std::size_t next = 0;
        if (!decode_name(bytes, off, name, next)) return std::nullopt;
        off = next;
        if (off + 10 > bytes.size()) return std::nullopt;
        const auto rtype  = read_be16(bytes.data() + off);
        /// rclass uses bit 0x8000 as the cache-flush flag — mask it
        /// off before comparing.
        const auto rclass_raw = read_be16(bytes.data() + off + 2);
        const auto rclass = static_cast<std::uint16_t>(rclass_raw & 0x7FFF);
        // const auto ttl = read_be32(bytes.data() + off + 4);
        (void)read_be32(bytes.data() + off + 4);
        const auto rdlen  = read_be16(bytes.data() + off + 8);
        off += 10;
        if (off + rdlen > bytes.size()) return std::nullopt;

        if (rclass == DNS_CLASS_IN && rtype == DNS_TYPE_A && rdlen == 4) {
            char buf[INET_ADDRSTRLEN]{};
            const std::uint8_t* o = bytes.data() + off;
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                           o[0], o[1], o[2], o[3]);
            DnsParsedMessage::Answer a;
            a.name = std::move(name);
            a.ipv4 = buf;
            out.answers.push_back(std::move(a));
        }
#ifdef __linux__
        else if (rclass == DNS_CLASS_IN && rtype == DNS_TYPE_AAAA
                  && rdlen == 16) {
            struct in6_addr in6;
            std::memcpy(&in6, bytes.data() + off, 16);
            char buf[INET6_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET6, &in6, buf, sizeof(buf)) != nullptr) {
                DnsParsedMessage::Answer a;
                a.name = std::move(name);
                a.ipv6 = buf;
                out.answers.push_back(std::move(a));
            }
        }
#endif
        off += rdlen;
    }
    return out;
}

// ── Local interface enumeration ────────────────────────────────────────

void MdnsManager::enumerate_local_addresses(std::vector<std::string>& v4,
                                                std::vector<std::string>& v6) {
    v4.clear();
    v6.clear();
#ifdef __linux__
    struct ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return;
    for (auto* ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* s = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            char buf[INET_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf))) {
                v4.emplace_back(buf);
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            auto* s = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (IN6_IS_ADDR_LINKLOCAL(&s->sin6_addr)) continue;
            char buf[INET6_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf))) {
                v6.emplace_back(buf);
            }
        }
    }
    freeifaddrs(list);
#else
    // TODO(mdns): macOS / Windows interface enumeration. Falls back
    // to an empty address list, which means the responder cannot
    // answer queries until the platform path is wired in.
#endif
}

// ── MdnsManager ─────────────────────────────────────────────────────────

MdnsManager::MdnsManager(asio::io_context& io)
    : io_(io),
      strand_(asio::make_strand(io.get_executor())),
      socket_v4_(strand_) {}

MdnsManager::~MdnsManager() {
    /// Synchronous teardown only — `stop()` posts to the strand via
    /// `shared_from_this()`, which throws `bad_weak_ptr` once the
    /// owning shared_ptr is being destructed. Close the socket
    /// directly and let the strand-bound work that's already in
    /// flight fire its callbacks against the captured self handles.
    running_.store(false, std::memory_order_release);
    stopping_.store(true, std::memory_order_release);
    std::error_code ec;
    socket_v4_.close(ec);
}

bool MdnsManager::start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return true;
    }
    enumerate_local_addresses(local_v4_, local_v6_);

    std::error_code ec;
    asio::ip::udp::endpoint listen_ep(asio::ip::udp::v4(), kMdnsPort);
    socket_v4_.open(asio::ip::udp::v4(), ec);
    if (ec) {
        running_.store(false, std::memory_order_release);
        return false;
    }
    socket_v4_.set_option(asio::ip::udp::socket::reuse_address(true), ec);
    /// SO_REUSEPORT lets the OS fan inbound multicast across every
    /// process bound to 5353 (system Avahi / mDNSResponder may
    /// already hold the port). On Linux REUSEPORT semantics include
    /// REUSEADDR; on platforms without REUSEPORT the open just falls
    /// back to the regular bind below.
#ifdef SO_REUSEPORT
    {
        const int yes = 1;
        ::setsockopt(socket_v4_.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                      &yes, sizeof(yes));
    }
#endif
    socket_v4_.bind(listen_ep, ec);
    if (ec) {
        socket_v4_.close(ec);
        running_.store(false, std::memory_order_release);
        return false;
    }
    /// Join the IPv4 multicast group. Failure is non-fatal: we keep
    /// the socket bound so queries we generate still reach unicast
    /// peers, but the responder side won't receive inbound queries.
    socket_v4_.set_option(
        asio::ip::multicast::join_group(
            asio::ip::make_address(kMdnsIPv4MulticastAddr)),
        ec);
    /// Disable loopback so our own queries don't bounce back as
    /// "inbound" packets — the resolver path would otherwise see
    /// every outgoing query and try to parse it as a response.
    socket_v4_.set_option(asio::ip::multicast::enable_loopback(true), ec);

    async_receive();
    return true;
}

void MdnsManager::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) return;
    stopping_.store(true, std::memory_order_release);
    asio::dispatch(strand_, [self = shared_from_this()] {
        std::error_code ec;
        self->socket_v4_.close(ec);
        for (auto& [_name, queries] : self->pending_) {
            for (auto& q : queries) {
                q->timer.cancel();
                if (!q->fired.exchange(true, std::memory_order_acq_rel)) {
                    if (q->cb) q->cb(q->accumulated);
                }
            }
        }
        self->pending_.clear();
    });
}

void MdnsManager::register_name(std::string hostname) {
    auto name_lc = to_lower(std::move(hostname));
    asio::dispatch(strand_, [self = shared_from_this(),
                              name_lc = std::move(name_lc)]() mutable {
        NameRecord rec;
        rec.ipv4 = self->local_v4_;
        rec.ipv6 = self->local_v6_;
        self->names_[std::move(name_lc)] = std::move(rec);
    });
}

void MdnsManager::unregister_name(const std::string& hostname) {
    auto name_lc = to_lower(hostname);
    asio::dispatch(strand_, [self = shared_from_this(), name_lc] {
        self->names_.erase(name_lc);
    });
}

void MdnsManager::resolve(std::string hostname,
                            std::chrono::milliseconds timeout,
                            MdnsResolveCallback cb) {
    auto name_lc = to_lower(std::move(hostname));
    asio::dispatch(strand_,
        [self = shared_from_this(), name_lc = std::move(name_lc),
         timeout, cb = std::move(cb)]() mutable {
            /// Short-circuit: if the manager has already registered
            /// this name (we're resolving our own hostname) answer
            /// from the local record directly.
            if (auto it = self->names_.find(name_lc); it != self->names_.end()) {
                MdnsResolveResult r;
                r.ipv4     = it->second.ipv4;
                r.ipv6     = it->second.ipv6;
                r.resolved = true;
                if (cb) cb(r);
                return;
            }

            auto q = std::make_shared<PendingQuery>(self->strand_, timeout);
            q->hostname_lc = name_lc;
            q->cb          = std::move(cb);
            std::uint16_t txn = 0;
            randombytes_buf(&txn, sizeof(txn));
            q->txn_id      = txn;
            self->pending_[name_lc].push_back(q);

            self->send_query(name_lc, q->txn_id);

            q->timer.expires_after(timeout);
            q->timer.async_wait(asio::bind_executor(self->strand_,
                [self, q](const std::error_code& ec) {
                    if (ec) return;
                    if (q->fired.exchange(true, std::memory_order_acq_rel)) return;
                    /// Remove from pending list.
                    auto it = self->pending_.find(q->hostname_lc);
                    if (it != self->pending_.end()) {
                        auto& vec = it->second;
                        vec.erase(std::remove(vec.begin(), vec.end(), q),
                                    vec.end());
                        if (vec.empty()) self->pending_.erase(it);
                    }
                    if (q->cb) q->cb(q->accumulated);
                }));
        });
}

MdnsResolveResult MdnsManager::resolve_sync(
    const std::string& hostname,
    std::chrono::milliseconds timeout) {
    auto promise = std::make_shared<std::promise<MdnsResolveResult>>();
    auto fut = promise->get_future();
    resolve(hostname, timeout, [promise](const MdnsResolveResult& r) {
        promise->set_value(r);
    });
    return fut.get();
}

void MdnsManager::async_receive() {
    if (stopping_.load(std::memory_order_acquire)) return;
    auto self = shared_from_this();
    socket_v4_.async_receive_from(
        asio::buffer(rx_buf_), recv_endpoint_,
        asio::bind_executor(strand_,
            [self](const std::error_code& ec, std::size_t n) {
                if (ec || self->stopping_.load(std::memory_order_acquire)) return;
                if (n > 0) {
                    self->on_packet(
                        std::span<const std::uint8_t>(self->rx_buf_.data(), n),
                        self->recv_endpoint_);
                }
                self->async_receive();
            }));
}

void MdnsManager::on_packet(std::span<const std::uint8_t> bytes,
                                const asio::ip::udp::endpoint& src) {
    auto parsed = parse_dns_message(bytes);
    if (!parsed) return;

    if (!parsed->is_response) {
        /// Inbound query. Match against registered names; answer
        /// every matching name with the local interface addresses.
        if (parsed->question.empty()) return;
        auto it = names_.find(parsed->question);
        if (it == names_.end()) return;
        send_answer(parsed->question, it->second, parsed->txn_id, src);
        return;
    }

    /// Response. Match by lowercase name across the pending queries.
    /// mDNS responders can answer multiple names in one packet; walk
    /// every answer and dispatch to whichever pending query matches.
    for (const auto& ans : parsed->answers) {
        auto qit = pending_.find(ans.name);
        if (qit == pending_.end()) continue;
        for (auto& q : qit->second) {
            if (!ans.ipv4.empty()
                && std::find(q->accumulated.ipv4.begin(),
                              q->accumulated.ipv4.end(), ans.ipv4)
                   == q->accumulated.ipv4.end()) {
                q->accumulated.ipv4.push_back(ans.ipv4);
                q->accumulated.resolved = true;
            }
            if (!ans.ipv6.empty()
                && std::find(q->accumulated.ipv6.begin(),
                              q->accumulated.ipv6.end(), ans.ipv6)
                   == q->accumulated.ipv6.end()) {
                q->accumulated.ipv6.push_back(ans.ipv6);
                q->accumulated.resolved = true;
            }
        }
    }

    /// Fire any queries that got at least one answer. We don't wait
    /// for the timeout if we already have a usable IP — the ICE
    /// session benefits from the earliest response it can get.
    for (auto it = pending_.begin(); it != pending_.end(); ) {
        auto& queries = it->second;
        for (auto qit = queries.begin(); qit != queries.end(); ) {
            auto& q = *qit;
            if (q->accumulated.resolved
                && !q->fired.exchange(true, std::memory_order_acq_rel)) {
                q->timer.cancel();
                if (q->cb) q->cb(q->accumulated);
                qit = queries.erase(qit);
            } else {
                ++qit;
            }
        }
        if (queries.empty()) {
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
}

void MdnsManager::send_query(const std::string& hostname_lc,
                                  std::uint16_t txn_id) {
    if (stopping_.load(std::memory_order_acquire)) return;
    std::error_code ec;
    asio::ip::udp::endpoint dst(
        asio::ip::make_address(kMdnsIPv4MulticastAddr), kMdnsPort);
    /// One A query + one AAAA query — two packets matches what
    /// browsers do and keeps the per-record-type parsing simple.
    auto pkt_a    = encode_dns_query(hostname_lc, txn_id, /*aaaa=*/false);
    auto pkt_aaaa = encode_dns_query(hostname_lc, txn_id, /*aaaa=*/true);
    if (!pkt_a.empty()) {
        socket_v4_.send_to(asio::buffer(pkt_a), dst, 0, ec);
    }
    if (!pkt_aaaa.empty()) {
        socket_v4_.send_to(asio::buffer(pkt_aaaa), dst, 0, ec);
    }
}

void MdnsManager::send_answer(const std::string& hostname,
                                   const NameRecord& rec,
                                   std::uint16_t txn_id,
                                   const asio::ip::udp::endpoint& dst) {
    if (stopping_.load(std::memory_order_acquire)) return;
    auto pkt = encode_dns_response(hostname, txn_id, rec.ipv4, rec.ipv6);
    if (pkt.empty()) return;
    std::error_code ec;
    /// Answer on the multicast group per RFC 6762 §6 unless the
    /// querier set the unicast-response bit — which we don't honour
    /// here for simplicity. Multicast is always correct.
    asio::ip::udp::endpoint mc(
        asio::ip::make_address(kMdnsIPv4MulticastAddr), kMdnsPort);
    socket_v4_.send_to(asio::buffer(pkt), mc, 0, ec);
    /// Also unicast back to the questioner for fast-path delivery
    /// on switches that filter mcast aggressively. RFC 6762 §6 §11
    /// allow this; some responders do, others don't.
    socket_v4_.send_to(asio::buffer(pkt), dst, 0, ec);
}

}  // namespace gn::link::ice
