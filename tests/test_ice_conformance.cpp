// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_conformance.cpp
/// @brief  Instantiates the SDK link teardown conformance suite
///         against `gn::link::ice::IceLink`. ICE has no acceptor —
///         `wire_credentials` plants a fake responder-side session
///         on the server so the suite can observe the
///         `notify_connect → notify_disconnect on shutdown caller
///         thread` invariant for ICE the same way it does for TCP.

#include <sdk/test/conformance/link_teardown.hpp>

#include "../candidate.hpp"
#include "../link_ice.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace gn::test::link::conformance {

template <>
struct LinkTraits<gn::link::ice::IceLink> {
    static constexpr const char* scheme = "ice";

    /// Server's fake peer pubkey — controls the URI the client uses.
    static const std::uint8_t* server_pk() {
        static constexpr std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk = {
            0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x70, 0x6b,
            0x66, 0x6f, 0x72, 0x49, 0x43, 0x45, 0x63, 0x6f,
            0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63,
            0x65, 0x74, 0x65, 0x73, 0x74, 0x73, 0x21, 0x21,
        };
        return pk.data();
    }

    /// Client's fake peer pubkey — what the server's responder
    /// session will be associated with.
    static const std::uint8_t* client_pk() {
        static constexpr std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk = {
            0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x70, 0x6b,
            0x66, 0x6f, 0x72, 0x49, 0x43, 0x45, 0x63, 0x6f,
            0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63,
            0x65, 0x74, 0x65, 0x73, 0x74, 0x73, 0x21, 0x21,
        };
        return pk.data();
    }

    static std::shared_ptr<gn::link::ice::IceLink> make() {
        return std::make_shared<gn::link::ice::IceLink>();
    }

    static std::string listen_uri() {
        std::string uri = "ice://";
        for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
            static constexpr char digits[] = "0123456789abcdef";
            uri += digits[server_pk()[i] >> 4];
            uri += digits[server_pk()[i] & 0x0F];
        }
        return uri;
    }

    /// `connect_uri` ignores the kernel-allocated port — ICE has no
    /// listening port. The URI carries the server's pubkey hex so
    /// the client allocates an initiator-role conn record.
    static std::string connect_uri(std::uint16_t /*port*/) {
        return listen_uri();
    }

    /// Deliver a synthetic OFFER to the server so it allocates a
    /// responder-role conn record. Combined with the client's
    /// `connect()` call this gives the conformance suite the two
    /// `notify_connect` events it expects to balance against
    /// shutdown's `notify_disconnect`s.
    static bool wire_credentials(gn::link::ice::IceLink& server,
                                  gn::link::ice::IceLink& /*client*/) {
        gn::link::ice::IceSignalData hdr{};
        const char ufrag[] = "TESTufrg";
        const char pwd[]   = "TESTpwd_long_enough_for_ICE";
        std::memcpy(hdr.ufrag, ufrag, sizeof(hdr.ufrag));
        std::memcpy(hdr.pwd, pwd,
            std::min(sizeof(hdr.pwd), sizeof(pwd)));
        hdr.candidate_count = 0;  // host-side will htonl below
        std::vector<std::uint8_t> blob(sizeof(hdr));
        std::memcpy(blob.data(), &hdr, sizeof(hdr));

        const auto rc = server.deliver_signal(
            client_pk(), gn::link::ice::ICE_SIGNAL_OFFER,
            std::span<const std::uint8_t>(blob.data(), blob.size()));
        return rc == GN_OK;
    }
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    IceLink,
    LinkTeardownConformance,
    ::testing::Types<gn::link::ice::IceLink>);

}  // namespace gn::test::link::conformance
