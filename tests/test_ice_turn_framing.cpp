// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/tests/test_ice_turn_framing.cpp
/// @brief  Unit tests for TURN-over-TCP / TURN-over-TLS framing per
///         RFC 5389 §7.2.2: 16-bit big-endian length prefix per STUN
///         message, reassembled from arbitrary-sized stream chunks.
///
/// The encode + take helpers live in `turn.hpp` as free functions
/// inside `gn::link::ice` so the framing path is independently
/// testable — TurnClient itself rides a `LinkCarrier` that needs a
/// full host_api scaffolding, but the framing logic is pure on
/// byte buffers and exercised here directly.

#include <gtest/gtest.h>

#include "../turn.hpp"
#include "../stun.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace gn::link::ice {
namespace {

using Bytes = std::vector<std::uint8_t>;

// ── encode_stream_frame ────────────────────────────────────────────

TEST(TurnFraming, EncodeEmptyPayload) {
    Bytes out;
    EXPECT_TRUE(encode_stream_frame({}, out));
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0x00);
}

TEST(TurnFraming, EncodeSmallPayload) {
    constexpr std::array<std::uint8_t, 3> payload{0xAB, 0xCD, 0xEF};
    Bytes out;
    EXPECT_TRUE(encode_stream_frame(payload, out));
    ASSERT_EQ(out.size(), 5u);
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0x03);
    EXPECT_EQ(out[2], 0xAB);
    EXPECT_EQ(out[3], 0xCD);
    EXPECT_EQ(out[4], 0xEF);
}

TEST(TurnFraming, EncodeAppendsToExistingBuffer) {
    Bytes out{0xDE, 0xAD};
    constexpr std::array<std::uint8_t, 2> payload{0x01, 0x02};
    EXPECT_TRUE(encode_stream_frame(payload, out));
    ASSERT_EQ(out.size(), 6u);
    EXPECT_EQ(out[0], 0xDE);
    EXPECT_EQ(out[1], 0xAD);
    EXPECT_EQ(out[2], 0x00);
    EXPECT_EQ(out[3], 0x02);
    EXPECT_EQ(out[4], 0x01);
    EXPECT_EQ(out[5], 0x02);
}

TEST(TurnFraming, EncodeBigEndianLengthAt257Bytes) {
    Bytes payload(257, 0x42);
    Bytes out;
    EXPECT_TRUE(encode_stream_frame(payload, out));
    ASSERT_EQ(out.size(), 2u + 257u);
    EXPECT_EQ(out[0], 0x01);
    EXPECT_EQ(out[1], 0x01);
}

TEST(TurnFraming, EncodeRejectsOversize) {
    Bytes payload(0x10000, 0x00);  // 65 536 = 2^16 — one over the field max
    Bytes out;
    EXPECT_FALSE(encode_stream_frame(payload, out));
    EXPECT_TRUE(out.empty());
}

TEST(TurnFraming, EncodeAcceptsBoundary65535) {
    Bytes payload(0xFFFF, 0x55);
    Bytes out;
    EXPECT_TRUE(encode_stream_frame(payload, out));
    EXPECT_EQ(out.size(), 2u + 0xFFFFu);
    EXPECT_EQ(out[0], 0xFF);
    EXPECT_EQ(out[1], 0xFF);
}

// ── try_take_stream_frame ──────────────────────────────────────────

TEST(TurnFraming, TakeReturnsFalseOnEmptyBuffer) {
    Bytes buf;
    Bytes out;
    EXPECT_FALSE(try_take_stream_frame(buf, out));
    EXPECT_TRUE(out.empty());
}

TEST(TurnFraming, TakeReturnsFalseOnLengthOnly) {
    Bytes buf{0x00};
    Bytes out;
    EXPECT_FALSE(try_take_stream_frame(buf, out));
    EXPECT_EQ(buf.size(), 1u);
}

TEST(TurnFraming, TakeReturnsFalseOnIncompletePayload) {
    /// header advertises 4 bytes but only 2 are present — partial chunk
    Bytes buf{0x00, 0x04, 0xAA, 0xBB};
    Bytes out;
    EXPECT_FALSE(try_take_stream_frame(buf, out));
    EXPECT_EQ(buf.size(), 4u);  // buffer untouched
}

TEST(TurnFraming, TakeExtractsSingleFrame) {
    Bytes buf{0x00, 0x03, 0x11, 0x22, 0x33};
    Bytes out;
    EXPECT_TRUE(try_take_stream_frame(buf, out));
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 0x11);
    EXPECT_EQ(out[1], 0x22);
    EXPECT_EQ(out[2], 0x33);
    EXPECT_TRUE(buf.empty());
}

TEST(TurnFraming, TakeExtractsTwoConcatenatedFrames) {
    /// Two complete frames in one chunk — the TCP/TLS carrier can and
    /// will coalesce multiple small messages into a single delivery.
    Bytes buf{
        0x00, 0x02, 0xAA, 0xBB,             // frame 1: [AA BB]
        0x00, 0x03, 0xCC, 0xDD, 0xEE,       // frame 2: [CC DD EE]
    };
    Bytes out;
    ASSERT_TRUE(try_take_stream_frame(buf, out));
    EXPECT_EQ(out, (Bytes{0xAA, 0xBB}));
    EXPECT_EQ(buf.size(), 5u);

    ASSERT_TRUE(try_take_stream_frame(buf, out));
    EXPECT_EQ(out, (Bytes{0xCC, 0xDD, 0xEE}));
    EXPECT_TRUE(buf.empty());

    EXPECT_FALSE(try_take_stream_frame(buf, out));
}

TEST(TurnFraming, TakePreservesTrailingPartialFrame) {
    /// One complete frame followed by the head of a second frame that
    /// the carrier hasn't fully delivered yet — `take` consumes the
    /// first frame and leaves the partial second frame intact for the
    /// next chunk to fill in.
    Bytes buf{
        0x00, 0x02, 0x11, 0x22,             // frame 1 complete
        0x00, 0x04, 0x33,                    // header + 1 of 4 body bytes
    };
    Bytes out;
    ASSERT_TRUE(try_take_stream_frame(buf, out));
    EXPECT_EQ(out, (Bytes{0x11, 0x22}));

    /// Second frame: header says 4, only 1 byte present — incomplete.
    ASSERT_FALSE(try_take_stream_frame(buf, out));
    /// Partial frame bytes left untouched at the buffer head.
    EXPECT_EQ(buf, (Bytes{0x00, 0x04, 0x33}));
}

TEST(TurnFraming, TakeHandlesByteByByteReassembly) {
    /// Worst case: TCP delivers the message one byte at a time. The
    /// driver loop in `on_inbound` calls `try_take` repeatedly and
    /// only succeeds once the final byte arrives.
    Bytes target_payload{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD};
    Bytes wire;
    ASSERT_TRUE(encode_stream_frame(target_payload, wire));

    Bytes buf;
    Bytes out;
    for (std::size_t i = 0; i + 1 < wire.size(); ++i) {
        buf.push_back(wire[i]);
        EXPECT_FALSE(try_take_stream_frame(buf, out))
            << "premature success at i=" << i;
    }
    buf.push_back(wire.back());
    ASSERT_TRUE(try_take_stream_frame(buf, out));
    EXPECT_EQ(out, target_payload);
    EXPECT_TRUE(buf.empty());
}

TEST(TurnFraming, RoundTripsStunBindingRequest) {
    /// End-to-end: build a real STUN Binding-Request, frame it, take
    /// it back, parse the unframed bytes — the parse must succeed and
    /// the message type must match.
    auto stun_bytes = StunBuilder(STUN_BINDING_REQUEST)
                          .add_username("user")
                          .add_fingerprint()
                          .build();
    Bytes wire;
    ASSERT_TRUE(encode_stream_frame(stun_bytes, wire));

    Bytes out;
    ASSERT_TRUE(try_take_stream_frame(wire, out));
    EXPECT_EQ(out, stun_bytes);

    auto parsed = parse_stun(out);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->msg_type, STUN_BINDING_REQUEST);
}

TEST(TurnFraming, RoundTripsChannelDataFrame) {
    /// ChannelData frames ride the same stream framing on TCP/TLS —
    /// the inner ChannelData header is opaque to the stream layer.
    constexpr std::array<std::uint8_t, 3> payload{0x10, 0x20, 0x30};
    auto channel_data = encode_channel_data(0x4001, payload);
    Bytes wire;
    ASSERT_TRUE(encode_stream_frame(channel_data, wire));

    Bytes out;
    ASSERT_TRUE(try_take_stream_frame(wire, out));
    EXPECT_EQ(out, channel_data);
    EXPECT_TRUE(is_channel_data(out));

    auto parsed = parse_channel_data(out);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->channel, 0x4001);
    EXPECT_EQ(parsed->payload.size(), payload.size());
}

}  // namespace
}  // namespace gn::link::ice
