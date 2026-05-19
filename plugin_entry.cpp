// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/plugin_entry.cpp
/// @brief  Plugin entry surface for `link-ice`.
///
/// Hand-rolled instead of using `GN_LINK_PLUGIN` because ICE registers
/// two extensions: the standard `gn.link.ice` (stats / send / close)
/// the kernel snapshots from every link, plus `gn.link.ice.signal`
/// for peer-to-peer offer / answer delivery.

#include "link_ice.hpp"

#include <sdk/abi.h>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <vector>

namespace {

using ::gn::link::ice::IceLink;
using ::gn::link::ice::gn_link_ice_signal_api_t;
using ::gn::link::ice::gn_link_ice_path_mtu_api_t;
using ::gn::link::ice::kIceSignalVersion;
using ::gn::link::ice::kIcePathMtuVersion;

constexpr const char* kIceScheme            = "ice";
constexpr const char* kIceLinkExtensionName = "gn.link.ice";
constexpr const char* kIceSignalExtensionName = "gn.link.ice.signal";
constexpr const char* kIcePathMtuExtensionName = "gn.link.ice.path_mtu";
constexpr const char* kPluginName           = "goodnet_link_ice";

struct IcePlugin {
    const host_api_t*           api                       = nullptr;
    void*                       host_ctx                  = nullptr;
    std::shared_ptr<IceLink>    link;
    gn_link_id_t                link_id                  = GN_INVALID_ID;
    gn_link_caps_t              caps                      = {};
    gn_link_vtable_t            link_vtable               = {};
    gn_link_api_t               link_extension_vtable     = {};
    gn_link_ice_signal_api_t    signal_extension_vtable   = {};
    gn_link_ice_path_mtu_api_t  path_mtu_extension_vtable = {};
    bool                        link_extension_registered    = false;
    bool                        signal_extension_registered  = false;
    bool                        path_mtu_extension_registered = false;
};

// ── kernel-facing gn_link_vtable_t thunks ───────────────────────────────────

const char* link_scheme(void* /*self*/) {
    return kIceScheme;
}

gn_result_t link_listen(void* self, const char* uri) noexcept {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(self);
        return p->link->listen(uri);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_connect(void* self, const char* uri) noexcept {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(self);
        return p->link->connect(uri);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_send(void* self, gn_conn_id_t conn,
                       const std::uint8_t* bytes, std::size_t size) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(self);
        return p->link->send(conn, std::span<const std::uint8_t>(bytes, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_send_batch(void* self, gn_conn_id_t conn,
                              const gn_byte_span_t* batch,
                              std::size_t count) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(self);
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return p->link->send_batch(conn,
            std::span<const std::span<const std::uint8_t>>(frames));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_disconnect(void* self, gn_conn_id_t conn) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(self);
        return p->link->disconnect(conn);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

const char* link_extension_name(void* /*self*/) noexcept {
    return kIceLinkExtensionName;
}

const void* link_extension_vtable(void* self) noexcept {
    if (!self) return nullptr;
    return &static_cast<IcePlugin*>(self)->link_extension_vtable;
}

void link_destroy(void* /*self*/) noexcept {
    /// Lifetime is owned by `gn_plugin_shutdown`; this slot is the
    /// link-vtable destructor path, not the plugin destructor.
}

// ── gn.link.ice (stats / capabilities / send / close) thunks ───────────────

gn_result_t link_ext_get_stats(void* ctx, gn_link_stats_t* out) noexcept {
    if (!ctx || !out) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        const auto s = p->link->stats();
        std::memset(out, 0, sizeof(*out));
        out->bytes_in           = s.bytes_in;
        out->bytes_out          = s.bytes_out;
        out->frames_in          = s.frames_in;
        out->frames_out         = s.frames_out;
        out->active_connections = s.active_connections;
        return GN_OK;
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_get_caps(void* ctx, gn_link_caps_t* out) noexcept {
    if (!ctx || !out) return GN_ERR_NULL_ARG;
    *out = static_cast<IcePlugin*>(ctx)->caps;
    return GN_OK;
}

gn_result_t link_ext_send(void* ctx, gn_conn_id_t conn,
                           const std::uint8_t* bytes,
                           std::size_t size) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->send(conn, std::span<const std::uint8_t>(bytes, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_send_batch(void* ctx, gn_conn_id_t conn,
                                 const gn_byte_span_t* batch,
                                 std::size_t count) noexcept {
    return link_send_batch(ctx, conn, batch, count);
}

gn_result_t link_ext_close(void* ctx, gn_conn_id_t conn, int /*hard*/) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->disconnect(conn);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_listen(void* ctx, const char* uri) noexcept {
    if (!ctx || !uri) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_listen(uri);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_connect(void* ctx, const char* uri,
                                        gn_conn_id_t* out_conn) noexcept {
    if (!ctx || !uri || !out_conn) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_connect(uri, out_conn);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_subscribe_data(
    void* ctx, gn_conn_id_t conn,
    gn_link_data_cb_t cb, void* user_data) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_subscribe_data(conn, cb, user_data);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_unsubscribe_data(
    void* ctx, gn_conn_id_t conn) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_unsubscribe_data(conn);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_subscribe_accept(
    void* ctx, gn_link_accept_cb_t cb, void* user_data,
    gn_subscription_id_t* out_token) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_subscribe_accept(cb, user_data, out_token);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_unsubscribe_accept(
    void* ctx, gn_subscription_id_t token) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_unsubscribe_accept(token);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_ext_composer_listen_port(void* ctx,
                                            std::uint16_t* out_port) noexcept {
    if (!ctx || !out_port) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->composer_listen_port(out_port);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

// ── gn.link.ice.signal thunks ─────────────────────────────────────────────

gn_result_t signal_ext_offer(void* ctx,
                               const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                               const std::uint8_t* blob,
                               std::size_t size) {
    if (!ctx || !peer_pk) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->deliver_signal(
            peer_pk, ::gn::link::ice::ICE_SIGNAL_OFFER,
            std::span<const std::uint8_t>(blob, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t signal_ext_answer(void* ctx,
                                const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                                const std::uint8_t* blob,
                                std::size_t size) {
    if (!ctx || !peer_pk) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->deliver_signal(
            peer_pk, ::gn::link::ice::ICE_SIGNAL_ANSWER,
            std::span<const std::uint8_t>(blob, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t signal_ext_offer_eoc(void* ctx,
                                   const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                                   const std::uint8_t* blob,
                                   std::size_t size) {
    if (!ctx || !peer_pk) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->deliver_signal(
            peer_pk, ::gn::link::ice::ICE_SIGNAL_OFFER_EOC,
            std::span<const std::uint8_t>(blob, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t signal_ext_answer_eoc(void* ctx,
                                     const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                                     const std::uint8_t* blob,
                                     std::size_t size) {
    if (!ctx || !peer_pk) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->deliver_signal(
            peer_pk, ::gn::link::ice::ICE_SIGNAL_ANSWER_EOC,
            std::span<const std::uint8_t>(blob, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t signal_ext_poll_local(void* ctx,
                                     const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                                     std::uint32_t* kind_out,
                                     std::uint8_t* blob_out,
                                     std::size_t blob_cap,
                                     std::size_t* blob_len_out) {
    if (!ctx || !peer_pk || !kind_out || !blob_len_out) return GN_ERR_NULL_ARG;
    if (blob_cap > 0 && !blob_out) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        return p->link->poll_local_signal(peer_pk, kind_out,
                                            blob_out, blob_cap, blob_len_out);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

void install_link_extension(IcePlugin* p) {
    auto& v = p->link_extension_vtable;
    v                  = gn_link_api_t{};
    v.api_size         = sizeof(gn_link_api_t);
    v.get_stats        = &link_ext_get_stats;
    v.get_capabilities = &link_ext_get_caps;
    v.send             = &link_ext_send;
    v.send_batch       = &link_ext_send_batch;
    v.close            = &link_ext_close;
    /// Composer surface — L2 plugins can `composer_connect`
    /// over this ICE link to ride a NAT-traversed UDP pair as a
    /// reliable / encrypted stream carrier (QUIC, DTLS).
    v.listen             = &link_ext_composer_listen;
    v.connect            = &link_ext_composer_connect;
    v.subscribe_data     = &link_ext_composer_subscribe_data;
    v.unsubscribe_data   = &link_ext_composer_unsubscribe_data;
    v.subscribe_accept   = &link_ext_composer_subscribe_accept;
    v.unsubscribe_accept = &link_ext_composer_unsubscribe_accept;
    v.composer_listen_port = &link_ext_composer_listen_port;
    v.ctx = p;
}

gn_result_t path_mtu_ext_get(void* ctx, gn_conn_id_t conn,
                                std::uint32_t* out_mtu) noexcept {
    if (!ctx || !out_mtu) return GN_ERR_NULL_ARG;
    try {
        auto* p = static_cast<IcePlugin*>(ctx);
        *out_mtu = p->link->effective_path_mtu(conn);
        return GN_OK;
    } catch (...) { return GN_ERR_NULL_ARG; }
}

void install_path_mtu_extension(IcePlugin* p) {
    auto& v = p->path_mtu_extension_vtable;
    v          = gn_link_ice_path_mtu_api_t{};
    v.api_size = sizeof(gn_link_ice_path_mtu_api_t);
    v.get      = &path_mtu_ext_get;
    v.ctx      = p;
}

void install_signal_extension(IcePlugin* p) {
    auto& v = p->signal_extension_vtable;
    v               = gn_link_ice_signal_api_t{};
    v.api_size      = sizeof(gn_link_ice_signal_api_t);
    v.offer         = &signal_ext_offer;
    v.answer        = &signal_ext_answer;
    v.offer_eoc     = &signal_ext_offer_eoc;
    v.answer_eoc    = &signal_ext_answer_eoc;
    v.poll_local    = &signal_ext_poll_local;
    v.ctx           = p;
}

void install_link_vtable(IcePlugin* p) {
    auto& v = p->link_vtable;
    v                 = gn_link_vtable_t{};
    v.api_size        = sizeof(gn_link_vtable_t);
    v.scheme          = &link_scheme;
    v.listen          = &link_listen;
    v.connect         = &link_connect;
    v.send            = &link_send;
    v.send_batch      = &link_send_batch;
    v.disconnect      = &link_disconnect;
    v.extension_name  = &link_extension_name;
    v.extension_vtable = &link_extension_vtable;
    v.destroy         = &link_destroy;
}

const char* const kProvidesList[] = {
    kIceLinkExtensionName,
    kIceSignalExtensionName,
    kIcePathMtuExtensionName,
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ kPluginName,
    /* version           */ "0.1.0",
    /* hot_reload_safe   */ 0,
    /* ext_requires      */ nullptr,
    /* ext_provides      */ kProvidesList,
    /* kind              */ GN_PLUGIN_KIND_LINK,
    /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

extern "C" {

GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(std::uint32_t* major,
                                              std::uint32_t* minor,
                                              std::uint32_t* patch) {
    if (major) *major = GN_SDK_VERSION_MAJOR;
    if (minor) *minor = GN_SDK_VERSION_MINOR;
    if (patch) *patch = GN_SDK_VERSION_PATCH;
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(const host_api_t* api,
                                              void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;
    auto* p = new (std::nothrow) IcePlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    try {
        p->api      = api;
        p->host_ctx = api->host_ctx;
        p->link     = std::make_shared<IceLink>();
        p->link->set_host_api(api);
        p->caps     = IceLink::capabilities();
        install_link_extension(p);
        install_signal_extension(p);
        install_path_mtu_extension(p);
        install_link_vtable(p);
        *out_self = p;
        return GN_OK;
    } catch (...) {
        delete p;
        return GN_ERR_OUT_OF_MEMORY;
    }
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<IcePlugin*>(self);
    if (!p->api || !p->api->register_vtable) return GN_ERR_NOT_IMPLEMENTED;

    gn_register_meta_t meta{};
    meta.api_size = sizeof(gn_register_meta_t);
    meta.name     = kIceScheme;
    if (auto rc = p->api->register_vtable(
            p->host_ctx, GN_REGISTER_LINK, &meta,
            &p->link_vtable, p, &p->link_id);
        rc != GN_OK) {
        return rc;
    }

    if (p->api->register_extension) {
        if (p->api->register_extension(
                p->host_ctx, kIceLinkExtensionName,
                GN_EXT_LINK_VERSION, &p->link_extension_vtable) == GN_OK) {
            p->link_extension_registered = true;
        }
        if (p->api->register_extension(
                p->host_ctx, kIceSignalExtensionName,
                kIceSignalVersion, &p->signal_extension_vtable) == GN_OK) {
            p->signal_extension_registered = true;
        }
        if (p->api->register_extension(
                p->host_ctx, kIcePathMtuExtensionName,
                kIcePathMtuVersion, &p->path_mtu_extension_vtable) == GN_OK) {
            p->path_mtu_extension_registered = true;
        }
    }
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<IcePlugin*>(self);
    if (p->path_mtu_extension_registered &&
        p->api && p->api->unregister_extension) {
        (void)p->api->unregister_extension(p->host_ctx, kIcePathMtuExtensionName);
        p->path_mtu_extension_registered = false;
    }
    if (p->signal_extension_registered &&
        p->api && p->api->unregister_extension) {
        (void)p->api->unregister_extension(p->host_ctx, kIceSignalExtensionName);
        p->signal_extension_registered = false;
    }
    if (p->link_extension_registered &&
        p->api && p->api->unregister_extension) {
        (void)p->api->unregister_extension(p->host_ctx, kIceLinkExtensionName);
        p->link_extension_registered = false;
    }
    if (p->api && p->api->unregister_vtable && p->link_id != GN_INVALID_ID) {
        (void)p->api->unregister_vtable(p->host_ctx, p->link_id);
        p->link_id = GN_INVALID_ID;
    }
    if (p->link) p->link->shutdown();
    return GN_OK;
}

GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {
    delete static_cast<IcePlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* GN_PLUGIN_DESCRIPTOR_NAME(void) {
    return &kDescriptor;
}

}  // extern "C"
