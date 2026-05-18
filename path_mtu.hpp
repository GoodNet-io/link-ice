// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
#pragma once
/// @file   plugins/links/ice/path_mtu.hpp
/// @brief  Active path-MTU discovery per RFC 8899 (DPLPMTUD).
///
/// The probe is a padded STUN binding REQUEST shaped to the candidate
/// MTU under test. The peer replies with an ordinary binding
/// response (RFC 8445 connectivity-check semantics); the response
/// arriving within `probe_timeout_ms` is treated as proof the path
/// supports the probe size.
///
/// State machine — RFC 8899 §5:
///   BASE             initial state, `effective_mtu` = base.
///   SEARCHING        a probe is in flight; waiting for ACK or loss.
///   SEARCH_COMPLETE  the ladder is exhausted or the binary search
///                    converged within `kProbeGranularity`.
///   ERROR            two consecutive losses at the same size; halve
///                    the search and re-enter SEARCHING.
///
/// The class is data-only; the owning `IceSession` drives the probe
/// transmission and timer arming. `next_probe_size()` returns the
/// candidate MTU to fire next; `on_probe_ack()` / `on_probe_loss()`
/// update the search; `is_complete()` ends the active phase.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace gn::link::ice {

/// Binary-search convergence threshold per RFC 8899 §5.1.4.
inline constexpr std::size_t kProbeGranularity = 8;

/// Consecutive losses at the same probe size before the FSM treats
/// the size as unsupported and halves the candidate (RFC 8899 §5.2).
inline constexpr std::uint32_t kProbeLossThreshold = 2;

enum class PathMtuState : std::uint8_t {
    Base,
    Searching,
    SearchComplete,
    Error,
};

class PathMtuProbe {
public:
    /// @param base     The conservative starting MTU (`IceConfig::path_mtu`).
    /// @param steps    Ascending ladder of candidate MTUs in bytes.
    PathMtuProbe(std::size_t base,
                 std::vector<int> steps) noexcept;

    PathMtuProbe(const PathMtuProbe&)            = delete;
    PathMtuProbe& operator=(const PathMtuProbe&) = delete;
    PathMtuProbe(PathMtuProbe&&) noexcept            = default;
    PathMtuProbe& operator=(PathMtuProbe&&) noexcept = default;

    /// Next candidate size to probe, in bytes. nullopt when the FSM
    /// is in `SearchComplete` — no further active probing required.
    [[nodiscard]] std::optional<std::size_t> next_probe_size() const noexcept;

    /// Successful round-trip at the most recently issued probe size.
    /// Promotes `effective_mtu` and advances the search.
    void on_probe_ack() noexcept;

    /// Loss (timer expired without a matching response) at the most
    /// recently issued probe size. Two consecutive losses at the same
    /// size halve the candidate; the search resumes from the halved
    /// value.
    void on_probe_loss() noexcept;

    [[nodiscard]] std::size_t effective_mtu() const noexcept { return effective_; }
    [[nodiscard]] PathMtuState state() const noexcept { return state_; }
    [[nodiscard]] bool is_complete() const noexcept {
        return state_ == PathMtuState::SearchComplete;
    }

private:
    std::size_t      base_;
    std::vector<int> steps_;
    /// Index into `steps_` of the candidate currently under probe.
    /// When the search bisects (after a loss-halve), `low_` and
    /// `high_` bracket the unconfirmed region between two ladder
    /// rungs.
    std::size_t      ladder_idx_ = 0;
    std::size_t      low_        = 0;
    std::size_t      high_       = 0;
    std::size_t      current_    = 0;
    std::size_t      effective_  = 0;
    std::uint32_t    loss_count_ = 0;
    PathMtuState     state_      = PathMtuState::Base;
};

}  // namespace gn::link::ice
