// SPDX-License-Identifier: GPL-2.0-only WITH GoodNet-linking-exception
/// @file   plugins/links/ice/path_mtu.cpp

#include "path_mtu.hpp"

#include <algorithm>

namespace gn::link::ice {

PathMtuProbe::PathMtuProbe(std::size_t base,
                             std::vector<int> steps) noexcept
    : base_(base),
      steps_(std::move(steps)) {
    /// Sort + dedupe + drop entries below the conservative base. The
    /// base itself is the FSM's starting `effective_mtu` so the
    /// search only walks values strictly above it.
    std::sort(steps_.begin(), steps_.end());
    steps_.erase(std::unique(steps_.begin(), steps_.end()), steps_.end());
    steps_.erase(std::remove_if(steps_.begin(), steps_.end(),
                                  [&](int v) {
                                      return v <= 0
                                          || static_cast<std::size_t>(v) <= base_;
                                  }),
                  steps_.end());
    effective_ = base_;
    if (steps_.empty()) {
        state_ = PathMtuState::SearchComplete;
        return;
    }
    state_ = PathMtuState::Searching;
    ladder_idx_ = 0;
    current_    = static_cast<std::size_t>(steps_[ladder_idx_]);
}

std::optional<std::size_t> PathMtuProbe::next_probe_size() const noexcept {
    if (state_ == PathMtuState::SearchComplete) return std::nullopt;
    if (current_ == 0) return std::nullopt;
    return current_;
}

void PathMtuProbe::on_probe_ack() noexcept {
    if (state_ == PathMtuState::SearchComplete) return;
    /// The probe size travelled end-to-end: promote `effective_` and
    /// reset the loss streak.
    effective_  = current_;
    loss_count_ = 0;

    if (high_ != 0) {
        /// Bisecting between the last failing size and the now-known
        /// good `current_`. If the surviving window is narrower than
        /// the granularity threshold we are done.
        low_ = current_;
        if (high_ - low_ <= kProbeGranularity) {
            state_   = PathMtuState::SearchComplete;
            current_ = 0;
            return;
        }
        current_ = (low_ + high_) / 2;
        state_   = PathMtuState::Searching;
        return;
    }

    /// Linear ladder walk. Advance to the next rung; if exhausted,
    /// the largest rung confirmed is the final answer.
    if (ladder_idx_ + 1 >= steps_.size()) {
        state_   = PathMtuState::SearchComplete;
        current_ = 0;
        return;
    }
    ++ladder_idx_;
    current_ = static_cast<std::size_t>(steps_[ladder_idx_]);
    state_   = PathMtuState::Searching;
}

void PathMtuProbe::on_probe_loss() noexcept {
    if (state_ == PathMtuState::SearchComplete) return;
    ++loss_count_;
    if (loss_count_ < kProbeLossThreshold) return;
    /// Two consecutive losses at the same probe size — declare the
    /// size unsupported and halve the active candidate. RFC 8899
    /// §5.2 calls this the ERROR state; we re-enter SEARCHING with
    /// the halved value as the new high-water bisection bound.
    loss_count_ = 0;
    state_      = PathMtuState::Error;

    high_ = current_;
    low_  = effective_;
    /// Bisection between known-good `effective_` and known-bad
    /// `current_`. When the unconfirmed window has collapsed below
    /// the granularity, the search is complete at the existing
    /// `effective_`.
    if (high_ - low_ <= kProbeGranularity) {
        state_   = PathMtuState::SearchComplete;
        current_ = 0;
        return;
    }
    current_ = (low_ + high_) / 2;
    state_   = PathMtuState::Searching;
}

}  // namespace gn::link::ice
