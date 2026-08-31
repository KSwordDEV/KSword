#include "MemorySnapshot.h"

#include <algorithm>
#include <utility>

namespace Ksword::Features::Memory {

MemorySnapshotHistory::MemorySnapshotHistory(const std::size_t maximumSnapshots)
    : maximumSnapshots_((std::max)(std::size_t{ 1U }, maximumSnapshots)) {
}

bool MemorySnapshotHistory::record(const std::uint32_t processId,
    const std::uint64_t address,
    const std::size_t requestedBytes,
    std::vector<std::uint8_t> bytes,
    std::wstring statusText) {
    if (processId == 0U || requestedBytes == 0U || bytes.empty()) {
        return false;
    }

    if (hasCurrent_ && currentIndex_ + 1U < snapshots_.size()) {
        snapshots_.erase(snapshots_.begin() + static_cast<std::ptrdiff_t>(currentIndex_ + 1U), snapshots_.end());
    }

    MemoryReadSnapshot snapshot{};
    snapshot.sequence = nextSequence_++;
    snapshot.processId = processId;
    snapshot.address = address;
    snapshot.requestedBytes = requestedBytes;
    snapshot.bytes = std::move(bytes);
    snapshot.statusText = std::move(statusText);
    snapshots_.push_back(std::move(snapshot));

    if (snapshots_.size() > maximumSnapshots_) {
        const std::size_t excess = snapshots_.size() - maximumSnapshots_;
        snapshots_.erase(snapshots_.begin(), snapshots_.begin() + static_cast<std::ptrdiff_t>(excess));
    }

    currentIndex_ = snapshots_.empty() ? 0U : snapshots_.size() - 1U;
    hasCurrent_ = !snapshots_.empty();
    return hasCurrent_;
}

bool MemorySnapshotHistory::canMovePrevious() const noexcept {
    return hasCurrent_ && currentIndex_ > 0U;
}

bool MemorySnapshotHistory::canMoveNext() const noexcept {
    return hasCurrent_ && currentIndex_ + 1U < snapshots_.size();
}

bool MemorySnapshotHistory::movePrevious() noexcept {
    if (!canMovePrevious()) {
        return false;
    }
    --currentIndex_;
    return true;
}

bool MemorySnapshotHistory::moveNext() noexcept {
    if (!canMoveNext()) {
        return false;
    }
    ++currentIndex_;
    return true;
}

const MemoryReadSnapshot* MemorySnapshotHistory::current() const noexcept {
    if (!hasCurrent_ || currentIndex_ >= snapshots_.size()) {
        return nullptr;
    }
    return &snapshots_[currentIndex_];
}

std::size_t MemorySnapshotHistory::size() const noexcept {
    return snapshots_.size();
}

std::size_t MemorySnapshotHistory::currentPosition() const noexcept {
    return hasCurrent_ ? currentIndex_ + 1U : 0U;
}

void MemorySnapshotHistory::clear() noexcept {
    snapshots_.clear();
    currentIndex_ = 0U;
    hasCurrent_ = false;
}

} // namespace Ksword::Features::Memory
