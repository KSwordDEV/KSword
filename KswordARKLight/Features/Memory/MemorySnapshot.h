#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Memory {

// MemoryReadSnapshot is an immutable successful read result. The displayed
// bytes always belong to the target PID and base address captured here; a later
// navigation never silently performs another driver read against a reused PID.
struct MemoryReadSnapshot final {
    std::uint64_t sequence = 0;
    std::uint32_t processId = 0;
    std::uint64_t address = 0;
    std::size_t requestedBytes = 0;
    std::vector<std::uint8_t> bytes;
    std::wstring statusText;
};

// MemorySnapshotHistory owns a bounded browser history for successful virtual
// memory reads. It deliberately has no driver dependency: callers supply an
// already-completed read and the history provides deterministic back/forward
// navigation, forward-branch truncation, and a stable current snapshot.
class MemorySnapshotHistory final {
public:
    explicit MemorySnapshotHistory(std::size_t maximumSnapshots = 64U);

    // record adds one non-empty successful read and makes it current. Any
    // snapshots after the current cursor are removed first, matching normal
    // navigation semantics. Returns false when the input cannot represent a
    // trustworthy read snapshot.
    bool record(std::uint32_t processId,
        std::uint64_t address,
        std::size_t requestedBytes,
        std::vector<std::uint8_t> bytes,
        std::wstring statusText);

    bool canMovePrevious() const noexcept;
    bool canMoveNext() const noexcept;
    bool movePrevious() noexcept;
    bool moveNext() noexcept;

    const MemoryReadSnapshot* current() const noexcept;
    std::size_t size() const noexcept;
    std::size_t currentPosition() const noexcept;
    void clear() noexcept;

private:
    std::size_t maximumSnapshots_ = 64U;
    std::uint64_t nextSequence_ = 1U;
    std::vector<MemoryReadSnapshot> snapshots_;
    std::size_t currentIndex_ = 0U;
    bool hasCurrent_ = false;
};

} // namespace Ksword::Features::Memory
