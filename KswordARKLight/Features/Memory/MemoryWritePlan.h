#pragma once

#include "MemorySnapshot.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Memory {

// kMemoryWritePlanBlockBytes keeps one controlled writeback chunk small enough
// for a focused preflight/readback verification. It is below the shared driver
// maximum and is a local policy, not a protocol or OS requirement.
constexpr std::size_t kMemoryWritePlanBlockBytes = 4U * 1024U;

// MemoryWriteBlock describes one contiguous changed range from an immutable
// read snapshot. expectedBefore is re-read immediately before a write; desiredAfter
// is re-read immediately afterwards. Neither vector may be empty or differ in
// length, which prevents a plan from silently growing or shrinking a snapshot.
struct MemoryWriteBlock final {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> expectedBefore;
    std::vector<std::uint8_t> desiredAfter;
};

// MemoryWritePlan freezes the PID/base identity of a successful read snapshot
// and stores only its changed byte ranges. desiredSnapshotBytes supports one
// final exact readback before a successful writeback becomes a new snapshot.
struct MemoryWritePlan final {
    std::uint64_t snapshotSequence = 0;
    std::uint32_t processId = 0;
    std::uint64_t baseAddress = 0;
    std::vector<std::uint8_t> desiredSnapshotBytes;
    std::vector<MemoryWriteBlock> blocks;
    std::size_t changedByteCount = 0;
};

// BuildMemoryWritePlan compares an immutable successful snapshot against a
// same-length editable byte buffer. It merges adjacent differences, splits them
// to the supplied bound, and freezes the snapshot PID/base rather than accepting
// mutable UI target fields. A zero-difference result is valid and has no blocks.
bool BuildMemoryWritePlan(
    const MemoryReadSnapshot& snapshot,
    const std::vector<std::uint8_t>& editedBytes,
    std::size_t maximumBlockBytes,
    MemoryWritePlan& planOut,
    std::wstring& errorText);

// ValidateMemoryWritePlan checks a plan before it can reach a driver facade.
// It protects against malformed ranges, inconsistent block payloads, overlap,
// and desired-byte drift without relying on raw UI state.
bool ValidateMemoryWritePlan(const MemoryWritePlan& plan, std::wstring& errorText);

} // namespace Ksword::Features::Memory
