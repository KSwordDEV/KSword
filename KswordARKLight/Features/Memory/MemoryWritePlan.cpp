#include "MemoryWritePlan.h"

#include <algorithm>
#include <limits>

namespace Ksword::Features::Memory {
namespace {

bool RangeFitsAddressSpace(const std::uint64_t baseAddress, const std::size_t byteCount) noexcept {
    return byteCount == 0U || baseAddress <= (std::numeric_limits<std::uint64_t>::max)() -
        static_cast<std::uint64_t>(byteCount - 1U);
}

void SetPlanError(std::wstring& errorText, const wchar_t* message) {
    errorText = message ? message : L"内存差异计划无效。";
}

} // namespace

bool BuildMemoryWritePlan(
    const MemoryReadSnapshot& snapshot,
    const std::vector<std::uint8_t>& editedBytes,
    const std::size_t maximumBlockBytes,
    MemoryWritePlan& planOut,
    std::wstring& errorText) {
    planOut = {};
    errorText.clear();
    if (snapshot.sequence == 0U || snapshot.processId == 0U || snapshot.bytes.empty()) {
        SetPlanError(errorText, L"读取快照缺少可写回的目标或字节。");
        return false;
    }
    if (editedBytes.size() != snapshot.bytes.size()) {
        SetPlanError(errorText, L"编辑字节数必须与读取快照完全一致。");
        return false;
    }
    if (maximumBlockBytes == 0U) {
        SetPlanError(errorText, L"差异块上限必须大于零。");
        return false;
    }
    if (!RangeFitsAddressSpace(snapshot.address, snapshot.bytes.size())) {
        SetPlanError(errorText, L"读取快照地址范围发生溢出，已拒绝写回。");
        return false;
    }

    MemoryWritePlan plan{};
    plan.snapshotSequence = snapshot.sequence;
    plan.processId = snapshot.processId;
    plan.baseAddress = snapshot.address;
    plan.desiredSnapshotBytes = editedBytes;

    std::size_t offset = 0U;
    while (offset < snapshot.bytes.size()) {
        if (snapshot.bytes[offset] == editedBytes[offset]) {
            ++offset;
            continue;
        }
        const std::size_t rangeStart = offset;
        while (offset < snapshot.bytes.size() && snapshot.bytes[offset] != editedBytes[offset]) {
            ++offset;
        }
        const std::size_t rangeEnd = offset;
        plan.changedByteCount += rangeEnd - rangeStart;

        for (std::size_t blockStart = rangeStart; blockStart < rangeEnd;) {
            const std::size_t blockBytes = (std::min)(maximumBlockBytes, rangeEnd - blockStart);
            MemoryWriteBlock block{};
            block.address = snapshot.address + static_cast<std::uint64_t>(blockStart);
            block.expectedBefore.assign(snapshot.bytes.begin() + static_cast<std::ptrdiff_t>(blockStart),
                snapshot.bytes.begin() + static_cast<std::ptrdiff_t>(blockStart + blockBytes));
            block.desiredAfter.assign(editedBytes.begin() + static_cast<std::ptrdiff_t>(blockStart),
                editedBytes.begin() + static_cast<std::ptrdiff_t>(blockStart + blockBytes));
            plan.blocks.push_back(std::move(block));
            blockStart += blockBytes;
        }
    }

    if (!ValidateMemoryWritePlan(plan, errorText)) {
        return false;
    }
    planOut = std::move(plan);
    return true;
}

bool ValidateMemoryWritePlan(const MemoryWritePlan& plan, std::wstring& errorText) {
    errorText.clear();
    if (plan.snapshotSequence == 0U || plan.processId == 0U || plan.desiredSnapshotBytes.empty()) {
        SetPlanError(errorText, L"差异计划缺少快照目标或期望字节。");
        return false;
    }
    if (!RangeFitsAddressSpace(plan.baseAddress, plan.desiredSnapshotBytes.size())) {
        SetPlanError(errorText, L"差异计划地址范围发生溢出。");
        return false;
    }

    std::size_t countedChanges = 0U;
    std::size_t previousEndOffset = 0U;
    bool hasPreviousBlock = false;
    for (const MemoryWriteBlock& block : plan.blocks) {
        if (block.expectedBefore.empty() || block.expectedBefore.size() != block.desiredAfter.size() ||
            block.address < plan.baseAddress) {
            SetPlanError(errorText, L"差异计划包含无效写入块。");
            return false;
        }
        const std::uint64_t relativeAddress = block.address - plan.baseAddress;
        if (relativeAddress > static_cast<std::uint64_t>(plan.desiredSnapshotBytes.size())) {
            SetPlanError(errorText, L"差异写入块超出快照范围。");
            return false;
        }
        const std::size_t offset = static_cast<std::size_t>(relativeAddress);
        if (block.expectedBefore.size() > plan.desiredSnapshotBytes.size() - offset ||
            (hasPreviousBlock && offset < previousEndOffset)) {
            SetPlanError(errorText, L"差异写入块重叠或超出快照范围。");
            return false;
        }
        if (!std::equal(block.desiredAfter.cbegin(), block.desiredAfter.cend(),
                plan.desiredSnapshotBytes.cbegin() + static_cast<std::ptrdiff_t>(offset))) {
            SetPlanError(errorText, L"差异写入块与期望快照字节不一致。");
            return false;
        }
        countedChanges += block.desiredAfter.size();
        previousEndOffset = offset + block.desiredAfter.size();
        hasPreviousBlock = true;
    }

    if (countedChanges != plan.changedByteCount || (plan.changedByteCount == 0U) != plan.blocks.empty()) {
        SetPlanError(errorText, L"差异计划统计信息不一致。");
        return false;
    }
    return true;
}

} // namespace Ksword::Features::Memory
