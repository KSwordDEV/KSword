#include "WorkspaceConfig.h"

#include <limits>

namespace Ksword::Core {
namespace {

constexpr std::size_t kMagicOffset = 0U;
constexpr std::size_t kVersionOffset = 4U;
constexpr std::size_t kDeclaredSizeOffset = 6U;
constexpr std::size_t kFlagsOffset = 8U;
constexpr std::size_t kRectLeftOffset = 12U;
constexpr std::size_t kRectTopOffset = 16U;
constexpr std::size_t kRectRightOffset = 20U;
constexpr std::size_t kRectBottomOffset = 24U;
constexpr std::size_t kActiveCommandIdOffset = 28U;
constexpr std::size_t kReservedOffset = 32U;

constexpr std::uint8_t kMagic[] = { static_cast<std::uint8_t>('K'), static_cast<std::uint8_t>('S'),
    static_cast<std::uint8_t>('L'), static_cast<std::uint8_t>('W') };
constexpr std::uint32_t kKnownFlags = kWorkspaceConfigFlagHasNormalRect | kWorkspaceConfigFlagMaximized;

void WriteU16Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value & 0x00FFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0x00FFU);
}

void WriteU32Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::uint32_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value & 0x000000FFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU);
    bytes[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU);
}

void WriteI32Le(WorkspaceConfigBinary& bytes, const std::size_t offset, const std::int32_t value) noexcept {
    WriteU32Le(bytes, offset, static_cast<std::uint32_t>(value));
}

std::uint16_t ReadU16Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
}

std::uint32_t ReadU32Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
        (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

std::int32_t ReadI32Le(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    const std::uint32_t value = ReadU32Le(bytes, offset);
    if ((value & 0x80000000U) == 0U) {
        return static_cast<std::int32_t>(value);
    }
    if (value == 0x80000000U) {
        return (std::numeric_limits<std::int32_t>::min)();
    }
    const std::uint32_t magnitude = (~value) + 1U;
    return -static_cast<std::int32_t>(magnitude);
}

bool HasCommandId(
    const std::span<const WorkspaceCommandId> availableCommandIds,
    const WorkspaceCommandId commandId) noexcept {
    if (commandId == 0) {
        return false;
    }
    for (const WorkspaceCommandId availableCommandId : availableCommandIds) {
        if (availableCommandId == commandId) {
            return true;
        }
    }
    return false;
}

} // namespace

bool IsWorkspaceNormalRectValid(const WorkspaceNormalRect& rect) noexcept {
    return rect.right > rect.left && rect.bottom > rect.top;
}

WorkspaceConfigBinary SerializeWorkspaceConfig(const WorkspaceConfig& config) noexcept {
    WorkspaceConfigBinary bytes{};
    for (std::size_t index = 0U; index < sizeof(kMagic); ++index) {
        bytes[kMagicOffset + index] = kMagic[index];
    }
    WriteU16Le(bytes, kVersionOffset, kWorkspaceConfigVersion);
    WriteU16Le(bytes, kDeclaredSizeOffset, kWorkspaceConfigDeclaredSize);

    const bool persistNormalRect = config.hasNormalRect && IsWorkspaceNormalRectValid(config.normalRect);
    std::uint32_t flags = config.maximized ? kWorkspaceConfigFlagMaximized : 0U;
    if (persistNormalRect) {
        flags |= kWorkspaceConfigFlagHasNormalRect;
    }
    WriteU32Le(bytes, kFlagsOffset, flags);
    WriteI32Le(bytes, kRectLeftOffset, persistNormalRect ? config.normalRect.left : 0);
    WriteI32Le(bytes, kRectTopOffset, persistNormalRect ? config.normalRect.top : 0);
    WriteI32Le(bytes, kRectRightOffset, persistNormalRect ? config.normalRect.right : 0);
    WriteI32Le(bytes, kRectBottomOffset, persistNormalRect ? config.normalRect.bottom : 0);
    WriteI32Le(bytes, kActiveCommandIdOffset, config.activeCommandId);
    WriteU32Le(bytes, kReservedOffset, 0U);
    return bytes;
}

WorkspaceConfigDecodeResult DeserializeWorkspaceConfig(const std::span<const std::uint8_t> bytes) noexcept {
    WorkspaceConfigDecodeResult result{};
    if (bytes.size() != kWorkspaceConfigBinarySize) {
        return result;
    }
    for (std::size_t index = 0U; index < sizeof(kMagic); ++index) {
        if (bytes[kMagicOffset + index] != kMagic[index]) {
            result.status = WorkspaceConfigDecodeStatus::InvalidMagic;
            return result;
        }
    }
    if (ReadU16Le(bytes, kVersionOffset) != kWorkspaceConfigVersion) {
        result.status = WorkspaceConfigDecodeStatus::UnsupportedVersion;
        return result;
    }
    if (ReadU16Le(bytes, kDeclaredSizeOffset) != kWorkspaceConfigDeclaredSize) {
        result.status = WorkspaceConfigDecodeStatus::InvalidDeclaredSize;
        return result;
    }
    const std::uint32_t flags = ReadU32Le(bytes, kFlagsOffset);
    if ((flags & ~kKnownFlags) != 0U) {
        result.status = WorkspaceConfigDecodeStatus::InvalidFlags;
        return result;
    }
    if (ReadU32Le(bytes, kReservedOffset) != 0U) {
        result.status = WorkspaceConfigDecodeStatus::InvalidReserved;
        return result;
    }

    result.config.maximized = (flags & kWorkspaceConfigFlagMaximized) != 0U;
    result.config.activeCommandId = ReadI32Le(bytes, kActiveCommandIdOffset);
    if ((flags & kWorkspaceConfigFlagHasNormalRect) != 0U) {
        const WorkspaceNormalRect rect{
            ReadI32Le(bytes, kRectLeftOffset),
            ReadI32Le(bytes, kRectTopOffset),
            ReadI32Le(bytes, kRectRightOffset),
            ReadI32Le(bytes, kRectBottomOffset)
        };
        if (IsWorkspaceNormalRectValid(rect)) {
            result.config.hasNormalRect = true;
            result.config.normalRect = rect;
        } else {
            result.discardedNormalRect = true;
        }
    }
    result.status = WorkspaceConfigDecodeStatus::Valid;
    return result;
}

WorkspaceCommandId ResolveWorkspaceCommandId(
    const WorkspaceCommandId savedCommandId,
    const std::span<const WorkspaceCommandId> availableCommandIds,
    const WorkspaceCommandId fallbackCommandId) noexcept {
    if (HasCommandId(availableCommandIds, savedCommandId)) {
        return savedCommandId;
    }
    if (HasCommandId(availableCommandIds, fallbackCommandId)) {
        return fallbackCommandId;
    }

    WorkspaceCommandId resolved = 0;
    for (const WorkspaceCommandId availableCommandId : availableCommandIds) {
        if (availableCommandId != 0 && (resolved == 0 || availableCommandId < resolved)) {
            resolved = availableCommandId;
        }
    }
    return resolved;
}

} // namespace Ksword::Core
