#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace Ksword::Core {

// WorkspaceConfig is the versioned, fixed-width payload stored as a REG_BINARY
// value. It intentionally contains only stable, process-independent state so
// restoring it never requires a driver, a dock, or a window handle.
inline constexpr std::size_t kWorkspaceConfigBinarySize = 36U;
inline constexpr std::uint16_t kWorkspaceConfigVersion = 1U;
inline constexpr std::uint16_t kWorkspaceConfigDeclaredSize = 36U;

inline constexpr std::uint32_t kWorkspaceConfigFlagHasNormalRect = 0x00000001U;
inline constexpr std::uint32_t kWorkspaceConfigFlagMaximized = 0x00000002U;

using WorkspaceCommandId = std::int32_t;
using WorkspaceConfigBinary = std::array<std::uint8_t, kWorkspaceConfigBinarySize>;

// WorkspaceNormalRect mirrors the four persisted i32 coordinates without
// importing Win32 RECT into the pure configuration/test surface. Negative
// positions are valid for secondary monitors.
struct WorkspaceNormalRect final {
    std::int32_t left = 0;
    std::int32_t top = 0;
    std::int32_t right = 0;
    std::int32_t bottom = 0;
};

struct WorkspaceConfig final {
    bool hasNormalRect = false;
    WorkspaceNormalRect normalRect;
    bool maximized = false;
    WorkspaceCommandId activeCommandId = 0;
};

enum class WorkspaceConfigDecodeStatus : std::uint8_t {
    Valid,
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidDeclaredSize,
    InvalidFlags,
    InvalidReserved
};

struct WorkspaceConfigDecodeResult final {
    WorkspaceConfigDecodeStatus status = WorkspaceConfigDecodeStatus::InvalidLength;
    WorkspaceConfig config;
    bool discardedNormalRect = false;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return status == WorkspaceConfigDecodeStatus::Valid;
    }
};

// IsWorkspaceNormalRectValid accepts geometrically valid restore bounds only.
// It intentionally does not impose a work-area or monitor-size policy: those
// are runtime/UI concerns and would make old saved layouts less portable.
bool IsWorkspaceNormalRectValid(const WorkspaceNormalRect& rect) noexcept;

// SerializeWorkspaceConfig emits exactly 36 bytes in the documented order:
// KSLW, u16 version, u16 size, u32 flags, four i32 coordinates, i32 command
// id, u32 reserved. Every multibyte field is explicitly little-endian; no C++
// struct layout or reinterpret cast participates in the wire format.
WorkspaceConfigBinary SerializeWorkspaceConfig(const WorkspaceConfig& config) noexcept;

// DeserializeWorkspaceConfig rejects malformed headers, unknown flags, and a
// nonzero reserved word. A malformed normal rectangle is recoverable: it is
// dropped while maximized and active-command state remain available.
WorkspaceConfigDecodeResult DeserializeWorkspaceConfig(std::span<const std::uint8_t> bytes) noexcept;

// ResolveWorkspaceCommandId restores a saved stable command id against the
// currently available command-id set. If it is unavailable, a supplied stable
// fallback wins; otherwise the smallest nonzero available id is chosen so a
// module-order change cannot alter the fallback result.
WorkspaceCommandId ResolveWorkspaceCommandId(
    WorkspaceCommandId savedCommandId,
    std::span<const WorkspaceCommandId> availableCommandIds,
    WorkspaceCommandId fallbackCommandId = 0) noexcept;

} // namespace Ksword::Core
