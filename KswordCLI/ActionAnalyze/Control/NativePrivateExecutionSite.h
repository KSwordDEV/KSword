#pragma once

#include "NativeBreakpointImage.h"

namespace ks::cli::action_analyze::control {

// One immutable observation of an AMD64 image data export and its private
// execution destination. VirtualQueryEx does not supply an allocation generation.
struct NativePrivateExecutionSite {
    NativeImageSite site;
    std::uint32_t allocationProtection = 0;
    std::uintptr_t selectorRegionBase = 0;
    std::size_t selectorRegionBytes = 0;
    std::uint32_t selectorProtection = 0;
};

// The export contains an aligned 64-bit pointer, not instruction bytes. Accepts
// non-executable readable image data, including read-only data exports. The
// destination must be committed MEM_PRIVATE with EXECUTE/RX/RWX protection.
// Never modifies protection, writes code, follows pointer changes or rebinds.
// A nonzero eventImageBase must come from a debug event with verified file identity.
[[nodiscard]] DWORD ResolveNativePrivateExecutionSite(HANDLE process, DWORD pid, std::wstring_view modulePath,
    std::string_view exportName, NativePrivateExecutionSite& result, std::uintptr_t eventImageBase = 0);

// Intended only while NativeDebugOwner holds a real debug event. Verifies the
// original selector and all frozen destination attributes; does not prove an
// unchanged allocation generation or unchanged executable content.
[[nodiscard]] DWORD VerifyNativePrivateExecutionSite(HANDLE process, const NativePrivateExecutionSite& frozen);

} // namespace ks::cli::action_analyze::control
