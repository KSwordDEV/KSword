#pragma once

#include "MemorySnapshot.h"

#include <cstddef>
#include <string>

namespace Ksword::Features::Memory {

// RenderMemorySnapshotHexAscii formats one immutable snapshot as an offset,
// hexadecimal-byte and printable-ASCII investigation view. It only consumes
// local snapshot bytes and never reads the target process again.
std::wstring RenderMemorySnapshotHexAscii(
    const MemoryReadSnapshot& snapshot,
    std::size_t bytesPerLine = 16U);

// ExtractMemorySnapshotText reports bounded printable ASCII and UTF-16LE runs
// from a local snapshot. The helper is intentionally conservative: it emits
// evidence rather than pretending every byte sequence is a decoded string.
std::wstring ExtractMemorySnapshotText(
    const MemoryReadSnapshot& snapshot,
    std::size_t minimumRunLength = 4U);

// BuildMemorySnapshotTextReport combines identity, transport status, hex/ASCII
// evidence and discovered text into one UTF-16 report suitable for copy/export.
std::wstring BuildMemorySnapshotTextReport(const MemoryReadSnapshot& snapshot);

} // namespace Ksword::Features::Memory
