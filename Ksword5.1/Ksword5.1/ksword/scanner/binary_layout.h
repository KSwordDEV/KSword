#pragma once

#include "binary_scanner.h"
#include <algorithm>
#include <limits>
#include <optional>

namespace ks::scanner
{
    // No wrapping arithmetic, guessed mapping of gaps, or fabricated BSS bytes.
    // Ambiguous overlapping headers/sections are deliberately not mapped.
    inline std::optional<std::uint64_t> FileOffsetToRva(
        const BinaryScanResult& layout, const std::uint64_t fileOffset)
    {
        if (fileOffset >= layout.fileSize) return std::nullopt;
        std::optional<std::uint64_t> result;
        for (const auto& region : layout.mappedRegions)
        {
            if (!region.mapped || fileOffset < region.fileOffset ||
                fileOffset - region.fileOffset >= region.fileSize) continue;
            const auto delta = fileOffset - region.fileOffset;
            const auto mappedBytes = region.virtualSize == 0 ? region.fileSize
                : std::min(region.fileSize, region.virtualSize);
            if (delta >= mappedBytes) return std::nullopt;
            if (delta > std::numeric_limits<std::uint64_t>::max() - region.rva)
                return std::nullopt;
            const auto rva = region.rva + delta;
            if (rva > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
            if (result) return std::nullopt;
            result = rva;
        }
        return result;
    }

    inline std::optional<std::uint64_t> RvaToFileOffset(
        const BinaryScanResult& layout, const std::uint64_t rva)
    {
        if (rva > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        std::optional<std::uint64_t> result;
        for (const auto& region : layout.mappedRegions)
        {
            if (!region.mapped || rva < region.rva) continue;
            const auto delta = rva - region.rva;
            if (delta >= std::max(region.fileSize, region.virtualSize)) continue;
            // A virtual tail is present in memory only, and has no disk offset.
            const auto mappedBytes = region.virtualSize == 0 ? region.fileSize
                : std::min(region.fileSize, region.virtualSize);
            if (delta >= mappedBytes) return std::nullopt;
            if (delta > std::numeric_limits<std::uint64_t>::max() - region.fileOffset)
                return std::nullopt;
            const auto offset = region.fileOffset + delta;
            if (offset >= layout.fileSize || result) return std::nullopt;
            result = offset;
        }
        return result;
    }

    inline std::optional<std::uint64_t> FileOffsetToVa(
        const BinaryScanResult& layout, const std::uint64_t fileOffset)
    {
        const auto rva = FileOffsetToRva(layout, fileOffset);
        if (!rva || *rva > std::numeric_limits<std::uint64_t>::max() - layout.imageBase)
            return std::nullopt;
        return layout.imageBase + *rva;
    }

    inline std::optional<std::uint64_t> VaToFileOffset(
        const BinaryScanResult& layout, const std::uint64_t va)
    {
        if (va < layout.imageBase) return std::nullopt;
        return RvaToFileOffset(layout, va - layout.imageBase);
    }
}
