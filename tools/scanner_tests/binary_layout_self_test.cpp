#include "../../Ksword5.1/Ksword5.1/ksword/scanner/binary_layout.h"
#include <iostream>
#include <limits>

namespace
{
    int failures = 0;
    int checks = 0;
    void expect(bool condition, const char* message)
    {
        ++checks;
        if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
    }
}

int main()
{
    using namespace ks::scanner;
    BinaryScanResult layout;
    layout.fileSize = 0x1000;
    layout.imageBase = 0x140000000;
    layout.mappedRegions = {
        {"Headers", 0, 0x200, 0, 0x200, 0, 0.0, true, BinaryRegionKind::Headers},
        {".text", 0x400, 0x200, 0x1000, 0x400, 0x60000020, 0.0, true, BinaryRegionKind::Code},
        {".data", 0x800, 0x200, 0x3000, 0x100, 0xC0000040, 0.0, true, BinaryRegionKind::Data},
        {"Overlay", 0xC00, 0x400, 0, 0, 0, 0.0, false, BinaryRegionKind::Overlay}
    };
    expect(FileOffsetToRva(layout, 0) == 0, "header offset zero is a real mapping");
    expect(FileOffsetToVa(layout, 0x1FF) == 0x1400001FF, "last header byte has VA");
    expect(!FileOffsetToRva(layout, 0x200), "header end is exclusive");
    expect(!FileOffsetToRva(layout, 0x3FF), "raw alignment gap has no RVA");
    expect(FileOffsetToRva(layout, 0x400) == 0x1000, "raw section start maps to RVA");
    expect(FileOffsetToRva(layout, 0x5FF) == 0x11FF, "last physical section byte maps");
    expect(!RvaToFileOffset(layout, 0x1200), "virtual zero-fill cannot fabricate a byte");
    expect(!RvaToFileOffset(layout, 0x13FF), "last virtual zero-fill byte has no disk offset");
    expect(!RvaToFileOffset(layout, 0x1400), "virtual section end is exclusive");
    expect(!RvaToFileOffset(layout, 0x31FF), "raw alignment tail remains visible bytes but has no asserted VA");
    expect(!FileOffsetToVa(layout, 0x9FF), "raw padding is not presented as mapped virtual evidence");
    expect(!FileOffsetToVa(layout, 0xC00), "overlay is unmapped");
    expect(!FileOffsetToRva(layout, 0x1000), "EOF is not an addressable byte");
    expect(!VaToFileOffset(layout, layout.imageBase - 1), "VA below image base does not underflow");
    expect(!RvaToFileOffset(layout, 0x100000000ULL), "RVA remains a 32-bit PE quantity");
    bool roundTrip = true;
    for (const auto& region : layout.mappedRegions)
    {
        if (!region.mapped) continue;
        for (std::uint64_t delta = 0; delta < std::min(region.fileSize, region.virtualSize); ++delta)
        {
            const auto file = region.fileOffset + delta;
            const auto va = FileOffsetToVa(layout, file);
            roundTrip = roundTrip && va && VaToFileOffset(layout, *va) == file;
        }
    }
    expect(roundTrip, "every captured mapped byte round-trips between file offset and VA");
    auto conflictingRaw = layout;
    conflictingRaw.mappedRegions.push_back({"conflict", 0x480, 0x20, 0x9000, 0x20, 0, 0, true});
    expect(!FileOffsetToRva(conflictingRaw, 0x490), "overlapping raw ranges with different RVAs are ambiguous");
    auto conflictingVirtual = layout;
    conflictingVirtual.mappedRegions.push_back({"conflict", 0xA00, 0x20, 0x1010, 0x20, 0, 0, true});
    expect(!RvaToFileOffset(conflictingVirtual, 0x1018), "overlapping virtual ranges with different disk offsets are ambiguous");
    auto duplicated = layout;
    duplicated.mappedRegions.push_back(layout.mappedRegions[1]);
    expect(!FileOffsetToRva(duplicated, 0x400) && !RvaToFileOffset(duplicated, 0x1000),
        "even identical overlapping mappings are rejected as ambiguous");
    auto wrappingVa = layout;
    wrappingVa.imageBase = std::numeric_limits<std::uint64_t>::max() - 0x100;
    expect(!FileOffsetToVa(wrappingVa, 0x400), "image base plus RVA cannot wrap");
    auto wrappingRva = layout;
    wrappingRva.mappedRegions = {{"bad", 0, 4, 0xFFFFFFFE, 4, 0, 0, true}};
    expect(!FileOffsetToRva(wrappingRva, 2), "raw delta cannot wrap a PE RVA");
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
