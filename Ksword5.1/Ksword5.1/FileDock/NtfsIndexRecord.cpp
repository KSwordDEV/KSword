#include "NtfsIndexRecord.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <unordered_set>

namespace ks::files::ntfs
{
    namespace
    {
        // NTFS multi-sector protection uses 512-byte strides, independently of
        // the volume's logical/physical sector size used for raw device I/O.
        constexpr std::size_t kUsaStride = 512;

        // Byte-wise loads also work on unaligned fields and non-little-endian hosts.
        std::uint64_t Load(const std::vector<std::byte>& bytes,
            const std::size_t offset, const std::size_t width)
        {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < width; ++i)
                value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
            return value;
        }

        bool Within(const std::size_t offset, const std::size_t size,
            const std::size_t limit)
        {
            return offset <= limit && size <= limit - offset;
        }

        bool ValidSize(const std::uint64_t value)
        {
            // NTFS size fields are signed LARGE_INTEGER values.
            return value <= static_cast<std::uint64_t>(
                std::numeric_limits<std::int64_t>::max());
        }

        bool ParseAttributeList(const std::vector<std::byte>& bytes,
            const std::size_t start, const std::size_t end,
            const bool unnamedDataOnly, std::vector<std::uint64_t>& references)
        {
            std::unordered_set<std::uint64_t> seen(references.begin(), references.end());
            auto entry = start;
            while (entry < end)
            {
                if (!Within(entry, 26, end))
                    return false;
                const auto entryLength = static_cast<std::size_t>(Load(bytes, entry + 4, 2));
                const auto entryNameLength = static_cast<std::size_t>(Load(bytes, entry + 6, 1));
                const auto entryNameOffset = static_cast<std::size_t>(Load(bytes, entry + 7, 1));
                if (entryLength < 26 || !Within(entry, entryLength, end)
                    || (entryNameLength && (entryNameOffset < 26
                        || !Within(entryNameOffset, entryNameLength * 2, entryLength))))
                    return false;
                if (!unnamedDataOnly || (Load(bytes, entry, 4) == 0x80U && entryNameLength == 0))
                {
                    const auto reference = Load(bytes, entry + 16, 8);
                    if (seen.insert(reference).second)
                        references.push_back(reference);
                }
                entry += entryLength;
            }
            return true;
        }

        bool ParseMappingPairs(const std::vector<std::byte>& bytes,
            std::size_t position, const std::size_t end, MftStreamPart& part)
        {
            std::uint64_t currentVcn = part.lowestVcn;
            std::uint64_t currentLcn = 0;
            while (position < end)
            {
                const auto header = Load(bytes, position++, 1);
                if (header == 0)
                    return !part.extents.empty() && currentVcn == part.highestVcn + 1;
                const auto lengthWidth = static_cast<std::size_t>(header & 15U);
                const auto offsetWidth = static_cast<std::size_t>(header >> 4);
                if (lengthWidth == 0 || lengthWidth > 8 || offsetWidth > 8
                    || !Within(position, lengthWidth + offsetWidth, end))
                    return false;
                const auto clusters = Load(bytes, position, lengthWidth);
                position += lengthWidth;
                if (clusters == 0 || clusters > part.highestVcn + 1 - currentVcn)
                    return false;
                DataExtent extent;
                extent.startVcn = currentVcn;
                extent.clusterCount = clusters;
                extent.sparse = offsetWidth == 0;
                if (offsetWidth)
                {
                    auto delta = Load(bytes, position, offsetWidth);
                    const bool negative = (delta & (std::uint64_t{1} << (offsetWidth * 8 - 1))) != 0;
                    if (negative)
                    {
                        if (offsetWidth < 8)
                            delta |= std::numeric_limits<std::uint64_t>::max() << (offsetWidth * 8);
                        const auto magnitude = ~delta + 1;
                        if (magnitude > currentLcn)
                            return false;
                        currentLcn -= magnitude;
                    }
                    else
                    {
                        if (delta > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - currentLcn)
                            return false;
                        currentLcn += delta;
                    }
                    if (clusters - 1 > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - currentLcn)
                        return false;
                    extent.startLcn = currentLcn;
                }
                position += offsetWidth;
                currentVcn += clusters;
                part.extents.push_back(extent);
            }
            return false; // A terminator is mandatory, even at exact attribute end.
        }
    }

    bool ParseRecord(const std::byte* const input, const std::size_t length,
        const std::uint32_t bytesPerSector, const std::uint64_t recordIndex,
        ParsedRecord& output, const RecordFormat format)
    {
        output = {};
        constexpr std::uint64_t indexMask = 0x0000ffffffffffffULL;
        // Cap a single untrusted allocation; NTFS records are normally 1/4 KiB.
        if (!input || length < 48 || length > 1024U * 1024U
            || bytesPerSector < 512 || bytesPerSector > 65536
            || (bytesPerSector & (bytesPerSector - 1U)) != 0
            || length % bytesPerSector != 0 || recordIndex > indexMask)
            return false;

        std::vector<std::byte> bytes(input, input + length);
        if (Load(bytes, 0, 4) != 0x454c4946U) // FILE
            return false;
        const auto usaOffset = static_cast<std::size_t>(Load(bytes, 4, 2));
        const auto usaCount = static_cast<std::size_t>(Load(bytes, 6, 2));
        const auto sectors = length / kUsaStride;
        if (usaCount != sectors + 1 || usaOffset < 42 || (usaOffset & 1U)
            || !Within(usaOffset, usaCount * 2, length)
            || usaOffset + usaCount * 2 > kUsaStride - 2)
            return false;
        if (format == RecordFormat::RawDisk)
        {
            const auto updateSequence = Load(bytes, usaOffset, 2);
            for (std::size_t sector = 0; sector < sectors; ++sector)
            {
                const auto tail = (sector + 1) * kUsaStride - 2;
                if (Load(bytes, tail, 2) != updateSequence) return false;
                bytes[tail] = bytes[usaOffset + (sector + 1) * 2];
                bytes[tail + 1] = bytes[usaOffset + (sector + 1) * 2 + 1];
            }
        }
        // FSCTL returns NTFS's logical, already-fixed-up cache record. Its tail
        // bytes can change after fixup without updating the old USA array. Keep
        // that content, even when a logical tail happens to equal the USN word.

        ParsedRecord parsed;
        parsed.reference = (Load(bytes, 16, 2) << 48) | recordIndex;
        const auto recordFlags = Load(bytes, 22, 2);
        parsed.inUse = (recordFlags & 1U) != 0;
        parsed.directory = (recordFlags & 2U) != 0;
        parsed.baseRecord = Load(bytes, 32, 8) == 0;
        // An unused record can contain stale/partially replaced attributes.
        if (!parsed.inUse)
        {
            output = std::move(parsed);
            return true;
        }

        const auto used = static_cast<std::size_t>(Load(bytes, 24, 4));
        const auto allocated = static_cast<std::size_t>(Load(bytes, 28, 4));
        auto position = static_cast<std::size_t>(Load(bytes, 20, 2));
        if (allocated > length || used > allocated || used < 48
            || position < 48 || (position & 7U) != 0 || position > used
            || position < usaOffset + usaCount * 2)
            return false;

        bool hasStandardInformation = false;
        bool hasData = false;
        bool ambiguousData = false;
        bool terminated = false;
        std::uint32_t filenameAttributes = 0;
        while (Within(position, 4, used))
        {
            const auto type = Load(bytes, position, 4);
            if (type == 0xffffffffU)
            {
                terminated = true;
                break;
            }
            if (!Within(position, 16, used))
                return false;
            const auto attributeLength = static_cast<std::size_t>(Load(bytes, position + 4, 4));
            const auto nonresident = Load(bytes, position + 8, 1);
            const auto nameLength = static_cast<std::size_t>(Load(bytes, position + 9, 1));
            const auto nameOffset = static_cast<std::size_t>(Load(bytes, position + 10, 2));
            const auto flags = Load(bytes, position + 12, 2);
            const std::size_t headerLength = nonresident ? 64U : 24U;
            if (nonresident > 1 || attributeLength < headerLength
                || (attributeLength & 7U) != 0
                || !Within(position, attributeLength, used)
                || (nameLength && (nameOffset < headerLength
                    || !Within(nameOffset, nameLength * 2, attributeLength))))
                return false;

            std::size_t valueLength = 0;
            std::size_t valueOffset = 0;
            if (!nonresident)
            {
                valueLength = static_cast<std::size_t>(Load(bytes, position + 16, 4));
                valueOffset = static_cast<std::size_t>(Load(bytes, position + 20, 2));
                if (valueOffset < headerLength
                    || !Within(valueOffset, valueLength, attributeLength)
                    || (nameLength && valueOffset < nameOffset + nameLength * 2))
                    return false;
            }
            else
            {
                const auto mappingOffset = static_cast<std::size_t>(Load(bytes, position + 32, 2));
                if (mappingOffset < headerLength || mappingOffset >= attributeLength
                    || (nameLength && mappingOffset < nameOffset + nameLength * 2))
                    return false;
            }

            if (type == 0x10U) // $STANDARD_INFORMATION
            {
                if (nonresident || valueLength < 36 || hasStandardInformation)
                    return false;
                parsed.attributes = static_cast<std::uint32_t>(Load(bytes,
                    position + valueOffset + 32, 4));
                hasStandardInformation = true;
            }
            else if (type == 0x20U) // $ATTRIBUTE_LIST
            {
                parsed.hasAttributeList = true;
                if (nonresident)
                    parsed.attributeListResident = false;
                else if (!ParseAttributeList(bytes, position + valueOffset,
                    position + valueOffset + valueLength, false, parsed.attributeReferences))
                    return false;
            }
            else if (type == 0x30U) // $FILE_NAME
            {
                if (nonresident || valueLength < 66)
                    return false;
                const auto value = position + valueOffset;
                const auto characters = static_cast<std::size_t>(Load(bytes, value + 64, 1));
                const auto nameSpace = Load(bytes, value + 65, 1);
                if (nameSpace > 3 || characters == 0
                    || !Within(66, characters * 2, valueLength))
                    return false;
                if (nameSpace != 2) // Ignore a separate DOS 8.3 alias.
                {
                    ParsedName name;
                    name.parentReference = Load(bytes, value, 8);
                    name.name.reserve(characters);
                    for (std::size_t i = 0; i < characters; ++i)
                    {
                        const auto character = static_cast<char16_t>(Load(bytes,
                            value + 66 + i * 2, 2));
                        if (character == 0 || character == u'\\' || character == u'/')
                            return false;
                        name.name.push_back(character);
                    }
                    const auto duplicate = std::find_if(parsed.names.begin(), parsed.names.end(),
                        [&name](const ParsedName& existing) {
                            return existing.parentReference == name.parentReference
                                && existing.name == name.name;
                        });
                    if (duplicate == parsed.names.end())
                        parsed.names.push_back(std::move(name));
                }
                filenameAttributes = static_cast<std::uint32_t>(Load(bytes, value + 56, 4));
            }
            else if (type == 0x80U && nameLength == 0) // Unnamed $DATA only.
            {
                if (hasData)
                    ambiguousData = true;
                hasData = true;
                if (!nonresident)
                {
                    parsed.logicalBytes = valueLength;
                    parsed.allocatedBytes = 0; // Resident bytes share the MFT record.
                    parsed.sizeKnown = flags == 0;
                }
                else
                {
                    const auto lowestVcn = Load(bytes, position + 16, 8);
                    const auto highestVcn = Load(bytes, position + 24, 8);
                    // Stream sizes belong only to the first extent. Later
                    // sparse/compressed segments can start mapping pairs at
                    // +64, with no TotalAllocated field and undefined sizes.
                    const bool firstExtent = lowestVcn == 0;
                    const auto logical = firstExtent ? Load(bytes, position + 48, 8) : 0;
                    const auto initialized = firstExtent ? Load(bytes, position + 56, 8) : 0;
                    auto diskBytes = firstExtent ? Load(bytes, position + 40, 8) : 0;
                    const bool emptyMapping = firstExtent
                        && highestVcn == std::numeric_limits<std::uint64_t>::max()
                        && logical == 0 && initialized == 0 && diskBytes == 0;
                    if (!ValidSize(logical) || !ValidSize(initialized)
                        || initialized > logical || !ValidSize(diskBytes)
                        || !ValidSize(lowestVcn) || (!ValidSize(highestVcn) && !emptyMapping)
                        || highestVcn < lowestVcn)
                        return false;
                    // Compressed/sparse headers carry TotalAllocated at +64;
                    // AllocatedLength at +40 is their logical cluster allocation.
                    if (firstExtent && (flags & 0x8001U) != 0)
                    {
                        const auto mappingOffset = Load(bytes, position + 32, 2);
                        if (attributeLength < 72 || mappingOffset < 72)
                            return false;
                        diskBytes = Load(bytes, position + 64, 8);
                        if (!ValidSize(diskBytes) || (emptyMapping && diskBytes != 0))
                            return false;
                    }
                    parsed.logicalBytes = logical;
                    parsed.allocatedBytes = diskBytes;
                    // Only the first extent contains authoritative stream sizes.
                    parsed.sizeKnown = firstExtent && (flags & 0x00feU) == 0;
                }
            }
            position += attributeLength;
        }
        if (!terminated)
            return false;
        if (!hasStandardInformation)
            parsed.attributes = filenameAttributes;
        if (parsed.directory)
        {
            parsed.attributes |= 0x10U;
            parsed.logicalBytes = 0;
            parsed.allocatedBytes = 0;
            parsed.sizeKnown = true;
        }
        if (parsed.hasAttributeList || ambiguousData)
            parsed.sizeKnown = false;
        output = std::move(parsed);
        return true;
    }

    bool ParseMftStreamParts(const std::byte* const input, const std::size_t length,
        const std::uint32_t bytesPerSector, std::vector<MftStreamPart>& parts,
        std::vector<std::uint64_t>& extensionReferences, const RecordFormat format,
        std::vector<MftStreamPart>* const attributeListParts)
    {
        parts.clear();
        extensionReferences.clear();
        if (attributeListParts) attributeListParts->clear();
        ParsedRecord record;
        if (!ParseRecord(input, length, bytesPerSector, 0, record, format) || !record.inUse)
            return false;
        std::vector<std::byte> bytes(input, input + length);
        if (format == RecordFormat::RawDisk)
        {
            const auto usa = static_cast<std::size_t>(Load(bytes, 4, 2));
            for (std::size_t sector = 0; sector < length / kUsaStride; ++sector)
            {
                const auto tail = (sector + 1) * kUsaStride - 2;
                bytes[tail] = bytes[usa + (sector + 1) * 2];
                bytes[tail + 1] = bytes[usa + (sector + 1) * 2 + 1];
            }
        }
        std::vector<MftStreamPart> foundParts;
        std::vector<MftStreamPart> foundAttributeListParts;
        std::vector<std::uint64_t> foundReferences;
        auto position = static_cast<std::size_t>(Load(bytes, 20, 2));
        const auto used = static_cast<std::size_t>(Load(bytes, 24, 4));
        while (Within(position, 4, used) && Load(bytes, position, 4) != 0xffffffffU)
        {
            // ParseRecord already validated every outer attribute boundary.
            const auto type = Load(bytes, position, 4);
            const auto attributeLength = static_cast<std::size_t>(Load(bytes, position + 4, 4));
            const auto nonresident = Load(bytes, position + 8, 1);
            const auto nameLength = Load(bytes, position + 9, 1);
            if (type == 0x80U && nameLength == 0)
            {
                if (!nonresident || (Load(bytes, position + 12, 2) & 0xc0ffU) != 0)
                    return false; // $MFT cannot be resident/compressed/encrypted.
                MftStreamPart part;
                part.lowestVcn = Load(bytes, position + 16, 8);
                part.highestVcn = Load(bytes, position + 24, 8);
                part.logicalBytes = part.lowestVcn == 0 ? Load(bytes, position + 48, 8) : 0;
                if (part.highestVcn < part.lowestVcn
                    || !ParseMappingPairs(bytes,
                        position + static_cast<std::size_t>(Load(bytes, position + 32, 2)),
                        position + attributeLength, part))
                    return false;
                foundParts.push_back(std::move(part));
            }
            else if (type == 0x20U)
            {
                if (nameLength != 0) return false;
                if (nonresident)
                {
                    if (!attributeListParts || Load(bytes, position + 12, 2) != 0
                        || Load(bytes, position + 34, 2) != 0)
                        return false;
                    MftStreamPart part;
                    part.lowestVcn = Load(bytes, position + 16, 8);
                    part.highestVcn = Load(bytes, position + 24, 8);
                    part.logicalBytes = Load(bytes, position + 48, 8);
                    const auto allocated = Load(bytes, position + 40, 8);
                    const auto initialized = Load(bytes, position + 56, 8);
                    if (!ValidSize(part.lowestVcn) || !ValidSize(part.highestVcn)
                        || part.highestVcn < part.lowestVcn
                        || !ValidSize(part.logicalBytes) || !ValidSize(allocated)
                        || !ValidSize(initialized) || initialized > part.logicalBytes
                        || (part.lowestVcn == 0
                            && (part.logicalBytes == 0 || initialized != part.logicalBytes))
                        || !ParseMappingPairs(bytes,
                            position + static_cast<std::size_t>(Load(bytes, position + 32, 2)),
                            position + attributeLength, part)
                        || std::any_of(part.extents.begin(), part.extents.end(),
                            [](const DataExtent& extent) { return extent.sparse; }))
                        return false;
                    foundAttributeListParts.push_back(std::move(part));
                }
                else
                {
                    const auto value = position + static_cast<std::size_t>(Load(bytes, position + 20, 2));
                    const auto end = value + static_cast<std::size_t>(Load(bytes, position + 16, 4));
                    if (!ParseAttributeList(bytes, value, end, true, foundReferences))
                        return false;
                }
            }
            position += attributeLength;
        }
        parts = std::move(foundParts);
        extensionReferences = std::move(foundReferences);
        if (attributeListParts) *attributeListParts = std::move(foundAttributeListParts);
        return true;
    }

    bool ParseMftAttributeList(const std::byte* const input, const std::size_t length,
        std::vector<std::uint64_t>& extensionReferences)
    {
        extensionReferences.clear();
        // The caller reads the complete bounded stream, never an allocation
        // rounded to clusters whose tail may contain unrelated old bytes.
        if (!input || length < 26 || length > 16U * 1024U * 1024U)
            return false;
        const std::vector<std::byte> bytes(input, input + length);
        std::vector<std::uint64_t> foundReferences;
        if (!ParseAttributeList(bytes, 0, length, true, foundReferences)) return false;
        extensionReferences = std::move(foundReferences);
        return true;
    }
}
