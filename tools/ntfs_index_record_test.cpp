#include "NtfsIndexRecord.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

using Bytes = std::vector<std::byte>;
using namespace ks::files::ntfs;

static void Put(Bytes& b, std::size_t p, std::uint64_t v, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i)
        b.at(p + i) = static_cast<std::byte>((v >> (i * 8)) & 255U);
}

static Bytes Name(std::uint64_t parent, const std::u16string& name, unsigned ns = 1)
{
    Bytes value(66 + name.size() * 2);
    Put(value, 0, parent, 8);
    Put(value, 64, name.size(), 1);
    Put(value, 65, ns, 1);
    for (std::size_t i = 0; i < name.size(); ++i)
        Put(value, 66 + i * 2, name[i], 2);
    return value;
}

static Bytes Resident(unsigned type, const Bytes& value, bool named = false)
{
    const std::size_t offset = named ? 32 : 24;
    Bytes b((offset + value.size() + 7) & ~std::size_t{7});
    Put(b, 0, type, 4);
    Put(b, 4, b.size(), 4);
    if (named)
    {
        Put(b, 9, 1, 1);
        Put(b, 10, 24, 2);
        Put(b, 24, u'X', 2);
    }
    Put(b, 16, value.size(), 4);
    Put(b, 20, offset, 2);
    std::copy(value.begin(), value.end(), b.begin() + offset);
    return b;
}

static Bytes Nonresident(unsigned flags = 0, std::uint64_t lowest = 0)
{
    const std::size_t mapping = flags & 0x8001U ? 72 : 64;
    Bytes b(mapping + 8);
    Put(b, 0, 0x80, 4);
    Put(b, 4, b.size(), 4);
    Put(b, 8, 1, 1);
    Put(b, 12, flags, 2);
    Put(b, 16, lowest, 8);
    Put(b, 24, lowest + 3, 8);
    Put(b, 32, mapping, 2);
    Put(b, 40, 16384, 8);
    Put(b, 48, 12500, 8);
    Put(b, 56, 12000, 8);
    if (mapping == 72)
        Put(b, 64, 8192, 8);
    Put(b, mapping, 0x11, 1);
    Put(b, mapping + 1, 4, 1);
    Put(b, mapping + 2, 20, 1);
    return b;
}

static Bytes Record(const std::vector<Bytes>& attributes, unsigned flags = 1)
{
    Bytes b(1024);
    Put(b, 0, 0x454c4946, 4);
    Put(b, 4, 48, 2);
    Put(b, 6, 3, 2);
    Put(b, 16, 7, 2);
    Put(b, 20, 56, 2);
    Put(b, 22, flags, 2);
    Put(b, 28, 1024, 4);
    std::size_t position = 56;
    for (const auto& attribute : attributes)
    {
        assert(position + attribute.size() + 4 < b.size());
        std::copy(attribute.begin(), attribute.end(), b.begin() + position);
        position += attribute.size();
    }
    Put(b, position, 0xffffffffU, 4);
    Put(b, 24, position + 4, 4);
    // Persist update sequence fixups last, exactly as an on-disk record does.
    Put(b, 48, 0xa55a, 2);
    for (unsigned sector = 0; sector < 2; ++sector)
    {
        const auto tail = (sector + 1U) * 512U - 2;
        b[50 + sector * 2] = b[tail];
        b[51 + sector * 2] = b[tail + 1];
        Put(b, tail, 0xa55a, 2);
    }
    return b;
}

static Bytes FsctlRecord(Bytes bytes)
{
    const auto usa = static_cast<std::size_t>(static_cast<unsigned>(bytes.at(4))
        | (static_cast<unsigned>(bytes.at(5)) << 8));
    for (std::size_t sector = 0; sector < bytes.size() / 512; ++sector)
    {
        bytes[(sector + 1) * 512 - 2] = bytes.at(usa + (sector + 1) * 2);
        bytes[(sector + 1) * 512 - 1] = bytes.at(usa + (sector + 1) * 2 + 1);
    }
    return bytes;
}

static void TestNonresidentContinuations()
{
    ParsedRecord parsed;
    for (const auto flags : {0x8000U, 1U, 0x8001U, 0U})
    {
        // Compressed/sparse continuation headers need not include the +64
        // TotalAllocated word; mapping pairs may start directly at +64.
        auto continuation = Nonresident(0, 4);
        Put(continuation, 12, flags, 2);
        auto raw = Record({continuation});
        assert(ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        assert(!parsed.sizeKnown);
        auto logical = FsctlRecord(raw);
        assert(ParseRecord(logical.data(), logical.size(), 512, 1, parsed, RecordFormat::FileSystemControl));
        assert(!parsed.sizeKnown);

        // These header words are undefined for LowestVcn > 0. A parser cannot
        // impose stream-size bounds or compare them as initialized <= logical.
        Put(continuation, 40, UINT64_MAX, 8);
        Put(continuation, 48, UINT64_MAX, 8);
        Put(continuation, 56, UINT64_MAX, 8);
        raw = Record({continuation});
        assert(ParseRecord(raw.data(), raw.size(), 512, 1, parsed) && !parsed.sizeKnown);
        logical = FsctlRecord(raw);
        assert(ParseRecord(logical.data(), logical.size(), 512, 1, parsed, RecordFormat::FileSystemControl)
            && !parsed.sizeKnown);
        std::vector<MftStreamPart> parts;
        std::vector<std::uint64_t> references;
        if (flags == 0)
        {
            assert(ParseMftStreamParts(raw.data(), raw.size(), 512, parts, references));
            assert(parts.size() == 1 && parts[0].lowestVcn == 4 && parts[0].logicalBytes == 0);
            assert(ParseMftStreamParts(logical.data(), logical.size(), 512, parts, references,
                RecordFormat::FileSystemControl));
            assert(parts.size() == 1 && parts[0].logicalBytes == 0);
        }
        else
            assert(!ParseMftStreamParts(raw.data(), raw.size(), 512, parts, references));

        // VCN bounds and first-segment size validation remain mandatory.
        Put(continuation, 24, 3, 8);
        raw = Record({continuation});
        assert(!ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        Put(continuation, 24, UINT64_MAX, 8);
        raw = Record({continuation});
        assert(!ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        auto first = Nonresident(flags);
        Put(first, 56, 12501, 8);
        raw = Record({first});
        assert(!ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        if (flags)
        {
            first = Nonresident(); Put(first, 12, flags, 2);
            raw = Record({first});
            assert(!ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        }
        raw = Record({Nonresident(flags)});
        assert(ParseRecord(raw.data(), raw.size(), 512, 1, parsed));
        assert(parsed.sizeKnown && parsed.logicalBytes == 12500
            && parsed.allocatedBytes == (flags ? 8192U : 16384U));
    }
}

// Storage sectors are 4096 bytes here; the NTFS USA stride stays 512 bytes.
// Keep the original 1 KiB fixture independent of this record-size variation.
static Bytes Record4Kn(const std::vector<Bytes>& attributes, std::size_t usaOffset = 48)
{
    Bytes bytes(4096);
    Put(bytes, 0, 0x454c4946, 4);
    Put(bytes, 4, usaOffset, 2);
    Put(bytes, 6, 9, 2);
    Put(bytes, 16, 7, 2);
    const std::size_t firstAttribute = (usaOffset + 18 + 7) & ~std::size_t{7};
    Put(bytes, 20, firstAttribute, 2);
    Put(bytes, 22, 1, 2);
    Put(bytes, 28, bytes.size(), 4);
    std::size_t position = firstAttribute;
    for (const auto& attribute : attributes)
    {
        assert(position + attribute.size() + 4 < bytes.size());
        std::copy(attribute.begin(), attribute.end(), bytes.begin() + position);
        position += attribute.size();
    }
    Put(bytes, position, 0xffffffffU, 4);
    Put(bytes, 24, position + 4, 4);
    Put(bytes, usaOffset, 0xa55a, 2);
    for (std::size_t stride = 0; stride < 8; ++stride)
    {
        const std::size_t tail = (stride + 1) * 512 - 2;
        bytes[usaOffset + (stride + 1) * 2] = bytes[tail];
        bytes[usaOffset + (stride + 1) * 2 + 1] = bytes[tail + 1];
        Put(bytes, tail, 0xa55a, 2);
    }
    return bytes;
}

static void Test4Kn()
{
    ParsedRecord parsed;
    std::vector<MftStreamPart> parts;
    std::vector<std::uint64_t> references;
    const auto raw = Record4Kn({Nonresident()});
    assert(ParseRecord(raw.data(), raw.size(), 4096, 0, parsed));
    assert(parsed.sizeKnown && parsed.logicalBytes == 12500);
    assert(ParseMftStreamParts(raw.data(), raw.size(), 4096, parts, references));
    assert(parts.size() == 1 && parts[0].extents[0].startLcn == 20);
    const auto logical = FsctlRecord(raw);
    assert(ParseRecord(logical.data(), logical.size(), 4096, 0, parsed, RecordFormat::FileSystemControl));
    assert(ParseMftStreamParts(logical.data(), logical.size(), 4096, parts, references, RecordFormat::FileSystemControl));
    assert(parts.size() == 1 && parts[0].extents[0].startLcn == 20);
    for (const std::size_t tail : {510U, 1022U, 4094U})
    {
        auto torn = raw;
        Put(torn, tail, 0, 2);
        assert(!ParseRecord(torn.data(), torn.size(), 4096, 0, parsed));
        assert(!ParseMftStreamParts(torn.data(), torn.size(), 4096, parts, references));
    }
    auto falseStorageStride = raw;
    Put(falseStorageStride, 6, 2, 2); // A single 4 KiB tail is not the NTFS USA layout.
    for (const auto format : {RecordFormat::RawDisk, RecordFormat::FileSystemControl})
    {
        assert(!ParseRecord(falseStorageStride.data(), falseStorageStride.size(), 4096, 0, parsed, format));
        assert(!ParseMftStreamParts(falseStorageStride.data(), falseStorageStride.size(), 4096, parts, references, format));
    }
    // The array may end at 510, before the first 512-byte stride's last word.
    const auto boundary = Record4Kn({Nonresident()}, 492);
    assert(ParseMftStreamParts(boundary.data(), boundary.size(), 4096, parts, references));
    const auto logicalBoundary = FsctlRecord(boundary);
    assert(ParseMftStreamParts(logicalBoundary.data(), logicalBoundary.size(), 4096,
        parts, references, RecordFormat::FileSystemControl));
    const auto overlappingArray = Record4Kn({Nonresident()}, 494);
    for (const auto format : {RecordFormat::RawDisk, RecordFormat::FileSystemControl})
    {
        assert(!ParseRecord(overlappingArray.data(), overlappingArray.size(), 4096, 0, parsed, format));
        assert(!ParseMftStreamParts(overlappingArray.data(), overlappingArray.size(), 4096, parts, references, format));
    }
    std::u16string name(240, u'a');
    const auto namedRaw = Record4Kn({Resident(0x30, Name(5, name)), Resident(0x80, Bytes(17))});
    assert(ParseRecord(namedRaw.data(), namedRaw.size(), 4096, 1, parsed) && parsed.names[0].name == name);
    auto cachedName = FsctlRecord(namedRaw);
    Put(cachedName, 510, u'新', 2); // Cached FILE_NAME data can change after fixup.
    name[174] = u'新';
    assert(ParseRecord(cachedName.data(), cachedName.size(), 4096, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.names[0].name == name);
    Put(cachedName, 510, 0xa55a, 2); Put(cachedName, 4094, 0xa55a, 2);
    name[174] = static_cast<char16_t>(0xa55a);
    assert(ParseRecord(cachedName.data(), cachedName.size(), 4096, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.names[0].name == name); // A logical marker must not restore stale USA data.
    auto mappingAttribute = Nonresident();
    mappingAttribute.resize(80); Put(mappingAttribute, 4, 80, 4);
    Put(mappingAttribute, 32, 68, 2); Put(mappingAttribute, 64, 0, 4);
    Put(mappingAttribute, 68, 0x31, 1); Put(mappingAttribute, 69, 4, 1);
    Put(mappingAttribute, 70, 20, 3); Put(mappingAttribute, 73, 0, 1);
    auto cachedMapping = FsctlRecord(Record4Kn({Resident(0x70, Bytes(344)), mappingAttribute}));
    Put(cachedMapping, 510, 30, 2); // Mapping LCN crosses the first USA stride.
    assert(ParseMftStreamParts(cachedMapping.data(), cachedMapping.size(), 4096, parts, references, RecordFormat::FileSystemControl));
    assert(parts.size() == 1 && parts[0].extents[0].startLcn == 30);
    Put(cachedMapping, 510, 0xa55a, 2);
    assert(ParseMftStreamParts(cachedMapping.data(), cachedMapping.size(), 4096, parts, references, RecordFormat::FileSystemControl));
    assert(parts[0].extents[0].startLcn == 0xa55a);
}

int main()
{
    TestNonresidentContinuations();
    ParsedRecord parsed;
    const auto data = Resident(0x80, Bytes(17));
    auto b = Record({Resident(0x30, Name(0x9000000000005ULL, u"hello.txt")), data});
    assert(ParseRecord(b.data(), b.size(), 512, 55, parsed));
    assert(parsed.reference == ((std::uint64_t{7} << 48) | 55));
    assert(parsed.inUse && parsed.baseRecord && !parsed.directory && parsed.sizeKnown);
    assert(parsed.logicalBytes == 17 && parsed.allocatedBytes == 0);
    assert(parsed.names.size() == 1 && parsed.names[0].name == u"hello.txt");
    assert(parsed.names[0].parentReference == 0x9000000000005ULL);

    b = Record({Resident(0x30, Name(5, u"a")), Resident(0x30, Name(6, u"b", 0)),
        Resident(0x30, Name(5, u"A~1", 2)), Resident(0x30, Name(5, u"a", 3)), data});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && parsed.names.size() == 2);
    b = Record({data, Resident(0x80, Bytes(25), true)});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.logicalBytes == 17 && parsed.sizeKnown);

    b = Record({Nonresident()});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.sizeKnown && parsed.logicalBytes == 12500 && parsed.allocatedBytes == 16384);
    std::vector<MftStreamPart> parts;
    std::vector<std::uint64_t> refs;
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    assert(parts.size() == 1 && parts[0].extents.size() == 1);
    assert(parts[0].extents[0].startVcn == 0 && parts[0].extents[0].startLcn == 20);
    assert(parts[0].extents[0].clusterCount == 4 && !parts[0].extents[0].sparse);

    for (const auto flags : {0x8000U, 1U, 0x8001U})
    {
        b = Record({Nonresident(flags)});
        assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
        assert(parsed.sizeKnown && parsed.allocatedBytes == 8192);
        assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    }
    b = Record({Nonresident(0, 4)});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && !parsed.sizeKnown);
    auto emptyNonresident = Nonresident();
    Put(emptyNonresident, 24, UINT64_MAX, 8); // Empty nonresident stream sentinel.
    Put(emptyNonresident, 40, 0, 8);
    Put(emptyNonresident, 48, 0, 8);
    Put(emptyNonresident, 56, 0, 8);
    Put(emptyNonresident, 64, 0, 1);
    b = Record({emptyNonresident});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.sizeKnown && parsed.logicalBytes == 0 && parsed.allocatedBytes == 0);
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    Put(emptyNonresident, 48, 1, 8);
    b = Record({emptyNonresident});
    assert(!ParseRecord(b.data(), b.size(), 512, 1, parsed));
    b = Record({data, Resident(0x20, {})});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.hasAttributeList && !parsed.sizeKnown);

    Bytes list(64);
    for (std::size_t offset : {0U, 32U})
    {
        Put(list, offset, 0x80, 4);
        Put(list, offset + 4, 32, 2);
        Put(list, offset + 16, 0x3000000000018ULL + offset, 8);
    }
    b = Record({Nonresident(), Resident(0x20, list)});
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs) && refs.size() == 2);
    assert(refs[0] == 0x3000000000018ULL && refs[1] == 0x3000000000038ULL);
    Put(list, 0, 0x30, 4); // Extension FILE_NAME references are equally important.
    b = Record({data, Resident(0x20, list)});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.attributeListResident && parsed.attributeReferences.size() == 2);
    assert(parsed.attributeReferences[0] == 0x3000000000018ULL);
    auto externalList = Nonresident();
    Put(externalList, 0, 0x20, 4);
    b = Record({data, externalList});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.hasAttributeList && !parsed.attributeListResident && !parsed.sizeKnown);
    assert(parsed.attributeReferences.empty());
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));

    // Mature/fragmented MFTs can store their attribute list in its own stream.
    // The parser exposes its runs only when the caller opts into reading it.
    Put(externalList, 48, 64, 8);
    Put(externalList, 56, 64, 8);
    b = Record({Nonresident(), externalList});
    std::vector<MftStreamPart> listParts;
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs,
        RecordFormat::RawDisk, &listParts));
    assert(parts.size() == 1 && refs.empty() && listParts.size() == 1);
    assert(listParts[0].logicalBytes == 64 && listParts[0].lowestVcn == 0);
    assert(listParts[0].extents.size() == 1
        && listParts[0].extents[0].startLcn == 20
        && listParts[0].extents[0].clusterCount == 4);
    auto externalValue = list;
    Put(externalValue, 0, 0x80, 4);
    assert(ParseMftAttributeList(externalValue.data(), externalValue.size(), refs));
    assert(refs.size() == 2 && refs[0] == 0x3000000000018ULL);
    auto repeatedValue = externalValue;
    Put(repeatedValue, 48, 0x3000000000018ULL, 8);
    assert(ParseMftAttributeList(repeatedValue.data(), repeatedValue.size(), refs)
        && refs.size() == 1);
    auto filteredValue = externalValue;
    Put(filteredValue, 0, 0x30, 4);
    Put(filteredValue, 38, 1, 1); // Named $DATA is not the MFT stream.
    Put(filteredValue, 39, 26, 1);
    Put(filteredValue, 58, u'X', 2);
    assert(ParseMftAttributeList(filteredValue.data(), filteredValue.size(), refs)
        && refs.empty());
    for (const std::size_t length : {0U, 1U, 25U, 31U, 33U, 63U})
    {
        refs.push_back(1);
        assert(!ParseMftAttributeList(externalValue.data(), length, refs) && refs.empty());
    }
    auto badValue = externalValue;
    Put(badValue, 36, 72, 2);
    assert(!ParseMftAttributeList(badValue.data(), badValue.size(), refs) && refs.empty());
    badValue = filteredValue;
    Put(badValue, 39, 31, 1); // Name extends beyond the entry boundary.
    assert(!ParseMftAttributeList(badValue.data(), badValue.size(), refs) && refs.empty());
    for (const auto change : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U})
    {
        auto invalidList = externalList;
        if (change == 0) Put(invalidList, 12, 0x8000, 2); // Sparse lists are invalid.
        if (change == 1) Put(invalidList, 34, 1, 2); // No compression unit.
        if (change == 2) Put(invalidList, 24, 4, 8); // Mapping is too short for highest VCN.
        if (change == 3) Put(invalidList, 48, UINT64_MAX, 8);
        if (change == 4) Put(invalidList, 56, 63, 8); // No uninitialized list tail.
        if (change == 5) Put(invalidList, 64, 0x01, 1); // A sparse mapping pair.
        if (change == 6) Put(invalidList, 66, 0xff, 1); // LCN delta underflows zero.
        if (change == 7) Put(invalidList, 67, 0xff, 1); // Missing mapping terminator.
        b = Record({Nonresident(), invalidList});
        refs.push_back(1);
        assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs,
            RecordFormat::RawDisk, &listParts));
        assert(parts.empty() && refs.empty() && listParts.empty());
    }
    b = Record({Nonresident(), externalList});
    auto brokenListRecord = b;
    Put(brokenListRecord, 1022, 0, 2);
    assert(!ParseMftStreamParts(brokenListRecord.data(), brokenListRecord.size(), 512,
        parts, refs, RecordFormat::RawDisk, &listParts) && listParts.empty());
    for (unsigned sector = 0; sector < 2; ++sector)
    {
        const auto tail = (sector + 1U) * 512U - 2;
        b[tail] = b[50 + sector * 2];
        b[tail + 1] = b[51 + sector * 2];
    }
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs,
        RecordFormat::RawDisk, &listParts));
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs,
        RecordFormat::FileSystemControl, &listParts) && listParts.size() == 1);
    Put(list, 4, 25, 2); // Every resident list entry is validated before publication.
    b = Record({data, Resident(0x20, list)});
    assert(!ParseRecord(b.data(), b.size(), 512, 1, parsed));

    // External lists can span many clusters. Preserve reference order while
    // deduplicating without quadratic work on the bounded on-disk stream.
    Bytes largeList(32768 * 32);
    for (std::size_t i = 0; i < 32768; ++i) {
        Put(largeList, i * 32, 0x80, 4);
        Put(largeList, i * 32 + 4, 32, 2);
        Put(largeList, i * 32 + 16, (std::uint64_t{3} << 48) | (i % 16384), 8);
    }
    assert(ParseMftAttributeList(largeList.data(), largeList.size(), refs));
    assert(refs.size() == 16384 && refs.front() == (std::uint64_t{3} << 48)
        && refs.back() == ((std::uint64_t{3} << 48) | 16383));

    // A negative mapping-pair LCN delta is relative to the previous run.
    auto nonresident = Nonresident();
    nonresident.resize(80);
    Put(nonresident, 4, 80, 4);
    Put(nonresident, 65, 2, 1);
    Put(nonresident, 67, 0x11, 1);
    Put(nonresident, 68, 2, 1);
    Put(nonresident, 69, 0xfb, 1); // 20 - 5 = 15
    b = Record({nonresident});
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    assert(parts[0].extents.size() == 2 && parts[0].extents[1].startLcn == 15);
    Put(nonresident, 69, 0xe0, 1); // 20 - 32 is invalid.
    b = Record({nonresident});
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs) && parts.empty());

    b = Record({}, 3);
    assert(ParseRecord(b.data(), b.size(), 512, 5, parsed));
    assert(parsed.directory && parsed.sizeKnown && (parsed.attributes & 16));
    b = Record({}, 0);
    Put(b, 20, 0, 2); // Unused record attributes need not remain valid.
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && !parsed.inUse);
    b = Record({data});
    Put(b, 32, 4, 8);
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && !parsed.baseRecord);

    b = Record({data});
    auto broken = b;
    broken[1023] = std::byte{0};
    assert(!ParseRecord(broken.data(), broken.size(), 512, 1, parsed));
    assert(parsed.names.empty() && !parsed.inUse && !parsed.sizeKnown);
    assert(!ParseRecord(b.data(), b.size(), 0, 1, parsed));
    assert(!ParseRecord(b.data(), b.size(), 513, 1, parsed));
    assert(!ParseRecord(b.data(), b.size(), 512, std::uint64_t{1} << 48, parsed));
    for (std::size_t length = 0; length < b.size(); ++length)
        assert(!ParseRecord(b.data(), length, 512, 1, parsed));

    broken = b;
    Put(broken, 60, 0xfffffff8U, 4); // Attribute length exceeds used bytes.
    assert(!ParseRecord(broken.data(), broken.size(), 512, 1, parsed));
    broken = b;
    Put(broken, 24, 56 + data.size(), 4); // Missing attribute terminator.
    assert(!ParseRecord(broken.data(), broken.size(), 512, 1, parsed));

    // Attribute contents cross a sector trailer: restoration must precede parsing.
    b = Record({Resident(0x80, Bytes(500))});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && parsed.logicalBytes == 500);
    std::u16string longName(240, u'文');
    longName[183] = u'件';
    b = Record({Resident(0x30, Name(5, longName)), data});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed));
    assert(parsed.names.size() == 1 && parsed.names[0].name == longName);
    auto restored = b;
    for (unsigned sector = 0; sector < 2; ++sector)
    {
        const auto tail = (sector + 1U) * 512U - 2;
        restored[tail] = restored[50 + sector * 2];
        restored[tail + 1] = restored[51 + sector * 2];
    }
    assert(!ParseRecord(restored.data(), restored.size(), 512, 1, parsed));
    assert(ParseRecord(restored.data(), restored.size(), 512, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.names.size() == 1 && parsed.names[0].name == longName);
    auto cachedData = FsctlRecord(Record({Resident(0x80, Bytes(700))}));
    Put(cachedData, 510, 0x4243, 2); // Legal resident payload changed after fixup.
    const auto unchangedInput = cachedData;
    assert(!ParseRecord(cachedData.data(), cachedData.size(), 512, 1, parsed));
    assert(ParseRecord(cachedData.data(), cachedData.size(), 512, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.sizeKnown && parsed.logicalBytes == 700 && cachedData == unchangedInput);
    Put(cachedData, 60, 0xfffffff8U, 4); // API format still rejects malformed attribute lengths.
    assert(!ParseRecord(cachedData.data(), cachedData.size(), 512, 1, parsed, RecordFormat::FileSystemControl));

    auto cachedName = restored;
    Put(cachedName, 510, u'新', 2); // FILE_NAME character 182 straddles a sector tail.
    auto updatedName = longName; updatedName[182] = u'新';
    assert(!ParseRecord(cachedName.data(), cachedName.size(), 512, 1, parsed));
    assert(ParseRecord(cachedName.data(), cachedName.size(), 512, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.names.size() == 1 && parsed.names[0].name == updatedName);
    // Both logical tails may happen to equal the update-sequence marker. The
    // FSCTL entry must still preserve them rather than restoring old characters.
    Put(cachedName, 510, 0xa55a, 2); Put(cachedName, 1022, 0xa55a, 2);
    updatedName[182] = static_cast<char16_t>(0xa55a);
    assert(ParseRecord(cachedName.data(), cachedName.size(), 512, 1, parsed, RecordFormat::FileSystemControl));
    assert(parsed.names[0].name == updatedName);

    auto cachedMappingAttribute = Nonresident();
    cachedMappingAttribute.resize(80); Put(cachedMappingAttribute, 4, 80, 4);
    Put(cachedMappingAttribute, 32, 68, 2);
    Put(cachedMappingAttribute, 64, 0, 4);
    Put(cachedMappingAttribute, 68, 0x31, 1); Put(cachedMappingAttribute, 69, 4, 1);
    Put(cachedMappingAttribute, 70, 20, 3); Put(cachedMappingAttribute, 73, 0, 1);
    // The LCN starts at absolute offset 510, behind a harmless resident attr.
    auto cachedMapping = FsctlRecord(Record({Resident(0x70, Bytes(360)), cachedMappingAttribute}));
    Put(cachedMapping, 510, 30, 2);
    assert(!ParseMftStreamParts(cachedMapping.data(), cachedMapping.size(), 512, parts, refs));
    assert(ParseMftStreamParts(cachedMapping.data(), cachedMapping.size(), 512, parts, refs, RecordFormat::FileSystemControl));
    assert(parts.size() == 1 && parts[0].extents[0].startLcn == 30);
    Put(cachedMapping, 510, 0xa55a, 2); Put(cachedMapping, 1022, 0xa55a, 2);
    assert(ParseMftStreamParts(cachedMapping.data(), cachedMapping.size(), 512, parts, refs, RecordFormat::FileSystemControl));
    assert(parts[0].extents[0].startLcn == 0xa55a); // Never overwrite an API mapping tail.
    b = Record({Nonresident()});
    for (unsigned sector = 0; sector < 2; ++sector)
    {
        const auto tail = (sector + 1U) * 512U - 2;
        b[tail] = b[50 + sector * 2];
        b[tail + 1] = b[51 + sector * 2];
    }
    assert(!ParseMftStreamParts(b.data(), b.size(), 512, parts, refs));
    assert(ParseMftStreamParts(b.data(), b.size(), 512, parts, refs, RecordFormat::FileSystemControl));
    assert(parts.size() == 1 && parts[0].extents[0].startLcn == 20);
    Bytes standard(48);
    Put(standard, 32, 0x2020, 4);
    b = Record({Resident(0x10, standard), Resident(0x30, Name(5, u"flags")), data});
    assert(ParseRecord(b.data(), b.size(), 512, 1, parsed) && parsed.attributes == 0x2020);
    Test4Kn();
    std::mt19937 generator(0x1234);
    for (unsigned i = 0; i < 5000; ++i)
    {
        auto fuzzed = b;
        for (unsigned j = 0; j < 4; ++j)
            fuzzed[generator() % fuzzed.size()] = static_cast<std::byte>(generator() & 255U);
        ParseRecord(fuzzed.data(), fuzzed.size(), 512, 1, parsed);
        ParseMftStreamParts(fuzzed.data(), fuzzed.size(), 512, parts, refs);
    }
    std::cout << "NTFS index record tests passed (5000 mutation inputs)\n";
}
