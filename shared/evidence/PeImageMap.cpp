#include "PeImageMap.h"

#include <algorithm>
#include <cstring>

namespace Ksword::Evidence {
namespace {

// PE 结构常量。刻意不 #include <Windows.h>：本层必须能在无 Win32 的环境里
// 单元测试，且 I 模块要求全仓只保留一套解析实现。
constexpr std::uint16_t kDosSignature = 0x5A4DU;          // 'MZ'
constexpr std::uint32_t kNtSignature = 0x00004550U;       // 'PE\0\0'
constexpr std::uint16_t kOptionalMagicPe32Plus = 0x020BU;

constexpr std::uint64_t kDosHeaderSize = 0x40U;
constexpr std::uint64_t kElfanewOffset = 0x3CU;
constexpr std::uint64_t kFileHeaderSize = 20U;
constexpr std::uint64_t kOptionalHeader64MinSize = 112U;  // 到 NumberOfRvaAndSizes 为止
constexpr std::uint64_t kDataDirectoryEntrySize = 8U;
constexpr std::uint64_t kSectionHeaderSize = 40U;

constexpr std::uint32_t kDirectoryIndexExport = 0U;
constexpr std::uint32_t kDirectoryIndexBaseReloc = 5U;
constexpr std::uint32_t kDirectoryIndexLoadConfig = 10U;

// IMAGE_LOAD_CONFIG_DIRECTORY64 里 DVRT 入口字段的偏移。手写常量而不是 offsetof，
// 因为本层不 #include <Windows.h>；这几个偏移由 PE 规范固定，不随 SDK 版本改变。
constexpr std::uint64_t kLoadConfigOffsetStructSize = 0U;            // DWORD Size
constexpr std::uint64_t kLoadConfigOffsetDvrtTableOffset = 224U;     // DWORD
constexpr std::uint64_t kLoadConfigOffsetDvrtTableSection = 228U;    // WORD
// 结构体必须长到能装下 DynamicValueRelocTableSection（228 + 2）才谈得上有 DVRT。
// 比这短的 LoadConfig 是 DVRT 字段出现之前的版本 —— 这是"确实没有"的正面证据。
constexpr std::uint64_t kLoadConfigMinSizeForDvrt = 230U;

constexpr std::uint64_t kDvrtTableHeaderSize = 8U;    // Version + Size
constexpr std::uint64_t kDvrtEntryHeaderSize = 12U;   // Symbol(8) + BaseRelocSize(4)
constexpr std::uint32_t kDvrtTableVersionOne = 1U;

constexpr std::uint32_t kScnCntCode = 0x00000020U;
constexpr std::uint32_t kScnMemExecute = 0x20000000U;
constexpr std::uint32_t kScnMemWrite = 0x80000000U;

constexpr std::uint16_t kFileRelocsStripped = 0x0001U;

// 重定位类型编号。只有 ABSOLUTE / HIGHLOW / DIR64 三种是本层支持的。
constexpr std::uint16_t kRelAbsolute = 0U;
constexpr std::uint16_t kRelHigh = 1U;
constexpr std::uint16_t kRelLow = 2U;
constexpr std::uint16_t kRelHighLow = 3U;
constexpr std::uint16_t kRelHighAdj = 4U;
constexpr std::uint16_t kRelDir64 = 10U;

constexpr std::uint64_t kRelocationBlockHeaderSize = 8U;  // VirtualAddress + SizeOfBlock

bool ReadU8(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
            std::uint8_t& out) noexcept {
    if (offset >= size) {
        return false;
    }
    out = data[static_cast<std::size_t>(offset)];
    return true;
}

bool ReadU16(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint16_t& out) noexcept {
    if (offset + 2U > size) {
        return false;
    }
    const std::size_t at = static_cast<std::size_t>(offset);
    out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[at]) |
                                     static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[at + 1U]) << 8U));
    return true;
}

bool ReadU32(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint32_t& out) noexcept {
    if (offset + 4U > size) {
        return false;
    }
    const std::size_t at = static_cast<std::size_t>(offset);
    out = static_cast<std::uint32_t>(data[at]) |
          (static_cast<std::uint32_t>(data[at + 1U]) << 8U) |
          (static_cast<std::uint32_t>(data[at + 2U]) << 16U) |
          (static_cast<std::uint32_t>(data[at + 3U]) << 24U);
    return true;
}

bool ReadU64(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint64_t& out) noexcept {
    std::uint32_t low = 0U;
    std::uint32_t high = 0U;
    if (!ReadU32(data, size, offset, low) || !ReadU32(data, size, offset + 4U, high)) {
        return false;
    }
    out = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
    return true;
}

bool IsPowerOfTwo(std::uint32_t value) noexcept {
    return value != 0U && (value & (value - 1U)) == 0U;
}

PeImageMap MakeFailure(PeParseStatus status, const char* detail, std::uint64_t fileSize,
                       std::uint64_t loadedBase) {
    PeImageMap map;
    map.status = status;
    map.errorDetail = detail;
    map.fileSize = fileSize;
    map.loadedBase = loadedBase;
    return map;
}

// 不支持的重定位类型影响到的字节宽度。宽度取保守值：宁可多标一点不可比较，
// 也不要漏标而把被改写的字节当成"干净差异"报出去。
std::uint32_t UnsupportedRelocationSpan(std::uint16_t type) noexcept {
    switch (type) {
    case kRelHigh:
    case kRelLow:
        return 2U;
    case kRelHighAdj:
        return 4U;
    default:
        return 8U;
    }
}

// 一个 DVRT 符号段里每条记录的字节宽度；0 表示本层不认识这个符号。
// 宽度取自 winnt.h 的记录结构，三种都把页内偏移放在低 12 位：
//   3 IMPORT_CONTROL_TRANSFER  —— IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION
//     DWORD PageRelativeOffset:12 / IndirectCall:1 / IATIndex:19  = 4 字节
//   4 INDIR_CONTROL_TRANSFER   —— IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION
//     WORD PageRelativeOffset:12 / IndirectCall:1 / RexWPrefix:1 / CfgCheck:1 /
//     Reserved:1                                                  = 2 字节
//   5 SWITCHTABLE_BRANCH       —— IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION
//     WORD PageRelativeOffset:12 / RegisterNumber:4               = 2 字节
// 注意：现役的 KernelCleanImageBaseline::collectDynamicRelocationSites 给符号 5
// 用的是 4 字节。那与 winnt.h 不符，会让 SWITCHTABLE 段每两条记录漏掉一条并且
// 把后一条的高半部当成偏移，本层不复制这个错误。
std::uint32_t DvrtEntryStride(std::uint64_t symbol) noexcept {
    switch (symbol) {
    case kDvrtSymbolImportControlTransfer:
        return 4U;
    case kDvrtSymbolIndirControlTransfer:
    case kDvrtSymbolSwitchtableBranch:
        return 2U;
    default:
        return 0U;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// 区间集合运算
// ---------------------------------------------------------------------------

std::vector<RvaRange> NormalizeRvaRanges(std::vector<RvaRange> ranges) {
    std::vector<RvaRange> kept;
    kept.reserve(ranges.size());
    for (const RvaRange& range : ranges) {
        if (!range.empty()) {
            kept.push_back(range);
        }
    }
    std::sort(kept.begin(), kept.end(), [](const RvaRange& a, const RvaRange& b) {
        if (a.rva != b.rva) {
            return a.rva < b.rva;
        }
        return a.length < b.length;
    });

    std::vector<RvaRange> merged;
    merged.reserve(kept.size());
    for (const RvaRange& range : kept) {
        if (!merged.empty()) {
            RvaRange& back = merged.back();
            // 相邻（end == rva）也合并：区间集合只描述"哪些字节属于这一类"，
            // 不描述它们来自哪一条原始记录。
            if (static_cast<std::uint64_t>(range.rva) <= back.endExclusive()) {
                const std::uint64_t newEnd = std::max(back.endExclusive(), range.endExclusive());
                back.length = static_cast<std::uint32_t>(newEnd - static_cast<std::uint64_t>(back.rva));
                continue;
            }
        }
        merged.push_back(range);
    }
    return merged;
}

std::vector<RvaRange> SubtractRvaRanges(const std::vector<RvaRange>& base,
                                        const std::vector<RvaRange>& cut) {
    const std::vector<RvaRange> normalizedBase = NormalizeRvaRanges(base);
    const std::vector<RvaRange> normalizedCut = NormalizeRvaRanges(cut);
    std::vector<RvaRange> result;
    result.reserve(normalizedBase.size());

    for (const RvaRange& range : normalizedBase) {
        std::uint64_t cursor = range.rva;
        const std::uint64_t end = range.endExclusive();
        for (const RvaRange& hole : normalizedCut) {
            const std::uint64_t holeBegin = hole.rva;
            const std::uint64_t holeEnd = hole.endExclusive();
            if (holeEnd <= cursor) {
                continue;
            }
            if (holeBegin >= end) {
                break;
            }
            if (holeBegin > cursor) {
                RvaRange piece;
                piece.rva = static_cast<std::uint32_t>(cursor);
                piece.length = static_cast<std::uint32_t>(holeBegin - cursor);
                result.push_back(piece);
            }
            cursor = std::max(cursor, holeEnd);
            if (cursor >= end) {
                break;
            }
        }
        if (cursor < end) {
            RvaRange piece;
            piece.rva = static_cast<std::uint32_t>(cursor);
            piece.length = static_cast<std::uint32_t>(end - cursor);
            result.push_back(piece);
        }
    }
    return NormalizeRvaRanges(std::move(result));
}

std::vector<RvaRange> IntersectRvaRanges(const std::vector<RvaRange>& base,
                                         const std::vector<RvaRange>& mask) {
    const std::vector<RvaRange> normalizedBase = NormalizeRvaRanges(base);
    const std::vector<RvaRange> normalizedMask = NormalizeRvaRanges(mask);
    std::vector<RvaRange> result;
    for (const RvaRange& range : normalizedBase) {
        for (const RvaRange& other : normalizedMask) {
            if (other.rva >= range.endExclusive()) {
                break;
            }
            if (other.endExclusive() <= range.rva) {
                continue;
            }
            const std::uint64_t begin = std::max<std::uint64_t>(range.rva, other.rva);
            const std::uint64_t end = std::min(range.endExclusive(), other.endExclusive());
            if (end > begin) {
                RvaRange piece;
                piece.rva = static_cast<std::uint32_t>(begin);
                piece.length = static_cast<std::uint32_t>(end - begin);
                result.push_back(piece);
            }
        }
    }
    return NormalizeRvaRanges(std::move(result));
}

std::uint64_t RvaRangesTotalBytes(const std::vector<RvaRange>& ranges) noexcept {
    std::uint64_t total = 0U;
    for (const RvaRange& range : ranges) {
        total += range.length;
    }
    return total;
}

bool RvaRangesContain(const std::vector<RvaRange>& ranges, std::uint32_t rva) noexcept {
    for (const RvaRange& range : ranges) {
        if (range.contains(rva)) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 枚举名字
// ---------------------------------------------------------------------------

const char* PeParseStatusName(PeParseStatus status) noexcept {
    switch (status) {
    case PeParseStatus::Ok:                        return "Ok";
    case PeParseStatus::EmptyInput:                return "EmptyInput";
    case PeParseStatus::TruncatedDosHeader:        return "TruncatedDosHeader";
    case PeParseStatus::BadDosSignature:           return "BadDosSignature";
    case PeParseStatus::BadNtHeaderOffset:         return "BadNtHeaderOffset";
    case PeParseStatus::TruncatedNtHeaders:        return "TruncatedNtHeaders";
    case PeParseStatus::BadNtSignature:            return "BadNtSignature";
    case PeParseStatus::UnsupportedOptionalMagic:  return "UnsupportedOptionalMagic";
    case PeParseStatus::TruncatedOptionalHeader:   return "TruncatedOptionalHeader";
    case PeParseStatus::InvalidSectionCount:       return "InvalidSectionCount";
    case PeParseStatus::TruncatedSectionTable:     return "TruncatedSectionTable";
    case PeParseStatus::SectionTableExceedsHeaders: return "SectionTableExceedsHeaders";
    case PeParseStatus::InvalidSizeOfImage:        return "InvalidSizeOfImage";
    case PeParseStatus::InvalidAlignment:          return "InvalidAlignment";
    }
    return "EmptyInput";
}

const char* SectionMapStatusName(SectionMapStatus status) noexcept {
    switch (status) {
    case SectionMapStatus::Mapped:        return "Mapped";
    case SectionMapStatus::NotComparable: return "NotComparable";
    }
    return "NotComparable";
}

const char* SectionDefectReasonName(SectionDefectReason reason) noexcept {
    switch (reason) {
    case SectionDefectReason::None:                   return "None";
    case SectionDefectReason::ZeroVirtualExtent:      return "ZeroVirtualExtent";
    case SectionDefectReason::VirtualRangeOutOfImage: return "VirtualRangeOutOfImage";
    case SectionDefectReason::VirtualRangeOverflow:   return "VirtualRangeOverflow";
    case SectionDefectReason::RawDataOutOfFile:       return "RawDataOutOfFile";
    case SectionDefectReason::RawRangeOverflow:       return "RawRangeOverflow";
    case SectionDefectReason::OverlapsEarlierSection: return "OverlapsEarlierSection";
    }
    return "None";
}

const char* RelocationStatusName(RelocationStatus status) noexcept {
    switch (status) {
    case RelocationStatus::NotNeeded:              return "NotNeeded";
    case RelocationStatus::Applied:                return "Applied";
    case RelocationStatus::AppliedWithUnsupported: return "AppliedWithUnsupported";
    case RelocationStatus::DirectoryMissing:       return "DirectoryMissing";
    case RelocationStatus::DirectoryUnbacked:      return "DirectoryUnbacked";
    case RelocationStatus::DirectoryMalformed:     return "DirectoryMalformed";
    case RelocationStatus::Stripped:               return "Stripped";
    }
    return "NotNeeded";
}

bool RelocationNormalizationSucceeded(RelocationStatus status) noexcept {
    switch (status) {
    case RelocationStatus::NotNeeded:
    case RelocationStatus::Applied:
    case RelocationStatus::AppliedWithUnsupported:
        // AppliedWithUnsupported 也算成功：不能归一化的**只是**那几个已被标成
        // 不可比较的字节范围，其余部分确实已经在目标基址上了。
        return true;
    case RelocationStatus::DirectoryMissing:
    case RelocationStatus::DirectoryUnbacked:
    case RelocationStatus::DirectoryMalformed:
    case RelocationStatus::Stripped:
        return false;
    }
    return false;
}

const char* DvrtStatusName(DvrtStatus status) noexcept {
    switch (status) {
    case DvrtStatus::NotPresent:              return "NotPresent";
    case DvrtStatus::Parsed:                  return "Parsed";
    case DvrtStatus::ParsedWithUnknownSymbol: return "ParsedWithUnknownSymbol";
    case DvrtStatus::LoadConfigUnusable:      return "LoadConfigUnusable";
    case DvrtStatus::TableUnbacked:           return "TableUnbacked";
    case DvrtStatus::UnsupportedVersion:      return "UnsupportedVersion";
    case DvrtStatus::Malformed:               return "Malformed";
    }
    return "NotPresent";
}

bool DvrtExtentFullyBounded(DvrtStatus status) noexcept {
    switch (status) {
    case DvrtStatus::NotPresent:
    case DvrtStatus::Parsed:
    case DvrtStatus::ParsedWithUnknownSymbol:
        // ParsedWithUnknownSymbol 也算界定完成：解不开的**只是**位点在页里的位置，
        // 而块头已经告诉我们加载器只会动那几页，那些页整页进了不可比较范围。
        return true;
    case DvrtStatus::LoadConfigUnusable:
    case DvrtStatus::TableUnbacked:
    case DvrtStatus::UnsupportedVersion:
    case DvrtStatus::Malformed:
        return false;
    }
    return false;
}

std::vector<RvaRange> DynamicRelocationReport::affectedRanges() const {
    std::vector<RvaRange> merged;
    merged.reserve(siteRanges.size() + unknownSymbolRanges.size());
    merged.insert(merged.end(), siteRanges.begin(), siteRanges.end());
    merged.insert(merged.end(), unknownSymbolRanges.begin(), unknownSymbolRanges.end());
    return NormalizeRvaRanges(std::move(merged));
}

const char* RvaKindName(RvaKind kind) noexcept {
    switch (kind) {
    case RvaKind::OutsideImage:     return "OutsideImage";
    case RvaKind::Header:           return "Header";
    case RvaKind::SectionRawBacked: return "SectionRawBacked";
    case RvaKind::SectionZeroFill:  return "SectionZeroFill";
    case RvaKind::SectionGap:       return "SectionGap";
    case RvaKind::NotComparable:    return "NotComparable";
    }
    return "OutsideImage";
}

const char* FileOffsetKindName(FileOffsetKind kind) noexcept {
    switch (kind) {
    case FileOffsetKind::OutsideFile:           return "OutsideFile";
    case FileOffsetKind::Header:                return "Header";
    case FileOffsetKind::SectionRawData:        return "SectionRawData";
    case FileOffsetKind::NotMappedByAnySection: return "NotMappedByAnySection";
    case FileOffsetKind::NotComparable:         return "NotComparable";
    }
    return "OutsideFile";
}

// ---------------------------------------------------------------------------
// SectionMap / PeHeaderFacts
// ---------------------------------------------------------------------------

bool SectionMap::executable() const noexcept {
    return (characteristics & (kScnMemExecute | kScnCntCode)) != 0U;
}

bool SectionMap::writable() const noexcept {
    return (characteristics & kScnMemWrite) != 0U;
}

RvaRange SectionMap::virtualRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress;
    range.length = effectiveVirtualSize;
    return range;
}

RvaRange SectionMap::rawBackedRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress;
    range.length = rawBackedBytes;
    return range;
}

RvaRange SectionMap::zeroFillRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress + rawBackedBytes;
    range.length = zeroFillBytes;
    return range;
}

bool PeHeaderFacts::relocationsStripped() const noexcept {
    return (fileCharacteristics & kFileRelocsStripped) != 0U;
}

std::vector<RvaRange> PeImageMap::executableRawBackedRanges() const {
    std::vector<RvaRange> ranges;
    for (const SectionMap& section : sections) {
        if (section.status == SectionMapStatus::Mapped && section.executable() &&
            section.rawBackedBytes != 0U) {
            ranges.push_back(section.rawBackedRange());
        }
    }
    return NormalizeRvaRanges(std::move(ranges));
}

const SectionMap* PeImageMap::sectionAt(std::size_t index) const noexcept {
    if (index >= sections.size()) {
        return nullptr;
    }
    return &sections[index];
}

// ---------------------------------------------------------------------------
// 解析与映射
// ---------------------------------------------------------------------------

namespace {

// 归一化后的区间集合里是否完整包含 span。集合必须已 NormalizeRvaRanges 过
// （相邻区间已合并），所以"跨两个相邻区间"不会被误判成不包含。
bool RangesContainSpan(const std::vector<RvaRange>& normalized, const RvaRange& span) noexcept {
    if (span.empty()) {
        return false;
    }
    for (const RvaRange& range : normalized) {
        if (range.rva > span.rva) {
            break;  // 已排序：后面的区间起点只会更大
        }
        if (range.containsRange(span)) {
            return true;
        }
    }
    return false;
}

// 解析节表并把每个节按边界校验后映射进 image。畸形节不终止整轮，只标记并跳过。
void MapSections(const std::uint8_t* data, std::size_t size, PeImageMap& map) {
    std::vector<RvaRange> accepted;
    accepted.reserve(static_cast<std::size_t>(map.header.sectionCount) + 1U);

    // I-02：PE 头是最先被放进映像的东西（BuildPeImageMap 里已 memcpy），因此它
    // 必须像一个"已接受的区间"那样参与重叠检查。否则 VirtualAddress 落在头里的节
    // 会被判 Mapped 并把头部字节覆盖掉，同一个 RVA 就有了两个互相矛盾的来源
    // （TranslateRva 说它是节，TranslateFileOffset 又把两个文件偏移映射到它）。
    // 用**声明的** SizeOfHeaders 而不是实际拷贝长度：文件被截断不改变"这段
    // RVA 属于头部"这个事实。
    RvaRange declaredHeaderRange;
    declaredHeaderRange.rva = 0U;
    declaredHeaderRange.length = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(map.header.sizeOfHeaders, map.header.sizeOfImage));
    if (!declaredHeaderRange.empty()) {
        accepted.push_back(declaredHeaderRange);
    }

    std::uint64_t mappedCount = 0U;
    std::uint64_t defectCount = 0U;

    for (std::uint16_t index = 0U; index < map.header.sectionCount; ++index) {
        const std::uint64_t entryOffset =
            map.header.sectionTableFileOffset + static_cast<std::uint64_t>(index) * kSectionHeaderSize;

        SectionMap section;
        char rawName[9] = {};
        bool nameOk = true;
        for (std::uint64_t byteIndex = 0U; byteIndex < 8U; ++byteIndex) {
            std::uint8_t nameByte = 0U;
            if (!ReadU8(data, size, entryOffset + byteIndex, nameByte)) {
                nameOk = false;
                break;
            }
            rawName[byteIndex] = static_cast<char>(nameByte);
        }
        // 节表整体的边界在 BuildPeImageMap 里已校验过；这里再取一次是为了不依赖
        // 上游校验的正确性 —— 越界读一次都不允许发生。
        std::uint32_t virtualSize = 0U;
        std::uint32_t virtualAddress = 0U;
        std::uint32_t sizeOfRawData = 0U;
        std::uint32_t pointerToRawData = 0U;
        std::uint32_t characteristics = 0U;
        const bool fieldsOk =
            nameOk && ReadU32(data, size, entryOffset + 8U, virtualSize) &&
            ReadU32(data, size, entryOffset + 12U, virtualAddress) &&
            ReadU32(data, size, entryOffset + 16U, sizeOfRawData) &&
            ReadU32(data, size, entryOffset + 20U, pointerToRawData) &&
            ReadU32(data, size, entryOffset + 36U, characteristics);

        section.name.assign(rawName, std::char_traits<char>::length(rawName));
        section.virtualSize = virtualSize;
        section.virtualAddress = virtualAddress;
        section.sizeOfRawData = sizeOfRawData;
        section.pointerToRawData = pointerToRawData;
        section.characteristics = characteristics;

        if (!fieldsOk) {
            section.status = SectionMapStatus::NotComparable;
            section.defect = SectionDefectReason::RawDataOutOfFile;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // VirtualSize 为 0 的老式节退回 SizeOfRawData；两者都为 0 就没有虚拟范围。
        const std::uint32_t effective = (virtualSize != 0U) ? virtualSize : sizeOfRawData;
        section.effectiveVirtualSize = effective;
        if (effective == 0U) {
            section.status = SectionMapStatus::NotComparable;
            section.defect = SectionDefectReason::ZeroVirtualExtent;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        const std::uint64_t virtualEnd =
            static_cast<std::uint64_t>(virtualAddress) + static_cast<std::uint64_t>(effective);
        if (virtualEnd > 0xFFFFFFFFULL) {
            section.status = SectionMapStatus::NotComparable;
            section.defect = SectionDefectReason::VirtualRangeOverflow;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }
        // I-02 新增校验：VirtualAddress + VirtualSize 不得越过 SizeOfImage。
        if (virtualEnd > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
            section.status = SectionMapStatus::NotComparable;
            section.defect = SectionDefectReason::VirtualRangeOutOfImage;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // I-02 新增校验：节区间与 PE 头或前面已接受的节重叠。重叠时保留先出现的
        // 那一份，后来者标不可比较 —— 无法判断哪一份才是真的映射内容，因此后来者
        // 不该给出比较结论；保留先者是为了让结果可复现，重叠范围会一并进
        // notComparableRanges。accepted 里第一项就是 PE 头区间。
        bool overlaps = false;
        RvaRange candidate;
        candidate.rva = virtualAddress;
        candidate.length = effective;
        for (const RvaRange& earlier : accepted) {
            if (earlier.overlaps(candidate)) {
                overlaps = true;
                break;
            }
        }
        if (overlaps) {
            section.status = SectionMapStatus::NotComparable;
            section.defect = SectionDefectReason::OverlapsEarlierSection;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // raw 支撑长度：loader 只把 min(SizeOfRawData, VirtualSize) 拷进映像，
        // raw > virtual 的尾部填充不进映像，也就不该进比较。
        const std::uint32_t rawBacked = std::min(sizeOfRawData, effective);
        if (rawBacked != 0U) {
            const std::uint64_t rawEnd =
                static_cast<std::uint64_t>(pointerToRawData) + static_cast<std::uint64_t>(rawBacked);
            if (rawEnd > 0xFFFFFFFFULL) {
                section.status = SectionMapStatus::NotComparable;
                section.defect = SectionDefectReason::RawRangeOverflow;
                ++defectCount;
                map.sections.push_back(std::move(section));
                continue;
            }
            // I-02 新增校验：PointerToRawData + SizeOfRawData 不得越过文件尾。
            // 截断的节只跳过这一个节，其余节照常映射。
            if (rawEnd > static_cast<std::uint64_t>(size)) {
                section.status = SectionMapStatus::NotComparable;
                section.defect = SectionDefectReason::RawDataOutOfFile;
                ++defectCount;
                map.sections.push_back(std::move(section));
                continue;
            }
        }

        section.rawBackedBytes = rawBacked;
        section.zeroFillBytes = effective - rawBacked;
        section.status = SectionMapStatus::Mapped;
        section.defect = SectionDefectReason::None;

        if (rawBacked != 0U) {
            std::memcpy(map.image.data() + virtualAddress,
                        data + pointerToRawData,
                        static_cast<std::size_t>(rawBacked));
        }
        // 零填充区已经是 0（image 初始化为 0），不需要再写，但要记入 zeroFillRanges。

        accepted.push_back(candidate);
        ++mappedCount;
        map.sections.push_back(std::move(section));
    }

    for (const SectionMap& section : map.sections) {
        if (section.status == SectionMapStatus::Mapped) {
            if (section.rawBackedBytes != 0U) {
                map.rawBackedRanges.push_back(section.rawBackedRange());
            }
            if (section.zeroFillBytes != 0U) {
                map.zeroFillRanges.push_back(section.zeroFillRange());
            }
        } else if (section.effectiveVirtualSize != 0U) {
            // 畸形节的虚拟范围只有在落进映像内时才可标注；越界的部分本来就不存在。
            const std::uint64_t end = static_cast<std::uint64_t>(section.virtualAddress) +
                                      static_cast<std::uint64_t>(section.effectiveVirtualSize);
            const std::uint64_t clampedEnd = std::min<std::uint64_t>(end, map.header.sizeOfImage);
            if (section.virtualAddress < map.header.sizeOfImage && clampedEnd > section.virtualAddress) {
                RvaRange range;
                range.rva = section.virtualAddress;
                range.length = static_cast<std::uint32_t>(clampedEnd - section.virtualAddress);
                map.notComparableRanges.push_back(range);
            }
        }
    }

    map.sectionCoverage.requestedBegin = OptionalU64::of(0U);
    map.sectionCoverage.requestedEnd = OptionalU64::of(map.header.sectionCount);
    map.sectionCoverage.processedBegin = OptionalU64::of(0U);
    map.sectionCoverage.processedEnd = OptionalU64::of(map.header.sectionCount);
    map.sectionCoverage.succeeded = mappedCount;
    map.sectionCoverage.failed = defectCount;
    map.sectionCoverage.totalKnown = OptionalU64::of(map.header.sectionCount);
}

// I-03 关键判据：归一化没做成时，map.image 里留下的是**首选基址**的字节，而现场
// 读到的是加载器按目标基址改写过的字节。此时逐字节比较会在每一个重定位点上报出
// 一条"未解释代码差异" —— 正是 I-01 明令禁止的批量误报；反过来若现场也取自这份
// 未归一化的字节，又会给出一个自信的"未发现差异"。两个方向都错。
// 唯一诚实的做法：把整份映像标不可比较，让差异引擎把它们记成"已排除"，
// coverage.skipped 非零，结论自然降到 Indeterminate。
void PushWholeImageNotComparable(PeImageMap& map) {
    if (map.header.sizeOfImage == 0U) {
        return;
    }
    RvaRange whole;
    whole.rva = 0U;
    whole.length = map.header.sizeOfImage;
    map.notComparableRanges.push_back(whole);
}

void MarkWholeImageNotComparable(PeImageMap& map) {
    // imageNotNormalized 只描述"重定位归一化失败"这一个原因，别的调用方（DVRT）
    // 不许顺手把它置上 —— 否则 UI 会把一个 DVRT 版本未知说成"基址没归一化"。
    map.relocation.imageNotNormalized = true;
    PushWholeImageNotComparable(map);
}

// I-03：按 .reloc 目录把映像从 preferredImageBase 归一化到 loadedBase。
void ApplyRelocations(PeImageMap& map) {
    RelocationReport& report = map.relocation;
    report.delta = map.loadedBase - map.header.preferredImageBase;

    // 后面要按条目校验"目标是否有文件字节支撑"，先把集合归一化，让相邻区间合并，
    // 否则跨两个相邻 raw 支撑区的目标会被误判成无支撑。
    map.rawBackedRanges = NormalizeRvaRanges(std::move(map.rawBackedRanges));

    report.coverage.requestedBegin = OptionalU64::of(map.header.relocationDirectoryRva);
    report.coverage.requestedEnd =
        OptionalU64::of(static_cast<std::uint64_t>(map.header.relocationDirectoryRva) +
                        static_cast<std::uint64_t>(map.header.relocationDirectorySize));
    report.coverage.processedBegin = OptionalU64::of(map.header.relocationDirectoryRva);
    report.coverage.processedEnd = OptionalU64::of(map.header.relocationDirectoryRva);

    if (report.delta == 0U) {
        report.status = RelocationStatus::NotNeeded;
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(0U);
        return;
    }

    if (map.header.relocationsStripped()) {
        // 声明 RELOCS_STRIPPED 却要求换基址：无法归一化，调用方必须看见这个状态，
        // 不能默默按"没有差异"处理，更不能拿未归一化的字节当磁盘参考去比。
        report.status = RelocationStatus::Stripped;
        MarkWholeImageNotComparable(map);
        return;
    }

    const std::uint32_t dirRva = map.header.relocationDirectoryRva;
    const std::uint32_t dirSize = map.header.relocationDirectorySize;
    if (dirRva == 0U || dirSize < kRelocationBlockHeaderSize) {
        report.status = RelocationStatus::DirectoryMissing;
        MarkWholeImageNotComparable(map);
        return;
    }
    const std::uint64_t dirEnd = static_cast<std::uint64_t>(dirRva) + static_cast<std::uint64_t>(dirSize);
    if (dirEnd > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        report.status = RelocationStatus::DirectoryMalformed;
        MarkWholeImageNotComparable(map);
        return;
    }

    // 目录必须落在有文件字节支撑的范围里，否则读到的是零填充，解析出来的块头全是
    // 伪造的 0 长度 —— 那不是"重定位表为空"，而是"我们根本没拿到重定位表"。
    RvaRange directoryRange;
    directoryRange.rva = dirRva;
    directoryRange.length = dirSize;
    const std::vector<RvaRange> backed =
        IntersectRvaRanges(std::vector<RvaRange>{directoryRange}, map.rawBackedRanges);
    if (RvaRangesTotalBytes(backed) != static_cast<std::uint64_t>(dirSize)) {
        report.status = RelocationStatus::DirectoryUnbacked;
        MarkWholeImageNotComparable(map);
        return;
    }

    const std::uint8_t* image = map.image.data();
    const std::size_t imageSize = map.image.size();
    bool malformed = false;
    std::uint32_t consumed = 0U;

    while (consumed < dirSize) {
        if (dirSize - consumed < kRelocationBlockHeaderSize) {
            malformed = true;
            break;
        }
        const std::uint64_t blockOffset = static_cast<std::uint64_t>(dirRva) + consumed;
        std::uint32_t blockRva = 0U;
        std::uint32_t blockSize = 0U;
        if (!ReadU32(image, imageSize, blockOffset, blockRva) ||
            !ReadU32(image, imageSize, blockOffset + 4U, blockSize)) {
            malformed = true;
            break;
        }
        if (blockSize == 0U) {
            // 长度 0 的块会让循环不前进；按截断处理并停止，已应用的部分保留。
            malformed = true;
            break;
        }
        if (blockSize < kRelocationBlockHeaderSize || blockSize > dirSize - consumed) {
            malformed = true;
            break;
        }
        const std::uint32_t entryBytes = blockSize - static_cast<std::uint32_t>(kRelocationBlockHeaderSize);
        if ((entryBytes % 2U) != 0U) {
            malformed = true;
            break;
        }
        const std::uint32_t entryCount = entryBytes / 2U;

        for (std::uint32_t entryIndex = 0U; entryIndex < entryCount; ++entryIndex) {
            std::uint16_t entry = 0U;
            const std::uint64_t entryOffset =
                blockOffset + kRelocationBlockHeaderSize + static_cast<std::uint64_t>(entryIndex) * 2U;
            if (!ReadU16(image, imageSize, entryOffset, entry)) {
                malformed = true;
                break;
            }
            ++report.entriesTotal;

            const std::uint16_t type = static_cast<std::uint16_t>(entry >> 12U);
            const std::uint64_t targetRva64 =
                static_cast<std::uint64_t>(blockRva) + static_cast<std::uint64_t>(entry & 0x0FFFU);

            if (type == kRelAbsolute) {
                // 对齐填充项，不改写任何字节。按"已正确处理"记账，否则真实 PE 的
                // 覆盖率永远不可能完整。
                ++report.entriesAbsolute;
                continue;
            }

            if (type == kRelDir64 || type == kRelHighLow) {
                const std::uint32_t width = (type == kRelDir64) ? 8U : 4U;
                if (targetRva64 + width > static_cast<std::uint64_t>(imageSize)) {
                    ++report.entriesOutOfRange;
                    continue;
                }
                RvaRange targetSpan;
                targetSpan.rva = static_cast<std::uint32_t>(targetRva64);
                targetSpan.length = width;
                // I-02：目标必须整段有文件字节支撑。落在零填充区时映像里是 0 而
                // 文件里根本没有这些字节 —— 读出 0、加 delta、写回去，等于在
                // "契约上必须为 0"的范围里留下非 0 值，还把凭空造出来的值当成
                // 磁盘参考。跨 raw/零填充边界更糟：进位会溢到可比较字节里。
                // 因此一律拒绝应用，并按不可比较记账。
                if (!RangesContainSpan(map.rawBackedRanges, targetSpan)) {
                    ++report.entriesUnbackedTarget;
                    report.unbackedTargetRanges.push_back(targetSpan);
                    map.notComparableRanges.push_back(targetSpan);
                    continue;
                }
                const std::size_t at = static_cast<std::size_t>(targetRva64);
                if (type == kRelDir64) {
                    std::uint64_t value = 0U;
                    std::memcpy(&value, map.image.data() + at, sizeof(value));
                    value += report.delta;
                    std::memcpy(map.image.data() + at, &value, sizeof(value));
                } else {
                    std::uint32_t value = 0U;
                    std::memcpy(&value, map.image.data() + at, sizeof(value));
                    value += static_cast<std::uint32_t>(report.delta & 0xFFFFFFFFULL);
                    std::memcpy(map.image.data() + at, &value, sizeof(value));
                }
                ++report.entriesApplied;
                RvaRange touched;
                touched.rva = static_cast<std::uint32_t>(targetRva64);
                touched.length = width;
                report.touchedRanges.push_back(touched);
                continue;
            }

            // 不支持的类型：只把受影响的字节范围标成不可比较，绝不让整个映像失败。
            ++report.entriesUnsupported;
            const std::uint32_t span = UnsupportedRelocationSpan(type);
            if (targetRva64 < static_cast<std::uint64_t>(map.header.sizeOfImage)) {
                const std::uint64_t end =
                    std::min<std::uint64_t>(targetRva64 + span, map.header.sizeOfImage);
                UnsupportedRelocation record;
                record.type = type;
                record.range.rva = static_cast<std::uint32_t>(targetRva64);
                record.range.length = static_cast<std::uint32_t>(end - targetRva64);
                report.unsupported.push_back(record);
                map.notComparableRanges.push_back(record.range);
            } else {
                UnsupportedRelocation record;
                record.type = type;
                record.range.rva = 0U;
                record.range.length = 0U;
                report.unsupported.push_back(record);
            }

            if (type == kRelHighAdj) {
                // HIGHADJ 额外吃掉紧随其后的一个 WORD 参数。不跳过它，后面的条目
                // 会整体错位，把参数当成重定位项去改写字节。
                // 参数字**不是**一个重定位条目，所以不进 entriesTotal —— 计进去会
                // 让 succeeded + failed 永远小于 totalKnown，覆盖率永远不完整，
                // describeRemaining() 报出一个幻影剩余量（I-03 / F-06）。
                if (entryIndex + 1U < entryCount) {
                    ++entryIndex;
                    ++report.entriesSkippedParameter;
                } else {
                    malformed = true;
                    break;
                }
            }
        }

        if (malformed) {
            break;
        }
        ++report.blocksProcessed;
        consumed += blockSize;
        report.coverage.processedEnd =
            OptionalU64::of(static_cast<std::uint64_t>(dirRva) + consumed);
    }

    report.touchedRanges = NormalizeRvaRanges(std::move(report.touchedRanges));
    report.unbackedTargetRanges = NormalizeRvaRanges(std::move(report.unbackedTargetRanges));

    if (malformed) {
        report.status = RelocationStatus::DirectoryMalformed;
        // 停在半路：剩下那些块的目标散落在哪里我们并不知道（块头的 VirtualAddress
        // 没有必须升序的保证），因此无法给"哪一段还没归一化"划一个下界。
        // 已应用的部分也一并放弃比较 —— 宁可多标不可比较，也不要给出一份
        // 半归一化的磁盘参考。
        MarkWholeImageNotComparable(map);
    } else if (report.entriesUnsupported != 0U || report.entriesOutOfRange != 0U ||
               report.entriesUnbackedTarget != 0U) {
        report.status = RelocationStatus::AppliedWithUnsupported;
    } else {
        report.status = RelocationStatus::Applied;
    }

    report.coverage.succeeded = report.entriesApplied + report.entriesAbsolute;
    report.coverage.failed =
        report.entriesUnsupported + report.entriesOutOfRange + report.entriesUnbackedTarget;
    report.coverage.totalKnown = OptionalU64::of(report.entriesTotal);
}

// ---------------------------------------------------------------------------
// I-03 DVRT
// ---------------------------------------------------------------------------

// [rva, rva+length) 是否整段落在有文件字节支撑的范围内。
// 这一条是 DVRT 解析的地基：LoadConfig 与表本体若落在零填充区，读出来的是一片
// 0，于是 Size=0、TableOffset=0，解析器会得出"这份 PE 没有 DVRT"——那是把
// "从没采到"当成了"确实没有"。所以读之前必须先要求正面的支撑证据。
bool SpanIsRawBacked(const PeImageMap& map, std::uint64_t rva, std::uint64_t length) noexcept {
    if (length == 0U) {
        return false;
    }
    const std::uint64_t end = rva + length;
    if (end > 0xFFFFFFFFULL || end > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        return false;
    }
    RvaRange span;
    span.rva = static_cast<std::uint32_t>(rva);
    span.length = static_cast<std::uint32_t>(length);
    return RangesContainSpan(map.rawBackedRanges, span);
}

// 把一个符号段的 payload 当作 IMAGE_BASE_RELOCATION 块序列走一遍。
// 返回 false 表示容器结构没走通 —— 此时"加载器会改哪些字节"无从界定，调用方
// 必须按范围未知处理，而不是当作"这一段没有位点"。
bool WalkDvrtBlocks(const PeImageMap& map,
                    std::uint64_t payloadRva,
                    std::uint32_t payloadBytes,
                    std::uint32_t entryStride,
                    DvrtSymbolGroup& group,
                    std::vector<RvaRange>& siteRanges,
                    std::vector<RvaRange>& pageRanges) {
    const std::uint8_t* image = map.image.data();
    const std::size_t imageSize = map.image.size();
    const std::uint32_t sizeOfImage = map.header.sizeOfImage;

    std::uint32_t consumed = 0U;
    while (static_cast<std::uint64_t>(payloadBytes - consumed) >= kRelocationBlockHeaderSize) {
        const std::uint64_t blockOffset = payloadRva + consumed;
        std::uint32_t blockRva = 0U;
        std::uint32_t blockSize = 0U;
        if (!ReadU32(image, imageSize, blockOffset, blockRva) ||
            !ReadU32(image, imageSize, blockOffset + 4U, blockSize)) {
            return false;
        }
        if (static_cast<std::uint64_t>(blockSize) < kRelocationBlockHeaderSize ||
            blockSize > payloadBytes - consumed) {
            return false;
        }
        // 块头必须描述一个真实存在的页。这两条是 IMAGE_BASE_RELOCATION 的硬不变式，
        // 这里拿它们当校验位：不认识的符号若其实不是块容器（例如 GUARD_RF_PROLOGUE
        // 的 payload 前面还有一个自己的头），几乎一定会在这里被挡下，而不是被误读
        // 成一串看似合理的页 —— 误读会把范围标到错误的地方，等于漏标真正的位点。
        if ((blockRva % kRelocationPageBytes) != 0U || blockRva >= sizeOfImage) {
            return false;
        }
        ++group.blocksWalked;

        const std::uint32_t entryBytes =
            blockSize - static_cast<std::uint32_t>(kRelocationBlockHeaderSize);
        if (entryStride == 0U) {
            // 符号不认识：位点解不出来，但块头已经把影响范围限定在这一页里。
            // 页粒度比位点粗，却是可以证明的上界，比"整份映像不可比较"精确得多。
            const std::uint64_t pageEnd = std::min<std::uint64_t>(
                static_cast<std::uint64_t>(blockRva) + kRelocationPageBytes, sizeOfImage);
            RvaRange page;
            page.rva = blockRva;
            page.length = static_cast<std::uint32_t>(pageEnd - blockRva);
            pageRanges.push_back(page);
        } else {
            for (std::uint32_t offset = 0U; offset + entryStride <= entryBytes;
                 offset += entryStride) {
                const std::uint64_t recordOffset =
                    blockOffset + kRelocationBlockHeaderSize + offset;
                std::uint32_t record = 0U;
                if (entryStride == 4U) {
                    if (!ReadU32(image, imageSize, recordOffset, record)) {
                        return false;
                    }
                } else {
                    std::uint16_t narrow = 0U;
                    if (!ReadU16(image, imageSize, recordOffset, narrow)) {
                        return false;
                    }
                    record = narrow;
                }
                // 三种已知符号的记录都把页内偏移放在低 12 位。
                const std::uint64_t site =
                    static_cast<std::uint64_t>(blockRva) + (record & 0x0FFFU);
                if (site >= static_cast<std::uint64_t>(sizeOfImage)) {
                    // 位点越过映像：没有任何字节可标，单独记账而不是悄悄丢掉。
                    ++group.sitesOutsideImage;
                    continue;
                }
                const std::uint64_t siteEnd =
                    std::min<std::uint64_t>(site + kDvrtSiteSpan, sizeOfImage);
                RvaRange range;
                range.rva = static_cast<std::uint32_t>(site);
                range.length = static_cast<std::uint32_t>(siteEnd - site);
                siteRanges.push_back(range);
                ++group.sitesDecoded;
            }
        }
        consumed += blockSize;
    }

    // 剩下的字节不足一个块头，装不下另一个块；但它们必须是填充（全 0），否则那里
    // 还藏着我们没看懂的记录，"影响范围已界定"这句话就不成立。
    for (std::uint32_t index = consumed; index < payloadBytes; ++index) {
        std::uint8_t pad = 0U;
        if (!ReadU8(image, imageSize, payloadRva + index, pad) || pad != 0U) {
            return false;
        }
    }
    return true;
}

// I-03：从 LoadConfig 目录定位 IMAGE_DYNAMIC_RELOCATION_TABLE，把加载器会改写的
// 位点标成不可比较。整份文件的解析状态**不受**本函数影响 —— DVRT 出问题只降级
// 范围，不让映像失败。
void ParseDynamicRelocations(PeImageMap& map) {
    DynamicRelocationReport& report = map.dynamicRelocation;

    // "确实没有 DVRT"：账目按"0 个符号段、全部处理完"记，覆盖率才可能判完整。
    const auto declareNotPresent = [&report]() {
        report.status = DvrtStatus::NotPresent;
        report.coverage.requestedBegin = OptionalU64::of(0U);
        report.coverage.requestedEnd = OptionalU64::of(0U);
        report.coverage.processedBegin = OptionalU64::of(0U);
        report.coverage.processedEnd = OptionalU64::of(0U);
        report.coverage.totalKnown = OptionalU64::of(0U);
    };
    // "可能有 DVRT，但划不出边界"：没有资格对任何一个字节说"这里没有差异"，
    // 整份映像进不可比较范围，差异引擎会把它们记成"已排除"。
    const auto declareUnbounded = [&map, &report](DvrtStatus status) {
        report.status = status;
        report.extentUnknown = true;
        PushWholeImageNotComparable(map);
    };

    if (map.header.dataDirectoryCount <= kDirectoryIndexLoadConfig) {
        declareNotPresent();
        return;
    }
    const std::uint32_t loadConfigRva = map.header.loadConfigDirectoryRva;
    const std::uint32_t loadConfigSize = map.header.loadConfigDirectorySize;
    if (loadConfigRva == 0U || loadConfigSize == 0U) {
        declareNotPresent();
        return;
    }
    report.loadConfigRva = OptionalU64::of(loadConfigRva);
    report.loadConfigDeclaredSize = OptionalU64::of(loadConfigSize);
    if (static_cast<std::uint64_t>(loadConfigSize) < kLoadConfigMinSizeForDvrt) {
        // 目录声明的结构体短于 DVRT 字段出现的那个版本 —— 确实没有 DVRT。
        declareNotPresent();
        return;
    }
    if (!SpanIsRawBacked(map, loadConfigRva, kLoadConfigMinSizeForDvrt)) {
        declareUnbounded(DvrtStatus::LoadConfigUnusable);
        return;
    }

    const std::uint8_t* image = map.image.data();
    const std::size_t imageSize = map.image.size();
    std::uint32_t structSize = 0U;
    std::uint32_t tableOffset = 0U;
    std::uint16_t tableSectionOneBased = 0U;
    if (!ReadU32(image, imageSize, loadConfigRva + kLoadConfigOffsetStructSize, structSize) ||
        !ReadU32(image, imageSize, loadConfigRva + kLoadConfigOffsetDvrtTableOffset, tableOffset) ||
        !ReadU16(image, imageSize, loadConfigRva + kLoadConfigOffsetDvrtTableSection,
                 tableSectionOneBased)) {
        declareUnbounded(DvrtStatus::LoadConfigUnusable);
        return;
    }
    report.loadConfigStructSize = OptionalU64::of(structSize);
    if (static_cast<std::uint64_t>(structSize) < kLoadConfigMinSizeForDvrt) {
        // 结构体自己声明它没有那么长：DVRT 字段在这个版本里不存在。
        declareNotPresent();
        return;
    }
    if (tableOffset == 0U || tableSectionOneBased == 0U) {
        declareNotPresent();
        return;
    }

    // DynamicValueRelocTableSection 是 1 基的节序号，偏移相对该节的 VirtualAddress。
    const SectionMap* host = map.sectionAt(static_cast<std::size_t>(tableSectionOneBased) - 1U);
    if (host == nullptr || host->status != SectionMapStatus::Mapped) {
        declareUnbounded(DvrtStatus::LoadConfigUnusable);
        return;
    }
    const std::uint64_t tableRva =
        static_cast<std::uint64_t>(host->virtualAddress) + static_cast<std::uint64_t>(tableOffset);
    report.tableRva = OptionalU64::of(tableRva);
    if (!SpanIsRawBacked(map, tableRva, kDvrtTableHeaderSize)) {
        declareUnbounded(DvrtStatus::TableUnbacked);
        return;
    }

    std::uint32_t version = 0U;
    std::uint32_t tableSize = 0U;
    if (!ReadU32(image, imageSize, tableRva, version) ||
        !ReadU32(image, imageSize, tableRva + 4U, tableSize)) {
        declareUnbounded(DvrtStatus::TableUnbacked);
        return;
    }
    report.tableVersion = OptionalU64::of(version);
    report.tableSize = OptionalU64::of(tableSize);
    if (version != kDvrtTableVersionOne) {
        // 版本不认识就一个字节都不解码。"看不懂"不等于"没有"。
        declareUnbounded(DvrtStatus::UnsupportedVersion);
        return;
    }

    const std::uint64_t entriesRva = tableRva + kDvrtTableHeaderSize;
    report.coverage.requestedBegin = OptionalU64::of(entriesRva);
    report.coverage.requestedEnd = OptionalU64::of(entriesRva + tableSize);
    report.coverage.processedBegin = OptionalU64::of(entriesRva);
    report.coverage.processedEnd = OptionalU64::of(entriesRva);

    if (tableSize == 0U) {
        // 版本合法、表为空：这是正面证据，"没有动态重定位位点"成立。
        report.status = DvrtStatus::Parsed;
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(0U);
        return;
    }
    if (entriesRva + tableSize > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        declareUnbounded(DvrtStatus::Malformed);
        return;
    }
    if (!SpanIsRawBacked(map, entriesRva, tableSize)) {
        declareUnbounded(DvrtStatus::TableUnbacked);
        return;
    }

    bool tableTruncated = false;   // 表在半路断了：后面还有几段我们并不知道
    std::uint64_t groupsFailed = 0U;
    std::uint32_t consumed = 0U;
    while (static_cast<std::uint64_t>(tableSize - consumed) >= kDvrtEntryHeaderSize) {
        const std::uint64_t entryOffset = entriesRva + consumed;
        std::uint64_t symbol = 0U;
        std::uint32_t payloadBytes = 0U;
        if (!ReadU64(image, imageSize, entryOffset, symbol) ||
            !ReadU32(image, imageSize, entryOffset + 8U, payloadBytes)) {
            tableTruncated = true;
            break;
        }
        consumed += static_cast<std::uint32_t>(kDvrtEntryHeaderSize);
        if (payloadBytes == 0U || payloadBytes > tableSize - consumed) {
            tableTruncated = true;
            break;
        }

        DvrtSymbolGroup group;
        group.symbol = symbol;
        group.payloadBytes = payloadBytes;
        group.entryStride = DvrtEntryStride(symbol);
        group.containerWalked =
            WalkDvrtBlocks(map, entriesRva + consumed, payloadBytes, group.entryStride, group,
                           report.siteRanges, report.unknownSymbolRanges);
        group.decoded = group.containerWalked && group.entryStride != 0U;

        ++report.groupsTotal;
        report.sitesDecoded += group.sitesDecoded;
        report.sitesOutsideImage += group.sitesOutsideImage;
        if (group.decoded) {
            ++report.groupsDecoded;
        } else if (group.containerWalked) {
            ++report.groupsUnknownSymbol;
        } else {
            ++groupsFailed;
        }
        report.groups.push_back(group);

        if (!group.containerWalked) {
            // 这一段的容器都没走通，后面的段起点也就不可信了，停在这里。
            break;
        }
        consumed += payloadBytes;
        report.coverage.processedEnd = OptionalU64::of(entriesRva + consumed);
    }

    if (!tableTruncated && groupsFailed == 0U) {
        // 表尾剩余不足一个条目头，装不下另一个符号段；但必须是填充（全 0）。
        for (std::uint32_t index = consumed; index < tableSize; ++index) {
            std::uint8_t pad = 0U;
            if (!ReadU8(image, imageSize, entriesRva + index, pad) || pad != 0U) {
                tableTruncated = true;
                break;
            }
        }
    }

    report.siteRanges = NormalizeRvaRanges(std::move(report.siteRanges));
    report.unknownSymbolRanges = NormalizeRvaRanges(std::move(report.unknownSymbolRanges));

    report.coverage.succeeded = report.groupsDecoded;
    // 符号不认识不是"失败"而是"跳过了位点级解码"：影响范围仍被页粒度界定住了。
    report.coverage.skipped = report.groupsUnknownSymbol;
    report.coverage.failed = groupsFailed;
    report.coverage.truncated = tableTruncated ? 1U : 0U;

    if (tableTruncated || groupsFailed != 0U) {
        // totalKnown 保持 unset：表断在半路，后面还有几个符号段我们并不知道。
        declareUnbounded(DvrtStatus::Malformed);
    } else {
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(report.groupsTotal);
        report.status = (report.groupsUnknownSymbol != 0U) ? DvrtStatus::ParsedWithUnknownSymbol
                                                           : DvrtStatus::Parsed;
    }

    // 位点与未知符号页一律进不可比较范围：磁盘上根本不存在加载器改写后的字节，
    // 拿磁盘原值去比必然报出一条"未解释差异"（I-01 明令禁止的批量误报）。
    // 即使上面已经整份标不可比较，这里也照样记 —— siteRanges 是独立导出的集合，
    // 差异引擎可以用它把差异标注成"动态重定位位点"而不是简单排除。
    for (const RvaRange& range : report.siteRanges) {
        map.notComparableRanges.push_back(range);
    }
    for (const RvaRange& range : report.unknownSymbolRanges) {
        map.notComparableRanges.push_back(range);
    }
}

} // namespace

PeImageMap BuildPeImageMap(const std::uint8_t* fileBytes,
                           std::size_t fileSize,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options) {
    if (fileBytes == nullptr || fileSize == 0U) {
        return MakeFailure(PeParseStatus::EmptyInput, "pe.parse.emptyInput", fileSize, loadedBase);
    }
    if (fileSize < kDosHeaderSize) {
        return MakeFailure(PeParseStatus::TruncatedDosHeader, "pe.parse.truncatedDosHeader",
                           fileSize, loadedBase);
    }

    std::uint16_t dosMagic = 0U;
    if (!ReadU16(fileBytes, fileSize, 0U, dosMagic) || dosMagic != kDosSignature) {
        return MakeFailure(PeParseStatus::BadDosSignature, "pe.parse.badDosSignature",
                           fileSize, loadedBase);
    }

    std::uint32_t lfanew = 0U;
    if (!ReadU32(fileBytes, fileSize, kElfanewOffset, lfanew)) {
        return MakeFailure(PeParseStatus::TruncatedDosHeader, "pe.parse.truncatedDosHeader",
                           fileSize, loadedBase);
    }
    // e_lfanew 必须 4 字节对齐且落在文件内；否则后续所有偏移都不可信。
    if ((lfanew % 4U) != 0U || static_cast<std::uint64_t>(lfanew) >= fileSize) {
        return MakeFailure(PeParseStatus::BadNtHeaderOffset, "pe.parse.badNtHeaderOffset",
                           fileSize, loadedBase);
    }

    const std::uint64_t ntOffset = lfanew;
    std::uint32_t ntSignature = 0U;
    if (!ReadU32(fileBytes, fileSize, ntOffset, ntSignature)) {
        return MakeFailure(PeParseStatus::TruncatedNtHeaders, "pe.parse.truncatedNtHeaders",
                           fileSize, loadedBase);
    }
    if (ntSignature != kNtSignature) {
        return MakeFailure(PeParseStatus::BadNtSignature, "pe.parse.badNtSignature",
                           fileSize, loadedBase);
    }

    const std::uint64_t fileHeaderOffset = ntOffset + 4U;
    std::uint16_t machine = 0U;
    std::uint16_t sectionCount = 0U;
    std::uint32_t timeDateStamp = 0U;
    std::uint16_t sizeOfOptionalHeader = 0U;
    std::uint16_t fileCharacteristics = 0U;
    if (!ReadU16(fileBytes, fileSize, fileHeaderOffset + 0U, machine) ||
        !ReadU16(fileBytes, fileSize, fileHeaderOffset + 2U, sectionCount) ||
        !ReadU32(fileBytes, fileSize, fileHeaderOffset + 4U, timeDateStamp) ||
        !ReadU16(fileBytes, fileSize, fileHeaderOffset + 16U, sizeOfOptionalHeader) ||
        !ReadU16(fileBytes, fileSize, fileHeaderOffset + 18U, fileCharacteristics)) {
        return MakeFailure(PeParseStatus::TruncatedNtHeaders, "pe.parse.truncatedNtHeaders",
                           fileSize, loadedBase);
    }

    const std::uint64_t optionalOffset = fileHeaderOffset + kFileHeaderSize;
    if (sizeOfOptionalHeader < kOptionalHeader64MinSize) {
        return MakeFailure(PeParseStatus::TruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }
    std::uint16_t optionalMagic = 0U;
    if (!ReadU16(fileBytes, fileSize, optionalOffset, optionalMagic)) {
        return MakeFailure(PeParseStatus::TruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }
    if (optionalMagic != kOptionalMagicPe32Plus) {
        // 本层只承诺 PE64。PE32 需要另一套字段偏移，不在本轮范围内 —— 明确拒绝
        // 好过按 64 位偏移去读 32 位头。
        return MakeFailure(PeParseStatus::UnsupportedOptionalMagic, "pe.parse.unsupportedOptionalMagic",
                           fileSize, loadedBase);
    }

    PeHeaderFacts header;
    header.machine = machine;
    header.sectionCount = sectionCount;
    header.fileCharacteristics = fileCharacteristics;
    header.timeDateStamp = timeDateStamp;
    header.ntHeadersFileOffset = ntOffset;

    const bool optionalOk =
        ReadU32(fileBytes, fileSize, optionalOffset + 16U, header.entryPointRva) &&
        ReadU64(fileBytes, fileSize, optionalOffset + 24U, header.preferredImageBase) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 32U, header.sectionAlignment) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 36U, header.fileAlignment) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 56U, header.sizeOfImage) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 60U, header.sizeOfHeaders) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 64U, header.checkSum) &&
        ReadU32(fileBytes, fileSize, optionalOffset + 108U, header.numberOfRvaAndSizes);
    if (!optionalOk) {
        return MakeFailure(PeParseStatus::TruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }

    const std::uint64_t directoryBase = optionalOffset + kOptionalHeader64MinSize;
    // I-02：NumberOfRvaAndSizes 是文件自己声明的，必须再用**可选头的实际长度**卡一道。
    // 只校验 SizeOfOptionalHeader >= 112 是不够的：声明 SizeOfOptionalHeader=112、
    // NumberOfRvaAndSizes=16 时，目录项落在 112 字节之后 —— 那里已经是节表字节。
    // 于是攻击者用一个 8 字节的节名就能完全控制 BASERELOC 目录的 RVA/size，而那
    // 决定了哪些字节会被改写、哪些范围被标不可比较。读取本身有边界检查所以不会
    // 越界，但解析器绝不能采信一个从未校验过的偏移。
    const std::uint32_t directoryRoom = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(sizeOfOptionalHeader) - kOptionalHeader64MinSize) /
        kDataDirectoryEntrySize);
    const std::uint32_t directoryCount =
        std::min<std::uint32_t>({header.numberOfRvaAndSizes, 16U, directoryRoom});
    header.dataDirectoryCount = directoryCount;
    if (directoryCount > kDirectoryIndexExport) {
        const std::uint64_t at = directoryBase + kDirectoryIndexExport * kDataDirectoryEntrySize;
        if (!ReadU32(fileBytes, fileSize, at, header.exportDirectoryRva) ||
            !ReadU32(fileBytes, fileSize, at + 4U, header.exportDirectorySize)) {
            header.exportDirectoryRva = 0U;
            header.exportDirectorySize = 0U;
        }
    }
    if (directoryCount > kDirectoryIndexBaseReloc) {
        const std::uint64_t at = directoryBase + kDirectoryIndexBaseReloc * kDataDirectoryEntrySize;
        if (!ReadU32(fileBytes, fileSize, at, header.relocationDirectoryRva) ||
            !ReadU32(fileBytes, fileSize, at + 4U, header.relocationDirectorySize)) {
            header.relocationDirectoryRva = 0U;
            header.relocationDirectorySize = 0U;
        }
    }
    // I-03：DVRT 的入口。目录条目数不足 11 时这两个字段留 0，ParseDynamicRelocations
    // 会据此判"确实没有 LoadConfig 目录"。
    if (directoryCount > kDirectoryIndexLoadConfig) {
        const std::uint64_t at = directoryBase + kDirectoryIndexLoadConfig * kDataDirectoryEntrySize;
        if (!ReadU32(fileBytes, fileSize, at, header.loadConfigDirectoryRva) ||
            !ReadU32(fileBytes, fileSize, at + 4U, header.loadConfigDirectorySize)) {
            header.loadConfigDirectoryRva = 0U;
            header.loadConfigDirectorySize = 0U;
        }
    }

    if (sectionCount == 0U || sectionCount > options.maxSectionCount) {
        return MakeFailure(PeParseStatus::InvalidSectionCount, "pe.parse.invalidSectionCount",
                           fileSize, loadedBase);
    }
    if (header.sizeOfImage == 0U || header.sizeOfImage > options.maxImageBytes ||
        header.sizeOfImage < header.sizeOfHeaders) {
        return MakeFailure(PeParseStatus::InvalidSizeOfImage, "pe.parse.invalidSizeOfImage",
                           fileSize, loadedBase);
    }
    // 对齐值非法说明整个头都不可信 —— 节偏移的所有推导都建立在它们之上。
    if (!IsPowerOfTwo(header.sectionAlignment) || !IsPowerOfTwo(header.fileAlignment) ||
        header.fileAlignment < 512U || header.fileAlignment > 65536U ||
        header.sectionAlignment < header.fileAlignment) {
        return MakeFailure(PeParseStatus::InvalidAlignment, "pe.parse.invalidAlignment",
                           fileSize, loadedBase);
    }

    header.sectionTableFileOffset = optionalOffset + sizeOfOptionalHeader;
    const std::uint64_t sectionTableEnd =
        header.sectionTableFileOffset + static_cast<std::uint64_t>(sectionCount) * kSectionHeaderSize;
    if (sectionTableEnd > fileSize) {
        return MakeFailure(PeParseStatus::TruncatedSectionTable, "pe.parse.truncatedSectionTable",
                           fileSize, loadedBase);
    }
    // I-02 新增校验：节表条目数必须与 SizeOfHeaders 自洽。节表越过 SizeOfHeaders
    // 说明头部声明本身矛盾，此时无法确定哪一份说法为准，整份文件不再解析。
    if (sectionTableEnd > static_cast<std::uint64_t>(header.sizeOfHeaders)) {
        return MakeFailure(PeParseStatus::SectionTableExceedsHeaders,
                           "pe.parse.sectionTableExceedsHeaders", fileSize, loadedBase);
    }

    PeImageMap map;
    map.status = PeParseStatus::Ok;
    map.header = header;
    map.loadedBase = loadedBase;
    map.fileSize = fileSize;
    map.image.assign(static_cast<std::size_t>(header.sizeOfImage), 0U);

    // 头部：文件里可能比 SizeOfHeaders 短（截断样本），按实际可读长度复制。
    const std::uint64_t headerCopy =
        std::min<std::uint64_t>({static_cast<std::uint64_t>(header.sizeOfHeaders),
                                 static_cast<std::uint64_t>(fileSize),
                                 static_cast<std::uint64_t>(header.sizeOfImage)});
    if (headerCopy != 0U) {
        std::memcpy(map.image.data(), fileBytes, static_cast<std::size_t>(headerCopy));
    }
    map.headerRange.rva = 0U;
    map.headerRange.length = static_cast<std::uint32_t>(headerCopy);
    if (headerCopy != 0U) {
        map.rawBackedRanges.push_back(map.headerRange);
    }

    MapSections(fileBytes, fileSize, map);

    // DVRT 解析要按"有文件字节支撑"判据校验 LoadConfig 与表本体，先把集合归一化
    // （相邻区间合并），否则跨两个相邻 raw 支撑区的跨度会被误判成无支撑。
    map.rawBackedRanges = NormalizeRvaRanges(std::move(map.rawBackedRanges));
    // 放在应用 .reloc 之前解析：DVRT 的入口字段（LoadConfig.Size / TableOffset /
    // TableSection）与表内容（块的 RVA、页内偏移）都不是 VA，不受基址重定位影响；
    // 提前读只是为了不引入"半归一化映像"这个额外变量。
    ParseDynamicRelocations(map);

    if (options.applyRelocations) {
        ApplyRelocations(map);
    } else {
        map.relocation.delta = loadedBase - header.preferredImageBase;
        map.relocation.status = (map.relocation.delta == 0U) ? RelocationStatus::NotNeeded
                                                             : RelocationStatus::DirectoryMissing;
        if (map.relocation.delta != 0U) {
            // 调用方主动关掉了归一化，但基址确实变了 —— 判据和"没有重定位目录"
            // 完全一样：这份映像不能当磁盘参考用。
            MarkWholeImageNotComparable(map);
        }
    }

    map.rawBackedRanges = NormalizeRvaRanges(std::move(map.rawBackedRanges));
    map.zeroFillRanges = NormalizeRvaRanges(std::move(map.zeroFillRanges));
    map.notComparableRanges = NormalizeRvaRanges(std::move(map.notComparableRanges));
    // 不可比较范围优先：畸形节与不支持的重定位覆盖到的字节不给任何比较结论。
    // rawBackedRanges 保留减之前的口径，差异引擎据此把这些字节记成"已排除"。
    map.comparableRanges = SubtractRvaRanges(map.rawBackedRanges, map.notComparableRanges);
    map.zeroFillRanges = SubtractRvaRanges(map.zeroFillRanges, map.notComparableRanges);
    return map;
}

PeImageMap BuildPeImageMap(const std::vector<std::uint8_t>& fileBytes,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options) {
    return BuildPeImageMap(fileBytes.empty() ? nullptr : fileBytes.data(), fileBytes.size(),
                           loadedBase, options);
}

// ---------------------------------------------------------------------------
// 转换
// ---------------------------------------------------------------------------

RvaTranslation TranslateRva(const PeImageMap& map, std::uint32_t rva) noexcept {
    RvaTranslation result;
    if (!map.valid() || rva >= map.header.sizeOfImage) {
        result.kind = RvaKind::OutsideImage;
        return result;
    }

    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        if (section.effectiveVirtualSize == 0U) {
            continue;
        }
        if (!section.virtualRange().contains(rva)) {
            continue;
        }
        result.sectionIndex = index;
        if (section.status != SectionMapStatus::Mapped) {
            result.kind = RvaKind::NotComparable;
            return result;
        }
        const std::uint32_t offsetInSection = rva - section.virtualAddress;
        if (offsetInSection < section.rawBackedBytes) {
            result.kind = RvaKind::SectionRawBacked;
            result.fileOffset = OptionalU64::of(static_cast<std::uint64_t>(section.pointerToRawData) +
                                                offsetInSection);
            return result;
        }
        // 零填充：映像里确实是 0，但文件里没有对应字节 —— fileOffset 保持 unset。
        result.kind = RvaKind::SectionZeroFill;
        return result;
    }

    if (map.headerRange.contains(rva)) {
        result.kind = RvaKind::Header;
        result.fileOffset = OptionalU64::of(rva);
        return result;
    }

    result.kind = RvaKind::SectionGap;
    return result;
}

FileOffsetTranslation TranslateFileOffset(const PeImageMap& map, std::uint64_t fileOffset) noexcept {
    FileOffsetTranslation result;
    if (!map.valid() || fileOffset >= map.fileSize) {
        result.kind = FileOffsetKind::OutsideFile;
        return result;
    }

    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        const std::uint32_t rawSpan = (section.status == SectionMapStatus::Mapped)
                                          ? section.rawBackedBytes
                                          : section.sizeOfRawData;
        if (rawSpan == 0U) {
            continue;
        }
        const std::uint64_t begin = section.pointerToRawData;
        const std::uint64_t end = begin + rawSpan;
        if (fileOffset < begin || fileOffset >= end) {
            continue;
        }
        result.sectionIndex = index;
        if (section.status != SectionMapStatus::Mapped) {
            result.kind = FileOffsetKind::NotComparable;
            return result;
        }
        result.kind = FileOffsetKind::SectionRawData;
        result.rva = OptionalU64::of(static_cast<std::uint64_t>(section.virtualAddress) +
                                     (fileOffset - begin));
        return result;
    }

    if (map.headerRange.length != 0U && fileOffset < map.headerRange.length) {
        result.kind = FileOffsetKind::Header;
        result.rva = OptionalU64::of(fileOffset);
        return result;
    }

    result.kind = FileOffsetKind::NotMappedByAnySection;
    return result;
}

std::size_t SectionIndexForRva(const PeImageMap& map, std::uint32_t rva) noexcept {
    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        if (section.status == SectionMapStatus::Mapped && section.virtualRange().contains(rva)) {
            return index;
        }
    }
    return kInvalidSectionIndex;
}

std::string SectionNameForRva(const PeImageMap& map, std::uint32_t rva) {
    const std::size_t index = SectionIndexForRva(map, rva);
    if (index != kInvalidSectionIndex) {
        return map.sections[index].name;
    }
    if (map.headerRange.contains(rva)) {
        return std::string("(headers)");
    }
    return std::string();
}

bool ReadNormalizedBytes(const PeImageMap& map,
                         std::uint32_t rva,
                         std::uint32_t length,
                         std::vector<std::uint8_t>& out) {
    if (!map.valid() || length == 0U) {
        return false;
    }
    const std::uint64_t end = static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    if (end > static_cast<std::uint64_t>(map.image.size())) {
        return false;
    }
    RvaRange span;
    span.rva = rva;
    span.length = length;
    // I-05：整段必须落在 comparableRanges 内 —— 它等于"有文件字节支撑"减去
    // "被标不可比较"。这一条判据同时挡住三种伪造：不可比较范围（畸形节 / 不支持
    // 的重定位 / 未归一化的映像）、零填充区、以及不属于任何节的对齐间隙。后两者
    // 在映像里确实是 0，但文件里没有对应字节；返回"成功 + 一片 0"会让调用方把
    // 补出来的 0 当成磁盘上的真实内容。
    if (!RangesContainSpan(map.comparableRanges, span)) {
        return false;
    }
    out.assign(map.image.begin() + static_cast<std::ptrdiff_t>(rva),
               map.image.begin() + static_cast<std::ptrdiff_t>(end));
    return true;
}

} // namespace Ksword::Evidence
