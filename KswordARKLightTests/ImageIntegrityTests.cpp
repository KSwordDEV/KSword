// I 模块（内核完整性检查深化）的离线自动测试。
//
// 覆盖编号：I-02 I-03 I-04 I-05 I-06 I-09 I-10。
//
// I-03 里的 DVRT（Windows 10+ IMAGE_DYNAMIC_RELOCATION_TABLE）部分覆盖：
//   * 三类已支持符号（3 IMPORT_CONTROL_TRANSFER / 4 INDIR_CONTROL_TRANSFER /
//     5 SWITCHTABLE_BRANCH）的位点解码、记录宽度、位点范围与账目；
//   * 不认识的符号只按块的页粒度标不可比较，不让整份映像失败；
//   * 表畸形（版本未知 / size 越界 / 块长度非法 / 块 VA 未页对齐 /
//     BaseRelocSize 越界 / 尾部有未解释字节）一律按范围降级，PE 解析仍然成功；
//   * LoadConfig 或表本体落在零填充区时判"不可用"，绝不推成"没有 DVRT"。
// 未覆盖：真实 ntoskrnl 样本（离线测试不带二进制样本）、DVRT 版本 2+ 的字段含义。
//
// 夹具全部由本文件用代码拼出 PE64 字节，不依赖磁盘上的样本文件；期望值（RVA、
// 文件偏移、长度、零填充边界）是按下面的常量手工算出来后写死的，不是从被测代码
// 反算的。被测代码只有 shared/evidence/PeImageMap.* 与 shared/evidence/ImageDiff.*，
// 测试里没有第二份映射/差异实现。
//
// 关于"现场"字节的来源（这条是本套件的地基）：差异比较的现场侧一律由本文件的
// IndependentLoadedImage() 独立铺出来，**绝不**拿 PeImageMap 归一化后的 map.image
// 当现场。后者会让每一条 CompareImage 断言退化成"参考对参考"：只要在生产归一化
// 里悄悄多改几个字节，整套测试照样全绿。IndependentLoadedImage 按 PE 规范和夹具
// 自己声明的重定位点手工计算，因此"零条未解释差异"才是一句有内容的断言。

#include "TestSupport.h"

#include "../shared/evidence/ImageDiff.h"
#include "../shared/evidence/PeImageMap.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

// ---------------------------------------------------------------------------
// PE64 夹具构造器
// ---------------------------------------------------------------------------
// 固定布局（手工算好，测试的期望值都基于这几个常量）：
//   0x0000  DOS 头，e_lfanew = 0x40
//   0x0040  'PE\0\0'
//   0x0044  IMAGE_FILE_HEADER（20 字节）
//   0x0058  IMAGE_OPTIONAL_HEADER64（240 字节 = 112 + 16 * 8）
//   0x0148  节表，每条 40 字节
constexpr std::size_t kNtOffset = 0x40U;
constexpr std::size_t kFileHeaderOffset = kNtOffset + 4U;          // 0x44
constexpr std::size_t kOptionalOffset = kFileHeaderOffset + 20U;   // 0x58
constexpr std::size_t kDataDirectoryOffset = kOptionalOffset + 112U; // 0xC8
constexpr std::size_t kSectionHeaderSize = 40U;
// 节表紧跟在可选头之后：SizeOfOptionalHeader 是可变的，节表偏移必须跟着它走。
// SizeOfOptionalHeader == 240 时正好是 0x148。

constexpr std::uint32_t kCharsCode = 0x60000020U;   // CNT_CODE | MEM_EXECUTE | MEM_READ
constexpr std::uint32_t kCharsData = 0xC0000040U;   // CNT_INITIALIZED_DATA | READ | WRITE
constexpr std::uint32_t kCharsReloc = 0x42000040U;  // CNT_INITIALIZED_DATA | DISCARDABLE | READ

struct SectionSpec final {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t pointerToRawData = 0;
    std::uint32_t sizeOfRawData = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint8_t> content;  // 真正写进文件的字节，长度可与 sizeOfRawData 不同
};

struct PeBuilder final {
    std::uint64_t imageBase = 0x0000000140000000ULL;
    std::uint32_t sectionAlignment = 0x1000U;
    std::uint32_t fileAlignment = 0x200U;
    std::uint32_t sizeOfHeaders = 0x400U;
    std::uint32_t sizeOfImage = 0x5000U;
    std::uint32_t entryPointRva = 0x1000U;
    std::uint16_t machine = 0x8664U;
    std::uint16_t optionalMagic = 0x020BU;
    std::uint16_t sizeOfOptionalHeader = 240U;
    std::uint16_t fileCharacteristics = 0x0022U;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::uint32_t timeDateStamp = 0x60112233U;
    std::uint32_t checkSum = 0x00ABCDEFU;
    std::uint32_t relocDirectoryRva = 0U;
    std::uint32_t relocDirectorySize = 0U;
    // 数据目录 10 = LOAD_CONFIG，DVRT 的入口。两者同时为 0 表示"没有 LoadConfig"。
    std::uint32_t loadConfigDirectoryRva = 0U;
    std::uint32_t loadConfigDirectorySize = 0U;
    std::uint32_t numberOfRvaAndSizes = 16U;
    std::vector<SectionSpec> sections;
    std::size_t truncateTo = 0U;  // 非 0 时把生成的文件截断到该长度
};

void Ensure(std::vector<std::uint8_t>& buffer, std::size_t needed) {
    if (buffer.size() < needed) {
        buffer.resize(needed, 0U);
    }
}

void Put8(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint8_t value) {
    Ensure(buffer, at + 1U);
    buffer[at] = value;
}

void Put16(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint16_t value) {
    Put8(buffer, at, static_cast<std::uint8_t>(value & 0xFFU));
    Put8(buffer, at + 1U, static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void Put32(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint32_t value) {
    Put16(buffer, at, static_cast<std::uint16_t>(value & 0xFFFFU));
    Put16(buffer, at + 2U, static_cast<std::uint16_t>((value >> 16U) & 0xFFFFU));
}

void Put64(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint64_t value) {
    Put32(buffer, at, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    Put32(buffer, at + 4U, static_cast<std::uint32_t>((value >> 32U) & 0xFFFFFFFFULL));
}

std::uint64_t ReadU64At(const std::vector<std::uint8_t>& buffer, std::size_t at) {
    std::uint64_t value = 0U;
    if (at + 8U <= buffer.size()) {
        std::memcpy(&value, buffer.data() + at, sizeof(value));
    }
    return value;
}

std::size_t SectionTableOffset(const PeBuilder& spec) {
    return kOptionalOffset + static_cast<std::size_t>(spec.sizeOfOptionalHeader);
}

std::vector<std::uint8_t> BuildPe(const PeBuilder& spec) {
    std::vector<std::uint8_t> file;
    file.assign(spec.sizeOfHeaders, 0U);

    Put16(file, 0U, 0x5A4DU);                 // 'MZ'
    Put32(file, 0x3CU, static_cast<std::uint32_t>(kNtOffset));
    Put32(file, kNtOffset, 0x00004550U);      // 'PE\0\0'

    Put16(file, kFileHeaderOffset + 0U, spec.machine);
    Put16(file, kFileHeaderOffset + 2U, static_cast<std::uint16_t>(spec.sections.size()));
    Put32(file, kFileHeaderOffset + 4U, spec.timeDateStamp);
    Put32(file, kFileHeaderOffset + 8U, 0U);
    Put32(file, kFileHeaderOffset + 12U, 0U);
    Put16(file, kFileHeaderOffset + 16U, spec.sizeOfOptionalHeader);
    Put16(file, kFileHeaderOffset + 18U, spec.fileCharacteristics);

    Put16(file, kOptionalOffset + 0U, spec.optionalMagic);
    Put32(file, kOptionalOffset + 16U, spec.entryPointRva);
    Put64(file, kOptionalOffset + 24U, spec.imageBase);
    Put32(file, kOptionalOffset + 32U, spec.sectionAlignment);
    Put32(file, kOptionalOffset + 36U, spec.fileAlignment);
    Put32(file, kOptionalOffset + 56U, spec.sizeOfImage);
    Put32(file, kOptionalOffset + 60U, spec.sizeOfHeaders);
    Put32(file, kOptionalOffset + 64U, spec.checkSum);
    Put32(file, kOptionalOffset + 108U, spec.numberOfRvaAndSizes);
    // 数据目录 5 = BASERELOC。只有当可选头真的长到能装下第 6 个目录（112 + 6*8
    // = 160 字节）时才写；否则那 8 个字节其实位于节表里，写进去就是在伪造节头。
    if (spec.sizeOfOptionalHeader >= 160U) {
        Put32(file, kDataDirectoryOffset + 5U * 8U, spec.relocDirectoryRva);
        Put32(file, kDataDirectoryOffset + 5U * 8U + 4U, spec.relocDirectorySize);
    }
    // 目录 10 需要可选头长到 112 + 11 * 8 = 200 字节。
    if (spec.sizeOfOptionalHeader >= 200U) {
        Put32(file, kDataDirectoryOffset + 10U * 8U, spec.loadConfigDirectoryRva);
        Put32(file, kDataDirectoryOffset + 10U * 8U + 4U, spec.loadConfigDirectorySize);
    }

    for (std::size_t index = 0; index < spec.sections.size(); ++index) {
        const SectionSpec& section = spec.sections[index];
        const std::size_t at = SectionTableOffset(spec) + index * kSectionHeaderSize;
        for (std::size_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
            const std::uint8_t value =
                (byteIndex < section.name.size())
                    ? static_cast<std::uint8_t>(section.name[byteIndex])
                    : static_cast<std::uint8_t>(0U);
            Put8(file, at + byteIndex, value);
        }
        Put32(file, at + 8U, section.virtualSize);
        Put32(file, at + 12U, section.virtualAddress);
        Put32(file, at + 16U, section.sizeOfRawData);
        Put32(file, at + 20U, section.pointerToRawData);
        Put32(file, at + 24U, 0U);
        Put32(file, at + 28U, 0U);
        Put16(file, at + 32U, 0U);
        Put16(file, at + 34U, 0U);
        Put32(file, at + 36U, section.characteristics);
    }

    for (const SectionSpec& section : spec.sections) {
        if (section.content.empty()) {
            continue;
        }
        const std::size_t at = static_cast<std::size_t>(section.pointerToRawData);
        Ensure(file, at + section.content.size());
        std::memcpy(file.data() + at, section.content.data(), section.content.size());
    }

    if (spec.truncateTo != 0U && spec.truncateTo < file.size()) {
        file.resize(spec.truncateTo);
    }
    return file;
}

// 确定性、恒不为 0 的填充。为 0 会让"读不到的字节被补成 00"这类缺陷侥幸通过。
std::vector<std::uint8_t> PatternBytes(std::size_t count, std::uint32_t seed) {
    std::vector<std::uint8_t> data(count, 0U);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint32_t mixed = (static_cast<std::uint32_t>(index) * 7U + seed) % 191U;
        data[index] = static_cast<std::uint8_t>(0x40U + mixed);
    }
    return data;
}

// 重定位类型编号。夹具侧自己写死，不从被测代码取。
constexpr std::uint16_t kRelTypeAbsolute = 0U;
constexpr std::uint16_t kRelTypeHighLow = 3U;
constexpr std::uint16_t kRelTypeHighAdj = 4U;
constexpr std::uint16_t kRelTypeDir64 = 10U;
constexpr std::uint16_t kRelTypeReservedSeven = 7U;   // 本层不支持的类型

struct RelocEntrySpec final {
    std::uint16_t type = 0;
    std::uint32_t rva = 0;
};

// 单块 .reloc 目录：8 字节块头 + 每条 2 字节。
std::vector<std::uint8_t> BuildRelocBlock(std::uint32_t blockRva,
                                          const std::vector<RelocEntrySpec>& entries) {
    std::vector<std::uint8_t> blob;
    const std::uint32_t blockSize = 8U + static_cast<std::uint32_t>(entries.size()) * 2U;
    blob.assign(blockSize, 0U);
    Put32(blob, 0U, blockRva);
    Put32(blob, 4U, blockSize);
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const std::uint16_t packed = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(entries[index].type) << 12U) |
            static_cast<std::uint16_t>((entries[index].rva - blockRva) & 0x0FFFU));
        Put16(blob, 8U + index * 2U, packed);
    }
    return blob;
}

// ---------------------------------------------------------------------------
// 夹具自己的"加载器"：完全不调用被测代码
// ---------------------------------------------------------------------------
// 按 PE 规范手工把文件铺成映像：
//   * 头部复制 min(SizeOfHeaders, 文件长度, SizeOfImage) 字节；
//   * 每个节复制 min(SizeOfRawData, 生效 VirtualSize) 字节到 VirtualAddress，
//     其余保持 0（零填充）；raw 越过文件尾或虚拟范围越过 SizeOfImage 的节不铺；
//   * 基址变化时，对夹具自己声明的 DIR64 / HIGHLOW 重定位点加 delta —— 真实
//     加载器就是这么做的，包括目标落在零填充区的情况。
// 这是差异比较里"现场"的唯一来源。它和 PeImageMap 没有任何共用代码，所以
// "重定位差异不产生未解释差异"这类断言才真的在验证生产归一化的正确性。
std::vector<std::uint8_t> IndependentLoadedImage(const PeBuilder& spec,
                                                 const std::vector<RelocEntrySpec>& relocEntries,
                                                 std::uint64_t loadedBase) {
    const std::vector<std::uint8_t> file = BuildPe(spec);
    std::vector<std::uint8_t> image(static_cast<std::size_t>(spec.sizeOfImage), 0U);

    const std::size_t headerCopy =
        std::min<std::size_t>({static_cast<std::size_t>(spec.sizeOfHeaders), file.size(),
                               static_cast<std::size_t>(spec.sizeOfImage)});
    if (headerCopy != 0U) {
        std::memcpy(image.data(), file.data(), headerCopy);
    }

    for (const SectionSpec& section : spec.sections) {
        const std::uint32_t effective =
            (section.virtualSize != 0U) ? section.virtualSize : section.sizeOfRawData;
        if (effective == 0U) {
            continue;
        }
        const std::uint64_t virtualEnd =
            static_cast<std::uint64_t>(section.virtualAddress) + static_cast<std::uint64_t>(effective);
        if (virtualEnd > static_cast<std::uint64_t>(spec.sizeOfImage)) {
            continue;
        }
        const std::uint32_t rawBacked = std::min(section.sizeOfRawData, effective);
        if (rawBacked == 0U) {
            continue;
        }
        const std::uint64_t rawEnd = static_cast<std::uint64_t>(section.pointerToRawData) +
                                     static_cast<std::uint64_t>(rawBacked);
        if (rawEnd > static_cast<std::uint64_t>(file.size())) {
            continue;
        }
        std::memcpy(image.data() + section.virtualAddress,
                    file.data() + section.pointerToRawData,
                    static_cast<std::size_t>(rawBacked));
    }

    const std::uint64_t delta = loadedBase - spec.imageBase;
    if (delta == 0U) {
        return image;
    }
    for (const RelocEntrySpec& entry : relocEntries) {
        if (entry.type == kRelTypeDir64) {
            if (static_cast<std::uint64_t>(entry.rva) + 8U > static_cast<std::uint64_t>(spec.sizeOfImage)) {
                continue;
            }
            std::uint64_t value = 0U;
            std::memcpy(&value, image.data() + entry.rva, sizeof(value));
            value += delta;
            std::memcpy(image.data() + entry.rva, &value, sizeof(value));
        } else if (entry.type == kRelTypeHighLow) {
            if (static_cast<std::uint64_t>(entry.rva) + 4U > static_cast<std::uint64_t>(spec.sizeOfImage)) {
                continue;
            }
            std::uint32_t value = 0U;
            std::memcpy(&value, image.data() + entry.rva, sizeof(value));
            value += static_cast<std::uint32_t>(delta & 0xFFFFFFFFULL);
            std::memcpy(image.data() + entry.rva, &value, sizeof(value));
        }
        // 其余类型本层不支持：生产侧把它们的目标范围标不可比较，那些字节根本
        // 不进比较，所以这里保持磁盘原值即可。
    }
    return image;
}

// ---------------------------------------------------------------------------
// 夹具 A：节大小不等 + 零填充 + 间隙
//   SizeOfHeaders 0x400，SizeOfImage 0x5000
//   .text  VA 0x1000  VS 0x0A00  ptr 0x0400  raw 0x0800  -> raw 支撑 0x800，零填充 0x200
//   .data  VA 0x2000  VS 0x0400  ptr 0x0C00  raw 0x0200  -> raw 支撑 0x200，零填充 0x200
//   .pad   VA 0x3000  VS 0x0100  ptr 0x0E00  raw 0x0200  -> raw > virtual，支撑截到 0x100
//   文件长度 0x1000
// ---------------------------------------------------------------------------
PeBuilder MakeLayoutFixture() {
    PeBuilder spec;
    spec.sizeOfImage = 0x5000U;

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x0A00U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x0800U;
    text.characteristics = kCharsCode;
    text.content = PatternBytes(0x0800U, 1U);

    SectionSpec data;
    data.name = ".data";
    data.virtualAddress = 0x2000U;
    data.virtualSize = 0x0400U;
    data.pointerToRawData = 0x0C00U;
    data.sizeOfRawData = 0x0200U;
    data.characteristics = kCharsData;
    data.content = PatternBytes(0x0200U, 2U);

    SectionSpec pad;
    pad.name = ".pad";
    pad.virtualAddress = 0x3000U;
    pad.virtualSize = 0x0100U;
    pad.pointerToRawData = 0x0E00U;
    pad.sizeOfRawData = 0x0200U;
    pad.characteristics = kCharsData;
    pad.content = PatternBytes(0x0200U, 3U);

    spec.sections = {text, data, pad};
    return spec;
}

// ---------------------------------------------------------------------------
// 夹具 B：差异定位用的大 .text，跨页边界在 RVA 0x2000
//   SizeOfHeaders 0x400，SizeOfImage 0x6000
//   .text  VA 0x1000  VS 0x3000  ptr 0x0400  raw 0x3000   （文件 0x0400..0x33FF）
//   .data  VA 0x4000  VS 0x1000  ptr 0x3400  raw 0x0200   （文件 0x3400..0x35FF）
//   可比较范围 = [0x0000,0x0400) ∪ [0x1000,0x4200)
// ---------------------------------------------------------------------------
constexpr std::uint64_t kDiffLoadedBase = 0x0000000140000000ULL;

PeBuilder MakeDiffFixture() {
    PeBuilder spec;
    spec.imageBase = kDiffLoadedBase;
    spec.sizeOfImage = 0x6000U;

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x3000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x3000U;
    text.characteristics = kCharsCode;
    text.content = PatternBytes(0x3000U, 11U);

    SectionSpec data;
    data.name = ".data";
    data.virtualAddress = 0x4000U;
    data.virtualSize = 0x1000U;
    data.pointerToRawData = 0x3400U;
    data.sizeOfRawData = 0x0200U;
    data.characteristics = kCharsData;
    data.content = PatternBytes(0x0200U, 12U);

    spec.sections = {text, data};
    return spec;
}

// ---------------------------------------------------------------------------
// 夹具 C：带 .reloc 的映像，RVA 0x1100 处放一个指向自身的 DIR64 VA
//   .text  VA 0x1000  VS 0x1000  ptr 0x0400  raw 0x1000
//   .reloc VA 0x2000  ptr 0x1400
//   SizeOfImage 0x3000，ImageBase 0x140000000
// ---------------------------------------------------------------------------
constexpr std::uint64_t kRelocPreferredBase = 0x0000000140000000ULL;
constexpr std::uint64_t kRelocOtherBase = 0x0000000180000000ULL;
constexpr std::uint32_t kRelocTargetRva = 0x1100U;
constexpr std::uint32_t kUnsupportedTargetRva = 0x1150U;

// 用一段任意 .reloc 原始字节造夹具。畸形目录的用例直接手写块头字节，
// 期望值全部按 PE 规范手算，不经过被测代码。
PeBuilder MakeRelocSpecRaw(const std::vector<std::uint8_t>& relocBlob,
                           std::uint32_t dirRva,
                           std::uint32_t dirSize) {
    PeBuilder spec;
    spec.imageBase = kRelocPreferredBase;
    spec.sizeOfImage = 0x3000U;

    std::vector<std::uint8_t> textContent = PatternBytes(0x1000U, 21U);
    // 磁盘上的值就是"按首选基址装载时应有的 VA"。
    Put64(textContent, kRelocTargetRva - 0x1000U, kRelocPreferredBase + kRelocTargetRva);
    Put64(textContent, kUnsupportedTargetRva - 0x1000U, kRelocPreferredBase + kUnsupportedTargetRva);

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x1000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x1000U;
    text.characteristics = kCharsCode;
    text.content = textContent;

    SectionSpec reloc;
    reloc.name = ".reloc";
    reloc.virtualAddress = 0x2000U;
    reloc.virtualSize = 0x0200U;
    reloc.pointerToRawData = 0x1400U;
    reloc.sizeOfRawData = 0x0200U;
    reloc.characteristics = kCharsReloc;
    reloc.content = relocBlob;
    reloc.content.resize(0x0200U, 0U);   // 目录之后补零，保证 raw 支撑覆盖整段

    spec.sections = {text, reloc};
    spec.relocDirectoryRva = dirRva;
    spec.relocDirectorySize = dirSize;
    return spec;
}

PeBuilder MakeRelocSpec(const std::vector<RelocEntrySpec>& entries) {
    const std::vector<std::uint8_t> blob = BuildRelocBlock(0x1000U, entries);
    return MakeRelocSpecRaw(blob, 0x2000U, static_cast<std::uint32_t>(blob.size()));
}

std::vector<std::uint8_t> MakeRelocImage(const std::vector<RelocEntrySpec>& entries) {
    return BuildPe(MakeRelocSpec(entries));
}

// ---------------------------------------------------------------------------
// 夹具 D：带 LoadConfig + DVRT（IMAGE_DYNAMIC_RELOCATION_TABLE）的映像
// ---------------------------------------------------------------------------
// 布局（全部手算，期望值都基于这几个常量）：
//   SizeOfHeaders 0x400，SizeOfImage 0x4000，ImageBase 0x140000000
//   .text  VA 0x1000  VS 0x1000  ptr 0x0400  raw 0x1000   文件 0x0400..0x13FF
//   .rdata VA 0x2000  VS 0x1000  ptr 0x1400  raw 0x1000   文件 0x1400..0x23FF
//   文件长度 0x2400
//   LoadConfig 位于 .rdata 起始 → RVA 0x2000
//     +0    DWORD Size
//     +224  DWORD DynamicValueRelocTableOffset      （相对宿主节 VirtualAddress）
//     +228  WORD  DynamicValueRelocTableSection     （1 基节序号，.rdata = 2）
//   DVRT 表 → RVA 0x2000 + 0x200 = 0x2200，表头 8 字节，条目从 0x2208 开始
//   .reloc（可选）→ .rdata 偏移 0x400，即 RVA 0x2400
constexpr std::uint64_t kDvrtPreferredBase = 0x0000000140000000ULL;
constexpr std::uint32_t kDvrtSizeOfImage = 0x4000U;
constexpr std::uint32_t kDvrtTextRva = 0x1000U;
constexpr std::uint32_t kDvrtRdataRva = 0x2000U;
constexpr std::uint32_t kDvrtLoadConfigRva = 0x2000U;
constexpr std::uint32_t kDvrtTableOffsetInSection = 0x200U;
constexpr std::uint32_t kDvrtTableRva = 0x2200U;
constexpr std::uint32_t kDvrtEntriesRva = 0x2208U;
constexpr std::uint32_t kDvrtRelocOffsetInSection = 0x400U;
constexpr std::uint32_t kDvrtRelocRva = 0x2400U;
// IMAGE_LOAD_CONFIG_DIRECTORY64 至少要有 230 字节才装得下 DVRT 字段。
constexpr std::uint32_t kDvrtLoadConfigSize = 320U;
// 生产层给一个位点保守标记的字节数。夹具侧自己写死，不从被测代码取。
constexpr std::uint32_t kExpectedSiteSpan = 8U;

// 一个基址重定位块：8 字节块头 + 若干记录。stride 为夹具声明的记录宽度。
std::vector<std::uint8_t> DvrtBlock(std::uint32_t blockRva,
                                    std::uint32_t stride,
                                    const std::vector<std::uint32_t>& records,
                                    std::uint32_t sizeOfBlockOverride = 0U) {
    std::vector<std::uint8_t> block;
    const std::uint32_t size = 8U + static_cast<std::uint32_t>(records.size()) * stride;
    block.assign(size, 0U);
    Put32(block, 0U, blockRva);
    Put32(block, 4U, (sizeOfBlockOverride != 0U) ? sizeOfBlockOverride : size);
    for (std::size_t index = 0; index < records.size(); ++index) {
        const std::size_t at = 8U + index * stride;
        if (stride == 4U) {
            Put32(block, at, records[index]);
        } else {
            Put16(block, at, static_cast<std::uint16_t>(records[index] & 0xFFFFU));
        }
    }
    return block;
}

// 一个符号段：IMAGE_DYNAMIC_RELOCATION64 头（symbol 8 字节 + BaseRelocSize 4 字节）
// 后面跟 payload。sizeOverride 非 0 时写这个长度（用来造畸形样本）。
void AppendDvrtGroup(std::vector<std::uint8_t>& entries,
                     std::uint64_t symbol,
                     const std::vector<std::uint8_t>& payload,
                     std::uint32_t sizeOverride = 0U) {
    const std::size_t at = entries.size();
    entries.resize(at + 12U, 0U);
    Put64(entries, at, symbol);
    Put32(entries, at + 8U,
          (sizeOverride != 0U) ? sizeOverride : static_cast<std::uint32_t>(payload.size()));
    entries.insert(entries.end(), payload.begin(), payload.end());
}

// 表头 + 条目。sizeOverride 非 0 时写这个长度（用来造 size 越界样本）。
std::vector<std::uint8_t> DvrtTable(std::uint32_t version,
                                    const std::vector<std::uint8_t>& entries,
                                    std::uint32_t sizeOverride = 0U) {
    std::vector<std::uint8_t> table(8U, 0U);
    Put32(table, 0U, version);
    Put32(table, 4U,
          (sizeOverride != 0U) ? sizeOverride : static_cast<std::uint32_t>(entries.size()));
    table.insert(table.end(), entries.begin(), entries.end());
    return table;
}

// 标准三段表。每个位点的 RVA 都是手算的：
//   段 1 符号 3 IMPORT_CONTROL_TRANSFER，记录 4 字节，低 12 位是页内偏移
//        块 VA 0x1000，记录 0x00000120 / 0x00080340 → 位点 0x1120 / 0x1340
//   段 2 符号 4 INDIR_CONTROL_TRANSFER，记录 2 字节
//        块 VA 0x1000，记录 0x1500 / 0x27F0 → 位点 0x1500 / 0x17F0
//   段 3 符号 5 SWITCHTABLE_BRANCH，记录 2 字节（注意：不是 4 字节）
//        块 VA 0x1000，记录 0x3900 / 0x1A00 → 位点 0x1900 / 0x1A00
// 段长：12 + 16 = 28、12 + 12 = 24、12 + 12 = 24，合计 76 字节。
// 六个位点互不相邻，各占 8 字节，合计 48 字节不可比较。
std::vector<std::uint8_t> CanonicalDvrtEntries() {
    std::vector<std::uint8_t> entries;
    AppendDvrtGroup(entries, 3U, DvrtBlock(0x1000U, 4U, {0x00000120U, 0x00080340U}));
    AppendDvrtGroup(entries, 4U, DvrtBlock(0x1000U, 2U, {0x1500U, 0x27F0U}));
    AppendDvrtGroup(entries, 5U, DvrtBlock(0x1000U, 2U, {0x3900U, 0x1A00U}));
    return entries;
}

constexpr std::uint32_t kCanonicalDvrtEntriesBytes = 76U;
constexpr std::uint32_t kCanonicalSiteRva0 = 0x1120U;
constexpr std::uint32_t kCanonicalSiteRva1 = 0x1340U;
constexpr std::uint32_t kCanonicalSiteRva2 = 0x1500U;
constexpr std::uint32_t kCanonicalSiteRva3 = 0x17F0U;
constexpr std::uint32_t kCanonicalSiteRva4 = 0x1900U;
constexpr std::uint32_t kCanonicalSiteRva5 = 0x1A00U;

// 夹具 D 里那个可选 DIR64 重定位点。刻意避开上面六个 DVRT 位点。
constexpr std::uint32_t kDvrtRelocTargetRva = 0x1180U;

struct DvrtFixtureSpec final {
    std::vector<std::uint8_t> table;                    // 写进 .rdata 的 DVRT 表字节
    std::uint32_t loadConfigDirectorySize = kDvrtLoadConfigSize;
    std::uint32_t loadConfigStructSize = kDvrtLoadConfigSize;
    std::uint32_t tableOffsetInSection = kDvrtTableOffsetInSection;
    std::uint16_t tableSectionOneBased = 2U;            // .rdata
    bool writeLoadConfigDirectory = true;
    bool includeReloc = false;                          // 在 .rdata 0x400 处放一个 .reloc
    std::uint32_t rdataRawSize = 0x1000U;               // 调小可把 LoadConfig 推进零填充区
};

PeBuilder MakeDvrtFixture(const DvrtFixtureSpec& fixture) {
    PeBuilder spec;
    spec.imageBase = kDvrtPreferredBase;
    spec.sizeOfImage = kDvrtSizeOfImage;

    std::vector<std::uint8_t> textContent = PatternBytes(0x1000U, 31U);
    if (fixture.includeReloc) {
        // 磁盘上的值就是"按首选基址装载时应有的 VA"。
        Put64(textContent, kDvrtRelocTargetRva - kDvrtTextRva,
              kDvrtPreferredBase + kDvrtRelocTargetRva);
    }

    // .rdata 用非 0 噪声填满：读不到的字节被补成 00 这类缺陷不能靠"恰好是 0"蒙混。
    std::vector<std::uint8_t> rdataContent = PatternBytes(0x1000U, 42U);
    Put32(rdataContent, 0U, fixture.loadConfigStructSize);
    Put32(rdataContent, 224U, fixture.tableOffsetInSection);
    Put16(rdataContent, 228U, fixture.tableSectionOneBased);
    for (std::size_t index = 0; index < fixture.table.size(); ++index) {
        rdataContent[static_cast<std::size_t>(fixture.tableOffsetInSection) + index] =
            fixture.table[index];
    }
    if (fixture.includeReloc) {
        const std::vector<std::uint8_t> relocBlob =
            BuildRelocBlock(kDvrtTextRva, {RelocEntrySpec{kRelTypeDir64, kDvrtRelocTargetRva}});
        for (std::size_t index = 0; index < relocBlob.size(); ++index) {
            rdataContent[static_cast<std::size_t>(kDvrtRelocOffsetInSection) + index] =
                relocBlob[index];
        }
        spec.relocDirectoryRva = kDvrtRelocRva;
        spec.relocDirectorySize = static_cast<std::uint32_t>(relocBlob.size());
    }
    rdataContent.resize(fixture.rdataRawSize);

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = kDvrtTextRva;
    text.virtualSize = 0x1000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x1000U;
    text.characteristics = kCharsCode;
    text.content = textContent;

    SectionSpec rdata;
    rdata.name = ".rdata";
    rdata.virtualAddress = kDvrtRdataRva;
    rdata.virtualSize = 0x1000U;
    rdata.pointerToRawData = 0x1400U;
    rdata.sizeOfRawData = fixture.rdataRawSize;
    rdata.characteristics = kCharsData;
    rdata.content = rdataContent;

    spec.sections = {text, rdata};
    if (fixture.writeLoadConfigDirectory) {
        spec.loadConfigDirectoryRva = kDvrtLoadConfigRva;
        spec.loadConfigDirectorySize = fixture.loadConfigDirectorySize;
    }
    return spec;
}

PeImageMap BuildDvrtMap(const DvrtFixtureSpec& fixture, std::uint64_t loadedBase) {
    const PeBuilder spec = MakeDvrtFixture(fixture);
    return BuildPeImageMap(BuildPe(spec), loadedBase);
}

PeImageMap BuildCanonicalDvrtMap() {
    DvrtFixtureSpec fixture;
    fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
    return BuildDvrtMap(fixture, kDvrtPreferredBase);
}

// ---------------------------------------------------------------------------
// 夹具 E：SizeOfImage 不是页整数倍，用来验证位点被截断 / 落到映像外
//   SizeOfImage 0x3F00
//   .text  VA 0x1000 VS 0x1000 ptr 0x0400 raw 0x1000
//   .rdata VA 0x2000 VS 0x1000 ptr 0x1400 raw 0x1000
//   .tail  VA 0x3000 VS 0x0F00 ptr 0x2400 raw 0x0F00   → 恰好顶到 0x3F00
// 块 VA 0x3000，记录 0xEFC / 0xF80：
//   位点 0x3EFC → 8 字节会越过 0x3F00，截成 4 字节
//   位点 0x3F80 → 已经在映像外，一个字节都不标，单独记账
// ---------------------------------------------------------------------------
constexpr std::uint32_t kClipSizeOfImage = 0x3F00U;
constexpr std::uint32_t kClipSiteRva = 0x3EFCU;
constexpr std::uint32_t kClipSiteLength = 4U;

PeBuilder MakeDvrtClipFixture() {
    std::vector<std::uint8_t> entries;
    AppendDvrtGroup(entries, 3U, DvrtBlock(0x3000U, 4U, {0x00000EFCU, 0x00000F80U}));

    DvrtFixtureSpec fixture;
    fixture.table = DvrtTable(1U, entries);
    PeBuilder spec = MakeDvrtFixture(fixture);
    spec.sizeOfImage = kClipSizeOfImage;

    SectionSpec tail;
    tail.name = ".tail";
    tail.virtualAddress = 0x3000U;
    tail.virtualSize = 0x0F00U;
    tail.pointerToRawData = 0x2400U;
    tail.sizeOfRawData = 0x0F00U;
    tail.characteristics = kCharsData;
    tail.content = PatternBytes(0x0F00U, 53U);
    spec.sections.push_back(tail);
    return spec;
}

const SectionMap* FindSection(const PeImageMap& map, const char* name) {
    for (const SectionMap& section : map.sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

const ImageDiffEntry* EntryAt(const ImageDiffReport& report, std::uint32_t rva) {
    for (const ImageDiffEntry& entry : report.entries) {
        if (entry.rva == rva) {
            return &entry;
        }
    }
    return nullptr;
}

// 现场字节：由夹具自己的加载器铺出来，与被测的 PeImageMap 没有任何共用代码。
// 刻意**不**提供 LiveFromMap(map) 之类的便利函数 —— 那会让每条差异断言退化成
// 参考对参考，生产归一化被改坏也照样全绿（BLOCKER Q-01）。
LiveImageBytes LiveFromSpec(const PeBuilder& spec,
                            std::uint64_t loadedBase,
                            const std::vector<RelocEntrySpec>& relocEntries = {}) {
    return LiveImageBytes::fromBytes(0U, IndependentLoadedImage(spec, relocEntries, loadedBase));
}

ImageDiffOptions DefaultOptions() {
    ImageDiffOptions options;
    options.evidenceSource = "test.offline.fixture";
    options.reference.kind = ReferenceSourceKind::LocalDisk;
    options.reference.description = "fixture://disk";
    return options;
}

// ---------------------------------------------------------------------------
// I-02 PE 文件到映像的正确映射
// ---------------------------------------------------------------------------
void TestLayoutMapping(KswordTests::Suite& s) {
    const std::vector<std::uint8_t> file = BuildPe(MakeLayoutFixture());
    s.expect(file.size() == 0x1000U, L"I-02 fixture file length is the hand-computed 0x1000");

    const PeImageMap map = BuildPeImageMap(file, 0x0000000140000000ULL);
    s.expect(map.status == PeParseStatus::Ok, L"I-02 a well-formed PE64 parses");
    s.expect(map.image.size() == 0x5000U, L"I-02 the mapped image is exactly SizeOfImage bytes");
    s.expect(map.header.sectionAlignment == 0x1000U && map.header.fileAlignment == 0x200U,
             L"I-02 SectionAlignment and FileAlignment are read, not assumed");

    const SectionMap* text = FindSection(map, ".text");
    const SectionMap* data = FindSection(map, ".data");
    const SectionMap* pad = FindSection(map, ".pad");
    s.expect(text != nullptr && data != nullptr && pad != nullptr,
             L"I-02 all three sections are present in the section list");
    if (text == nullptr || data == nullptr || pad == nullptr) {
        return;
    }

    // raw != virtual：0x800 字节有文件支撑，剩下 0x200 是零填充。
    s.expect(text->status == SectionMapStatus::Mapped, L"I-02 .text maps cleanly");
    s.expect(text->rawBackedBytes == 0x0800U, L"I-02 .text raw-backed length is 0x800");
    s.expect(text->zeroFillBytes == 0x0200U, L"I-02 .text zero-fill length is 0x200");
    // raw > virtual：多出来的 0x100 字节尾部填充不进映像，也就不进比较。
    s.expect(pad->rawBackedBytes == 0x0100U,
             L"I-02 a section whose SizeOfRawData exceeds VirtualSize is clamped to VirtualSize");
    s.expect(pad->zeroFillBytes == 0U, L"I-02 the clamped section has no zero fill");

    const RvaTranslation atStart = TranslateRva(map, 0x1000U);
    s.expect(atStart.kind == RvaKind::SectionRawBacked &&
                 atStart.fileOffset == OptionalU64::of(0x0400U),
             L"I-02 RVA 0x1000 maps to file offset 0x400");
    const RvaTranslation atLastRaw = TranslateRva(map, 0x17FFU);
    s.expect(atLastRaw.kind == RvaKind::SectionRawBacked &&
                 atLastRaw.fileOffset == OptionalU64::of(0x0BFFU),
             L"I-02 RVA 0x17FF maps to file offset 0xBFF");
    const RvaTranslation atZeroFill = TranslateRva(map, 0x1800U);
    s.expect(atZeroFill.kind == RvaKind::SectionZeroFill && !atZeroFill.fileOffset.present,
             L"I-02 RVA 0x1800 reports zero-fill and carries no file offset");
    const RvaTranslation atZeroFillEnd = TranslateRva(map, 0x19FFU);
    s.expect(atZeroFillEnd.kind == RvaKind::SectionZeroFill,
             L"I-02 the zero-fill window ends at VirtualSize, not at SizeOfRawData");
    const RvaTranslation atGap = TranslateRva(map, 0x1A00U);
    s.expect(atGap.kind == RvaKind::SectionGap,
             L"I-02 the alignment gap after a section is neither section nor header");
    const RvaTranslation atHeader = TranslateRva(map, 0x0100U);
    s.expect(atHeader.kind == RvaKind::Header && atHeader.fileOffset == OptionalU64::of(0x0100U),
             L"I-02 header RVAs translate one-to-one to file offsets");
    const RvaTranslation past = TranslateRva(map, 0x5000U);
    s.expect(past.kind == RvaKind::OutsideImage, L"I-02 RVA == SizeOfImage is outside the image");

    const FileOffsetTranslation backToText = TranslateFileOffset(map, 0x0400U);
    s.expect(backToText.kind == FileOffsetKind::SectionRawData &&
                 backToText.rva == OptionalU64::of(0x1000U),
             L"I-02 file offset 0x400 translates back to RVA 0x1000");
    const FileOffsetTranslation backToHeader = TranslateFileOffset(map, 0x0100U);
    s.expect(backToHeader.kind == FileOffsetKind::Header,
             L"I-02 file offsets inside SizeOfHeaders translate back to the header");
    const FileOffsetTranslation padTail = TranslateFileOffset(map, 0x0F00U);
    s.expect(padTail.kind == FileOffsetKind::NotMappedByAnySection,
             L"I-02 raw bytes past the clamped section are not mapped by any section");
    const FileOffsetTranslation beyond = TranslateFileOffset(map, 0x1000U);
    s.expect(beyond.kind == FileOffsetKind::OutsideFile,
             L"I-02 a file offset at the file length is outside the file");

    // 零填充区在映像里确实是 0，而不是把文件里后续字节顺移过来。
    s.expect(map.image[0x1800U] == 0U && map.image[0x19FFU] == 0U,
             L"I-02 zero-fill bytes are zero rather than the next file bytes");
    s.expect(map.image[0x3000U] == PatternBytes(0x0200U, 3U)[0],
             L"I-02 the clamped section still maps its first VirtualSize bytes");
    s.expect(map.image[0x3100U] == 0U,
             L"I-02 raw bytes beyond VirtualSize never reach the image");

    s.expect(map.sectionCoverage.succeeded == 3U && map.sectionCoverage.failed == 0U,
             L"I-02 section coverage accounts three mapped and zero defective sections");
    s.expect(RvaRangesTotalBytes(map.comparableRanges) == 0x400U + 0x800U + 0x200U + 0x100U,
             L"I-02 comparable bytes are headers plus the raw-backed part of every section");

    // I-05：ReadNormalizedBytes 是"磁盘参考窗口"接口。零填充区与节间隙在映像里
    // 确实是 0，但文件里根本没有这些字节 —— 返回"成功 + 一片 0"会让调用方把补出来
    // 的 0 当成磁盘上的真实内容。判据统一为"整段必须有文件字节支撑"。
    std::vector<std::uint8_t> window;
    s.expect(ReadNormalizedBytes(map, 0x1500U, 0x10U, window) && window.size() == 0x10U &&
                 window[0] == PatternBytes(0x0800U, 1U)[0x1500U - 0x1000U],
             L"I-05 a fully raw-backed window is returned and carries the on-disk bytes");
    s.expect(ReadNormalizedBytes(map, 0x0100U, 0x10U, window),
             L"I-05 a window inside the copied headers is raw-backed and readable");
    s.expect(!ReadNormalizedBytes(map, 0x1800U, 0x10U, window),
             L"I-05 a window inside a section's zero fill is refused, not answered with fabricated zeros");
    s.expect(!ReadNormalizedBytes(map, 0x17F8U, 0x10U, window),
             L"I-05 a window straddling the raw/zero-fill boundary is refused as a whole");
    s.expect(!ReadNormalizedBytes(map, 0x1A00U, 0x10U, window),
             L"I-05 a window in an alignment gap claimed by no section is refused");
    s.expect(!ReadNormalizedBytes(map, 0x3100U, 0x10U, window),
             L"I-05 raw bytes clamped away by VirtualSize are not readable through the image either");
}

void TestMalformedSections(KswordTests::Suite& s) {
    // 截断：.data 的 raw 区越过文件尾，只跳过 .data，.text 继续可比。
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0800U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0800U;
        text.characteristics = kCharsCode;
        text.content = PatternBytes(0x0800U, 5U);
        SectionSpec data;
        data.name = ".data";
        data.virtualAddress = 0x2000U;
        data.virtualSize = 0x0200U;
        data.pointerToRawData = 0x0C00U;
        data.sizeOfRawData = 0x0200U;
        data.characteristics = kCharsData;
        data.content = PatternBytes(0x0200U, 6U);
        spec.sections = {text, data};
        spec.truncateTo = 0x0D00U;

        const std::vector<std::uint8_t> file = BuildPe(spec);
        s.expect(file.size() == 0x0D00U, L"I-02 the truncated fixture really is 0xD00 bytes");
        const PeImageMap map = BuildPeImageMap(file, 0x0000000140000000ULL);
        s.expect(map.status == PeParseStatus::Ok,
                 L"I-02 a truncated section does not reject the whole image");
        const SectionMap* text2 = FindSection(map, ".text");
        const SectionMap* data2 = FindSection(map, ".data");
        s.expect(text2 != nullptr && text2->status == SectionMapStatus::Mapped,
                 L"I-02 the intact section keeps mapping after a truncated neighbour");
        s.expect(data2 != nullptr && data2->status == SectionMapStatus::NotComparable &&
                     data2->defect == SectionDefectReason::RawDataOutOfFile,
                 L"I-02 the truncated section is skipped and marked RawDataOutOfFile");
        s.expect(map.sectionCoverage.succeeded == 1U && map.sectionCoverage.failed == 1U,
                 L"I-02 the skipped section is accounted as failed, not silently dropped");
        s.expect(RvaRangesContain(map.notComparableRanges, 0x2000U),
                 L"I-02 the truncated section's virtual range is marked not comparable");
        s.expect(!RvaRangesContain(map.comparableRanges, 0x2000U),
                 L"I-02 the truncated section contributes no comparable bytes");
        s.expect(map.image.size() == 0x3000U,
                 L"I-02 the image buffer is still exactly SizeOfImage after a defect");
    }

    // 重叠节：后出现的节标不可比较，先出现的节保留，重叠字节整体退出比较。
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x4000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x2000U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x2000U;
        text.characteristics = kCharsCode;
        text.content = PatternBytes(0x2000U, 7U);
        SectionSpec overlap;
        overlap.name = ".ovl";
        overlap.virtualAddress = 0x1800U;   // 落在 .text 的 [0x1000,0x3000) 内
        overlap.virtualSize = 0x0400U;
        overlap.pointerToRawData = 0x2400U;
        overlap.sizeOfRawData = 0x0400U;
        overlap.characteristics = kCharsData;
        overlap.content = PatternBytes(0x0400U, 8U);
        spec.sections = {text, overlap};

        const PeImageMap map = BuildPeImageMap(BuildPe(spec), 0x0000000140000000ULL);
        s.expect(map.status == PeParseStatus::Ok,
                 L"I-02 overlapping sections do not reject the whole image");
        const SectionMap* overlapped = FindSection(map, ".ovl");
        s.expect(overlapped != nullptr && overlapped->status == SectionMapStatus::NotComparable &&
                     overlapped->defect == SectionDefectReason::OverlapsEarlierSection,
                 L"I-02 the overlapping section is detected and marked");
        s.expect(RvaRangesContain(map.comparableRanges, 0x17FFU) &&
                     !RvaRangesContain(map.comparableRanges, 0x1800U) &&
                     !RvaRangesContain(map.comparableRanges, 0x1BFFU) &&
                     RvaRangesContain(map.comparableRanges, 0x1C00U),
                 L"I-02 exactly the overlapped RVA window drops out of the comparable set");
    }

    // 越界节：VirtualAddress + VirtualSize 越过 SizeOfImage。
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0400U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = PatternBytes(0x0400U, 9U);
        SectionSpec past;
        past.name = ".past";
        past.virtualAddress = 0x2000U;
        past.virtualSize = 0x2000U;   // 0x2000 + 0x2000 = 0x4000 > SizeOfImage 0x3000
        past.pointerToRawData = 0x0800U;
        past.sizeOfRawData = 0x0200U;
        past.characteristics = kCharsData;
        past.content = PatternBytes(0x0200U, 10U);
        spec.sections = {text, past};

        const PeImageMap map = BuildPeImageMap(BuildPe(spec), 0x0000000140000000ULL);
        const SectionMap* beyond = FindSection(map, ".past");
        s.expect(beyond != nullptr && beyond->defect == SectionDefectReason::VirtualRangeOutOfImage,
                 L"I-02 VirtualAddress + VirtualSize past SizeOfImage is rejected per section");
        s.expect(map.image.size() == 0x3000U,
                 L"I-02 an out-of-image section never grows the image buffer");
    }

    // 越界的原始数据指针：既不能崩，也不能读出任何字节。
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec wild;
        wild.name = ".wild";
        wild.virtualAddress = 0x1000U;
        wild.virtualSize = 0x1000U;
        wild.pointerToRawData = 0x7FFFFF00U;   // 远超文件长度
        wild.sizeOfRawData = 0x1000U;
        wild.characteristics = kCharsCode;
        SectionSpec wrap;
        wrap.name = ".wrap";
        wrap.virtualAddress = 0x2000U;
        wrap.virtualSize = 0x0800U;
        wrap.pointerToRawData = 0xFFFFFF00U;   // ptr + raw 在 32 位里回绕
        wrap.sizeOfRawData = 0x0800U;
        wrap.characteristics = kCharsData;
        spec.sections = {wild, wrap};

        const PeImageMap map = BuildPeImageMap(BuildPe(spec), 0x0000000140000000ULL);
        s.expect(map.status == PeParseStatus::Ok,
                 L"I-02 wild raw pointers stay a per-section defect");
        const SectionMap* wildSection = FindSection(map, ".wild");
        const SectionMap* wrapSection = FindSection(map, ".wrap");
        s.expect(wildSection != nullptr &&
                     wildSection->defect == SectionDefectReason::RawDataOutOfFile,
                 L"I-02 a raw pointer past the file end is refused before any read");
        s.expect(wrapSection != nullptr &&
                     wrapSection->defect == SectionDefectReason::RawRangeOverflow,
                 L"I-02 a raw range that wraps 32 bits is refused before any read");
        bool allZero = true;
        for (std::size_t index = 0x1000U; index < 0x3000U; ++index) {
            if (map.image[index] != 0U) {
                allZero = false;
                break;
            }
        }
        s.expect(allZero, L"I-02 nothing is copied into the image for defective sections");
        std::vector<std::uint8_t> scratch;
        s.expect(!ReadNormalizedBytes(map, 0x1000U, 0x10U, scratch),
                 L"I-02 normalized reads inside a defective section are refused");
        s.expect(!ReadNormalizedBytes(map, 0x2FF8U, 0x10U, scratch),
                 L"I-02 normalized reads past SizeOfImage are refused");
    }
}

// I-02：头部与节的边界，以及数据目录的边界。这两个夹具都是"读取本身没有越界，
// 但解析器采信了一个从未校验的偏移"。
void TestHeaderBoundaries(KswordTests::Suite& s) {
    // (1) 节的 VirtualAddress 落在 SizeOfHeaders 之内 —— 节内容会盖掉已经放进
    //     映像的 PE 头字节，同一个 RVA 于是有两个互相矛盾的来源。
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec hdrOverlap;
        hdrOverlap.name = ".hdrovl";
        hdrOverlap.virtualAddress = 0x0200U;   // SizeOfHeaders 是 0x400
        hdrOverlap.virtualSize = 0x0200U;
        hdrOverlap.pointerToRawData = 0x0800U;
        hdrOverlap.sizeOfRawData = 0x0200U;
        hdrOverlap.characteristics = kCharsCode;
        hdrOverlap.content = PatternBytes(0x0200U, 41U);
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0400U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = PatternBytes(0x0400U, 42U);
        spec.sections = {hdrOverlap, text};

        std::vector<std::uint8_t> file = BuildPe(spec);
        // 头部第 0x200 字节本来是填充 0；写一个可识别的值，"头部字节没被盖掉"
        // 才是一句可验证的断言。
        file[0x0200U] = 0x5CU;

        const PeImageMap map = BuildPeImageMap(file, 0x0000000140000000ULL);
        s.expect(map.status == PeParseStatus::Ok,
                 L"I-02 a section overlapping the headers stays a per-section defect");
        const SectionMap* overlapping = FindSection(map, ".hdrovl");
        s.expect(overlapping != nullptr &&
                     overlapping->status == SectionMapStatus::NotComparable &&
                     overlapping->defect == SectionDefectReason::OverlapsEarlierSection,
                 L"I-02 a section whose VirtualAddress falls inside SizeOfHeaders is refused");
        s.expect(map.image[0x0200U] == 0x5CU,
                 L"I-02 the PE header bytes survive: the overlapping section never gets copied over them");
        s.expect(map.image[0x0200U] != PatternBytes(0x0200U, 41U)[0],
                 L"I-02 the refused section's content is nowhere in the image");
        s.expect(RvaRangesContain(map.notComparableRanges, 0x0200U) &&
                     !RvaRangesContain(map.comparableRanges, 0x0200U),
                 L"I-02 the contested header window drops out of the comparable set");
        s.expect(RvaRangesContain(map.comparableRanges, 0x01FFU),
                 L"I-02 header bytes before the contested window stay comparable");
        // 来源回溯必须单向：0x200 不能既是头又是节。
        const RvaTranslation contested = TranslateRva(map, 0x0200U);
        s.expect(contested.kind == RvaKind::NotComparable,
                 L"I-02 a contested RVA reports NotComparable instead of claiming one of the two sources");
        const FileOffsetTranslation sectionRaw = TranslateFileOffset(map, 0x0800U);
        s.expect(sectionRaw.kind == FileOffsetKind::NotComparable,
                 L"I-02 the refused section's raw bytes do not claim an RVA of their own");
        const FileOffsetTranslation headerRaw = TranslateFileOffset(map, 0x0200U);
        s.expect(headerRaw.kind == FileOffsetKind::Header && headerRaw.rva == OptionalU64::of(0x0200U),
                 L"I-02 exactly one file offset maps to RVA 0x200, and it is the header one");
        // .text 照常映射：一个坏节不该拖垮整份映像。
        const SectionMap* text2 = FindSection(map, ".text");
        s.expect(text2 != nullptr && text2->status == SectionMapStatus::Mapped,
                 L"I-02 the well-formed section keeps mapping next to a header-overlapping one");
    }

    // (2) SizeOfOptionalHeader = 112 且 NumberOfRvaAndSizes = 16：目录项其实落在
    //     节表字节里。攻击者一个 8 字节节名就能完全控制 BASERELOC 的 RVA/size。
    {
        PeBuilder spec;
        spec.sizeOfOptionalHeader = 112U;   // 只到 NumberOfRvaAndSizes 为止
        spec.numberOfRvaAndSizes = 16U;     // 却声称有 16 个目录
        spec.sizeOfImage = 0x3000U;
        spec.relocDirectoryRva = 0x2000U;   // BuildPe 在这种长度下不会写它
        spec.relocDirectorySize = 0x20U;
        SectionSpec reloc;
        reloc.name = ".reloc";              // 节名字节就是被误读成目录的那 8 个字节
        reloc.virtualAddress = 0x1000U;
        reloc.virtualSize = 0x0400U;
        reloc.pointerToRawData = 0x0400U;
        reloc.sizeOfRawData = 0x0400U;
        reloc.characteristics = kCharsReloc;
        reloc.content = PatternBytes(0x0400U, 43U);
        spec.sections = {reloc};

        const PeImageMap map = BuildPeImageMap(BuildPe(spec), 0x0000000140000000ULL);
        s.expect(map.status == PeParseStatus::Ok,
                 L"I-02 a 112-byte optional header still parses; the directories are simply absent");
        s.expect(map.header.dataDirectoryCount == 0U,
                 L"I-02 no data directory fits inside a 112-byte optional header");
        s.expect(map.header.relocationDirectoryRva == 0U &&
                     map.header.relocationDirectorySize == 0U,
                 L"I-02 section-table bytes are never read as a data directory");
        // 0x6C65722E 是 '.rel' 的小端读法 —— 旧行为下 relocationDirectoryRva 就是它。
        s.expect(map.header.relocationDirectoryRva != 0x6C65722EU,
                 L"I-02 the relocation directory RVA is not the ASCII of a section name");
        s.expect(map.header.sectionTableFileOffset == kOptionalOffset + 112U,
                 L"I-02 the section table starts right after the declared optional header");
    }
}

void TestWholeImageRejection(KswordTests::Suite& s) {
    const std::vector<std::uint8_t> empty;
    s.expect(BuildPeImageMap(empty, 0U).status == PeParseStatus::EmptyInput,
             L"I-02 an empty buffer is rejected as EmptyInput");

    std::vector<std::uint8_t> notPe = BuildPe(MakeLayoutFixture());
    notPe[0] = 'Z';
    s.expect(BuildPeImageMap(notPe, 0U).status == PeParseStatus::BadDosSignature,
             L"I-02 a bad DOS signature rejects the whole file");

    // 节表条目数与 SizeOfHeaders 不一致：节表末尾 0x148 + 3 * 40 = 0x1E0 > 0x180。
    PeBuilder tight = MakeLayoutFixture();
    tight.sizeOfHeaders = 0x180U;
    s.expect(BuildPeImageMap(BuildPe(tight), 0U).status ==
                 PeParseStatus::SectionTableExceedsHeaders,
             L"I-02 a section table that overruns SizeOfHeaders rejects the whole file");

    PeBuilder pe32 = MakeLayoutFixture();
    pe32.optionalMagic = 0x010BU;
    s.expect(BuildPeImageMap(BuildPe(pe32), 0U).status == PeParseStatus::UnsupportedOptionalMagic,
             L"I-02 PE32 is refused rather than read with PE32+ field offsets");

    PeBuilder badAlign = MakeLayoutFixture();
    badAlign.fileAlignment = 0x300U;   // 非 2 的幂
    s.expect(BuildPeImageMap(BuildPe(badAlign), 0U).status == PeParseStatus::InvalidAlignment,
             L"I-02 a non power-of-two FileAlignment rejects the whole file");

    PeBuilder tinyImage = MakeLayoutFixture();
    tinyImage.sizeOfImage = 0x100U;    // 小于 SizeOfHeaders
    s.expect(BuildPeImageMap(BuildPe(tinyImage), 0U).status == PeParseStatus::InvalidSizeOfImage,
             L"I-02 SizeOfImage smaller than SizeOfHeaders rejects the whole file");
}

// ---------------------------------------------------------------------------
// I-03 重定位与加载变更
// ---------------------------------------------------------------------------
void TestRelocationNormalization(KswordTests::Suite& s) {
    const std::vector<RelocEntrySpec> entries = {RelocEntrySpec{kRelTypeDir64, kRelocTargetRva}};
    const PeBuilder relocSpec = MakeRelocSpec(entries);
    const std::vector<std::uint8_t> file = BuildPe(relocSpec);

    const PeImageMap atPreferred = BuildPeImageMap(file, kRelocPreferredBase);
    const PeImageMap atOther = BuildPeImageMap(file, kRelocOtherBase);
    s.expect(atPreferred.status == PeParseStatus::Ok && atOther.status == PeParseStatus::Ok,
             L"I-03 the relocatable fixture parses at both bases");
    s.expect(atPreferred.relocation.status == RelocationStatus::NotNeeded,
             L"I-03 mapping at the preferred base needs no relocation");
    s.expect(atOther.relocation.status == RelocationStatus::Applied,
             L"I-03 mapping at a different base applies the relocation directory");
    s.expect(atOther.relocation.delta == kRelocOtherBase - kRelocPreferredBase,
             L"I-03 the recorded delta is the base difference");
    s.expect(atOther.relocation.entriesApplied == 1U &&
                 atOther.relocation.entriesUnsupported == 0U,
             L"I-03 exactly one DIR64 entry is applied");

    s.expect(ReadU64At(atPreferred.image, kRelocTargetRva) ==
                 kRelocPreferredBase + kRelocTargetRva,
             L"I-03 at the preferred base the stored VA is the on-disk value");
    s.expect(ReadU64At(atOther.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
             L"I-03 at the other base the DIR64 target is rebased");
    s.expect(atPreferred.image != atOther.image,
             L"I-03 the two normalized images really do differ (the fixture exercises relocation)");

    // 生产归一化的结果必须逐字节等于夹具自己算出来的加载器映像。这是本套件里
    // 唯一一条能直接抓住"归一化多改/漏改字节"的断言：右边完全不经过被测代码。
    s.expect(atPreferred.image == IndependentLoadedImage(relocSpec, entries, kRelocPreferredBase),
             L"I-03 at the preferred base the normalized image equals the independently loaded image");
    s.expect(atOther.image == IndependentLoadedImage(relocSpec, entries, kRelocOtherBase),
             L"I-03 at the other base the normalized image equals the independently loaded image byte for byte");

    // 只有重定位差异时，零条未解释差异。现场取自独立加载器，不是 map.image。
    ImageDiffOptions options = DefaultOptions();
    const ImageDiffReport clean =
        CompareImage(atOther, LiveFromSpec(relocSpec, kRelocOtherBase, entries), options);
    s.expect(clean.entries.empty() && clean.unexplainedEntries == 0U,
             L"I-03 a relocation-only base change yields zero unexplained differences against an independently loaded image");
    s.expect(clean.conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"I-03 a fully covered clean comparison concludes NoDifferenceObserved");

    // 再改一个非重定位字节 —— 必须精确定位到那个 RVA。
    LiveImageBytes tampered = LiveFromSpec(relocSpec, kRelocOtherBase, entries);
    constexpr std::uint32_t kTamperRva = 0x1200U;
    tampered.bytes[kTamperRva] = static_cast<std::uint8_t>(tampered.bytes[kTamperRva] ^ 0xFFU);
    const ImageDiffReport tamperedReport = CompareImage(atOther, tampered, options);
    s.expect(tamperedReport.entries.size() == 1U,
             L"I-03 changing one non-relocated byte in an independently loaded image produces exactly one difference");
    const ImageDiffEntry* hit = EntryAt(tamperedReport, kTamperRva);
    s.expect(hit != nullptr && hit->length == 1U && hit->rva == kTamperRva,
             L"I-03 the difference is located at the tampered RVA with length 1");
    s.expect(hit != nullptr && hit->explanation == DiffExplanation::Unexplained,
             L"I-03 a real modification stays unexplained without a rule");

    // 不支持的重定位类型：该范围标不可比较，其余照常归一化。
    const std::vector<RelocEntrySpec> mixedEntries = {
        RelocEntrySpec{kRelTypeDir64, kRelocTargetRva},
        RelocEntrySpec{kRelTypeReservedSeven, kUnsupportedTargetRva},
    };
    const PeBuilder mixedSpec = MakeRelocSpec(mixedEntries);
    const std::vector<std::uint8_t> mixedFile = BuildPe(mixedSpec);
    const PeImageMap mixed = BuildPeImageMap(mixedFile, kRelocOtherBase);
    s.expect(mixed.status == PeParseStatus::Ok,
             L"I-03 an unsupported relocation type does not fail the whole image");
    s.expect(mixed.relocation.status == RelocationStatus::AppliedWithUnsupported,
             L"I-03 the relocation report says some types were unsupported");
    s.expect(mixed.relocation.entriesApplied == 1U && mixed.relocation.entriesUnsupported == 1U,
             L"I-03 applied and unsupported relocation entries are counted separately");
    s.expect(mixed.relocation.unsupported.size() == 1U &&
                 mixed.relocation.unsupported[0].type == 7U,
             L"I-03 the unsupported relocation type number is recorded");
    s.expect(ReadU64At(mixed.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
             L"I-03 the supported entry is still normalized alongside an unsupported one");
    s.expect(RvaRangesContain(mixed.notComparableRanges, kUnsupportedTargetRva) &&
                 RvaRangesContain(mixed.notComparableRanges, kUnsupportedTargetRva + 7U) &&
                 !RvaRangesContain(mixed.notComparableRanges, kUnsupportedTargetRva + 8U),
             L"I-03 exactly the affected 8 bytes are marked not comparable");
    s.expect(!RvaRangesContain(mixed.comparableRanges, kUnsupportedTargetRva) &&
                 RvaRangesContain(mixed.comparableRanges, kUnsupportedTargetRva - 1U),
             L"I-03 the unsupported range drops out of the comparable set, its neighbours stay");
    s.expect(mixed.relocation.coverage.failed == 1U &&
                 mixed.relocation.coverage.succeeded == 1U &&
                 mixed.relocation.coverage.totalKnown == OptionalU64::of(2U),
             L"I-03 relocation coverage records applied and unsupported entry counts");

    const ImageDiffReport mixedReport =
        CompareImage(mixed, LiveFromSpec(mixedSpec, kRelocOtherBase, mixedEntries), options);
    s.expect(mixedReport.excludedBytes == 8U,
             L"I-03 the diff engine excludes the not-comparable relocation window");
    s.expect(mixedReport.entries.empty(),
             L"I-03 the excluded window produces no entry at all, not an unexplained difference");
    s.expect(mixedReport.conclusion == AnalysisConclusion::Indeterminate,
             L"I-03 an excluded window keeps the conclusion Indeterminate, not NoDifferenceObserved");
    // I-09：含排除窗口的页必须同时进 attempted 与 excluded。只在"整页从未被比较"
    // 时才计 excluded 会让这一页报出 100% 成功。
    // 可比较集合 = 头 [0,0x400) + .text [0x1000,0x2000) + .reloc [0x2000,0x2200)
    // → 触到页 0、1、2 三页；被排除的 8 字节在 0x1150，属于页 1。
    s.expect(mixedReport.stats.pages.attempted == 3U && mixedReport.stats.pages.succeeded == 3U &&
                 mixedReport.stats.pages.failed == 0U && mixedReport.stats.pages.excluded == 1U,
             L"I-09 a page that contains an excluded window is counted in both attempted and excluded");
}

// I-03：重定位无法应用时，整份映像必须标不可比较。
// 三种"归一化根本没做成"的状态各造一个夹具，比较的两侧都换过基址。
void TestRelocationCannotNormalize(KswordTests::Suite& s) {
    const std::vector<RelocEntrySpec> entries = {RelocEntrySpec{kRelTypeDir64, kRelocTargetRva}};
    const ImageDiffOptions options = DefaultOptions();

    // 可比较集合的字节总数（手算）：头 0x400 + .text 0x1000 + .reloc 0x200 = 0x1600。
    constexpr std::uint64_t kRawBackedTotal = 0x400U + 0x1000U + 0x200U;

    struct Case final {
        PeBuilder spec;
        RelocationStatus expected;
        const wchar_t* label;
    };
    std::vector<Case> cases;

    // (1) RELOCS_STRIPPED：声明没有重定位表，却要求换基址。
    {
        PeBuilder stripped = MakeRelocSpec(entries);
        stripped.fileCharacteristics =
            static_cast<std::uint16_t>(stripped.fileCharacteristics | 0x0001U);
        cases.push_back(Case{stripped, RelocationStatus::Stripped,
                             L"I-03 RELOCS_STRIPPED with a base change"});
    }
    // (2) DirectoryMissing：目录 RVA/size 都为 0。
    {
        PeBuilder none = MakeRelocSpec(entries);
        none.relocDirectoryRva = 0U;
        none.relocDirectorySize = 0U;
        cases.push_back(Case{none, RelocationStatus::DirectoryMissing,
                             L"I-03 a base change with no relocation directory"});
    }
    // (3) DirectoryUnbacked：目录 RVA 落在 .text 的零填充/间隙里，没有文件字节支撑。
    //     .text raw 支撑到 0x2000，.reloc 支撑 [0x2000,0x2200)；0x2200 之后到
    //     SizeOfImage 0x3000 都是没有任何节声明的间隙。
    {
        PeBuilder unbacked = MakeRelocSpec(entries);
        unbacked.relocDirectoryRva = 0x2800U;
        unbacked.relocDirectorySize = 0x20U;
        cases.push_back(Case{unbacked, RelocationStatus::DirectoryUnbacked,
                             L"I-03 a relocation directory with no file bytes behind it"});
    }

    for (const Case& one : cases) {
        const PeImageMap map = BuildPeImageMap(BuildPe(one.spec), kRelocOtherBase);
        s.expect(map.status == PeParseStatus::Ok, one.label);
        s.expect(map.relocation.status == one.expected, one.label);
        s.expect(map.relocation.imageNotNormalized,
                 L"I-03 a relocation failure marks the map as not normalized");
        s.expect(!RelocationNormalizationSucceeded(map.relocation.status),
                 L"I-03 the four failure statuses all report normalization as not done");
        // 整份映像进不可比较集合：0% 归一化就不能只标 0% 不可比较。
        s.expect(RvaRangesTotalBytes(map.comparableRanges) == 0U,
                 L"I-03 an image that could not be normalized has no comparable bytes left");
        s.expect(RvaRangesContain(map.notComparableRanges, 0U) &&
                     RvaRangesContain(map.notComparableRanges, map.header.sizeOfImage - 1U),
                 L"I-03 the whole image range is marked not comparable");

        // 方向一：现场是加载器真正会产出的字节（重定位已生效）。旧行为会在每个
        // 重定位点上报出未解释差异 —— 那正是 I-01 禁止的批量误报。
        const ImageDiffReport live =
            CompareImage(map, LiveFromSpec(one.spec, kRelocOtherBase, entries), options);
        s.expect(live.entries.empty() && live.unexplainedEntries == 0U,
                 L"I-03 an un-normalizable image reports zero differences instead of one per relocation site");
        s.expect(live.excludedBytes == kRawBackedTotal,
                 L"I-03 every requested byte of an un-normalizable image is accounted as excluded");
        s.expect(live.outcome.status == CollectionStatus::Partial,
                 L"I-03 an un-normalizable image cannot be collected as Success");
        s.expect(live.conclusion == AnalysisConclusion::Indeterminate,
                 L"I-03 an un-normalizable image concludes Indeterminate");

        // 方向二：现场恰好也是未归一化的字节。旧行为给出自信的"未发现差异"。
        LiveImageBytes sameAsReference = LiveImageBytes::fromBytes(0U, map.image);
        const ImageDiffReport quiet = CompareImage(map, sameAsReference, options);
        s.expect(quiet.conclusion == AnalysisConclusion::Indeterminate,
                 L"I-03 bytes matching an un-normalized reference still cannot conclude NoDifferenceObserved");
        s.expect(quiet.outcome.status == CollectionStatus::Partial && quiet.excludedBytes == kRawBackedTotal,
                 L"I-03 the quiet direction is excluded exactly like the loud one");
    }

    // 需要重定位却没有目录时，限制键仍然要出现（旧断言，判据未放宽）。
    const PeBuilder noRelocSpec = MakeDiffFixture();
    const PeImageMap missing = BuildPeImageMap(BuildPe(noRelocSpec), kDiffLoadedBase + 0x10000U);
    s.expect(missing.relocation.status == RelocationStatus::DirectoryMissing,
             L"I-03 a base change without a relocation directory is reported, not ignored");
    const ImageDiffReport missingReport =
        CompareImage(missing, LiveFromSpec(noRelocSpec, kDiffLoadedBase + 0x10000U), options);
    bool sawRelocLimitation = false;
    bool sawExcludedLimitation = false;
    for (const std::string& key : missingReport.limitationKeys) {
        if (key == "integrity.limitation.relocationDirectoryMissing") {
            sawRelocLimitation = true;
        }
        if (key == "integrity.limitation.excludedNotComparable") {
            sawExcludedLimitation = true;
        }
    }
    s.expect(sawRelocLimitation,
             L"I-03 the missing relocation directory surfaces as a limitation key");
    s.expect(sawExcludedLimitation && missingReport.excludedBytes == 0x400U + 0x3000U + 0x200U,
             L"I-03 a limitation key alone is not enough: the bytes are excluded too");
}

// I-03 / Q-02：七个 RelocationStatus 与几条只有异常输入才走到的分支。
void TestRelocationEdgeCases(KswordTests::Suite& s) {
    // (1) 畸形目录的四种形态。判据统一：停止解析、状态 DirectoryMalformed、
    //     整份映像不可比较（剩下哪些块没处理无法界定，不能给半归一化的参考）。
    struct MalformedCase final {
        std::vector<std::uint8_t> blob;
        std::uint32_t dirSize;
        const wchar_t* label;
    };
    std::vector<MalformedCase> malformed;
    {
        // blockSize == 0：循环不前进。
        std::vector<std::uint8_t> blob(16U, 0U);
        Put32(blob, 0U, 0x1000U);
        Put32(blob, 4U, 0U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block with SizeOfBlock 0"});
    }
    {
        // blockSize == 4：小于 8 字节块头。
        std::vector<std::uint8_t> blob(16U, 0U);
        Put32(blob, 0U, 0x1000U);
        Put32(blob, 4U, 4U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block smaller than its own header"});
    }
    {
        // blockSize 越过目录剩余长度：块头声称 0x40，目录只有 0x10。
        std::vector<std::uint8_t> blob(16U, 0U);
        Put32(blob, 0U, 0x1000U);
        Put32(blob, 4U, 0x40U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block that overruns the directory"});
    }
    {
        // entryBytes 为奇数：blockSize 11 = 8 + 3。
        std::vector<std::uint8_t> blob(16U, 0U);
        Put32(blob, 0U, 0x1000U);
        Put32(blob, 4U, 11U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block with an odd number of entry bytes"});
    }
    for (const MalformedCase& one : malformed) {
        const PeBuilder spec = MakeRelocSpecRaw(one.blob, 0x2000U, one.dirSize);
        const PeImageMap map = BuildPeImageMap(BuildPe(spec), kRelocOtherBase);
        s.expect(map.status == PeParseStatus::Ok, one.label);
        s.expect(map.relocation.status == RelocationStatus::DirectoryMalformed, one.label);
        s.expect(map.relocation.imageNotNormalized &&
                     RvaRangesTotalBytes(map.comparableRanges) == 0U,
                 L"I-03 a malformed relocation directory leaves no comparable bytes behind");
        s.expect(ReadU64At(map.image, kRelocTargetRva) == kRelocPreferredBase + kRelocTargetRva,
                 L"I-03 a malformed directory never half-applies a relocation it could not parse");
    }

    // (2) entriesOutOfRange：DIR64 目标越过 SizeOfImage。
    //     块 RVA 0x2000 + 偏移 0xFFC = 0x2FFC，+8 = 0x3004 > SizeOfImage 0x3000。
    {
        const std::vector<RelocEntrySpec> entries = {RelocEntrySpec{kRelTypeDir64, 0x2FFCU}};
        const std::vector<std::uint8_t> blob = BuildRelocBlock(0x2000U, entries);
        const PeBuilder spec =
            MakeRelocSpecRaw(blob, 0x2000U, static_cast<std::uint32_t>(blob.size()));
        const PeImageMap map = BuildPeImageMap(BuildPe(spec), kRelocOtherBase);
        s.expect(map.relocation.entriesOutOfRange == 1U && map.relocation.entriesApplied == 0U,
                 L"I-03 a DIR64 target past SizeOfImage is counted out of range and never written");
        s.expect(map.relocation.status == RelocationStatus::AppliedWithUnsupported,
                 L"I-03 an out-of-range entry degrades the status instead of failing the image");
        bool tailAllZero = true;
        for (std::size_t at = 0x2FF0U; at < 0x3000U; ++at) {
            if (map.image[at] != 0U) {
                tailAllZero = false;
            }
        }
        s.expect(tailAllZero, L"I-03 an out-of-range relocation writes no bytes at all");
    }

    // (3) HIGHADJ：参数字必须被跳过，且**不能**被计成一个重定位条目。
    //     同一块里 HIGHADJ@0x1200 + 参数字 + DIR64@0x1100。
    {
        std::vector<std::uint8_t> blob(8U + 3U * 2U, 0U);
        Put32(blob, 0U, 0x1000U);
        Put32(blob, 4U, static_cast<std::uint32_t>(blob.size()));
        Put16(blob, 8U, static_cast<std::uint16_t>((kRelTypeHighAdj << 12U) | 0x200U));
        Put16(blob, 10U, 0x1234U);   // HIGHADJ 的参数字，不是条目
        Put16(blob, 12U, static_cast<std::uint16_t>((kRelTypeDir64 << 12U) | 0x100U));
        const PeBuilder spec =
            MakeRelocSpecRaw(blob, 0x2000U, static_cast<std::uint32_t>(blob.size()));
        const PeImageMap map = BuildPeImageMap(BuildPe(spec), kRelocOtherBase);

        s.expect(map.relocation.entriesTotal == 2U,
                 L"I-03 the HIGHADJ parameter word is not counted as a relocation entry");
        s.expect(map.relocation.entriesSkippedParameter == 1U,
                 L"I-03 the skipped HIGHADJ parameter word gets its own counter");
        s.expect(map.relocation.entriesApplied == 1U && map.relocation.entriesUnsupported == 1U,
                 L"I-03 the DIR64 after a HIGHADJ is still applied and the HIGHADJ stays unsupported");
        s.expect(ReadU64At(map.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
                 L"I-03 the parameter word is skipped rather than treated as an entry that shifts the rest");
        s.expect(map.relocation.coverage.succeeded + map.relocation.coverage.failed ==
                     map.relocation.coverage.totalKnown.value,
                 L"I-03 relocation coverage closes: succeeded plus failed equals the known entry total");
        s.expect(map.relocation.coverage.totalKnown == OptionalU64::of(2U),
                 L"I-03 totalKnown counts entries, not the words consumed by them");
    }

    // (4) I-02：重定位目标必须整段有文件字节支撑。
    //     .text VA 0x1000 / VS 0x1000 / raw 0x400 → raw 支撑 [0x1000,0x1400)，
    //     零填充 [0x1400,0x2000)。
    {
        PeBuilder spec;
        spec.imageBase = kRelocPreferredBase;
        spec.sizeOfImage = 0x3000U;

        // 块 RVA 0x1000，两个 DIR64：0x1500（整段在零填充里）、0x13FC（跨边界）。
        const std::vector<RelocEntrySpec> entries = {
            RelocEntrySpec{kRelTypeDir64, 0x1500U},
            RelocEntrySpec{kRelTypeDir64, 0x13FCU},
        };
        const std::vector<std::uint8_t> blob = BuildRelocBlock(0x1000U, entries);

        std::vector<std::uint8_t> textContent = PatternBytes(0x400U, 31U);
        // 0x13FC 处磁盘上的 4 字节写成 0x40001400 的低半，方便手算跨界结果。
        Put32(textContent, 0x13FCU - 0x1000U, 0x40001400U);

        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x1000U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = textContent;

        SectionSpec reloc;
        reloc.name = ".reloc";
        reloc.virtualAddress = 0x2000U;
        reloc.virtualSize = 0x0200U;
        reloc.pointerToRawData = 0x0800U;
        reloc.sizeOfRawData = 0x0200U;
        reloc.characteristics = kCharsReloc;
        reloc.content = blob;
        reloc.content.resize(0x0200U, 0U);

        spec.sections = {text, reloc};
        spec.relocDirectoryRva = 0x2000U;
        spec.relocDirectorySize = static_cast<std::uint32_t>(blob.size());

        const PeImageMap map = BuildPeImageMap(BuildPe(spec), kRelocOtherBase);
        s.expect(map.relocation.entriesUnbackedTarget == 2U && map.relocation.entriesApplied == 0U,
                 L"I-02 relocation targets without full file backing are refused, not applied");

        bool zeroFillUntouched = true;
        for (std::size_t at = 0x1500U; at < 0x1508U; ++at) {
            if (map.image[at] != 0U) {
                zeroFillUntouched = false;
            }
        }
        s.expect(zeroFillUntouched,
                 L"I-02 a relocation whose target lies in zero fill leaves those bytes zero, keeping the zero-fill contract");
        s.expect(RvaRangesContain(map.zeroFillRanges, 0x1503U) == false,
                 L"I-02 the refused zero-fill target drops out of zeroFillRanges rather than hiding a non-zero byte");
        // 跨界目标：磁盘上是 00 14 00 40，未加 delta 才是正确结果。
        s.expect(map.image[0x13FCU] == 0x00U && map.image[0x13FDU] == 0x14U &&
                     map.image[0x13FEU] == 0x00U && map.image[0x13FFU] == 0x40U,
                 L"I-02 a relocation straddling the raw/zero-fill boundary never carries a delta into comparable bytes");
        s.expect(!RvaRangesContain(map.comparableRanges, 0x13FCU) &&
                     !RvaRangesContain(map.comparableRanges, 0x1500U),
                 L"I-02 both refused relocation windows leave the comparable set");
        s.expect(RvaRangesContain(map.comparableRanges, 0x13FBU),
                 L"I-02 the byte just before a refused window stays comparable");
    }
}

// ---------------------------------------------------------------------------
// I-05 差异定位和上下文
// ---------------------------------------------------------------------------
void TestDifferenceLocation(KswordTests::Suite& s) {
    const PeBuilder spec = MakeDiffFixture();
    const std::vector<std::uint8_t> file = BuildPe(spec);
    const PeImageMap map = BuildPeImageMap(file, kDiffLoadedBase);
    s.expect(map.status == PeParseStatus::Ok, L"I-05 the diff fixture parses");
    s.expect(RvaRangesTotalBytes(map.comparableRanges) == 0x400U + 0x3000U + 0x200U,
             L"I-05 the comparable set is headers plus .text plus the raw part of .data");

    // .text 的磁盘内容是 PatternBytes(0x3000, 11)，从 RVA 0x1000 起。期望字节全部
    // 用这个独立生成器算，不从 map.image 反查。
    const std::vector<std::uint8_t> textPattern = PatternBytes(0x3000U, 11U);
    const std::vector<std::uint8_t> loaded = IndependentLoadedImage(spec, {}, kDiffLoadedBase);
    s.expect(loaded.size() == 0x6000U && loaded[0x1000U] == textPattern[0],
             L"I-05 the independently loaded image places .text content at RVA 0x1000");

    ImageDiffOptions options = DefaultOptions();
    LiveImageBytes live = LiveFromSpec(spec, kDiffLoadedBase);

    // 开头 / 中部 / 末尾 / 跨页边界各改一处已知字节。
    constexpr std::uint32_t kAtStart = 0x1000U;
    constexpr std::uint32_t kAcrossPage = 0x1FFEU;   // 覆盖 0x1FFE..0x2001，跨 0x2000 页边界
    constexpr std::uint32_t kAtMiddle = 0x2800U;
    constexpr std::uint32_t kAtEnd = 0x41FFU;        // 可比较范围的最后一个字节
    live.bytes[kAtStart] = static_cast<std::uint8_t>(live.bytes[kAtStart] ^ 0xFFU);
    for (std::uint32_t offset = 0U; offset < 4U; ++offset) {
        const std::uint32_t at = kAcrossPage + offset;
        live.bytes[at] = static_cast<std::uint8_t>(live.bytes[at] ^ 0x5AU);
    }
    for (std::uint32_t offset = 0U; offset < 3U; ++offset) {
        const std::uint32_t at = kAtMiddle + offset;
        live.bytes[at] = static_cast<std::uint8_t>(live.bytes[at] ^ 0x33U);
    }
    live.bytes[kAtEnd] = static_cast<std::uint8_t>(live.bytes[kAtEnd] ^ 0x01U);

    const ImageDiffReport report = CompareImage(map, live, options);
    s.expect(report.entries.size() == 4U, L"I-05 four separated changes produce four entries");
    s.expect(report.differingBytes == 1U + 4U + 3U + 1U,
             L"I-05 the differing byte total is 9");

    const ImageDiffEntry* start = EntryAt(report, kAtStart);
    const ImageDiffEntry* page = EntryAt(report, kAcrossPage);
    const ImageDiffEntry* middle = EntryAt(report, kAtMiddle);
    const ImageDiffEntry* tail = EntryAt(report, kAtEnd);
    s.expect(start != nullptr && start->length == 1U && start->sectionName == ".text",
             L"I-05 the change at the start of .text is located exactly");
    s.expect(page != nullptr && page->length == 4U,
             L"I-05 a change straddling a page boundary stays one range of length 4");
    s.expect(middle != nullptr && middle->length == 3U,
             L"I-05 the change in the middle keeps its exact length");
    s.expect(tail != nullptr && tail->length == 1U && tail->sectionName == ".data",
             L"I-05 the change at the last comparable byte is attributed to .data");
    s.expect(start != nullptr && start->va == kDiffLoadedBase + kAtStart,
             L"I-05 the VA is the loaded base plus the RVA");
    s.expect(page != nullptr && page->referenceBytes.size() == 4U &&
                 page->liveBytes.size() == 4U,
             L"I-05 both before and after bytes are carried for a readable difference");
    // 参考字节对着独立生成器比，不对 map.image 比 —— 后者是"实现和它自己比"。
    s.expect(page != nullptr && page->referenceBytes[0] == textPattern[kAcrossPage - 0x1000U] &&
                 page->liveBytes[0] == static_cast<std::uint8_t>(
                                           textPattern[kAcrossPage - 0x1000U] ^ 0x5AU),
             L"I-05 the carried reference byte matches the independent pattern generator, not the implementation output");
    s.expect(start != nullptr && start->evidenceSource == "test.offline.fixture",
             L"I-05 every entry carries its evidence source");
    s.expect(report.conclusion == AnalysisConclusion::DifferenceObserved,
             L"I-05 observed differences conclude DifferenceObserved");
    s.expect(report.stats.pages.attempted == 5U && report.stats.pages.failed == 0U,
             L"I-05 page accounting covers the five pages touched by the comparable set");

    // 头部的差异归到 "(headers)"。
    LiveImageBytes headerLive = LiveFromSpec(spec, kDiffLoadedBase);
    headerLive.bytes[0x0100U] = static_cast<std::uint8_t>(headerLive.bytes[0x0100U] ^ 0xFFU);
    const ImageDiffReport headerReport = CompareImage(map, headerLive, options);
    const ImageDiffEntry* headerEntry = EntryAt(headerReport, 0x0100U);
    s.expect(headerEntry != nullptr && headerEntry->sectionName == "(headers)",
             L"I-05 a difference inside SizeOfHeaders is attributed to the header region");

    // 不可读的现场字节：缺失标记，不是 00 差异。
    LiveImageBytes unreadable = LiveFromSpec(spec, kDiffLoadedBase);
    RvaRange hole;
    hole.rva = 0x2A00U;
    hole.length = 0x10U;
    for (std::uint32_t offset = 0U; offset < hole.length; ++offset) {
        unreadable.bytes[hole.rva + offset] = 0U;   // 若实现补 00 参与比较，这里会变成差异
    }
    unreadable.markRange(hole, ByteReadStatus::Unreadable);
    const ImageDiffReport holeReport = CompareImage(map, unreadable, options);
    s.expect(holeReport.byteDifferenceEntries == 0U,
             L"I-05 unreadable bytes never turn into byte differences");
    s.expect(holeReport.missingEntries == 1U && holeReport.entries.size() == 1U,
             L"I-05 the unreadable window becomes exactly one missing marker");
    const ImageDiffEntry* missing = EntryAt(holeReport, hole.rva);
    s.expect(missing != nullptr && missing->kind == DiffKind::MissingLiveBytes &&
                 missing->readStatus == ByteReadStatus::Unreadable && missing->length == 0x10U,
             L"I-05 the missing marker carries Unreadable and the exact window length");
    s.expect(missing != nullptr && missing->liveBytes.empty() &&
                 missing->referenceBytes.size() == 0x10U,
             L"I-05 a missing marker carries reference bytes but no fabricated live bytes");
    s.expect(holeReport.unreadableBytes == 0x10U && holeReport.comparedBytes ==
                 0x400U + 0x3000U + 0x200U - 0x10U,
             L"I-05 unreadable bytes are excluded from the compared byte total");
    s.expect(holeReport.conclusion == AnalysisConclusion::Indeterminate,
             L"I-05 a partial read cannot conclude NoDifferenceObserved");
    s.expect(holeReport.stats.pages.failed == 1U && holeReport.stats.pages.succeeded == 4U,
             L"I-05 the page holding the unreadable window is counted as failed");

    // 未采集与不可读是两个状态：窗口之外一律 NotCollected。
    LiveImageBytes narrow = LiveImageBytes::fromBytes(
        0x1000U, std::vector<std::uint8_t>(loaded.begin() + 0x1000, loaded.begin() + 0x4000));
    const ImageDiffReport narrowReport = CompareImage(map, narrow, options);
    s.expect(narrowReport.notCollectedBytes == 0x400U + 0x200U &&
                 narrowReport.unreadableBytes == 0U,
             L"I-05 bytes outside the live window are NotCollected, not Unreadable");

    // 折叠：默认不折叠，开启后原始子范围仍可展开。
    LiveImageBytes gapped = LiveFromSpec(spec, kDiffLoadedBase);
    gapped.bytes[0x3000U] = static_cast<std::uint8_t>(gapped.bytes[0x3000U] ^ 0xFFU);
    gapped.bytes[0x3004U] = static_cast<std::uint8_t>(gapped.bytes[0x3004U] ^ 0xFFU);
    const ImageDiffReport unfolded = CompareImage(map, gapped, options);
    s.expect(unfolded.entries.size() == 2U,
             L"I-05 with no collapse budget two nearby changes stay two entries");

    ImageDiffOptions collapsing = options;
    collapsing.collapseGapBytes = 8U;
    const ImageDiffReport folded = CompareImage(map, gapped, collapsing);
    s.expect(folded.entries.size() == 1U && folded.entries[0].rva == 0x3000U &&
                 folded.entries[0].length == 5U && folded.entries[0].collapsed,
             L"I-05 nearby changes collapse into one range of length 5");
    s.expect(folded.entries[0].subRanges.size() == 2U &&
                 folded.entries[0].subRanges[0].rva == 0x3000U &&
                 folded.entries[0].subRanges[0].length == 1U &&
                 folded.entries[0].subRanges[1].rva == 0x3004U &&
                 folded.entries[0].subRanges[1].length == 1U,
             L"I-05 the collapsed entry still exposes the original sub-ranges");
}

// I-05 要求每条差异带模块实例与前后少量反汇编。本层没有解码器，所以判据是：
// 字段必须存在，且"没尝试"与"尝试过但解不出来"必须是两个可分辨的状态。
void TestDifferenceContextFields(KswordTests::Suite& s) {
    const PeBuilder spec = MakeDiffFixture();
    const PeImageMap map = BuildPeImageMap(BuildPe(spec), kDiffLoadedBase);
    const std::vector<std::uint8_t> textPattern = PatternBytes(0x3000U, 11U);

    constexpr std::uint32_t kChangedRva = 0x1400U;
    LiveImageBytes live = LiveFromSpec(spec, kDiffLoadedBase);
    live.bytes[kChangedRva] = static_cast<std::uint8_t>(live.bytes[kChangedRva] ^ 0x6DU);

    DriverInstanceId module;
    module.bootId = "boot-I";
    module.imagePath = "\\SystemRoot\\System32\\drivers\\fixture.sys";
    module.imageBase = OptionalU64::of(kDiffLoadedBase);
    module.imageSize = OptionalU64::of(0x6000U);
    module.timeDateStamp = OptionalU64::of(0x60112233U);
    module.pdbSignature = "1111AAAA-2222-3333-4444-555566667777-1";

    ImageDiffOptions options = DefaultOptions();
    options.module = module;

    const ImageDiffReport withoutDisassembly = CompareImage(map, live, options);
    s.expect(withoutDisassembly.entries.size() == 1U,
             L"I-05 the context fixture produces exactly one difference");
    const ImageDiffEntry* plain = EntryAt(withoutDisassembly, kChangedRva);
    s.expect(plain != nullptr && plain->module.crossSessionKey() == module.crossSessionKey() &&
                 !plain->module.crossSessionKey().empty(),
             L"I-05 every difference carries the module instance it belongs to");
    s.expect(plain != nullptr && plain->disassembly.notAttempted() &&
                 !plain->disassembly.decoded &&
                 plain->disassembly.unavailableReasonKey.empty(),
             L"I-05 with no disassembly requested the context reads as not attempted");

    ImageDiffOptions decoding = options;
    decoding.attemptDisassembly = true;
    const ImageDiffReport withDisassembly = CompareImage(map, live, decoding);
    const ImageDiffEntry* decoded = EntryAt(withDisassembly, kChangedRva);
    s.expect(decoded != nullptr && decoded->disassembly.attemptedButUndecoded(),
             L"I-05 requesting disassembly in a decoder-free layer yields attempted-but-undecoded, not silence");
    s.expect(decoded != nullptr &&
                 decoded->disassembly.unavailableReasonKey ==
                     "integrity.disassembly.noDecoderInThisLayer",
             L"I-05 a missing disassembly is an explicit reason key, never an empty string");
    s.expect(decoded != nullptr && !decoded->disassembly.notAttempted() &&
                 plain != nullptr && plain->disassembly.notAttempted(),
             L"I-05 not-attempted and attempted-but-undecoded are distinguishable states");

    // 反汇编解不出来绝不能影响原始字节证据。
    s.expect(decoded != nullptr && decoded->referenceBytes.size() == 1U &&
                 decoded->referenceBytes[0] == textPattern[kChangedRva - 0x1000U] &&
                 decoded->liveBytes.size() == 1U &&
                 decoded->liveBytes[0] ==
                     static_cast<std::uint8_t>(textPattern[kChangedRva - 0x1000U] ^ 0x6DU),
             L"I-05 a failed disassembly leaves the raw before/after byte evidence intact");
    s.expect(plain != nullptr && decoded != nullptr &&
                 plain->referenceBytes == decoded->referenceBytes &&
                 plain->liveBytes == decoded->liveBytes && plain->rva == decoded->rva &&
                 plain->length == decoded->length,
             L"I-05 asking for disassembly changes nothing about the located difference itself");
}

// ---------------------------------------------------------------------------
// I-04 热补丁和未知合法变化
// ---------------------------------------------------------------------------
void TestExplanationRules(KswordTests::Suite& s) {
    const PeBuilder spec = MakeDiffFixture();
    const std::vector<std::uint8_t> file = BuildPe(spec);
    const PeImageMap map = BuildPeImageMap(file, kDiffLoadedBase);

    constexpr std::uint32_t kDocumentedRva = 0x1300U;
    constexpr std::uint32_t kLookalikeRva = 0x1900U;
    constexpr std::uint32_t kOrdinaryRva = 0x2500U;
    const std::vector<std::uint8_t> patch = {0xE9U, 0x11U, 0x22U, 0x33U, 0x44U};

    LiveImageBytes live = LiveFromSpec(spec, kDiffLoadedBase);
    for (std::size_t offset = 0; offset < patch.size(); ++offset) {
        live.bytes[kDocumentedRva + offset] = patch[offset];
        live.bytes[kLookalikeRva + offset] = patch[offset];   // 字节完全相同，但没有依据
    }
    live.bytes[kOrdinaryRva] = static_cast<std::uint8_t>(live.bytes[kOrdinaryRva] ^ 0x7EU);

    ExplanationRule rule;
    rule.ruleId = "hotpatch.fixture.0001";
    rule.ruleVersion = 3U;
    rule.range.rva = kDocumentedRva;
    rule.range.length = static_cast<std::uint32_t>(patch.size());
    rule.evidenceText = "fixture: documented hotpatch range";

    ImageDiffOptions options = DefaultOptions();
    options.rules = {rule};

    const ImageDiffReport report = CompareImage(map, live, options);
    s.expect(report.entries.size() == 3U, L"I-04 three separate changes produce three entries");
    const ImageDiffEntry* documented = EntryAt(report, kDocumentedRva);
    const ImageDiffEntry* lookalike = EntryAt(report, kLookalikeRva);
    const ImageDiffEntry* ordinary = EntryAt(report, kOrdinaryRva);
    s.expect(documented != nullptr && documented->explanation == DiffExplanation::Explained,
             L"I-04 a change inside a documented RVA range is Explained");
    s.expect(documented != nullptr && documented->ruleId == "hotpatch.fixture.0001" &&
                 documented->ruleVersion == 3U,
             L"I-04 the explained entry records the rule id and rule version");
    s.expect(lookalike != nullptr && lookalike->explanation == DiffExplanation::Unexplained &&
                 lookalike->ruleId.empty(),
             L"I-04 the same bytes at an undocumented RVA stay Unexplained");
    s.expect(ordinary != nullptr && ordinary->explanation == DiffExplanation::Unexplained,
             L"I-04 an ordinary code change stays Unexplained");
    s.expect(report.explainedEntries == 1U && report.unexplainedEntries == 2U,
             L"I-04 explained and unexplained entries are counted separately");
    s.expect(report.conclusion == AnalysisConclusion::DifferenceObserved,
             L"I-04 an explained difference is still an observed difference");

    // 规则只覆盖一部分时，剩余字节必须保持未解释。
    ImageDiffOptions partialRule = DefaultOptions();
    ExplanationRule narrow = rule;
    narrow.range.length = 2U;
    partialRule.rules = {narrow};
    const ImageDiffReport partialReport = CompareImage(map, live, partialRule);
    const ImageDiffEntry* head = EntryAt(partialReport, kDocumentedRva);
    const ImageDiffEntry* rest = EntryAt(partialReport, kDocumentedRva + 2U);
    s.expect(head != nullptr && head->length == 2U &&
                 head->explanation == DiffExplanation::Explained,
             L"I-04 only the covered prefix of a patch is Explained");
    s.expect(rest != nullptr && rest->length == 3U &&
                 rest->explanation == DiffExplanation::Unexplained,
             L"I-04 the uncovered remainder of the same patch stays Unexplained");

    // 空范围的规则不可用：不存在"整模块豁免"这条路。
    ImageDiffOptions emptyRule = DefaultOptions();
    ExplanationRule emptyRange;
    emptyRange.ruleId = "vendor.signed.microsoft";
    emptyRange.ruleVersion = 1U;
    emptyRange.range.rva = 0U;
    emptyRange.range.length = 0U;
    emptyRule.rules = {emptyRange};
    const ImageDiffReport emptyReport = CompareImage(map, live, emptyRule);
    s.expect(emptyReport.explainedEntries == 0U && emptyReport.unexplainedEntries == 3U,
             L"I-04 a rule without a concrete RVA range explains nothing");

    // 整映像范围的规则：一条"签名有效"就想解释掉模块里所有差异。这条路必须被
    // 堵死 —— 否则 I-04 的"不得给整份驱动永久放行"形同虚设。
    ImageDiffOptions wholeImageRule = DefaultOptions();
    ExplanationRule wholeModule;
    wholeModule.ruleId = "vendor.microsoft.signed";
    wholeModule.ruleVersion = 1U;
    wholeModule.range.rva = 0U;
    wholeModule.range.length = 0xFFFFFFFFU;
    wholeModule.evidenceText = "signature is valid";
    wholeImageRule.rules = {wholeModule};
    const ImageDiffReport wholeReport = CompareImage(map, live, wholeImageRule);
    s.expect(wholeReport.entries.size() == 3U && wholeReport.explainedEntries == 0U &&
                 wholeReport.unexplainedEntries == 3U,
             L"I-04 a rule spanning the whole image explains nothing at all");
    s.expect(wholeReport.rejectedRuleCount == 1U,
             L"I-04 the discarded over-broad rule is counted, not silently ignored");
    bool sawBroadKey = false;
    for (const std::string& key : wholeReport.limitationKeys) {
        if (key == "integrity.limitation.explanationRuleUnusable" ||
            key == "integrity.limitation.explanationRuleCoversWholeImage") {
            sawBroadKey = true;
        }
    }
    s.expect(sawBroadKey, L"I-04 dropping an over-broad rule surfaces an explicit limitation key");

    // 恰好等于 SizeOfImage 的规则同样是整模块豁免，只是写法不同。
    ExplanationRule exactImage = wholeModule;
    exactImage.range.length = 0x6000U;
    s.expect(AdmitExplanationRule(map, exactImage) == RuleAdmission::CoversWholeImage,
             L"I-04 a rule whose range equals SizeOfImage is refused as a whole-module exemption");

    // 跨节的规则没有可核对的对象：从 .text 末尾跨到 .data。
    ExplanationRule crossSection;
    crossSection.ruleId = "hotpatch.fixture.cross";
    crossSection.ruleVersion = 1U;
    crossSection.range.rva = 0x3FF0U;    // .text 是 [0x1000,0x4000)
    crossSection.range.length = 0x0100U; // 越过 0x4000 进入 .data
    s.expect(AdmitExplanationRule(map, crossSection) == RuleAdmission::NotScopedToOneSection,
             L"I-04 a rule that spans two sections is not scoped to anything checkable");

    // 硬上限：无映像上下文的 usable() 也不能被一条超宽规则骗过。
    ExplanationRule oversized;
    oversized.ruleId = "hotpatch.fixture.oversized";
    oversized.range.rva = 0x1000U;
    oversized.range.length = kExplanationRuleMaxSpanBytes + 1U;
    s.expect(!oversized.usable(),
             L"I-04 a rule wider than the documented hard cap is structurally unusable");
    s.expect(AdmitExplanationRule(map, oversized) == RuleAdmission::Unusable,
             L"I-04 the hard cap is enforced before any image-relative check");

    RvaRange span;
    span.rva = kDocumentedRva;
    span.length = 5U;
    s.expect(FindExplanationRule(map, emptyRule.rules, span) == nullptr,
             L"I-04 an empty-range rule never matches a span");
    s.expect(FindExplanationRule(map, wholeImageRule.rules, span) == nullptr,
             L"I-04 a whole-image rule never matches a span either");
    s.expect(FindExplanationRule(map, options.rules, span) != nullptr,
             L"I-04 a rule fully containing the span does match");
    RvaRange wider = span;
    wider.length = 6U;
    s.expect(FindExplanationRule(map, options.rules, wider) == nullptr,
             L"I-04 partial coverage does not count as a match");
}

// ---------------------------------------------------------------------------
// I-06 跳转目标和所有者
// ---------------------------------------------------------------------------
std::vector<ModuleRange> MakeModules() {
    ModuleRange kernel;
    kernel.name = "ntoskrnl.exe";
    kernel.base = 0xFFFFF80000000000ULL;
    kernel.size = 0x00800000ULL;
    ModuleRange driverA;
    driverA.name = "driverA.sys";
    driverA.base = 0xFFFFF80100000000ULL;
    driverA.size = 0x00010000ULL;
    ModuleRange driverB;
    driverB.name = "driverB.sys";
    driverB.base = 0xFFFFF80200000000ULL;
    driverB.size = 0x00010000ULL;
    return {kernel, driverA, driverB};
}

void TestBranchFollowing(KswordTests::Suite& s) {
    const std::vector<ModuleRange> modules = MakeModules();
    const std::uint64_t kernelStart = 0xFFFFF80000001000ULL;
    const std::uint64_t driverAEntry = 0xFFFFF80100000100ULL;

    const TargetOwner owner = ResolveTargetOwner(0xFFFFF80200000040ULL, modules);
    s.expect(owner.kind == TargetOwnerKind::InsideModule && owner.moduleName == "driverB.sys" &&
                 owner.offset == OptionalU64::of(0x40U),
             L"I-06 an address inside a known module resolves to module plus offset");
    const TargetOwner stranger = ResolveTargetOwner(0x0000000000001234ULL, modules);
    s.expect(stranger.kind == TargetOwnerKind::OutsideKnownModules && stranger.moduleName.empty(),
             L"I-06 an address outside every known module is reported as such, not as malicious");

    // 直接跳转到另一个正常模块 -> Resolved，且跨模块只是事实。
    const BranchResolver directResolver = [&](std::uint64_t address) {
        BranchStep step;
        step.bytesConsumed = 5U;
        if (address == kernelStart) {
            step.kind = FollowStepKind::DirectBranch;
            step.target = driverAEntry;
        } else {
            step.kind = FollowStepKind::ResolvedCode;
        }
        return step;
    };
    const FollowResult direct = FollowBranchTarget(kernelStart, modules, directResolver);
    s.expect(direct.termination == FollowTermination::Resolved,
             L"I-06 a direct branch to known code terminates as Resolved");
    s.expect(direct.path.size() == 2U && direct.path[1].address == driverAEntry &&
                 direct.path[1].owner.moduleName == "driverA.sys" &&
                 direct.path[1].owner.offset == OptionalU64::of(0x100U),
             L"I-06 the resolved target is attributed to the owning module and offset");
    s.expect(direct.crossedModuleBoundary,
             L"I-06 crossing into another normal module is recorded as a fact");
    s.expect(direct.depthUsed == 1U, L"I-06 one hop consumes exactly one depth unit");

    // 间接未解析。
    const BranchResolver indirectResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::IndirectUnresolved;
        step.bytesConsumed = 6U;
        return step;
    };
    const FollowResult indirect = FollowBranchTarget(kernelStart, modules, indirectResolver);
    s.expect(indirect.termination == FollowTermination::IndirectUnresolved,
             L"I-06 an indirect branch whose pointer cannot be read ends as IndirectUnresolved");

    // 导出转发必须与未解析间接目标是两个不同的结果。
    const BranchResolver forwarderResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::ExportForwarder;
        step.bytesConsumed = 0U;
        step.forwarderText = "NTOSKRNL.ExAllocatePool2";
        return step;
    };
    const FollowResult forwarder = FollowBranchTarget(kernelStart, modules, forwarderResolver);
    s.expect(forwarder.termination == FollowTermination::ExportForwarder,
             L"I-06 an export forwarder ends as ExportForwarder");
    s.expect(forwarder.termination != indirect.termination,
             L"I-06 forwarder and unresolved indirect target are distinct result values");
    s.expect(!forwarder.path.empty() &&
                 forwarder.path.back().forwarderText == "NTOSKRNL.ExAllocatePool2",
             L"I-06 the forwarder text is preserved");

    // 环检测确实终止。
    const std::uint64_t loopA = 0xFFFFF80000002000ULL;
    const std::uint64_t loopB = 0xFFFFF80000003000ULL;
    const BranchResolver cycleResolver = [&](std::uint64_t address) {
        BranchStep step;
        step.kind = FollowStepKind::DirectBranch;
        step.bytesConsumed = 5U;
        step.target = (address == loopA) ? loopB : loopA;
        return step;
    };
    const FollowResult cycle = FollowBranchTarget(loopA, modules, cycleResolver);
    s.expect(cycle.termination == FollowTermination::CycleDetected,
             L"I-06 a two-node loop terminates with CycleDetected");
    s.expect(cycle.path.size() == 3U,
             L"I-06 the cycle path stops at the first repeated address");

    // 目标不可读。
    const BranchResolver unreadableResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::TargetUnreadable;
        return step;
    };
    const FollowResult unreadable = FollowBranchTarget(kernelStart, modules, unreadableResolver);
    s.expect(unreadable.termination == FollowTermination::TargetUnreadable,
             L"I-06 an unreadable target ends as TargetUnreadable");

    // 起点就落在已知模块之外。
    const FollowResult outside = FollowBranchTarget(0x1234ULL, modules, directResolver);
    s.expect(outside.termination == FollowTermination::OutsideKnownModules,
             L"I-06 following stops at the edge of known modules");

    // 深度上限。
    const BranchResolver chainResolver = [](std::uint64_t address) {
        BranchStep step;
        step.kind = FollowStepKind::DirectBranch;
        step.bytesConsumed = 5U;
        step.target = address + 0x100U;
        return step;
    };
    FollowOptions shallow;
    shallow.maxDepth = 2U;
    shallow.maxBytes = 1024U;
    const FollowResult deep = FollowBranchTarget(kernelStart, modules, chainResolver, shallow);
    s.expect(deep.termination == FollowTermination::DepthExhausted,
             L"I-06 an unbounded chain stops at the depth limit");
    s.expect(deep.depthUsed == 2U && deep.path.size() == 3U,
             L"I-06 the depth limit is honoured exactly");

    // 字节预算上限与深度上限是两个独立的终止原因。
    FollowOptions tightBytes;
    tightBytes.maxDepth = 64U;
    tightBytes.maxBytes = 8U;
    const FollowResult budget = FollowBranchTarget(kernelStart, modules, chainResolver, tightBytes);
    s.expect(budget.termination == FollowTermination::ByteBudgetExhausted,
             L"I-06 exceeding the byte budget is a separate termination reason");
}

// ---------------------------------------------------------------------------
// I-09 扫描覆盖和竞态
// ---------------------------------------------------------------------------
DriverInstanceId MakeDriverId() {
    DriverInstanceId id;
    id.bootId = "boot-I";
    id.imagePath = "\\SystemRoot\\System32\\drivers\\fixture.sys";
    id.imageBase = OptionalU64::of(0xFFFFF80100000000ULL);
    id.imageSize = OptionalU64::of(0x10000U);
    id.timeDateStamp = OptionalU64::of(0x60112233U);
    id.pdbSignature = "1111AAAA-2222-3333-4444-555566667777-1";
    return id;
}

void TestScanCoverageAndStaleness(KswordTests::Suite& s) {
    const DriverInstanceId before = MakeDriverId();

    s.expect(CheckModuleStillSame(before, before) == ModuleStalenessVerdict::Same,
             L"I-09 an unchanged module identity is Same");

    DriverInstanceId unloaded;   // 读后拿不到任何身份
    s.expect(CheckModuleStillSame(before, unloaded) == ModuleStalenessVerdict::Stale,
             L"I-09 a module that no longer reports any identity is Stale");

    DriverInstanceId newVersion = before;
    newVersion.pdbSignature = "9999BBBB-2222-3333-4444-555566667777-2";
    newVersion.timeDateStamp = OptionalU64::of(0x60998877U);
    s.expect(CheckModuleStillSame(before, newVersion) == ModuleStalenessVerdict::Stale,
             L"I-09 a different image version at the same path is Stale");

    DriverInstanceId rebased = before;
    rebased.imageBase = OptionalU64::of(0xFFFFF80300000000ULL);
    s.expect(CheckModuleStillSame(before, rebased) == ModuleStalenessVerdict::Stale,
             L"I-09 a reload at another base within one boot is Stale");

    DriverInstanceId otherBoot = before;
    otherBoot.bootId = "boot-II";
    s.expect(CheckModuleStillSame(before, otherBoot) == ModuleStalenessVerdict::Stale,
             L"I-09 identities from different boots are not comparable and count as Stale");

    DriverInstanceId weak;
    weak.bootId = "boot-I";
    weak.imagePath = before.imagePath;
    DriverInstanceId weakAgain = weak;
    s.expect(CheckModuleStillSame(weak, weakAgain) == ModuleStalenessVerdict::Unverifiable,
             L"I-09 a path-only identity cannot be confirmed and is Unverifiable, not Same");

    DriverInstanceId nothing;
    s.expect(CheckModuleStillSame(nothing, before) == ModuleStalenessVerdict::Unverifiable,
             L"I-09 without a usable pre-read identity the verdict is Unverifiable");

    // 过期模块：结论不得被升级，账目要显式记为失败。
    const PeBuilder spec = MakeDiffFixture();
    const PeImageMap map = BuildPeImageMap(BuildPe(spec), kDiffLoadedBase);
    ImageDiffOptions options = DefaultOptions();
    options.staleness = ModuleStalenessVerdict::Stale;
    LiveImageBytes live = LiveFromSpec(spec, kDiffLoadedBase);
    live.bytes[0x1500U] = static_cast<std::uint8_t>(live.bytes[0x1500U] ^ 0xFFU);
    const ImageDiffReport staleReport = CompareImage(map, live, options);
    s.expect(staleReport.conclusion == AnalysisConclusion::Indeterminate,
             L"I-09 a stale module never yields a confident conclusion");
    s.expect(staleReport.stats.modules.attempted == 1U && staleReport.stats.modules.failed == 1U &&
                 staleReport.stats.modules.succeeded == 0U,
             L"I-09 module level accounting records the stale module as failed");
    bool sawStaleKey = false;
    for (const std::string& key : staleReport.limitationKeys) {
        if (key == "integrity.limitation.moduleStale") {
            sawStaleKey = true;
        }
    }
    s.expect(sawStaleKey, L"I-09 staleness surfaces as an explicit limitation key");
    s.expect(!staleReport.entries.empty(),
             L"I-09 a stale scan still keeps the observed facts instead of dropping everything");

    // I-09 + I-01：Unverifiable 是"无法判断"，不是"确认没变"。它必须和 Stale 一样
    // 封顶在 Indeterminate；把它走正常路径就等于把"分析无法判断"塌成"正确的空
    // 集合"。这里用一份干净的现场字节，正是旧行为最容易给出自信结论的场景。
    ImageDiffOptions unverifiable = DefaultOptions();
    unverifiable.staleness = ModuleStalenessVerdict::Unverifiable;
    const ImageDiffReport unverifiedReport =
        CompareImage(map, LiveFromSpec(spec, kDiffLoadedBase), unverifiable);
    s.expect(unverifiedReport.differingBytes == 0U && unverifiedReport.entries.empty(),
             L"I-09 the unverifiable fixture really does compare a clean image");
    s.expect(unverifiedReport.conclusion == AnalysisConclusion::Indeterminate,
             L"I-09 an unverifiable module identity can never conclude NoDifferenceObserved");
    s.expect(unverifiedReport.outcome.status == CollectionStatus::Partial,
             L"I-09 an unverifiable module identity degrades the collection outcome to Partial");
    s.expect(unverifiedReport.stats.modules.attempted == 1U &&
                 unverifiedReport.stats.modules.succeeded == 0U &&
                 unverifiedReport.stats.modules.failed == 0U,
             L"I-09 an unverifiable module counts as neither a succeeded nor a failed module");
    bool sawUnverifiableKey = false;
    for (const std::string& key : unverifiedReport.limitationKeys) {
        if (key == "integrity.limitation.moduleIdentityUnverifiable") {
            sawUnverifiableKey = true;
        }
    }
    s.expect(sawUnverifiableKey,
             L"I-09 the unverifiable identity still surfaces its own limitation key");

    // 字节 / 页 / 模块三个口径分别统计。
    ImageDiffOptions clean = DefaultOptions();
    LiveImageBytes partial = LiveFromSpec(spec, kDiffLoadedBase);
    RvaRange hole;
    hole.rva = 0x3000U;
    hole.length = 0x1000U;
    partial.markRange(hole, ByteReadStatus::Unreadable);
    const ImageDiffReport partialReport = CompareImage(map, partial, clean);
    s.expect(partialReport.stats.bytes.attempted == 0x400U + 0x3000U + 0x200U,
             L"I-09 byte accounting counts every byte in the effective compare set");
    s.expect(partialReport.stats.bytes.failed == 0x1000U,
             L"I-09 unreadable bytes are counted as failed bytes");
    s.expect(partialReport.stats.bytes.succeeded ==
                 partialReport.stats.bytes.attempted - 0x1000U,
             L"I-09 succeeded plus failed accounts for the whole attempted byte range");
    s.expect(partialReport.stats.pages.attempted == 5U && partialReport.stats.pages.failed == 1U &&
                 partialReport.stats.pages.succeeded == 4U,
             L"I-09 page accounting is independent of byte accounting");

    ScanCoverageStats total;
    AccumulateStats(total, partialReport.stats);
    AccumulateStats(total, staleReport.stats);
    s.expect(total.modules.attempted == 2U && total.modules.failed == 1U &&
                 total.modules.succeeded == 1U,
             L"I-09 per-module statistics accumulate across a multi-module scan");

    // F-06：命中上限时账目必须闭合。真正停住扫描的是片段数上限（maxEntries*4+16），
    // 不是 maxEntries；被截掉的那一大段既不是失败也不是排除，必须单独记账，
    // 否则请求的字节里会有一大半查无去向。
    ImageDiffOptions capped = DefaultOptions();
    capped.maxEntries = 4U;                       // 片段上限 = 4 * 4 + 16 = 32（手算）
    LiveImageBytes noisy = LiveFromSpec(spec, kDiffLoadedBase);
    for (std::uint32_t at = 0x1000U; at < 0x4000U; at += 2U) {
        noisy.bytes[at] = static_cast<std::uint8_t>(noisy.bytes[at] ^ 0xA5U);
    }
    const ImageDiffReport cappedReport = CompareImage(map, noisy, capped);
    constexpr std::uint64_t kRequestedBytes = 0x400U + 0x3000U + 0x200U;
    s.expect(cappedReport.limitHit && cappedReport.scanStoppedAtPieceLimit,
             L"F-06 the scan really is stopped by the piece limit, not by maxEntries");
    s.expect(cappedReport.pieceLimit == 32U && cappedReport.entryLimit == 4U,
             L"F-06 both the piece limit and the entry limit are exposed with their real values");
    s.expect(cappedReport.coverage.limit == OptionalU64::of(32U),
             L"F-06 the reported limit is the one that actually bound the scan, in its own unit");
    // 手算：头 0x400 字节全比完，.text 从 0x1000 起隔字节篡改，第 32 个片段在
    // 0x103F 落定，第 33 个片段在 0x1040 触发停止 —— 共 0x400 + 0x41 = 1089 字节。
    s.expect(cappedReport.stats.bytes.attempted == 1089U,
             L"F-06 the attempted byte count matches the hand-computed stop point");
    s.expect(cappedReport.notAttemptedBytes == kRequestedBytes - 1089U,
             L"F-06 the untouched tail of the compare set lands in its own bucket");
    s.expect(cappedReport.stats.bytes.attempted + cappedReport.stats.bytes.notAttempted +
                     cappedReport.stats.bytes.excluded ==
                 kRequestedBytes,
             L"F-06 attempted plus notAttempted plus excluded accounts for every requested byte");
    s.expect(cappedReport.stats.pages.attempted == 2U && cappedReport.stats.pages.notAttempted == 3U,
             L"F-06 pages never reached by the truncated scan are counted as not attempted");
    s.expect(cappedReport.entries.size() == 4U && cappedReport.coverage.truncated != 0U,
             L"F-06 the entry limit still caps how many entries are reported");
    bool sawNotAttemptedKey = false;
    for (const std::string& key : cappedReport.limitationKeys) {
        if (key == "integrity.limitation.bytesNotAttempted") {
            sawNotAttemptedKey = true;
        }
    }
    s.expect(sawNotAttemptedKey, L"F-06 the unscanned remainder surfaces its own limitation key");
    s.expect(cappedReport.conclusion == AnalysisConclusion::DifferenceObserved,
             L"F-06 a truncated scan still reports the differences it did observe");
}

// ---------------------------------------------------------------------------
// I-10 磁盘参考的可信度
// ---------------------------------------------------------------------------
bool SameEntries(const ImageDiffReport& a, const ImageDiffReport& b) {
    if (a.entries.size() != b.entries.size()) {
        return false;
    }
    for (std::size_t index = 0; index < a.entries.size(); ++index) {
        const ImageDiffEntry& left = a.entries[index];
        const ImageDiffEntry& right = b.entries[index];
        if (left.rva != right.rva || left.length != right.length || left.va != right.va ||
            left.kind != right.kind || left.readStatus != right.readStatus ||
            left.explanation != right.explanation || left.sectionName != right.sectionName ||
            left.referenceBytes != right.referenceBytes || left.liveBytes != right.liveBytes) {
            return false;
        }
    }
    return true;
}

void TestReferenceTrust(KswordTests::Suite& s) {
    const PeBuilder spec = MakeDiffFixture();
    const PeImageMap map = BuildPeImageMap(BuildPe(spec), kDiffLoadedBase);
    LiveImageBytes live = LiveFromSpec(spec, kDiffLoadedBase);
    live.bytes[0x1800U] = static_cast<std::uint8_t>(live.bytes[0x1800U] ^ 0xFFU);
    live.bytes[0x1801U] = static_cast<std::uint8_t>(live.bytes[0x1801U] ^ 0xFFU);

    ImageDiffOptions fromDisk = DefaultOptions();
    fromDisk.reference.kind = ReferenceSourceKind::LocalDisk;
    fromDisk.reference.description = "C:/Windows/System32/drivers/fixture.sys";

    ImageDiffOptions fromUser = fromDisk;
    fromUser.reference.kind = ReferenceSourceKind::UserSelectedImage;
    fromUser.reference.description = "D:/reference/fixture.sys";

    ImageDiffOptions fromSnapshot = fromDisk;
    fromSnapshot.reference.kind = ReferenceSourceKind::SavedSnapshot;
    fromSnapshot.reference.description = "session://2026-09-04/fixture";

    const ImageDiffReport diskReport = CompareImage(map, live, fromDisk);
    const ImageDiffReport userReport = CompareImage(map, live, fromUser);
    const ImageDiffReport snapshotReport = CompareImage(map, live, fromSnapshot);

    s.expect(diskReport.entries.size() == 1U && diskReport.entries[0].length == 2U,
             L"I-10 the fixture produces one two-byte difference");
    s.expect(SameEntries(diskReport, userReport) && SameEntries(diskReport, snapshotReport),
             L"I-10 the same bytes give identical difference entries under every reference source");
    s.expect(diskReport.conclusion == userReport.conclusion &&
                 diskReport.conclusion == snapshotReport.conclusion,
             L"I-10 the difference conclusion does not depend on the reference source");

    s.expect(diskReport.trustNotes != userReport.trustNotes &&
                 diskReport.trustNotes != snapshotReport.trustNotes &&
                 userReport.trustNotes != snapshotReport.trustNotes,
             L"I-10 each reference source gets its own trust notes");

    bool sawTrustRootNote = false;
    for (const std::string& key : diskReport.trustNotes) {
        if (key == "integrity.reference.localDisk.notATrustRoot") {
            sawTrustRootNote = true;
        }
    }
    s.expect(sawTrustRootNote,
             L"I-10 the local disk reference states it is not a tamper-proof trust root");

    // 信任说明里不允许出现"与磁盘一致所以安全"这类结论键。
    bool sawVerdictKey = false;
    const std::vector<std::vector<std::string>> allNotes = {
        diskReport.trustNotes, userReport.trustNotes, snapshotReport.trustNotes};
    for (const std::vector<std::string>& notes : allNotes) {
        for (const std::string& key : notes) {
            if (key.find("safe") != std::string::npos ||
                key.find("clean") != std::string::npos ||
                key.find("trusted") != std::string::npos) {
                sawVerdictKey = true;
            }
        }
    }
    s.expect(!sawVerdictKey,
             L"I-10 trust notes never carry a safety verdict, only comparison basis");

    ReferenceSource unknownIdentity;
    unknownIdentity.kind = ReferenceSourceKind::LocalDisk;
    const std::vector<std::string> weakNotes = BuildTrustNotes(unknownIdentity);
    bool sawIdentityNote = false;
    for (const std::string& key : weakNotes) {
        if (key == "integrity.reference.identityUnusable") {
            sawIdentityNote = true;
        }
    }
    s.expect(sawIdentityNote,
             L"I-10 a reference without a usable file identity says so explicitly");
}

// ---------------------------------------------------------------------------
// I-03 DVRT：支持的符号被正确解码，位点进不可比较范围
// ---------------------------------------------------------------------------
void TestDynamicRelocationSites(KswordTests::Suite& s) {
    const PeImageMap map = BuildCanonicalDvrtMap();
    const DynamicRelocationReport& report = map.dynamicRelocation;

    s.expect(map.valid(), L"I-02 a PE carrying a DVRT still parses");
    s.expect(report.status == DvrtStatus::Parsed, L"I-03 a well formed DVRT parses fully");
    s.expect(!report.extentUnknown && DvrtExtentFullyBounded(report.status),
             L"I-03 a fully parsed DVRT bounds its own affected extent");

    // 表定位：LoadConfig RVA、表 RVA、版本、长度全部手算写死。
    s.expect(report.loadConfigRva == OptionalU64::of(kDvrtLoadConfigRva),
             L"I-03 the load config directory RVA is recorded");
    s.expect(report.loadConfigDeclaredSize == OptionalU64::of(kDvrtLoadConfigSize),
             L"I-03 the declared load config size is recorded");
    s.expect(report.loadConfigStructSize == OptionalU64::of(kDvrtLoadConfigSize),
             L"I-03 the load config structure size field is recorded");
    s.expect(report.tableRva == OptionalU64::of(kDvrtTableRva),
             L"I-03 the DVRT table RVA is section VA plus table offset");
    s.expect(report.tableVersion == OptionalU64::of(1U), L"I-03 the DVRT table version is recorded");
    s.expect(report.tableSize == OptionalU64::of(kCanonicalDvrtEntriesBytes),
             L"I-03 the DVRT table size is recorded");

    // 三个符号段。第三段是关键：SWITCHTABLE_BRANCH 的记录宽度是 2 字节，
    // 现役 KernelCleanImageBaseline 用的 4 字节会在这里少解出一个位点。
    s.expect(report.groupsTotal == 3U, L"I-03 all three DVRT symbol groups are walked");
    s.expect(report.groupsDecoded == 3U, L"I-03 all three supported symbols decode to sites");
    s.expect(report.groupsUnknownSymbol == 0U, L"I-03 no unknown symbol in the canonical table");
    s.expect(report.groups.size() == 3U, L"I-03 one accounting record per symbol group");
    if (report.groups.size() == 3U) {
        s.expect(report.groups[0].symbol == kDvrtSymbolImportControlTransfer &&
                     report.groups[0].entryStride == 4U && report.groups[0].sitesDecoded == 2U &&
                     report.groups[0].blocksWalked == 1U && report.groups[0].decoded,
                 L"I-03 IMPORT_CONTROL_TRANSFER records are four bytes wide");
        s.expect(report.groups[1].symbol == kDvrtSymbolIndirControlTransfer &&
                     report.groups[1].entryStride == 2U && report.groups[1].sitesDecoded == 2U &&
                     report.groups[1].decoded,
                 L"I-03 INDIR_CONTROL_TRANSFER records are two bytes wide");
        s.expect(report.groups[2].symbol == kDvrtSymbolSwitchtableBranch &&
                     report.groups[2].entryStride == 2U && report.groups[2].sitesDecoded == 2U &&
                     report.groups[2].decoded,
                 L"I-03 SWITCHTABLE_BRANCH records are two bytes wide, not four");
    }

    // 六个位点的 RVA 全部手算，各占 8 字节且互不相邻。
    s.expect(report.sitesDecoded == 6U, L"I-03 six dynamic relocation sites are decoded");
    s.expect(report.sitesOutsideImage == 0U, L"I-03 every canonical site lands inside the image");
    s.expect(report.siteRanges.size() == 6U, L"I-03 the six sites stay six separate ranges");
    s.expect(RvaRangesTotalBytes(report.siteRanges) == 6U * kExpectedSiteSpan,
             L"I-03 each decoded site covers exactly the conservative site span");
    const std::uint32_t expectedSites[6] = {kCanonicalSiteRva0, kCanonicalSiteRva1,
                                            kCanonicalSiteRva2, kCanonicalSiteRva3,
                                            kCanonicalSiteRva4, kCanonicalSiteRva5};
    bool everySiteMatches = report.siteRanges.size() == 6U;
    for (std::size_t index = 0; index < 6U && everySiteMatches; ++index) {
        everySiteMatches = report.siteRanges[index].rva == expectedSites[index] &&
                           report.siteRanges[index].length == kExpectedSiteSpan;
    }
    s.expect(everySiteMatches, L"I-03 decoded site RVAs match the hand computed page offsets");
    s.expect(report.unknownSymbolRanges.empty(),
             L"I-03 no page level fallback range when every symbol is understood");
    s.expect(report.affectedRanges().size() == 6U,
             L"I-03 affectedRanges exports the site set for the difference engine");

    // 位点进不可比较范围：磁盘上根本没有加载器改写后的字节。
    for (std::size_t index = 0; index < 6U; ++index) {
        s.expect(RvaRangesContain(map.notComparableRanges, expectedSites[index]),
                 L"I-03 every dynamic relocation site is marked not comparable");
        s.expect(!RvaRangesContain(map.comparableRanges, expectedSites[index]),
                 L"I-03 a dynamic relocation site never stays in the comparable set");
    }
    // 可比较字节数 = 头 0x400 + .text 0x1000 + .rdata 0x1000 - 6 * 8 = 9168。
    s.expect(RvaRangesTotalBytes(map.rawBackedRanges) == 9216U,
             L"I-02 the raw backed set keeps its pre-exclusion size");
    s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9168U,
             L"I-03 exactly the site bytes are removed from the comparable set");

    // ReadNormalizedBytes 是磁盘参考窗口：跨到位点上必须失败，而不是给一片 0。
    std::vector<std::uint8_t> bytes;
    s.expect(!ReadNormalizedBytes(map, kCanonicalSiteRva0, 8U, bytes),
             L"I-05 reading exactly a dynamic relocation site is refused");
    s.expect(!ReadNormalizedBytes(map, kCanonicalSiteRva0 - 8U, 16U, bytes),
             L"I-05 a span straddling a dynamic relocation site is refused");
    s.expect(ReadNormalizedBytes(map, kCanonicalSiteRva0 - 8U, 8U, bytes) && bytes.size() == 8U,
             L"I-05 the bytes just before a site remain readable");
    s.expect(ReadNormalizedBytes(map, kCanonicalSiteRva0 + kExpectedSiteSpan, 8U, bytes),
             L"I-05 the bytes just after a site remain readable");

    // 账目：三段全部处理完，符号总数已知，因此覆盖率可以判完整。
    s.expect(report.coverage.totalKnown == OptionalU64::of(3U),
             L"I-09 the DVRT account knows how many symbol groups exist");
    s.expect(report.coverage.succeeded == 3U && report.coverage.failed == 0U &&
                 report.coverage.skipped == 0U && report.coverage.truncated == 0U,
             L"I-09 the DVRT account counts three decoded groups and nothing else");
    s.expect(report.coverage.fullyCovered(),
             L"I-09 a fully walked DVRT reports positive complete coverage");
}

// I-03：DVRT 与 .reloc 是两件事 —— 基址归一化照做，位点照样排除。
void TestDynamicRelocationWithBaseChange(KswordTests::Suite& s) {
    DvrtFixtureSpec fixture;
    fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
    fixture.includeReloc = true;
    const std::uint64_t loadedBase = kDvrtPreferredBase + 0x40000000ULL;
    const PeImageMap map = BuildDvrtMap(fixture, loadedBase);

    s.expect(map.valid(), L"I-02 a DVRT image with a base change still parses");
    s.expect(map.relocation.status == RelocationStatus::Applied,
             L"I-03 the classic .reloc directory still normalizes under a base change");
    s.expect(map.relocation.entriesApplied == 1U,
             L"I-03 exactly the one declared DIR64 entry is applied");
    // 手算期望：磁盘上是 preferredBase + 0x1180，归一化后必须是 loadedBase + 0x1180。
    s.expect(ReadU64At(map.image, kDvrtRelocTargetRva) == loadedBase + kDvrtRelocTargetRva,
             L"I-03 the relocated pointer holds the target base value");
    s.expect(map.dynamicRelocation.status == DvrtStatus::Parsed &&
                 map.dynamicRelocation.sitesDecoded == 6U,
             L"I-03 base relocation does not disturb DVRT decoding");
    // 被 .reloc 改写的字节仍然可比较（它可以从磁盘算出来）；DVRT 位点不行。
    s.expect(RvaRangesContain(map.comparableRanges, kDvrtRelocTargetRva),
             L"I-03 a normalizable relocation target stays comparable");
    s.expect(!RvaRangesContain(map.comparableRanges, kCanonicalSiteRva0),
             L"I-03 a dynamic relocation site is not comparable even when .reloc succeeded");
    s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9168U,
             L"I-03 only the DVRT sites are excluded, not the relocation targets");
}

// I-03：位点被 SizeOfImage 截断 / 落到映像外
void TestDynamicRelocationSiteClipping(KswordTests::Suite& s) {
    const PeBuilder spec = MakeDvrtClipFixture();
    const PeImageMap map = BuildPeImageMap(BuildPe(spec), kDvrtPreferredBase);
    const DynamicRelocationReport& report = map.dynamicRelocation;

    s.expect(map.valid(), L"I-02 the clipping fixture parses");
    s.expect(report.status == DvrtStatus::Parsed, L"I-03 the clipping fixture DVRT parses fully");
    s.expect(report.sitesDecoded == 1U,
             L"I-03 only the site inside SizeOfImage is decoded");
    s.expect(report.sitesOutsideImage == 1U,
             L"I-03 a site past SizeOfImage is counted, not silently dropped");
    s.expect(report.siteRanges.size() == 1U && report.siteRanges[0].rva == kClipSiteRva &&
                 report.siteRanges[0].length == kClipSiteLength,
             L"I-03 a site near the image end is clipped to SizeOfImage");
}

// I-03：不认识的符号只按块的页粒度标不可比较，绝不让整份映像失败
void TestDynamicRelocationUnknownSymbol(KswordTests::Suite& s) {
    std::vector<std::uint8_t> entries;
    AppendDvrtGroup(entries, 3U, DvrtBlock(0x1000U, 4U, {0x00000120U}));
    // 符号 9 未定义：容器仍是合法的基址重定位块，但记录含义未知。
    AppendDvrtGroup(entries, 9U, DvrtBlock(0x1000U, 4U, {0x00000700U, 0x00000710U}));

    DvrtFixtureSpec fixture;
    fixture.table = DvrtTable(1U, entries);
    const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
    const DynamicRelocationReport& report = map.dynamicRelocation;

    s.expect(map.valid(),
             L"I-03 an unknown DVRT symbol does not fail the whole image");
    s.expect(report.status == DvrtStatus::ParsedWithUnknownSymbol,
             L"I-03 an unknown symbol is reported as such, not as a clean parse");
    s.expect(!report.extentUnknown,
             L"I-03 a block container still bounds an unknown symbol to its pages");
    s.expect(report.groupsDecoded == 1U && report.groupsUnknownSymbol == 1U,
             L"I-03 decoded and unknown symbol groups are counted apart");
    s.expect(report.sitesDecoded == 1U,
             L"I-03 an unknown symbol contributes no decoded sites");
    s.expect(report.unknownSymbolRanges.size() == 1U &&
                 report.unknownSymbolRanges[0].rva == 0x1000U &&
                 report.unknownSymbolRanges[0].length == 0x1000U,
             L"I-03 an unknown symbol marks exactly the pages its blocks name");
    // 页粒度降级只吃掉 .text 那一页，.rdata 照常可比较 —— 这就是"按范围降级"。
    s.expect(!RvaRangesContain(map.comparableRanges, 0x1700U),
             L"I-03 a byte inside an unknown symbol page is not comparable");
    s.expect(RvaRangesContain(map.comparableRanges, kDvrtRdataRva + 0x100U),
             L"I-03 pages outside the unknown symbol stay comparable");
    s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9216U - 0x1000U,
             L"I-03 exactly one page is removed for the unknown symbol");
    s.expect(report.coverage.skipped == 1U && report.coverage.succeeded == 1U &&
                 report.coverage.failed == 0U,
             L"I-09 an unknown symbol is accounted as skipped, not as success");
    s.expect(!report.coverage.fullyCovered(),
             L"I-09 a skipped symbol group forbids a complete coverage claim");
}

// ---------------------------------------------------------------------------
// I-03 DVRT 的降级路径：畸形/未知版本/无支撑一律标范围，绝不悄悄当作"没有 DVRT"
// ---------------------------------------------------------------------------
void TestDynamicRelocationDegradation(KswordTests::Suite& s) {
    // (0) 七个状态值必须互相可分：名字互不相同，界定判据把它们切成 3 + 4。
    //     状态塌成一个就等于把"没有 DVRT""看不懂 DVRT""读不到 DVRT"混为一谈。
    {
        const DvrtStatus allStatuses[7] = {
            DvrtStatus::NotPresent,         DvrtStatus::Parsed,
            DvrtStatus::ParsedWithUnknownSymbol, DvrtStatus::LoadConfigUnusable,
            DvrtStatus::TableUnbacked,      DvrtStatus::UnsupportedVersion,
            DvrtStatus::Malformed};
        bool namesDistinct = true;
        for (std::size_t left = 0; left < 7U; ++left) {
            for (std::size_t right = left + 1U; right < 7U; ++right) {
                if (std::string(DvrtStatusName(allStatuses[left])) ==
                    DvrtStatusName(allStatuses[right])) {
                    namesDistinct = false;
                }
            }
        }
        s.expect(namesDistinct, L"I-03 every DVRT status has its own name");
        std::size_t boundedCount = 0;
        for (std::size_t index = 0; index < 7U; ++index) {
            if (DvrtExtentFullyBounded(allStatuses[index])) {
                ++boundedCount;
            }
        }
        s.expect(boundedCount == 3U,
                 L"I-03 only not-present, parsed and parsed-with-unknown-symbol bound the extent");
    }

    // (1) 完全没有 LoadConfig 目录 —— 这是"确实没有 DVRT"的正面证据。
    {
        const PeImageMap map = BuildPeImageMap(BuildPe(MakeLayoutFixture()), 0x140000000ULL);
        const DynamicRelocationReport& report = map.dynamicRelocation;
        s.expect(report.status == DvrtStatus::NotPresent,
                 L"I-03 a PE without a load config directory reports DVRT not present");
        s.expect(!report.extentUnknown && report.siteRanges.empty(),
                 L"I-03 absent DVRT marks nothing not comparable");
        s.expect(report.coverage.totalKnown == OptionalU64::of(0U) &&
                     report.coverage.fullyCovered(),
                 L"I-09 absent DVRT is positive evidence of zero symbol groups");
    }

    // (2) 数据目录声明的 LoadConfig 长度早于 DVRT 字段出现的版本。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        fixture.loadConfigDirectorySize = 100U;
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::NotPresent,
                 L"I-03 a pre-DVRT load config directory size means DVRT cannot exist");
        s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9216U,
                 L"I-03 a pre-DVRT load config excludes nothing");
    }

    // (3) 结构体自己的 Size 字段太短，尽管数据目录声明得很长。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        fixture.loadConfigStructSize = 200U;
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::NotPresent,
                 L"I-03 the load config Size field also gates the DVRT fields");
        s.expect(map.dynamicRelocation.loadConfigStructSize == OptionalU64::of(200U),
                 L"I-03 the structure size that caused the decision is preserved");
    }

    // (4) DVRT 表偏移为 0 —— 结构体有那个字段但没有表。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        fixture.tableOffsetInSection = 0U;
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::NotPresent,
                 L"I-03 a zero DynamicValueRelocTableOffset means no table");
        s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9216U,
                 L"I-03 a zero table offset excludes nothing");
    }

    // (5) LoadConfig 落在零填充区：读出来会是一片 0，于是 Size=0、Offset=0。
    //     不做支撑校验就会得出"这份 PE 没有 DVRT"——把"从没采到"当成"确实没有"。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        fixture.rdataRawSize = 0x80U;   // LoadConfig 需要 230 字节，raw 只有 0x80
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = map.dynamicRelocation;
        s.expect(report.status == DvrtStatus::LoadConfigUnusable,
                 L"I-03 an unbacked load config is unusable, never 'no DVRT'");
        s.expect(report.extentUnknown && !DvrtExtentFullyBounded(report.status),
                 L"I-03 an unusable load config leaves the DVRT extent unknown");
        s.expect(map.comparableRanges.empty(),
                 L"I-03 an unknown DVRT extent removes every byte from comparison");
        s.expect(!map.relocation.imageNotNormalized,
                 L"I-03 a DVRT problem is not reported as a failed base normalization");
    }

    // (6) 宿主节序号越界。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        fixture.tableSectionOneBased = 9U;
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::LoadConfigUnusable,
                 L"I-03 an out of range DynamicValueRelocTableSection is unusable");
        s.expect(map.dynamicRelocation.extentUnknown && map.comparableRanges.empty(),
                 L"I-03 an unusable host section leaves the extent unknown");
    }

    // (7) 表版本不是 1 —— "看不懂"不等于"没有"。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(2U, CanonicalDvrtEntries());
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = map.dynamicRelocation;
        s.expect(map.valid(), L"I-03 an unknown DVRT version does not fail the PE parse");
        s.expect(report.status == DvrtStatus::UnsupportedVersion,
                 L"I-03 an unknown DVRT version is named explicitly");
        s.expect(report.tableVersion == OptionalU64::of(2U),
                 L"I-03 the unrecognised version number is preserved");
        s.expect(report.sitesDecoded == 0U && report.siteRanges.empty(),
                 L"I-03 an unknown version decodes no sites at all");
        s.expect(report.extentUnknown && map.comparableRanges.empty(),
                 L"I-03 an unknown version removes every byte from comparison");
    }

    // (8) 版本合法但表为空：这是正面证据，"没有位点"成立。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, std::vector<std::uint8_t>{});
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = map.dynamicRelocation;
        s.expect(report.status == DvrtStatus::Parsed && !report.extentUnknown,
                 L"I-03 an empty but valid DVRT table is a clean parse");
        s.expect(report.coverage.totalKnown == OptionalU64::of(0U) &&
                     report.coverage.fullyCovered(),
                 L"I-09 an empty DVRT table is complete coverage of zero groups");
        s.expect(RvaRangesTotalBytes(map.comparableRanges) == 9216U,
                 L"I-03 an empty DVRT table excludes nothing");
    }

    // (9) 表 Size 声明越过映像。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries(), 0x4000U);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.valid(), L"I-03 an oversized DVRT size does not fail the PE parse");
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 a DVRT size running past SizeOfImage is malformed");
        s.expect(map.dynamicRelocation.extentUnknown && map.comparableRanges.empty(),
                 L"I-03 an oversized DVRT size leaves the extent unknown");
    }

    // (10) 块长度非法（小于块头）。
    {
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, DvrtBlock(0x1000U, 4U, {0x00000120U}, 4U));
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.valid(), L"I-03 an invalid DVRT block size does not fail the PE parse");
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 a block shorter than its own header is malformed");
        s.expect(map.dynamicRelocation.coverage.failed == 1U,
                 L"I-09 the symbol group whose container broke is counted as failed");
        s.expect(map.dynamicRelocation.extentUnknown && map.comparableRanges.empty(),
                 L"I-03 a broken block container leaves the extent unknown");
    }

    // (11) 块的 VirtualAddress 不是页对齐 —— 那不是一个真的块容器。
    {
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, DvrtBlock(0x1004U, 4U, {0x00000120U}));
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 a block VirtualAddress that is not page aligned is malformed");
        s.expect(map.dynamicRelocation.extentUnknown,
                 L"I-03 a misaligned block leaves the extent unknown");
    }

    // (12) 符号段声明的 BaseRelocSize 超过表里剩下的字节。
    {
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, DvrtBlock(0x1000U, 4U, {0x00000120U}), 0x1000U);
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 a BaseRelocSize past the table end is malformed");
        s.expect(map.dynamicRelocation.groupsTotal == 0U,
                 L"I-03 a symbol group with an impossible payload size is not counted as walked");
        s.expect(map.dynamicRelocation.coverage.truncated == 1U,
                 L"I-09 a table that stops early is accounted as truncated");
        s.expect(!map.dynamicRelocation.coverage.totalKnown.present,
                 L"I-09 a truncated DVRT walk never claims to know the group total");
    }

    // (13) 段 payload 尾部剩下不足一个块头，但那几个字节不是 0 —— 里面可能还藏着记录。
    {
        std::vector<std::uint8_t> payload = DvrtBlock(0x1000U, 4U, {0x00000120U});
        payload.push_back(0x11U);
        payload.push_back(0x22U);
        payload.push_back(0x33U);
        payload.push_back(0x44U);
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, payload);
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 non-zero trailing bytes inside a symbol payload are malformed");
        s.expect(map.dynamicRelocation.extentUnknown,
                 L"I-03 unexplained payload bytes leave the extent unknown");
    }

    // (14) 同样的尾部但全是 0：那是对齐填充，容器仍然走通。
    {
        std::vector<std::uint8_t> payload = DvrtBlock(0x1000U, 4U, {0x00000120U});
        payload.resize(payload.size() + 4U, 0U);
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, payload);
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::Parsed,
                 L"I-03 zero padding at the end of a symbol payload is accepted");
        s.expect(map.dynamicRelocation.sitesDecoded == 1U,
                 L"I-03 padding does not swallow the decoded site");
    }

    // (15) 表尾剩下不足一个条目头，且那几个字节非 0。
    {
        std::vector<std::uint8_t> entries;
        AppendDvrtGroup(entries, 3U, DvrtBlock(0x1000U, 4U, {0x00000120U}));
        entries.push_back(0x55U);
        entries.push_back(0x66U);
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, entries);
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(map.dynamicRelocation.status == DvrtStatus::Malformed,
                 L"I-03 non-zero trailing bytes at the table end are malformed");
        s.expect(map.dynamicRelocation.coverage.truncated == 1U,
                 L"I-09 unexplained table tail bytes are accounted as truncation");
    }

    // (16) 表本体落在零填充区：读到的块头全是伪造的 0。
    {
        DvrtFixtureSpec fixture;
        fixture.table = DvrtTable(1U, CanonicalDvrtEntries());
        // LoadConfig（.rdata 前 230 字节）与表头（0x200..0x208）仍有支撑，但条目
        // 从 0x208 一直到 0x254，raw 只到 0x220 —— 后半段读到的是零填充。
        fixture.rdataRawSize = 0x220U;
        const PeImageMap map = BuildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = map.dynamicRelocation;
        s.expect(report.status == DvrtStatus::TableUnbacked,
                 L"I-03 a DVRT table without file bytes behind it is unbacked, not empty");
        s.expect(report.extentUnknown && map.comparableRanges.empty(),
                 L"I-03 an unbacked DVRT table leaves the extent unknown");
        s.expect(report.sitesDecoded == 0U,
                 L"I-03 an unbacked DVRT table decodes nothing");
    }
}

} // namespace

int RunImageIntegrityTests() {
    KswordTests::Suite suite(L"I image integrity");
    TestLayoutMapping(suite);
    TestMalformedSections(suite);
    TestHeaderBoundaries(suite);
    TestWholeImageRejection(suite);
    TestRelocationNormalization(suite);
    TestRelocationCannotNormalize(suite);
    TestRelocationEdgeCases(suite);
    TestDynamicRelocationSites(suite);
    TestDynamicRelocationWithBaseChange(suite);
    TestDynamicRelocationSiteClipping(suite);
    TestDynamicRelocationUnknownSymbol(suite);
    TestDynamicRelocationDegradation(suite);
    TestDifferenceLocation(suite);
    TestDifferenceContextFields(suite);
    TestExplanationRules(suite);
    TestBranchFollowing(suite);
    TestScanCoverageAndStaleness(suite);
    TestReferenceTrust(suite);
    suite.report();
    return suite.failures();
}
