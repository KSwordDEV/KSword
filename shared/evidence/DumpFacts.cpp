#include "DumpFacts.h"

#include <algorithm>
#include <utility>

namespace Ksword::Evidence {
namespace {

// ---------------------------------------------------------------------------
// 格式常量。全部写死在实现里，不从被解析的文件读，也不暴露给测试 ——
// 测试必须自己按 DUMP_HEADER64 的公开布局写偏移，否则偏移写错测不出来（Q-01）。
// ---------------------------------------------------------------------------
constexpr std::uint32_t kSignatureMdmp = 0x504D444DU;   // 'MDMP'
constexpr std::uint32_t kSignaturePage = 0x45474150U;   // 'PAGE'
constexpr std::uint32_t kValidDump64 = 0x34365544U;     // 'DU64'
constexpr std::uint32_t kValidDump32 = 0x504D5544U;     // 'DUMP'

// 转储写入器只填自己关心的字段，其余保持 'PAGE' 填充。读到填充值就等于
// "这一格没被写过"，绝不能当成真实取值 —— C-03 点名的陷阱。
constexpr std::uint32_t kPageFillDword = 0x45474150U;
constexpr std::uint64_t kPageFillQword = 0x4547415045474150ULL;

constexpr std::size_t kMinidumpHeaderBytes = 0x20U;
constexpr std::size_t kKernelHeader64Bytes = 0x2000U;
constexpr std::size_t kKernelHeader32Bytes = 0x1000U;
constexpr std::size_t kSignatureBytes = 8U;

// DUMP_HEADER64 字段偏移。
constexpr std::size_t kOffMajorVersion = 0x08U;
constexpr std::size_t kOffMinorVersion = 0x0CU;
constexpr std::size_t kOffDirectoryTableBase = 0x10U;
constexpr std::size_t kOffMachineImageType = 0x30U;
constexpr std::size_t kOffNumberProcessors = 0x34U;
constexpr std::size_t kOffBugCheckCode = 0x38U;
constexpr std::size_t kOffBugCheckParameters = 0x40U;
constexpr std::size_t kOffDumpType = 0xF98U;
constexpr std::size_t kOffSystemTime = 0xFA8U;
constexpr std::size_t kOffSystemUpTime = 0x1030U;
constexpr std::size_t kOffWriterStatus = 0x1048U;

// PE 机器类型。
constexpr std::uint32_t kMachineX86 = 0x014CU;
constexpr std::uint32_t kMachineX64 = 0x8664U;
constexpr std::uint32_t kMachineArm = 0x01C4U;
constexpr std::uint32_t kMachineArm64 = 0xAA64U;

constexpr const char* kRecognitionDomain = "KSWORD_DUMPRECOGNITION";

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
constexpr bool IsAsciiUpper(unsigned char byte) noexcept { return byte >= 'A' && byte <= 'Z'; }
constexpr bool IsAsciiLower(unsigned char byte) noexcept { return byte >= 'a' && byte <= 'z'; }
constexpr bool IsAsciiDigit(unsigned char byte) noexcept { return byte >= '0' && byte <= '9'; }

constexpr bool IsAsciiAlpha(unsigned char byte) noexcept {
    return IsAsciiUpper(byte) || IsAsciiLower(byte);
}

constexpr bool IsAsciiAlnum(unsigned char byte) noexcept {
    return IsAsciiAlpha(byte) || IsAsciiDigit(byte);
}

constexpr char AsciiLowerChar(char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return IsAsciiUpper(byte) ? static_cast<char>(byte - 'A' + 'a') : value;
}

// 只折 ASCII 大小写。非 ASCII 字节原样保留：没有 locale 就不该猜别的字符集，
// 折错了会把两个不同的模块名合成一个。
std::string AsciiLower(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (const char value : text) {
        result.push_back(AsciiLowerChar(value));
    }
    return result;
}

// 下面两个不分配内存的比较函数专供 noexcept 判据用：判据里不许有可能抛
// bad_alloc 的分配，否则 noexcept 会把一次内存不足变成 std::terminate。
bool AsciiEqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t index = 0; index < a.size(); ++index) {
        if (AsciiLowerChar(a[index]) != AsciiLowerChar(b[index])) {
            return false;
        }
    }
    return true;
}

// needle 必须已经是小写字面量。
bool ContainsIgnoreCase(std::string_view haystack, std::string_view loweredNeedle) noexcept {
    if (loweredNeedle.empty() || haystack.size() < loweredNeedle.size()) {
        return false;
    }
    const std::size_t last = haystack.size() - loweredNeedle.size();
    for (std::size_t start = 0; start <= last; ++start) {
        std::size_t offset = 0;
        while (offset < loweredNeedle.size() &&
               AsciiLowerChar(haystack[start + offset]) == loweredNeedle[offset]) {
            ++offset;
        }
        if (offset == loweredNeedle.size()) {
            return true;
        }
    }
    return false;
}

// 控制字符：C0 区与 DEL。
constexpr bool IsControlByte(unsigned char byte) noexcept {
    return byte < 0x20U || byte == 0x7FU;
}

// 报告里允许保留的排版控制字符。
constexpr bool IsLayoutControlByte(unsigned char byte) noexcept {
    return byte == '\t' || byte == '\n' || byte == '\r';
}

std::string_view BaseNameOf(std::string_view path) noexcept {
    std::size_t begin = 0;
    for (std::size_t index = 0; index < path.size(); ++index) {
        if (path[index] == '\\' || path[index] == '/') {
            begin = index + 1;
        }
    }
    return path.substr(begin);
}

} // namespace

// ---------------------------------------------------------------------------
// 字节读取
// ---------------------------------------------------------------------------
bool ReadLittleEndianU32(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint32_t& out) noexcept {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        return false;
    }
    out = static_cast<std::uint32_t>(bytes[offset]) |
          (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
          (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
          (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    return true;
}

bool ReadLittleEndianU64(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint64_t& out) noexcept {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    if (!ReadLittleEndianU32(bytes, offset, low) ||
        !ReadLittleEndianU32(bytes, offset + 4U, high)) {
        return false;
    }
    out = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
    return true;
}

// ---------------------------------------------------------------------------
// C-02 文件识别
// ---------------------------------------------------------------------------
const char* DumpKindName(DumpKind kind) noexcept {
    switch (kind) {
    case DumpKind::NotADump: return "NotADump";
    case DumpKind::Unsupported: return "Unsupported";
    case DumpKind::UserMinidump: return "UserMinidump";
    case DumpKind::KernelSmall: return "KernelSmall";
    case DumpKind::KernelMemory: return "KernelMemory";
    }
    return "NotADump";
}

bool DumpKindCarriesKernelFacts(DumpKind kind) noexcept {
    return kind == DumpKind::KernelSmall || kind == DumpKind::KernelMemory;
}

const char* SignatureFamilyName(SignatureFamily family) noexcept {
    switch (family) {
    case SignatureFamily::None: return "None";
    case SignatureFamily::Mdmp: return "Mdmp";
    case SignatureFamily::KernelPage64: return "KernelPage64";
    case SignatureFamily::KernelPage32: return "KernelPage32";
    }
    return "None";
}

const char* RecognitionReasonName(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::Recognized: return "Recognized";
    case RecognitionReason::EmptyFile: return "EmptyFile";
    case RecognitionReason::TooSmallForSignature: return "TooSmallForSignature";
    case RecognitionReason::TruncatedHeader: return "TruncatedHeader";
    case RecognitionReason::UnknownSignature: return "UnknownSignature";
    case RecognitionReason::UnsupportedKernelBitness: return "UnsupportedKernelBitness";
    case RecognitionReason::UnsupportedArchitecture: return "UnsupportedArchitecture";
    case RecognitionReason::UnsupportedDumpType: return "UnsupportedDumpType";
    }
    return "UnknownSignature";
}

const char* TargetArchitectureName(TargetArchitecture architecture) noexcept {
    switch (architecture) {
    case TargetArchitecture::Unknown: return "Unknown";
    case TargetArchitecture::X86: return "X86";
    case TargetArchitecture::X64: return "X64";
    case TargetArchitecture::Arm: return "Arm";
    case TargetArchitecture::Arm64: return "Arm64";
    case TargetArchitecture::Other: return "Other";
    }
    return "Unknown";
}

namespace {

TargetArchitecture ArchitectureFromMachineType(std::uint32_t machineType) noexcept {
    switch (machineType) {
    case kMachineX86: return TargetArchitecture::X86;
    case kMachineX64: return TargetArchitecture::X64;
    case kMachineArm: return TargetArchitecture::Arm;
    case kMachineArm64: return TargetArchitecture::Arm64;
    default: break;
    }
    // 'PAGE' 填充不是机器类型，是"没填过"。不许把它归到 Other 冒充一个取值。
    if (machineType == kPageFillDword || machineType == 0U) {
        return TargetArchitecture::Unknown;
    }
    return TargetArchitecture::Other;
}

const char* RecognitionMessageKey(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::Recognized: return "dump.recognize.ok";
    case RecognitionReason::EmptyFile: return "dump.recognize.empty_file";
    case RecognitionReason::TooSmallForSignature: return "dump.recognize.too_small";
    case RecognitionReason::TruncatedHeader: return "dump.recognize.truncated_header";
    case RecognitionReason::UnknownSignature: return "dump.recognize.unknown_signature";
    case RecognitionReason::UnsupportedKernelBitness: return "dump.recognize.kernel32_unsupported";
    case RecognitionReason::UnsupportedArchitecture: return "dump.recognize.arch_unsupported";
    case RecognitionReason::UnsupportedDumpType: return "dump.recognize.dumptype_unsupported";
    }
    return "dump.recognize.unknown_signature";
}

CollectionStatus RecognitionStatus(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::Recognized:
        return CollectionStatus::Success;
    case RecognitionReason::TruncatedHeader:
        // 签名读到了、格式后半段没读到 —— 这是部分采集，不是"格式不支持"。
        return CollectionStatus::Partial;
    case RecognitionReason::UnsupportedKernelBitness:
    case RecognitionReason::UnsupportedArchitecture:
    case RecognitionReason::UnsupportedDumpType:
        return CollectionStatus::Unsupported;
    case RecognitionReason::EmptyFile:
    case RecognitionReason::TooSmallForSignature:
    case RecognitionReason::UnknownSignature:
        return CollectionStatus::Error;
    }
    return CollectionStatus::Error;
}

void FinishRecognition(DumpRecognition& recognition, RecognitionReason reason) {
    recognition.reason = reason;
    const CollectionStatus status = RecognitionStatus(reason);
    if (status == CollectionStatus::Success) {
        recognition.outcome = CollectionOutcome::success();
        recognition.outcome.message = RecognitionMessageKey(reason);
        return;
    }
    recognition.outcome = CollectionOutcome::failure(status,
                                                     kRecognitionDomain,
                                                     static_cast<std::uint64_t>(reason),
                                                     RecognitionMessageKey(reason));
}

} // namespace

// 刻意不是 noexcept：FinishRecognition 在每条失败路径上都要构造一个带 22 字节
// domain 字符串的 CollectionOutcome，必然堆分配（MSVC 的 SSO 上限是 15 字节）。
// 详见 DumpFacts.h 里这个函数的声明处。
DumpRecognition RecognizeDump(std::span<const std::uint8_t> headBytes,
                              const OptionalU64& totalFileSize) {
    DumpRecognition recognition;
    recognition.bytesProvided = OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));
    recognition.fileSize = totalFileSize.present
                               ? totalFileSize
                               : OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));

    const std::uint64_t declaredSize = recognition.fileSize.value;

    if (declaredSize == 0U) {
        FinishRecognition(recognition, RecognitionReason::EmptyFile);
        return recognition;
    }

    std::uint32_t signature = 0;
    std::uint32_t validDump = 0;
    if (declaredSize < kSignatureBytes || headBytes.size() < kSignatureBytes ||
        !ReadLittleEndianU32(headBytes, 0U, signature) ||
        !ReadLittleEndianU32(headBytes, 4U, validDump)) {
        // 文件本身太短，或调用方给的窗口太短。两者的区别由 bytesProvided 与
        // fileSize 两个字段暴露，不塞进同一个 reason 里含糊过去。
        FinishRecognition(recognition, RecognitionReason::TooSmallForSignature);
        return recognition;
    }

    recognition.rawSignature = OptionalU64::of(signature);
    recognition.rawValidDump = OptionalU64::of(validDump);

    // 用户态 minidump 的判据只有一条：签名是 'MDMP'。红线 —— 一旦命中，
    // 后面所有内核分支都不再考虑，绝不可能被识别成内核 dump。
    if (signature == kSignatureMdmp) {
        recognition.family = SignatureFamily::Mdmp;
        recognition.headerBytesRequired =
            OptionalU64::of(static_cast<std::uint64_t>(kMinidumpHeaderBytes));
        if (declaredSize < kMinidumpHeaderBytes || headBytes.size() < kMinidumpHeaderBytes) {
            recognition.kind = DumpKind::Unsupported;
            FinishRecognition(recognition, RecognitionReason::TruncatedHeader);
            return recognition;
        }
        recognition.parseAttempted = true;
        recognition.kind = DumpKind::UserMinidump;
        // 用户态 minidump 的目标架构在 SystemInfoStream 里，不在头里。
        // 本函数只看头，因此架构是 Unknown —— 不猜，也不按扩展名补。
        recognition.architecture = TargetArchitecture::Unknown;
        FinishRecognition(recognition, RecognitionReason::Recognized);
        return recognition;
    }

    if (signature != kSignaturePage) {
        FinishRecognition(recognition, RecognitionReason::UnknownSignature);
        return recognition;
    }

    if (validDump == kValidDump32) {
        recognition.family = SignatureFamily::KernelPage32;
        recognition.headerBytesRequired =
            OptionalU64::of(static_cast<std::uint64_t>(kKernelHeader32Bytes));
        recognition.kind = DumpKind::Unsupported;
        // 本轮只支持 x64 内核转储。明确拒绝，不去按 64 位布局硬读 32 位文件。
        FinishRecognition(recognition, RecognitionReason::UnsupportedKernelBitness);
        return recognition;
    }

    if (validDump != kValidDump64) {
        FinishRecognition(recognition, RecognitionReason::UnknownSignature);
        return recognition;
    }

    recognition.family = SignatureFamily::KernelPage64;
    recognition.headerBytesRequired =
        OptionalU64::of(static_cast<std::uint64_t>(kKernelHeader64Bytes));

    // 头被截断时仍尽量把机器类型读出来（它在 0x30，远早于 0x2000），
    // 这样 UI 至少能说"是一份被截断的 x64 内核转储"，但 kind 不收敛。
    std::uint32_t machineType = 0;
    if (ReadLittleEndianU32(headBytes, kOffMachineImageType, machineType)) {
        recognition.parseAttempted = true;
        recognition.rawMachineType = OptionalU64::of(machineType);
        recognition.architecture = ArchitectureFromMachineType(machineType);
    }

    if (declaredSize < kKernelHeader64Bytes || headBytes.size() < kKernelHeader64Bytes) {
        recognition.kind = DumpKind::Unsupported;
        FinishRecognition(recognition, RecognitionReason::TruncatedHeader);
        return recognition;
    }

    if (recognition.architecture != TargetArchitecture::X64) {
        recognition.kind = DumpKind::Unsupported;
        FinishRecognition(recognition, RecognitionReason::UnsupportedArchitecture);
        return recognition;
    }

    std::uint32_t dumpType = 0;
    if (!ReadLittleEndianU32(headBytes, kOffDumpType, dumpType)) {
        recognition.kind = DumpKind::Unsupported;
        FinishRecognition(recognition, RecognitionReason::TruncatedHeader);
        return recognition;
    }
    recognition.rawDumpType = OptionalU64::of(dumpType);
    recognition.parseAttempted = true;

    switch (dumpType) {
    case 3U:  // 仅转储头
    case 4U:  // triage / 小型内存转储
        // 两者都不保证包含 IRP/锁/进程/pool，C-07 的上界一致，因此同归 KernelSmall；
        // 原始 DumpType 在 rawDumpType 里无损保留，报告要区分时看那一格。
        recognition.kind = DumpKind::KernelSmall;
        break;
    case 1U:  // 完整内存
    case 2U:  // 内核内存
    case 5U:  // 活动内存（bitmap full）
    case 6U:  // 活动内核内存（bitmap kernel）
    case 7U:  // 自动内存
        recognition.kind = DumpKind::KernelMemory;
        break;
    default:
        recognition.kind = DumpKind::Unsupported;
        FinishRecognition(recognition, RecognitionReason::UnsupportedDumpType);
        return recognition;
    }

    FinishRecognition(recognition, RecognitionReason::Recognized);
    return recognition;
}

bool RecognitionIsDamagedRatherThanUnsupported(const DumpRecognition& recognition) noexcept {
    switch (recognition.reason) {
    case RecognitionReason::EmptyFile:
    case RecognitionReason::TooSmallForSignature:
    case RecognitionReason::TruncatedHeader:
        return true;
    case RecognitionReason::Recognized:
    case RecognitionReason::UnknownSignature:
    case RecognitionReason::UnsupportedKernelBitness:
    case RecognitionReason::UnsupportedArchitecture:
    case RecognitionReason::UnsupportedDumpType:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// C-03 崩溃事实
// ---------------------------------------------------------------------------
const char* DumpFieldAvailabilityName(DumpFieldAvailability availability) noexcept {
    switch (availability) {
    case DumpFieldAvailability::NotParsed: return "NotParsed";
    case DumpFieldAvailability::NotRecorded: return "NotRecorded";
    case DumpFieldAvailability::Present: return "Present";
    }
    return "NotParsed";
}

DumpField DumpField::present(std::uint64_t v) noexcept {
    DumpField field;
    field.availability = DumpFieldAvailability::Present;
    field.value = OptionalU64::of(v);
    return field;
}

DumpField DumpField::notRecorded() noexcept {
    DumpField field;
    field.availability = DumpFieldAvailability::NotRecorded;
    return field;
}

DumpField DumpField::notParsed() noexcept {
    return DumpField{};
}

bool DumpField::consistent() const noexcept {
    return (availability == DumpFieldAvailability::Present) == value.present;
}

namespace {

// zeroIsUnrecorded 逐字段显式给定，不设默认值 —— "0 到底算不算真值"是每个字段
// 自己的语义，统一处理必然错一半。
DumpField ClassifyU32Field(std::span<const std::uint8_t> bytes,
                           std::size_t offset,
                           bool zeroIsUnrecorded) {
    std::uint32_t raw = 0;
    if (!ReadLittleEndianU32(bytes, offset, raw)) {
        return DumpField::notParsed();
    }
    if (raw == kPageFillDword) {
        return DumpField::notRecorded();
    }
    if (zeroIsUnrecorded && raw == 0U) {
        return DumpField::notRecorded();
    }
    return DumpField::present(raw);
}

DumpField ClassifyU64Field(std::span<const std::uint8_t> bytes,
                           std::size_t offset,
                           bool zeroIsUnrecorded) {
    std::uint64_t raw = 0;
    if (!ReadLittleEndianU64(bytes, offset, raw)) {
        return DumpField::notParsed();
    }
    if (raw == kPageFillQword) {
        return DumpField::notRecorded();
    }
    if (zeroIsUnrecorded && raw == 0U) {
        return DumpField::notRecorded();
    }
    return DumpField::present(raw);
}

// 所有字段的统一遍历点。新增字段必须同时加到这里，否则计数会静默漏项。
std::array<const DumpField*, 12> AllFields(const BugCheckFacts& facts) noexcept {
    return {&facts.code,
            &facts.parameters[0],
            &facts.parameters[1],
            &facts.parameters[2],
            &facts.parameters[3],
            &facts.targetOsMajor,
            &facts.targetOsBuild,
            &facts.processorCount,
            &facts.crashTimeUtc100ns,
            &facts.uptime100ns,
            &facts.writerStatus,
            &facts.directoryTableBase};
}

std::size_t CountFields(const BugCheckFacts& facts, DumpFieldAvailability wanted) noexcept {
    std::size_t count = 0;
    for (const DumpField* field : AllFields(facts)) {
        if (field->availability == wanted) {
            ++count;
        }
    }
    return count;
}

void SetAllFields(BugCheckFacts& facts, const DumpField& value) {
    facts.code = value;
    for (DumpField& parameter : facts.parameters) {
        parameter = value;
    }
    facts.targetOsMajor = value;
    facts.targetOsBuild = value;
    facts.processorCount = value;
    facts.crashTimeUtc100ns = value;
    facts.uptime100ns = value;
    facts.writerStatus = value;
    facts.directoryTableBase = value;
}

} // namespace

std::size_t BugCheckFacts::fieldCount() const noexcept { return AllFields(*this).size(); }

std::size_t BugCheckFacts::presentFieldCount() const noexcept {
    return CountFields(*this, DumpFieldAvailability::Present);
}

std::size_t BugCheckFacts::notRecordedFieldCount() const noexcept {
    return CountFields(*this, DumpFieldAvailability::NotRecorded);
}

std::size_t BugCheckFacts::notParsedFieldCount() const noexcept {
    return CountFields(*this, DumpFieldAvailability::NotParsed);
}

bool BugCheckFacts::hasAnyFact() const noexcept { return presentFieldCount() > 0U; }

BugCheckFacts ExtractBugCheckFacts(const DumpRecognition& recognition,
                                   std::span<const std::uint8_t> headBytes) {
    BugCheckFacts facts;
    facts.dumpKind = recognition.kind;
    facts.bytesProvided = OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));
    facts.fileSizeDeclared = recognition.fileSize;
    facts.windowShorterThanFile =
        recognition.fileSize.present &&
        static_cast<std::uint64_t>(headBytes.size()) < recognition.fileSize.value;

    switch (recognition.kind) {
    case DumpKind::NotADump:
        // 根本没跑解析。全部 NotParsed —— "不知道有没有"，不是"没有"。
        SetAllFields(facts, DumpField::notParsed());
        facts.outcome = CollectionOutcome::notCollected();
        facts.outcome.message = "dump.facts.not_a_dump";
        return facts;
    case DumpKind::Unsupported:
        SetAllFields(facts, DumpField::notParsed());
        facts.outcome = CollectionOutcome::failure(CollectionStatus::Unsupported,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.unsupported_format");
        return facts;
    case DumpKind::UserMinidump:
        // 用户态 minidump 的格式里就不存在 bugcheck 字段。这是 NotRecorded
        // （知道没有），与 NotParsed（不知道有没有）是两件事。
        SetAllFields(facts, DumpField::notRecorded());
        facts.outcome = CollectionOutcome::failure(CollectionStatus::Unsupported,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.user_minidump_has_no_bugcheck");
        return facts;
    case DumpKind::KernelSmall:
    case DumpKind::KernelMemory:
        break;
    }

    // 停止码 0 在 Windows 里不存在；读到 0 说明这一格没被写入器填过。按缺失处理，
    // 而不是报一个假的 0x0 —— 这正是 C-03 点名的陷阱的反面。
    facts.code = ClassifyU32Field(headBytes, kOffBugCheckCode, true);
    // 停止码参数 0 是完全合法的取值（很多停止码只用前一两个参数），
    // 因此这里 zeroIsUnrecorded=false：真的是 0 就报 Present(0)。
    for (std::size_t index = 0; index < facts.parameters.size(); ++index) {
        facts.parameters[index] =
            ClassifyU64Field(headBytes, kOffBugCheckParameters + index * 8U, false);
    }
    facts.targetOsMajor = ClassifyU32Field(headBytes, kOffMajorVersion, true);
    facts.targetOsBuild = ClassifyU32Field(headBytes, kOffMinorVersion, true);
    facts.processorCount = ClassifyU32Field(headBytes, kOffNumberProcessors, true);
    // FILETIME 0 是 1601 年，不是真实崩溃时间；uptime 0 同理说明没填。
    facts.crashTimeUtc100ns = ClassifyU64Field(headBytes, kOffSystemTime, true);
    facts.uptime100ns = ClassifyU64Field(headBytes, kOffSystemUpTime, true);
    // 写入器状态 0 表示"写入正常"，是有意义的取值，绝不能当缺失。
    facts.writerStatus = ClassifyU32Field(headBytes, kOffWriterStatus, false);
    facts.directoryTableBase = ClassifyU64Field(headBytes, kOffDirectoryTableBase, true);

    const std::size_t notParsed = facts.notParsedFieldCount();
    if (facts.presentFieldCount() == 0U && notParsed == facts.fieldCount()) {
        facts.outcome = CollectionOutcome::failure(CollectionStatus::Error,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.nothing_readable");
    } else if (notParsed > 0U) {
        facts.outcome = CollectionOutcome::failure(CollectionStatus::Partial,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.window_or_file_truncated");
    } else {
        facts.outcome = CollectionOutcome::success();
        facts.outcome.message = "dump.facts.ok";
    }
    return facts;
}

// ---------------------------------------------------------------------------
// C-04 符号精确匹配
// ---------------------------------------------------------------------------
const char* SymbolMatchName(SymbolMatch match) noexcept {
    switch (match) {
    case SymbolMatch::NotAttempted: return "NotAttempted";
    case SymbolMatch::Absent: return "Absent";
    case SymbolMatch::WrongVersion: return "WrongVersion";
    case SymbolMatch::Matched: return "Matched";
    }
    return "NotAttempted";
}

const char* SymbolCacheSourceName(SymbolCacheSource source) noexcept {
    switch (source) {
    case SymbolCacheSource::Unknown: return "Unknown";
    case SymbolCacheSource::NotLoaded: return "NotLoaded";
    case SymbolCacheSource::LocalDirectory: return "LocalDirectory";
    case SymbolCacheSource::LocalCache: return "LocalCache";
    case SymbolCacheSource::SymbolServer: return "SymbolServer";
    case SymbolCacheSource::DumpEmbedded: return "DumpEmbedded";
    }
    return "Unknown";
}

const char* SymbolLoadAttemptName(SymbolLoadAttempt attempt) noexcept {
    switch (attempt) {
    case SymbolLoadAttempt::NotAttempted: return "NotAttempted";
    case SymbolLoadAttempt::FileNotFound: return "FileNotFound";
    case SymbolLoadAttempt::LoadFailed: return "LoadFailed";
    case SymbolLoadAttempt::FileLoaded: return "FileLoaded";
    }
    return "NotAttempted";
}

bool SamePdbIdentity(const PdbIdentity& a, const PdbIdentity& b) noexcept {
    // 任一侧没有标识就无从证明相同。两个空标识不算"相同"——
    // 那是"默认即安全"的写法，会让没有 CodeView 记录的模块白拿到函数名。
    if (!a.present || !b.present) {
        return false;
    }
    return a.age == b.age && a.guid == b.guid;
}

SymbolMatch DeriveSymbolMatch(SymbolLoadAttempt attempt,
                              const PdbIdentity& wanted,
                              const PdbIdentity& loaded) noexcept {
    switch (attempt) {
    case SymbolLoadAttempt::NotAttempted:
        return SymbolMatch::NotAttempted;
    case SymbolLoadAttempt::FileNotFound:
    case SymbolLoadAttempt::LoadFailed:
        // 两者都落到 Absent（SymbolMatch 只有规范给的四个值），但区别由
        // ModuleSymbolState::attempt 与 outcome 保留，报告可以分开说。
        return SymbolMatch::Absent;
    case SymbolLoadAttempt::FileLoaded:
        break;
    }
    if (SamePdbIdentity(wanted, loaded)) {
        return SymbolMatch::Matched;
    }
    // 装进来了但版本对不上，或者根本无从证明版本一致（任一侧没有 GUID/Age）。
    // 两种情况对"能不能给函数名/行号"的答案完全一样：不能。
    return SymbolMatch::WrongVersion;
}

bool MayReportFunctionName(const ModuleSymbolState& state) noexcept {
    return state.match == SymbolMatch::Matched;
}

bool MayReportSourceLine(const ModuleSymbolState& state) noexcept {
    return state.match == SymbolMatch::Matched;
}

const char* SymbolAttributionName(SymbolAttribution attribution) noexcept {
    switch (attribution) {
    case SymbolAttribution::ModuleOnly: return "ModuleOnly";
    case SymbolAttribution::ModulePlusOffset: return "ModulePlusOffset";
    case SymbolAttribution::FunctionPlusOffset: return "FunctionPlusOffset";
    case SymbolAttribution::FunctionAndSourceLine: return "FunctionAndSourceLine";
    }
    return "ModuleOnly";
}

SymbolAttribution AllowedAttribution(const ModuleSymbolState& state,
                                     bool moduleBaseKnown) noexcept {
    if (state.match == SymbolMatch::Matched) {
        return SymbolAttribution::FunctionAndSourceLine;
    }
    // 错版 / 无符号 / 没试过：最多"模块+偏移"。没有基址连偏移都算不出来。
    return moduleBaseKnown ? SymbolAttribution::ModulePlusOffset : SymbolAttribution::ModuleOnly;
}

const char* SymbolServerDecisionName(SymbolServerDecision decision) noexcept {
    switch (decision) {
    case SymbolServerDecision::Allow: return "Allow";
    case SymbolServerDecision::RejectNotEnabled: return "RejectNotEnabled";
    case SymbolServerDecision::RejectNotCancellable: return "RejectNotCancellable";
    case SymbolServerDecision::RejectNoTimeBudget: return "RejectNoTimeBudget";
    }
    return "RejectNotEnabled";
}

SymbolServerDecision DecideSymbolServerFetch(const SymbolServerPolicy& policy) noexcept {
    if (!policy.userEnabled) {
        return SymbolServerDecision::RejectNotEnabled;
    }
    if (!policy.cancellable) {
        return SymbolServerDecision::RejectNotCancellable;
    }
    // "有限时"必须是真的时间预算：只给字节/页数上限不算 —— 一个卡在
    // connect() 上的符号服务器不会消耗任何字节。
    if (!policy.budget.maxDurationNanos.present || policy.budget.maxDurationNanos.value == 0U) {
        return SymbolServerDecision::RejectNoTimeBudget;
    }
    return SymbolServerDecision::Allow;
}

// ---------------------------------------------------------------------------
// C-05 栈与模块
// ---------------------------------------------------------------------------
const char* UnwindStateName(UnwindState state) noexcept {
    switch (state) {
    case UnwindState::TruncatedNoData: return "TruncatedNoData";
    case UnwindState::TruncatedCorrupt: return "TruncatedCorrupt";
    case UnwindState::Guessed: return "Guessed";
    case UnwindState::Unwound: return "Unwound";
    }
    return "TruncatedNoData";
}

bool UnwindStateIsTerminal(UnwindState state) noexcept {
    return state == UnwindState::TruncatedNoData || state == UnwindState::TruncatedCorrupt;
}

bool UnwindStateIsTrustworthy(UnwindState state) noexcept {
    return state == UnwindState::Unwound;
}

std::size_t StackTrace::unwoundCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (frame.unwindState == UnwindState::Unwound) {
            ++count;
        }
    }
    return count;
}

std::size_t StackTrace::guessedCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (frame.unwindState == UnwindState::Guessed) {
            ++count;
        }
    }
    return count;
}

std::size_t StackTrace::truncatedCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (UnwindStateIsTerminal(frame.unwindState)) {
            ++count;
        }
    }
    return count;
}

const char* StackValidationName(StackValidation validation) noexcept {
    switch (validation) {
    case StackValidation::Ok: return "Ok";
    case StackValidation::FramesAfterTruncation: return "FramesAfterTruncation";
    case StackValidation::FunctionNameWithoutMatchedSymbols:
        return "FunctionNameWithoutMatchedSymbols";
    case StackValidation::SourceLineWithoutMatchedSymbols:
        return "SourceLineWithoutMatchedSymbols";
    case StackValidation::CandidatesWithoutMatchedSymbols:
        return "CandidatesWithoutMatchedSymbols";
    case StackValidation::AmbiguityCollapsed: return "AmbiguityCollapsed";
    case StackValidation::IncompleteArgumentsClaimedComplete:
        return "IncompleteArgumentsClaimedComplete";
    }
    return "Ok";
}

StackValidation ValidateStackTrace(const StackTrace& trace) noexcept {
    bool truncationSeen = false;
    for (const StackFrame& frame : trace.frames) {
        // 边界先判：截断帧之后再出现任何一帧，就是把猜测帧拼到了展开结果后面。
        if (truncationSeen) {
            return StackValidation::FramesAfterTruncation;
        }
        // 函数内偏移与函数名同罪：没解析出函数就没有"函数内偏移"这回事。
        if ((!frame.functionName.empty() || frame.functionOffset.present) &&
            frame.symbolMatch != SymbolMatch::Matched) {
            return StackValidation::FunctionNameWithoutMatchedSymbols;
        }
        if ((!frame.sourceFile.empty() || frame.sourceLine.present) &&
            frame.symbolMatch != SymbolMatch::Matched) {
            return StackValidation::SourceLineWithoutMatchedSymbols;
        }
        // 候选函数名同样会被渲染到 UI，只是从单数变复数。错版 PDB 解出来的名字
        // 挂上"候选"两个字不会因此变成可用信息 —— C-04 的红线对复数一样有效。
        if (!frame.candidateFunctions.empty() && frame.symbolMatch != SymbolMatch::Matched) {
            return StackValidation::CandidatesWithoutMatchedSymbols;
        }
        if (frame.attributionAmbiguous && frame.candidateFunctions.size() < 2U) {
            // 标了歧义却只留一个候选 = 把歧义抹平成了确定答案。
            return StackValidation::AmbiguityCollapsed;
        }
        if (frame.argsComplete) {
            for (const OptionalU64& argument : frame.availableArgs) {
                if (!argument.present) {
                    return StackValidation::IncompleteArgumentsClaimedComplete;
                }
            }
        }
        if (UnwindStateIsTerminal(frame.unwindState)) {
            truncationSeen = true;
        }
    }
    return StackValidation::Ok;
}

// ---------------------------------------------------------------------------
// C-06 可疑模块解释
// ---------------------------------------------------------------------------
const char* ModuleEvidenceKindName(ModuleEvidenceKind kind) noexcept {
    switch (kind) {
    case ModuleEvidenceKind::OnStack: return "OnStack";
    case ModuleEvidenceKind::FaultingIpModule: return "FaultingIpModule";
    case ModuleEvidenceKind::VerifierReported: return "VerifierReported";
    }
    return "OnStack";
}

std::size_t ModuleEvidenceGroup::evidenceCount() const noexcept {
    return onStack.size() + faultingIp.size() + verifier.size();
}

bool IsWellKnownSystemModuleName(std::string_view moduleName) noexcept {
    // 名单写死在实现里，不从转储读。命中只降低"线索"资格，不是判决。
    static constexpr std::string_view kNames[] = {
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe",
        "hal.dll",      "halmacpi.dll", "halacpi.dll",  "ntdll.dll",
        "win32k.sys",   "win32kbase.sys", "win32kfull.sys", "ci.dll",
        "kernel32.dll", "kernelbase.dll",
    };
    const std::string_view base = BaseNameOf(moduleName);
    for (const std::string_view candidate : kNames) {
        if (AsciiEqualsIgnoreCase(base, candidate)) {
            return true;
        }
    }
    return false;
}

const char* InvestigationLeadName(InvestigationLead lead) noexcept {
    switch (lead) {
    case InvestigationLead::Undetermined: return "Undetermined";
    case InvestigationLead::SystemModuleOnly: return "SystemModuleOnly";
    case InvestigationLead::StackPresenceOnly: return "StackPresenceOnly";
    case InvestigationLead::FaultingIpAttributed: return "FaultingIpAttributed";
    case InvestigationLead::VerifierNamed: return "VerifierNamed";
    }
    return "Undetermined";
}

namespace {

// 故障 IP 证据的前提。正常情况下故障 IP 来自 trap frame / context record，
// 那时 ipFromContextRecord 为真，与展开质量无关；反过来，如果这条证据是从某个
// 展开帧上读出来的，那一帧必须真的被展开过（Unwound）。
// 帧已经被判成 TruncatedCorrupt（数据自相矛盾）却仍据此点名一个第三方驱动，
// 是拿自己都不信的数据下结论 —— C-06 要求这种情况写"无法确定"。
bool FaultingIpEvidenceIsFounded(const ModuleEvidenceItem& item) noexcept {
    return item.ipFromContextRecord || UnwindStateIsTrustworthy(item.frameUnwindState);
}

} // namespace

InvestigationLead ClassifyLead(const ModuleEvidenceGroup& group) noexcept {
    // 连分组键都没有 = 这一组没有身份。GroupModuleEvidence 对一个空模块名就会产出
    // 这样一组，而"某个连名字都没有的模块是可查线索"是没有意义的一句话。
    if (group.moduleKey.empty()) {
        return InvestigationLead::Undetermined;
    }
    // Verifier 是唯一"由系统自己点名"的证据，强度与前两类不同，先判。
    if (!group.verifier.empty()) {
        return InvestigationLead::VerifierNamed;
    }
    if (!group.faultingIp.empty()) {
        // 故障 IP 落在 ntoskrnl/hal 里是延迟内存损坏的常态，不是根因。
        if (group.isWellKnownSystemModule) {
            return InvestigationLead::SystemModuleOnly;
        }
        for (const ModuleEvidenceItem& item : group.faultingIp) {
            if (FaultingIpEvidenceIsFounded(item)) {
                return InvestigationLead::FaultingIpAttributed;
            }
        }
        // 故障 IP 证据自己站不住脚：不升级，但也不丢掉这一组 —— 继续按栈上证据判，
        // 该是弱线索就是弱线索，该是无法确定就是无法确定。
    }
    if (!group.onStack.empty()) {
        if (group.isWellKnownSystemModule) {
            return InvestigationLead::SystemModuleOnly;
        }
        // 只出现在栈扫描猜测帧里的模块不构成线索：Guessed 不是展开结果，
        // 栈上的残留返回地址可能来自很久以前的调用。
        for (const ModuleEvidenceItem& item : group.onStack) {
            if (UnwindStateIsTrustworthy(item.frameUnwindState)) {
                return InvestigationLead::StackPresenceOnly;
            }
        }
        return InvestigationLead::Undetermined;
    }
    return InvestigationLead::Undetermined;
}

std::vector<ModuleEvidenceGroup> GroupModuleEvidence(std::vector<ModuleEvidenceItem> items) {
    // O(n log n)：先算一次键，再按键排序下标，最后一趟合并。
    // 不做两两比较 —— 上一轮实测在别的模块抓到过 O(n^2) 的 13/15 秒。
    std::vector<std::pair<std::string, std::size_t>> keyed;
    keyed.reserve(items.size());
    for (std::size_t index = 0; index < items.size(); ++index) {
        keyed.emplace_back(AsciiLower(items[index].moduleName), index);
    }
    std::stable_sort(keyed.begin(), keyed.end(),
                     [](const std::pair<std::string, std::size_t>& a,
                        const std::pair<std::string, std::size_t>& b) {
                         return a.first < b.first;
                     });

    std::vector<ModuleEvidenceGroup> groups;
    for (std::size_t position = 0; position < keyed.size(); ++position) {
        const std::string& key = keyed[position].first;
        if (groups.empty() || groups.back().moduleKey != key) {
            ModuleEvidenceGroup group;
            group.moduleKey = key;
            // 展示名用首次出现时的原始写法，不做任何归一化。
            group.moduleName = items[keyed[position].second].moduleName;
            group.isWellKnownSystemModule = IsWellKnownSystemModuleName(group.moduleName);
            groups.push_back(std::move(group));
        }
        ModuleEvidenceItem& item = items[keyed[position].second];
        ModuleEvidenceGroup& target = groups.back();
        switch (item.kind) {
        case ModuleEvidenceKind::OnStack:
            target.onStack.push_back(std::move(item));
            break;
        case ModuleEvidenceKind::FaultingIpModule:
            target.faultingIp.push_back(std::move(item));
            break;
        case ModuleEvidenceKind::VerifierReported:
            target.verifier.push_back(std::move(item));
            break;
        }
    }
    return groups;
}

SuspectReport BuildSuspectReport(std::vector<ModuleEvidenceGroup> groups,
                                 const CollectionOutcome& stackOutcome) {
    SuspectReport report;
    report.leads.reserve(groups.size());

    // 没有观测就没有结论。此时即使调用方塞了 group 进来，也一律降为 Undetermined ——
    // "从没采到推出结论"是明确的红线。
    const bool haveObservation = StatusCarriesObservation(stackOutcome.status);
    for (ModuleEvidenceGroup& group : groups) {
        SuspectLead lead;
        lead.lead = haveObservation ? ClassifyLead(group) : InvestigationLead::Undetermined;
        lead.group = std::move(group);
        report.leads.push_back(std::move(lead));
    }

    if (!haveObservation) {
        report.conclusion = AnalysisConclusion::NoEvidence;
        report.limitationKeys.emplace_back("dump.suspect.no_stack_observation");
        return report;
    }

    bool anyActionable = false;
    bool anySystemOnly = false;
    bool anyStackOnly = false;
    for (const SuspectLead& lead : report.leads) {
        switch (lead.lead) {
        case InvestigationLead::VerifierNamed:
        case InvestigationLead::FaultingIpAttributed:
            anyActionable = true;
            break;
        case InvestigationLead::SystemModuleOnly:
            anySystemOnly = true;
            break;
        case InvestigationLead::StackPresenceOnly:
            anyStackOnly = true;
            break;
        case InvestigationLead::Undetermined:
            break;
        }
    }

    // 本函数永不返回 NoDifferenceObserved：一份转储的前提就是确实崩了，
    // "未发现差异"在这里没有意义，写出来只会被读成"这台机器没事"。
    report.conclusion = anyActionable ? AnalysisConclusion::DifferenceObserved
                                      : AnalysisConclusion::Indeterminate;

    if (report.leads.empty()) {
        report.limitationKeys.emplace_back("dump.suspect.no_module_evidence");
    }
    if (!anyActionable) {
        report.limitationKeys.emplace_back("dump.suspect.insufficient_evidence");
    }
    if (anySystemOnly) {
        report.limitationKeys.emplace_back("dump.suspect.system_module_only");
    }
    if (anyStackOnly) {
        report.limitationKeys.emplace_back("dump.suspect.stack_presence_only");
    }
    if (stackOutcome.status == CollectionStatus::Partial) {
        report.limitationKeys.emplace_back("dump.suspect.stack_partial");
    }
    return report;
}

// ---------------------------------------------------------------------------
// C-07 缺失内存的边界
// ---------------------------------------------------------------------------
const char* ContentCategoryName(ContentCategory category) noexcept {
    switch (category) {
    case ContentCategory::IrpObjects: return "IrpObjects";
    case ContentCategory::LockObjects: return "LockObjects";
    case ContentCategory::FullProcessSpace: return "FullProcessSpace";
    case ContentCategory::PoolMemory: return "PoolMemory";
    case ContentCategory::KernelModuleList: return "KernelModuleList";
    case ContentCategory::ThreadStacks: return "ThreadStacks";
    case ContentCategory::PhysicalMemory: return "PhysicalMemory";
    }
    return "IrpObjects";
}

const char* ContentPresenceName(ContentPresence presence) noexcept {
    switch (presence) {
    case ContentPresence::Unknown: return "Unknown";
    case ContentPresence::NotIncluded: return "NotIncluded";
    case ContentPresence::NotParsable: return "NotParsable";
    case ContentPresence::Included: return "Included";
    }
    return "Unknown";
}

ContentPresence DumpContentAvailability::presenceOf(ContentCategory category) const noexcept {
    const auto index = static_cast<std::size_t>(category);
    if (index >= presence.size()) {
        return ContentPresence::Unknown;
    }
    return presence[index];
}

void DumpContentAvailability::set(ContentCategory category, ContentPresence value) noexcept {
    const auto index = static_cast<std::size_t>(category);
    if (index < presence.size()) {
        presence[index] = value;
    }
}

DumpContentAvailability DeriveAvailabilityFromKind(DumpKind kind) noexcept {
    DumpContentAvailability availability;  // 全 Unknown 起步
    switch (kind) {
    case DumpKind::KernelSmall:
        // small dump 格式上就不含这四类，可以确定地说"转储未包含"。
        availability.set(ContentCategory::IrpObjects, ContentPresence::NotIncluded);
        availability.set(ContentCategory::LockObjects, ContentPresence::NotIncluded);
        availability.set(ContentCategory::FullProcessSpace, ContentPresence::NotIncluded);
        availability.set(ContentCategory::PoolMemory, ContentPresence::NotIncluded);
        availability.set(ContentCategory::PhysicalMemory, ContentPresence::NotIncluded);
        // 模块表与崩溃线程栈"可能"在 triage 块里，但 DumpType=3（仅头）就没有。
        // 由类型推不出来，因此留 Unknown，要靠实际解析确认 —— 绝不预先写 Included。
        break;
    case DumpKind::KernelMemory:
        // 完整/内核/活动内存转储之间差别很大（DumpType 1/2/5/6/7 已被合并到本类），
        // 单靠 kind 推不出任何一项"确定包含"。全 Unknown 是唯一诚实的答案。
        break;
    case DumpKind::UserMinidump:
        // 用户态转储里不存在内核对象。
        availability.set(ContentCategory::IrpObjects, ContentPresence::NotIncluded);
        availability.set(ContentCategory::LockObjects, ContentPresence::NotIncluded);
        availability.set(ContentCategory::PoolMemory, ContentPresence::NotIncluded);
        availability.set(ContentCategory::KernelModuleList, ContentPresence::NotIncluded);
        availability.set(ContentCategory::PhysicalMemory, ContentPresence::NotIncluded);
        // 完整进程空间取决于 MiniDumpWithFullMemory，线程栈取决于写入选项 —— Unknown。
        break;
    case DumpKind::NotADump:
    case DumpKind::Unsupported:
        // 什么都不知道。绝不能因为"没解析出来"就说"不包含"。
        break;
    }
    return availability;
}

const char* ContentQueryResultName(ContentQueryResult result) noexcept {
    switch (result) {
    case ContentQueryResult::Available: return "Available";
    case ContentQueryResult::NotIncludedInDump: return "NotIncludedInDump";
    case ContentQueryResult::NotParsableHere: return "NotParsableHere";
    case ContentQueryResult::UnknownAvailability: return "UnknownAvailability";
    }
    return "UnknownAvailability";
}

ContentQueryResult QueryContent(const DumpContentAvailability& availability,
                               ContentCategory category) noexcept {
    switch (availability.presenceOf(category)) {
    case ContentPresence::Included: return ContentQueryResult::Available;
    case ContentPresence::NotIncluded: return ContentQueryResult::NotIncludedInDump;
    case ContentPresence::NotParsable: return ContentQueryResult::NotParsableHere;
    case ContentPresence::Unknown: return ContentQueryResult::UnknownAvailability;
    }
    return ContentQueryResult::UnknownAvailability;
}

bool SupplementDisclosed(const ExternalSupplement& supplement) noexcept {
    if (!supplement.used) {
        return true;  // 没用外部数据，没什么要声明的
    }
    return !supplement.disclosureKey.empty() && !supplement.source.collectorId.empty() &&
           supplement.source.origin == SourceOrigin::ExternalFile;
}

// ---------------------------------------------------------------------------
// C-08 超时、取消与隔离
// ---------------------------------------------------------------------------
const char* HelperStateName(HelperState state) noexcept {
    switch (state) {
    case HelperState::NotStarted: return "NotStarted";
    case HelperState::Starting: return "Starting";
    case HelperState::Ready: return "Ready";
    case HelperState::Busy: return "Busy";
    case HelperState::Stalled: return "Stalled";
    case HelperState::Disconnected: return "Disconnected";
    case HelperState::Cancelling: return "Cancelling";
    case HelperState::Exited: return "Exited";
    case HelperState::Failed: return "Failed";
    }
    return "NotStarted";
}

bool HelperStateIsTerminal(HelperState state) noexcept {
    return state == HelperState::Exited || state == HelperState::Failed;
}

bool HelperStateSettled(HelperState state) noexcept {
    // 白名单式判定，不写成 "!= 这几个"：以后往 HelperState 里加一个状态时，
    // 默认必须落到"未结算"那一边，而不是白拿一个"已结算"。
    switch (state) {
    case HelperState::Ready:
    case HelperState::Exited:
        return true;
    case HelperState::NotStarted:
    case HelperState::Starting:
    case HelperState::Busy:
    case HelperState::Stalled:
    case HelperState::Disconnected:
    case HelperState::Cancelling:
    case HelperState::Failed:
        return false;
    }
    return false;
}

namespace {

// helper 没结算时，报告要说清楚是哪一种"没结算"。
const char* HelperUnsettledKey(HelperState state) noexcept {
    switch (state) {
    case HelperState::NotStarted: return "dump.helper.not_started";
    case HelperState::Starting:
    case HelperState::Busy: return "dump.helper.still_running";
    case HelperState::Cancelling: return "dump.helper.cancelling";
    case HelperState::Stalled: return "dump.helper.stalled";
    case HelperState::Disconnected: return "dump.helper.disconnected";
    case HelperState::Failed: return "dump.helper.failed";
    case HelperState::Ready:
    case HelperState::Exited: break;
    }
    return "dump.helper.not_settled";
}

} // namespace

const char* TerminateDecisionName(TerminateDecision decision) noexcept {
    switch (decision) {
    case TerminateDecision::Allow: return "Allow";
    case TerminateDecision::RejectNotOwned: return "RejectNotOwned";
    case TerminateDecision::RejectOwnerMismatch: return "RejectOwnerMismatch";
    case TerminateDecision::RejectNoHelperIdentity: return "RejectNoHelperIdentity";
    }
    return "RejectNotOwned";
}

TerminateDecision DecideHelperTermination(const HelperOwnership& helper,
                                          std::string_view requestingModuleId) noexcept {
    // 顺序固定：先看"是不是我起的"，再看 owner 对不对，最后看有没有确切目标。
    if (!helper.startedByThisModule) {
        return TerminateDecision::RejectNotOwned;
    }
    if (helper.ownerModuleId.empty() || requestingModuleId.empty() ||
        helper.ownerModuleId != requestingModuleId) {
        return TerminateDecision::RejectOwnerMismatch;
    }
    if (helper.helperId.empty()) {
        // 连实例 id 都没有就"按 pid 杀" —— pid 会复用，可能打到别人的调试器。
        return TerminateDecision::RejectNoHelperIdentity;
    }
    return TerminateDecision::Allow;
}

InterruptedResult BuildInterruptedResult(BudgetStop stop,
                                         HelperState helperState,
                                         const ScanBudget& budget,
                                         CoverageAccount coverage,
                                         bool haveAnyResult) {
    InterruptedResult result;
    result.stop = stop;
    result.helperState = helperState;
    result.coverage = std::move(coverage);
    ApplyStopToCoverage(stop, budget, result.coverage);
    result.outcome = OutcomeForStop(stop);
    result.partialResultsRetained = haveAnyResult;

    if (stop != BudgetStop::Continue) {
        result.interruptionKeys.emplace_back(std::string("dump.interrupt.") +
                                             BudgetStopName(stop));
    }

    switch (helperState) {
    case HelperState::Stalled:
        result.outcome.status = CollectionStatus::Timeout;
        result.outcome.message = "dump.helper.stalled";
        result.interruptionKeys.emplace_back("dump.helper.stalled");
        break;
    case HelperState::Disconnected:
        result.outcome.status = CollectionStatus::Error;
        result.outcome.message = "dump.helper.disconnected";
        result.interruptionKeys.emplace_back("dump.helper.disconnected");
        break;
    case HelperState::Failed:
        result.outcome.status = CollectionStatus::Error;
        result.outcome.message = "dump.helper.failed";
        result.interruptionKeys.emplace_back("dump.helper.failed");
        break;
    case HelperState::Cancelling:
        // 仍在收尾，不许伪报"已清理"。
        result.interruptionKeys.emplace_back("dump.helper.cancelling");
        break;
    case HelperState::NotStarted:
        // 从来没起来过：这一轮的 0 条结果不是"这里确实什么都没有"，
        // 而是"根本没人去看过"。
        result.interruptionKeys.emplace_back("dump.helper.not_started");
        break;
    case HelperState::Starting:
    case HelperState::Busy:
        // 还在跑：现在手上的结果集合天生不完整。
        result.interruptionKeys.emplace_back("dump.helper.still_running");
        break;
    case HelperState::Ready:
    case HelperState::Exited:
        break;
    }

    if (!haveAnyResult) {
        // 一次"什么都没采到"的中断绝不能报 Partial：StatusCarriesObservation
        // 会放行，下游据此推出正向结论。
        switch (stop) {
        case BudgetStop::Continue:
            // 没被中断且确实一条都没有 —— 这是"正确的空集合"，保持 Success。
            break;
        case BudgetStop::Cancelled:
            if (result.outcome.status == CollectionStatus::Partial) {
                result.outcome.status = CollectionStatus::NotCollected;
                result.outcome.message = "dump.interrupt.cancelled_before_any_result";
            }
            break;
        case BudgetStop::TimeExhausted:
            if (result.outcome.status == CollectionStatus::Partial) {
                result.outcome.status = CollectionStatus::Timeout;
                result.outcome.message = "dump.interrupt.timeout_before_any_result";
            }
            break;
        case BudgetStop::BytesExhausted:
        case BudgetStop::PagesExhausted:
        case BudgetStop::ItemsExhausted:
            if (result.outcome.status == CollectionStatus::Partial) {
                result.outcome.status = CollectionStatus::Error;
                result.outcome.message = "dump.interrupt.budget_before_any_result";
            }
            break;
        }
        if (stop != BudgetStop::Continue) {
            result.interruptionKeys.emplace_back("dump.interrupt.no_partial_results");
        }
    }

    // helperState 是与 stop 无关的第二维。stop==Continue 只说明"预算没用完"，
    // 它对 helper 到底跑没跑一无所知：NotStarted / Starting / Busy / Cancelling
    // 四种状态下报 Success，下游 StatusCarriesObservation 会放行，
    // deriveConclusion 就会给出"未发现差异"—— 从没采到推出正常，C-08 的红线。
    // 这里只降级、不升级：已经落到 Timeout/Error/NotCollected 的更严重结论保持不动。
    if (!HelperStateSettled(helperState)) {
        if (result.outcome.status == CollectionStatus::Success) {
            result.outcome.status = haveAnyResult ? CollectionStatus::Partial
                                                  : CollectionStatus::NotCollected;
            result.outcome.message = HelperUnsettledKey(helperState);
        } else if (result.outcome.status == CollectionStatus::Partial && !haveAnyResult) {
            result.outcome.status = CollectionStatus::NotCollected;
            result.outcome.message = HelperUnsettledKey(helperState);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// C-09 不可信路径与输出
// ---------------------------------------------------------------------------
std::string EscapeForReport(std::string_view untrusted) {
    std::string out;
    out.reserve(untrusted.size() + untrusted.size() / 4U + 8U);
    for (const char raw : untrusted) {
        const auto byte = static_cast<unsigned char>(raw);
        if (IsControlByte(byte)) {
            // 模块名/路径/符号名里出现换行、制表、NUL 本身就是异常输入：
            // 一律换成 U+FFFD 的十进制数字引用（纯 ASCII 输出，不破坏报告结构）。
            out += "&#65533;";
            continue;
        }
        switch (byte) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default:
            // >= 0x80 的字节原样透传，不破坏 UTF-8 序列。
            out.push_back(raw);
            break;
        }
    }
    return out;
}

std::string SanitizeForPlainTextField(std::string_view untrusted) {
    std::string out;
    out.reserve(untrusted.size());
    for (const char raw : untrusted) {
        const auto byte = static_cast<unsigned char>(raw);
        // 纯文本报告按制表分列、按换行分行，因此字段内的控制字符会打乱重核者
        // 看到的结构。这不是注入，但同样会误导，一律换成 '?'。
        out.push_back(IsControlByte(byte) ? '?' : raw);
    }
    return out;
}

namespace {

// 白名单是**完整命令**，不是前缀，也不带任何可拼接的参数位。
constexpr std::string_view kAllowedCommands[] = {
    ".bugcheck",
    "lm",
    "k",
    "vertarget",
    ".time",
};

constexpr std::size_t kMaxCommandBytes = 64U;
constexpr std::size_t kMaxPathBytes = 32767U;

bool IsShellMetacharacter(unsigned char byte) noexcept {
    switch (byte) {
    case ';': case '|': case '&': case '<': case '>': case '$': case '`':
    case '"': case '\'': case '\\': case '(': case ')': case '{': case '}':
    case '[': case ']': case '!': case '*': case '?': case '^': case '%':
        return true;
    default:
        return false;
    }
}

} // namespace

std::span<const std::string_view> AllowedAnalysisCommands() noexcept {
    return std::span<const std::string_view>(kAllowedCommands,
                                             sizeof(kAllowedCommands) / sizeof(kAllowedCommands[0]));
}

bool IsSafeAnalysisCommand(std::string_view command) noexcept {
    for (const std::string_view allowed : kAllowedCommands) {
        if (command == allowed) {
            return true;
        }
    }
    return false;
}

const char* CommandRejectionName(CommandRejection rejection) noexcept {
    switch (rejection) {
    case CommandRejection::Accepted: return "Accepted";
    case CommandRejection::Empty: return "Empty";
    case CommandRejection::TooLong: return "TooLong";
    case CommandRejection::ContainsControlCharacter: return "ContainsControlCharacter";
    case CommandRejection::ContainsShellMetacharacter: return "ContainsShellMetacharacter";
    case CommandRejection::NotInWhitelist: return "NotInWhitelist";
    }
    return "NotInWhitelist";
}

CommandRejection ClassifyCommandRequest(std::string_view request) noexcept {
    if (request.empty()) {
        return CommandRejection::Empty;
    }
    if (request.size() > kMaxCommandBytes) {
        return CommandRejection::TooLong;
    }
    for (const char raw : request) {
        if (IsControlByte(static_cast<unsigned char>(raw))) {
            return CommandRejection::ContainsControlCharacter;
        }
    }
    for (const char raw : request) {
        if (IsShellMetacharacter(static_cast<unsigned char>(raw))) {
            return CommandRejection::ContainsShellMetacharacter;
        }
    }
    if (!IsSafeAnalysisCommand(request)) {
        return CommandRejection::NotInWhitelist;
    }
    return CommandRejection::Accepted;
}

const char* PathRiskName(PathRisk risk) noexcept {
    switch (risk) {
    case PathRisk::Ok: return "Ok";
    case PathRisk::Empty: return "Empty";
    case PathRisk::TooLong: return "TooLong";
    case PathRisk::ControlCharacter: return "ControlCharacter";
    case PathRisk::WildCard: return "WildCard";
    case PathRisk::ParentTraversal: return "ParentTraversal";
    case PathRisk::AlternateDataStream: return "AlternateDataStream";
    case PathRisk::DeviceName: return "DeviceName";
    case PathRisk::TrailingDotOrSpace: return "TrailingDotOrSpace";
    case PathRisk::UncOrRemote: return "UncOrRemote";
    }
    return "Empty";
}

namespace {

bool IsReservedDeviceBase(std::string_view segment) noexcept {
    static constexpr std::string_view kDevices[] = {
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    };
    // 设备名判定只看第一个 '.' 之前的部分："nul.dmp" 一样落在 NUL 设备上。
    const std::size_t dot = segment.find('.');
    const std::string_view base =
        dot == std::string_view::npos ? segment : segment.substr(0, dot);
    for (const std::string_view device : kDevices) {
        if (AsciiEqualsIgnoreCase(base, device)) {
            return true;
        }
    }
    return false;
}

constexpr bool IsPathSeparator(char value) noexcept { return value == '\\' || value == '/'; }

// Win32 的三种 "\\x\" 前缀语义完全不同，不能一把梭：
//   \\.\     DOS 设备命名空间（\\.\PhysicalDrive0、\\.\pipe\x）。不是文件，直接拒。
//            CreateFile 对 //./ 与 \\.\ 一视同仁，因此两种分隔符都认。
//   \\?\     长路径前缀。它是打开超过 MAX_PATH 的转储文件的唯一写法，必须剥掉再判定，
//            否则里面的 '?' 会被通配符扫描误伤。这个前缀只有反斜杠形式有效
//            （它的作用正是关掉路径规范化），"//?/" 不是它 —— 那条路径里的 '?'
//            该被当成通配符就当成通配符，失败方向是安全的。
//   \\?\UNC\ 长路径写法的 UNC，剥掉之后仍然是远程路径。
struct PathPrefixInfo final {
    std::size_t skip = 0;
    bool deviceNamespace = false;
    bool uncFromPrefix = false;
};

PathPrefixInfo ClassifyPathPrefix(std::string_view path) noexcept {
    PathPrefixInfo info;
    if (path.size() >= 4U && IsPathSeparator(path[0]) && IsPathSeparator(path[1]) &&
        path[2] == '.' && IsPathSeparator(path[3])) {
        info.deviceNamespace = true;
        return info;
    }
    if (path.size() >= 4U && path[0] == '\\' && path[1] == '\\' && path[2] == '?' &&
        path[3] == '\\') {
        info.skip = 4U;
        const std::string_view rest = path.substr(4U);
        // \\?\GLOBALROOT\Device\HarddiskVolume1\... 绕回设备命名空间，一样拒。
        if (rest.size() >= 10U && AsciiEqualsIgnoreCase(rest.substr(0U, 10U), "globalroot") &&
            (rest.size() == 10U || IsPathSeparator(rest[10U]))) {
            info.deviceNamespace = true;
            return info;
        }
        if (rest.size() >= 4U && AsciiEqualsIgnoreCase(rest.substr(0U, 3U), "unc") &&
            IsPathSeparator(rest[3U])) {
            info.skip = 8U;
            info.uncFromPrefix = true;
        }
    }
    return info;
}

// Windows 打开文件时会把每一段结尾的 '.' 与 ' ' 剥掉。留着它们，"被判定的字符串"
// 与"真正被打开的文件"就不是同一个 —— 判定本身失去意义。"." 与 ".." 是路径语法的
// 一部分，不算这一类（".." 由上面的 ParentTraversal 单独接住）。
bool SegmentHasTrailingDotOrSpace(std::string_view segment) noexcept {
    if (segment.empty() || segment == "." || segment == "..") {
        return false;
    }
    const char last = segment.back();
    return last == '.' || last == ' ';
}

} // namespace

PathRisk ClassifyDumpPath(std::string_view path) noexcept {
    // 判定顺序固定，报告与测试都依赖它。
    if (path.empty()) {
        return PathRisk::Empty;
    }
    if (path.size() > kMaxPathBytes) {
        return PathRisk::TooLong;
    }
    for (const char raw : path) {
        if (IsControlByte(static_cast<unsigned char>(raw))) {
            return PathRisk::ControlCharacter;
        }
    }

    // 前缀先剥。设备命名空间在这里就被挡下：它既不是远程路径也不是文件，
    // 之前会一路走到最后被当成 UncOrRemote —— UI 问错问题（"这是远程路径，确认？"），
    // 用户确认之后还真把裸盘/命名管道交给了解析器。
    const PathPrefixInfo prefix = ClassifyPathPrefix(path);
    if (prefix.deviceNamespace) {
        return PathRisk::DeviceName;
    }
    const std::string_view body = path.substr(prefix.skip);
    if (body.empty()) {
        // 只有一个前缀、后面什么都没有：没有任何东西可打开。
        return PathRisk::Empty;
    }

    for (const char raw : body) {
        if (raw == '*' || raw == '?') {
            return PathRisk::WildCard;
        }
    }

    // 分段扫描：".." 段、段尾的 '.'/' '、设备名段。分隔符两种都认。
    std::size_t segmentBegin = 0;
    bool sawDeviceSegment = false;
    for (std::size_t index = 0; index <= body.size(); ++index) {
        const bool atEnd = index == body.size();
        if (!atEnd && !IsPathSeparator(body[index])) {
            continue;
        }
        const std::string_view segment = body.substr(segmentBegin, index - segmentBegin);
        if (segment == "..") {
            return PathRisk::ParentTraversal;
        }
        if (SegmentHasTrailingDotOrSpace(segment)) {
            return PathRisk::TrailingDotOrSpace;
        }
        if (!segment.empty() && IsReservedDeviceBase(segment)) {
            sawDeviceSegment = true;
        }
        segmentBegin = index + 1;
    }

    // 冒号：只有 "X:" 形式的驱动器号合法，其余一律当备用数据流。
    for (std::size_t index = 0; index < body.size(); ++index) {
        if (body[index] != ':') {
            continue;
        }
        const bool driveColon =
            index == 1U && IsAsciiAlpha(static_cast<unsigned char>(body[0]));
        if (!driveColon) {
            return PathRisk::AlternateDataStream;
        }
    }

    if (sawDeviceSegment) {
        return PathRisk::DeviceName;
    }

    const bool unc = prefix.uncFromPrefix ||
                     (body.size() >= 2U && ((body[0] == '\\' && body[1] == '\\') ||
                                            (body[0] == '/' && body[1] == '/')));
    if (unc) {
        return PathRisk::UncOrRemote;
    }
    return PathRisk::Ok;
}

bool PathAcceptableForOpen(PathRisk risk) noexcept {
    return risk == PathRisk::Ok || risk == PathRisk::UncOrRemote;
}

bool PathNeedsExplicitConfirmation(PathRisk risk) noexcept {
    return risk == PathRisk::UncOrRemote;
}

const char* ReportOutputRiskName(ReportOutputRisk risk) noexcept {
    switch (risk) {
    case ReportOutputRisk::Ok: return "Ok";
    case ReportOutputRisk::RawControlCharacter: return "RawControlCharacter";
    case ReportOutputRisk::ExternalLink: return "ExternalLink";
    case ReportOutputRisk::ExternalResourceTag: return "ExternalResourceTag";
    case ReportOutputRisk::DebuggerMarkupLink: return "DebuggerMarkupLink";
    case ReportOutputRisk::ScriptOrEventHandler: return "ScriptOrEventHandler";
    }
    return "Ok";
}

namespace {

int RiskSeverity(ReportOutputRisk risk) noexcept {
    switch (risk) {
    case ReportOutputRisk::Ok: return 0;
    case ReportOutputRisk::ExternalLink: return 1;
    case ReportOutputRisk::ExternalResourceTag: return 2;
    case ReportOutputRisk::DebuggerMarkupLink: return 3;
    case ReportOutputRisk::ScriptOrEventHandler: return 4;
    case ReportOutputRisk::RawControlCharacter: return 5;
    }
    return 0;
}

// 事件处理器属性：形如 " onclick=" / " onerror ="。大小写在比较时现折，不建临时串。
bool HasEventHandlerAttribute(std::string_view attributes) noexcept {
    for (std::size_t index = 0; index + 2U < attributes.size(); ++index) {
        const char previous = index == 0U ? ' ' : attributes[index - 1U];
        const bool boundary = previous == ' ' || previous == '\t' || previous == '\n' ||
                              previous == '\r' || previous == '/';
        if (!boundary || AsciiLowerChar(attributes[index]) != 'o' ||
            AsciiLowerChar(attributes[index + 1U]) != 'n') {
            continue;
        }
        std::size_t cursor = index + 2U;
        std::size_t letters = 0;
        while (cursor < attributes.size() &&
               IsAsciiAlpha(static_cast<unsigned char>(attributes[cursor]))) {
            ++cursor;
            ++letters;
        }
        while (cursor < attributes.size() && attributes[cursor] == ' ') {
            ++cursor;
        }
        if (letters > 0U && cursor < attributes.size() && attributes[cursor] == '=') {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 字符引用折叠。浏览器在把属性值当 URL 解析**之前**先解字符引用，所以
// `&#106;avascript:` 对它来说就是 `javascript:`；只比字面量等于没比。
//
// 这里不折出一个新字符串：本判据在 noexcept 路径上，分配一次就可能把一次内存不足
// 变成 std::terminate（见文件开头那一节）。改成"按需逐字符解码后比对"，零分配。
//
// 只折属性区，绝不折整个片段：把 `&lt;` 折回 '<' 会把一段**已经转义好的**安全文本
// 重新拼成标签，那才是真的误报。
// ---------------------------------------------------------------------------
constexpr char kNonAsciiSentinel = '\x01';  // 判据里的 needle 全是可打印 ASCII，撞不上

struct NamedEntity final {
    std::string_view name;
    char value;
};

constexpr NamedEntity kNamedEntities[] = {
    {"lt", '<'},     {"gt", '>'},     {"amp", '&'},    {"quot", '"'},   {"apos", '\''},
    {"colon", ':'},  {"sol", '/'},    {"period", '.'}, {"commat", '@'}, {"lpar", '('},
    {"rpar", ')'},   {"tab", '\t'},   {"newline", '\n'}, {"nbsp", ' '},
};

struct DecodedByte final {
    char value = '\0';
    std::size_t consumed = 1U;
};

// 从 text[pos] 解出一个字符。命中字符引用就解码，否则原样返回这一个字节。
// 分号可有可无：浏览器在属性值里对数字引用同样宽容，判据这一侧宁可多认一种写法。
DecodedByte DecodeEntityAt(std::string_view text, std::size_t pos) noexcept {
    DecodedByte decoded;
    decoded.value = text[pos];
    if (text[pos] != '&' || pos + 1U >= text.size()) {
        return decoded;
    }
    std::size_t cursor = pos + 1U;
    if (text[cursor] == '#') {
        ++cursor;
        std::uint32_t base = 10U;
        if (cursor < text.size() && (text[cursor] == 'x' || text[cursor] == 'X')) {
            base = 16U;
            ++cursor;
        }
        std::uint32_t code = 0;
        std::size_t digits = 0;
        while (cursor < text.size() && digits < 8U) {
            const auto byte = static_cast<unsigned char>(text[cursor]);
            std::uint32_t digit = 0;
            if (IsAsciiDigit(byte)) {
                digit = static_cast<std::uint32_t>(byte - '0');
            } else if (base == 16U && byte >= 'a' && byte <= 'f') {
                digit = static_cast<std::uint32_t>(byte - 'a') + 10U;
            } else if (base == 16U && byte >= 'A' && byte <= 'F') {
                digit = static_cast<std::uint32_t>(byte - 'A') + 10U;
            } else {
                break;
            }
            code = code * base + digit;
            ++cursor;
            ++digits;
        }
        if (digits == 0U) {
            return decoded;  // "&#" 后面没有数字：这就是三个普通字节
        }
        if (cursor < text.size() && text[cursor] == ';') {
            ++cursor;
        }
        decoded.value = code <= 0x7FU ? static_cast<char>(code) : kNonAsciiSentinel;
        decoded.consumed = cursor - pos;
        return decoded;
    }

    std::size_t nameEnd = cursor;
    while (nameEnd < text.size() && (nameEnd - cursor) < 12U &&
           IsAsciiAlpha(static_cast<unsigned char>(text[nameEnd]))) {
        ++nameEnd;
    }
    const std::string_view name = text.substr(cursor, nameEnd - cursor);
    if (name.empty()) {
        return decoded;
    }
    for (const NamedEntity& entity : kNamedEntities) {
        if (!AsciiEqualsIgnoreCase(name, entity.name)) {
            continue;
        }
        std::size_t end = nameEnd;
        if (end < text.size() && text[end] == ';') {
            ++end;
        }
        decoded.value = entity.value;
        decoded.consumed = end - pos;
        return decoded;
    }
    return decoded;
}

// 在"折叠后的" text 里找 loweredNeedle。needle 必须已经是小写字面量。
bool ContainsFoldedIgnoreCase(std::string_view text, std::string_view loweredNeedle) noexcept {
    if (loweredNeedle.empty() || text.empty()) {
        return false;
    }
    for (std::size_t start = 0; start < text.size(); ++start) {
        std::size_t cursor = start;
        std::size_t matched = 0;
        while (matched < loweredNeedle.size() && cursor < text.size()) {
            const DecodedByte decoded = DecodeEntityAt(text, cursor);
            if (AsciiLowerChar(decoded.value) != loweredNeedle[matched]) {
                break;
            }
            cursor += decoded.consumed;
            ++matched;
        }
        if (matched == loweredNeedle.size()) {
            return true;
        }
    }
    return false;
}

bool MentionsAnyOf(std::string_view attributes,
                   std::span<const std::string_view> loweredNames) noexcept {
    for (const std::string_view name : loweredNames) {
        if (ContainsIgnoreCase(attributes, name)) {
            return true;
        }
    }
    return false;
}

bool ContainsAnyFolded(std::string_view attributes,
                       std::span<const std::string_view> loweredNeedles) noexcept {
    for (const std::string_view needle : loweredNeedles) {
        if (ContainsFoldedIgnoreCase(attributes, needle)) {
            return true;
        }
    }
    return false;
}

// 指向报告外面的写法。url( 与 @import 是 CSS 的两种取资源语法 —— 它们出现在 style
// 属性或 <style> 里同样会发请求，跟 http:// 没有区别。
constexpr std::string_view kExternalTargetNeedles[] = {
    "http://", "https://", "ftp://", "file:", "//", "url(", "@import",
};

// 危险协议：点一下（或者根本不用点）就执行脚本。data: 一并算上 —— 本模块的报告
// 永远不会正当地生成 data: URI，而 data:text/html 在浏览器里就是一段可执行文档。
constexpr std::string_view kDangerousSchemeNeedles[] = {
    "javascript:", "vbscript:", "data:",
};

// 打开报告就**自动**发请求的属性，不需要用户点。style 在列：
// <div style="background:url(https://evil/beacon.png)"> 是一次无声的外连。
constexpr std::string_view kAutoFetchAttributes[] = {
    "src", "srcset", "background", "poster", "data", "style", "lowsrc",
};

// 需要用户点一下 / 提交表单才走出去的属性。
constexpr std::string_view kLinkAttributes[] = {
    "href", "action", "formaction", "cite", "content", "ping",
};

bool AttributesAutoFetchExternal(std::string_view attributes) noexcept {
    return MentionsAnyOf(attributes, kAutoFetchAttributes) &&
           ContainsAnyFolded(attributes, kExternalTargetNeedles);
}

bool AttributesReferenceExternal(std::string_view attributes) noexcept {
    return MentionsAnyOf(attributes, kLinkAttributes) &&
           ContainsAnyFolded(attributes, kExternalTargetNeedles);
}

bool AttributesUseDangerousScheme(std::string_view attributes) noexcept {
    // 这一条不设属性名门槛：危险协议出现在属性区的任何位置都不该被写进报告。
    return ContainsAnyFolded(attributes, kDangerousSchemeNeedles);
}

bool IsExternalResourceTagName(std::string_view name) noexcept {
    static constexpr std::string_view kTags[] = {
        "img", "iframe", "object", "embed", "video", "audio", "source", "link", "base", "meta",
        // <style> 里的 @import / url() 与 <img src> 一样是自动外连，只是写在标签内容里，
        // 属性区看不到 —— 因此按标签名接住。
        "style",
    };
    for (const std::string_view tag : kTags) {
        if (AsciiEqualsIgnoreCase(name, tag)) {
            return true;
        }
    }
    return false;
}

} // namespace

ReportOutputRisk ClassifyReportFragment(std::string_view fragment) noexcept {
    // 控制字符先判并立即返回：它说明有一条外来文本根本没过转义出口。
    for (const char raw : fragment) {
        const auto byte = static_cast<unsigned char>(raw);
        if (IsControlByte(byte) && !IsLayoutControlByte(byte)) {
            return ReportOutputRisk::RawControlCharacter;
        }
    }

    ReportOutputRisk worst = ReportOutputRisk::Ok;
    const auto consider = [&worst](ReportOutputRisk candidate) noexcept {
        if (RiskSeverity(candidate) > RiskSeverity(worst)) {
            worst = candidate;
        }
    };

    // 一趟扫描：每碰到一个 '<' 就把标签名与属性区取出来判一次，
    // 然后跳到 '>' 之后。总代价 O(n)，不做回溯。
    std::size_t index = 0;
    while (index < fragment.size()) {
        if (fragment[index] != '<') {
            ++index;
            continue;
        }
        std::size_t cursor = index + 1U;
        if (cursor < fragment.size() && fragment[cursor] == '/') {
            ++cursor;
        }
        const std::size_t nameBegin = cursor;
        while (cursor < fragment.size() &&
               IsAsciiAlnum(static_cast<unsigned char>(fragment[cursor]))) {
            ++cursor;
        }
        const std::string_view name = fragment.substr(nameBegin, cursor - nameBegin);
        const std::size_t close = fragment.find('>', cursor);
        const std::size_t attributesEnd = close == std::string_view::npos ? fragment.size() : close;
        const std::string_view attributes = fragment.substr(cursor, attributesEnd - cursor);

        if (AsciiEqualsIgnoreCase(name, "script") ||
            AttributesUseDangerousScheme(attributes) ||
            HasEventHandlerAttribute(attributes)) {
            consider(ReportOutputRisk::ScriptOrEventHandler);
        }
        // DML：调试器标记语言的 <exec cmd="..."> / <link cmd="...">。
        // 它让报告读者一点就把任意命令喂回调试器，比外链更危险。
        if (AsciiEqualsIgnoreCase(name, "exec") ||
            ((AsciiEqualsIgnoreCase(name, "link") || AsciiEqualsIgnoreCase(name, "a")) &&
             ContainsIgnoreCase(attributes, "cmd="))) {
            consider(ReportOutputRisk::DebuggerMarkupLink);
        }
        if (IsExternalResourceTagName(name) || AttributesAutoFetchExternal(attributes)) {
            // 标签名无害不代表片段无害：<table background="//evil/x.png"> 与
            // <div style="background:url(https://evil/x.png)"> 一样是打开即外连。
            consider(ReportOutputRisk::ExternalResourceTag);
        }
        if (AttributesReferenceExternal(attributes)) {
            consider(ReportOutputRisk::ExternalLink);
        }

        index = close == std::string_view::npos ? fragment.size() : close + 1U;
    }
    return worst;
}

// ---------------------------------------------------------------------------
// C-10 报告出处
// ---------------------------------------------------------------------------
const char* ProvenanceGapName(ProvenanceGap gap) noexcept {
    switch (gap) {
    case ProvenanceGap::MissingEngineIdentity: return "MissingEngineIdentity";
    case ProvenanceGap::MissingEngineVersion: return "MissingEngineVersion";
    case ProvenanceGap::MissingInputPath: return "MissingInputPath";
    case ProvenanceGap::MissingInputSize: return "MissingInputSize";
    case ProvenanceGap::MissingInputHash: return "MissingInputHash";
    case ProvenanceGap::MissingAnalysisWindow: return "MissingAnalysisWindow";
    case ProvenanceGap::MissingSymbolStates: return "MissingSymbolStates";
    case ProvenanceGap::UnstatedAnalysisScope: return "UnstatedAnalysisScope";
    case ProvenanceGap::WrongSourceOrigin: return "WrongSourceOrigin";
    case ProvenanceGap::UndisclosedExternalSupplement:
        return "UndisclosedExternalSupplement";
    }
    return "MissingEngineIdentity";
}

namespace {

bool LooksLikeSha256Hex(std::string_view text) noexcept {
    if (text.size() != 64U) {
        return false;
    }
    for (const char raw : text) {
        const auto byte = static_cast<unsigned char>(raw);
        const bool hex = IsAsciiDigit(byte) || (byte >= 'a' && byte <= 'f') ||
                         (byte >= 'A' && byte <= 'F');
        if (!hex) {
            return false;
        }
    }
    return true;
}

bool ScopeStated(const CoverageAccount& scope) noexcept {
    if (scope.totalKnown.present) {
        return true;
    }
    if (scope.requestedBegin.present && scope.requestedEnd.present) {
        return true;
    }
    return scope.succeeded > 0U || scope.failed > 0U || scope.skipped > 0U ||
           scope.truncated > 0U;
}

std::string OptionalFieldValue(const OptionalU64& value, U64Format format) {
    if (!value.present) {
        return std::string(kUnknownValueKey);
    }
    return FormatU64(value.value, format);
}

} // namespace

std::vector<ProvenanceGap> AuditProvenance(const DumpReportProvenance& provenance) {
    std::vector<ProvenanceGap> gaps;
    if (provenance.engine.engineId.empty()) {
        gaps.push_back(ProvenanceGap::MissingEngineIdentity);
    }
    if (provenance.engine.engineVersion.empty()) {
        gaps.push_back(ProvenanceGap::MissingEngineVersion);
    }
    if (provenance.input.filePath.empty()) {
        gaps.push_back(ProvenanceGap::MissingInputPath);
    }
    if (!provenance.input.fileSize.present) {
        gaps.push_back(ProvenanceGap::MissingInputSize);
    }
    if (!provenance.input.hashComputed || !LooksLikeSha256Hex(provenance.input.sha256Hex)) {
        gaps.push_back(ProvenanceGap::MissingInputHash);
    }
    if (!provenance.window.startUtc100ns.present || !provenance.window.endUtc100ns.present) {
        gaps.push_back(ProvenanceGap::MissingAnalysisWindow);
    }
    if (provenance.symbolStates.empty()) {
        // 一份没写符号状态的报告无法被重核：读者分不清"函数名可信"与"只是猜的"。
        gaps.push_back(ProvenanceGap::MissingSymbolStates);
    }
    if (!ScopeStated(provenance.analysisScope)) {
        gaps.push_back(ProvenanceGap::UnstatedAnalysisScope);
    }
    if (provenance.source.origin != SourceOrigin::OfflineSample) {
        gaps.push_back(ProvenanceGap::WrongSourceOrigin);
    }
    if (!SupplementDisclosed(provenance.supplement)) {
        gaps.push_back(ProvenanceGap::UndisclosedExternalSupplement);
    }
    return gaps;
}

bool ProvenanceReviewable(const DumpReportProvenance& provenance) {
    return AuditProvenance(provenance).empty();
}

std::vector<ReportField> BuildProvenanceFields(const DumpReportProvenance& provenance) {
    std::vector<ReportField> fields;
    fields.reserve(18U);

    const auto push = [&fields](std::string key, std::string rawValue) {
        // 唯一出口：所有值在这里统一过转义，调用方拿到的就是可直接进 HTML 的值。
        fields.push_back(ReportField{std::move(key), EscapeForReport(rawValue)});
    };
    const auto pushText = [&push](std::string key, const std::string& text) {
        push(std::move(key), text.empty() ? std::string(kUnknownValueKey) : text);
    };

    pushText("dump.report.engine_id", provenance.engine.engineId);
    pushText("dump.report.engine_version", provenance.engine.engineVersion);
    push("dump.report.engine_available",
         provenance.engine.engineAvailable ? std::string("true") : std::string("false"));

    pushText("dump.report.input_path", provenance.input.filePath);
    push("dump.report.input_size",
         OptionalFieldValue(provenance.input.fileSize, U64Format::Decimal));
    push("dump.report.input_sha256",
         provenance.input.hashComputed && !provenance.input.sha256Hex.empty()
             ? provenance.input.sha256Hex
             : std::string(kUnknownValueKey));
    push("dump.report.input_last_modified",
         OptionalFieldValue(provenance.input.lastModifiedUtc100ns, U64Format::Decimal));

    pushText("dump.report.source_collector", provenance.source.collectorId);
    push("dump.report.source_origin", SourceOriginName(provenance.source.origin));

    push("dump.report.analysis_window_start",
         OptionalFieldValue(provenance.window.startUtc100ns, U64Format::Decimal));
    push("dump.report.analysis_window_end",
         OptionalFieldValue(provenance.window.endUtc100ns, U64Format::Decimal));
    push("dump.report.analysis_scope_remaining", provenance.analysisScope.describeRemaining());

    std::uint64_t matched = 0;
    std::uint64_t wrongVersion = 0;
    std::uint64_t absent = 0;
    std::uint64_t notAttempted = 0;
    for (const ModuleSymbolState& state : provenance.symbolStates) {
        switch (state.match) {
        case SymbolMatch::Matched: ++matched; break;
        case SymbolMatch::WrongVersion: ++wrongVersion; break;
        case SymbolMatch::Absent: ++absent; break;
        case SymbolMatch::NotAttempted: ++notAttempted; break;
        }
    }
    push("dump.report.symbol_module_count",
         FormatU64(static_cast<std::uint64_t>(provenance.symbolStates.size()), U64Format::Decimal));
    push("dump.report.symbol_matched_count", FormatU64(matched, U64Format::Decimal));
    push("dump.report.symbol_wrong_version_count", FormatU64(wrongVersion, U64Format::Decimal));
    push("dump.report.symbol_absent_count", FormatU64(absent, U64Format::Decimal));
    push("dump.report.symbol_not_attempted_count", FormatU64(notAttempted, U64Format::Decimal));

    push("dump.report.external_supplement",
         provenance.supplement.used
             ? (provenance.supplement.disclosureKey.empty()
                    ? std::string(kUnknownValueKey)
                    : provenance.supplement.disclosureKey)
             : std::string("none"));
    return fields;
}

} // namespace Ksword::Evidence
