// C 模块（离线崩溃转储分析）的离线自动测试。
//
// 覆盖编号：C-02 C-03 C-04 C-05 C-06 C-07 C-08 C-09 C-10。
// C-01（DbgEng 探测）与"与真实 dump / WinDbg 对照"不在这里 —— 那要真实样本与调试引擎。
//
// 断言原则（Q-01 红线：测试不许自我印证）：
//   * 转储字节由本文件按 DUMP_HEADER64 的**公开布局**手写偏移生成，
//     生产代码里的偏移常量全在匿名 namespace 里，测试拿不到 —— 偏移写错必然暴露；
//   * 期望值一律独立写死（转义后的字符串逐字节列出、字段计数手数），
//     不把生产函数的输出当成"另一侧"输入；
//   * 每个枚举的每条分支都要被断到，不许有零覆盖的分支；
//   * "默认构造"单独测一遍：默认必须是未知/不可信/被拒绝，不许是完整/安全/放行。

#include "TestSupport.h"

#include "../shared/evidence/DumpFacts.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

// ---------------------------------------------------------------------------
// Reporter：KswordTests::Suite 的本地转发器。计数仍然全部走真正的 Suite，
// 这里只多做一件事 —— 修复被中文套件名弄坏的宽字符流。
//
// 为什么需要它（实测，不是猜测）：套件名 L"C 离线崩溃转储分析" 里的非 ASCII 宽字符
// 在默认 "C" locale 下无法由 wcout/wcerr 转成窄字符，MSVC 会在那一位置 badbit 并
// **吞掉此后所有输出**。注入一条真实缺陷后实测：3 条断言失败，控制台只出现
// 一行截断的 "FAIL [C "，另外两条的标签全丢 —— 失败数对得上，但没人知道错在哪。
// 每次断言后清一次流状态，并在失败时补一行纯 ASCII 的完整标签，失败才可调试。
// ---------------------------------------------------------------------------
class Reporter final {
public:
    explicit Reporter(KswordTests::Suite& suite) : suite_(suite) {}

    void expect(bool condition, const wchar_t* label) {
        const int before = suite_.failures();
        suite_.expect(condition, label);
        // 套件名已改成纯 ASCII，宽流不再会因转换失败被吞；TestSupport.h 的 Suite
        // 也会在每次输出后清一次流状态。这里不再补打重复的 FAIL 行。
        (void)before;
    }

private:
    KswordTests::Suite& suite_;
};

// ---------------------------------------------------------------------------
// 字节构造工具。全部在测试侧，偏移由测试自己写。
// ---------------------------------------------------------------------------
void PutU32(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint32_t value) {
    buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xFFU);
    buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
    buffer[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFFU);
    buffer[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFFU);
}

void PutU64(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint64_t value) {
    PutU32(buffer, offset, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    PutU32(buffer, offset + 4, static_cast<std::uint32_t>((value >> 32) & 0xFFFFFFFFULL));
}

void PutAscii(std::vector<std::uint8_t>& buffer, std::size_t offset, const char* text) {
    for (std::size_t index = 0; text[index] != '\0'; ++index) {
        buffer[offset + index] = static_cast<std::uint8_t>(text[index]);
    }
}

std::span<const std::uint8_t> View(const std::vector<std::uint8_t>& buffer) {
    return std::span<const std::uint8_t>(buffer.data(), buffer.size());
}

// 手写的 DUMP_HEADER64 值。测试后面逐字段对照这些常量，不从生产代码反算。
constexpr std::uint32_t kFixtureMajorVersion = 15U;
constexpr std::uint32_t kFixtureBuildNumber = 26100U;
constexpr std::uint32_t kFixtureProcessorCount = 16U;
constexpr std::uint32_t kFixtureBugCheckCode = 0x0000007EU;
constexpr std::uint64_t kFixtureParam0 = 0xFFFFFFFFC0000005ULL;
constexpr std::uint64_t kFixtureParam1 = 0xFFFFF80312345678ULL;
constexpr std::uint64_t kFixtureParam2 = 0x0000000000000000ULL;  // 真的是 0，不是缺失
constexpr std::uint64_t kFixtureParam3 = 0xFFFFF8031234ABCDULL;
constexpr std::uint64_t kFixtureCrashTime = 0x01DA1234ABCD0000ULL;
constexpr std::uint64_t kFixtureUptime = 0x0000000E4E1C0000ULL;
constexpr std::uint64_t kFixtureDirectoryTableBase = 0x00000000001AA000ULL;

// MakeKernelHeader：一份 0x2000 字节的 PAGEDU64 头。
// 所有偏移都按官方 DUMP_HEADER64 布局手写。
std::vector<std::uint8_t> MakeKernelHeader(std::uint32_t dumpType, std::uint32_t machineType) {
    std::vector<std::uint8_t> buffer(0x2000, 0U);
    PutAscii(buffer, 0x00, "PAGE");
    PutAscii(buffer, 0x04, "DU64");
    PutU32(buffer, 0x08, kFixtureMajorVersion);
    PutU32(buffer, 0x0C, kFixtureBuildNumber);
    PutU64(buffer, 0x10, kFixtureDirectoryTableBase);
    PutU32(buffer, 0x30, machineType);
    PutU32(buffer, 0x34, kFixtureProcessorCount);
    PutU32(buffer, 0x38, kFixtureBugCheckCode);
    PutU64(buffer, 0x40, kFixtureParam0);
    PutU64(buffer, 0x48, kFixtureParam1);
    PutU64(buffer, 0x50, kFixtureParam2);
    PutU64(buffer, 0x58, kFixtureParam3);
    PutU32(buffer, 0xF98, dumpType);
    PutU64(buffer, 0xFA8, kFixtureCrashTime);
    PutU64(buffer, 0x1030, kFixtureUptime);
    PutU32(buffer, 0x1048, 0U);  // WriterStatus = 0：这是"写入正常"，不是缺失
    return buffer;
}

// 除了签名与判别字段外全部保持 'PAGE' 填充 —— 写入器没填过的样子。
std::vector<std::uint8_t> MakePageFilledKernelHeader() {
    std::vector<std::uint8_t> buffer(0x2000, 0U);
    static const char kFill[4] = {'P', 'A', 'G', 'E'};
    for (std::size_t index = 0; index < buffer.size(); ++index) {
        buffer[index] = static_cast<std::uint8_t>(kFill[index % 4U]);
    }
    PutAscii(buffer, 0x00, "PAGE");
    PutAscii(buffer, 0x04, "DU64");
    PutU32(buffer, 0x30, 0x8664U);
    PutU32(buffer, 0xF98, 4U);
    return buffer;
}

// 除签名/架构/类型外全 0 的头。用来分辨"0 是真值"与"0 是没填"。
std::vector<std::uint8_t> MakeZeroedKernelHeader() {
    std::vector<std::uint8_t> buffer(0x2000, 0U);
    PutAscii(buffer, 0x00, "PAGE");
    PutAscii(buffer, 0x04, "DU64");
    PutU32(buffer, 0x30, 0x8664U);
    PutU32(buffer, 0xF98, 4U);
    return buffer;
}

std::vector<std::uint8_t> MakeUserMinidump(std::size_t size) {
    std::vector<std::uint8_t> buffer(size, 0U);
    if (size >= 4U) {
        PutAscii(buffer, 0x00, "MDMP");
    }
    if (size >= 8U) {
        PutU32(buffer, 0x04, 0x0000A793U);  // MINIDUMP_VERSION
    }
    if (size >= 0x20U) {
        PutU32(buffer, 0x08, 7U);        // NumberOfStreams
        PutU32(buffer, 0x0C, 0x00000020U);  // StreamDirectoryRva
    }
    return buffer;
}

std::vector<std::uint8_t> MakeKernel32Header() {
    std::vector<std::uint8_t> buffer(0x1000, 0U);
    PutAscii(buffer, 0x00, "PAGE");
    PutAscii(buffer, 0x04, "DUMP");
    return buffer;
}

// 确定性伪随机字节。固定种子，跑多少次都一样。
std::vector<std::uint8_t> MakeRandomBytes(std::size_t size, std::uint64_t seed) {
    std::vector<std::uint8_t> buffer(size, 0U);
    std::uint64_t state = seed;
    for (std::size_t index = 0; index < size; ++index) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        buffer[index] = static_cast<std::uint8_t>((state >> 33U) & 0xFFU);
    }
    return buffer;
}

// ---------------------------------------------------------------------------
// C-02 文件识别与支持范围
// ---------------------------------------------------------------------------
void TestRecognition(Reporter& s) {
    // 合法 small kernel dump（DumpType=4）。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::KernelSmall,
                 L"C-02 small kernel dump is recognized as KernelSmall");
        s.expect(recognition.family == SignatureFamily::KernelPage64,
                 L"C-02 small kernel dump reports the PAGEDU64 signature family");
        s.expect(recognition.reason == RecognitionReason::Recognized,
                 L"C-02 small kernel dump recognition reason is Recognized");
        s.expect(recognition.architecture == TargetArchitecture::X64,
                 L"C-02 small kernel dump target architecture is x64");
        s.expect(recognition.rawDumpType == OptionalU64::of(4U),
                 L"C-02 raw DumpType 4 survives classification");
        s.expect(recognition.rawMachineType == OptionalU64::of(0x8664U),
                 L"C-02 raw machine type 0x8664 survives classification");
        s.expect(recognition.rawSignature == OptionalU64::of(0x45474150U),
                 L"C-02 raw PAGE signature is kept losslessly");
        s.expect(recognition.rawValidDump == OptionalU64::of(0x34365544U),
                 L"C-02 raw DU64 discriminator is kept losslessly");
        s.expect(recognition.parseAttempted,
                 L"C-02 a recognized kernel dump reports that fields were actually read");
        s.expect(recognition.outcome.status == CollectionStatus::Success,
                 L"C-02 recognized dump carries a Success collection outcome");
        s.expect(recognition.fileSize == OptionalU64::of(0x2000ULL),
                 L"C-02 recognition falls back to the provided window size as file size");
        s.expect(!RecognitionIsDamagedRatherThanUnsupported(recognition),
                 L"C-02 a healthy dump is not reported as damaged");
        s.expect(DumpKindCarriesKernelFacts(recognition.kind),
                 L"C-02 KernelSmall is allowed to carry kernel bugcheck facts");
    }

    // DumpType=3（仅转储头）也归 KernelSmall，但原始值保留。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(3U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::KernelSmall,
                 L"C-02 header-only dump is treated with the small-dump content upper bound");
        s.expect(recognition.rawDumpType == OptionalU64::of(3U),
                 L"C-02 header-only dump keeps raw DumpType 3 so the report can tell them apart");
    }

    // 合法 kernel memory dump（DumpType=2）。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(2U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::KernelMemory,
                 L"C-02 kernel memory dump is recognized as KernelMemory");
        s.expect(recognition.reason == RecognitionReason::Recognized,
                 L"C-02 kernel memory dump recognition reason is Recognized");
    }
    for (const std::uint32_t dumpType : {1U, 5U, 6U, 7U}) {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(dumpType, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::KernelMemory,
                 L"C-02 every memory-bearing DumpType maps to KernelMemory");
    }

    // 用户态 minidump —— 红线：绝不能被当成内核 dump。
    {
        const std::vector<std::uint8_t> bytes = MakeUserMinidump(0x400);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::UserMinidump,
                 L"C-02 a user-mode MDMP is recognized as UserMinidump");
        s.expect(recognition.family == SignatureFamily::Mdmp,
                 L"C-02 a user-mode MDMP reports the MDMP signature family");
        s.expect(recognition.kind != DumpKind::KernelSmall &&
                     recognition.kind != DumpKind::KernelMemory,
                 L"C-02 red line: a user-mode minidump is never classified as a kernel dump");
        s.expect(!DumpKindCarriesKernelFacts(recognition.kind),
                 L"C-02 a user minidump is not allowed to carry kernel bugcheck facts");
        s.expect(recognition.architecture == TargetArchitecture::Unknown,
                 L"C-02 MDMP architecture stays Unknown because the header does not carry it");
        s.expect(recognition.rawMachineType == OptionalU64::unset(),
                 L"C-02 MDMP raw machine type stays unset rather than defaulting to zero");
    }

    // 空文件。
    {
        const std::vector<std::uint8_t> bytes;
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::NotADump,
                 L"C-02 an empty file is NotADump");
        s.expect(recognition.reason == RecognitionReason::EmptyFile,
                 L"C-02 an empty file reports the EmptyFile reason, not a generic failure");
        s.expect(recognition.family == SignatureFamily::None,
                 L"C-02 an empty file has no signature family");
        s.expect(!recognition.parseAttempted,
                 L"C-02 an empty file never claims fields were parsed");
        s.expect(recognition.outcome.status == CollectionStatus::Error,
                 L"C-02 an empty file yields an error outcome, not Success");
        s.expect(recognition.outcome.nativeCode ==
                     OptionalU64::of(static_cast<std::uint64_t>(RecognitionReason::EmptyFile)),
                 L"C-02 the recognition outcome preserves the raw reason code");
        s.expect(recognition.outcome.nativeCodeDomain == "KSWORD_DUMPRECOGNITION",
                 L"C-02 the recognition outcome names its own error domain");
        s.expect(RecognitionIsDamagedRatherThanUnsupported(recognition),
                 L"C-02 an empty file is a file problem, not an unsupported format");
    }

    // 7 字节：连签名都读不出来。
    {
        const std::vector<std::uint8_t> bytes(7U, 0x41U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.reason == RecognitionReason::TooSmallForSignature,
                 L"C-02 a 7-byte file reports TooSmallForSignature");
        s.expect(recognition.kind == DumpKind::NotADump,
                 L"C-02 a 7-byte file is NotADump");
        s.expect(recognition.rawSignature == OptionalU64::unset(),
                 L"C-02 an unreadable signature stays unset rather than defaulting to zero");
    }

    // 截断的内核转储文件（0x100 字节）。
    {
        std::vector<std::uint8_t> full = MakeKernelHeader(4U, 0x8664U);
        const std::vector<std::uint8_t> bytes(full.begin(), full.begin() + 0x100);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::Unsupported,
                 L"C-02 a truncated kernel dump cannot converge to Small or Memory");
        s.expect(recognition.family == SignatureFamily::KernelPage64,
                 L"C-02 a truncated kernel dump still reports its signature family");
        s.expect(recognition.reason == RecognitionReason::TruncatedHeader,
                 L"C-02 a truncated kernel dump reports TruncatedHeader");
        s.expect(recognition.architecture == TargetArchitecture::X64,
                 L"C-02 a truncated kernel dump still reads the machine type at 0x30");
        s.expect(recognition.rawDumpType == OptionalU64::unset(),
                 L"C-02 a truncated kernel dump leaves DumpType unset instead of guessing");
        s.expect(recognition.outcome.status == CollectionStatus::Partial,
                 L"C-02 a truncated header is a partial collection, not an unsupported format");
        s.expect(RecognitionIsDamagedRatherThanUnsupported(recognition),
                 L"C-02 truncation is reported as damage, not as unsupported");
        s.expect(recognition.headerBytesRequired == OptionalU64::of(0x2000ULL),
                 L"C-02 the required header size is stated so the UI can explain the shortfall");
    }

    // 截断的用户态 minidump：家族仍然可信 —— 依旧证明"不是内核 dump"。
    {
        const std::vector<std::uint8_t> bytes = MakeUserMinidump(16U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.family == SignatureFamily::Mdmp,
                 L"C-02 a truncated MDMP still proves it is a user-mode minidump family");
        s.expect(recognition.kind == DumpKind::Unsupported,
                 L"C-02 a truncated MDMP does not claim a parsable kind");
        s.expect(recognition.reason == RecognitionReason::TruncatedHeader,
                 L"C-02 a truncated MDMP reports TruncatedHeader");
        s.expect(recognition.kind != DumpKind::KernelSmall &&
                     recognition.kind != DumpKind::KernelMemory,
                 L"C-02 red line: a truncated user minidump is still never a kernel dump");
    }

    // 调用方只给了前 0x1000 字节，但声明文件有 0x2000。
    {
        const std::vector<std::uint8_t> full = MakeKernelHeader(4U, 0x8664U);
        const std::vector<std::uint8_t> head(full.begin(), full.begin() + 0x1000);
        const DumpRecognition recognition = RecognizeDump(View(head), OptionalU64::of(0x2000ULL));
        s.expect(recognition.reason == RecognitionReason::TruncatedHeader,
                 L"C-02 a short read window is reported instead of silently parsing garbage");
        s.expect(recognition.bytesProvided == OptionalU64::of(0x1000ULL),
                 L"C-02 the provided window size is recorded");
        s.expect(recognition.fileSize == OptionalU64::of(0x2000ULL),
                 L"C-02 the declared file size is recorded separately from the window");
    }

    // 窗口正好停在某个读取偏移的**中间**。这是 ReadLittleEndianU32/U64 长度边界的
    // 唯一触发条件：offset < size < offset + 4（或 + 8）。上面那些截断样本都是
    // "整块砍掉"，窗口末尾从来没落在字段内部，因此那条边界一直是零覆盖 ——
    // 实测把 `bytes.size() - offset < 4U` 削掉之后整套断言仍然全绿，
    // 而同一份代码在 guard page 探针下当场越界读到守卫页（ACCESS_VIOLATION）。
    //
    // 期望值独立写死：DUMP_HEADER64 里 MachineImageType 在 0x30、DumpType 在 0xF98、
    // SystemUpTime 在 0x1030、WriterStatus 在 0x1048（都是本文件自己写的偏移常量，
    // 与生产代码无关）。窗口长度取这些字段的每一个内部切点。
    {
        const std::vector<std::uint8_t> full = MakeKernelHeader(4U, 0x8664U);
        const std::size_t kPartialWindows[] = {
            0x30U, 0x31U, 0x32U, 0x33U,          // MachineImageType 内部
            0x10U, 0x11U, 0x12U, 0x13U,          // DirectoryTableBase 低半
            0x14U, 0x15U, 0x16U, 0x17U,          // DirectoryTableBase 高半
            0xF98U, 0xF99U, 0xF9AU, 0xF9BU,      // DumpType 内部
            0x1030U, 0x1031U, 0x1034U, 0x1037U,  // SystemUpTime 内部
            0x1048U, 0x1049U, 0x104AU, 0x104BU,  // WriterStatus 内部
        };
        bool allSafe = true;
        bool allUnparsedMachine = true;
        bool allUnparsedDumpType = true;
        bool allFieldsAccountedFor = true;
        for (const std::size_t windowSize : kPartialWindows) {
            const std::vector<std::uint8_t> window(full.begin(),
                                                   full.begin() +
                                                       static_cast<std::ptrdiff_t>(windowSize));
            const DumpRecognition recognition =
                RecognizeDump(View(window), OptionalU64::of(0x2000ULL));
            // 头不完整 -> 永远收敛不到可解析的 kind，也永远不报"识别成功"。
            allSafe = allSafe && recognition.kind == DumpKind::Unsupported &&
                      recognition.reason == RecognitionReason::TruncatedHeader;
            if (windowSize <= 0x33U) {
                // 机器类型这一格自己就没读全：必须 unset，不许拿半个字段拼一个值。
                allUnparsedMachine = allUnparsedMachine && !recognition.rawMachineType.present;
            }
            allUnparsedDumpType = allUnparsedDumpType && !recognition.rawDumpType.present;

            const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(window));
            allFieldsAccountedFor =
                allFieldsAccountedFor && facts.presentFieldCount() == 0U &&
                facts.notParsedFieldCount() == 12U && facts.fieldCount() == 12U &&
                !facts.hasAnyFact();
        }
        s.expect(allSafe,
                 L"C-02 a window that stops inside a header field never converges to a parsable kind");
        s.expect(allUnparsedMachine,
                 L"C-02 a machine type whose last bytes are missing stays unset instead of half-read");
        s.expect(allUnparsedDumpType,
                 L"C-02 a DumpType whose last bytes are missing stays unset instead of half-read");
        s.expect(allFieldsAccountedFor,
                 L"C-03 every field of a mid-field truncated window is NotParsed, none fabricated");

        // 反面：窗口刚好读到机器类型的最后一个字节时，那一格才允许出现。
        const std::vector<std::uint8_t> exact(full.begin(), full.begin() + 0x34);
        const DumpRecognition recognition = RecognizeDump(View(exact), OptionalU64::of(0x2000ULL));
        s.expect(recognition.rawMachineType == OptionalU64::of(0x8664U),
                 L"C-02 one byte more and the machine type reads exactly, proving the bound is off-by-none");
        s.expect(recognition.reason == RecognitionReason::TruncatedHeader,
                 L"C-02 reading the machine type does not make a truncated header complete");
    }

    // 逐字节扫过整个头长度：任何窗口都不许崩、不许冒充解析成功、字段账目恒等于 12。
    {
        const std::vector<std::uint8_t> full = MakeKernelHeader(4U, 0x8664U);
        bool neverClaimsSuccess = true;
        bool accountsAlwaysBalance = true;
        for (std::size_t windowSize = 0; windowSize < 0x120U; ++windowSize) {
            const std::vector<std::uint8_t> window(full.begin(),
                                                   full.begin() +
                                                       static_cast<std::ptrdiff_t>(windowSize));
            const DumpRecognition recognition =
                RecognizeDump(View(window), OptionalU64::of(0x2000ULL));
            neverClaimsSuccess = neverClaimsSuccess && !DumpKindCarriesKernelFacts(recognition.kind);
            const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(window));
            accountsAlwaysBalance =
                accountsAlwaysBalance &&
                (facts.presentFieldCount() + facts.notRecordedFieldCount() +
                 facts.notParsedFieldCount()) == 12U;
        }
        s.expect(neverClaimsSuccess,
                 L"C-02 no truncated window length ever yields a kind that carries kernel facts");
        s.expect(accountsAlwaysBalance,
                 L"C-03 the field account adds up to twelve at every truncated window length");
    }

    // 随机字节。
    {
        const std::vector<std::uint8_t> bytes = MakeRandomBytes(4096U, 0x1234ABCDULL);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::NotADump,
                 L"C-02 random bytes are NotADump");
        s.expect(recognition.reason == RecognitionReason::UnknownSignature,
                 L"C-02 random bytes report UnknownSignature");
        s.expect(!recognition.parseAttempted,
                 L"C-02 random bytes never claim a format parse happened");
        s.expect(!RecognitionIsDamagedRatherThanUnsupported(recognition),
                 L"C-02 an unknown signature is not reported as a damaged dump");
    }

    // 32 位内核转储：明确拒绝，不冒充解析成功。
    {
        const std::vector<std::uint8_t> bytes = MakeKernel32Header();
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::Unsupported,
                 L"C-02 a 32-bit PAGEDUMP is explicitly unsupported");
        s.expect(recognition.family == SignatureFamily::KernelPage32,
                 L"C-02 a 32-bit PAGEDUMP reports its own signature family");
        s.expect(recognition.reason == RecognitionReason::UnsupportedKernelBitness,
                 L"C-02 a 32-bit PAGEDUMP names bitness as the reason");
        s.expect(recognition.outcome.status == CollectionStatus::Unsupported,
                 L"C-02 an unsupported format yields the Unsupported status");
        s.expect(!recognition.parseAttempted,
                 L"C-02 an unsupported 32-bit dump is not parsed with the 64-bit layout");
        s.expect(!RecognitionIsDamagedRatherThanUnsupported(recognition),
                 L"C-02 unsupported bitness is a format limit, not file damage");
    }

    // 'PAGE' 但判别字段不认识。
    {
        std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x8664U);
        PutAscii(bytes, 0x04, "XXXX");
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.reason == RecognitionReason::UnknownSignature,
                 L"C-02 a PAGE signature with an unknown discriminator is not force-parsed");
        s.expect(recognition.kind == DumpKind::NotADump,
                 L"C-02 an unknown PAGE discriminator yields NotADump");
    }

    // 非 x64 架构。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0xAA64U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::Unsupported,
                 L"C-02 an ARM64 kernel dump is unsupported this round");
        s.expect(recognition.reason == RecognitionReason::UnsupportedArchitecture,
                 L"C-02 an ARM64 kernel dump names architecture as the reason");
        s.expect(recognition.architecture == TargetArchitecture::Arm64,
                 L"C-02 the ARM64 architecture is still reported, not hidden");
    }
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x014CU);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.architecture == TargetArchitecture::X86,
                 L"C-02 an x86 machine type is classified as X86");
    }
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x01C4U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.architecture == TargetArchitecture::Arm,
                 L"C-02 an ARM machine type is classified as Arm");
    }
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x5555U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.architecture == TargetArchitecture::Other,
                 L"C-02 an unrecognized machine type is Other, with the raw value preserved");
        s.expect(recognition.rawMachineType == OptionalU64::of(0x5555U),
                 L"C-02 the raw machine type is preserved for an unknown architecture");
    }
    {
        // 'PAGE' 填充落在机器类型上：那是"没填过"，不是一个取值。
        std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x8664U);
        PutU32(bytes, 0x30, 0x45474150U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.architecture == TargetArchitecture::Unknown,
                 L"C-02 a PAGE-filled machine type is Unknown, never a fabricated architecture");
        s.expect(recognition.reason == RecognitionReason::UnsupportedArchitecture,
                 L"C-02 an unknown architecture is rejected rather than assumed to be x64");
    }

    // 未知 DumpType。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(99U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::Unsupported,
                 L"C-02 an unknown DumpType is not force-mapped to a supported kind");
        s.expect(recognition.reason == RecognitionReason::UnsupportedDumpType,
                 L"C-02 an unknown DumpType names DumpType as the reason");
        s.expect(recognition.rawDumpType == OptionalU64::of(99U),
                 L"C-02 the raw unknown DumpType is preserved");
    }

    // 不按扩展名解析：同一份 MDMP 字节无论调用方怎么想都还是用户态转储。
    // API 里根本没有路径/扩展名参数，这一条由接口形状保证，这里断言其后果。
    {
        const std::vector<std::uint8_t> mdmp = MakeUserMinidump(0x200);
        const DumpRecognition first = RecognizeDump(View(mdmp), OptionalU64::of(0x200ULL));
        const DumpRecognition second = RecognizeDump(View(mdmp), OptionalU64::of(0x200ULL));
        s.expect(first.kind == second.kind && first.kind == DumpKind::UserMinidump,
                 L"C-02 classification depends only on bytes, never on a name or extension");
    }

    // 名字覆盖：每个枚举量都有名字，且互不相同（避免 UI 把两种状态显示成一句话）。
    s.expect(std::string(DumpKindName(DumpKind::NotADump)) == "NotADump" &&
                 std::string(DumpKindName(DumpKind::Unsupported)) == "Unsupported" &&
                 std::string(DumpKindName(DumpKind::UserMinidump)) == "UserMinidump" &&
                 std::string(DumpKindName(DumpKind::KernelSmall)) == "KernelSmall" &&
                 std::string(DumpKindName(DumpKind::KernelMemory)) == "KernelMemory",
             L"C-02 every DumpKind has its own distinct name");
    s.expect(std::string(SignatureFamilyName(SignatureFamily::None)) == "None" &&
                 std::string(SignatureFamilyName(SignatureFamily::Mdmp)) == "Mdmp" &&
                 std::string(SignatureFamilyName(SignatureFamily::KernelPage64)) == "KernelPage64" &&
                 std::string(SignatureFamilyName(SignatureFamily::KernelPage32)) == "KernelPage32",
             L"C-02 every SignatureFamily has its own distinct name");
    s.expect(std::string(TargetArchitectureName(TargetArchitecture::Other)) == "Other" &&
                 std::string(TargetArchitectureName(TargetArchitecture::Unknown)) == "Unknown",
             L"C-02 TargetArchitecture names cover Unknown and Other separately");
    s.expect(std::string(RecognitionReasonName(RecognitionReason::Recognized)) == "Recognized",
             L"C-02 RecognitionReason exposes a stable name for reports");

    // 默认构造：不许是"识别成功"。
    {
        const DumpRecognition fresh;
        s.expect(fresh.kind == DumpKind::NotADump && !fresh.parseAttempted &&
                     fresh.outcome.status == CollectionStatus::NotCollected,
                 L"C-02 a default-constructed recognition is NotADump and NotCollected");
    }
}

// ---------------------------------------------------------------------------
// C-03 崩溃事实
// ---------------------------------------------------------------------------
void TestBugCheckFacts(Reporter& s) {
    // 全部字段都有真值的正常 small dump。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));

        s.expect(facts.dumpKind == DumpKind::KernelSmall,
                 L"C-03 the facts record which dump kind they came from");
        s.expect(facts.code == DumpField::present(kFixtureBugCheckCode),
                 L"C-03 bugcheck code 0x7E is read back exactly");
        s.expect(facts.parameters[0] == DumpField::present(kFixtureParam0),
                 L"C-03 bugcheck parameter 0 is read back exactly");
        s.expect(facts.parameters[1] == DumpField::present(kFixtureParam1),
                 L"C-03 bugcheck parameter 1 is read back exactly");
        s.expect(facts.parameters[2].availability == DumpFieldAvailability::Present &&
                     facts.parameters[2].value == OptionalU64::of(0ULL),
                 L"C-03 a genuine zero parameter is Present(0), not reported as missing");
        s.expect(facts.parameters[3] == DumpField::present(kFixtureParam3),
                 L"C-03 bugcheck parameter 3 is read back exactly");
        s.expect(facts.targetOsMajor == DumpField::present(kFixtureMajorVersion),
                 L"C-03 the target OS major version is read back exactly");
        s.expect(facts.targetOsBuild == DumpField::present(kFixtureBuildNumber),
                 L"C-03 the target OS build number is read back exactly");
        s.expect(facts.processorCount == DumpField::present(kFixtureProcessorCount),
                 L"C-03 the processor count is read back exactly");
        s.expect(facts.crashTimeUtc100ns == DumpField::present(kFixtureCrashTime),
                 L"C-03 the crash FILETIME is read back exactly and losslessly");
        s.expect(facts.uptime100ns == DumpField::present(kFixtureUptime),
                 L"C-03 the uptime is read back exactly and losslessly");
        s.expect(facts.writerStatus.availability == DumpFieldAvailability::Present &&
                     facts.writerStatus.value == OptionalU64::of(0ULL),
                 L"C-03 writer status zero means healthy and stays Present(0)");
        s.expect(facts.directoryTableBase == DumpField::present(kFixtureDirectoryTableBase),
                 L"C-03 the crash-time CR3 is read back exactly");
        s.expect(facts.presentFieldCount() == 12U && facts.fieldCount() == 12U,
                 L"C-03 a complete header yields twelve present fields");
        s.expect(facts.notRecordedFieldCount() == 0U && facts.notParsedFieldCount() == 0U,
                 L"C-03 a complete header reports no missing and no unparsed fields");
        s.expect(facts.hasAnyFact(), L"C-03 a complete header has facts");
        s.expect(facts.outcome.status == CollectionStatus::Success,
                 L"C-03 a fully readable header yields a Success outcome");
        s.expect(!facts.windowShorterThanFile,
                 L"C-03 a full window is not flagged as shorter than the file");
        s.expect(facts.code.consistent() && facts.parameters[2].consistent() &&
                     facts.uptime100ns.consistent(),
                 L"C-03 Present fields carry a value and only Present fields do");
    }

    // 'PAGE' 填充：每一格都读到了，但每一格都说"没写过"。
    {
        const std::vector<std::uint8_t> bytes = MakePageFilledKernelHeader();
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        s.expect(recognition.kind == DumpKind::KernelSmall,
                 L"C-03 a PAGE-filled but well-formed header is still recognized");
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));
        s.expect(facts.notRecordedFieldCount() == 12U,
                 L"C-03 every PAGE-filled field is reported as NotRecorded");
        s.expect(facts.presentFieldCount() == 0U,
                 L"C-03 red line: PAGE fill never becomes a present value");
        s.expect(facts.notParsedFieldCount() == 0U,
                 L"C-03 PAGE fill is NotRecorded, which is different from NotParsed");
        s.expect(!facts.hasAnyFact(),
                 L"C-03 a PAGE-filled header yields no facts at all");
        s.expect(facts.code.value == OptionalU64::unset() &&
                     facts.uptime100ns.value == OptionalU64::unset() &&
                     facts.parameters[0].value == OptionalU64::unset(),
                 L"C-03 red line: a missing field never carries a fabricated zero");
        s.expect(facts.outcome.status == CollectionStatus::Success,
                 L"C-03 reading every field successfully is Success even when nothing was recorded");
        s.expect(!facts.hasAnyFact() && facts.outcome.status == CollectionStatus::Success,
                 L"C-03 Success does not imply facts exist, and the UI must check hasAnyFact");
    }

    // 全 0 头：0 在哪些字段是真值、在哪些字段是"没填"，必须分得清。
    {
        const std::vector<std::uint8_t> bytes = MakeZeroedKernelHeader();
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));
        s.expect(facts.code.availability == DumpFieldAvailability::NotRecorded,
                 L"C-03 bugcheck code zero is not a valid stop code, so it is NotRecorded");
        s.expect(facts.parameters[0].availability == DumpFieldAvailability::Present &&
                     facts.parameters[1].availability == DumpFieldAvailability::Present &&
                     facts.parameters[2].availability == DumpFieldAvailability::Present &&
                     facts.parameters[3].availability == DumpFieldAvailability::Present,
                 L"C-03 all four zero parameters stay Present because zero is legal there");
        s.expect(facts.writerStatus.availability == DumpFieldAvailability::Present,
                 L"C-03 writer status zero stays Present because zero means healthy");
        s.expect(facts.crashTimeUtc100ns.availability == DumpFieldAvailability::NotRecorded &&
                     facts.uptime100ns.availability == DumpFieldAvailability::NotRecorded,
                 L"C-03 a zero crash time or uptime is treated as not recorded, never as a real time");
        s.expect(facts.targetOsBuild.availability == DumpFieldAvailability::NotRecorded &&
                     facts.targetOsMajor.availability == DumpFieldAvailability::NotRecorded &&
                     facts.processorCount.availability == DumpFieldAvailability::NotRecorded &&
                     facts.directoryTableBase.availability == DumpFieldAvailability::NotRecorded,
                 L"C-03 zeroed build, processor count and CR3 are reported as not recorded");
        s.expect(facts.presentFieldCount() == 5U && facts.notRecordedFieldCount() == 7U,
                 L"C-03 the zeroed header yields exactly five present and seven missing fields");
    }

    // 采集窗口比文件短：字段级 NotParsed，与 NotRecorded 分开。
    {
        const std::vector<std::uint8_t> bytes = MakeKernelHeader(4U, 0x8664U);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const std::span<const std::uint8_t> shortWindow = View(bytes).subspan(0, 0x1000);
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, shortWindow);
        s.expect(facts.uptime100ns.availability == DumpFieldAvailability::NotParsed &&
                     facts.writerStatus.availability == DumpFieldAvailability::NotParsed,
                 L"C-03 fields past the read window are NotParsed, not NotRecorded");
        s.expect(facts.code == DumpField::present(kFixtureBugCheckCode),
                 L"C-03 fields inside the read window are still read exactly");
        s.expect(facts.crashTimeUtc100ns == DumpField::present(kFixtureCrashTime),
                 L"C-03 the crash time at 0xFA8 is inside a 0x1000 window and is read");
        s.expect(facts.presentFieldCount() == 10U && facts.notParsedFieldCount() == 2U,
                 L"C-03 a short window yields exactly ten present and two unparsed fields");
        s.expect(facts.outcome.status == CollectionStatus::Partial,
                 L"C-03 a partially readable header yields a Partial outcome");
        s.expect(facts.windowShorterThanFile,
                 L"C-03 the report can tell a short window apart from a short file");
        s.expect(facts.bytesProvided == OptionalU64::of(0x1000ULL) &&
                     facts.fileSizeDeclared == OptionalU64::of(0x2000ULL),
                 L"C-03 both the window size and the declared file size are kept");
    }

    // 用户态 minidump：该格式不含 bugcheck 字段 -> NotRecorded（知道没有）。
    {
        const std::vector<std::uint8_t> bytes = MakeUserMinidump(0x400);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));
        s.expect(facts.notRecordedFieldCount() == 12U && facts.presentFieldCount() == 0U,
                 L"C-03 a user minidump reports all bugcheck fields as NotRecorded");
        s.expect(facts.outcome.status == CollectionStatus::Unsupported,
                 L"C-03 asking a user minidump for bugcheck facts is Unsupported, not Success");
        s.expect(facts.outcome.message == "dump.facts.user_minidump_has_no_bugcheck",
                 L"C-03 the unsupported reason is stated with a stable key");
    }

    // 随机文件：没跑解析 -> NotParsed（不知道有没有），与上一条区分。
    {
        const std::vector<std::uint8_t> bytes = MakeRandomBytes(4096U, 0x99ULL);
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));
        s.expect(facts.notParsedFieldCount() == 12U,
                 L"C-03 a non-dump reports all fields as NotParsed, never as NotRecorded");
        s.expect(facts.outcome.status == CollectionStatus::NotCollected,
                 L"C-03 a non-dump yields NotCollected rather than a failure of collection");
        s.expect(!StatusCarriesObservation(facts.outcome.status),
                 L"C-03 a NotCollected facts outcome carries no observation");
    }

    // 未支持的 32 位转储：也是 NotParsed，但 outcome 是 Unsupported。
    {
        const std::vector<std::uint8_t> bytes = MakeKernel32Header();
        const DumpRecognition recognition = RecognizeDump(View(bytes), OptionalU64::unset());
        const BugCheckFacts facts = ExtractBugCheckFacts(recognition, View(bytes));
        s.expect(facts.notParsedFieldCount() == 12U,
                 L"C-03 an unsupported format reports all fields as NotParsed");
        s.expect(facts.outcome.status == CollectionStatus::Unsupported,
                 L"C-03 an unsupported format yields Unsupported, distinct from NotCollected");
    }

    // 三态与默认构造。
    {
        const DumpField fresh;
        s.expect(fresh.availability == DumpFieldAvailability::NotParsed && !fresh.value.present,
                 L"C-03 a default-constructed field is NotParsed with no value");
        s.expect(DumpField::notRecorded().availability == DumpFieldAvailability::NotRecorded &&
                     !DumpField::notRecorded().value.present,
                 L"C-03 a NotRecorded field carries no value");
        s.expect(DumpField::present(0ULL).value == OptionalU64::of(0ULL),
                 L"C-03 Present(0) is a real zero and stays distinguishable from missing");
        s.expect(DumpField::present(0ULL) != DumpField::notRecorded(),
                 L"C-03 Present(0) never compares equal to NotRecorded");
        s.expect(DumpField::notRecorded() != DumpField::notParsed(),
                 L"C-03 NotRecorded never compares equal to NotParsed");
        s.expect(std::string(DumpFieldAvailabilityName(DumpFieldAvailability::NotParsed)) == "NotParsed" &&
                     std::string(DumpFieldAvailabilityName(DumpFieldAvailability::NotRecorded)) ==
                         "NotRecorded" &&
                     std::string(DumpFieldAvailabilityName(DumpFieldAvailability::Present)) == "Present",
                 L"C-03 all three availability states have distinct names");
        const BugCheckFacts freshFacts;
        s.expect(!freshFacts.hasAnyFact() && freshFacts.notParsedFieldCount() == 12U,
                 L"C-03 default-constructed facts contain nothing and claim nothing");
    }
}

// ---------------------------------------------------------------------------
// C-04 符号精确匹配
// ---------------------------------------------------------------------------
PdbIdentity MakePdb(std::uint8_t seed, std::uint32_t age) {
    PdbIdentity identity;
    for (std::size_t index = 0; index < identity.guid.size(); ++index) {
        identity.guid[index] = static_cast<std::uint8_t>(seed + index);
    }
    identity.age = age;
    identity.present = true;
    identity.pdbName = "ntkrnlmp.pdb";
    return identity;
}

void TestSymbolMatching(Reporter& s) {
    const PdbIdentity wanted = MakePdb(0x10U, 1U);
    const PdbIdentity sameBuild = MakePdb(0x10U, 1U);
    const PdbIdentity olderAge = MakePdb(0x10U, 2U);
    const PdbIdentity otherGuid = MakePdb(0x20U, 1U);
    const PdbIdentity absent;  // 默认构造：没有标识

    s.expect(SamePdbIdentity(wanted, sameBuild),
             L"C-04 identical GUID and age compare as the same PDB identity");
    s.expect(!SamePdbIdentity(wanted, olderAge),
             L"C-04 the same GUID with a different age is not the same PDB");
    s.expect(!SamePdbIdentity(wanted, otherGuid),
             L"C-04 a different GUID is not the same PDB");
    s.expect(!SamePdbIdentity(absent, absent),
             L"C-04 two empty identities never compare as matching");
    s.expect(!SamePdbIdentity(wanted, absent),
             L"C-04 a missing identity on either side blocks a match");

    // 四条 SymbolMatch 分支。
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::NotAttempted, absent, absent) ==
                 SymbolMatch::NotAttempted,
             L"C-04 a default attempt with empty identities is NotAttempted, never Matched");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::FileNotFound, wanted, absent) ==
                 SymbolMatch::Absent,
             L"C-04 a missing PDB file yields Absent");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::LoadFailed, wanted, absent) ==
                 SymbolMatch::Absent,
             L"C-04 a PDB that fails to load yields Absent, with the reason kept in attempt");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::FileLoaded, wanted, olderAge) ==
                 SymbolMatch::WrongVersion,
             L"C-04 a loaded PDB with a mismatched age is WrongVersion");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::FileLoaded, wanted, otherGuid) ==
                 SymbolMatch::WrongVersion,
             L"C-04 a loaded PDB with a mismatched GUID is WrongVersion");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::FileLoaded, absent, sameBuild) ==
                 SymbolMatch::WrongVersion,
             L"C-04 a loaded PDB that cannot be proven to match is never Matched");
    s.expect(DeriveSymbolMatch(SymbolLoadAttempt::FileLoaded, wanted, sameBuild) ==
                 SymbolMatch::Matched,
             L"C-04 a loaded PDB with matching GUID and age is Matched");

    // 错版 PDB 的红线：不给函数名、不给行号，只能到"模块+偏移"。
    ModuleSymbolState wrongVersionState;
    wrongVersionState.moduleName = "acme_filter.sys";
    wrongVersionState.wanted = wanted;
    wrongVersionState.loaded = olderAge;
    wrongVersionState.attempt = SymbolLoadAttempt::FileLoaded;
    wrongVersionState.match =
        DeriveSymbolMatch(wrongVersionState.attempt, wrongVersionState.wanted,
                          wrongVersionState.loaded);
    wrongVersionState.cacheSource = SymbolCacheSource::LocalCache;
    s.expect(wrongVersionState.match == SymbolMatch::WrongVersion,
             L"C-04 the wrong-version fixture really is WrongVersion");
    s.expect(!MayReportFunctionName(wrongVersionState),
             L"C-04 red line: a wrong-version PDB may not produce a definite function name");
    s.expect(!MayReportSourceLine(wrongVersionState),
             L"C-04 red line: a wrong-version PDB may not produce a source line");
    s.expect(AllowedAttribution(wrongVersionState, true) == SymbolAttribution::ModulePlusOffset,
             L"C-04 a wrong-version PDB with a known base allows only module plus offset");
    s.expect(AllowedAttribution(wrongVersionState, false) == SymbolAttribution::ModuleOnly,
             L"C-04 a wrong-version PDB without a base allows only the module name");

    ModuleSymbolState absentState;
    absentState.moduleName = "acme_filter.sys";
    absentState.attempt = SymbolLoadAttempt::FileNotFound;
    absentState.match = SymbolMatch::Absent;
    absentState.cacheSource = SymbolCacheSource::NotLoaded;
    s.expect(!MayReportFunctionName(absentState) && !MayReportSourceLine(absentState),
             L"C-04 a module without symbols may not produce a function name or line");
    s.expect(AllowedAttribution(absentState, true) == SymbolAttribution::ModulePlusOffset,
             L"C-04 a module without symbols still shows module plus offset");

    ModuleSymbolState matchedState;
    matchedState.moduleName = "ntoskrnl.exe";
    matchedState.wanted = wanted;
    matchedState.loaded = sameBuild;
    matchedState.attempt = SymbolLoadAttempt::FileLoaded;
    matchedState.match = SymbolMatch::Matched;
    matchedState.cacheSource = SymbolCacheSource::LocalDirectory;
    s.expect(MayReportFunctionName(matchedState) && MayReportSourceLine(matchedState),
             L"C-04 a matched PDB is allowed to produce a function name and line");
    s.expect(AllowedAttribution(matchedState, true) == SymbolAttribution::FunctionAndSourceLine,
             L"C-04 a matched PDB allows the full attribution level");

    const ModuleSymbolState freshState;
    s.expect(freshState.match == SymbolMatch::NotAttempted &&
                 freshState.attempt == SymbolLoadAttempt::NotAttempted &&
                 freshState.cacheSource == SymbolCacheSource::Unknown,
             L"C-04 a default-constructed symbol state claims nothing");
    s.expect(!MayReportFunctionName(freshState),
             L"C-04 a default-constructed symbol state may not produce a function name");
    s.expect(AllowedAttribution(freshState, false) == SymbolAttribution::ModuleOnly,
             L"C-04 a default-constructed symbol state allows only the module name");

    // FileNotFound 与 LoadFailed 都落到 Absent，但两者仍然可区分。
    s.expect(absentState.attempt != SymbolLoadAttempt::LoadFailed,
             L"C-04 the load attempt keeps file-not-found apart from load-failed");
    s.expect(std::string(SymbolLoadAttemptName(SymbolLoadAttempt::LoadFailed)) == "LoadFailed" &&
                 std::string(SymbolLoadAttemptName(SymbolLoadAttempt::FileNotFound)) ==
                     "FileNotFound",
             L"C-04 the two Absent causes have distinct names for the report");

    // 名字覆盖（每条分支）。
    s.expect(std::string(SymbolMatchName(SymbolMatch::NotAttempted)) == "NotAttempted" &&
                 std::string(SymbolMatchName(SymbolMatch::Absent)) == "Absent" &&
                 std::string(SymbolMatchName(SymbolMatch::WrongVersion)) == "WrongVersion" &&
                 std::string(SymbolMatchName(SymbolMatch::Matched)) == "Matched",
             L"C-04 every SymbolMatch state has a distinct name");
    s.expect(std::string(SymbolCacheSourceName(SymbolCacheSource::SymbolServer)) ==
                     "SymbolServer" &&
                 std::string(SymbolCacheSourceName(SymbolCacheSource::DumpEmbedded)) ==
                     "DumpEmbedded" &&
                 std::string(SymbolCacheSourceName(SymbolCacheSource::LocalCache)) == "LocalCache" &&
                 std::string(SymbolCacheSourceName(SymbolCacheSource::LocalDirectory)) ==
                     "LocalDirectory" &&
                 std::string(SymbolCacheSourceName(SymbolCacheSource::NotLoaded)) == "NotLoaded" &&
                 std::string(SymbolCacheSourceName(SymbolCacheSource::Unknown)) == "Unknown",
             L"C-04 every symbol cache source has a distinct name");
    s.expect(std::string(SymbolAttributionName(SymbolAttribution::ModuleOnly)) == "ModuleOnly" &&
                 std::string(SymbolAttributionName(SymbolAttribution::FunctionPlusOffset)) ==
                     "FunctionPlusOffset",
             L"C-04 attribution levels have distinct names");

    // 网络符号下载：三个前提缺一不可，默认全缺。
    {
        const SymbolServerPolicy fresh;
        s.expect(DecideSymbolServerFetch(fresh) == SymbolServerDecision::RejectNotEnabled,
                 L"C-04 network symbol download is off by default");

        SymbolServerPolicy enabled;
        enabled.userEnabled = true;
        s.expect(DecideSymbolServerFetch(enabled) == SymbolServerDecision::RejectNotCancellable,
                 L"C-04 an enabled but uncancellable symbol fetch is rejected");

        SymbolServerPolicy cancellable = enabled;
        cancellable.cancellable = true;
        s.expect(DecideSymbolServerFetch(cancellable) == SymbolServerDecision::RejectNoTimeBudget,
                 L"C-04 a symbol fetch without a time budget is rejected");

        SymbolServerPolicy byteBudgetOnly = cancellable;
        byteBudgetOnly.budget.maxBytes = OptionalU64::of(1ULL << 20U);
        s.expect(DecideSymbolServerFetch(byteBudgetOnly) == SymbolServerDecision::RejectNoTimeBudget,
                 L"C-04 a byte budget is not a time budget for a blocking symbol server");

        SymbolServerPolicy zeroTime = cancellable;
        zeroTime.budget.maxDurationNanos = OptionalU64::of(0ULL);
        s.expect(DecideSymbolServerFetch(zeroTime) == SymbolServerDecision::RejectNoTimeBudget,
                 L"C-04 a zero time budget is not a usable time limit");

        SymbolServerPolicy allowed = cancellable;
        allowed.budget.maxDurationNanos = OptionalU64::of(15ULL * 1000000000ULL);
        s.expect(DecideSymbolServerFetch(allowed) == SymbolServerDecision::Allow,
                 L"C-04 an enabled, cancellable, time-bounded symbol fetch is allowed");
        s.expect(allowed.budget.bounded(),
                 L"C-04 the allowed symbol fetch budget really is bounded");
        s.expect(std::string(SymbolServerDecisionName(SymbolServerDecision::Allow)) == "Allow",
                 L"C-04 symbol server decisions have stable names");
    }
}

// ---------------------------------------------------------------------------
// C-05 栈与模块
// ---------------------------------------------------------------------------
StackFrame MakeUnwoundFrame(std::uint64_t address, const char* moduleName) {
    StackFrame frame;
    frame.address = OptionalU64::of(address);
    frame.stackPointer = OptionalU64::of(address - 0x1000ULL);
    frame.moduleName = moduleName;
    frame.moduleBase = OptionalU64::of(address & ~0xFFFFULL);
    frame.offsetInModule = OptionalU64::of(address & 0xFFFFULL);
    frame.unwindState = UnwindState::Unwound;
    return frame;
}

void TestStackAndUnwind(Reporter& s) {
    // 展开状态的四条分支。
    s.expect(UnwindStateIsTerminal(UnwindState::TruncatedNoData) &&
                 UnwindStateIsTerminal(UnwindState::TruncatedCorrupt),
             L"C-05 both truncation states are terminal frame boundaries");
    s.expect(!UnwindStateIsTerminal(UnwindState::Unwound) &&
                 !UnwindStateIsTerminal(UnwindState::Guessed),
             L"C-05 unwound and guessed frames are not boundaries");
    s.expect(UnwindStateIsTrustworthy(UnwindState::Unwound),
             L"C-05 only an actually unwound frame is trustworthy");
    s.expect(!UnwindStateIsTrustworthy(UnwindState::Guessed) &&
                 !UnwindStateIsTrustworthy(UnwindState::TruncatedNoData) &&
                 !UnwindStateIsTrustworthy(UnwindState::TruncatedCorrupt),
             L"C-05 a guessed or truncated frame is never trustworthy");
    s.expect(std::string(UnwindStateName(UnwindState::TruncatedNoData)) == "TruncatedNoData" &&
                 std::string(UnwindStateName(UnwindState::TruncatedCorrupt)) ==
                     "TruncatedCorrupt" &&
                 std::string(UnwindStateName(UnwindState::Guessed)) == "Guessed" &&
                 std::string(UnwindStateName(UnwindState::Unwound)) == "Unwound",
             L"C-05 all four unwind states have distinct names");

    {
        const StackFrame fresh;
        s.expect(fresh.unwindState == UnwindState::TruncatedNoData &&
                     fresh.symbolMatch == SymbolMatch::NotAttempted && !fresh.argsComplete &&
                     !fresh.attributionAmbiguous,
                 L"C-05 a default frame is a boundary with no symbols and no claims");
    }

    // 合法栈：可信帧 + 无符号帧 + 明确的截断边界。
    StackTrace trace;
    {
        StackFrame top = MakeUnwoundFrame(0xFFFFF80312345678ULL, "ntoskrnl.exe");
        top.symbolMatch = SymbolMatch::Matched;
        top.functionName = "KeBugCheckEx";
        top.functionOffset = OptionalU64::of(0x1CULL);
        top.sourceFile = "d:\\rs\\ke\\bugcheck.c";
        top.sourceLine = OptionalU64::of(1234ULL);
        top.availableArgs = {OptionalU64::of(0x7EULL), OptionalU64::of(0ULL)};
        top.argsComplete = true;
        trace.frames.push_back(top);

        StackFrame middle = MakeUnwoundFrame(0xFFFFF8031999ABCDULL, "acme_filter.sys");
        middle.symbolMatch = SymbolMatch::Absent;
        middle.availableArgs = {OptionalU64::of(1ULL), OptionalU64::unset()};
        middle.argsComplete = false;  // 有未知参数，因此不敢声称完整
        trace.frames.push_back(middle);

        StackFrame boundary;
        boundary.address = OptionalU64::of(0xFFFFF80311110000ULL);
        boundary.unwindState = UnwindState::TruncatedNoData;
        trace.frames.push_back(boundary);
    }
    trace.outcome = CollectionOutcome::success();
    s.expect(ValidateStackTrace(trace) == StackValidation::Ok,
             L"C-05 a well-formed stack with an explicit boundary validates");
    s.expect(trace.unwoundCount() == 2U && trace.guessedCount() == 0U &&
                 trace.truncatedCount() == 1U,
             L"C-05 unwound, guessed and truncated frames are counted separately");

    // 截断之后再接帧 = 拼接猜测帧。
    {
        StackTrace spliced = trace;
        spliced.frames.push_back(MakeUnwoundFrame(0xFFFFF80300000000ULL, "guessed.sys"));
        s.expect(ValidateStackTrace(spliced) == StackValidation::FramesAfterTruncation,
                 L"C-05 red line: appending frames after a truncation boundary is rejected");
    }

    // 无匹配符号却给了函数名 / 行号。
    {
        StackTrace bad = trace;
        bad.frames[1].functionName = "AcmeFilterDispatch";
        s.expect(ValidateStackTrace(bad) == StackValidation::FunctionNameWithoutMatchedSymbols,
                 L"C-05 a function name without matched symbols is rejected");
    }
    {
        StackTrace bad = trace;
        bad.frames[1].symbolMatch = SymbolMatch::WrongVersion;
        bad.frames[1].sourceLine = OptionalU64::of(77ULL);
        s.expect(ValidateStackTrace(bad) == StackValidation::SourceLineWithoutMatchedSymbols,
                 L"C-05 red line: a wrong-version PDB may not contribute a source line to a frame");
    }
    {
        StackTrace bad = trace;
        bad.frames[1].symbolMatch = SymbolMatch::Absent;
        bad.frames[1].sourceFile = "guessed.c";
        s.expect(ValidateStackTrace(bad) == StackValidation::SourceLineWithoutMatchedSymbols,
                 L"C-05 a source file without matched symbols is rejected too");
    }

    // 归因歧义必须保留，不许抹平。
    // 歧义只可能出现在**有匹配符号**的帧上：没有匹配符号时连一个候选都不该有
    // （下面那一条断言就是这个），所以这里用 frames[0]（Matched）而不是
    // frames[1]（Absent）—— 原来那版用 Absent 帧承载候选，自身就是一份违规输入。
    {
        StackTrace ambiguous = trace;
        ambiguous.frames[0].attributionAmbiguous = true;
        ambiguous.frames[0].candidateFunctions = {"AcmeInline"};
        s.expect(ValidateStackTrace(ambiguous) == StackValidation::AmbiguityCollapsed,
                 L"C-05 declaring ambiguity while keeping one candidate is rejected");
        ambiguous.frames[0].candidateFunctions = {"AcmeInline", "AcmeOuter"};
        s.expect(ValidateStackTrace(ambiguous) == StackValidation::Ok,
                 L"C-05 ambiguity with at least two candidates is preserved and accepted");
    }

    // C-04 红线对复数一样有效：错版 PDB 解出来的函数名挂上"候选"两个字，
    // 仍然是错版符号在往 UI 上写函数名，只是从单数变复数。
    {
        StackTrace candidates = trace;
        candidates.frames[1].symbolMatch = SymbolMatch::WrongVersion;
        candidates.frames[1].attributionAmbiguous = true;
        candidates.frames[1].candidateFunctions = {"AcmeStartIo", "AcmeCompleteIrp"};
        s.expect(ValidateStackTrace(candidates) ==
                     StackValidation::CandidatesWithoutMatchedSymbols,
                 L"C-04 red line: a wrong-version PDB may not contribute candidate function names");
        candidates.frames[1].symbolMatch = SymbolMatch::Absent;
        s.expect(ValidateStackTrace(candidates) ==
                     StackValidation::CandidatesWithoutMatchedSymbols,
                 L"C-04 candidates on a frame with no symbols at all are rejected the same way");
        candidates.frames[1].symbolMatch = SymbolMatch::NotAttempted;
        s.expect(ValidateStackTrace(candidates) ==
                     StackValidation::CandidatesWithoutMatchedSymbols,
                 L"C-04 candidates on a frame whose symbols were never attempted are rejected");
        candidates.frames[1].symbolMatch = SymbolMatch::Matched;
        s.expect(ValidateStackTrace(candidates) == StackValidation::Ok,
                 L"C-05 two candidates on a matched frame are preserved and accepted");
    }

    // 函数内偏移与函数名同罪：没有解析出函数，就没有"函数内偏移"这回事。
    {
        StackTrace offsetOnly = trace;
        offsetOnly.frames[1].symbolMatch = SymbolMatch::Absent;
        offsetOnly.frames[1].functionOffset = OptionalU64::of(0x40ULL);
        s.expect(ValidateStackTrace(offsetOnly) ==
                     StackValidation::FunctionNameWithoutMatchedSymbols,
                 L"C-04 a function-relative offset without matched symbols is rejected too");
    }

    // 参数不全却声称齐全。
    {
        StackTrace bad = trace;
        bad.frames[1].argsComplete = true;
        s.expect(ValidateStackTrace(bad) == StackValidation::IncompleteArgumentsClaimedComplete,
                 L"C-05 claiming complete arguments while one is unknown is rejected");
        s.expect(!bad.frames[1].availableArgs[1].present,
                 L"C-05 an unknown argument stays unset instead of being filled with zero");
    }

    // 纯栈扫描结果：合法，但一帧都不可信。
    {
        StackTrace guessed;
        for (std::uint64_t index = 0; index < 5U; ++index) {
            StackFrame frame = MakeUnwoundFrame(0xFFFFF80300010000ULL + index * 0x100ULL,
                                                "unknown.sys");
            frame.unwindState = UnwindState::Guessed;
            guessed.frames.push_back(frame);
        }
        s.expect(ValidateStackTrace(guessed) == StackValidation::Ok,
                 L"C-05 a scan-only stack is structurally valid");
        s.expect(guessed.unwoundCount() == 0U && guessed.guessedCount() == 5U,
                 L"C-05 a scan-only stack reports zero unwound frames so the UI cannot call it a call stack");
    }

    // 损坏截断：与"没有数据"是两种边界。
    {
        StackTrace corrupt;
        corrupt.frames.push_back(MakeUnwoundFrame(0xFFFFF80312340000ULL, "ntoskrnl.exe"));
        StackFrame boundary;
        boundary.unwindState = UnwindState::TruncatedCorrupt;
        corrupt.frames.push_back(boundary);
        s.expect(ValidateStackTrace(corrupt) == StackValidation::Ok,
                 L"C-05 a corrupt-truncation boundary is a valid terminal frame");
        s.expect(corrupt.frames[1].unwindState != UnwindState::TruncatedNoData,
                 L"C-05 corrupt truncation stays distinct from missing-data truncation");
    }

    {
        const StackTrace empty;
        s.expect(ValidateStackTrace(empty) == StackValidation::Ok &&
                     empty.unwoundCount() == 0U && empty.guessedCount() == 0U,
                 L"C-05 an empty stack is valid and claims no frames");
        s.expect(empty.outcome.status == CollectionStatus::NotCollected,
                 L"C-05 a default stack trace has not been collected");
    }

    s.expect(std::string(StackValidationName(StackValidation::Ok)) == "Ok" &&
                 std::string(StackValidationName(StackValidation::FramesAfterTruncation)) ==
                     "FramesAfterTruncation" &&
                 std::string(StackValidationName(
                     StackValidation::IncompleteArgumentsClaimedComplete)) ==
                     "IncompleteArgumentsClaimedComplete" &&
                 std::string(StackValidationName(StackValidation::AmbiguityCollapsed)) ==
                     "AmbiguityCollapsed" &&
                 std::string(StackValidationName(
                     StackValidation::CandidatesWithoutMatchedSymbols)) ==
                     "CandidatesWithoutMatchedSymbols" &&
                 std::string(StackValidationName(
                     StackValidation::FunctionNameWithoutMatchedSymbols)) !=
                     std::string(StackValidationName(
                         StackValidation::CandidatesWithoutMatchedSymbols)),
             L"C-05 every stack validation verdict has a distinct name");
}

// ---------------------------------------------------------------------------
// C-06 可疑模块解释
// ---------------------------------------------------------------------------
ModuleEvidenceItem MakeEvidence(ModuleEvidenceKind kind,
                                const char* moduleName,
                                UnwindState frameState,
                                std::uint64_t frameIndex) {
    ModuleEvidenceItem item;
    item.kind = kind;
    item.moduleName = moduleName;
    item.frameUnwindState = frameState;
    item.frameIndex = OptionalU64::of(frameIndex);
    item.detail = "raw text from the dump";
    return item;
}

void TestSuspectExplanation(Reporter& s) {
    s.expect(IsWellKnownSystemModuleName("ntoskrnl.exe"),
             L"C-06 ntoskrnl.exe is recognized as a well-known system module");
    s.expect(IsWellKnownSystemModuleName("\\SystemRoot\\system32\\ntoskrnl.exe"),
             L"C-06 a full NT path to ntoskrnl is still recognized");
    s.expect(IsWellKnownSystemModuleName("C:/Windows/System32/HAL.DLL"),
             L"C-06 the system module check folds ASCII case and both separators");
    s.expect(!IsWellKnownSystemModuleName("acme_filter.sys"),
             L"C-06 a third-party driver is not a well-known system module");
    s.expect(!IsWellKnownSystemModuleName("ntoskrnl.exe.evil.sys"),
             L"C-06 a look-alike name is not treated as the system module");
    s.expect(!IsWellKnownSystemModuleName(""),
             L"C-06 an empty module name is not a system module");

    // 默认构造的分组不许产生任何线索。
    {
        const ModuleEvidenceGroup fresh;
        s.expect(ClassifyLead(fresh) == InvestigationLead::Undetermined,
                 L"C-06 a default-constructed evidence group yields Undetermined");
        s.expect(fresh.evidenceCount() == 0U,
                 L"C-06 a default-constructed evidence group holds no evidence");
    }

    // 三类证据在分组里分开存放。
    {
        std::vector<ModuleEvidenceItem> items;
        items.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "acme_filter.sys",
                                     UnwindState::Unwound, 2U));
        items.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule, "acme_filter.sys",
                                     UnwindState::Unwound, 0U));
        items.push_back(MakeEvidence(ModuleEvidenceKind::VerifierReported, "acme_filter.sys",
                                     UnwindState::Unwound, 0U));
        items.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "NTOSKRNL.EXE",
                                     UnwindState::Unwound, 1U));
        items.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "ntoskrnl.exe",
                                     UnwindState::Unwound, 3U));
        const std::vector<ModuleEvidenceGroup> groups = GroupModuleEvidence(items);
        s.expect(groups.size() == 2U,
                 L"C-06 evidence is grouped per module and ASCII case variants merge");
        std::size_t acmeIndex = groups.size();
        std::size_t kernelIndex = groups.size();
        for (std::size_t index = 0; index < groups.size(); ++index) {
            if (groups[index].moduleKey == "acme_filter.sys") {
                acmeIndex = index;
            }
            if (groups[index].moduleKey == "ntoskrnl.exe") {
                kernelIndex = index;
            }
        }
        s.expect(acmeIndex < groups.size() && kernelIndex < groups.size(),
                 L"C-06 both expected module groups are present with lowercase keys");
        if (acmeIndex < groups.size() && kernelIndex < groups.size()) {
            const ModuleEvidenceGroup& acme = groups[acmeIndex];
            s.expect(acme.onStack.size() == 1U && acme.faultingIp.size() == 1U &&
                         acme.verifier.size() == 1U,
                     L"C-06 the three evidence kinds stay in three separate lists");
            s.expect(acme.evidenceCount() == 3U,
                     L"C-06 the evidence count adds up across the three lists");
            s.expect(!acme.isWellKnownSystemModule,
                     L"C-06 a third-party driver group is not flagged as a system module");
            s.expect(acme.onStack[0].frameIndex == OptionalU64::of(2U),
                     L"C-06 each evidence item keeps the frame it came from");
            s.expect(acme.onStack[0].detail == "raw text from the dump",
                     L"C-06 the raw detail text is kept verbatim, not rewritten");

            const ModuleEvidenceGroup& kernel = groups[kernelIndex];
            s.expect(kernel.onStack.size() == 2U,
                     L"C-06 both case spellings of ntoskrnl land in the same group");
            s.expect(kernel.isWellKnownSystemModule,
                     L"C-06 the ntoskrnl group is flagged as a well-known system module");
            s.expect(kernel.moduleName == "NTOSKRNL.EXE",
                     L"C-06 the display name keeps the original spelling of the first occurrence");
        }
    }

    // ClassifyLead 的五条分支。
    // 每个分组都显式给 moduleKey：GroupModuleEvidence 产出的分组一定有键，
    // 没有键的分组根本没有身份，ClassifyLead 对它只会回答"无法确定"（见下面那一段）。
    {
        ModuleEvidenceGroup thirdPartyStack;
        thirdPartyStack.moduleName = "acme_filter.sys";
        thirdPartyStack.moduleKey = "acme_filter.sys";
        thirdPartyStack.onStack.push_back(MakeEvidence(ModuleEvidenceKind::OnStack,
                                                       "acme_filter.sys",
                                                       UnwindState::Unwound, 2U));
        s.expect(ClassifyLead(thirdPartyStack) == InvestigationLead::StackPresenceOnly,
                 L"C-06 a third-party module on a trustworthy frame is a weak lead only");

        ModuleEvidenceGroup guessedOnly;
        guessedOnly.moduleName = "acme_filter.sys";
        guessedOnly.moduleKey = "acme_filter.sys";
        guessedOnly.onStack.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "acme_filter.sys",
                                                   UnwindState::Guessed, 9U));
        s.expect(ClassifyLead(guessedOnly) == InvestigationLead::Undetermined,
                 L"C-06 a module seen only in scan-guessed frames is not a lead at all");

        ModuleEvidenceGroup faulting;
        faulting.moduleName = "acme_filter.sys";
        faulting.moduleKey = "acme_filter.sys";
        faulting.faultingIp.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule,
                                                   "acme_filter.sys", UnwindState::Unwound, 0U));
        s.expect(ClassifyLead(faulting) == InvestigationLead::FaultingIpAttributed,
                 L"C-06 a faulting IP inside a third-party module is an actionable lead");

        ModuleEvidenceGroup verifier;
        verifier.moduleName = "acme_filter.sys";
        verifier.moduleKey = "acme_filter.sys";
        verifier.verifier.push_back(MakeEvidence(ModuleEvidenceKind::VerifierReported,
                                                  "acme_filter.sys", UnwindState::Unwound, 0U));
        s.expect(ClassifyLead(verifier) == InvestigationLead::VerifierNamed,
                 L"C-06 a Verifier report is the strongest lead");

        ModuleEvidenceGroup systemStack;
        systemStack.moduleName = "ntoskrnl.exe";
        systemStack.moduleKey = "ntoskrnl.exe";
        systemStack.isWellKnownSystemModule = true;
        systemStack.onStack.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "ntoskrnl.exe",
                                                   UnwindState::Unwound, 0U));
        s.expect(ClassifyLead(systemStack) == InvestigationLead::SystemModuleOnly,
                 L"C-06 red line: ntoskrnl on the stack is explicitly not a lead");

        ModuleEvidenceGroup systemFaulting;
        systemFaulting.moduleName = "ntoskrnl.exe";
        systemFaulting.moduleKey = "ntoskrnl.exe";
        systemFaulting.isWellKnownSystemModule = true;
        systemFaulting.faultingIp.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule,
                                                          "ntoskrnl.exe", UnwindState::Unwound, 0U));
        s.expect(ClassifyLead(systemFaulting) == InvestigationLead::SystemModuleOnly,
                 L"C-06 red line: a faulting IP inside ntoskrnl is not automatically the cause");
    }

    // 故障 IP 证据自己的前提。一帧被判定为"数据自相矛盾"（TruncatedCorrupt）却仍据此
    // 把某个第三方驱动升级成可查线索，是拿自己都不信的数据下结论。
    // onStack 分支一直有这道门槛，faultingIp 分支以前完全没有。
    {
        ModuleEvidenceGroup corruptFrame;
        corruptFrame.moduleName = "acme_filter.sys";
        corruptFrame.moduleKey = "acme_filter.sys";
        corruptFrame.faultingIp.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule,
                                                       "acme_filter.sys",
                                                       UnwindState::TruncatedCorrupt, 0U));
        s.expect(ClassifyLead(corruptFrame) == InvestigationLead::Undetermined,
                 L"C-06 a faulting IP read off a self-contradictory frame is not an actionable lead");

        ModuleEvidenceGroup noData = corruptFrame;
        noData.faultingIp[0].frameUnwindState = UnwindState::TruncatedNoData;
        s.expect(ClassifyLead(noData) == InvestigationLead::Undetermined,
                 L"C-06 a faulting IP with no frame data behind it is not an actionable lead");

        ModuleEvidenceGroup guessedFrame = corruptFrame;
        guessedFrame.faultingIp[0].frameUnwindState = UnwindState::Guessed;
        s.expect(ClassifyLead(guessedFrame) == InvestigationLead::Undetermined,
                 L"C-06 a faulting IP guessed from a stack scan is not an actionable lead");

        // 真正的故障 IP 来自 trap frame / context record，与展开质量无关。
        // 这一位为真时才免检 —— 默认是 false，默认不免检。
        ModuleEvidenceGroup fromContext = corruptFrame;
        fromContext.faultingIp[0].ipFromContextRecord = true;
        s.expect(ClassifyLead(fromContext) == InvestigationLead::FaultingIpAttributed,
                 L"C-06 a faulting IP taken from the context record is an actionable lead");
        s.expect(!ModuleEvidenceItem{}.ipFromContextRecord,
                 L"C-06 evidence does not claim a context-record IP by default");

        // 故障 IP 站不住脚不等于这一组消失：栈上还有可信帧就仍是弱线索。
        ModuleEvidenceGroup alsoOnStack = corruptFrame;
        alsoOnStack.onStack.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "acme_filter.sys",
                                                   UnwindState::Unwound, 3U));
        s.expect(ClassifyLead(alsoOnStack) == InvestigationLead::StackPresenceOnly,
                 L"C-06 an unfounded faulting IP falls back to the stack evidence, not to nothing");
    }

    // 连名字都没有的模块拿不到线索。空模块名经过 GroupModuleEvidence 会产出一个
    // 键为空的分组 —— 那样一组的"可查线索"没有任何可查的对象。
    {
        std::vector<ModuleEvidenceItem> nameless;
        nameless.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule, "",
                                        UnwindState::Unwound, 0U));
        const std::vector<ModuleEvidenceGroup> groups = GroupModuleEvidence(nameless);
        s.expect(groups.size() == 1U && groups[0].moduleKey.empty(),
                 L"C-06 an empty module name still forms exactly one keyless group");
        s.expect(groups.size() == 1U && ClassifyLead(groups[0]) == InvestigationLead::Undetermined,
                 L"C-06 red line: a module with no name at all never becomes an actionable lead");
        const SuspectReport report =
            BuildSuspectReport(groups, CollectionOutcome::success());
        s.expect(report.conclusion == AnalysisConclusion::Indeterminate,
                 L"C-06 a nameless module group does not push the report to an actionable conclusion");
    }

    // 没有观测 -> NoEvidence，且即便传入了 verifier 组也一律降为 Undetermined。
    {
        std::vector<ModuleEvidenceGroup> groups;
        ModuleEvidenceGroup verifier;
        verifier.moduleName = "acme_filter.sys";
        verifier.moduleKey = "acme_filter.sys";
        verifier.verifier.push_back(MakeEvidence(ModuleEvidenceKind::VerifierReported,
                                                  "acme_filter.sys", UnwindState::Unwound, 0U));
        groups.push_back(verifier);

        CollectionOutcome noStack = CollectionOutcome::notCollected();
        const SuspectReport report = BuildSuspectReport(groups, noStack);
        s.expect(report.conclusion == AnalysisConclusion::NoEvidence,
                 L"C-06 red line: no stack observation yields NoEvidence, never a verdict");
        s.expect(report.leads.size() == 1U &&
                     report.leads[0].lead == InvestigationLead::Undetermined,
                 L"C-06 red line: without an observation even a Verifier group stays Undetermined");
        s.expect(report.limitationKeys.size() == 1U &&
                     report.limitationKeys[0] == "dump.suspect.no_stack_observation",
                 L"C-06 the missing observation is stated explicitly in the limitations");
    }

    // 只有 ntoskrnl：无法确定。
    {
        std::vector<ModuleEvidenceGroup> groups;
        ModuleEvidenceGroup kernel;
        kernel.moduleName = "ntoskrnl.exe";
        kernel.moduleKey = "ntoskrnl.exe";
        kernel.isWellKnownSystemModule = true;
        kernel.onStack.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "ntoskrnl.exe",
                                              UnwindState::Unwound, 0U));
        kernel.faultingIp.push_back(MakeEvidence(ModuleEvidenceKind::FaultingIpModule,
                                                  "ntoskrnl.exe", UnwindState::Unwound, 0U));
        groups.push_back(kernel);

        const SuspectReport report = BuildSuspectReport(groups, CollectionOutcome::success());
        s.expect(report.conclusion == AnalysisConclusion::Indeterminate,
                 L"C-06 an ntoskrnl-only dump concludes Indeterminate, not a root cause");
        s.expect(report.conclusion != AnalysisConclusion::NoDifferenceObserved,
                 L"C-06 a crash dump never concludes no-difference-observed");
        bool sawSystemOnlyKey = false;
        bool sawInsufficientKey = false;
        for (const std::string& key : report.limitationKeys) {
            sawSystemOnlyKey = sawSystemOnlyKey || key == "dump.suspect.system_module_only";
            sawInsufficientKey = sawInsufficientKey || key == "dump.suspect.insufficient_evidence";
        }
        s.expect(sawSystemOnlyKey && sawInsufficientKey,
                 L"C-06 the report states both that evidence is insufficient and why");
        s.expect(report.leads[0].lead == InvestigationLead::SystemModuleOnly,
                 L"C-06 the ntoskrnl lead is classified as system-module-only");
    }

    // 有 Verifier 点名的第三方驱动：可查线索。
    {
        std::vector<ModuleEvidenceItem> items;
        items.push_back(MakeEvidence(ModuleEvidenceKind::VerifierReported, "acme_filter.sys",
                                     UnwindState::Unwound, 0U));
        items.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "ntoskrnl.exe",
                                     UnwindState::Unwound, 0U));
        const SuspectReport report =
            BuildSuspectReport(GroupModuleEvidence(items), CollectionOutcome::success());
        s.expect(report.conclusion == AnalysisConclusion::DifferenceObserved,
                 L"C-06 a Verifier-named third-party driver yields an actionable conclusion");
        s.expect(report.leads.size() == 2U,
                 L"C-06 both the named driver and the system module keep their own entries");
    }

    // Partial 采集必须在限制里说出来。
    {
        std::vector<ModuleEvidenceItem> items;
        items.push_back(MakeEvidence(ModuleEvidenceKind::OnStack, "acme_filter.sys",
                                     UnwindState::Unwound, 1U));
        CollectionOutcome partial;
        partial.status = CollectionStatus::Partial;
        const SuspectReport report = BuildSuspectReport(GroupModuleEvidence(items), partial);
        bool sawPartialKey = false;
        bool sawStackOnlyKey = false;
        for (const std::string& key : report.limitationKeys) {
            sawPartialKey = sawPartialKey || key == "dump.suspect.stack_partial";
            sawStackOnlyKey = sawStackOnlyKey || key == "dump.suspect.stack_presence_only";
        }
        s.expect(sawPartialKey && sawStackOnlyKey,
                 L"C-06 a partial stack collection is disclosed alongside the weak-lead note");
        s.expect(report.conclusion == AnalysisConclusion::Indeterminate,
                 L"C-06 stack presence alone does not become an actionable conclusion");
    }

    // 空证据集合 + 有观测：明确写"没有模块证据"。
    {
        const SuspectReport report =
            BuildSuspectReport(std::vector<ModuleEvidenceGroup>{}, CollectionOutcome::success());
        bool sawNoModuleKey = false;
        for (const std::string& key : report.limitationKeys) {
            sawNoModuleKey = sawNoModuleKey || key == "dump.suspect.no_module_evidence";
        }
        s.expect(sawNoModuleKey,
                 L"C-06 an empty but observed evidence set is stated, not silently positive");
        s.expect(report.conclusion == AnalysisConclusion::Indeterminate,
                 L"C-06 an empty evidence set is Indeterminate, not NoDifferenceObserved");
    }

    s.expect(std::string(InvestigationLeadName(InvestigationLead::Undetermined)) ==
                     "Undetermined" &&
                 std::string(InvestigationLeadName(InvestigationLead::SystemModuleOnly)) ==
                     "SystemModuleOnly" &&
                 std::string(InvestigationLeadName(InvestigationLead::StackPresenceOnly)) ==
                     "StackPresenceOnly" &&
                 std::string(InvestigationLeadName(InvestigationLead::FaultingIpAttributed)) ==
                     "FaultingIpAttributed" &&
                 std::string(InvestigationLeadName(InvestigationLead::VerifierNamed)) ==
                     "VerifierNamed",
             L"C-06 every investigation lead level has a distinct name");
    s.expect(std::string(ModuleEvidenceKindName(ModuleEvidenceKind::OnStack)) == "OnStack" &&
                 std::string(ModuleEvidenceKindName(ModuleEvidenceKind::FaultingIpModule)) ==
                     "FaultingIpModule" &&
                 std::string(ModuleEvidenceKindName(ModuleEvidenceKind::VerifierReported)) ==
                     "VerifierReported",
             L"C-06 the three evidence kinds have distinct names");

    // 越权判定字段的文案检查：线索等级名里不许出现数字或百分号，
    // 否则很容易被读成"未校准的责任比例"。
    {
        bool clean = true;
        for (const InvestigationLead lead :
             {InvestigationLead::Undetermined, InvestigationLead::SystemModuleOnly,
              InvestigationLead::StackPresenceOnly, InvestigationLead::FaultingIpAttributed,
              InvestigationLead::VerifierNamed}) {
            const std::string name = InvestigationLeadName(lead);
            for (const char value : name) {
                if ((value >= '0' && value <= '9') || value == '%') {
                    clean = false;
                }
            }
        }
        s.expect(clean,
                 L"C-06 lead levels carry no digits or percent signs, so they cannot read as blame shares");
    }
}

// ---------------------------------------------------------------------------
// C-07 缺失内存的边界
// ---------------------------------------------------------------------------
void TestContentAvailability(Reporter& s) {
    {
        const DumpContentAvailability fresh;
        bool allUnknown = true;
        for (const ContentCategory category :
             {ContentCategory::IrpObjects, ContentCategory::LockObjects,
              ContentCategory::FullProcessSpace, ContentCategory::PoolMemory,
              ContentCategory::KernelModuleList, ContentCategory::ThreadStacks,
              ContentCategory::PhysicalMemory}) {
            allUnknown = allUnknown && fresh.presenceOf(category) == ContentPresence::Unknown;
        }
        s.expect(allUnknown,
                 L"C-07 a default-constructed availability table is entirely Unknown");
        s.expect(QueryContent(fresh, ContentCategory::IrpObjects) ==
                     ContentQueryResult::UnknownAvailability,
                 L"C-07 an unjudged category answers UnknownAvailability, never 'not there'");
    }

    // small dump：查 IRP 必须回"转储未包含"。
    {
        const DumpContentAvailability small = DeriveAvailabilityFromKind(DumpKind::KernelSmall);
        s.expect(QueryContent(small, ContentCategory::IrpObjects) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 asking a small dump for IRP objects answers 'not included in dump'");
        s.expect(QueryContent(small, ContentCategory::LockObjects) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 asking a small dump for lock objects answers 'not included in dump'");
        s.expect(QueryContent(small, ContentCategory::FullProcessSpace) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 a small dump does not contain a full process address space");
        s.expect(QueryContent(small, ContentCategory::PoolMemory) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 a small dump does not contain pool memory");
        s.expect(QueryContent(small, ContentCategory::PhysicalMemory) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 a small dump does not contain physical memory");
        s.expect(QueryContent(small, ContentCategory::KernelModuleList) ==
                     ContentQueryResult::UnknownAvailability,
                 L"C-07 a small dump's module list is Unknown until actually parsed, never assumed present");
        s.expect(QueryContent(small, ContentCategory::ThreadStacks) ==
                     ContentQueryResult::UnknownAvailability,
                 L"C-07 a small dump's thread stacks are Unknown until actually parsed");
    }

    // kernel memory dump：单靠类型推不出任何一项"确定包含"。
    {
        const DumpContentAvailability memory = DeriveAvailabilityFromKind(DumpKind::KernelMemory);
        bool allUnknown = true;
        for (const ContentCategory category :
             {ContentCategory::IrpObjects, ContentCategory::LockObjects,
              ContentCategory::FullProcessSpace, ContentCategory::PoolMemory,
              ContentCategory::KernelModuleList, ContentCategory::ThreadStacks,
              ContentCategory::PhysicalMemory}) {
            allUnknown = allUnknown && QueryContent(memory, category) ==
                                           ContentQueryResult::UnknownAvailability;
        }
        s.expect(allUnknown,
                 L"C-07 a kernel memory dump promises nothing by type alone; everything stays Unknown");
    }

    // 用户态转储：内核对象一定不在里面。
    {
        const DumpContentAvailability user = DeriveAvailabilityFromKind(DumpKind::UserMinidump);
        s.expect(QueryContent(user, ContentCategory::IrpObjects) ==
                         ContentQueryResult::NotIncludedInDump &&
                     QueryContent(user, ContentCategory::PoolMemory) ==
                         ContentQueryResult::NotIncludedInDump &&
                     QueryContent(user, ContentCategory::KernelModuleList) ==
                         ContentQueryResult::NotIncludedInDump,
                 L"C-07 a user minidump reports kernel-only categories as not included");
        s.expect(QueryContent(user, ContentCategory::FullProcessSpace) ==
                     ContentQueryResult::UnknownAvailability,
                 L"C-07 whether a user minidump has full memory depends on the writer flags");
    }

    // 认不出来的文件：不许因为解析失败就说"不包含"。
    {
        const DumpContentAvailability unknown = DeriveAvailabilityFromKind(DumpKind::NotADump);
        const DumpContentAvailability unsupported =
            DeriveAvailabilityFromKind(DumpKind::Unsupported);
        s.expect(QueryContent(unknown, ContentCategory::IrpObjects) ==
                         ContentQueryResult::UnknownAvailability &&
                     QueryContent(unsupported, ContentCategory::PoolMemory) ==
                         ContentQueryResult::UnknownAvailability,
                 L"C-07 an unparsed file never claims that content is absent");
    }

    // 显式设置的三种存在状态都能被查询区分。
    {
        DumpContentAvailability manual;
        manual.set(ContentCategory::IrpObjects, ContentPresence::Included);
        manual.set(ContentCategory::LockObjects, ContentPresence::NotParsable);
        manual.set(ContentCategory::PoolMemory, ContentPresence::NotIncluded);
        s.expect(QueryContent(manual, ContentCategory::IrpObjects) ==
                     ContentQueryResult::Available,
                 L"C-07 an explicitly present category is queryable");
        s.expect(QueryContent(manual, ContentCategory::LockObjects) ==
                     ContentQueryResult::NotParsableHere,
                 L"C-07 'present but unparsable' stays distinct from 'not in the dump'");
        s.expect(QueryContent(manual, ContentCategory::PoolMemory) ==
                     ContentQueryResult::NotIncludedInDump,
                 L"C-07 an explicitly absent category answers 'not included in dump'");
        s.expect(manual.presenceOf(ContentCategory::ThreadStacks) == ContentPresence::Unknown,
                 L"C-07 categories that were never set stay Unknown");
    }

    // 名字覆盖。
    s.expect(std::string(ContentPresenceName(ContentPresence::Unknown)) == "Unknown" &&
                 std::string(ContentPresenceName(ContentPresence::NotIncluded)) == "NotIncluded" &&
                 std::string(ContentPresenceName(ContentPresence::NotParsable)) == "NotParsable" &&
                 std::string(ContentPresenceName(ContentPresence::Included)) == "Included",
             L"C-07 all four presence states have distinct names");
    s.expect(std::string(ContentQueryResultName(ContentQueryResult::NotIncludedInDump)) ==
                     "NotIncludedInDump" &&
                 std::string(ContentQueryResultName(ContentQueryResult::NotParsableHere)) ==
                     "NotParsableHere" &&
                 std::string(ContentQueryResultName(ContentQueryResult::UnknownAvailability)) ==
                     "UnknownAvailability" &&
                 std::string(ContentQueryResultName(ContentQueryResult::Available)) == "Available",
             L"C-07 all four query results have distinct names");
    s.expect(std::string(ContentCategoryName(ContentCategory::IrpObjects)) == "IrpObjects" &&
                 std::string(ContentCategoryName(ContentCategory::PhysicalMemory)) ==
                     "PhysicalMemory",
             L"C-07 content categories have stable names for the report");

    // 转储外补全必须显式声明。
    {
        const ExternalSupplement none;
        s.expect(SupplementDisclosed(none),
                 L"C-07 not using external data needs no disclosure");

        ExternalSupplement undisclosed;
        undisclosed.used = true;
        s.expect(!SupplementDisclosed(undisclosed),
                 L"C-07 red line: filling gaps from outside the dump without disclosure is rejected");

        ExternalSupplement wrongOrigin = undisclosed;
        wrongOrigin.disclosureKey = "dump.supplement.disk_image";
        wrongOrigin.source.collectorId = "disk.image.reader";
        wrongOrigin.source.origin = SourceOrigin::LiveKernel;
        s.expect(!SupplementDisclosed(wrongOrigin),
                 L"C-07 external supplements must be labelled as coming from an external file");

        ExternalSupplement disclosed = wrongOrigin;
        disclosed.source.origin = SourceOrigin::ExternalFile;
        s.expect(SupplementDisclosed(disclosed),
                 L"C-07 a disclosed external supplement with a proper source is accepted");
    }
}

// ---------------------------------------------------------------------------
// C-08 超时、取消与隔离
// ---------------------------------------------------------------------------
void TestInterruptionAndHelpers(Reporter& s) {
    // 只结束本模块拥有的 helper。
    {
        const HelperOwnership fresh;
        s.expect(DecideHelperTermination(fresh, "dump.facts") == TerminateDecision::RejectNotOwned,
                 L"C-08 red line: a default helper record is never allowed to be terminated");

        HelperOwnership foreign;
        foreign.startedByThisModule = true;
        foreign.ownerModuleId = "someone.else";
        foreign.helperId = "helper-1";
        s.expect(DecideHelperTermination(foreign, "dump.facts") ==
                     TerminateDecision::RejectOwnerMismatch,
                 L"C-08 red line: another module's helper is never terminated");

        HelperOwnership anonymous;
        anonymous.startedByThisModule = true;
        anonymous.ownerModuleId = "dump.facts";
        s.expect(DecideHelperTermination(anonymous, "dump.facts") ==
                     TerminateDecision::RejectNoHelperIdentity,
                 L"C-08 a helper with no instance id is not terminated by pid alone");

        HelperOwnership mine = anonymous;
        mine.helperId = "helper-7";
        mine.processId = OptionalU64::of(4242ULL);
        s.expect(DecideHelperTermination(mine, "dump.facts") == TerminateDecision::Allow,
                 L"C-08 this module's own identified helper may be terminated");
        s.expect(DecideHelperTermination(mine, "") == TerminateDecision::RejectOwnerMismatch,
                 L"C-08 an unnamed requester never gets termination rights");
    }

    s.expect(HelperStateIsTerminal(HelperState::Exited) && HelperStateIsTerminal(HelperState::Failed),
             L"C-08 Exited and Failed are terminal helper states");
    s.expect(!HelperStateIsTerminal(HelperState::Cancelling) &&
                 !HelperStateIsTerminal(HelperState::Stalled) &&
                 !HelperStateIsTerminal(HelperState::Disconnected) &&
                 !HelperStateIsTerminal(HelperState::NotStarted) &&
                 !HelperStateIsTerminal(HelperState::Starting) &&
                 !HelperStateIsTerminal(HelperState::Ready) &&
                 !HelperStateIsTerminal(HelperState::Busy),
             L"C-08 a cancelling or stalled helper is not terminal and may still hold resources");
    s.expect(std::string(HelperStateName(HelperState::Cancelling)) == "Cancelling" &&
                 std::string(HelperStateName(HelperState::Stalled)) == "Stalled" &&
                 std::string(HelperStateName(HelperState::Disconnected)) == "Disconnected",
             L"C-08 helper states have distinct names");
    s.expect(std::string(TerminateDecisionName(TerminateDecision::Allow)) == "Allow" &&
                 std::string(TerminateDecisionName(TerminateDecision::RejectNoHelperIdentity)) ==
                     "RejectNoHelperIdentity",
             L"C-08 termination decisions have distinct names");

    ScanBudget budget;
    budget.maxDurationNanos = OptionalU64::of(10ULL * 1000000000ULL);
    budget.maxItems = OptionalU64::of(5000ULL);

    // 超时但保住了部分结果。
    {
        CoverageAccount coverage;
        coverage.succeeded = 120U;
        coverage.totalKnown = OptionalU64::of(4000ULL);
        const InterruptedResult result =
            BuildInterruptedResult(BudgetStop::TimeExhausted, HelperState::Busy, budget, coverage,
                                   true);
        s.expect(result.outcome.status == CollectionStatus::Partial,
                 L"C-08 a timed-out run that kept results is Partial");
        s.expect(result.coverage.limitHit &&
                     result.coverage.limit == OptionalU64::of(10ULL * 1000000000ULL),
                 L"C-08 the time budget that stopped the run is written into the account");
        s.expect(result.partialResultsRetained,
                 L"C-08 the partial results are marked as retained");
        s.expect(!result.coverage.fullyCovered(),
                 L"C-08 an interrupted run is never reported as fully covered");
        bool sawStopKey = false;
        for (const std::string& key : result.interruptionKeys) {
            sawStopKey = sawStopKey || key == "dump.interrupt.TimeExhausted";
        }
        s.expect(sawStopKey, L"C-08 the interruption reason is stated with a stable key");
    }

    // 超时且什么都没采到：绝不能报 Partial。
    {
        const InterruptedResult result =
            BuildInterruptedResult(BudgetStop::TimeExhausted, HelperState::Busy, budget,
                                   CoverageAccount{}, false);
        s.expect(result.outcome.status == CollectionStatus::Timeout,
                 L"C-08 red line: a timeout with zero results is Timeout, never Partial");
        s.expect(!StatusCarriesObservation(result.outcome.status),
                 L"C-08 a zero-result timeout carries no observation for downstream conclusions");
        bool sawNoResultKey = false;
        for (const std::string& key : result.interruptionKeys) {
            sawNoResultKey = sawNoResultKey || key == "dump.interrupt.no_partial_results";
        }
        s.expect(sawNoResultKey, L"C-08 having no partial results at all is stated explicitly");
    }

    // 取消。
    {
        CoverageAccount coverage;
        coverage.succeeded = 3U;
        const InterruptedResult kept =
            BuildInterruptedResult(BudgetStop::Cancelled, HelperState::Cancelling, budget, coverage,
                                   true);
        s.expect(kept.outcome.status == CollectionStatus::Partial,
                 L"C-08 a cancellation that kept results is Partial");
        s.expect(kept.coverage.cancelled && !kept.coverage.limitHit,
                 L"C-08 a cancellation is recorded as cancelled, not as hitting an unknown limit");
        bool sawCancellingKey = false;
        for (const std::string& key : kept.interruptionKeys) {
            sawCancellingKey = sawCancellingKey || key == "dump.helper.cancelling";
        }
        s.expect(sawCancellingKey,
                 L"C-08 a helper still winding down is disclosed rather than reported as cleaned up");

        const InterruptedResult empty =
            BuildInterruptedResult(BudgetStop::Cancelled, HelperState::Cancelling, budget,
                                   CoverageAccount{}, false);
        s.expect(empty.outcome.status == CollectionStatus::NotCollected,
                 L"C-08 a cancellation before any result is NotCollected, never Partial");
    }

    // helper 卡住 / 断连 / 失败。
    {
        const InterruptedResult stalled =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Stalled, budget,
                                   CoverageAccount{}, true);
        s.expect(stalled.outcome.status == CollectionStatus::Timeout &&
                     stalled.outcome.message == "dump.helper.stalled",
                 L"C-08 a stalled helper is reported as a timeout with its own reason");

        const InterruptedResult dropped =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Disconnected, budget,
                                   CoverageAccount{}, true);
        s.expect(dropped.outcome.status == CollectionStatus::Error &&
                     dropped.outcome.message == "dump.helper.disconnected",
                 L"C-08 a disconnected helper is an error distinct from a timeout");

        const InterruptedResult failed =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Failed, budget,
                                   CoverageAccount{}, true);
        s.expect(failed.outcome.status == CollectionStatus::Error &&
                     failed.outcome.message == "dump.helper.failed",
                 L"C-08 a failed helper is reported as an error");
    }

    // 正确的空集合：没被中断，也确实没有结果。
    // 前提是 helper 已经结算 —— Ready 和 Exited 才算，别的状态见下面那一段。
    {
        const InterruptedResult clean =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Ready, budget,
                                   CoverageAccount{}, false);
        s.expect(clean.outcome.status == CollectionStatus::Success,
                 L"C-08 an uninterrupted run with genuinely nothing to report stays Success");
        s.expect(clean.interruptionKeys.empty(),
                 L"C-08 an uninterrupted run reports no interruption keys");
        s.expect(!clean.partialResultsRetained,
                 L"C-08 a correct empty set is distinguishable from retained partial results");

        const InterruptedResult exited =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Exited, budget,
                                   CoverageAccount{}, false);
        s.expect(exited.outcome.status == CollectionStatus::Success,
                 L"C-08 a helper that finished and exited also yields a correct empty set");
    }

    // C-08 红线：helper 从没启动 / 还在启动 / 还在跑 / 正在取消收尾时，
    // 一条结果都没有却报 Success，就是"从没采到推出正常"——
    // StatusCarriesObservation 会放行，下游据此得到"未发现差异"。
    // stop==Continue 只说明预算没用完，它对 helper 跑没跑一无所知。
    {
        const HelperState kUnsettled[] = {HelperState::NotStarted, HelperState::Starting,
                                          HelperState::Busy, HelperState::Cancelling};
        bool allNonObserving = true;
        bool allNotCollected = true;
        bool allDisclosed = true;
        for (const HelperState state : kUnsettled) {
            const InterruptedResult result =
                BuildInterruptedResult(BudgetStop::Continue, state, budget, CoverageAccount{},
                                       false);
            allNonObserving = allNonObserving && !StatusCarriesObservation(result.outcome.status);
            allNotCollected =
                allNotCollected && result.outcome.status == CollectionStatus::NotCollected;
            allDisclosed = allDisclosed && !result.interruptionKeys.empty();
        }
        s.expect(allNonObserving,
                 L"C-08 red line: a helper that never settled carries no observation for conclusions");
        s.expect(allNotCollected,
                 L"C-08 an unsettled helper with zero results is NotCollected, never Success");
        s.expect(allDisclosed,
                 L"C-08 an unsettled helper states why the run is incomplete");

        const InterruptedResult notStarted =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::NotStarted, budget,
                                   CoverageAccount{}, false);
        s.expect(notStarted.outcome.message == "dump.helper.not_started",
                 L"C-08 a helper that was never started says so instead of reporting success");
        bool sawNotStartedKey = false;
        for (const std::string& key : notStarted.interruptionKeys) {
            sawNotStartedKey = sawNotStartedKey || key == "dump.helper.not_started";
        }
        s.expect(sawNotStartedKey,
                 L"C-08 the never-started helper is disclosed with its own stable key");

        const InterruptedResult busy =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Busy, budget,
                                   CoverageAccount{}, false);
        s.expect(busy.outcome.message == "dump.helper.still_running",
                 L"C-08 a helper still running is disclosed rather than reported as finished");

        // 还在跑但已经有结果：这是货真价实的部分结果，不是完整成功。
        CoverageAccount someCoverage;
        someCoverage.succeeded = 7U;
        const InterruptedResult busyWithResults =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Busy, budget, someCoverage,
                                   true);
        s.expect(busyWithResults.outcome.status == CollectionStatus::Partial,
                 L"C-08 results held by a still-running helper are Partial, never a complete Success");
        s.expect(busyWithResults.partialResultsRetained,
                 L"C-08 the results a still-running helper already produced are retained");

        // 取消收尾中且一无所获：既不是 Partial 也不是 Success。
        const InterruptedResult cancelling =
            BuildInterruptedResult(BudgetStop::Continue, HelperState::Cancelling, budget,
                                   CoverageAccount{}, false);
        bool sawCancellingKey = false;
        for (const std::string& key : cancelling.interruptionKeys) {
            sawCancellingKey = sawCancellingKey || key == "dump.helper.cancelling";
        }
        s.expect(sawCancellingKey,
                 L"C-08 a helper winding down is disclosed even when the budget said continue");
    }

    // HelperStateSettled 的九条分支逐个断死。期望值在这里手写，不从被测函数反算。
    s.expect(HelperStateSettled(HelperState::Ready) && HelperStateSettled(HelperState::Exited),
             L"C-08 only a ready or exited helper counts as settled");
    s.expect(!HelperStateSettled(HelperState::NotStarted) &&
                 !HelperStateSettled(HelperState::Starting) &&
                 !HelperStateSettled(HelperState::Busy) &&
                 !HelperStateSettled(HelperState::Stalled) &&
                 !HelperStateSettled(HelperState::Disconnected) &&
                 !HelperStateSettled(HelperState::Cancelling) &&
                 !HelperStateSettled(HelperState::Failed),
             L"C-08 every other helper state is unsettled and its result set is incomplete");
    s.expect(!HelperStateIsTerminal(HelperState::Ready) && HelperStateSettled(HelperState::Ready),
             L"C-08 settled and terminal are two different questions about a helper");

    // 条数/字节/页预算耗尽且一无所获。
    {
        const InterruptedResult items =
            BuildInterruptedResult(BudgetStop::ItemsExhausted, HelperState::Busy, budget,
                                   CoverageAccount{}, false);
        s.expect(items.outcome.status == CollectionStatus::Error,
                 L"C-08 an item budget exhausted before any result is an error, not Partial");
        const InterruptedResult bytes =
            BuildInterruptedResult(BudgetStop::BytesExhausted, HelperState::Busy, budget,
                                   CoverageAccount{}, true);
        s.expect(bytes.outcome.status == CollectionStatus::Partial && bytes.coverage.limitHit,
                 L"C-08 a byte budget exhausted with results kept is Partial with limitHit");
        const InterruptedResult pages =
            BuildInterruptedResult(BudgetStop::PagesExhausted, HelperState::Busy, budget,
                                   CoverageAccount{}, true);
        s.expect(pages.outcome.status == CollectionStatus::Partial,
                 L"C-08 a page budget exhausted with results kept is Partial");
    }

    {
        const InterruptedResult fresh;
        s.expect(fresh.stop == BudgetStop::Continue &&
                     fresh.helperState == HelperState::NotStarted &&
                     !fresh.partialResultsRetained,
                 L"C-08 a default interrupted result claims nothing was started or retained");
    }
}

// ---------------------------------------------------------------------------
// C-09 不可信路径与输出
// ---------------------------------------------------------------------------
void TestUntrustedTextAndCommands(Reporter& s) {
    // 期望值逐字节手写，不由生产函数反算。
    s.expect(EscapeForReport("<script>alert('x')</script>") ==
                 "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;",
             L"C-09 a script tag is fully escaped into text");
    s.expect(EscapeForReport("A&B<C>D\"E'F") == "A&amp;B&lt;C&gt;D&quot;E&#39;F",
             L"C-09 all five HTML-significant characters are escaped");
    s.expect(EscapeForReport("evil\";DEL /F /Q C:\\ &whoami") ==
                 "evil&quot;;DEL /F /Q C:\\ &amp;whoami",
             L"C-09 quotes and ampersands in a shell-looking module name are escaped as text");
    s.expect(EscapeForReport("<exec cmd=\"!process 0 0\">") ==
                 "&lt;exec cmd=&quot;!process 0 0&quot;&gt;",
             L"C-09 a DML exec tag is escaped into inert text");
    s.expect(EscapeForReport("..\\..\\Windows\\System32\\config\\SAM") ==
                 "..\\..\\Windows\\System32\\config\\SAM",
             L"C-09 a traversal path is passed through as data without rewriting");
    s.expect(EscapeForReport("a\nb\tc\rd") == "a&#65533;b&#65533;c&#65533;d",
             L"C-09 newlines and tabs inside an untrusted field become replacement references");
    s.expect(EscapeForReport("") == "",
             L"C-09 escaping an empty string yields an empty string");
    s.expect(EscapeForReport("plain_module.sys") == "plain_module.sys",
             L"C-09 a harmless module name is left byte-for-byte alone");
    s.expect(EscapeForReport("\xE4" "\xB8" "\xAD") == "\xE4" "\xB8" "\xAD",
             L"C-09 non-ASCII UTF-8 bytes pass through unchanged");
    {
        std::string withNul = "mod";
        withNul.push_back('\0');
        withNul += "ule";
        s.expect(EscapeForReport(withNul) == "mod&#65533;ule",
                 L"C-09 an embedded NUL byte is neutralised without truncating the field");
    }

    // 纯文本报告出口：只消毒控制字符，不做 HTML 转义。
    s.expect(SanitizeForPlainTextField("mod\r\nule\tname") == "mod??ule?name",
             L"C-09 the plain-text field sanitiser replaces control characters so columns survive");
    s.expect(SanitizeForPlainTextField("<b>&amp;</b>") == "<b>&amp;</b>",
             L"C-09 the plain-text sanitiser does not HTML-escape, it is a separate exit");

    // 出口检查：这些原始片段各自命中一条风险。
    s.expect(ClassifyReportFragment("<script>x()</script>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a raw script tag is caught by the report exit check");
    s.expect(ClassifyReportFragment("<div onclick=\"x()\">") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 an inline event handler is caught by the report exit check");
    s.expect(ClassifyReportFragment("<a href=\"javascript:x()\">go</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a javascript: URL is caught by the report exit check");
    s.expect(ClassifyReportFragment("<exec cmd=\"!process 0 0\">run</exec>") ==
                 ReportOutputRisk::DebuggerMarkupLink,
             L"C-09 a DML exec tag is caught by the report exit check");
    s.expect(ClassifyReportFragment("<link cmd=\".reload /f\">reload</link>") ==
                 ReportOutputRisk::DebuggerMarkupLink,
             L"C-09 a DML link tag outranks its plain HTML resource meaning");
    s.expect(ClassifyReportFragment("<img src=\"http://evil.example/x.png\">") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 an external image tag is caught by the report exit check");
    s.expect(ClassifyReportFragment("<IMG SRC=HTTP://EVIL.EXAMPLE/X.PNG>") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 the exit check folds ASCII case, so uppercase tags do not slip through");
    s.expect(ClassifyReportFragment("<a href=\"https://evil.example/\">click</a>") ==
                 ReportOutputRisk::ExternalLink,
             L"C-09 an external hyperlink is caught by the report exit check");
    // file: 与 "//" 是同一个 OR 链里的两条独立分支。原来只有一条断言，输入是
    // "file://server/share/x" —— 里面的 "//" 先命中，file: 那条分支从未被执行到
    // （实测：删掉 file: 判定，整套断言依旧全绿）。这里拆成两条，各覆盖一条分支。
    s.expect(ClassifyReportFragment("<a href=\"file:C:/dumps/x\">click</a>") ==
                 ReportOutputRisk::ExternalLink,
             L"C-09 a file: URL with no double slash is caught by the file: branch itself");
    s.expect(ClassifyReportFragment("<a href=\"file:C:\\dumps\\x\">click</a>") ==
                 ReportOutputRisk::ExternalLink,
             L"C-09 a backslash file: URL is caught by the file: branch too");
    s.expect(ClassifyReportFragment("<a href=\"file://server/share/x\">click</a>") ==
                 ReportOutputRisk::ExternalLink,
             L"C-09 a protocol-relative double slash in a link is caught by its own branch");

    // 打开报告就自动外连的四种写法。全部与 href/src 无关，因此原来的属性门槛
    // （只认 href 与 src）一条都拦不住 —— 实测四条全部返回 Ok。
    s.expect(ClassifyReportFragment(
                 "<div style=\"background:url(https://evil.example/beacon.png)\">mod</div>") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 a CSS url() in a style attribute is an automatic external fetch");
    s.expect(ClassifyReportFragment("<style>@import url(http://evil.example/a.css);</style>") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 an @import inside a style element is an automatic external fetch");
    s.expect(ClassifyReportFragment(
                 "<table background=\"http://evil.example/beacon.png\"><tr><td>x</td></tr></table>") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 a legacy background attribute on a harmless tag is an automatic external fetch");
    s.expect(ClassifyReportFragment("<body background=\"//evil.example/beacon.png\">") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 a protocol-relative background attribute is an automatic external fetch");
    s.expect(ClassifyReportFragment("<video poster=\"https://evil.example/p.png\">") ==
                 ReportOutputRisk::ExternalResourceTag,
             L"C-09 a poster attribute is an automatic external fetch");
    s.expect(ClassifyReportFragment("<form action=\"https://evil.example/collect\">") ==
                 ReportOutputRisk::ExternalLink,
             L"C-09 a form action pointing outside is caught as an external link");

    // 浏览器在把属性值当 URL 解析**之前**先解字符引用，所以只比字面量
    // "javascript:" 等于没比。三种写法实测都曾返回 Ok。
    s.expect(ClassifyReportFragment("<a href=\"&#106;avascript:alert(1)\">click</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a decimal character reference cannot smuggle a javascript: URL past the exit check");
    s.expect(ClassifyReportFragment("<a href=\"&#x6a;avascript:alert(1)\">click</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a hex character reference cannot smuggle a javascript: URL either");
    s.expect(ClassifyReportFragment("<a href=\"javascript&colon;alert(1)\">click</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a named character reference for the colon cannot smuggle a javascript: URL");
    s.expect(ClassifyReportFragment(
                 "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a data: URI is treated as script, not as harmless inline content");
    s.expect(ClassifyReportFragment("<a href=\"vbscript:msgbox(1)\">x</a>") ==
                 ReportOutputRisk::ScriptOrEventHandler,
             L"C-09 a vbscript: URL is caught alongside javascript:");
    // 折叠只作用于属性区。一段**已经转义好**的安全文本不许被折回标签再报警。
    s.expect(ClassifyReportFragment("&lt;a href=&quot;javascript:alert(1)&quot;&gt;x&lt;/a&gt;") ==
                 ReportOutputRisk::Ok,
             L"C-09 entity folding never resurrects tags from already-escaped safe text");
    s.expect(ClassifyReportFragment("<span title=\"crash at 10:24 &amp; module a&amp;b\">x</span>") ==
                 ReportOutputRisk::Ok,
             L"C-09 ordinary escaped ampersands in an attribute do not trip the folded scan");
    s.expect(ClassifyReportFragment("faulting module acme\x01_filter.sys") ==
                 ReportOutputRisk::RawControlCharacter,
             L"C-09 a raw control character in the report is caught by the exit check");
    s.expect(ClassifyReportFragment("module acme_filter.sys + 0x1234\nnext line\tcolumn") ==
                 ReportOutputRisk::Ok,
             L"C-09 ordinary report text with layout whitespace passes the exit check");
    s.expect(ClassifyReportFragment("<a href=\"#local-anchor\">jump</a>") == ReportOutputRisk::Ok,
             L"C-09 a purely local anchor is not flagged as an external link");
    s.expect(ClassifyReportFragment("") == ReportOutputRisk::Ok,
             L"C-09 an empty fragment passes the exit check");

    // 端到端：任何恶意外来文本经过转义出口后都不再触发出口检查。
    {
        const char* const kEvilNames[] = {
            "<script>fetch('http://evil.example')</script>",
            "<img src=\"http://evil.example/beacon.png\">",
            "<exec cmd=\".shell del /f /q C:\\\">click</exec>",
            "<link cmd=\"!process 0 0\">x</link>",
            "acme\";shutdown -r -t 0 &",
            "..\\..\\..\\Windows\\System32\\drivers\\evil.sys",
            "a\nb\rc\td",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<div onmouseover=alert(1)>",
            "CON",
            "'; DROP TABLE modules; --",
        };
        bool allSafe = true;
        bool allChanged = true;
        for (const char* const evil : kEvilNames) {
            const std::string escaped = EscapeForReport(evil);
            allSafe = allSafe && ClassifyReportFragment(escaped) == ReportOutputRisk::Ok;
            // 至少要真的改动过含有危险字符的那些；纯路径类不含 & < > " ' 与控制字符。
            const std::string_view original(evil);
            const bool needsChange =
                original.find_first_of("&<>\"'\n\r\t") != std::string_view::npos;
            allChanged = allChanged && (!needsChange || escaped != original);
        }
        s.expect(allSafe,
                 L"C-09 every escaped untrusted name passes the report exit check");
        s.expect(allChanged,
                 L"C-09 escaping actually rewrites the dangerous inputs rather than passing them through");
    }

    // 白名单自审：先用独立扫描确认表本身干净，再确认判据接受它。
    {
        const std::span<const std::string_view> commands = AllowedAnalysisCommands();
        s.expect(!commands.empty(), L"C-09 the analysis command whitelist is not empty");
        bool tableClean = true;
        for (const std::string_view command : commands) {
            if (command.empty() || command.size() > 64U) {
                tableClean = false;
            }
            for (const char raw : command) {
                const auto byte = static_cast<unsigned char>(raw);
                const bool structural = byte < 0x20U || byte == 0x7FU || byte == ';' ||
                                        byte == '|' || byte == '&' || byte == '<' || byte == '>' ||
                                        byte == '$' || byte == '`' || byte == '"' || byte == '\'' ||
                                        byte == '\\' || byte == '(' || byte == ')' || byte == '{' ||
                                        byte == '}' || byte == '[' || byte == ']' || byte == '!' ||
                                        byte == '*' || byte == '?' || byte == '^' || byte == '%';
                if (structural) {
                    tableClean = false;
                }
            }
        }
        s.expect(tableClean,
                 L"C-09 every whitelisted command is short and free of control and shell characters");
        bool allAccepted = true;
        for (const std::string_view command : commands) {
            allAccepted = allAccepted && IsSafeAnalysisCommand(command) &&
                          ClassifyCommandRequest(command) == CommandRejection::Accepted;
        }
        s.expect(allAccepted,
                 L"C-09 the whitelist and the request classifier agree on every entry");
    }

    // 拒绝分支逐条覆盖。
    s.expect(ClassifyCommandRequest("") == CommandRejection::Empty,
             L"C-09 an empty analysis command is rejected as Empty");
    s.expect(ClassifyCommandRequest(std::string(200U, 'k')) == CommandRejection::TooLong,
             L"C-09 an over-long analysis command is rejected as TooLong");
    s.expect(ClassifyCommandRequest("lm\nk") == CommandRejection::ContainsControlCharacter,
             L"C-09 a newline in an analysis command is rejected before anything else");
    s.expect(ClassifyCommandRequest(".bugcheck; .shell dir") ==
                 CommandRejection::ContainsShellMetacharacter,
             L"C-09 a chained shell command is rejected as a metacharacter");
    s.expect(ClassifyCommandRequest(".bugcheck && whoami") ==
                 CommandRejection::ContainsShellMetacharacter,
             L"C-09 an ampersand chain is rejected as a metacharacter");
    s.expect(ClassifyCommandRequest("!process 0 0") ==
                 CommandRejection::ContainsShellMetacharacter,
             L"C-09 an extension command with a bang prefix is rejected");
    s.expect(ClassifyCommandRequest("lmv") == CommandRejection::NotInWhitelist,
             L"C-09 a near-miss command is rejected as not whitelisted");
    s.expect(ClassifyCommandRequest(".bugcheck ") == CommandRejection::NotInWhitelist,
             L"C-09 a trailing space makes the command a non-member of the whitelist");
    s.expect(ClassifyCommandRequest("k v") == CommandRejection::NotInWhitelist,
             L"C-09 adding an argument to a whitelisted command is rejected");
    s.expect(!IsSafeAnalysisCommand(".BUGCHECK"),
             L"C-09 the whitelist match is exact, not case-folded");
    s.expect(!IsSafeAnalysisCommand(""), L"C-09 the empty string is not a whitelisted command");
    s.expect(std::string(CommandRejectionName(CommandRejection::NotInWhitelist)) ==
                     "NotInWhitelist" &&
                 std::string(CommandRejectionName(CommandRejection::Accepted)) == "Accepted",
             L"C-09 command rejection reasons have distinct names");

    // 路径判定的九条分支。
    s.expect(ClassifyDumpPath("C:\\Windows\\Minidump\\010124-12345-01.dmp") == PathRisk::Ok,
             L"C-09 a normal local dump path is Ok");
    s.expect(ClassifyDumpPath("") == PathRisk::Empty,
             L"C-09 an empty path is Empty");
    s.expect(ClassifyDumpPath(std::string(40000U, 'a')) == PathRisk::TooLong,
             L"C-09 an absurdly long path is TooLong");
    s.expect(ClassifyDumpPath("C:\\dumps\\bad\nname.dmp") == PathRisk::ControlCharacter,
             L"C-09 a newline inside a path is caught");
    s.expect(ClassifyDumpPath("C:\\dumps\\*.dmp") == PathRisk::WildCard,
             L"C-09 a wildcard path is not silently expanded");
    s.expect(ClassifyDumpPath("C:\\dumps\\..\\..\\Windows\\System32\\config") ==
                 PathRisk::ParentTraversal,
             L"C-09 a parent traversal segment is caught");
    s.expect(ClassifyDumpPath("C:\\dumps\\a.dmp:hidden") == PathRisk::AlternateDataStream,
             L"C-09 an alternate data stream suffix is caught");
    s.expect(ClassifyDumpPath("C:\\dumps\\NUL.dmp") == PathRisk::DeviceName,
             L"C-09 a reserved device name segment is caught even with an extension");
    s.expect(ClassifyDumpPath("C:\\dumps\\com1") == PathRisk::DeviceName,
             L"C-09 a reserved COM device name is caught case-insensitively");
    s.expect(ClassifyDumpPath("\\\\server\\share\\crash.dmp") == PathRisk::UncOrRemote,
             L"C-09 a UNC path is flagged as remote");
    s.expect(ClassifyDumpPath("//server/share/crash.dmp") == PathRisk::UncOrRemote,
             L"C-09 a forward-slash UNC path is flagged as remote");
    s.expect(ClassifyDumpPath("dumps/sub/crash.dmp") == PathRisk::Ok,
             L"C-09 a relative path without traversal is Ok");

    // DOS 设备命名空间。\\.\ 既不是远程路径也不是文件：以前它一路走到最后被当成
    // UncOrRemote，于是 UI 问的是"这是远程路径，确认？"（问错了问题），
    // 确认之后还真允许打开 —— 本地攻击者架一个命名管道就能冒充转储文件，
    // 向解析器喂无限长、可变、非文件的字节流。
    s.expect(ClassifyDumpPath("\\\\.\\PhysicalDrive0") == PathRisk::DeviceName,
             L"C-09 the raw disk device namespace is a device name, not a remote path");
    s.expect(ClassifyDumpPath("\\\\.\\pipe\\evil") == PathRisk::DeviceName,
             L"C-09 a named pipe in the device namespace is a device name, not a remote path");
    s.expect(ClassifyDumpPath("\\\\.\\C:") == PathRisk::DeviceName,
             L"C-09 a volume opened through the device namespace is a device name");
    s.expect(ClassifyDumpPath("//./PhysicalDrive0") == PathRisk::DeviceName,
             L"C-09 the forward-slash spelling of the device namespace is caught the same way");
    s.expect(ClassifyDumpPath("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\x.dmp") ==
                 PathRisk::DeviceName,
             L"C-09 GLOBALROOT loops back into the device namespace and is caught there");
    s.expect(!PathAcceptableForOpen(ClassifyDumpPath("\\\\.\\PhysicalDrive0")) &&
                 !PathAcceptableForOpen(ClassifyDumpPath("\\\\.\\pipe\\evil")) &&
                 !PathAcceptableForOpen(ClassifyDumpPath("\\\\.\\C:")),
             L"C-09 red line: nothing in the device namespace is acceptable to open as a dump");

    // Win32 长路径前缀。它是打开超过 MAX_PATH 的转储的唯一写法；前缀里的 '?'
    // 以前被通配符扫描一刀切掉，合法的长路径转储永远打不开，理由还是错的。
    s.expect(ClassifyDumpPath("\\\\?\\C:\\Windows\\Minidump\\010124-12345-01.dmp") == PathRisk::Ok,
             L"C-09 a long-path-prefixed local dump is Ok, not a wildcard");
    s.expect(PathAcceptableForOpen(
                 ClassifyDumpPath("\\\\?\\C:\\Windows\\Minidump\\010124-12345-01.dmp")),
             L"C-09 a long-path-prefixed local dump can actually be opened");
    s.expect(ClassifyDumpPath("\\\\?\\UNC\\server\\share\\c.dmp") == PathRisk::UncOrRemote,
             L"C-09 the long-path spelling of a UNC share is still a remote path");
    s.expect(PathNeedsExplicitConfirmation(ClassifyDumpPath("\\\\?\\UNC\\server\\share\\c.dmp")),
             L"C-09 a long-path UNC still needs explicit confirmation");
    // 剥前缀不等于放行：前缀后面的内容照旧逐条判定。
    s.expect(ClassifyDumpPath("\\\\?\\C:\\dumps\\*.dmp") == PathRisk::WildCard,
             L"C-09 a real wildcard behind the long-path prefix is still a wildcard");
    s.expect(ClassifyDumpPath("\\\\?\\C:\\dumps\\..\\..\\config") == PathRisk::ParentTraversal,
             L"C-09 a traversal behind the long-path prefix is still a traversal");
    s.expect(ClassifyDumpPath("\\\\?\\C:\\dumps\\NUL.dmp") == PathRisk::DeviceName,
             L"C-09 a reserved device name behind the long-path prefix is still a device name");
    s.expect(ClassifyDumpPath("\\\\?\\") == PathRisk::Empty,
             L"C-09 a bare long-path prefix names nothing to open");
    // "//?/" 不是长路径前缀（那个前缀的作用正是关掉路径规范化，只有反斜杠形式有效），
    // 所以里面的 '?' 该当通配符就当通配符 —— 失败方向是安全的那一侧。
    s.expect(ClassifyDumpPath("//?/C:/dumps/x.dmp") == PathRisk::WildCard,
             L"C-09 the forward-slash spelling is not a long-path prefix and stays a wildcard");

    // 段尾的 '.' 与 ' '：Windows 打开时会剥掉它们，被判定的字符串与真正被打开的
    // 文件因此不是同一个，判定本身失去意义。
    s.expect(ClassifyDumpPath("C:\\dumps\\crash.dmp.") == PathRisk::TrailingDotOrSpace,
             L"C-09 a trailing dot is refused because Windows would strip it before opening");
    s.expect(ClassifyDumpPath("C:\\dumps\\crash.dmp ") == PathRisk::TrailingDotOrSpace,
             L"C-09 a trailing space is refused for the same reason");
    s.expect(ClassifyDumpPath("C:\\dumps \\crash.dmp") == PathRisk::TrailingDotOrSpace,
             L"C-09 a trailing space on an intermediate segment is refused too");
    s.expect(!PathAcceptableForOpen(PathRisk::TrailingDotOrSpace),
             L"C-09 a path whose text does not name the file that would be opened is not opened");
    s.expect(ClassifyDumpPath(".\\crash.dmp") == PathRisk::Ok &&
                 ClassifyDumpPath("C:\\dumps\\.\\crash.dmp") == PathRisk::Ok,
             L"C-09 a current-directory segment is path syntax, not a trailing-dot problem");

    s.expect(PathAcceptableForOpen(PathRisk::Ok) && PathAcceptableForOpen(PathRisk::UncOrRemote),
             L"C-09 only ordinary and UNC paths are acceptable to open");
    s.expect(!PathAcceptableForOpen(PathRisk::ParentTraversal) &&
                 !PathAcceptableForOpen(PathRisk::DeviceName) &&
                 !PathAcceptableForOpen(PathRisk::AlternateDataStream) &&
                 !PathAcceptableForOpen(PathRisk::WildCard) &&
                 !PathAcceptableForOpen(PathRisk::ControlCharacter) &&
                 !PathAcceptableForOpen(PathRisk::TrailingDotOrSpace) &&
                 !PathAcceptableForOpen(PathRisk::TooLong) &&
                 !PathAcceptableForOpen(PathRisk::Empty),
             L"C-09 every risky path class is refused for opening");
    s.expect(PathNeedsExplicitConfirmation(PathRisk::UncOrRemote) &&
                 !PathNeedsExplicitConfirmation(PathRisk::Ok),
             L"C-09 only a remote path additionally needs explicit confirmation");
    s.expect(std::string(PathRiskName(PathRisk::AlternateDataStream)) == "AlternateDataStream" &&
                 std::string(PathRiskName(PathRisk::ParentTraversal)) == "ParentTraversal" &&
                 std::string(PathRiskName(PathRisk::DeviceName)) == "DeviceName" &&
                 std::string(PathRiskName(PathRisk::TrailingDotOrSpace)) == "TrailingDotOrSpace",
             L"C-09 path risks have distinct names");
    s.expect(std::string(ReportOutputRiskName(ReportOutputRisk::DebuggerMarkupLink)) ==
                     "DebuggerMarkupLink" &&
                 std::string(ReportOutputRiskName(ReportOutputRisk::ExternalResourceTag)) ==
                     "ExternalResourceTag" &&
                 std::string(ReportOutputRiskName(ReportOutputRisk::RawControlCharacter)) ==
                     "RawControlCharacter" &&
                 std::string(ReportOutputRiskName(ReportOutputRisk::ExternalLink)) ==
                     "ExternalLink" &&
                 std::string(ReportOutputRiskName(ReportOutputRisk::Ok)) == "Ok",
             L"C-09 report output risks have distinct names");
}

// ---------------------------------------------------------------------------
// C-10 报告出处
// ---------------------------------------------------------------------------
DumpReportProvenance MakeCompleteProvenance() {
    DumpReportProvenance provenance;
    provenance.engine.engineId = "ksword.dumpfacts";
    provenance.engine.engineVersion = "1.0.0";
    provenance.engine.engineAvailable = true;
    provenance.input.filePath = "C:\\Windows\\Minidump\\010124-12345-01.dmp";
    provenance.input.fileSize = OptionalU64::of(0x50000ULL);
    provenance.input.sha256Hex =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    provenance.input.hashComputed = true;
    provenance.input.lastModifiedUtc100ns = OptionalU64::of(133000000000000000ULL);
    provenance.source.collectorId = "offline.dump.facts";
    provenance.source.collectorVersion = 1U;
    provenance.source.sourceGroup = "offline-sample";
    provenance.source.origin = SourceOrigin::OfflineSample;
    provenance.window.startUtc100ns = OptionalU64::of(133100000000000000ULL);
    provenance.window.endUtc100ns = OptionalU64::of(133100000012000000ULL);
    provenance.window.mode = CaptureMode::Replay;
    provenance.analysisScope.totalKnown = OptionalU64::of(42ULL);
    provenance.analysisScope.succeeded = 42U;

    ModuleSymbolState matched;
    matched.moduleName = "ntoskrnl.exe";
    matched.match = SymbolMatch::Matched;
    matched.attempt = SymbolLoadAttempt::FileLoaded;
    matched.cacheSource = SymbolCacheSource::LocalCache;
    provenance.symbolStates.push_back(matched);

    ModuleSymbolState wrong;
    wrong.moduleName = "acme_filter.sys";
    wrong.match = SymbolMatch::WrongVersion;
    wrong.attempt = SymbolLoadAttempt::FileLoaded;
    provenance.symbolStates.push_back(wrong);

    ModuleSymbolState absent;
    absent.moduleName = "mystery.sys";
    absent.match = SymbolMatch::Absent;
    absent.attempt = SymbolLoadAttempt::FileNotFound;
    provenance.symbolStates.push_back(absent);

    provenance.availability = DeriveAvailabilityFromKind(DumpKind::KernelSmall);
    return provenance;
}

bool HasGap(const std::vector<ProvenanceGap>& gaps, ProvenanceGap wanted) {
    for (const ProvenanceGap gap : gaps) {
        if (gap == wanted) {
            return true;
        }
    }
    return false;
}

std::string FieldValue(const std::vector<ReportField>& fields, const std::string& key) {
    for (const ReportField& field : fields) {
        if (field.key == key) {
            return field.value;
        }
    }
    return std::string("<<missing key>>");
}

void TestProvenance(Reporter& s) {
    // 默认构造：不可重核，且缺口逐条列出。
    {
        const DumpReportProvenance fresh;
        const std::vector<ProvenanceGap> gaps = AuditProvenance(fresh);
        s.expect(!ProvenanceReviewable(fresh),
                 L"C-10 a default-constructed report provenance is not reviewable");
        s.expect(gaps.size() == 9U,
                 L"C-10 the default provenance reports exactly the nine missing items");
        s.expect(HasGap(gaps, ProvenanceGap::MissingEngineIdentity) &&
                     HasGap(gaps, ProvenanceGap::MissingEngineVersion) &&
                     HasGap(gaps, ProvenanceGap::MissingInputPath) &&
                     HasGap(gaps, ProvenanceGap::MissingInputSize) &&
                     HasGap(gaps, ProvenanceGap::MissingInputHash) &&
                     HasGap(gaps, ProvenanceGap::MissingAnalysisWindow) &&
                     HasGap(gaps, ProvenanceGap::MissingSymbolStates) &&
                     HasGap(gaps, ProvenanceGap::UnstatedAnalysisScope) &&
                     HasGap(gaps, ProvenanceGap::WrongSourceOrigin),
                 L"C-10 every default gap is named individually rather than as one failure");
        s.expect(!HasGap(gaps, ProvenanceGap::UndisclosedExternalSupplement),
                 L"C-10 not using an external supplement is not itself a gap");
    }

    // 完整出处：可重核。
    const DumpReportProvenance complete = MakeCompleteProvenance();
    s.expect(AuditProvenance(complete).empty() && ProvenanceReviewable(complete),
             L"C-10 a complete provenance has no gaps and is reviewable");

    // 逐项拿掉，各自只产生对应的那一条缺口。
    {
        DumpReportProvenance missing = complete;
        missing.engine.engineVersion.clear();
        const std::vector<ProvenanceGap> gaps = AuditProvenance(missing);
        s.expect(gaps.size() == 1U && gaps[0] == ProvenanceGap::MissingEngineVersion,
                 L"C-10 dropping the engine version yields exactly that gap");
    }
    {
        DumpReportProvenance missing = complete;
        missing.input.hashComputed = false;
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingInputHash,
                 L"C-10 an uncomputed input hash is reported as a gap, not as a zero hash");
    }
    {
        DumpReportProvenance missing = complete;
        missing.input.sha256Hex = "0123";
        s.expect(HasGap(AuditProvenance(missing), ProvenanceGap::MissingInputHash),
                 L"C-10 a malformed hash string does not pass as an input identity");
    }
    {
        DumpReportProvenance missing = complete;
        missing.input.fileSize = OptionalU64::unset();
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingInputSize,
                 L"C-10 an unknown input size is a gap, never a reported zero");
    }
    {
        DumpReportProvenance missing = complete;
        missing.window.endUtc100ns = OptionalU64::unset();
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingAnalysisWindow,
                 L"C-10 a half-open analysis window counts as missing");
    }
    {
        DumpReportProvenance missing = complete;
        missing.symbolStates.clear();
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingSymbolStates,
                 L"C-10 a report without symbol status cannot be re-reviewed");
    }
    {
        DumpReportProvenance missing = complete;
        missing.analysisScope = CoverageAccount{};
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::UnstatedAnalysisScope,
                 L"C-10 an empty coverage account does not count as a stated analysis scope");
    }
    {
        DumpReportProvenance wrong = complete;
        wrong.source.origin = SourceOrigin::LiveKernel;
        s.expect(AuditProvenance(wrong).size() == 1U &&
                     AuditProvenance(wrong)[0] == ProvenanceGap::WrongSourceOrigin,
                 L"C-10 an offline dump report must be labelled as an offline sample");
    }
    {
        DumpReportProvenance supplemented = complete;
        supplemented.supplement.used = true;
        s.expect(AuditProvenance(supplemented).size() == 1U &&
                     AuditProvenance(supplemented)[0] ==
                         ProvenanceGap::UndisclosedExternalSupplement,
                 L"C-10 using data from outside the dump without disclosing it is a gap");
        supplemented.supplement.disclosureKey = "dump.supplement.disk_image";
        supplemented.supplement.source.collectorId = "disk.image.reader";
        supplemented.supplement.source.origin = SourceOrigin::ExternalFile;
        s.expect(AuditProvenance(supplemented).empty(),
                 L"C-10 a disclosed external supplement closes the gap");
    }
    {
        DumpReportProvenance missing = complete;
        missing.engine.engineId.clear();
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingEngineIdentity,
                 L"C-10 dropping the engine id yields exactly that gap");
    }
    {
        DumpReportProvenance missing = complete;
        missing.input.filePath.clear();
        s.expect(AuditProvenance(missing).size() == 1U &&
                     AuditProvenance(missing)[0] == ProvenanceGap::MissingInputPath,
                 L"C-10 dropping the input path yields exactly that gap");
    }

    // 报告字段：外来文本统一转义，缺失值用固定占位键。
    {
        DumpReportProvenance evil = complete;
        evil.input.filePath = "C:\\dumps\\<img src=\"http://evil.example/x\">.dmp";
        evil.engine.engineVersion = "1.0 & \"beta\"";
        const std::vector<ReportField> fields = BuildProvenanceFields(evil);
        s.expect(FieldValue(fields, "dump.report.input_path") ==
                     "C:\\dumps\\&lt;img src=&quot;http://evil.example/x&quot;&gt;.dmp",
                 L"C-10 the report path field is escaped byte-for-byte as expected");
        s.expect(FieldValue(fields, "dump.report.engine_version") == "1.0 &amp; &quot;beta&quot;",
                 L"C-10 the engine version field is escaped too");
        bool allSafe = true;
        for (const ReportField& field : fields) {
            allSafe = allSafe && ClassifyReportFragment(field.value) == ReportOutputRisk::Ok;
        }
        s.expect(allSafe,
                 L"C-09 every generated report field passes the report exit check");
        s.expect(FieldValue(fields, "dump.report.symbol_module_count") == "3" &&
                     FieldValue(fields, "dump.report.symbol_matched_count") == "1" &&
                     FieldValue(fields, "dump.report.symbol_wrong_version_count") == "1" &&
                     FieldValue(fields, "dump.report.symbol_absent_count") == "1" &&
                     FieldValue(fields, "dump.report.symbol_not_attempted_count") == "0",
                 L"C-10 the report states the symbol status breakdown so it can be re-reviewed");
        s.expect(FieldValue(fields, "dump.report.input_size") == "327680",
                 L"C-10 the input size is written as an exact decimal, not a rounded value");
        s.expect(FieldValue(fields, "dump.report.source_origin") == "OfflineSample",
                 L"C-10 the report names the source origin explicitly");
        s.expect(FieldValue(fields, "dump.report.external_supplement") == "none",
                 L"C-10 the report states that no external supplement was used");
    }
    {
        const std::vector<ReportField> fields = BuildProvenanceFields(DumpReportProvenance{});
        s.expect(FieldValue(fields, "dump.report.input_size") == "dump.value.unknown",
                 L"C-10 an unknown input size renders as the unknown key, never as 0");
        s.expect(FieldValue(fields, "dump.report.input_sha256") == "dump.value.unknown",
                 L"C-10 an uncomputed hash renders as the unknown key, never as an empty string");
        s.expect(FieldValue(fields, "dump.report.analysis_window_start") == "dump.value.unknown" &&
                     FieldValue(fields, "dump.report.analysis_window_end") == "dump.value.unknown",
                 L"C-10 an unknown analysis window renders as the unknown key");
        s.expect(FieldValue(fields, "dump.report.engine_available") == "false",
                 L"C-10 engine availability defaults to false in the report");
        s.expect(FieldValue(fields, "dump.report.analysis_scope_remaining") == "remaining:unknown",
                 L"C-10 an unstated scope reports its remainder as unknown, not as zero");
    }

    s.expect(std::string(ProvenanceGapName(ProvenanceGap::UndisclosedExternalSupplement)) ==
                     "UndisclosedExternalSupplement" &&
                 std::string(ProvenanceGapName(ProvenanceGap::UnstatedAnalysisScope)) ==
                     "UnstatedAnalysisScope" &&
                 std::string(ProvenanceGapName(ProvenanceGap::MissingInputHash)) ==
                     "MissingInputHash",
             L"C-10 provenance gaps have distinct names");
}

// ---------------------------------------------------------------------------
// 性能护栏：上一轮实测抓到过 15 秒与 13 秒两处 O(n^2)。
// 这里对三条会吃到大输入的路径设硬上限。
// ---------------------------------------------------------------------------
void TestPerformanceGuards(Reporter& s) {
    using Clock = std::chrono::steady_clock;

    // 1) 十万帧栈校验。
    {
        StackTrace trace;
        trace.frames.reserve(100000U);
        for (std::uint64_t index = 0; index < 100000U; ++index) {
            StackFrame frame;
            frame.address = OptionalU64::of(0xFFFFF80300000000ULL + index * 0x40ULL);
            frame.moduleName = "acme_filter.sys";
            frame.unwindState = UnwindState::Unwound;
            frame.availableArgs.push_back(OptionalU64::of(index));
            trace.frames.push_back(std::move(frame));
        }
        const Clock::time_point begin = Clock::now();
        const StackValidation verdict = ValidateStackTrace(trace);
        const std::size_t unwound = trace.unwoundCount();
        const auto elapsedMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - begin).count();
        s.expect(verdict == StackValidation::Ok && unwound == 100000U,
                 L"C-05 a hundred-thousand-frame stack still validates correctly");
        s.expect(elapsedMs < 2000,
                 L"C-05 validating a hundred thousand frames stays well under two seconds");
    }

    // 2) 十万条模块证据分组（五百个不同模块名）。
    {
        std::vector<ModuleEvidenceItem> items;
        items.reserve(100000U);
        for (std::uint64_t index = 0; index < 100000U; ++index) {
            ModuleEvidenceItem item;
            item.kind = ModuleEvidenceKind::OnStack;
            item.moduleName = "drv_" + std::to_string(index % 500U) + ".sys";
            item.frameUnwindState = UnwindState::Unwound;
            item.frameIndex = OptionalU64::of(index);
            items.push_back(std::move(item));
        }
        const Clock::time_point begin = Clock::now();
        const std::vector<ModuleEvidenceGroup> groups = GroupModuleEvidence(std::move(items));
        const auto elapsedMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - begin).count();
        s.expect(groups.size() == 500U,
                 L"C-06 grouping a hundred thousand evidence items yields the five hundred modules");
        std::size_t total = 0;
        for (const ModuleEvidenceGroup& group : groups) {
            total += group.evidenceCount();
        }
        s.expect(total == 100000U,
                 L"C-06 grouping keeps every evidence item exactly once");
        s.expect(elapsedMs < 3000,
                 L"C-06 grouping a hundred thousand evidence items stays under three seconds");
    }

    // 3) 256 KiB 外来文本走转义与出口检查。
    {
        std::string huge;
        huge.reserve(256U * 1024U);
        while (huge.size() < 256U * 1024U) {
            huge += "<a href=\"http://evil.example\">module&name</a>\t";
        }
        const Clock::time_point begin = Clock::now();
        const std::string escaped = EscapeForReport(huge);
        const ReportOutputRisk risk = ClassifyReportFragment(escaped);
        const auto elapsedMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - begin).count();
        s.expect(risk == ReportOutputRisk::Ok,
                 L"C-09 a quarter-megabyte of hostile text is fully neutralised");
        s.expect(escaped.size() > huge.size(),
                 L"C-09 escaping a hostile blob actually expands it, proving it did work");
        s.expect(elapsedMs < 2000,
                 L"C-09 escaping and checking a quarter-megabyte stays under two seconds");
        // 原始（未转义）文本必须被出口检查挡下 —— 否则上面那条"通过"毫无意义。
        s.expect(ClassifyReportFragment(huge) != ReportOutputRisk::Ok,
                 L"C-09 the same blob before escaping is rejected by the exit check");
    }
}

} // namespace

int RunDumpFactsTests() {
    KswordTests::Suite suite(L"C offline dump facts");
    Reporter reporter(suite);
    TestRecognition(reporter);
    TestBugCheckFacts(reporter);
    TestSymbolMatching(reporter);
    TestStackAndUnwind(reporter);
    TestSuspectExplanation(reporter);
    TestContentAvailability(reporter);
    TestInterruptionAndHelpers(reporter);
    TestUntrustedTextAndCommands(reporter);
    TestProvenance(reporter);
    TestPerformanceGuards(reporter);
    suite.report();
    return suite.failures();
}
