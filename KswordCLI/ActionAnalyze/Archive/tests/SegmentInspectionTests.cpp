#include "../SegmentInspection.h"

#include <limits>
#include <iostream>
#include <stdexcept>
#include <windows.h>

namespace {

namespace archive = ks::cli::action_analyze::archive;
using archive::SegmentScanStatus;
using archive::SegmentIssue;
using archive::StreamKind;

constexpr archive::ArchiveUuid kProject{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef,
                                         0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
constexpr archive::ArchiveUuid kSample{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x43, 0x21,
                                        0xa2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
constexpr archive::SegmentIdentity kIdentity{StreamKind::Raw, 1, kProject, kSample};

void Check(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct File {
    HANDLE handle;

    explicit File(const std::filesystem::path& path)
        : handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
    {
        Check(handle != INVALID_HANDLE_VALUE, "open A0 fixture");
    }

    File(const File&) = delete;
    File& operator=(const File&) = delete;
    ~File() { CloseHandle(handle); }
};

void TestNames()
{
    auto id = kIdentity;
    const auto raw = archive::NameInspectionSegment(id);
    Check(raw && raw->streamDirectory == L"raw" && raw->fileName == L"00000000000000000001.ksaseg", "raw logical name");
    id.stream = StreamKind::Records;
    id.ordinal = (std::numeric_limits<std::uint64_t>::max)();
    const auto records = archive::NameInspectionSegment(id);
    Check(records && records->streamDirectory == L"records" && records->fileName == L"18446744073709551615.ksaseg",
          "maximum ordinal logical name");
    id.stream = StreamKind::Control;
    id.ordinal = 42;
    const auto control = archive::NameInspectionSegment(id);
    Check(control && control->streamDirectory == L"control" && control->fileName == L"00000000000000000042.ksaseg",
          "control logical name");
    id.stream = StreamKind::Analysis;
    Check(!archive::NameInspectionSegment(id) && !archive::InspectOpenSegment(nullptr, id), "analysis without run binding");
    id.stream = StreamKind::Raw;
    id.ordinal = 0;
    Check(!archive::NameInspectionSegment(id) && !archive::InspectOpenSegment(nullptr, id), "zero segment ordinal");
}

void TestCoverage(const std::filesystem::path& directory)
{
    const File raw(directory / "raw-segment.ksaseg");
    LARGE_INTEGER start{};
    start.QuadPart = 13;
    Check(SetFilePointerEx(raw.handle, start, nullptr, FILE_BEGIN) != 0, "set nonzero initial position");
    const auto full = archive::InspectOpenSegment(raw.handle, kIdentity);
    Check(full && full->framingStatus == SegmentScanStatus::FramingComplete && full->expectedIdentity.sample == kSample &&
          full->createdUtc100ns == 81985529216486895ull && full->requiredRecordCount == 1 &&
          !full->interpretedBytes && !full->durableBytes, "identity, timestamp and coverage status");
    const auto& coverage = full->framingCoverage;
    Check(coverage.fileBytes == 218 && coverage.scanLimitBytes == 218 && !coverage.requestedEndOffset &&
          coverage.framedBytes == 218 && coverage.blockCount == 1 && coverage.lastBlockOrdinal == 1 && coverage.lastSequence == 0,
          "exact A0 raw segment coverage");
    start.QuadPart = 0;
    LARGE_INTEGER current{};
    Check(SetFilePointerEx(raw.handle, start, &current, FILE_CURRENT) != 0 && current.QuadPart == 218, "borrowed handle position");

    const auto headerOnly = archive::InspectOpenSegment(raw.handle, kIdentity, 96);
    Check(headerOnly && headerOnly->framingStatus == SegmentScanStatus::FramingComplete &&
          headerOnly->framingCoverage.fileBytes == 218 && headerOnly->framingCoverage.requestedEndOffset == 96 &&
          headerOnly->framingCoverage.scanLimitBytes == 96 && headerOnly->framingCoverage.framedBytes == 96 &&
          !headerOnly->framingCoverage.lastSequence, "explicit block boundary");
    const auto partial = archive::InspectOpenSegment(raw.handle, kIdentity, 217);
    Check(partial && partial->framingStatus == SegmentScanStatus::Truncated && partial->error.offset == 217 &&
          partial->framingCoverage.framedBytes == 96, "request cuts inside block");
    const auto beyond = archive::InspectOpenSegment(raw.handle, kIdentity, 219);
    Check(beyond && beyond->framingStatus == SegmentScanStatus::Truncated && beyond->error.offset == 218 &&
          beyond->framingCoverage.framedBytes == 218, "request beyond observed EOF");

    auto wrongId = kIdentity;
    wrongId.sample[0] = 0;
    const auto wrong = archive::InspectOpenSegment(raw.handle, wrongId);
    Check(wrong && wrong->framingStatus == SegmentScanStatus::Corrupt && wrong->error.issue == SegmentIssue::Identity &&
          wrong->framingCoverage.framedBytes == 0 && !wrong->createdUtc100ns, "mismatched sample identity");
    const auto invalidFile = archive::InspectOpenSegment(INVALID_HANDLE_VALUE, kIdentity);
    Check(invalidFile && invalidFile->framingStatus == SegmentScanStatus::IoError &&
          !invalidFile->framingCoverage.fileBytes && !invalidFile->framingCoverage.scanLimitBytes, "unknown file size on I/O failure");
}

void TestClassifications(const std::filesystem::path& directory)
{
    const auto inspect = [&](const wchar_t* file) {
        const File fixture(directory / file);
        const auto result = archive::InspectOpenSegment(fixture.handle, kIdentity);
        Check(result.has_value(), "fixture inspection did not run");
        return *result;
    };
    const auto corrupt = inspect(L"bad-second-stored-crc.ksaseg");
    Check(corrupt.framingStatus == SegmentScanStatus::Corrupt && corrupt.error.issue == SegmentIssue::StoredCrc &&
          corrupt.framingCoverage.fileBytes == 340 && corrupt.framingCoverage.framedBytes == 218 &&
          corrupt.framingCoverage.blockCount == 1 && corrupt.error.offset == 298, "corrupt tail prefix");
    const auto codec = inspect(L"unavailable-zstd.ksaseg");
    Check(codec.framingStatus == SegmentScanStatus::Unsupported && codec.error.issue == SegmentIssue::Codec &&
          codec.framingCoverage.framedBytes == 96 && codec.unsupportedRequiredRecords == 0, "unsupported codec classification");
    const auto optional = inspect(L"optional-unknown-record.ksaseg");
    Check(optional.framingStatus == SegmentScanStatus::FramingComplete && optional.framingCoverage.framedBytes == 208 &&
          optional.unsupportedRequiredRecords == 0 && optional.unsupportedOptionalRecords == 1, "optional unknown record");
    const auto required = inspect(L"required-unknown-record.ksaseg");
    Check(required.framingStatus == SegmentScanStatus::FramingComplete && required.framingCoverage.framedBytes == 208 &&
          required.unsupportedRequiredRecords == 1 && required.unsupportedOptionalRecords == 0 &&
          required.requiredRecordCount == 1 && !required.interpretedBytes && !required.durableBytes, "required unknown record");
    const auto invalidRaw = inspect(L"raw-metadata-is-not-object.ksaseg");
    Check(invalidRaw.framingStatus == SegmentScanStatus::FramingComplete && invalidRaw.framingCoverage.framedBytes == 218 &&
          invalidRaw.requiredRecordCount == 1 && invalidRaw.unsupportedRequiredRecords == 0 &&
          !invalidRaw.interpretedBytes && !invalidRaw.durableBytes, "catalogued required record with invalid semantics");
}

// 返回测试期用的分类，供脚本逐项与 A0 向量比较。
const char* VectorStatus(const archive::SegmentInspection& inspection)
{
    const auto issue = inspection.error.issue;
    if (inspection.framingStatus == SegmentScanStatus::FramingComplete) return "framing-complete";
    if (inspection.framingStatus == SegmentScanStatus::Truncated) return "truncated";
    switch (issue) {
    case SegmentIssue::Version: return "unsupported-version";
    case SegmentIssue::Flags: return "unsupported-flags";
    case SegmentIssue::Identity: return "identity";
    case SegmentIssue::HeaderCrc: return "header-crc";
    case SegmentIssue::StoredCrc: return "stored-crc";
    case SegmentIssue::DecodedCrc: return "decoded-crc";
    case SegmentIssue::Codec: return "unsupported-codec";
    case SegmentIssue::BlockLength: return "block-length";
    case SegmentIssue::RecordLength: return "record-length";
    case SegmentIssue::RecordCount: return "record-count";
    case SegmentIssue::Sequence: return "sequence";
    case SegmentIssue::QpcRange: return "qpc-range";
    case SegmentIssue::RecordPayloadCrc: return "record-payload-crc";
    default: return "unexpected-result";
    }
}

void ProbeVector(const std::filesystem::path& path, std::string_view stream)
{
    Check(stream == "1" || stream == "2", "unexpected fixture stream");
    auto identity = kIdentity;
    identity.stream = stream == "1" ? StreamKind::Raw : StreamKind::Records;
    const File file(path);
    const auto result = archive::InspectOpenSegment(file.handle, identity);
    Check(result && !result->interpretedBytes && !result->durableBytes, "invalid interpretation or durability claim");
    std::cout << VectorStatus(*result) << ' ' << result->framingCoverage.framedBytes << ' '
              << result->framingCoverage.blockCount << ' ' << result->unsupportedOptionalRecords << ' '
              << result->unsupportedRequiredRecords << '\n';
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--vector") {
            ProbeVector(argv[2], argv[3]);
            return 0;
        }
        Check(argc == 2, "pass a directory with materialized A0 Stored vectors named by case ID");
        TestNames();
        const std::filesystem::path directory(argv[1]);
        TestCoverage(directory);
        TestClassifications(directory);
        std::cout << "PASS archive.inspect names and six literal A0 Stored vectors\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
