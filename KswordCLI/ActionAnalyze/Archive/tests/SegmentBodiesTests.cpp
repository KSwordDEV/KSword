#include "../SegmentBodies.h"
#include "../SegmentWriter.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <windows.h>

namespace {

namespace archive = ks::cli::action_analyze::archive;
using archive::BodyIssue;
using archive::SegmentScanStatus;

constexpr archive::SegmentIdentity kIdentity{
    archive::StreamKind::Raw, 1,
    {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x43, 0x21, 0xa2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};

void Check(bool condition, const char* detail)
{
    if (!condition) {
        throw std::runtime_error(detail);
    }
}

struct File {
    explicit File(const std::filesystem::path& path)
        : handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
    {
        Check(handle != INVALID_HANDLE_VALUE, "open fixture for reading");
    }
    ~File() { CloseHandle(handle); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    HANDLE handle;
};

const char* Status(const archive::BodyFailure& failure)
{
    if (failure.issue == BodyIssue::None) return "ok";
    if (failure.recordType == 3) {
        if (failure.issue == BodyIssue::Length) return "raw.length";
        if (failure.issue == BodyIssue::Json) return "raw.json";
    } else if (failure.recordType == 4) {
        switch (failure.issue) {
        case BodyIssue::Length: return "event.length";
        case BodyIssue::Json: return "event.json";
        case BodyIssue::RequiredRef: return "event.requiredRef";
        case BodyIssue::ValidityBits: return "event.validityBits";
        case BodyIssue::ValidityValue: return "event.validityValue";
        default: break;
        }
    }
    return "unexpected-body-status";
}

void CheckRaw(const archive::DecodedRecord& record)
{
    const auto* raw = std::get_if<archive::RawRecordV1>(&record.body);
    Check(raw && record.recordType == 3 && record.recordSchemaVersion == 1 && (record.flags & 1) != 0,
          "RawRecord type, version and flags");
    Check(raw->metadataJson == "{}" && raw->inlineRawOffsetInPayload == 6 && raw->inlineRawBytes == 4,
          "RawRecord metadata and inline raw extent");
}

void CheckEvent(const archive::DecodedRecord& record)
{
    const auto* event = std::get_if<archive::CanonicalEventV1>(&record.body);
    Check(event && record.recordType == 4 && record.recordSchemaVersion == 1 && (record.flags & 1) != 0,
          "CanonicalEvent type, version and flags");
    Check(record.recordSequence == 29 && event->eventOrdinal == 0 && event->primaryRawRecordSequence == 0 &&
          event->producerSequence == 0 && event->sourceInstanceDictionaryId == 0x0102030405060708ULL &&
          event->sourceEpochDictionaryId == 0xfedcba9876543210ULL, "disjoint identity and sequence fields");
    Check(event->sourceTimestamp == 0x1011121314151617ULL && event->receiveQpc == 0x2122232425262728ULL &&
          event->actorProcessObjectId == 0x3132333435363738ULL && !event->targetProcessObjectId &&
          event->observedThreadObjectId == 0x4142434445464748ULL, "separate time and object roles");
    Check(event->operationDictionaryId == 0x5152535455565758ULL &&
          event->captureRevisionDictionaryId == 0x6162636465666768ULL &&
          event->effectiveRevisionDictionaryId == 0x7172737475767778ULL &&
          event->coverageDictionaryId == 0x8182838485868788ULL, "independent dictionary references");
    Check(event->eventKind == 0x11223344u && event->category == 0x5566 && event->phase == 0x77 &&
          event->clockDomain == 0x88 && event->validityBits == 2015 && event->fieldJson == "{}", "opaque enum codes and JSON");
}

void TestVector(const std::filesystem::path& path, std::string_view stream)
{
    auto expected = kIdentity;
    Check(stream == "1" || stream == "2", "unexpected stream for vector");
    if (stream == "2") expected.stream = archive::StreamKind::Records;
    const File file(path);
    std::uint64_t visited = 0;
    std::uint64_t projected = 0;
    const auto result = archive::ScanOpenSegmentBodies(file.handle, expected, std::nullopt,
        [&](const auto& identity, const auto&, const auto& records) {
            Check(identity.project == expected.project && identity.sample == expected.sample &&
                  identity.stream == expected.stream && identity.ordinal == expected.ordinal, "wrong visitor scope");
            ++visited;
            Check(records.size() == 1, "literal A0 blocks in this corpus each have one record");
            for (const auto& record : records) {
                if (!std::holds_alternative<std::monostate>(record.body)) {
                    if (expected.stream == archive::StreamKind::Raw) CheckRaw(record);
                    else CheckEvent(record);
                    ++projected;
                }
            }
            return true;
        });
    Check(!result.framing.interpretedBytes && visited == result.bodyCheckedBlocks, "framing state or visitor changed");
    Check(projected + result.opaqueOptionalRecords + result.opaqueRequiredRecords == visited,
          "missing typed metadata or opaque record accounting");
    if (result.bodyFailure.issue != BodyIssue::None) {
        Check(result.bodyFailure.recordOffset == 176 && result.framing.status == SegmentScanStatus::FramingComplete,
              "body failure changed frame status or byte offset");
    }
    std::cout << Status(result.bodyFailure) << ' ' << result.framing.framedBytes << ' ' << result.bodyCheckedBytes << ' '
              << result.bodyCheckedBlocks << ' ' << result.opaqueOptionalRecords << ' ' << result.opaqueRequiredRecords << '\n';
}

archive::StoredRecord Raw(std::string_view json, std::uint64_t sequence)
{
    const auto length = static_cast<std::uint32_t>(json.size());
    archive::StoredRecord record{3, 1, archive::kRequiredRecord, sequence, {}};
    for (unsigned index = 0; index < 4; ++index) {
        record.payload.push_back(static_cast<std::uint8_t>(length >> (8 * index)));
    }
    record.payload.insert(record.payload.end(), json.begin(), json.end());
    return record;
}

std::string Nested(std::size_t levels)
{
    return "{\"a\":" + std::string(levels, '[') + "0" + std::string(levels, ']') + '}';
}

void TestSynthetic(const std::filesystem::path& path)
{
    const auto check = [&](const std::vector<archive::StoredRecord>& records, BodyIssue issue) {
        archive::SegmentWriter writer(path, {kIdentity, 0});
        Check(writer.AppendBlock({Raw("{}", 0)}).status == archive::SegmentWriteStatus::Ok, "append first block");
        const auto firstEnd = writer.WrittenBytes();
        Check(writer.AppendBlock(records).status == archive::SegmentWriteStatus::Ok, "append test block");
        Check(writer.AppendBlock({Raw("{}", 3)}).status == archive::SegmentWriteStatus::Ok, "append last block");
        const auto fullEnd = writer.WrittenBytes();
        Check(writer.Close().status == archive::SegmentWriteStatus::Ok, "close test writer");
        {
            const File file(path);
            std::vector<std::uint64_t> visited;
            const auto result = archive::ScanOpenSegmentBodies(file.handle, kIdentity, std::nullopt,
                [&](const auto&, const auto&, const auto& decoded) {
                    for (const auto& record : decoded) visited.push_back(record.recordSequence);
                    return true;
                });
            Check(result.framing.status == SegmentScanStatus::FramingComplete && result.framing.framedBytes == fullEnd &&
                  result.bodyFailure.issue == issue, "test block was misclassified");
            const bool allChecked = issue == BodyIssue::None;
            Check(result.bodyCheckedBytes == (allChecked ? fullEnd : firstEnd) &&
                  result.bodyCheckedBlocks == (allChecked ? 3u : 1u), "body validation published an incomplete block");
            Check(visited.size() == (allChecked ? records.size() + 2 : 1) && visited.front() == 0 &&
                  visited.back() == (allChecked ? 3u : 0u), "body visitor escaped the validated prefix");
            if (allChecked && records.front().type != 3) {
                Check(result.opaqueRequiredRecords == 1 && result.framing.unsupportedRequiredRecords == 0,
                      "in-catalog undecoded required type was missed");
            }
        }
        Check(DeleteFileW(path.c_str()) != 0, "clean test segment");
    };
    const std::pair<std::string, BodyIssue> jsonCases[] = {
        {"{\"limits\":[-2147483648,4294967295,-0,0],\"str\":\"02\\uD83D\\uDE00\"}", BodyIssue::None},
        {"{\"a\":01}", BodyIssue::Json},
        {"{\"a\":-2147483649}", BodyIssue::Json},
        {"{\"a\":4294967296}", BodyIssue::Json},
        {"{\"a\":1e2}", BodyIssue::Json},
        {"{\"a\":1.2}", BodyIssue::Json},
        {"{\"a\":0,\"\\u0061\":1}", BodyIssue::Json},
        {"{\"a\":\"\\uD800\"}", BodyIssue::Json},
        {"{\"a\":\"\xc0\x80\"}", BodyIssue::Json},
        {"\xef\xbb\xbf{}", BodyIssue::Json},
        {"{}{}", BodyIssue::Json},
        {Nested(31), BodyIssue::None},
        {Nested(32), BodyIssue::Json},
        {"{\"a\":\"" + std::string(65536, 'x') + "\"}", BodyIssue::None},
        {"{\"a\":\"" + std::string(65537, 'x') + "\"}", BodyIssue::Json},
        {"{}" + std::string(4u * 1024u * 1024u - 2, ' '), BodyIssue::None},
        {"{}" + std::string(4u * 1024u * 1024u - 1, ' '), BodyIssue::Json},
    };
    for (const auto& [json, issue] : jsonCases) {
        check({Raw("{}", 1), Raw(json, 2)}, issue);
    }
    check({{11, 1, archive::kRequiredRecord, 1, {}}}, BodyIssue::None);
    std::vector<std::uint8_t> event(130, 0);
    event[124] = 2;
    event[128] = '{';
    event[129] = '}';
    check({{4, 1, archive::kRequiredRecord, 1, event}}, BodyIssue::RequiredRef);
    event[16] = 1;
    event[24] = 1;
    event[120] = 0x10;
    check({{4, 1, archive::kRequiredRecord, 1, event}}, BodyIssue::ValidityValue);

    std::string largeArray = "{\"a\":[";
    for (int index = 0; index < 524288; ++index) largeArray += "0,";
    largeArray += "0]}";
    check({Raw(largeArray, 1)}, BodyIssue::JsonBudget);
    std::cout << "PASS " << std::size(jsonCases) + 4 << " bounded body cases with prefix checks\n";
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--vector") {
            TestVector(argv[2], argv[3]);
        } else {
            Check(argc == 2, "pass a fixed scratch directory");
            TestSynthetic(std::filesystem::path(argv[1]) / "body-synthetic.ksaseg");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
