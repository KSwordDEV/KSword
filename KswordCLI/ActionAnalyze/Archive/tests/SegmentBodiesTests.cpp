#include "../SegmentBodies.h"
#include "../SegmentWriter.h"

#include <iostream>
#include <iterator>
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
    // 字节向量包含 NUL 和非 UTF-8 字节，读回值保持原样。
    Check(raw->inlineRawData == std::string_view("\x00\xff\x80\x4b", 4), "RawRecord callback preserves inline bytes");
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

void TestEtwCoverage(const std::filesystem::path& path)
{
    constexpr std::string_view golden =
        R"({"kind":"etw-coverage-v1","providerId":"12345678-9abc-4def-8123-456789abcdef",)"
        R"("sourceEpoch":"fedcba98-7654-4321-a234-56789abcdef0","rawSegmentOrdinal":"1",)"
        R"("planRawSequence":"1","endRawSequence":"2","observationCount":"0","eventsLost":null,)"
        R"("logBuffersLost":null,"realTimeBuffersLost":null,"queueDropped":"0",)"
        R"("payloadTruncated":"0","malformedPayload":"0"})";
    const archive::EtwCoverageV1 zero{"12345678-9abc-4def-8123-456789abcdef",
        "fedcba98-7654-4321-a234-56789abcdef0", 1, 1, 2, 0, {}, {}, {}, 0, 0, 0};
    const auto payloadText = [](const std::vector<std::uint8_t>& bytes) {
        return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    };
    std::vector<std::uint8_t> payload;
    Check(archive::EncodeEtwCoverageV1(zero, payload) == BodyIssue::None && payloadText(payload) == golden,
          "ETW Coverage v1 golden payload");
    const auto goldenPayload = payload;
    auto decoded = zero;
    decoded.endRawSequence = 9;
    Check(archive::DecodeEtwCoverageV1(golden, decoded) == BodyIssue::None &&
          decoded.endRawSequence == 2 && !decoded.eventsLost && !decoded.logBuffersLost && !decoded.realTimeBuffersLost,
          "zero observations and unknown STOP counters");

    // 上界用例验证序号差值无溢出，系统已知零不与 null 混同。
    auto known = zero;
    known.rawSegmentOrdinal = UINT64_MAX;
    known.planRawSequence = UINT64_MAX - 2;
    known.endRawSequence = UINT64_MAX;
    known.observationCount = 1;
    known.eventsLost = 0;
    known.logBuffersLost = UINT32_MAX;
    known.realTimeBuffersLost = 3;
    known.queueDropped = UINT64_MAX;
    known.payloadTruncated = 5;
    known.malformedPayload = 7;
    Check(archive::EncodeEtwCoverageV1(known, payload) == BodyIssue::None &&
          archive::DecodeEtwCoverageV1(payloadText(payload), decoded) == BodyIssue::None &&
          decoded.providerId == known.providerId && decoded.sourceEpoch == known.sourceEpoch &&
          decoded.rawSegmentOrdinal == known.rawSegmentOrdinal && decoded.planRawSequence == known.planRawSequence &&
          decoded.endRawSequence == known.endRawSequence && decoded.observationCount == known.observationCount &&
          decoded.eventsLost == known.eventsLost && decoded.logBuffersLost == known.logBuffersLost &&
          decoded.realTimeBuffersLost == known.realTimeBuffersLost && decoded.queueDropped == known.queueDropped &&
          decoded.payloadTruncated == known.payloadTruncated && decoded.malformedPayload == known.malformedPayload,
          "lossless ETW coverage round trip");
    auto invalid = known;
    invalid.realTimeBuffersLost.reset();
    const auto before = payload;
    Check(archive::EncodeEtwCoverageV1(invalid, payload) == BodyIssue::CoverageFields && payload == before,
          "encoder preserves output on invalid known counters");
    invalid = zero;
    invalid.endRawSequence = invalid.planRawSequence;
    Check(archive::EncodeEtwCoverageV1(invalid, payload) == BodyIssue::CoverageFields && payload == before,
          "encoder rejects an empty endpoint interval");

    const auto replace = [&](std::string_view find, std::string_view value) {
        std::string text(golden);
        const auto offset = text.find(find);
        Check(offset != text.npos, "missing golden substitution token");
        text.replace(offset, find.size(), value);
        return text;
    };
    const std::pair<std::string, BodyIssue> cases[] = {
        {replace(R"("kind":"etw-coverage-v1")", R"("kind":"other-coverage-v1")"), BodyIssue::UnsupportedKind},
        {replace(R"("kind":"etw-coverage-v1",)", ""), BodyIssue::UnsupportedKind},
        {replace(R"("providerId":)", R"("extra":null,"providerId":)"), BodyIssue::CoverageFields},
        {replace(R"(,"malformedPayload":"0")", ""), BodyIssue::CoverageFields},
        {replace(R"("queueDropped":"0")", R"("queueDropped":"18446744073709551616")"), BodyIssue::CoverageFields},
        {replace(R"("queueDropped":"0")", R"("queueDropped":"00")"), BodyIssue::CoverageFields},
        {replace(R"("payloadTruncated":"0")", R"("payloadTruncated":0)"), BodyIssue::CoverageFields},
        {replace(R"("rawSegmentOrdinal":"1")", R"("rawSegmentOrdinal":"0")"), BodyIssue::CoverageFields},
        {replace(R"("planRawSequence":"1")", R"("planRawSequence":"3")"), BodyIssue::CoverageFields},
        {replace(R"("observationCount":"0")", R"("observationCount":"1")"), BodyIssue::CoverageFields},
        {replace(R"("eventsLost":null)", R"("eventsLost":0)"), BodyIssue::CoverageFields},
        {replace(R"("eventsLost":null)", R"("eventsLost":"0")"), BodyIssue::CoverageFields},
        {replace(R"("eventsLost":null)", R"("eventsLost":4294967296)"), BodyIssue::Json},
        {replace(R"("eventsLost":null,"logBuffersLost":null,"realTimeBuffersLost":null)",
                 R"("eventsLost":-0,"logBuffersLost":0,"realTimeBuffersLost":0)"), BodyIssue::None},
        {replace("12345678-9abc-4def-8123-456789abcdef", "12345678-9Abc-4def-8123-456789abcdef"), BodyIssue::CoverageFields},
        {replace("fedcba98-7654-4321-a234-56789abcdef0", "00000000-0000-0000-0000-000000000000"), BodyIssue::CoverageFields},
        {replace(R"("queueDropped":"0")", R"("queueDropped":"0","\u0071ueueDropped":"0")"), BodyIssue::Json},
        {replace("12345678-9abc-4def-8123-456789abcdef", "\xc0\x80"), BodyIssue::Json},
        {replace("fedcba98-7654-4321-a234-56789abcdef0", R"(\uD800)"), BodyIssue::Json},
        {"\xef\xbb\xbf" + std::string(golden), BodyIssue::Json},
        {std::string(golden) + "Unexpected tail", BodyIssue::Json},
        {std::string(golden) + std::string(archive::kMaxEtwCoverageV1Bytes - golden.size(), ' '), BodyIssue::None},
        {std::string(golden) + std::string(archive::kMaxEtwCoverageV1Bytes - golden.size() + 1, ' '), BodyIssue::Length},
    };
    for (const auto& [json, issue] : cases) {
        decoded.observationCount = UINT64_MAX;
        Check(archive::DecodeEtwCoverageV1(json, decoded) == issue, "ETW coverage strict payload case");
        Check(decoded.observationCount == (issue == BodyIssue::None ? 0 : UINT64_MAX),
              "ETW coverage decoder assignment boundary");
    }

    const auto scan = [&](std::string_view json, std::uint32_t flags,
                          archive::StreamKind stream, BodyIssue issue, bool expectTyped) {
        auto identity = kIdentity;
        identity.stream = stream;
        archive::SegmentWriter writer(path, {identity, 0});
        const auto record = [](std::string_view body, std::uint32_t recordFlags, std::uint64_t seq) {
            return archive::StoredRecord{archive::kCoverageRecordType, 1, recordFlags, seq,
                std::vector<std::uint8_t>(body.begin(), body.end())};
        };
        const archive::StoredRecord first{archive::kCoverageRecordType, 1, archive::kRequiredRecord, 1, goldenPayload};
        Check(writer.AppendBlock({first}).status == archive::SegmentWriteStatus::Ok,
              "append baseline coverage block");
        const auto firstEnd = writer.WrittenBytes();
        Check(writer.AppendBlock({record(json, flags, 2)}).status == archive::SegmentWriteStatus::Ok,
              "append tested coverage block");
        const auto fullEnd = writer.WrittenBytes();
        Check(writer.Flush().status == archive::SegmentWriteStatus::Ok &&
              writer.Close().status == archive::SegmentWriteStatus::Ok, "finish coverage blocks");
        {
            const File file(path);
            std::uint64_t visited = 0;
            const auto result = archive::ScanOpenSegmentBodies(file.handle, identity, std::nullopt,
                [&](const auto&, const auto&, const auto& records) {
                    Check(records.size() == 1 && records.front().recordSequence == ++visited, "coverage block order");
                    const auto* coverage = std::get_if<archive::EtwCoverageV1>(&records.front().body);
                    const bool typed = visited == 1 ? stream == archive::StreamKind::Records : expectTyped;
                    Check((coverage != nullptr) == typed, "coverage body dispatch");
                    if (coverage) {
                        Check(coverage->providerId == zero.providerId && coverage->endRawSequence == zero.endRawSequence,
                              "projected coverage data");
                    }
                    return true;
                });
            const bool ok = issue == BodyIssue::None;
            Check(result.framing.status == SegmentScanStatus::FramingComplete && result.framing.framedBytes == fullEnd &&
                  !result.framing.interpretedBytes && result.bodyFailure.issue == issue && visited == (ok ? 2u : 1u) &&
                  result.bodyCheckedBytes == (ok ? fullEnd : firstEnd), "coverage checked prefix versus framing");
            if (!ok) {
                Check(result.bodyFailure.recordType == archive::kCoverageRecordType &&
                      result.bodyFailure.recordOffset == firstEnd + archive::kBlockHeaderBytes, "coverage failure location");
            }
            const unsigned baselineOpaque = stream == archive::StreamKind::Records ? 0u : 1u;
            const bool opaque = ok && !expectTyped;
            Check(result.opaqueRequiredRecords == baselineOpaque + (opaque && flags != 0 ? 1u : 0u) &&
                  result.opaqueOptionalRecords == (opaque && flags == 0 ? 1u : 0u), "opaque coverage record counts");
        }
        Check(DeleteFileW(path.c_str()) != 0, "clean coverage test segment");
    };
    const auto stream = archive::StreamKind::Records;
    const auto required = archive::kRequiredRecord;
    scan(golden, required, stream, BodyIssue::None, true);
    scan(golden, 0, stream, BodyIssue::CoverageFlags, false);
    scan(golden, required, archive::StreamKind::Raw, BodyIssue::None, false);
    scan(R"({"kind":"etw-coverage-v2"})", required, stream, BodyIssue::None, false);
    scan(R"({"kind":"other-coverage-v1"})" + std::string(1024, ' '), 0, stream, BodyIssue::None, false);
    scan(R"({"kind":"etw-coverage-v1"})", required, stream, BodyIssue::CoverageFields, false);
    scan(std::string(golden) + std::string(1024, ' '), required, stream, BodyIssue::Length, false);
    std::cout << "PASS ETW coverage golden payload, " << std::size(cases) << " strict cases and 7 Stored scan cases\n";
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--vector") {
            TestVector(argv[2], argv[3]);
        } else {
            Check(argc == 2, "pass a fixed scratch directory");
            const auto path = std::filesystem::path(argv[1]) / "body-synthetic.ksaseg";
            TestSynthetic(path);
            TestEtwCoverage(path);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
