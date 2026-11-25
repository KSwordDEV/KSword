#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentReader.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentWriter.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <windows.h>

namespace {

namespace archive = ks::cli::action_analyze::archive;
using Bytes = std::vector<std::uint8_t>;
using archive::ScanSegment;
using archive::SegmentIssue;
using archive::SegmentScanStatus;
using archive::SegmentWriteStatus;

constexpr std::uint64_t kLast = (std::numeric_limits<std::uint64_t>::max)();
constexpr std::size_t kFirstBlock = 96;
constexpr std::size_t kFirstRecord = kFirstBlock + 80;
constexpr std::size_t kSecondRecord = kFirstRecord + 32 + 3;
constexpr std::size_t kSecondBlock = kSecondRecord + 32;
constexpr std::size_t kThirdBlock = kSecondBlock + 80 + 32 + 1;

void Check(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class Fixture final {
public:
    explicit Fixture(std::filesystem::path path) : path_(std::move(path))
    {
        const auto file = CreateFileW(path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(file != INVALID_HANDLE_VALUE, "cannot create test fixture (path already exists or is unavailable)");
        CloseHandle(file);
    }

    ~Fixture() { DeleteFileW(path_.c_str()); }

    const std::filesystem::path& path() const { return path_; }

    void Write(const Bytes& bytes, std::size_t size) const
    {
        std::ofstream file(path_, std::ios::binary | std::ios::trunc);
        if (size != 0) {
            file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(size));
        }
        file.close();
        Check(file.good(), "cannot write test fixture");
    }

private:
    std::filesystem::path path_;
};

Bytes ReadAll(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    Check(file.good(), "cannot open test fixture");
    return Bytes(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// 独立逐位 CRC 与字段写入，供合成合法块、坏块和逐字节比较。
std::uint32_t ReferenceCrc(const Bytes& bytes, std::size_t offset, std::size_t size)
{
    std::uint32_t state = 0xffffffffu;
    for (std::size_t i = offset; i < offset + size; ++i) {
        state ^= bytes.at(i);
        for (unsigned int bit = 0; bit < 8; ++bit) {
            const std::uint32_t polynomial = (state % 2u) != 0 ? 0x82f63b78u : 0;
            state = (state / 2u) ^ polynomial;
        }
    }
    return ~state;
}

void Put(Bytes& bytes, std::size_t offset, std::size_t size, std::uint64_t value)
{
    for (std::size_t i = 0; i < size; ++i) {
        bytes.at(offset + i) = static_cast<std::uint8_t>(value % 256);
        value /= 256;
    }
}

void FixHeader(Bytes& bytes, std::size_t offset, std::size_t size)
{
    Put(bytes, offset + size - 4, 4, ReferenceCrc(bytes, offset, size - 4));
}

void FixBlock(Bytes& bytes, std::size_t offset, std::size_t size)
{
    const auto crc = ReferenceCrc(bytes, offset + 80, size);
    Put(bytes, offset + 64, 4, crc);
    Put(bytes, offset + 68, 4, crc);
    FixHeader(bytes, offset, 80);
}

Bytes ReferenceSegment()
{
    Bytes bytes(kThirdBlock + 80 + 32, 0);
    std::copy_n("KSAASEG", 7, bytes.begin());
    Put(bytes, 8, 2, 1);
    Put(bytes, 12, 4, 96);
    Put(bytes, 20, 4, 1);
    Put(bytes, 24, 8, 256);
    for (std::uint8_t i = 0; i < 32; ++i) {
        bytes[32u + i] = static_cast<std::uint8_t>(0x11u + i);
    }
    Put(bytes, 64, 8, 0x0123456789abcdefull);
    FixHeader(bytes, 0, 96);

    const auto record = [&](std::size_t offset, std::uint16_t type, std::uint32_t flags,
                            std::uint64_t sequence, const Bytes& payload) {
        Put(bytes, offset, 4, 32 + payload.size());
        Put(bytes, offset + 4, 2, type);
        Put(bytes, offset + 6, 2, 1);
        Put(bytes, offset + 8, 4, flags);
        Put(bytes, offset + 12, 4, payload.size());
        Put(bytes, offset + 16, 8, sequence);
        std::copy(payload.begin(), payload.end(), bytes.begin() + offset + 32);
        Put(bytes, offset + 24, 4, ReferenceCrc(bytes, offset + 32, payload.size()));
        FixHeader(bytes, offset, 32);
    };
    const auto block = [&](std::size_t offset, std::uint32_t count, std::uint64_t ordinal,
                           std::uint64_t first, std::uint64_t last, std::uint32_t size, bool qpcValid) {
        std::copy_n("AAB1", 4, bytes.begin() + offset);
        Put(bytes, offset + 4, 2, 80);
        Put(bytes, offset + 6, 2, 1);
        Put(bytes, offset + 10, 2, qpcValid ? 1 : 0);
        Put(bytes, offset + 12, 4, count);
        Put(bytes, offset + 16, 8, ordinal);
        Put(bytes, offset + 24, 8, first);
        Put(bytes, offset + 32, 8, last);
        Put(bytes, offset + 40, 4, size);
        Put(bytes, offset + 44, 4, size);
        FixBlock(bytes, offset, size);
    };
    record(kFirstRecord, 3, 1, 0, {0x41, 0, 0xff});
    record(kSecondRecord, 11, 0, 90, {});
    block(kFirstBlock, 2, 1, 0, 90, 67, true);
    record(kSecondBlock + 80, 3, 0, kLast - 2, {0x42});
    block(kSecondBlock, 1, 2, kLast - 2, kLast - 2, 33, false);
    record(kThirdBlock + 80, 11, 0, kLast, {});
    block(kThirdBlock, 1, 3, kLast, kLast, 32, false);
    return bytes;
}

void TestWriter(const std::filesystem::path& path, const Bytes& expected)
{
    archive::SegmentHeader header;
    header.identity.stream = archive::StreamKind::Raw;
    header.identity.ordinal = 256;
    std::copy_n(expected.data() + 32, 16, header.identity.project.begin());
    std::copy_n(expected.data() + 48, 16, header.identity.sample.begin());
    header.createdUtc100ns = 0x0123456789abcdefull;
    archive::SegmentWriter writer(path, header);
    const std::vector<archive::StoredRecord> first{{3, 1, 1, 0, {0x41, 0, 0xff}}, {11, 1, 0, 90, {}}};
    const std::vector<archive::StoredRecord> second{{3, 1, 0, kLast - 2, {0x42}}};
    const std::vector<archive::StoredRecord> third{{11, 1, 0, kLast, {}}};
    Check(writer.AppendBlock({}).error.issue == SegmentIssue::RecordCount, "accepted empty block");
    Check(writer.AppendBlock(first, archive::QpcRange{3, 2}).error.issue == SegmentIssue::QpcRange, "accepted reversed QPC");
    Check(writer.AppendBlock({{23, 1, 0, 0, {}}}).error.issue == SegmentIssue::RecordSchema, "accepted unknown write schema");
    Check(writer.AppendBlock({{3, 1, 0, 0, Bytes(8u << 20)}}).error.issue == SegmentIssue::BlockLength,
          "accepted oversized write block");
    Check(!std::filesystem::exists(path) && writer.WrittenBytes() == 0, "invalid input created an empty segment");
    Check(writer.AppendBlock(first, archive::QpcRange{}).status == SegmentWriteStatus::Ok, "cannot append initial block");
    Check(writer.WrittenBytes() == kSecondBlock && writer.FlushedBytes() == 0, "wrong initial writer watermarks");
    Check(writer.Flush().status == SegmentWriteStatus::Ok && writer.FlushedBytes() == kSecondBlock, "flush watermark did not advance");
    Check(writer.AppendBlock(first).error.issue == SegmentIssue::Sequence, "accepted backward writer sequence");

    archive::SegmentScanOptions options;
    options.expectedIdentity = header.identity;
    const auto initial = ScanSegment(path, options, [&](const auto& block, const auto& records) {
        Check(block.ordinal == 1 && block.endOffset == kSecondBlock && block.receiveQpc.has_value(), "wrong first block locator/QPC");
        Check(block.receiveQpc->minimum == 0 && block.receiveQpc->maximum == 0, "zero QPC lost");
        Check(records.size() == 2 && records[0].catalogTypeV1 && records[0].sequence == 0 &&
              records[0].offset == kFirstRecord && records[0].payloadBytes == 3 && records[0].payload[2] == 0xff &&
              records[1].payloadBytes == 0 && records[1].sequence == 90, "wrong record views");
        Check(writer.AppendBlock(second).status == SegmentWriteStatus::Ok, "live append while reading failed");
        return true;
    });
    Check(initial.status == SegmentScanStatus::FramingComplete && initial.fileBytes == kSecondBlock && initial.blockCount == 1,
          "reader did not freeze initial file endpoint");
    Check(!initial.interpretedBytes && initial.requiredRecordCount == 1 && initial.unsupportedRequiredRecords == 0,
          "invalid RawRecord payload was reported interpreted");
    Check(writer.AppendBlock(third).status == SegmentWriteStatus::Ok, "cannot append maximum sequence");
    Check(writer.AppendBlock(third).error.issue == SegmentIssue::Sequence, "accepted duplicate maximum sequence");
    Check(writer.Close().status == SegmentWriteStatus::Ok && writer.FlushedBytes() == kSecondBlock, "close changed flush state");
    Check(writer.AppendBlock(third).status == SegmentWriteStatus::Closed, "closed writer accepted append");
    Check(ReadAll(path) == expected, "writer bytes disagree with independent encoder");

    archive::SegmentWriter conflict(path, header);
    const auto failure = conflict.AppendBlock(first);
    Check(failure.status == SegmentWriteStatus::IoError && failure.error.issue == SegmentIssue::FileOpen &&
          failure.error.win32Error == ERROR_FILE_EXISTS, "existing segment not rejected");
    Check(conflict.Flush().error.win32Error == failure.error.win32Error && ReadAll(path) == expected,
          "create-new failure lost first error or modified the source");
}

void TestReader(const Fixture& fixture, const Bytes& valid)
{
    // 每个可能的截断字节都验证前缀端点及块发布次数。
    for (std::size_t size = 0; size <= valid.size(); ++size) {
        fixture.Write(valid, size);
        const auto prefix = size >= valid.size() ? valid.size() : size >= kThirdBlock ? kThirdBlock :
                            size >= kSecondBlock ? kSecondBlock : size >= kFirstBlock ? kFirstBlock : 0;
        const auto blocks = size >= valid.size() ? 3u : size >= kThirdBlock ? 2u : size >= kSecondBlock ? 1u : 0u;
        unsigned int callbacks = 0;
        const auto result = ScanSegment(fixture.path(), {}, [&](const auto&, const auto&) { ++callbacks; return true; });
        const auto status = size != 0 && size == prefix ? SegmentScanStatus::FramingComplete : SegmentScanStatus::Truncated;
        Check(result.status == status && result.framedBytes == prefix && result.blockCount == blocks && callbacks == blocks,
              "cut did not preserve only complete blocks");
        if (status == SegmentScanStatus::Truncated) {
            Check(result.error.offset == size, "unexpected first missing byte offset");
        }
    }

    const auto checkFailure = [&](Bytes mutation, SegmentScanStatus status, SegmentIssue issue, std::size_t prefix) {
        fixture.Write(mutation, mutation.size());
        unsigned int callbacks = 0;
        const auto result = ScanSegment(fixture.path(), {}, [&](const auto&, const auto&) { ++callbacks; return true; });
        Check(result.status == status && result.error.issue == issue && result.framedBytes == prefix &&
              callbacks == (prefix == kSecondBlock ? 1u : 0u), "unexpected bad-block classification or callback");
        Check(ReadAll(fixture.path()) == mutation, "read-only recovery changed the source");
    };

    auto mutation = valid;
    mutation[9] ^= 1;
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::HeaderCrc, 0);
    FixHeader(mutation, 0, 96);
    checkFailure(mutation, SegmentScanStatus::Unsupported, SegmentIssue::Version, 0);
    mutation = valid;
    Put(mutation, 16, 4, 1);
    FixHeader(mutation, 0, 96);
    checkFailure(mutation, SegmentScanStatus::Unsupported, SegmentIssue::Flags, 0);
    mutation = valid;
    Put(mutation, kSecondBlock + 8, 2, 1);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Unsupported, SegmentIssue::Codec, kSecondBlock);
    Put(mutation, kSecondBlock + 44, 4, (9u << 20) + 1u);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::BlockLength, kSecondBlock);
    mutation = valid;
    Put(mutation, kSecondBlock + 40, 4, 32);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::BlockLength, kSecondBlock);
    mutation = valid;
    Put(mutation, kSecondBlock + 12, 4, 32769);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::RecordCount, kSecondBlock);
    mutation = valid;
    Put(mutation, kSecondBlock + 16, 8, 1);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::Ordinal, kSecondBlock);
    mutation = valid;
    Put(mutation, kSecondBlock + 10, 2, 1);
    Put(mutation, kSecondBlock + 48, 8, 1);
    FixHeader(mutation, kSecondBlock, 80);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::QpcRange, kSecondBlock);
    mutation = valid;
    mutation[kSecondBlock + 80 + 32] ^= 1;
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::StoredCrc, kSecondBlock);
    FixBlock(mutation, kSecondBlock, 33);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::RecordPayloadCrc, kSecondBlock);
    mutation = valid;
    mutation[kSecondRecord + 28] ^= 1;
    FixBlock(mutation, kFirstBlock, 67);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::HeaderCrc, kFirstBlock);
    Put(mutation, kSecondRecord, 4, 0xffffffffu);
    FixHeader(mutation, kSecondRecord, 32);
    FixBlock(mutation, kFirstBlock, 67);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::RecordLength, kFirstBlock);
    mutation = valid;
    Put(mutation, kSecondRecord + 16, 8, 0);
    FixHeader(mutation, kSecondRecord, 32);
    FixBlock(mutation, kFirstBlock, 67);
    checkFailure(mutation, SegmentScanStatus::Corrupt, SegmentIssue::Sequence, kFirstBlock);

    mutation = valid;
    Put(mutation, kFirstRecord + 6, 2, 2);
    Put(mutation, kSecondRecord + 4, 2, 65535);
    FixHeader(mutation, kFirstRecord, 32);
    FixHeader(mutation, kSecondRecord, 32);
    FixBlock(mutation, kFirstBlock, 67);
    fixture.Write(mutation, mutation.size());
    const auto unknown = ScanSegment(fixture.path());
    Check(unknown.status == SegmentScanStatus::FramingComplete && unknown.unsupportedOptionalRecords == 1 &&
          unknown.unsupportedRequiredRecords == 1 && unknown.requiredRecordCount == 1 && !unknown.interpretedBytes &&
          unknown.lastSequence == kLast, "unknown record schema counters failed");

    mutation = valid;
    Put(mutation, kSecondRecord + 8, 4, 1);
    FixHeader(mutation, kSecondRecord, 32);
    FixBlock(mutation, kFirstBlock, 67);
    fixture.Write(mutation, mutation.size());
    const auto opaqueRequired = ScanSegment(fixture.path());
    Check(opaqueRequired.status == SegmentScanStatus::FramingComplete && opaqueRequired.framedBytes == mutation.size() &&
          opaqueRequired.requiredRecordCount == 2 && opaqueRequired.unsupportedRequiredRecords == 0 &&
          !opaqueRequired.interpretedBytes, "catalogued opaque required record was reported interpreted");

    archive::SegmentScanOptions opts;
    opts.endOffset = kSecondBlock;
    const auto bounded = ScanSegment(fixture.path(), opts);
    Check(bounded.status == SegmentScanStatus::FramingComplete && bounded.framedBytes == kSecondBlock && bounded.fileBytes == valid.size(),
          "checkpoint boundary was ignored");
    opts.endOffset = valid.size() + 1;
    Check(ScanSegment(fixture.path(), opts).status == SegmentScanStatus::Truncated, "missing checkpoint bytes reported complete");
    opts.endOffset.reset();
    opts.previousSequence = 0;
    Check(ScanSegment(fixture.path(), opts).error.issue == SegmentIssue::Sequence, "previous-segment sequence boundary ignored");
    opts.expectedIdentity = archive::SegmentIdentity{};
    Check(ScanSegment(fixture.path(), opts).error.issue == SegmentIssue::Identity, "wrong segment identity accepted");

    const auto stopped = ScanSegment(fixture.path(), {}, [](const auto&, const auto&) { return false; });
    Check(stopped.status == SegmentScanStatus::Stopped && stopped.framedBytes == kSecondBlock, "visitor cancellation lost delivered prefix");
}

const char* ProbeStatus(const archive::SegmentScanResult& scan)
{
    switch (scan.status) {
    case SegmentScanStatus::FramingComplete: return "framing-complete";
    case SegmentScanStatus::Truncated: return "truncated";
    default: break;
    }
    switch (scan.error.issue) {
    case SegmentIssue::HeaderCrc: return scan.error.offset == 0 ? "segment.headerCrc" : "block.headerCrc";
    case SegmentIssue::Identity: return "segment.identity";
    case SegmentIssue::StoredCrc: return "block.storedCrc";
    case SegmentIssue::Codec: return "block.codec";
    case SegmentIssue::BlockLength: return "block.length";
    case SegmentIssue::RecordCount: return "block.recordCount";
    case SegmentIssue::Sequence: return "record.sequence";
    default: return "unexpected-status";
    }
}

void ProbeA0Vector(const std::filesystem::path& path, std::string_view stream)
{
    constexpr archive::ArchiveUuid project{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef,
                                           0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    constexpr archive::ArchiveUuid sample{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x43, 0x21,
                                          0xa2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    Check(stream == "1" || stream == "2", "unexpected vector stream");
    archive::SegmentScanOptions options;
    options.expectedIdentity = archive::SegmentIdentity{stream == "1" ? archive::StreamKind::Raw : archive::StreamKind::Records,
                                                        1, project, sample};
    const auto scan = ScanSegment(path, options);
    Check(!scan.interpretedBytes, "framing scan unexpectedly reported interpreted bytes");
    std::cout << ProbeStatus(scan) << ' ' << scan.framedBytes << ' ' << scan.blockCount << ' '
              << scan.unsupportedOptionalRecords << ' ' << scan.unsupportedRequiredRecords << '\n';
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--a0-vector") {
            ProbeA0Vector(argv[2], argv[3]);
            return 0;
        }
        Check(argc == 2, "pass the path of a new fixed scratch directory");
        const std::filesystem::path directory(argv[1]);
        Check(std::filesystem::is_directory(directory), "scratch directory is missing");
        const auto path = directory / "writer.ksaseg";
        Check(!std::filesystem::exists(path), "writer fixture already exists");
        const Fixture fixture(directory / "reader.ksaseg");
        const auto* standard = reinterpret_cast<const std::uint8_t*>("123456789");
        Check(archive::Crc32c(standard, 9) == 0xe3069283u, "CRC32C standard check failed");
        const auto expected = ReferenceSegment();
        TestWriter(path, expected);
        TestReader(fixture, expected);
        Check(std::filesystem::remove(path), "cannot clean writer fixture");
        std::cout << "PASS Stored segment writer, scanner and " << expected.size() + 1 << " EOF boundaries\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
