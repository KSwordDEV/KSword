#include "SegmentReader.h"

#include "SegmentWire.h"

#include <algorithm>
#include <windows.h>

namespace ks::cli::action_analyze::archive {
namespace {

struct ReadHandle {
    HANDLE value = INVALID_HANDLE_VALUE;

    ~ReadHandle()
    {
        if (value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
};

struct ScanFailure {
    SegmentScanStatus status = SegmentScanStatus::FramingComplete;
    SegmentError error;

    explicit operator bool() const noexcept { return status != SegmentScanStatus::FramingComplete; }
};

ScanFailure Corrupt(SegmentIssue issue, std::uint64_t offset) noexcept
{
    return {SegmentScanStatus::Corrupt, {issue, offset}};
}

ScanFailure Unsupported(SegmentIssue issue, std::uint64_t offset) noexcept
{
    return {SegmentScanStatus::Unsupported, {issue, offset}};
}

ScanFailure Truncated(std::uint64_t offset) noexcept
{
    return {SegmentScanStatus::Truncated, {SegmentIssue::EndOfFile, offset}};
}

ScanFailure ReadBytes(HANDLE handle, std::uint8_t* bytes, std::uint32_t requested,
                      std::uint64_t offset, DWORD& read) noexcept
{
    if (requested == 0) {
        return {};
    }
    if (!ReadFile(handle, bytes, requested, &read, nullptr)) {
        const auto error = GetLastError();
        if (error == ERROR_HANDLE_EOF) {
            return Truncated(offset);
        }
        return {SegmentScanStatus::IoError, {SegmentIssue::FileRead, offset, error}};
    }
    if (read != requested) {
        return Truncated(offset + read);
    }
    return {};
}

template <std::size_t HeaderSize, std::size_t MagicSize>
ScanFailure ReadHeader(HANDLE handle, std::array<std::uint8_t, HeaderSize>& bytes,
                       const std::array<std::uint8_t, MagicSize>& magic,
                       std::uint64_t offset, std::uint64_t end) noexcept
{
    const auto requested = static_cast<std::uint32_t>(std::min<std::uint64_t>(HeaderSize, end - offset));
    DWORD read = 0;
    const auto failure = ReadBytes(handle, bytes.data(), requested, offset, read);
    if (failure.status == SegmentScanStatus::IoError) {
        return failure;
    }
    // 半头可恢复。已读到的魔数前缀不符则已有损坏证据。
    if (!std::equal(magic.begin(), magic.begin() + std::min<std::size_t>(MagicSize, read), bytes.begin())) {
        return Corrupt(SegmentIssue::Magic, offset);
    }
    if (read < HeaderSize) {
        return Truncated(offset + read);
    }
    return {};
}

ScanFailure DecodeSegmentHeader(const std::array<std::uint8_t, kSegmentHeaderBytes>& bytes,
                                SegmentHeader& header) noexcept
{
    const auto* data = bytes.data();
    if (wire::Get<std::uint32_t>(data, 92) != Crc32c(data, 92)) {
        return Corrupt(SegmentIssue::HeaderCrc, 0);
    }
    if (wire::Get<std::uint16_t>(data, 8) != wire::kSegmentMajor ||
        wire::Get<std::uint16_t>(data, 10) != wire::kSegmentMinor) {
        return Unsupported(SegmentIssue::Version, 0);
    }
    if (wire::Get<std::uint32_t>(data, 12) != kSegmentHeaderBytes) {
        return Corrupt(SegmentIssue::HeaderLength, 0);
    }
    if (wire::Get<std::uint32_t>(data, 16) != 0) {
        return Unsupported(SegmentIssue::Flags, 0);
    }
    const auto kind = static_cast<StreamKind>(wire::Get<std::uint32_t>(data, 20));
    if (!wire::KnownStream(kind)) {
        return Unsupported(SegmentIssue::Stream, 0);
    }
    const auto ordinal = wire::Get<std::uint64_t>(data, 24);
    if (ordinal == 0) {
        return Corrupt(SegmentIssue::Ordinal, 0);
    }
    if (std::any_of(bytes.begin() + 72, bytes.begin() + 92, [](auto value) { return value != 0; })) {
        return Corrupt(SegmentIssue::Reserved, 0);
    }

    header.identity.stream = kind;
    header.identity.ordinal = ordinal;
    std::copy_n(data + 32, header.identity.project.size(), header.identity.project.begin());
    std::copy_n(data + 48, header.identity.sample.size(), header.identity.sample.begin());
    header.createdUtc100ns = wire::Get<std::uint64_t>(data, 64);
    return {};
}

bool SameIdentity(const SegmentIdentity& left, const SegmentIdentity& right) noexcept
{
    return left.stream == right.stream && left.ordinal == right.ordinal &&
           left.project == right.project && left.sample == right.sample;
}

struct BlockHeader {
    BlockInfo info;
    std::uint16_t codec = 0;
    std::uint32_t decodedBytes = 0;
    std::uint32_t storedBytes = 0;
    std::uint32_t decodedCrc = 0;
    std::uint32_t storedCrc = 0;
};

ScanFailure DecodeBlockHeader(const std::array<std::uint8_t, kBlockHeaderBytes>& bytes,
                              const SegmentScanResult& prefix, std::optional<std::uint64_t> previousSequence,
                              BlockHeader& header) noexcept
{
    const auto offset = prefix.framedBytes;
    const auto* data = bytes.data();
    if (wire::Get<std::uint32_t>(data, 76) != Crc32c(data, 76)) {
        return Corrupt(SegmentIssue::HeaderCrc, offset);
    }
    if (wire::Get<std::uint16_t>(data, 6) != wire::kBlockVersion) {
        return Unsupported(SegmentIssue::Version, offset);
    }
    if (wire::Get<std::uint16_t>(data, 4) != kBlockHeaderBytes) {
        return Corrupt(SegmentIssue::HeaderLength, offset);
    }
    const auto flags = wire::Get<std::uint16_t>(data, 10);
    if ((flags & ~wire::kQpcValid) != 0) {
        return Unsupported(SegmentIssue::Flags, offset);
    }
    if (wire::Get<std::uint32_t>(data, 72) != 0) {
        return Corrupt(SegmentIssue::Reserved, offset);
    }

    header.codec = wire::Get<std::uint16_t>(data, 8);
    header.decodedBytes = wire::Get<std::uint32_t>(data, 40);
    header.storedBytes = wire::Get<std::uint32_t>(data, 44);
    if (header.decodedBytes > kMaxDecodedBlockBytes || header.storedBytes > kMaxStoredBlockBytes ||
        header.storedBytes == 0 || (header.codec == wire::kStoredCodec && header.decodedBytes != header.storedBytes)) {
        return Corrupt(SegmentIssue::BlockLength, offset);
    }
    auto& info = header.info;
    info.offset = offset;
    info.endOffset = offset + kBlockHeaderBytes + header.storedBytes;
    if (info.endOffset > kMaxSegmentBytes) {
        return Corrupt(SegmentIssue::SegmentLimit, offset);
    }
    info.recordCount = wire::Get<std::uint32_t>(data, 12);
    if (info.recordCount == 0 || info.recordCount > kMaxBlockRecords ||
        info.recordCount > header.decodedBytes / kRecordHeaderBytes) {
        return Corrupt(SegmentIssue::RecordCount, offset);
    }
    info.ordinal = wire::Get<std::uint64_t>(data, 16);
    if (prefix.lastBlockOrdinal && info.ordinal <= *prefix.lastBlockOrdinal) {
        return Corrupt(SegmentIssue::Ordinal, offset);
    }
    info.firstSequence = wire::Get<std::uint64_t>(data, 24);
    info.lastSequence = wire::Get<std::uint64_t>(data, 32);
    if ((previousSequence && info.firstSequence <= *previousSequence) || info.firstSequence > info.lastSequence ||
        info.lastSequence - info.firstSequence < info.recordCount - 1u) {
        return Corrupt(SegmentIssue::Sequence, offset);
    }
    if ((flags & wire::kQpcValid) != 0) {
        const QpcRange range{wire::Get<std::uint64_t>(data, 48), wire::Get<std::uint64_t>(data, 56)};
        if (range.minimum > range.maximum) {
            return Corrupt(SegmentIssue::QpcRange, offset);
        }
        info.receiveQpc = range;
    }
    header.decodedCrc = wire::Get<std::uint32_t>(data, 64);
    header.storedCrc = wire::Get<std::uint32_t>(data, 68);
    return {};
}

ScanFailure DecodeRecords(const std::vector<std::uint8_t>& payload, const BlockInfo& block,
                          std::vector<RecordView>& records)
{
    records.clear();
    records.reserve(block.recordCount);
    std::size_t cursor = 0;
    for (std::uint32_t index = 0; index < block.recordCount; ++index) {
        const auto offset = block.offset + kBlockHeaderBytes + cursor;
        const auto remaining = payload.size() - cursor;
        if (remaining < kRecordHeaderBytes) {
            return Corrupt(SegmentIssue::RecordLength, offset);
        }
        const auto* data = payload.data() + cursor;
        if (wire::Get<std::uint32_t>(data, 28) != Crc32c(data, 28)) {
            return Corrupt(SegmentIssue::HeaderCrc, offset);
        }
        const auto totalBytes = wire::Get<std::uint32_t>(data, 0);
        const auto payloadBytes = wire::Get<std::uint32_t>(data, 12);
        if (totalBytes < kRecordHeaderBytes || totalBytes > remaining || totalBytes - kRecordHeaderBytes != payloadBytes) {
            return Corrupt(SegmentIssue::RecordLength, offset);
        }
        const auto sequence = wire::Get<std::uint64_t>(data, 16);
        if ((index == 0 && sequence != block.firstSequence) ||
            (!records.empty() && sequence <= records.back().sequence) ||
            (index + 1 == block.recordCount && sequence != block.lastSequence)) {
            return Corrupt(SegmentIssue::Sequence, offset);
        }
        const auto flags = wire::Get<std::uint32_t>(data, 8);
        if ((flags & ~kRequiredRecord) != 0) {
            return Unsupported(SegmentIssue::Flags, offset);
        }
        if (wire::Get<std::uint32_t>(data, 24) != Crc32c(data + kRecordHeaderBytes, payloadBytes)) {
            return Corrupt(SegmentIssue::RecordPayloadCrc, offset + kRecordHeaderBytes);
        }
        const auto type = wire::Get<std::uint16_t>(data, 4);
        const auto schema = wire::Get<std::uint16_t>(data, 6);
        records.push_back({type, schema, flags, sequence, offset, data + kRecordHeaderBytes, payloadBytes,
                           wire::IsCatalogTypeV1(type, schema)});
        cursor += totalBytes;
    }
    if (cursor != payload.size()) {
        return Corrupt(SegmentIssue::RecordCount, block.offset + kBlockHeaderBytes + cursor);
    }
    return {};
}

ScanFailure ReadBlocks(HANDLE handle, std::uint64_t scanEnd, const SegmentScanOptions& options,
                       const SegmentBlockVisitor& visitor, SegmentScanResult& result)
{
    std::vector<std::uint8_t> payload;
    std::vector<RecordView> records;
    const auto end = std::min(scanEnd, kMaxSegmentBytes);
    while (result.framedBytes < end) {
        const auto offset = result.framedBytes;
        if (scanEnd > end && end - offset < kBlockHeaderBytes) {
            return Corrupt(SegmentIssue::SegmentLimit, offset);
        }
        std::array<std::uint8_t, kBlockHeaderBytes> bytes{};
        if (const auto failure = ReadHeader(handle, bytes, wire::kBlockMagic, offset, end)) {
            return failure;
        }
        BlockHeader header;
        const auto previous = result.lastSequence ? result.lastSequence : options.previousSequence;
        if (const auto failure = DecodeBlockHeader(bytes, result, previous, header)) {
            return failure;
        }
        if (header.info.endOffset > end) {
            return Truncated(end);
        }
        if (header.codec != wire::kStoredCodec) {
            return Unsupported(SegmentIssue::Codec, offset);
        }

        payload.resize(header.storedBytes);
        DWORD read = 0;
        const auto payloadOffset = offset + kBlockHeaderBytes;
        if (const auto failure = ReadBytes(handle, payload.data(), header.storedBytes, payloadOffset, read)) {
            return failure;
        }
        const auto crc = Crc32c(payload.data(), payload.size());
        if (crc != header.storedCrc) {
            return Corrupt(SegmentIssue::StoredCrc, payloadOffset);
        }
        if (crc != header.decodedCrc) {
            return Corrupt(SegmentIssue::DecodedCrc, payloadOffset);
        }
        if (const auto failure = DecodeRecords(payload, header.info, records)) {
            return failure;
        }

        // 仅在整块记录均验证后推进前缀和调用消费方。
        result.framedBytes = header.info.endOffset;
        result.lastBlockOrdinal = header.info.ordinal;
        result.lastSequence = header.info.lastSequence;
        ++result.blockCount;
        for (const auto& record : records) {
            const bool required = (record.flags & kRequiredRecord) != 0;
            if (required) {
                ++result.requiredRecordCount;
            }
            if (!record.catalogTypeV1) {
                if (required) {
                    ++result.unsupportedRequiredRecords;
                } else {
                    ++result.unsupportedOptionalRecords;
                }
            }
        }
        if (visitor && !visitor(header.info, records)) {
            return {SegmentScanStatus::Stopped, {}};
        }
    }
    if (scanEnd > end) {
        return Corrupt(SegmentIssue::SegmentLimit, end);
    }
    if (options.endOffset && *options.endOffset > result.fileBytes) {
        return Truncated(result.fileBytes);
    }
    return {};
}

ScanFailure Scan(HANDLE file, const SegmentScanOptions& options,
                 const SegmentBlockVisitor& visitor, SegmentScanResult& result)
{
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        return {SegmentScanStatus::IoError, {SegmentIssue::FileSize, 0, GetLastError()}};
    }
    // 活动段增长时以扫描开始时观测的文件大小为界。
    result.fileSizeKnown = true;
    result.fileBytes = static_cast<std::uint64_t>(size.QuadPart);
    const auto scanEnd = std::min(result.fileBytes, options.endOffset.value_or(result.fileBytes));
    std::array<std::uint8_t, kSegmentHeaderBytes> bytes{};
    if (const auto failure = ReadHeader(file, bytes, wire::kSegmentMagic, 0, scanEnd)) {
        return failure;
    }
    SegmentHeader header;
    if (const auto failure = DecodeSegmentHeader(bytes, header)) {
        return failure;
    }
    if (options.expectedIdentity && !SameIdentity(header.identity, *options.expectedIdentity)) {
        return Corrupt(SegmentIssue::Identity, 0);
    }
    result.header = header;
    result.framedBytes = bytes.size();
    return ReadBlocks(file, scanEnd, options, visitor, result);
}

} // namespace

SegmentScanResult ScanSegment(const std::filesystem::path& path,
                              const SegmentScanOptions& options,
                              const SegmentBlockVisitor& visitor)
{
    // 只打开一次，读取时持有同一文件句柄并禁止共享删除。
    const ReadHandle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (file.value == INVALID_HANDLE_VALUE) {
        SegmentScanResult result;
        result.status = SegmentScanStatus::IoError;
        result.error = {SegmentIssue::FileOpen, 0, GetLastError()};
        return result;
    }
    return ScanOpenSegment(file.value, options, visitor);
}

SegmentScanResult ScanOpenSegment(void* fileHandle, const SegmentScanOptions& options,
                                  const SegmentBlockVisitor& visitor)
{
    SegmentScanResult result;
    const LARGE_INTEGER start{};
    if (!SetFilePointerEx(fileHandle, start, nullptr, FILE_BEGIN)) {
        result.status = SegmentScanStatus::IoError;
        result.error = {SegmentIssue::FileRead, 0, GetLastError()};
        return result;
    }
    const auto failure = Scan(fileHandle, options, visitor, result);
    result.status = failure.status;
    result.error = failure.error;
    return result;
}

} // namespace ks::cli::action_analyze::archive
