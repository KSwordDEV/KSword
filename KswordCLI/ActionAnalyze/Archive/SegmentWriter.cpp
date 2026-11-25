#include "SegmentWriter.h"

#include "SegmentWire.h"

#include <algorithm>
#include <utility>
#include <windows.h>

namespace ks::cli::action_analyze::archive {
namespace {

SegmentWriteResult InvalidInput(SegmentIssue issue, std::uint64_t offset) noexcept
{
    return {SegmentWriteStatus::InvalidInput, {issue, offset}};
}

void EncodeRecord(const StoredRecord& record, std::uint8_t* output)
{
    const auto payloadBytes = static_cast<std::uint32_t>(record.payload.size());
    wire::Put(output, 0, static_cast<std::uint32_t>(kRecordHeaderBytes) + payloadBytes);
    wire::Put(output, 4, record.type);
    wire::Put(output, 6, record.schemaVersion);
    wire::Put(output, 8, record.flags);
    wire::Put(output, 12, payloadBytes);
    wire::Put(output, 16, record.sequence);
    wire::Put(output, 24, Crc32c(record.payload.data(), payloadBytes));
    wire::Put(output, 28, Crc32c(output, 28));
    std::copy(record.payload.begin(), record.payload.end(), output + kRecordHeaderBytes);
}

} // namespace

SegmentWriter::SegmentWriter(std::filesystem::path path, SegmentHeader header,
                             std::optional<std::uint64_t> previousSequence)
    : path_(std::move(path)), header_(header), lastSequence_(previousSequence)
{
}

SegmentWriter::~SegmentWriter()
{
    Close();
}

SegmentWriteResult SegmentWriter::FileError(SegmentIssue issue, std::uint64_t offset, std::uint32_t error) noexcept
{
    // 任何写入或刷盘失败后保留首次错误和最后一个完整块端点。
    if (!fileFailure_) {
        fileFailure_ = SegmentWriteResult{SegmentWriteStatus::IoError, {issue, offset, error}};
    }
    return *fileFailure_;
}

SegmentWriteResult SegmentWriter::Write(const std::uint8_t* bytes, std::uint32_t size, std::uint64_t offset) noexcept
{
    DWORD written = 0;
    if (!WriteFile(handle_, bytes, size, &written, nullptr)) {
        return FileError(SegmentIssue::FileWrite, offset, GetLastError());
    }
    if (written != size) {
        return FileError(SegmentIssue::FileWrite, offset + written, ERROR_WRITE_FAULT);
    }
    return {};
}

SegmentWriteResult SegmentWriter::Open()
{
    const auto handle = CreateFileW(path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return FileError(SegmentIssue::FileOpen, 0, GetLastError());
    }
    handle_ = handle;

    std::array<std::uint8_t, kSegmentHeaderBytes> bytes{};
    std::copy(wire::kSegmentMagic.begin(), wire::kSegmentMagic.end(), bytes.begin());
    wire::Put(bytes.data(), 8, wire::kSegmentMajor);
    wire::Put(bytes.data(), 10, wire::kSegmentMinor);
    wire::Put(bytes.data(), 12, static_cast<std::uint32_t>(kSegmentHeaderBytes));
    wire::Put(bytes.data(), 20, static_cast<std::uint32_t>(header_.identity.stream));
    wire::Put(bytes.data(), 24, header_.identity.ordinal);
    std::copy(header_.identity.project.begin(), header_.identity.project.end(), bytes.begin() + 32);
    std::copy(header_.identity.sample.begin(), header_.identity.sample.end(), bytes.begin() + 48);
    wire::Put(bytes.data(), 64, header_.createdUtc100ns);
    wire::Put(bytes.data(), 92, Crc32c(bytes.data(), 92));

    const auto result = Write(bytes.data(), static_cast<std::uint32_t>(bytes.size()), 0);
    if (result.status == SegmentWriteStatus::Ok) {
        writtenBytes_ = bytes.size();
    }
    return result;
}

SegmentWriteResult SegmentWriter::AppendBlock(const std::vector<StoredRecord>& records,
                                              std::optional<QpcRange> receiveQpc)
{
    if (fileFailure_) {
        return *fileFailure_;
    }
    if (closed_) {
        return {SegmentWriteStatus::Closed, {}};
    }
    if (!wire::KnownStream(header_.identity.stream)) {
        return InvalidInput(SegmentIssue::Stream, 0);
    }
    if (header_.identity.ordinal == 0) {
        return InvalidInput(SegmentIssue::Ordinal, 0);
    }

    const std::uint64_t blockOffset = handle_ ? writtenBytes_ : kSegmentHeaderBytes;
    if (records.empty() || records.size() > kMaxBlockRecords) {
        return InvalidInput(SegmentIssue::RecordCount, blockOffset);
    }
    if (receiveQpc && receiveQpc->minimum > receiveQpc->maximum) {
        return InvalidInput(SegmentIssue::QpcRange, blockOffset);
    }

    // 批次完整验过再写任何内容，参数错误可纠正后重试。
    std::size_t decodedBytes = 0;
    auto previous = lastSequence_;
    for (const auto& record : records) {
        const auto recordOffset = blockOffset + kBlockHeaderBytes + decodedBytes;
        if (previous && record.sequence <= *previous) {
            return InvalidInput(SegmentIssue::Sequence, recordOffset);
        }
        if ((record.flags & ~kRequiredRecord) != 0) {
            return InvalidInput(SegmentIssue::Flags, recordOffset);
        }
        if (!wire::IsCatalogTypeV1(record.type, record.schemaVersion)) {
            return InvalidInput(SegmentIssue::RecordSchema, recordOffset);
        }
        const auto remaining = kMaxDecodedBlockBytes - decodedBytes;
        if (remaining < kRecordHeaderBytes || record.payload.size() > remaining - kRecordHeaderBytes) {
            return InvalidInput(SegmentIssue::BlockLength, recordOffset);
        }
        decodedBytes += kRecordHeaderBytes + record.payload.size();
        previous = record.sequence;
    }

    const auto blockEnd = blockOffset + kBlockHeaderBytes + decodedBytes;
    if (blockEnd > kMaxSegmentBytes) {
        return {SegmentWriteStatus::SegmentFull, {SegmentIssue::SegmentLimit, blockOffset}};
    }

    std::vector<std::uint8_t> payload(decodedBytes);
    std::size_t payloadOffset = 0;
    for (const auto& record : records) {
        EncodeRecord(record, payload.data() + payloadOffset);
        payloadOffset += kRecordHeaderBytes + record.payload.size();
    }

    std::array<std::uint8_t, kBlockHeaderBytes> block{};
    std::copy(wire::kBlockMagic.begin(), wire::kBlockMagic.end(), block.begin());
    wire::Put(block.data(), 4, static_cast<std::uint16_t>(kBlockHeaderBytes));
    wire::Put(block.data(), 6, wire::kBlockVersion);
    wire::Put(block.data(), 8, wire::kStoredCodec);
    wire::Put(block.data(), 12, static_cast<std::uint32_t>(records.size()));
    wire::Put(block.data(), 16, blockCount_ + 1);
    wire::Put(block.data(), 24, records.front().sequence);
    wire::Put(block.data(), 32, records.back().sequence);
    wire::Put(block.data(), 40, static_cast<std::uint32_t>(decodedBytes));
    wire::Put(block.data(), 44, static_cast<std::uint32_t>(decodedBytes));
    if (receiveQpc) {
        wire::Put(block.data(), 10, wire::kQpcValid);
        wire::Put(block.data(), 48, receiveQpc->minimum);
        wire::Put(block.data(), 56, receiveQpc->maximum);
    }
    const auto crc = Crc32c(payload.data(), payload.size());
    wire::Put(block.data(), 64, crc);
    wire::Put(block.data(), 68, crc);
    wire::Put(block.data(), 76, Crc32c(block.data(), 76));

    if (!handle_) {
        const auto result = Open();
        if (result.status != SegmentWriteStatus::Ok) {
            return result;
        }
    }
    const auto headerResult = Write(block.data(), static_cast<std::uint32_t>(block.size()), blockOffset);
    if (headerResult.status != SegmentWriteStatus::Ok) {
        return headerResult;
    }
    const auto payloadResult = Write(payload.data(), static_cast<std::uint32_t>(decodedBytes), blockOffset + block.size());
    if (payloadResult.status != SegmentWriteStatus::Ok) {
        return payloadResult;
    }
    writtenBytes_ = blockEnd;
    ++blockCount_;
    lastSequence_ = previous;
    return {};
}

SegmentWriteResult SegmentWriter::Flush() noexcept
{
    if (fileFailure_) {
        return *fileFailure_;
    }
    if (closed_) {
        return {SegmentWriteStatus::Closed, {}};
    }
    if (handle_ && !FlushFileBuffers(handle_)) {
        return FileError(SegmentIssue::FileFlush, flushedBytes_, GetLastError());
    }
    flushedBytes_ = writtenBytes_;
    return {};
}

SegmentWriteResult SegmentWriter::Close() noexcept
{
    closed_ = true;
    if (handle_) {
        const auto handle = std::exchange(handle_, nullptr);
        if (!CloseHandle(handle)) {
            return FileError(SegmentIssue::FileClose, writtenBytes_, GetLastError());
        }
    }
    return fileFailure_.value_or(SegmentWriteResult{});
}

} // namespace ks::cli::action_analyze::archive
