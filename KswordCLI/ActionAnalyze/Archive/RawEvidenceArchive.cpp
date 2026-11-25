#include "RawEvidenceArchive.h"

#include <limits>

namespace ks::cli::action_analyze::archive {
namespace {

// 分配器在上限前检查可用序号，禁止跨 u64 回绕。
constexpr auto kLastSequence = (std::numeric_limits<std::uint64_t>::max)();
// 只使用 A0 已分配的 RawRecord v1 记录类型。
constexpr std::uint16_t kRawRecordType = 3;

} // namespace

RawEvidenceArchive::RawEvidenceArchive(const std::filesystem::path& validatedSegmentPath,
    SegmentHeader header, std::optional<std::uint64_t> previousSequence)
    : writer_(validatedSegmentPath, header, previousSequence),
      validStream_(header.identity.stream == StreamKind::Raw),
      lastSequence_(previousSequence.value_or(0))
{
}

RawEvidenceReceipt RawEvidenceArchive::Snapshot(SegmentWriteResult result) const noexcept
{
    return {failure_.value_or(result), BodyIssue::None, std::nullopt, written_, flushed_};
}

RawEvidenceReceipt RawEvidenceArchive::Append(std::span<const RawEvidenceInput> inputs,
                                             std::optional<QpcRange> receiveQpc)
{
    if (finish_) {
        return Snapshot({SegmentWriteStatus::Closed, {}});
    }
    if (failure_) {
        return Snapshot(*failure_);
    }

    // 在验证输入之前冻结当前端点，供错误回执引用。
    const auto offset = written_ ? written_->byteOffset : kSegmentHeaderBytes;
    if (!validStream_) {
        return Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::Stream, 0}});
    }
    if (inputs.empty() || inputs.size() > kMaxBlockRecords) {
        return Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::RecordCount, offset}});
    }
    if (inputs.size() > kLastSequence - lastSequence_) {
        return Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::Sequence, offset}});
    }
    if (receiveQpc && receiveQpc->minimum > receiveQpc->maximum) {
        return Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::QpcRange, offset}});
    }

    // 按 Stored 块限制预计算整个批次的长度，超限拒绝且不分配正文缓冲。
    constexpr auto overhead = kRecordHeaderBytes + kRawRecordV1PrefixBytes;
    std::size_t blockBytes = 0;
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const auto& input = inputs[i];
        const auto remaining = kMaxDecodedBlockBytes - blockBytes;
        if (remaining < overhead || input.metadataJson.size() > remaining - overhead ||
            input.inlineRawData.size() > remaining - overhead - input.metadataJson.size()) {
            auto receipt = Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::BlockLength, offset}});
            receipt.inputIssue = BodyIssue::Length;
            receipt.rejectedInput = i;
            return receipt;
        }
        blockBytes += overhead + input.metadataJson.size() + input.inlineRawData.size();
    }

    // 完整验证并编码后交给单段 writer。写成前不提交已分配的归档序号。
    std::vector<StoredRecord> records;
    records.reserve(inputs.size());
    auto sequence = lastSequence_;
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const auto& input = inputs[i];
        auto& record = records.emplace_back();
        record.type = kRawRecordType;
        record.sequence = ++sequence;
        const auto issue = EncodeRawRecordV1(input.metadataJson, input.inlineRawData, record.payload);
        if (issue != BodyIssue::None) {
            auto receipt = Snapshot({SegmentWriteStatus::InvalidInput, {SegmentIssue::RecordSchema, offset}});
            receipt.inputIssue = issue;
            receipt.rejectedInput = i;
            return receipt;
        }
    }

    const auto result = writer_.AppendBlock(records, receiveQpc);
    if (result.status == SegmentWriteStatus::Ok) {
        lastSequence_ = sequence;
        const auto blockOrdinal = written_ ? written_->blockOrdinal + 1 : 1;
        written_ = RawEvidenceBoundary{writer_.WrittenBytes(), blockOrdinal, sequence};
    } else if (result.status == SegmentWriteStatus::IoError) {
        failure_ = result;
    }
    return Snapshot(result);
}

RawEvidenceReceipt RawEvidenceArchive::Flush() noexcept
{
    if (finish_) {
        return Snapshot({SegmentWriteStatus::Closed, {}});
    }
    // 刷盘失败保留先前的完整端点和首个故障，方便调用者停采并重开检查。
    const auto result = writer_.Flush();
    if (result.status == SegmentWriteStatus::Ok) {
        flushed_ = written_;
    } else if (result.status == SegmentWriteStatus::IoError) {
        failure_ = result;
    }
    return Snapshot(result);
}

RawEvidenceReceipt RawEvidenceArchive::Finish() noexcept
{
    if (!finish_) {
        const auto flush = Flush().result;
        const auto close = writer_.Close();
        finish_ = flush.status == SegmentWriteStatus::Ok ? close : flush;
    }
    return Snapshot(*finish_);
}

bool RawEvidenceScanResult::VerifiedBoundary(const RawEvidenceBoundary& expected) const noexcept
{
    return checked && segment.framing.status == SegmentScanStatus::FramingComplete &&
        segment.bodyFailure.issue == BodyIssue::None && issue == RawEvidenceScanIssue::None &&
        checked->byteOffset == expected.byteOffset && checked->blockOrdinal == expected.blockOrdinal &&
        checked->lastSequence == expected.lastSequence;
}

RawEvidenceScanResult ScanOpenRawEvidence(void* fileHandle, const SegmentIdentity& expectedIdentity,
    std::optional<std::uint64_t> endOffset, std::optional<std::uint64_t> previousSequence,
    const SegmentBodyVisitor& visitor)
{
    RawEvidenceScanResult result;
    if (expectedIdentity.stream != StreamKind::Raw) {
        result.issue = RawEvidenceScanIssue::WrongStream;
        return result;
    }

    // 仅在完整块通过正文和顺序核对后推进本适配层端点。底层封装回执仍保留。
    auto sequence = previousSequence;
    result.segment = ScanOpenSegmentBodies(fileHandle, expectedIdentity, endOffset,
        [&](const SegmentIdentity& identity, const BlockInfo& block, const std::vector<DecodedRecord>& records) {
            for (const auto& record : records) {
                if (!std::holds_alternative<RawRecordV1>(record.body)) {
                    result.issue = RawEvidenceScanIssue::UnsupportedRecord;
                } else if (sequence && (*sequence == kLastSequence || record.recordSequence != *sequence + 1)) {
                    result.issue = RawEvidenceScanIssue::UnexpectedSequence;
                }
                if (result.issue != RawEvidenceScanIssue::None) {
                    result.invalidRecordOffset = record.recordOffset;
                    return false;
                }
                sequence = record.recordSequence;
            }
            result.checked = RawEvidenceBoundary{block.endOffset, block.ordinal, block.lastSequence};
            return !visitor || visitor(identity, block, records);
        });
    return result;
}

} // namespace ks::cli::action_analyze::archive
