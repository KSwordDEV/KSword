#pragma once

#include "SegmentBodies.h"
#include "SegmentWriter.h"

#include <span>

namespace ks::cli::action_analyze::archive {

// 借用调用方准备好的严格 JSON 元数据和原字节，视图有效至 Append 返回。
// 元数据字段由来源契约解释。本层只校验和保留 RawRecord v1 封装。
struct RawEvidenceInput {
    std::string_view metadataJson;
    std::string_view inlineRawData;
};

// 一个完整块的三元端点。首块之前端点为空，写入与刷盘分别回读。
struct RawEvidenceBoundary {
    std::uint64_t byteOffset = 0;
    std::uint64_t blockOrdinal = 0;
    std::uint64_t lastSequence = 0;
};

struct RawEvidenceReceipt {
    SegmentWriteResult result; // 本次操作及底层首次 I/O 错误。
    BodyIssue inputIssue = BodyIssue::None; // 正文未通过校验时设置。
    std::optional<std::size_t> rejectedInput; // 首个有问题的元素，零基。
    std::optional<RawEvidenceBoundary> written;
    std::optional<RawEvidenceBoundary> flushed; // 只表示本段 FlushFileBuffers 成功。
};

// 每采样的 raw 单写者使用本对象写一个新段。调用方保留项目写锁和目录句柄，
// 传入由段身份推导的已校验路径、正数段号及可选前一段实存记录序号。
// 各方法在同一归档工作线程串行调用，Append 包含同步磁盘 I/O。
class RawEvidenceArchive final {
public:
    RawEvidenceArchive(const std::filesystem::path& validatedSegmentPath, SegmentHeader header,
                       std::optional<std::uint64_t> previousSequence = std::nullopt);

    // 一批对应一个完整块，按输入次序分配 archive sequence，自 1 或前序+1 起。
    // 无效批次可以纠正后重试。输入顺序由来源所有者提供，QPC 范围限同一接收时钟。
    RawEvidenceReceipt Append(std::span<const RawEvidenceInput> inputs,
                              std::optional<QpcRange> receiveQpc = std::nullopt);
    RawEvidenceReceipt Flush() noexcept;
    // 刷新并关闭，无记录时不创建文件。可以回读同一收尾结果，析构只关闭句柄。
    RawEvidenceReceipt Finish() noexcept;

private:
    RawEvidenceReceipt Snapshot(SegmentWriteResult result) const noexcept;

    SegmentWriter writer_; // 负责 CREATE_NEW、CRC、写入、刷盘和错误保留。
    bool validStream_ = false; // 写入入口仅支持 raw 流。
    std::uint64_t lastSequence_ = 0; // 最后一次成功写入的序号或起始前序。
    std::optional<RawEvidenceBoundary> written_;
    std::optional<RawEvidenceBoundary> flushed_;
    std::optional<SegmentWriteResult> failure_; // 首个底层 I/O 故障。
    std::optional<SegmentWriteResult> finish_;
};

enum class RawEvidenceScanIssue { None, WrongStream, UnsupportedRecord, UnexpectedSequence };

struct RawEvidenceScanResult {
    SegmentBodyScanResult segment; // 封装和 A0 正文检查结果。
    RawEvidenceScanIssue issue = RawEvidenceScanIssue::None;
    std::uint64_t invalidRecordOffset = 0;
    std::optional<RawEvidenceBoundary> checked; // 通过本适配层检查的最后完整块。

    // 比较显式持有的文件刷盘回执端点，需用该 byteOffset 扫描至正常结束。
    bool VerifiedBoundary(const RawEvidenceBoundary& expected) const noexcept;
};

// 对持有的只读同步句柄扫描。上一序号省略时，首条序号从段中实读；传入时要求紧邻。
// 回调每次收到完整校验且顺序连续的 RawRecord v1 块，视图借用至回调返回。
// 文件损坏或截尾仅推进到前一完整块。此接口只回读字节与顺序，来源质量由上层解释。
RawEvidenceScanResult ScanOpenRawEvidence(void* fileHandle, const SegmentIdentity& expectedIdentity,
    std::optional<std::uint64_t> endOffset = std::nullopt,
    std::optional<std::uint64_t> previousSequence = std::nullopt,
    const SegmentBodyVisitor& visitor = {});

} // namespace ks::cli::action_analyze::archive
