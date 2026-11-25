#pragma once

#include "SegmentFormat.h"

#include <filesystem>

namespace ks::cli::action_analyze::archive {

enum class SegmentWriteStatus {
    Ok,
    InvalidInput,
    SegmentFull,
    IoError,
    Closed,
};

struct SegmentWriteResult {
    SegmentWriteStatus status = SegmentWriteStatus::Ok;
    SegmentError error;
};

// 单线程、单段写入。首次有效的 AppendBlock 以 CREATE_NEW 打开目标。
// 路径由调用方从已验证的项目根及身份构造。析构仅关闭句柄。
class SegmentWriter final {
public:
    SegmentWriter(std::filesystem::path path, SegmentHeader header,
                  std::optional<std::uint64_t> previousSequence = std::nullopt);
    ~SegmentWriter();

    SegmentWriter(const SegmentWriter&) = delete;
    SegmentWriter& operator=(const SegmentWriter&) = delete;

    // 调用方校验正文并提供批次、流内序号及可选 QPC 范围。每段的写入块序号从 1 开始。
    SegmentWriteResult AppendBlock(const std::vector<StoredRecord>& records,
                                   std::optional<QpcRange> receiveQpc = std::nullopt);
    SegmentWriteResult Flush() noexcept;
    SegmentWriteResult Close() noexcept;

    // 记录已完整写入/通过 FlushFileBuffers 的字节端点。跨流持久水位由 checkpoint 决定。
    std::uint64_t WrittenBytes() const noexcept { return writtenBytes_; }
    std::uint64_t FlushedBytes() const noexcept { return flushedBytes_; }

private:
    SegmentWriteResult Open();
    SegmentWriteResult Write(const std::uint8_t* bytes, std::uint32_t size, std::uint64_t offset) noexcept;
    SegmentWriteResult FileError(SegmentIssue issue, std::uint64_t offset, std::uint32_t error) noexcept;

    std::filesystem::path path_;
    SegmentHeader header_;
    std::optional<std::uint64_t> lastSequence_;
    void* handle_ = nullptr;
    std::uint64_t blockCount_ = 0;
    std::uint64_t writtenBytes_ = 0;
    std::uint64_t flushedBytes_ = 0;
    std::optional<SegmentWriteResult> fileFailure_;
    bool closed_ = false;
};

} // namespace ks::cli::action_analyze::archive
