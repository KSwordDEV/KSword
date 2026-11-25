#pragma once

#include "SegmentFormat.h"

#include <filesystem>
#include <functional>

namespace ks::cli::action_analyze::archive {

enum class SegmentScanStatus {
    FramingComplete,
    Truncated,
    Corrupt,
    Unsupported,
    IoError,
    Stopped,
};

struct SegmentScanOptions {
    std::optional<SegmentIdentity> expectedIdentity;
    // 调用方可传 checkpoint 的段内字节端点。省略时以打开后的文件大小为扫描边界。
    std::optional<std::uint64_t> endOffset;
    std::optional<std::uint64_t> previousSequence;
};

struct SegmentScanResult {
    SegmentScanStatus status = SegmentScanStatus::FramingComplete;
    SegmentError error;
    std::optional<SegmentHeader> header;
    std::uint64_t fileBytes = 0;
    std::uint64_t framedBytes = 0;
    // 本层只检查封装，始终为 nullopt。语义可读端点由调用方独立验证和维护。
    std::optional<std::uint64_t> interpretedBytes;
    std::uint64_t blockCount = 0;
    std::optional<std::uint64_t> lastBlockOrdinal;
    std::optional<std::uint64_t> lastSequence;
    std::uint64_t requiredRecordCount = 0;
    // 仅统计目录外的编号或 v1 以外的版本。目录内的必需记录也需要语义验证。
    std::uint64_t unsupportedOptionalRecords = 0;
    std::uint64_t unsupportedRequiredRecords = 0;
};

// 整块验证后回调。RecordView 及 payload 有效期至回调返回，返回 false 可停止扫描。
// 所有 RecordView 均为原字节。调用方验证 RawRecord/CanonicalEvent v1 正文，并核对必需类型是否确有解码器。
using SegmentBlockVisitor = std::function<bool(const BlockInfo&, const std::vector<RecordView>&)>;

// 从段头只读扫描，在首个无法校验封装的块终止。FramingComplete 表示给定边界的字节封装完整。
SegmentScanResult ScanSegment(const std::filesystem::path& path,
                              const SegmentScanOptions& options = {},
                              const SegmentBlockVisitor& visitor = {});

} // namespace ks::cli::action_analyze::archive
