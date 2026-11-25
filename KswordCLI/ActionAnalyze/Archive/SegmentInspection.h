#pragma once

#include "SegmentReader.h"

#include <string>
#include <string_view>

namespace ks::cli::action_analyze::archive {

struct SegmentLogicalName {
    std::wstring_view streamDirectory;
    std::wstring fileName;
};

// 返回供 Project 安全打开使用的两个固定组件。analysis 需要另行绑定 runId。
std::optional<SegmentLogicalName> NameInspectionSegment(const SegmentIdentity& identity);

struct SegmentFramingCoverage {
    // 未指定时以扫描开始时观测的大小为范围。指定端点并不代表已发布 checkpoint。
    std::optional<std::uint64_t> requestedEndOffset;
    std::optional<std::uint64_t> fileBytes;
    std::optional<std::uint64_t> scanLimitBytes;
    std::uint64_t framedBytes = 0;
    std::uint64_t blockCount = 0;
    std::optional<std::uint64_t> lastBlockOrdinal;
    std::optional<std::uint64_t> lastSequence;
};

struct SegmentInspection {
    SegmentIdentity expectedIdentity;
    SegmentScanStatus framingStatus = SegmentScanStatus::FramingComplete;
    SegmentError error;
    SegmentFramingCoverage framingCoverage;
    std::optional<std::uint64_t> createdUtc100ns;
    std::uint64_t requiredRecordCount = 0;
    // 这两个计数仅指封装前缀内的目录外类型或版本。
    std::uint64_t unsupportedOptionalRecords = 0;
    std::uint64_t unsupportedRequiredRecords = 0;
    // 本检查没有正文或 checkpoint 证据，这两个端点保持未知。
    std::optional<std::uint64_t> interpretedBytes;
    std::optional<std::uint64_t> durableBytes;
};

// 使用与 Project 路径/身份复核相同的已打开同步句柄。调用方持有其租约和文件位置。
// 正数段号与 raw/records/control 是本入口的范围。超出该范围返回 nullopt。
std::optional<SegmentInspection> InspectOpenSegment(void* resolvedFileHandle,
                                                    const SegmentIdentity& expectedIdentity,
                                                    std::optional<std::uint64_t> endOffset = std::nullopt);

} // namespace ks::cli::action_analyze::archive
