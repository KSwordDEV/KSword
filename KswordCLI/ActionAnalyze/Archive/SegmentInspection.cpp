#include "SegmentInspection.h"

#include <algorithm>
#include <utility>

namespace ks::cli::action_analyze::archive {
namespace {

std::wstring_view InspectionStreamDirectory(StreamKind kind) noexcept
{
    switch (kind) {
    case StreamKind::Raw: return L"raw";
    case StreamKind::Records: return L"records";
    case StreamKind::Control: return L"control";
    case StreamKind::Analysis: break;
    }
    return {};
}

} // namespace

std::optional<SegmentLogicalName> NameInspectionSegment(const SegmentIdentity& identity)
{
    const auto streamDirectory = InspectionStreamDirectory(identity.stream);
    if (identity.ordinal == 0 || streamDirectory.empty()) {
        return std::nullopt;
    }
    const auto digits = std::to_wstring(identity.ordinal);
    std::wstring fileName(20 - digits.size(), L'0');
    fileName.append(digits);
    fileName.append(L".ksaseg");
    return SegmentLogicalName{streamDirectory, std::move(fileName)};
}

std::optional<SegmentInspection> InspectOpenSegment(void* resolvedFileHandle,
                                                    const SegmentIdentity& expectedIdentity,
                                                    std::optional<std::uint64_t> endOffset)
{
    if (expectedIdentity.ordinal == 0 || InspectionStreamDirectory(expectedIdentity.stream).empty()) {
        return std::nullopt;
    }

    SegmentScanOptions options;
    options.expectedIdentity = expectedIdentity;
    options.endOffset = endOffset;
    const auto scan = ScanOpenSegment(resolvedFileHandle, options);

    SegmentInspection inspection;
    inspection.expectedIdentity = expectedIdentity;
    inspection.framingStatus = scan.status;
    inspection.error = scan.error;
    inspection.requiredRecordCount = scan.requiredRecordCount;
    inspection.unsupportedOptionalRecords = scan.unsupportedOptionalRecords;
    inspection.unsupportedRequiredRecords = scan.unsupportedRequiredRecords;
    if (scan.header) {
        inspection.createdUtc100ns = scan.header->createdUtc100ns;
    }

    auto& coverage = inspection.framingCoverage;
    coverage.requestedEndOffset = endOffset;
    if (scan.fileSizeKnown) {
        coverage.fileBytes = scan.fileBytes;
        coverage.scanLimitBytes = std::min({scan.fileBytes, endOffset.value_or(scan.fileBytes), kMaxSegmentBytes});
    }
    coverage.framedBytes = scan.framedBytes;
    coverage.blockCount = scan.blockCount;
    coverage.lastBlockOrdinal = scan.lastBlockOrdinal;
    coverage.lastSequence = scan.lastSequence;
    return inspection;
}

} // namespace ks::cli::action_analyze::archive
