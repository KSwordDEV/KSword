#include "ProjectDocument.h"
#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"

#include <utility>

namespace Ksword::ActionAnalyze {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using ProjectStorage::Failure;

Archive::ArchiveUuid UuidBytes(std::string_view checkedUuid) {
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    Archive::ArchiveUuid bytes{};
    std::size_t offset = 0;
    // 输入已由项目文档校验。按文本顺序取字节，保持与段头的 UUID 一致。
    for (auto& byte : bytes) {
        if (checkedUuid[offset] == '-') ++offset;
        byte = static_cast<std::uint8_t>((digit(checkedUuid[offset]) << 4) | digit(checkedUuid[offset + 1]));
        offset += 2;
    }
    return bytes;
}

ProjectResult LabelMissingPath(ProjectResult result, const char* detail) {
    if (result.error == ProjectError::NotFound) result.detail = detail;
    return result;
}

} // namespace

ProjectResult ProjectDocument::InspectSegment(std::string_view projectId, std::string_view sampleId,
    Archive::StreamKind stream, std::uint64_t ordinal, std::optional<std::uint64_t> endOffset,
    Archive::SegmentInspection& out) const {
    const auto* info = Info();
    const auto* root = RootForRead();
    if (!info || !root) return Failure(ProjectError::NotOpen, "project");
    if (projectId != info->projectId) return Failure(ProjectError::InvalidArgument, "archiveProjectIdMismatch");
    if (ordinal == 0) return Failure(ProjectError::InvalidArgument, "archiveOrdinal");
    if (endOffset && *endOffset > Archive::kMaxSegmentBytes) {
        return Failure(ProjectError::LimitExceeded, "archiveEndOffset");
    }

    Archive::SegmentIdentity identity;
    identity.stream = stream;
    identity.ordinal = ordinal;
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name) return Failure(ProjectError::Unsupported, "archiveStream");

    SampleRecord sample;
    if (auto result = ReadSample(sampleId, sample); !result) return result;
    identity.project = UuidBytes(info->projectId);
    identity.sample = UuidBytes(sample.info.sampleId);

    // 保持目录与文件句柄到扫描结束。共享模式约束当前文件，允许并行只读。
    ProjectStorage::Directory directory;
    if (auto result = ProjectStorage::OpenDirectory(*root,
            {L"samples", ProjectStorage::WideAscii(sample.info.sampleId), name->streamDirectory}, directory); !result) {
        return LabelMissingPath(result, "archiveStreamUnavailable");
    }
    ProjectStorage::Handle file;
    if (auto result = ProjectStorage::OpenFile(directory, name->fileName, GENERIC_READ,
                                             FILE_SHARE_READ, OPEN_EXISTING, file); !result) {
        return LabelMissingPath(result, "archiveSegmentUnavailable");
    }
    auto inspection = Archive::InspectOpenSegment(file.get(), identity, endOffset);
    if (!inspection) return Failure(ProjectError::Unsupported, "archiveStream");
    out = std::move(*inspection);
    return {};
}

} // namespace Ksword::ActionAnalyze
