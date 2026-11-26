#include "ProjectRawEvidence.h"

#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"

#include <utility>

namespace Ksword::ActionAnalyze {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using ProjectStorage::Failure;

// 从已登记采样生成安全路径组件和段头身份。外来路径字符串不能进入归档位置。
ProjectResult ResolveRawEvidence(const ProjectDocument& project, std::string_view projectId,
    std::string_view sampleId, std::uint64_t ordinal, ProjectEvidenceLane lane, Archive::SegmentIdentity& identity,
    Archive::SegmentLogicalName& name)
{
    const auto* info = project.Info();
    if (!info) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (projectId != info->projectId) {
        return Failure(ProjectError::InvalidArgument, "archiveProjectIdMismatch");
    }

    SampleRecord sample; // 通过已提交目录寻找并验证采样描述。
    if (const auto status = project.ReadSample(sampleId, sample); !status) {
        return status;
    }
    identity = {Archive::StreamKind::Raw, ordinal, ProjectStorage::UuidBytes(info->projectId),
        ProjectStorage::UuidBytes(sample.info.sampleId)};
    auto resolvedName = Archive::NameInspectionSegment(identity);
    if (!resolvedName) {
        return Failure(ProjectError::InvalidArgument, "archiveOrdinal");
    }
    name = std::move(*resolvedName);
    if (lane == ProjectEvidenceLane::MixedEtw) name.streamDirectory = L"raw-etw";
    return {};
}

} // namespace

ProjectResult ProjectDocument::WriteRawEvidenceSegment(const ProjectRawEvidenceWrite& request,
                                                       Archive::RawEvidenceReceipt& out)
{
    out = {};
    const auto* root = RootForRead();
    if (!root) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (Info()->access != ProjectAccess::ReadWrite) {
        return Failure(ProjectError::ReadOnly, "project");
    }
    if (!request.append || (request.ordinal == 1 && request.previousSequence.value_or(0) != 0) ||
        (request.ordinal > 1 && request.previousSequence.value_or(0) == 0)) {
        return Failure(ProjectError::InvalidArgument, "archiveWriter");
    }

    Archive::SegmentIdentity identity;
    Archive::SegmentLogicalName name;
    if (const auto status = ResolveRawEvidence(*this, request.projectId, request.sampleId, request.ordinal,
            request.lane, identity, name); !status) {
        return status;
    }

    // 核对前段的完整前缀与末序号。无法确认边界时必须保留中断，不能追加新段掩盖短尾。
    if (request.ordinal > 1) {
        const ProjectRawEvidenceRead previous{request.projectId, request.sampleId, request.ordinal - 1,
            std::nullopt, std::nullopt, {}, std::nullopt, request.lane};
        Archive::RawEvidenceScanResult checked;
        if (const auto status = ReadRawEvidenceSegment(previous, checked); !status) {
            return status;
        }
        if (!checked.checked || !checked.VerifiedBoundary(*checked.checked) ||
            checked.checked->lastSequence != *request.previousSequence) {
            return Failure(ProjectError::RecoveryRequired, "archivePreviousSegment");
        }
    }

    // 持有全部父目录的句柄。新目录只能由已持项目写锁的本线程建立。
    const auto sample = ProjectStorage::WideAscii(request.sampleId);
    ProjectStorage::Directory rawDirectory;
    const auto components = {std::wstring_view(L"samples"), std::wstring_view(sample), name.streamDirectory};
    auto directory = ProjectStorage::OpenDirectory(*root, components, rawDirectory);
    if (directory.error == ProjectError::NotFound) {
        directory = ProjectStorage::OpenDirectory(*root, components, rawDirectory, true);
    }
    if (!directory) {
        return directory;
    }

    // 只用 CREATE_NEW 写新段。采样登记继续保留原有文档语义，刷盘端点仅由回执承载。
    const auto path = std::filesystem::path(rawDirectory.path) / name.fileName;
    Archive::RawEvidenceArchive writer(path, {identity, ProjectStorage::UtcNow()}, request.previousSequence);
    const auto produce = request.append(writer);
    out = writer.Finish();
    if (!produce) {
        return produce;
    }
    if (out.result.status == Archive::SegmentWriteStatus::IoError) {
        return ProjectStorage::WinFailure("archiveRawWriter", out.result.error.win32Error);
    }
    return {};
}

ProjectResult ProjectDocument::ReadRawEvidenceSegment(const ProjectRawEvidenceRead& request,
                                                       Archive::RawEvidenceScanResult& out,
                                                       std::string* prefixHash) const
{
    out = {};
    if (prefixHash) prefixHash->clear();
    const auto* root = RootForRead();
    if (!root) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (request.endOffset && *request.endOffset > Archive::kMaxSegmentBytes) {
        return Failure(ProjectError::LimitExceeded, "archiveEndOffset");
    }

    Archive::SegmentIdentity identity;
    Archive::SegmentLogicalName name;
    if (const auto status = ResolveRawEvidence(*this, request.projectId, request.sampleId, request.ordinal,
            request.lane, identity, name); !status) {
        return status;
    }

    // 与已登记采样的检查入口一样，通过同一个已验证的文件句柄完成整个扫描。
    ProjectStorage::Directory rawDirectory;
    if (const auto status = ProjectStorage::OpenDirectory(*root,
            {L"samples", ProjectStorage::WideAscii(request.sampleId), name.streamDirectory}, rawDirectory); !status) {
        return status;
    }
    ProjectStorage::Handle file;
    // 校验散列时从同一禁止写入及删除的句柄扫描与散列前缀。
    const DWORD share = request.endOffset && !prefixHash ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ;
    if (const auto status = ProjectStorage::OpenFile(rawDirectory, name.fileName, GENERIC_READ,
            share, OPEN_EXISTING, file); !status) {
        return status;
    }
    if (request.maxFileBytes) {
        LARGE_INTEGER fileSize{}; // 从实际持有的段句柄读取字节长度。
        if (!GetFileSizeEx(file.get(), &fileSize)) {
            return ProjectStorage::WinFailure("archiveFileSize", GetLastError());
        }
        if (request.endOffset.value_or(static_cast<std::uint64_t>(fileSize.QuadPart)) > *request.maxFileBytes) {
            return Failure(ProjectError::LimitExceeded, "archiveFileSize");
        }
    }
    out = Archive::ScanOpenRawEvidence(file.get(), identity, request.endOffset,
        request.previousSequence, request.visitor);
    if (prefixHash && out.checked && out.VerifiedBoundary(*out.checked)) {
        return ProjectStorage::HashArchivePrefix(file.get(), out.checked->byteOffset, *prefixHash);
    }
    return {};
}

} // namespace Ksword::ActionAnalyze
