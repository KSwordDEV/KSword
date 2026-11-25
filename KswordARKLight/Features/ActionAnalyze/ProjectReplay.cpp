#include "ProjectReplay.h"

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <filesystem>

namespace Ksword::Features::ActionAnalyze {
namespace {

namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
constexpr wchar_t kManifestName[] = L"project.ksaproj"; // 正式项目清单的固定名称。
constexpr wchar_t kRawName[] = L"00000000000000000001.ksaseg"; // 终态切片的固定 raw/1。

// 将共享项目错误保留给桌面状态区，兼顾项目错误类型和具体失败步骤。
std::string ReplayDiagnostic(const Project::ProjectResult& result) {
    return std::string(Project::ProjectErrorName(result.error)) + "/" + result.detail;
}

// 校验并固定用户选择的本地项目根。只读打开期间保留其父目录身份。
Project::ProjectResult PinProjectRoot(const std::wstring& path, Storage::Directory& root) {
    const std::filesystem::path manifest(path); // 保留原始 UTF-16 路径。
    if (!manifest.is_absolute() || !IsProjectReplayManifest(path)) {
        return Storage::Failure(Project::ProjectError::InvalidArgument, "replayManifest");
    }
    return Storage::OpenRoot(manifest.parent_path().wstring(), false, false, root);
}

// 返回无法发布的新请求回执，控件层继续保留上次提交的数据和详情。
ProjectReplayEvidence ReplayFailure(const Project::ProjectResult& result) {
    ProjectReplayEvidence evidence; // 失败时没有段身份或预览行。
    evidence.raw.diagnostic = ReplayDiagnostic(result);
    evidence.raw.systemError = result.nativeError;
    return evidence;
}

} // namespace

bool IsProjectReplayManifest(const std::wstring& path) {
    const auto name = std::filesystem::path(path).filename().wstring(); // 只比较最终分量。
    return CompareStringOrdinal(name.c_str(), -1, kManifestName, -1, TRUE) == CSTR_EQUAL;
}

ProjectReplayCatalog ReadProjectReplayCatalog(const std::wstring& manifestPath) {
    ProjectReplayCatalog catalog; // 只在全部页面通过项目校验后交付选择数据。
    Storage::Directory root; // 与后续文档打开同一已固定的项目根。
    Project::ProjectDocument project; // 后台线程独占的只读项目。
    auto status = PinProjectRoot(manifestPath, root); // 逐组件拒绝不安全路径。
    if (status) status = project.Open(manifestPath, Project::ProjectAccess::ReadOnly);
    if (status) {
        const auto& info = *project.Info(); // 此次目录所绑定的已提交项目代次。
        catalog.recoveredPrevious = info.recoveredPrevious;
        catalog.choices.reserve(static_cast<std::size_t>(info.sampleCount));
        while (catalog.choices.size() < info.sampleCount) {
            std::vector<Project::SampleInfo> page; // 共享目录支持的单页数据。
            status = project.ListSamples(catalog.choices.size(), Project::kProjectCatalogPageSize, page);
            if (!status) break;
            if (page.empty()) {
                status = Storage::Failure(Project::ProjectError::Corrupt, "replayCatalogCount");
                break;
            }
            for (auto& sample : page) {
                catalog.choices.push_back({std::move(sample.title), {manifestPath, info.projectId,
                    std::move(sample.sampleId), std::move(sample.descriptionHash)}});
            }
        }
    }

    // 目录任一页失败时丢弃草稿候选。旧结果仍由控件层持有。
    if (!status) {
        catalog.choices.clear();
        catalog.diagnostic = ReplayDiagnostic(status);
        catalog.systemError = status.nativeError;
    }
    return catalog;
}

ProjectReplayEvidence ReadProjectReplay(const ProjectReplayRequest& request) {
    Storage::Directory root; // 固定清单所在的本地目录及祖先句柄。
    if (const auto status = PinProjectRoot(request.manifestPath, root); !status) return ReplayFailure(status);
    Project::ProjectDocument project; // 当前读取所绑定的已提交项目快照。
    if (const auto status = project.Open(request.manifestPath, Project::ProjectAccess::ReadOnly); !status) {
        return ReplayFailure(status);
    }
    if (request.projectId != project.Info()->projectId) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayProjectId"));
    }
    Project::SampleRecord sample; // 经过目录、描述散列及冻结配置校验的真实采样。
    if (const auto status = project.ReadSample(request.sampleId, sample); !status) return ReplayFailure(status);
    if (request.descriptionHash != sample.info.descriptionHash) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayDescriptionHash"));
    }

    // 共用接口负责两条流及提交标记。只有标记缺失才能回退到项目内的 raw 段。
    Project::ProjectEtwCheckpoint checkpoint; // 通过验证的两流范围和散列。
    const auto terminal = project.ReadEtwCheckpoint(request.sampleId, checkpoint);
    if (!terminal && terminal.error != Project::ProjectError::NotFound) return ReplayFailure(terminal);

    // 生成目录名只用已验证 UUID，打开路径和文件身份交由共享存储层核对。
    const auto sampleName = Storage::WideAscii(sample.info.sampleId); // 固定目录分量。
    Storage::Directory rawDirectory; // 目录链在本次散列和投影期间保持固定。
    const auto directoryStatus = Storage::OpenDirectory(root, {L"samples", sampleName, L"raw"}, rawDirectory);
    if (!directoryStatus) return ReplayFailure(directoryStatus);
    Storage::Handle rawFile; // 同一同步只读句柄贯穿散列和后续投影，禁止写入及删除共享。
    const auto fileStatus = Storage::OpenFile(rawDirectory, kRawName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, rawFile);
    if (!fileStatus) return ReplayFailure(fileStatus);

    std::optional<std::uint64_t> readEnd; // 旧 raw 使用实际文件范围，已提交项目用精确端点。
    if (terminal) {
        readEnd = checkpoint.raw.end.byteOffset;
        std::string hash; // 实际用于投影的文件前缀 SHA-256。
        if (const auto status = Storage::HashArchivePrefix(rawFile.get(), *readEnd, hash); !status) {
            return ReplayFailure(status);
        }
        if (hash != checkpoint.raw.sha256) {
            return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayRawHash"));
        }
    }

    const SegmentIdentity expected{request.projectId, sample.info.sampleId, 1, 1}; // 项目 raw/1 的预期段头。
    ProjectReplayEvidence result; // 完整提交投影或显式标记的旧 raw 前缀。
    result.raw = ReadOpenStoredEvidence(rawFile.get(), readEnd, &expected);
    if (!terminal) {
        result.checkpoint = CheckpointState::NotPublished;
        return result;
    }
    if (!result.raw.diagnostic.empty() || result.raw.decodedPrefixBytes != *readEnd ||
        result.raw.lastBlockOrdinal != checkpoint.raw.end.blockOrdinal ||
        result.raw.lastSequence != checkpoint.raw.end.lastSequence) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayRawProjection", result.raw.systemError));
    }
    result.checkpoint = CheckpointState::Verified;
    result.recordsEnd = checkpoint.records.end.byteOffset;
    return result;
}

} // namespace Ksword::Features::ActionAnalyze
