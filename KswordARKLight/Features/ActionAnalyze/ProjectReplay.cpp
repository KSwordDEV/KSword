#include "ProjectReplay.h"

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <filesystem>
#include <deque>
#include <iterator>

namespace Ksword::Features::ActionAnalyze {
namespace {

namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
constexpr wchar_t kManifestName[] = L"project.ksaproj"; // 正式项目清单的固定名称。
constexpr std::uint64_t kSelectionRawBytes = 16ULL * 1024 * 1024;

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

// 通过固定目录句柄读取指定段。已发布段从同一文件句柄复核散列、身份和端点。
SegmentEvidence ReadRawSegment(const Storage::Directory& directory, const ProjectReplayRequest& request,
    std::uint64_t ordinal, const Project::ProjectEtwCheckpoint* checkpoint, ProjectReplayMode mode) {
    const auto digits = std::to_wstring(ordinal); // 规范段文件名的十进制编号。
    const auto name = std::wstring(20 - digits.size(), L'0') + digits + L".ksaseg"; // 项目内固定文件名。
    Storage::Handle file; // 禁止其它句柄在本次读回期间写入或删除文件。
    if (const auto status = Storage::OpenFile(directory, name, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !status) {
        return ReplayFailure(status).raw;
    }
    const SegmentIdentity expected{request.projectId, request.sampleId, 1, ordinal}; // 正确的 raw 段头身份。
    if (!checkpoint) {
        if (mode == ProjectReplayMode::SelectionPreview) {
            LARGE_INTEGER size{};
            if (!::GetFileSizeEx(file.get(), &size)) {
                return ReplayFailure(Storage::WinFailure("replayRawSize", ::GetLastError())).raw;
            }
            if (static_cast<std::uint64_t>(size.QuadPart) > kSelectionRawBytes) {
                SegmentEvidence limited;
                limited.diagnostic = "replaySelectionLimit";
                return limited;
            }
        }
        return ReadOpenStoredEvidence(file.get(), std::nullopt, &expected);
    }

    const auto& end = checkpoint->raw.end; // 检查点限定的完整块水位。
    std::string hash; // 从实际用于投影的文件读回的已提交前缀摘要。
    if (const auto status = Storage::HashArchivePrefix(file.get(), end.byteOffset, hash); !status) {
        return ReplayFailure(status).raw;
    }
    if (hash != checkpoint->raw.sha256) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayRawHash")).raw;
    }
    auto segment = ReadOpenStoredEvidence(file.get(), end.byteOffset, &expected, true); // 本段最近行及真实解析端点。
    if (segment.diagnostic.empty() && (segment.decodedPrefixBytes != end.byteOffset ||
        segment.lastBlockOrdinal != end.blockOrdinal || segment.lastSequence != end.lastSequence)) {
        segment.diagnostic = "replayRawProjection";
    }
    return segment;
}

// 首标记不存在时允许旧段或有尾记的 API 段回放。持续计划等待首次发布。
ProjectReplayEvidence ReadBeforeFirstCheckpoint(const Storage::Directory& directory, const ProjectReplayRequest& request,
    ProjectReplayMode mode) {
    ProjectReplayEvidence result; // 在项目回退与等待中只提交允许展示的内容。
    result.raw = ReadRawSegment(directory, request, 1, nullptr, mode);
    if (result.raw.continuousEtwPlan) {
        result.raw = {};
        result.raw.diagnostic = "checkpointPending";
        result.checkpoint.state = CheckpointState::Pending;
        result.checkpoint.pendingOrdinal = 1;
    } else {
        result.checkpoint.state = CheckpointState::NotPublished;
    }
    return result;
}

} // namespace

bool IsProjectReplayManifest(const std::wstring& path) {
    const auto name = std::filesystem::path(path).filename().wstring(); // 只比较最终分量。
    return CompareStringOrdinal(name.c_str(), -1, kManifestName, -1, TRUE) == CSTR_EQUAL;
}

ProjectReplayCatalog ReadProjectReplayCatalog(const std::wstring& manifestPath) {
    ProjectReplayCatalog catalog; // 只在全部页面通过项目校验后交付选择数据。
    catalog.manifestPath = manifestPath;
    Storage::Directory root; // 与后续文档打开同一已固定的项目根。
    Project::ProjectDocument project; // 后台线程独占的只读项目。
    auto status = PinProjectRoot(manifestPath, root); // 逐组件拒绝不安全路径。
    if (status) status = project.Open(manifestPath, Project::ProjectAccess::ReadOnly);
    if (status) {
        const auto& info = *project.Info(); // 此次目录所绑定的已提交项目代次。
        catalog.projectId = info.projectId;
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

ProjectReplayCatalog CreateProjectReplayCatalog(const std::wstring& directory) {
    ProjectReplayCatalog catalog;
    const std::filesystem::path root(directory);
    catalog.manifestPath = (root / kManifestName).wstring();
    Project::ProjectDocument project;
    const auto name = root.filename().u8string();
    const std::string title(reinterpret_cast<const char*>(name.data()), name.size());
    const auto status = root.is_absolute() ? project.Create(directory, {title, ""}) :
        Storage::Failure(Project::ProjectError::InvalidArgument, "replayProjectPath");
    if (status) {
        catalog.projectId = project.Info()->projectId;
    } else {
        catalog.diagnostic = ReplayDiagnostic(status);
        catalog.systemError = status.nativeError;
    }
    return catalog;
}

ProjectReplayEvidence ReadProjectReplay(const ProjectReplayRequest& request, ProjectReplayMode mode) {
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

    // 生成目录名只用已验证 UUID，打开路径和文件身份交由共享存储层核对。
    const auto sampleName = Storage::WideAscii(sample.info.sampleId); // 固定目录分量。
    Storage::Directory rawDirectory; // 目录链在本次散列和投影期间保持固定。
    const auto directoryStatus = Storage::OpenDirectory(root, {L"samples", sampleName, L"raw"}, rawDirectory);
    if (!directoryStatus) return ReplayFailure(directoryStatus);
    ProjectReplayEvidence result; // 只携带已验证的连续前缀与尾段诊断。
    std::deque<EvidenceRecord> rows; // 在整个采样上独立保留固定数量的最近记录。
    std::uint64_t lastSequence = 0; // 检查点之间必须使用连续的全采样原始序号。
    for (std::uint64_t ordinal = 1; ordinal != 0; ++ordinal) {
        Project::ProjectEtwCheckpoint checkpoint; // 本段已经双流校验的范围。
        auto status = project.ReadEtwCheckpoint(request.sampleId, checkpoint, ordinal);
        if (status.error == Project::ProjectError::NotFound && ordinal == 1) {
            return ReadBeforeFirstCheckpoint(rawDirectory, request, mode);
        }

        // 读取失败时保留此前已确认的段，源文件位置始终属于各自的段。
        if (status && (lastSequence == UINT64_MAX || checkpoint.planRawSequence != lastSequence + 1)) {
            status = Storage::Failure(Project::ProjectError::Corrupt, "replayRawSequence");
        }
        auto segment = status ? ReadRawSegment(rawDirectory, request, ordinal, &checkpoint, mode) : ReplayFailure(status).raw;
        if (!segment.diagnostic.empty()) {
            result.checkpoint.state = status.error == Project::ProjectError::NotFound ? CheckpointState::Pending : CheckpointState::Partial;
            result.checkpoint.pendingOrdinal = ordinal;
            result.raw.diagnostic = std::move(segment.diagnostic);
            result.raw.systemError = segment.systemError;
            result.raw.failureOffset = segment.failureOffset;
            break;
        }

        // 本段完整通过核验，可以更新最近窗口并推进检查点。
        for (auto& row : segment.rows) {
            if (rows.size() == kEvidenceRows) {
                rows.pop_front();
            }
            rows.push_back(std::move(row));
        }
        lastSequence = checkpoint.raw.end.lastSequence;
        result.raw = std::move(segment);
        result.checkpoint.lastVerifiedOrdinal = ordinal;
        result.checkpoint.recordsEnd = checkpoint.records.end.byteOffset;
        if (checkpoint.finalSegment) {
            result.checkpoint.state = CheckpointState::Verified;
            break;
        }
        if (mode == ProjectReplayMode::SelectionPreview) {
            result.checkpoint.state = CheckpointState::PreviewLimited;
            break;
        }
    }
    if (result.raw.identity) {
        result.raw.identity->ordinal = 1; // 逻辑结果锚定整次采样，行内保留实际段号。
        result.raw.rows.assign(std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
    }
    return result;
}

} // namespace Ksword::Features::ActionAnalyze
