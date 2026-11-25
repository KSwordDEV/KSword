#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ks::cli::action_analyze::archive {
enum class StreamKind : std::uint32_t;
struct SegmentInspection;
struct RawEvidenceReceipt;
struct RawEvidenceScanResult;
struct RawEvidenceBoundary;
struct EtwCoverageV1;
}

namespace Ksword::ActionAnalyze {

namespace ProjectStorage { struct Directory; }
struct ProjectRawEvidenceWrite;
struct ProjectRawEvidenceRead;
struct ProjectEtwCheckpoint;

// 该能力只承载离线项目、调查说明与未采集的独立配置快照。
inline constexpr char kOfflineProjectFeature[] = "cli-offline-project-v1";
inline constexpr std::uint64_t kProjectCatalogPageSize = 256;
inline constexpr std::uint64_t kProjectSampleLimit = 4096;

enum class ProjectError {
    None, InvalidArgument, AlreadyOpen, NotOpen, NotFound, AlreadyExists,
    ReadOnly, WriterBusy, StaleRevision, Unsupported, RecoveryRequired, UnsafePath,
    Corrupt, LimitExceeded, IoError
};

struct ProjectResult {
    ProjectError error = ProjectError::None;
    std::uint32_t nativeError = 0;
    const char* detail = "";

    explicit operator bool() const noexcept { return error == ProjectError::None; }
};

const char* ProjectErrorName(ProjectError error) noexcept;

enum class ProjectAccess { ReadOnly, ReadWrite };

struct RevisionSettings {
    std::string title;
    std::string notes;
};

struct ProjectInfo {
    std::string projectId;
    std::uint64_t createdUtc = 0; // FILETIME 纪元，100ns。
    RevisionSettings settings;
    std::string revisionId;
    std::string revisionHash;
    std::string configSemanticHash;
    std::uint64_t generation = 0;
    std::uint64_t sampleCount = 0;
    ProjectAccess access = ProjectAccess::ReadOnly;
    bool recoveredPrevious = false;
    ProjectResult primaryFailure;
};

struct SampleInfo {
    std::string sampleId;
    std::string title;
    std::uint64_t createdUtc = 0;
    std::string revisionId;
    std::string snapshotId;
    std::string descriptionHash;
};

inline constexpr char kOfflineSampleStatus[] = "not-collected";

struct SampleRecord {
    SampleInfo info;
    RevisionSettings frozenSettings;
    std::string revisionHash;
    std::string configSemanticHash;
};

// 由 CLI 的项目请求线程串行持有。读者以打开时的提交为快照。
class ProjectDocument final {
public:
    ProjectDocument();
    ~ProjectDocument();
    ProjectDocument(const ProjectDocument&) = delete;
    ProjectDocument& operator=(const ProjectDocument&) = delete;

    // Create 的参数是尚不存在的专用目录。Open 接受目录或其中的 project.ksaproj。
    ProjectResult Create(const std::wstring& directory, const RevisionSettings& settings);
    ProjectResult Open(const std::wstring& directoryOrManifest,
                       ProjectAccess access = ProjectAccess::ReadOnly);
    void Close() noexcept;
    const ProjectInfo* Info() const noexcept;

    // 编辑端可传入草稿基于的修订 ID，避免晚到的保存覆盖当前修订。
    ProjectResult Save(const RevisionSettings& settings, std::string_view expectedRevisionId = {});
    ProjectResult CreateSample(std::string_view title, SampleInfo& out);
    // start 是当前 generation 内的零基序号。每次最多返回一页容量。
    ProjectResult ListSamples(std::uint64_t start, std::uint64_t limit,
                              std::vector<SampleInfo>& out) const;
    ProjectResult ReadSample(std::string_view sampleId, SampleRecord& out) const;
    // 读取已登记采样的指定段，端点为本次扫描的字节边界。成功后从 out 读取封装检查结果。
    // archiveStreamUnavailable / archiveSegmentUnavailable 只描述本次指定路径无法打开。
    ProjectResult InspectSegment(std::string_view projectId, std::string_view sampleId,
        ks::cli::action_analyze::archive::StreamKind stream, std::uint64_t ordinal,
        std::optional<std::uint64_t> endOffset, ks::cli::action_analyze::archive::SegmentInspection& out) const;
    // 归档工作线程持有项目和目录租约。段级回执独立于旧采样登记文档。
    ProjectResult WriteRawEvidenceSegment(const ProjectRawEvidenceWrite& request,
        ks::cli::action_analyze::archive::RawEvidenceReceipt& out);
    ProjectResult ReadRawEvidenceSegment(const ProjectRawEvidenceRead& request,
        ks::cli::action_analyze::archive::RawEvidenceScanResult& out, std::string* prefixHash = nullptr) const;
    ProjectResult PublishEtwCheckpoint(std::string_view sampleId,
        const ks::cli::action_analyze::archive::RawEvidenceBoundary& rawEnd,
        const ks::cli::action_analyze::archive::EtwCoverageV1& coverage, ProjectEtwCheckpoint& out);
    ProjectResult ReadEtwCheckpoint(std::string_view sampleId, ProjectEtwCheckpoint& out) const;
    // 显式扫描未纳入当前目录的样本目录名，返回尚待核验的孤立候选 ID。
    ProjectResult ListOrphans(std::vector<std::string>& out) const;

private:
    const ProjectStorage::Directory* RootForRead() const noexcept;
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace Ksword::ActionAnalyze
