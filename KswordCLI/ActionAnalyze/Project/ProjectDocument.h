#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
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
enum class ProjectEvidenceLane { Primary, MixedEtw };
inline constexpr std::string_view kMixedEtwProviderId = "d4a71ada-81b0-4b15-a173-417f33bc8107";

// 该能力只承载离线项目、调查说明与未采集的独立配置快照。
inline constexpr char kOfflineProjectFeature[] = "cli-offline-project-v1";
inline constexpr char kBreakpointDefinitionsFeature[] = "project-breakpoint-definitions-v1";
inline constexpr char kBreakpointDefinitionsKey[] = "breakpointDefinitions"; // 项目配置和冻结快照共用的字段名。
inline constexpr std::size_t kProjectBreakpointLimit = 64;
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

// 模块文件标签及可选的精确映像散列，均为离线输入值。
struct BreakpointModule {
    std::string name;
    std::optional<std::string> imageSha256;
    bool operator==(const BreakpointModule&) const = default;
};

// RSDS 标识与 age 一起标记符号所属 PDB。
struct BreakpointPdb {
    std::string guid;
    std::uint32_t age = 0;
    bool operator==(const BreakpointPdb&) const = default;
};

// 模块相对位置以 32 位 RVA 保存。
struct BreakpointRva {
    std::uint32_t rva = 0;
    bool operator==(const BreakpointRva&) const = default;
};

// 精确符号文本及可选 PDB 标识。
struct BreakpointSymbol {
    std::string symbol;
    std::optional<BreakpointPdb> pdb;
    bool operator==(const BreakpointSymbol&) const = default;
};

// 草稿新项以空 ID 和修订 0 提交，已保存项携带当前稳定 ID 和逐项修订。
struct BreakpointDefinition {
    std::string breakpointDefinitionId;
    std::uint64_t definitionRevision = 0;
    bool enabled = true;
    BreakpointModule module;
    std::variant<BreakpointRva, BreakpointSymbol> location;
    bool operator==(const BreakpointDefinition&) const = default;
};

struct RevisionSettings {
    std::string title;
    std::string notes;
    // 缺省表示旧配置形状，空集合表示扩展配置中已明确清空。
    std::optional<std::vector<BreakpointDefinition>> breakpointDefinitions = std::nullopt;
    bool operator==(const RevisionSettings&) const = default;
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

    // 保存完整草稿。扩展配置要求草稿基于的项目修订 ID。
    ProjectResult Save(const RevisionSettings& settings, std::string_view expectedRevisionId = {});
    // 冻结当前已提交配置。扩展配置要求本次采用的项目修订 ID。
    ProjectResult CreateSample(std::string_view title, SampleInfo& out, std::string_view expectedRevisionId = {});
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
        const ks::cli::action_analyze::archive::EtwCoverageV1& coverage, ProjectEtwCheckpoint& out,
        ProjectEvidenceLane lane = ProjectEvidenceLane::Primary);
    // 校验指定代次的双流。NotFound 仅表示该代次的标记不存在。
    ProjectResult ReadEtwCheckpoint(std::string_view sampleId, ProjectEtwCheckpoint& out,
        std::uint64_t ordinal = 1, ProjectEvidenceLane lane = ProjectEvidenceLane::Primary) const;
    // 显式扫描未纳入当前目录的样本目录名，返回尚待核验的孤立候选 ID。
    ProjectResult ListOrphans(std::vector<std::string>& out) const;

private:
    friend struct ProjectApiCheckpointAccess; // 供独立 API 检查点实现借用已固定的项目目录。
    const ProjectStorage::Directory* RootForRead() const noexcept;
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace Ksword::ActionAnalyze
