#include "ProjectNetworkEvidence.h"

#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"

namespace Ksword::ActionAnalyze {

// 与写入器共享同一私有访问桥，只借用项目已固定的目录，不取得写入权。
struct ProjectNetworkEvidenceAccess {
    static const ProjectStorage::Directory* Root(const ProjectDocument& project) { return project.RootForRead(); }
};

namespace {
namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;

// 读取网络专用检查点原文。目录与文件名完全由已校验 sample UUID 和正整数生成。
ProjectResult Marker(const Directory& root, std::string_view sampleId, std::uint64_t ordinal, JsonValue& out)
{
    return Read(root, {L"samples", WideAscii(sampleId), L"checkpoints-network"}, NumberFile(ordinal), {}, out);
}

// 将持久来源声明还原为原归档器的强类型绑定；不把历史声明升级为当前活采集权限。
bool Binding(const JsonValue& marker, const ProjectInfo& project, std::string_view sampleId,
    Archive::NetworkEvidenceBinding& out)
{
    std::string epoch; // 来源代次的 UUID 文本。
    std::uint64_t domain = 0; // 来源实际时钟域。
    if (!GetString(marker, "sourceId", out.sourceId) || !GetUuid(marker, "sourceEpoch", epoch) ||
        !GetString(marker, "clockId", out.clockId) || !GetString(marker, "bootId", out.bootId) ||
        !GetNumber(marker, "clockDomain", domain)) return false;
    out.project = UuidBytes(project.projectId);
    out.sample = UuidBytes(sampleId);
    out.sourceEpoch = UuidBytes(epoch);
    if (domain == static_cast<std::uint8_t>(Archive::NetworkTimeDomain::Qpc)) {
        std::uint64_t frequency = 0; // 只有 QPC 来源带频率。
        if (!GetNumber(marker, "frequencyHz", frequency) || !frequency) return false;
        out.frequencyHz = frequency;
    } else if (domain != static_cast<std::uint8_t>(Archive::NetworkTimeDomain::FileTime) ||
        !IsNull(marker, "frequencyHz")) return false;
    out.clockDomain = static_cast<Archive::NetworkTimeDomain>(domain);
    return true;
}
} // namespace

// 校验标记、完整网络正文、前段序号与散列。回调借用字节，仅在本函数成功后才能对外发布。
ProjectResult ReadNetworkEvidence(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, ProjectNetworkCheckpoint& out, const Archive::NetworkFlowBlockVisitor& visitor)
{
    using namespace ProjectStorage;
    out = {};
    const auto* root = ProjectNetworkEvidenceAccess::Root(project); // 固定目录租约归原项目所有者。
    if (!root || !project.Info()) return Failure(ProjectError::NotOpen, "networkProject");
    if (!ordinal || ordinal > 4096) return Failure(ProjectError::InvalidArgument, "networkOrdinal");
    SampleRecord sample; // 查询原 sample 冻结描述，避免把另一个采样的标记接过来。
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;
    JsonValue marker;
    if (const auto status = Marker(*root, sampleId, ordinal, marker); !status) return status;
    ProjectNetworkCheckpoint draft; // 失败不发布任何已读端点。
    std::uint64_t pid = 0;
    if (!IsString(marker, "kind", "network-archive-checkpoint-v1") ||
        !IsString(marker, "projectId", project.Info()->projectId) || !IsString(marker, "sampleId", sampleId) ||
        !IsString(marker, "descriptionHash", sample.info.descriptionHash) ||
        !GetNumber(marker, "ordinal", draft.ordinal) || draft.ordinal != ordinal ||
        !GetNumber(marker, "endOffset", draft.endOffset) || !GetNumber(marker, "lastSequence", draft.lastSequence) ||
        !GetHash(marker, "sha256", draft.sha256) || !GetNumber(marker, "requestedPid", pid) || !pid || pid >= UINT32_MAX ||
        !GetNumber(marker, "requestedCreation", draft.requestedCreation) || !draft.requestedCreation ||
        !GetString(marker, "stopReason", draft.stopReason) || !IsText(draft.stopReason, 64) ||
        !Binding(marker, *project.Info(), sampleId, draft.source)) {
        return Failure(ProjectError::Corrupt, "networkCheckpointDocument");
    }
    draft.requestedPid = static_cast<std::uint32_t>(pid);

    // 每段绑定前一标记的摘要及末序号；顺序浏览者使用 LoadNetworkEvidenceTail 核验整条链。
    std::optional<std::uint64_t> previousSequence;
    if (ordinal > 1) {
        JsonValue previous;
        std::string previousHash;
        std::uint64_t sequence = 0;
        if (const auto status = Marker(*root, sampleId, ordinal - 1, previous); !status) {
            return Failure(ProjectError::RecoveryRequired, "networkPreviousCheckpoint", status.nativeError);
        }
        if (!GetHash(previous, "sha256", previousHash) || !IsString(marker, "previousSha256", previousHash) ||
            !IsString(previous, "projectId", project.Info()->projectId) || !IsString(previous, "sampleId", sampleId) ||
            !GetNumber(previous, "lastSequence", sequence) || !sequence) {
            return Failure(ProjectError::Corrupt, "networkCheckpointChain");
        }
        previousSequence = sequence;
    } else if (!IsNull(marker, "previousSha256")) {
        return Failure(ProjectError::Corrupt, "networkFirstCheckpoint");
    }
    const Archive::SegmentIdentity identity{Archive::StreamKind::Raw, ordinal,
        UuidBytes(project.Info()->projectId), UuidBytes(sampleId)};
    const auto name = Archive::NameInspectionSegment(identity); // 文件名沿用统一 Stored 段命名。
    Directory raw;
    if (const auto status = OpenDirectory(*root, {L"samples", WideAscii(sampleId), L"raw-network"}, raw); !status) return status;
    Handle file;
    if (!name) return Failure(ProjectError::Corrupt, "networkSegmentName");
    if (const auto status = OpenFile(raw, name->fileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !status) return status;
    std::string hash; // 摘要只覆盖已发布前缀，未发布尾部不成为产品结果。
    if (const auto status = HashArchivePrefix(file.get(), draft.endOffset, hash); !status) return status;
    if (hash != draft.sha256) return Failure(ProjectError::Corrupt, "networkCheckpointHash");
    const auto framing = Archive::ScanOpenSegment(file.get(), {identity, draft.endOffset, previousSequence});
    if (framing.status != Archive::SegmentScanStatus::FramingComplete || framing.lastSequence != draft.lastSequence) {
        return Failure(ProjectError::Corrupt, "networkCheckpointFraming", framing.error.win32Error);
    }
    const auto decoded = Archive::ScanOpenNetworkEvidence(file.get(), draft.source, ordinal, draft.endOffset, visitor);
    if (decoded.framing.status != Archive::SegmentScanStatus::FramingComplete || !decoded.eof ||
        decoded.checkedBytes != draft.endOffset || decoded.framing.lastSequence != draft.lastSequence) {
        return Failure(ProjectError::Corrupt, "networkCheckpointBody", decoded.framing.error.win32Error);
    }
    out = std::move(draft);
    return {};
}

// 开始采集前只加载一次已有链；发现中断时保持现场，拒绝换段隐藏损坏材料。
ProjectResult LoadNetworkEvidenceTail(const ProjectDocument& project, std::string_view sampleId,
    ProjectNetworkCheckpoint& out)
{
    using namespace ProjectStorage;
    out = {};
    const auto* root = ProjectNetworkEvidenceAccess::Root(project);
    if (!root || !project.Info()) return Failure(ProjectError::NotOpen, "networkProject");
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;
    for (std::uint64_t ordinal = 1; ordinal <= 4096; ++ordinal) {
        JsonValue marker; // 先区分标记不存在与标记已存在但正文缺失。
        const auto found = Marker(*root, sampleId, ordinal, marker);
        if (found.error == ProjectError::NotFound) return {};
        if (!found) return found;
        ProjectNetworkCheckpoint checked;
        if (const auto status = ReadNetworkEvidence(project, sampleId, ordinal, checked); !status) return status;
        out = std::move(checked);
    }
    return Failure(ProjectError::LimitExceeded, "networkSegmentLimit");
}

} // namespace Ksword::ActionAnalyze
