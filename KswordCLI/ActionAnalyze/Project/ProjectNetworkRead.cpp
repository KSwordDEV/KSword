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

// v1检查点允许没有成员窗口；新字段只恢复筛选身份，不提升原包的归属等级。
bool TargetWindows(const JsonValue& marker, std::vector<ProjectNetworkTargetWindow>& out)
{
    const auto* value = marker.find("targetWindows"); // 旧单目标档没有该可选字段。
    if (!value)
    {
        return true;
    }
    const auto* windows = value->asArray(); // 新检查点中声明的全部已接管实例。
    if (!windows)
    {
        return false;
    }
    for (const auto& item : *windows)
    {
        ProjectNetworkTargetWindow window; // 逐项验证后才加入可发布快照。
        std::uint64_t pid = 0; // 无损读取后校验Win32 PID范围。
        const auto* root = item.find("root"); // 根成员标志必须是原生布尔值。
        if (!GetNumber(item, "pid", pid) || !pid || pid >= UINT32_MAX ||
            !GetNumber(item, "creationFileTime", window.creationFileTime) || !window.creationFileTime ||
            !GetNumber(item, "startUtc", window.startUtc) || !window.startUtc ||
            (!IsNull(item, "endUtc") && (!GetNumber(item, "endUtc", window.endUtc) ||
                !window.endUtc || window.endUtc < window.startUtc)) ||
            !root || !root->tryGetBool(window.root) ||
            !GetString(item, "endReason", window.endReason) || !IsText(window.endReason, 64))
        {
            return false;
        }
        window.pid = static_cast<std::uint32_t>(pid);
        for (const auto& previous : out)
        {
            if (previous.pid == window.pid && previous.creationFileTime == window.creationFileTime)
            {
                return false;
            }
        }
        out.push_back(std::move(window));
    }
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
        !Binding(marker, *project.Info(), sampleId, draft.source) || !TargetWindows(marker, draft.targetWindows)) {
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
    draft.loss = decoded.loss; // 只有整段正文、EOF和摘要均核验成功后才发布真实损失计数。
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
