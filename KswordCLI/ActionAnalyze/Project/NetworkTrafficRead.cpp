#include "NetworkTrafficRead.h"
#include "ProjectStorage.h"

#include <objbase.h>
#include <algorithm>
#include <utility>

namespace Ksword::ActionAnalyze {
namespace Archive = ks::cli::action_analyze::archive;

// 此处只读取系统启动标识，不创建采集会话或取得任何控制权。
std::string ReadNetworkTrafficBootId()
{
    using QuerySystem = LONG (NTAPI*)(ULONG, void*, ULONG, ULONG*);
    struct BootEnvironment {
        GUID bootIdentifier; // 操作系统提供的本次启动UUID。
        ULONG firmwareType; // 系统结构中固件类型占位。
        ULONGLONG bootFlags; // 系统结构中启动标志占位。
    } value{};
    const auto module = GetModuleHandleW(L"ntdll.dll"); // 仅借用已加载系统模块。
    const auto query = module ? reinterpret_cast<QuerySystem>(
        GetProcAddress(module, "NtQuerySystemInformation")) : nullptr;
    if (!query || query(90, &value, static_cast<ULONG>(sizeof(value)), nullptr) < 0) {
        return {};
    }

    // StringFromGUID2输出带括号UUID，归档按小写无括号文本保存。
    wchar_t guid[39]{}; // 系统UUID文字缓冲区，包含结尾NUL。
    if (StringFromGUID2(value.bootIdentifier, guid, 39) != 39) {
        return {};
    }
    std::string id; // 启动身份的规范ASCII形式。
    for (std::size_t index = 1; index <= 36; ++index) {
        const auto ch = guid[index]; // 保留系统原始UUID位值。
        id.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + L'a' - L'A' : ch));
    }
    return ProjectStorage::IsUuid(id) && id != "00000000-0000-0000-0000-000000000000" ? id : std::string{};
}

// 整段与检查点链先通过原读端核验；失败丢弃暂存内容，避免页面展示未验证尾部。
NetworkTrafficReadResult ReadNetworkTraffic(const ProjectDocument& project,
    std::string_view sampleId, std::uint64_t ordinal, std::uint64_t recordSequence)
{
    NetworkTrafficReadResult out; // 暂存已验证结果，调用方按status决定发布。
    if (!ordinal) {
        out.status = LoadNetworkEvidenceTail(project, sampleId, out.checkpoint);
        if (!out.status) {
            return out;
        }
        ordinal = out.checkpoint.ordinal;
    }
    if (!ordinal) {
        out.status = ProjectStorage::Failure(ProjectError::NotFound, "networkCheckpointUnavailable");
        return out;
    }

    // 只读固定项目与原sample；默认每条64字节，精确序号不裁剪归档正文。
    if (!ProjectStorage::IsUuid(sampleId) || !project.Info()) {
        out.status = ProjectStorage::Failure(ProjectError::InvalidArgument, "networkReadIdentity");
        return out;
    }
    const Archive::SegmentIdentity identity{Archive::StreamKind::Raw, ordinal,
        ProjectStorage::UuidBytes(project.Info()->projectId), ProjectStorage::UuidBytes(sampleId)};
    out.status = ReadNetworkEvidence(project, sampleId, ordinal, out.checkpoint,
        [&](const auto&, const auto& flows, std::span<const Archive::RecordView> records) {
            out.totalRecords += flows.size();
            for (std::size_t index = 0; index < flows.size(); ++index) {
                if (recordSequence && flows[index].recordSequence != recordSequence) {
                    continue;
                }
                if (out.records.size() == Archive::kNetworkQueueCapacity) {
                    continue;
                }
                const auto projected = Archive::ProjectNetworkFlowRecord(identity, records[index]);
                if (!projected) {
                    continue; // 原ReadNetworkEvidence仍独立核验完整正文，不跳过坏尾。
                }
                Archive::NetworkStoredFlowPreview preview; // 所有字节拥有到UI发布结束。
                preview.segmentOrdinal = ordinal;
                preview.flow = flows[index];
                preview.source = projected->source;
                preview.sourceTrust = Archive::NetworkSourceTrust::MatchedVerifiedBinding;
                const auto count = recordSequence ? projected->inlineBytes.size() :
                    (std::min)(projected->inlineBytes.size(), std::size_t{64});
                preview.bytes.assign(projected->inlineBytes.begin(), projected->inlineBytes.begin() + count);
                out.records.push_back(std::move(preview));
            }
        });
    if (!out.status) {
        out.records.clear();
        out.totalRecords = 0;
    } else if (recordSequence && out.records.empty()) {
        out.status = ProjectStorage::Failure(ProjectError::NotFound, "networkRecordUnavailable");
    }
    return out;
}

} // namespace Ksword::ActionAnalyze
