#include "ApiTransferChain.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {
constexpr std::size_t kRetainedWrites = 1024; // 分析时只保留有界链路状态，不缓存原始包副本。
constexpr auto kIdentityFlags = Evidence::ApiInjectionActorIdentity | Evidence::ApiInjectionTargetIdentity |
    Evidence::ApiInjectionTargetStable;

// 只接受调用窗口内已解析且前后相同的目标，任何缺身份或明显矛盾都不串链。
bool HasIdentities(const Evidence::ApiInjectionFieldsV1& fields, std::uint32_t actorPid)
{
    return (fields.flags & kIdentityFlags) == kIdentityFlags && actorPid && fields.actorCreationFileTime &&
        fields.targetPid && fields.targetCreationFileTime &&
        (fields.targetPid != actorPid || fields.targetCreationFileTime == fields.actorCreationFileTime);
}
} // namespace

ApiTransferChain::ApiTransferChain(SampleScope scope) : scope_(std::move(scope)) {}

// 仅按同来源、实例代次、实际半开区间和 QPC 顺序建立候选；没有实际执行观测时止于创建请求。
std::vector<ApiTransferLink> ApiTransferChain::Accept(const EvidenceRef& evidence,
    const ks::winapi_monitor::ApiMonitorEventPacket& packet)
{
    std::vector<ApiTransferLink> result; // 当前创建操作可能对应多次重叠写入，保留全部有界候选。
    if (scope_.projectId.empty() || scope_.sampleId.empty() || evidence.projectId != scope_.projectId ||
        evidence.sampleId != scope_.sampleId || evidence.sourceId.empty() || evidence.sourceEpoch.empty() ||
        !evidence.raw || !evidence.raw->segmentOrdinal || !evidence.raw->sequence || !packet.sessionIdentity) {
        return result;
    }
    const auto fields = Evidence::ReadApiInjectionFields(packet); // 显式格式验证失败时不尝试解析旧摘要。
    if (!fields || !HasIdentities(*fields, packet.pid) || fields->targetPid == packet.pid) return result;
    const auto outcome = Evidence::ApiInjectionCallOutcome(packet, *fields);
    if (fields->operation == Evidence::ApiInjectionOperation::MemoryWrite) {
        constexpr auto required = Evidence::ApiInjectionAddress | Evidence::ApiInjectionCompletedLength;
        if ((fields->flags & required) != required || !fields->address || !fields->completedBytes ||
            fields->completedBytes > std::numeric_limits<std::uint64_t>::max() - fields->address ||
            (outcome != Evidence::ApiInjectionOutcome::Succeeded && outcome != Evidence::ApiInjectionOutcome::Partial)) {
            return result;
        }
        const auto duplicate = std::find_if(writes_.begin(), writes_.end(), [&](const Write& write) {
            return write.evidence.sourceId == evidence.sourceId && write.evidence.sourceEpoch == evidence.sourceEpoch &&
                write.evidence.raw == evidence.raw;
        });
        if (duplicate != writes_.end()) return result; // 重复消费同一原包不增加链路状态。
        if (writes_.size() == kRetainedWrites) {
            writes_.pop_front();
            ++evictedWrites_;
        }
        writes_.push_back({evidence, *fields, packet.pid, packet.sessionIdentity});
        return result;
    }
    if (outcome != Evidence::ApiInjectionOutcome::Succeeded ||
        !(fields->flags & Evidence::ApiInjectionStartAddress) || !fields->startAddress) return result;
    for (const auto& write : writes_) {
        const auto& prior = write.fields; // 线程创建只能关联同一个采集会话中已完成的先前写入。
        if (write.session != packet.sessionIdentity || write.actorPid != packet.pid ||
            write.evidence.sourceId != evidence.sourceId || write.evidence.sourceEpoch != evidence.sourceEpoch ||
            prior.actorCreationFileTime != fields->actorCreationFileTime || prior.targetPid != fields->targetPid ||
            prior.targetCreationFileTime != fields->targetCreationFileTime || prior.returnQpc >= fields->enterQpc ||
            fields->startAddress < prior.address || fields->startAddress - prior.address >= prior.completedBytes) continue;
        result.push_back({write.evidence, evidence, packet.pid, fields->actorCreationFileTime,
            static_cast<std::uint32_t>(fields->targetPid), fields->targetCreationFileTime,
            prior.address, prior.completedBytes, fields->startAddress});
    }
    return result;
}

std::vector<ApiApcTransferLink> ApiTransferChain::AcceptApc(const EvidenceRef& evidence,
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) const
{
    std::vector<ApiApcTransferLink> result; // 同一个队列请求可对应多个重叠写入，保留全部有界候选。
    if (scope_.projectId.empty() || scope_.sampleId.empty() || evidence.projectId != scope_.projectId ||
        evidence.sampleId != scope_.sampleId || evidence.sourceId.empty() || evidence.sourceEpoch.empty() ||
        !evidence.raw || !evidence.raw->segmentOrdinal || !evidence.raw->sequence || !packet.sessionIdentity) {
        return result;
    }
    const auto* clue = Evidence::ClassifyApiMonitorClue(packet); // 模块、导出和类别必须精确匹配。
    const auto fields = Evidence::ReadApiApcFields(packet); // AAAP1独立于AAIP1，不猜测摘要中的地址。
    constexpr auto required = Evidence::ApiApcActorIdentity | Evidence::ApiApcTargetIdentity |
        Evidence::ApiApcThreadIdentity | Evidence::ApiApcRoutineAddress | Evidence::ApiApcTargetStable;
    if (!clue || clue->family != "apc-queue" || !fields || (fields->flags & required) != required ||
        !packet.pid || !fields->actorCreationFileTime || fields->targetPid == packet.pid ||
        !fields->targetPid || !fields->targetCreationFileTime || !fields->targetTid ||
        fields->targetThreadCreationFileTime < fields->targetCreationFileTime || !fields->routineAddress ||
        Evidence::ApiApcCallOutcome(packet) != Evidence::ApiApcQueueOutcome::Accepted) {
        return result;
    }
    for (const auto& write : writes_) {
        const auto& prior = write.fields; // 比较同来源的已完成写入，严格先于本次入队请求。
        if (write.session != packet.sessionIdentity || write.actorPid != packet.pid ||
            write.evidence.sourceId != evidence.sourceId || write.evidence.sourceEpoch != evidence.sourceEpoch ||
            prior.actorCreationFileTime != fields->actorCreationFileTime || prior.targetPid != fields->targetPid ||
            prior.targetCreationFileTime != fields->targetCreationFileTime || prior.returnQpc >= fields->enterQpc ||
            fields->routineAddress < prior.address || fields->routineAddress - prior.address >= prior.completedBytes) {
            continue;
        }
        result.push_back({write.evidence, evidence, packet.pid, fields->actorCreationFileTime,
            static_cast<std::uint32_t>(fields->targetPid), fields->targetCreationFileTime,
            static_cast<std::uint32_t>(fields->targetTid), fields->targetThreadCreationFileTime,
            prior.address, prior.completedBytes, fields->routineAddress});
    }
    return result; // 不创建执行边，不依据队列接受状态推断APC已经投递。
}

// 输入同一已核验原包及来源坐标；返回全部重叠写入候选，不修改共享写入窗口。
std::vector<ApiContextTransferLink> ApiTransferChain::AcceptContext(const EvidenceRef& evidence,
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) const
{
    std::vector<ApiContextTransferLink> result; // 请求IP可能覆盖多个先前实际写入，分别保留原坐标。
    if (scope_.projectId.empty() || scope_.sampleId.empty() || evidence.projectId != scope_.projectId ||
        evidence.sampleId != scope_.sampleId || evidence.sourceId.empty() || evidence.sourceEpoch.empty() ||
        !evidence.raw || !evidence.raw->segmentOrdinal || !evidence.raw->sequence || !packet.sessionIdentity) {
        return result;
    }
    const auto* clue = Evidence::ClassifyApiMonitorClue(packet); // 核对模块、导出及业务分类。
    const auto fields = Evidence::ReadApiContextFields(packet); // 只读显式AACT1，不猜测摘要。
    constexpr auto required = Evidence::ApiContextActorIdentity | Evidence::ApiContextTargetIdentity |
        Evidence::ApiContextThreadIdentity | Evidence::ApiContextFlags | Evidence::ApiContextControlRegisters |
        Evidence::ApiContextTargetStable; // 只允许完整线程身份和已读取CONTROL寄存器的请求。
    if (!clue || clue->family != "thread-context" || !fields || (fields->flags & required) != required ||
        !packet.pid || !fields->actorCreationFileTime || fields->targetPid == packet.pid ||
        !fields->targetPid || !fields->targetCreationFileTime || !fields->targetTid ||
        fields->targetThreadCreationFileTime < fields->targetCreationFileTime || !fields->requestedIp ||
        (fields->contextFlags & (fields->contextArchitecture == 64 ? 0x100001ull : 0x10001ull)) !=
            (fields->contextArchitecture == 64 ? 0x100001ull : 0x10001ull) ||
        (fields->contextArchitecture == 32 && (fields->requestedIp > UINT32_MAX || fields->requestedSp > UINT32_MAX)) ||
        Evidence::ApiContextCallOutcome(packet) != Evidence::ApiContextOutcome::Accepted) {
        return result;
    }
    for (const auto& write : writes_) {
        const auto& prior = write.fields; // 只关联同来源、同实例代次且严格先于请求的实际写入。
        if (write.session != packet.sessionIdentity || write.actorPid != packet.pid ||
            write.evidence.sourceId != evidence.sourceId || write.evidence.sourceEpoch != evidence.sourceEpoch ||
            prior.actorCreationFileTime != fields->actorCreationFileTime || prior.targetPid != fields->targetPid ||
            prior.targetCreationFileTime != fields->targetCreationFileTime || prior.returnQpc >= fields->enterQpc ||
            fields->requestedIp < prior.address || fields->requestedIp - prior.address >= prior.completedBytes) {
            continue;
        }
        result.push_back({write.evidence, evidence, packet.pid, fields->actorCreationFileTime,
            static_cast<std::uint32_t>(fields->targetPid), fields->targetCreationFileTime,
            static_cast<std::uint32_t>(fields->targetTid), fields->targetThreadCreationFileTime,
            prior.address, prior.completedBytes, fields->requestedIp, fields->requestedSp, fields->contextArchitecture});
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Detection
