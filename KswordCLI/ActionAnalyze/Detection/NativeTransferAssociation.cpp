#include "NativeTransferAssociation.h"

#include "../Project/ProjectStorage.h"

#include <limits>

namespace Ksword::ActionAnalyze::Detection {
namespace {
using namespace ProjectStorage;

bool NativeId(const Evidence::JsonValue& object, std::string_view key, std::uint32_t expected)
{
    const auto* value = object.find(key);
    std::uint64_t number = 0;
    return value && value->type() == Evidence::JsonType::UInt && value->tryGetU64(number) && number == expected;
}
} // namespace

std::optional<NativeTransferAssociation> AssociateNativeTransfer(const SampleScope& scope,
    const ApiTransferLink& transfer, const ArchivedGraphRecord& creation,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal)
{
    if (!HasEvidenceLocation(scope, transfer.write) || !HasEvidenceLocation(scope, transfer.threadCreate) ||
        !transfer.threadCreate.raw || transfer.threadCreate.raw->segmentOrdinal != creation.segmentOrdinal ||
        transfer.threadCreate.raw->sequence != creation.recordSequence || !creation.apiInjection ||
        creation.apiOutcome != Evidence::ApiInjectionOutcome::Succeeded || !nativeSegmentOrdinal ||
        !execution.end.lastSequence || !IsHash(execution.sha256) || !transfer.writtenAddress ||
        !transfer.writtenBytes || transfer.writtenBytes > (std::numeric_limits<std::uint64_t>::max)() - transfer.writtenAddress)
        return {};
    const auto& fields = *creation.apiInjection;
    constexpr auto identities = Evidence::ApiInjectionActorIdentity | Evidence::ApiInjectionTargetIdentity |
        Evidence::ApiInjectionThreadIdentity | Evidence::ApiInjectionTargetStable | Evidence::ApiInjectionStartAddress;
    if (fields.operation != Evidence::ApiInjectionOperation::ThreadCreate || (fields.flags & identities) != identities ||
        creation.headerPid != transfer.actorPid || fields.actorCreationFileTime != transfer.actorCreationFileTime ||
        fields.targetPid != transfer.targetPid || fields.targetCreationFileTime != transfer.targetCreationFileTime ||
        fields.startAddress != transfer.requestedStartAddress || !fields.targetTid || fields.targetTid > UINT32_MAX ||
        !fields.targetThreadCreationFileTime || fields.targetThreadCreationFileTime < fields.targetCreationFileTime ||
        !fields.enterQpc || fields.returnQpc < fields.enterQpc) return {};

    const auto& doc = execution.document;
    if (!IsString(doc, "kind", "native-execution-v1") || !IsString(doc, "projectId", scope.projectId) ||
        !IsString(doc, "sampleId", scope.sampleId)) return {};
    const auto* target = doc.find("target");
    const auto* thread = doc.find("thread");
    std::uint64_t processCreated = 0, threadCreated = 0, address = 0, qpc = 0;
    if (!target || !thread || !NativeId(*target, "pid", transfer.targetPid) ||
        !NativeId(*thread, "tid", static_cast<std::uint32_t>(fields.targetTid)) ||
        !GetNumber(*target, "creationFileTime", processCreated) || processCreated != transfer.targetCreationFileTime ||
        !GetNumber(*thread, "creationFileTime", threadCreated) || threadCreated != fields.targetThreadCreationFileTime ||
        !GetNumber(doc, "instructionAddress", address) || address < transfer.writtenAddress ||
        address - transfer.writtenAddress >= transfer.writtenBytes) return {};
    // 两类档案尚未证明共同启动期时钟。尤其不能要求执行晚于创建返回：线程可能提前运行。
    std::string kind;
    if (!GetString(doc, "observation", kind) ||
        (kind != "execution-enter-attempt" && kind != "instruction-completed")) return {};
    NativeTransferAssociation result;
    result.transfer = transfer;
    result.nativeSegmentOrdinal = nativeSegmentOrdinal;
    result.nativeRecordSequence = execution.end.lastSequence;
    result.nativeSha256 = execution.sha256;
    result.observation = std::move(kind);
    result.instructionAddress = address;
    result.tid = static_cast<std::uint32_t>(fields.targetTid);
    result.threadCreationFileTime = threadCreated;
    if (GetNumber(doc, "observedQpc", qpc)) result.observedQpc = qpc;
    result.createEnterQpc = fields.enterQpc;
    return result;
}

std::optional<NativeApcTransferAssociation> AssociateNativeApcTransfer(const SampleScope& scope,
    const ApiApcTransferLink& transfer, const ArchivedGraphRecord& queue,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal)
{
    if (!HasEvidenceLocation(scope, transfer.write) || !HasEvidenceLocation(scope, transfer.queue) ||
        !transfer.queue.raw || transfer.queue.raw->segmentOrdinal != queue.segmentOrdinal ||
        transfer.queue.raw->sequence != queue.recordSequence || !queue.apiApc || queue.apiFamily != "apc-queue" ||
        queue.apcOutcome != Evidence::ApiApcQueueOutcome::Accepted || !nativeSegmentOrdinal ||
        !execution.end.lastSequence || !IsHash(execution.sha256) || !transfer.writtenAddress ||
        !transfer.writtenBytes || transfer.writtenBytes > UINT64_MAX - transfer.writtenAddress) {
        return {};
    }
    const auto& fields = *queue.apiApc; // 已由AAAP1解析器核对的原请求和线程身份。
    constexpr auto identities = Evidence::ApiApcActorIdentity | Evidence::ApiApcTargetIdentity |
        Evidence::ApiApcThreadIdentity | Evidence::ApiApcRoutineAddress | Evidence::ApiApcTargetStable;
    if ((fields.flags & identities) != identities || queue.headerPid != transfer.actorPid ||
        fields.actorCreationFileTime != transfer.actorCreationFileTime || fields.targetPid != transfer.targetPid ||
        fields.targetCreationFileTime != transfer.targetCreationFileTime || fields.targetTid != transfer.targetTid ||
        fields.targetThreadCreationFileTime != transfer.targetThreadCreationFileTime ||
        !fields.targetTid || fields.targetThreadCreationFileTime < fields.targetCreationFileTime ||
        fields.routineAddress != transfer.requestedRoutineAddress || !fields.enterQpc || fields.returnQpc < fields.enterQpc) {
        return {};
    }
    const auto& doc = execution.document; // 历史原生事件仍不转换成活控制对象。
    if (!IsString(doc, "kind", "native-execution-v1") || !IsString(doc, "projectId", scope.projectId) ||
        !IsString(doc, "sampleId", scope.sampleId)) {
        return {};
    }
    const auto* target = doc.find("target"); // 实际执行事件的进程与线程身份。
    const auto* thread = doc.find("thread");
    std::uint64_t processCreated = 0; // 事件所属进程的创建FILETIME。
    std::uint64_t threadCreated = 0; // 事件实际线程的创建FILETIME。
    std::uint64_t address = 0; // 原生指令起点，不用下一RIP冒充入口。
    if (!target || !thread || !NativeId(*target, "pid", transfer.targetPid) ||
        !NativeId(*thread, "tid", transfer.targetTid) ||
        !GetNumber(*target, "creationFileTime", processCreated) || processCreated != transfer.targetCreationFileTime ||
        !GetNumber(*thread, "creationFileTime", threadCreated) || threadCreated != transfer.targetThreadCreationFileTime ||
        !GetNumber(doc, "instructionAddress", address) || address != fields.routineAddress ||
        address < transfer.writtenAddress || address - transfer.writtenAddress >= transfer.writtenBytes) {
        return {};
    }
    NativeApcTransferAssociation result; // 仅全部匹配后发布同线程同入口的一致性候选。
    if (!GetString(doc, "observation", result.observation) ||
        (result.observation != "execution-enter-attempt" && result.observation != "instruction-completed")) {
        return {};
    }
    result.transfer = transfer;
    result.nativeSegmentOrdinal = nativeSegmentOrdinal;
    result.nativeRecordSequence = execution.end.lastSequence;
    result.nativeSha256 = execution.sha256;
    result.instructionAddress = address;
    std::uint64_t qpc = 0; // 仅保存原生时钟，目标线程可能在队列API返回前执行。
    if (GetNumber(doc, "observedQpc", qpc)) {
        result.observedQpc = qpc;
    }
    return result;
}

// 输入已核验的历史段及上下文原包，输出一致性候选；任何缺失身份或地址矛盾返回空。
std::optional<NativeContextTransferAssociation> AssociateNativeContextTransfer(const SampleScope& scope,
    const ApiContextTransferLink& transfer, const ArchivedGraphRecord& context,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal)
{
    if (!HasEvidenceLocation(scope, transfer.write) || !HasEvidenceLocation(scope, transfer.context) ||
        !transfer.context.raw || transfer.context.raw->segmentOrdinal != context.segmentOrdinal ||
        transfer.context.raw->sequence != context.recordSequence || !context.apiContext ||
        context.apiFamily != "thread-context" || context.contextOutcome != Evidence::ApiContextOutcome::Accepted ||
        !nativeSegmentOrdinal || !execution.end.lastSequence || !IsHash(execution.sha256) ||
        !transfer.writtenAddress || !transfer.writtenBytes ||
        transfer.writtenBytes > UINT64_MAX - transfer.writtenAddress) {
        return {};
    }
    const auto& fields = *context.apiContext; // 请求快照，不能解释为执行时寄存器快照。
    constexpr auto required = Evidence::ApiContextActorIdentity | Evidence::ApiContextTargetIdentity |
        Evidence::ApiContextThreadIdentity | Evidence::ApiContextFlags | Evidence::ApiContextControlRegisters |
        Evidence::ApiContextTargetStable; // 精确线程身份和已读取的CONTROL请求缺一不可。
    if ((fields.flags & required) != required || context.headerPid != transfer.actorPid ||
        fields.actorCreationFileTime != transfer.actorCreationFileTime || fields.targetPid != transfer.targetPid ||
        fields.targetCreationFileTime != transfer.targetCreationFileTime || fields.targetTid != transfer.targetTid ||
        fields.targetThreadCreationFileTime != transfer.targetThreadCreationFileTime || !fields.targetTid ||
        fields.targetThreadCreationFileTime < fields.targetCreationFileTime ||
        fields.requestedIp != transfer.requestedIp || fields.requestedSp != transfer.requestedSp ||
        fields.contextArchitecture != transfer.contextArchitecture || fields.contextArchitecture != 64 ||
        (fields.contextFlags & 0x100001ull) != 0x100001ull ||
        !fields.enterQpc || fields.returnQpc < fields.enterQpc) {
        return {};
    }
    const auto& doc = execution.document; // 原生产品目前只输出AMD64执行观察，拒绝用x86请求混配。
    if (!IsString(doc, "kind", "native-execution-v1") || !IsString(doc, "projectId", scope.projectId) ||
        !IsString(doc, "sampleId", scope.sampleId)) {
        return {};
    }
    const auto* target = doc.find("target"); // 执行事件的进程身份。
    const auto* thread = doc.find("thread"); // 执行事件的线程身份。
    std::uint64_t processCreated = 0; // 原生进程创建FILETIME。
    std::uint64_t threadCreated = 0; // 原生实际线程创建FILETIME。
    std::uint64_t address = 0; // 实际指令起点，不采用下一RIP。
    if (!target || !thread || !NativeId(*target, "pid", transfer.targetPid) ||
        !NativeId(*thread, "tid", transfer.targetTid) ||
        !GetNumber(*target, "creationFileTime", processCreated) || processCreated != transfer.targetCreationFileTime ||
        !GetNumber(*thread, "creationFileTime", threadCreated) || threadCreated != transfer.targetThreadCreationFileTime ||
        !GetNumber(doc, "instructionAddress", address) || address != fields.requestedIp ||
        address < transfer.writtenAddress || address - transfer.writtenAddress >= transfer.writtenBytes) {
        return {};
    }
    NativeContextTransferAssociation result; // 只在全部坐标、请求及实际事件匹配后构造结果。
    if (!GetString(doc, "observation", result.observation) ||
        (result.observation != "execution-enter-attempt" && result.observation != "instruction-completed")) {
        return {};
    }
    result.transfer = transfer;
    result.nativeSegmentOrdinal = nativeSegmentOrdinal;
    result.nativeRecordSequence = execution.end.lastSequence;
    result.nativeSha256 = execution.sha256;
    result.instructionAddress = address;
    std::uint64_t qpc = 0; // 仅保留原生原始时钟，不要求晚于设置上下文返回。
    if (GetNumber(doc, "observedQpc", qpc)) {
        result.observedQpc = qpc;
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Detection
