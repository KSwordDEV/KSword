#include "NativeSectionMapAssociation.h"

#include "../Project/ProjectStorage.h"

#include <limits>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {

// 核心只消费读端已核验的两路历史输入；空结果表示不具备本项一致性，不修补任何原证据。
std::optional<NativeSectionMapAssociation> AssociateNativeSectionMap(
    const SampleScope& scope,
    const EvidenceRef& evidence,
    const ArchivedGraphRecord& mapping,
    std::string_view mappingSha256,
    const ArchivedNativeExecution& execution,
    std::uint64_t nativeSegmentOrdinal)
{
    namespace storage = ProjectStorage;
    if (!HasArchivedApiLocation(scope, evidence) || !evidence.raw || evidence.sourceId.empty() ||
        evidence.sourceEpoch.empty() || !mapping.segmentOrdinal || !mapping.recordSequence ||
        evidence.raw->segmentOrdinal != mapping.segmentOrdinal ||
        evidence.raw->sequence != mapping.recordSequence || !storage::IsHash(mappingSha256) ||
        !nativeSegmentOrdinal || !execution.end.lastSequence || !storage::IsHash(execution.sha256) ||
        mapping.operation != "NtMapViewOfSection" || mapping.apiFamily != "section-map" ||
        mapping.apiCategory != "memory" || !mapping.apiSectionMap ||
        mapping.sectionMapOutcome != Evidence::ApiSectionMapOutcome::Accepted) {
        return {};
    }

    const auto& fields = *mapping.apiSectionMap; // 原包解析出的独立映射字段，不依赖写入链。
    constexpr auto required = Evidence::ApiSectionMapActorIdentity | Evidence::ApiSectionMapTargetIdentity |
        Evidence::ApiSectionMapTargetStable | Evidence::ApiSectionMapMappedBase |
        Evidence::ApiSectionMapMappedBytes; // 实际范围及前后稳定进程身份缺一不可。
    if (fields.operation != Evidence::ApiSectionMapOperation::Map || (fields.flags & required) != required ||
        !mapping.headerPid || !*mapping.headerPid || !fields.actorCreationFileTime ||
        !fields.targetPid || fields.targetPid > UINT32_MAX || !fields.targetCreationFileTime ||
        (fields.targetPid == *mapping.headerPid &&
         fields.actorCreationFileTime != fields.targetCreationFileTime) ||
        !fields.mappedBase || !fields.mappedBytes ||
        fields.mappedBytes > (std::numeric_limits<std::uint64_t>::max)() - fields.mappedBase ||
        !fields.enterQpc || fields.returnQpc < fields.enterQpc) {
        return {};
    }

    const auto& document = execution.document; // 原生文档独立保留，不反序列化为活控制对象。
    if (!IsNativeExecutionDocument(document) ||
        !storage::IsString(document, "projectId", scope.projectId) ||
        !storage::IsString(document, "sampleId", scope.sampleId)) {
        return {};
    }
    const auto* target = document.find("target"); // 原生观察的真实所属进程声明。
    const auto* thread = document.find("thread"); // 原生观察的实际执行线程声明。
    if (!target || !thread) {
        return {};
    }
    const auto* nativePid = target->find("pid"); // 原生 PID 的 UInt 字段，不接受字符串补值。
    const auto* nativeTid = thread->find("tid"); // 原生 TID 的 UInt 字段，不从映射参数推导。
    std::uint64_t pid = 0; // 原生进程 PID 的解码值。
    std::uint64_t tid = 0; // 原生线程 TID 的解码值。
    std::uint64_t processCreated = 0; // 原生进程创建 FILETIME。
    std::uint64_t threadCreated = 0; // 原生线程创建 FILETIME。
    std::uint64_t address = 0; // 原生实际指令起点，不是下一 RIP。
    if (!nativePid || nativePid->type() != Evidence::JsonType::UInt || !nativePid->tryGetU64(pid) ||
        pid != fields.targetPid || !nativeTid || nativeTid->type() != Evidence::JsonType::UInt ||
        !nativeTid->tryGetU64(tid) || !tid || tid > UINT32_MAX ||
        !storage::GetNumber(*target, "creationFileTime", processCreated) ||
        processCreated != fields.targetCreationFileTime ||
        !storage::GetNumber(*thread, "creationFileTime", threadCreated) || threadCreated < processCreated ||
        !storage::GetNumber(document, "instructionAddress", address) || address < fields.mappedBase ||
        address - fields.mappedBase >= fields.mappedBytes) {
        return {};
    }

    NativeSectionMapAssociation result; // 全部身份及实际半开区间一致后才发布候选。
    if (!storage::GetString(document, "observation", result.observation) ||
        (result.observation != "execution-enter-attempt" && result.observation != "instruction-completed")) {
        return {};
    }
    result.mapping = evidence;
    result.mappingSha256 = std::string(mappingSha256);
    result.fields = fields;
    result.actorPid = *mapping.headerPid;
    result.nativeSegmentOrdinal = nativeSegmentOrdinal;
    result.nativeRecordSequence = execution.end.lastSequence;
    result.nativeSha256 = execution.sha256;
    result.instructionAddress = address;
    result.tid = static_cast<std::uint32_t>(tid);
    result.threadCreationFileTime = threadCreated;
    std::uint64_t qpc = 0; // 原生原 QPC，仅保存，不与 API 进入/返回时点排序。
    if (storage::GetNumber(document, "observedQpc", qpc)) {
        result.observedQpc = qpc;
    }
    std::uint64_t frequency = 0; // 原生文档报告的时钟频率，零值也按原值保留。
    if (storage::GetNumber(document, "qpcFrequency", frequency)) {
        result.nativeQpcFrequency = frequency;
    }
    return result;
}

// 输入AAIM1原始返回记录和已核验原生文档，输出实际范围/指令的一致性，不建立分配代次。
std::optional<NativeMemoryRangeAssociation> AssociateNativeMemoryRange(const SampleScope& scope,
    const EvidenceRef& evidence, const ArchivedGraphRecord& request, std::string_view requestSha256,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal)
{
    namespace storage = ProjectStorage;
    using namespace Evidence;
    if (!HasArchivedApiLocation(scope, evidence) || !request.apiMemoryLifecycle ||
        evidence.raw->segmentOrdinal != request.segmentOrdinal || evidence.raw->sequence != request.recordSequence ||
        !storage::IsHash(requestSha256) || !nativeSegmentOrdinal || !execution.end.lastSequence ||
        !storage::IsHash(execution.sha256) || request.apiCategory != "memory")
    {
        return {};
    }
    const auto& fields = *request.apiMemoryLifecycle; // 严格AAIM1解析后的原值，不从API名称猜测输出。
    const bool allocate = fields.operation == ApiMemoryOperation::Allocate; // 只开放有实际范围的两种返回。
    const bool protect = fields.operation == ApiMemoryOperation::Protect;
    constexpr auto required = ApiMemoryActorIdentity | ApiMemoryTargetIdentity | ApiMemoryTargetStable |
        ApiMemoryOutputBase | ApiMemoryOutputBytes; // 输出和强实例必须都有独立有效位。
    if ((!allocate && !protect) || (allocate && request.operation != "NtAllocateVirtualMemory") ||
        (protect && request.operation != "NtProtectVirtualMemory") || !fields.returnValid || fields.status < 0 ||
        (fields.flags & required) != required || !request.headerPid || !*request.headerPid ||
        !fields.actorCreationFileTime || !fields.targetPid || fields.targetPid > UINT32_MAX ||
        !fields.targetCreationFileTime || (fields.targetPid == *request.headerPid &&
            fields.targetCreationFileTime != fields.actorCreationFileTime) ||
        !fields.outputBase || !fields.outputBytes || fields.outputBytes > UINT64_MAX - fields.outputBase ||
        !fields.enterQpc || fields.returnQpc < fields.enterQpc)
    {
        return {};
    }
    const auto& document = execution.document; // 原生档案只作历史观察，不能反序列化成活owner。
    if (!IsNativeExecutionDocument(document) || !storage::IsString(document, "projectId", scope.projectId) ||
        !storage::IsString(document, "sampleId", scope.sampleId))
    {
        return {};
    }
    const auto* target = document.find("target"); // 原生观察目标的真实身份字段。
    const auto* thread = document.find("thread"); // 真实事件线程，不借用API包头TID。
    const auto* pidValue = target ? target->find("pid") : nullptr;
    const auto* tidValue = thread ? thread->find("tid") : nullptr;
    std::uint64_t pid = 0, tid = 0, created = 0; // 本次解码的进程、线程编号及进程创建时间。
    NativeMemoryRangeAssociation result; // 所有核对成功后才返回结果。
    if (!pidValue || pidValue->type() != JsonType::UInt || !pidValue->tryGetU64(pid) || pid != fields.targetPid ||
        !tidValue || tidValue->type() != JsonType::UInt || !tidValue->tryGetU64(tid) || !tid || tid > UINT32_MAX ||
        !storage::GetNumber(*target, "creationFileTime", created) || created != fields.targetCreationFileTime ||
        !storage::GetNumber(*thread, "creationFileTime", result.threadCreationFileTime) || result.threadCreationFileTime < created ||
        !storage::GetNumber(document, "instructionAddress", result.instructionAddress) || result.instructionAddress < fields.outputBase ||
        result.instructionAddress - fields.outputBase >= fields.outputBytes ||
        !storage::GetString(document, "observation", result.observation) ||
        (result.observation != "execution-enter-attempt" && result.observation != "instruction-completed"))
    {
        return {};
    }
    result.request = evidence;
    result.requestSha256 = requestSha256;
    result.fields = fields;
    result.nativeSegmentOrdinal = nativeSegmentOrdinal;
    result.tid = static_cast<std::uint32_t>(tid);
    return result;
}

} // namespace Ksword::ActionAnalyze::Detection
