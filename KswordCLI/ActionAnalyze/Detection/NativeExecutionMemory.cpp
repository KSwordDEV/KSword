#include "NativeExecutionMemory.h"

#include "../Project/ProjectStorage.h"

#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {
using namespace ProjectStorage;
using V = Evidence::JsonValue;

// 比较两个历史文档的无损十进制字段；缺字段和格式错误都不能形成匹配。
bool SameNumber(const V& left, std::string_view leftKey, const V& right, std::string_view rightKey)
{
    std::uint64_t leftValue = 0; // 左侧归档字段的原整数值。
    std::uint64_t rightValue = 0; // 右侧归档字段的原整数值。
    return GetNumber(left, leftKey, leftValue) && GetNumber(right, rightKey, rightValue) &&
        leftValue != 0 && leftValue == rightValue;
}

// PID在两种格式中均为UInt，进程实例标签与创建时间也必须全部相等。
bool SameProcess(const V& executionTarget, const V& memoryTarget)
{
    const auto* executionPid = executionTarget.find("pid"); // 执行事件所属的进程编号。
    const auto* memoryPid = memoryTarget.find("pid"); // 读取范围所属的进程编号。
    std::uint64_t expectedPid = 0; // 不通过字符串或浮点数弱化PID格式。
    std::uint64_t observedPid = 0; // 内存读取计划报告的PID。
    std::string instance; // 由原生所有者生成并保留在两份记录中的实例标签。
    return executionPid && memoryPid && executionPid->type() == Evidence::JsonType::UInt &&
        memoryPid->type() == Evidence::JsonType::UInt && executionPid->tryGetU64(expectedPid) &&
        memoryPid->tryGetU64(observedPid) && expectedPid != 0 && expectedPid <= UINT32_MAX &&
        expectedPid == observedPid && SameNumber(executionTarget, "creationFileTime", memoryTarget, "creationFileTime") &&
        GetString(executionTarget, "processInstanceId", instance) && !instance.empty() &&
        IsString(memoryTarget, "processInstanceId", instance);
}

// 比较完整历史停点身份，不用RIP相等或QPC接近代替事件、代次及修订。
bool SameStop(const V& execution, const V& executionTarget, const V& stop)
{
    const auto* event = execution.find("event"); // 执行归档保存的后端实例与原生事件序号。
    const auto* targetPid = executionTarget.find("pid");
    const auto* stopPid = stop.find("pid");
    std::uint64_t expectedPid = 0; // 两份已核验文档的PID仍在匹配处明确核对。
    std::uint64_t observedPid = 0; // 内存前后检查令牌报告的PID。
    std::string group; // 原停止组身份。
    std::string stopId; // 原停止责任令牌。
    std::string backend; // 后端实例代次，防止跨owner事件序号碰撞。
    return event && targetPid && stopPid && targetPid->tryGetU64(expectedPid) &&
        stopPid->tryGetU64(observedPid) && expectedPid == observedPid &&
        SameNumber(executionTarget, "creationFileTime", stop, "creationFileTime") &&
        GetString(execution, "groupId", group) && !group.empty() && IsString(stop, "groupId", group) &&
        GetString(execution, "stopId", stopId) && !stopId.empty() && IsString(stop, "stopId", stopId) &&
        GetUuid(*event, "backendInstanceId", backend) && IsString(stop, "backendInstanceId", backend) &&
        SameNumber(*event, "serial", stop, "eventSerial") &&
        SameNumber(execution, "stateRevision", stop, "stateRevision");
}
} // namespace

ProjectResult AssociateNativeExecutionMemory(std::string_view projectId, std::string_view sampleId,
    const ArchivedNativeExecution& execution, const ArchivedMemorySnapshot& memory,
    std::uint64_t byteCount, NativeExecutionMemoryMatch& out)
{
    out = {}; // 不向调用端泄露前一次成功结果或本次失败前得到的部分字节。
    if (!IsUuid(projectId) || !IsUuid(sampleId) || !byteCount || byteCount > 15) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryRange");
    }
    if (!IsHash(execution.sha256) || !execution.end.lastSequence ||
        !IsHash(memory.sha256) || !memory.boundary.lastSequence) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryVerifiedInputs");
    }

    const auto& doc = execution.document; // 原生执行归档；不反序列化成活控制对象。
    const auto& plan = memory.plan; // 原内存采样的冻结身份与读取上下文。
    if (!IsString(doc, "kind", "native-execution-v1") ||
        !IsString(plan, "kind", "selected-memory-plan-v1") ||
        !IsString(doc, "projectId", projectId) || !IsString(plan, "projectId", projectId) ||
        !IsString(doc, "sampleId", sampleId) || !IsString(plan, "sampleId", sampleId)) {
        return Failure(ProjectError::InvalidArgument, "nativeMemorySample");
    }
    const auto* executionTarget = doc.find("target"); // 执行事件时的精确实例。
    const auto* memoryTarget = plan.find("target"); // 读取请求时冻结的精确实例。
    if (!executionTarget || !memoryTarget || !SameProcess(*executionTarget, *memoryTarget)) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryProcess");
    }

    const auto* context = plan.find("readContext"); // 旧live格式不具备停点对应关系。
    bool held = false; // 两次读取检查均持有同一事件的已存声明。
    if (!context || !IsString(*context, "source", "held-event") ||
        !context->find("heldAtBothChecks") || !context->find("heldAtBothChecks")->tryGetBool(held) || !held) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryHeldContext");
    }
    const auto* before = context->find("before"); // 读取前从原owner回读的历史令牌。
    const auto* after = context->find("after"); // 读取后从同一owner回读的历史令牌。
    if (!before || !after || !SameStop(doc, *executionTarget, *before) ||
        !SameStop(doc, *executionTarget, *after)) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryStop");
    }

    NativeExecutionMemoryMatch staged; // 所有匹配和字节选择完成前不发布结果。
    if (!GetString(doc, "observation", staged.observation) ||
        (staged.observation != "execution-enter-attempt" && staged.observation != "instruction-completed") ||
        !GetNumber(doc, "instructionAddress", staged.instructionAddress) || !staged.instructionAddress) {
        return Failure(ProjectError::InvalidArgument, "nativeMemoryExecution");
    }
    const ks::cli::action_analyze::memory::Range range{staged.instructionAddress, byteCount}; // 允许跨页但不补缺口。
    if (const auto selected = SelectMemorySnapshotBytes(memory, range, staged.bytes); !selected) {
        return selected;
    }
    for (const auto& page : memory.pages) {
        // Reader已经核验页范围无溢出及页序；这里只保留实际相交的原始记录坐标。
        if (page.range.base < range.base + range.length && page.range.base + page.range.length > range.base) {
            staged.memoryRecordSequences.push_back(page.sequence);
        }
    }
    staged.heldAtBothChecks = true; // 全部身份、前后停点及所选字节通过后才发布成功语义。
    out = std::move(staged);
    return {};
}

} // namespace Ksword::ActionAnalyze::Detection
