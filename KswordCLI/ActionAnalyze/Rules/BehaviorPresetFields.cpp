#include "BehaviorPresetFields.h"

#include <algorithm>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

// 不登记未投影的目标对象、执行或关联字段；缺值由解释器保留 NotCollected。
constexpr FieldBinding Catalog[] = {
    {"api.family", FieldType::Text, Phase::Observation},
    {"api.name", FieldType::Text, Phase::Observation},
    {"result.returned", FieldType::Bool, Phase::Observation},
    {"result.win32Status", FieldType::U64, Phase::Observation},
    {"evidence.format", FieldType::Text, Phase::Observation},
    {"evidence.phase", FieldType::Text, Phase::Observation},
    {"result.succeeded", FieldType::Bool, Phase::Observation},
    // 进程和线程创建代次来自协议有效位，不能由读取器当前进程补齐。
    {"actor.pid", FieldType::U64, Phase::Observation},
    {"actor.creationFileTime", FieldType::U64, Phase::Observation},
    {"target.pid", FieldType::U64, Phase::Observation},
    {"target.creationFileTime", FieldType::U64, Phase::Observation},
    {"target.stable", FieldType::Bool, Phase::Observation},
    {"target.tid", FieldType::U64, Phase::Observation},
    {"target.threadCreationFileTime", FieldType::U64, Phase::Observation},
    {"thread.previousSuspendCount", FieldType::U64, Phase::Observation}, // 仅ResumeThread成功返回的旧计数，不是当前线程状态。
    // 内存字段保留原请求／返回分工，不暴露“执行成功”派生字段。
    {"memory.operation", FieldType::U64, Phase::Observation},
    {"memory.newProtection", FieldType::U64, Phase::Observation},
    {"memory.oldProtection", FieldType::U64, Phase::Observation},
    {"memory.outputBase", FieldType::U64, Phase::Observation},
    {"memory.outputBytes", FieldType::U64, Phase::Observation},
    {"memory.allocationType", FieldType::U64, Phase::Observation},
    // APC/context 的地址始终为请求值；map 的输出只在采到时发布。
    {"apc.requestedRoutine", FieldType::U64, Phase::Observation},
    {"context.requestedIp", FieldType::U64, Phase::Observation},
    {"context.requestedSp", FieldType::U64, Phase::Observation},
    {"map.requestedProtection", FieldType::U64, Phase::Observation},
    {"map.outputBase", FieldType::U64, Phase::Observation},
    {"map.outputBytes", FieldType::U64, Phase::Observation},
    // 普通强类型调用只发布显式返回；错误码域不混称 Win32 LastError。
    {"result.returnBits", FieldType::U64, Phase::Observation},
    {"result.status", FieldType::U64, Phase::Observation},
    {"result.statusDomain", FieldType::Text, Phase::Observation},
    {"registry.key", FieldType::Text, Phase::Observation},
    {"registry.rootHandle", FieldType::U64, Phase::Observation},
    {"registry.subkey", FieldType::Text, Phase::Observation},
    {"registry.valueName", FieldType::Text, Phase::Observation},
    {"registry.valueNameLower", FieldType::Text, Phase::Observation},
    {"registry.path", FieldType::Text, Phase::Observation},
    {"registry.pathLower", FieldType::Text, Phase::Observation},
    // 参数仍区分请求文本与实际结果；精确匹配字段不采用宽松正则或当前系统补值。
    {"module.name", FieldType::Text, Phase::Observation},
    {"module.nameLower", FieldType::Text, Phase::Observation},
    {"system.informationClass", FieldType::U64, Phase::Observation},
    {"process.application", FieldType::Text, Phase::Observation},
    {"process.applicationBaseLower", FieldType::Text, Phase::Observation},
    {"process.commandLine", FieldType::Text, Phase::Observation},
    {"file.path", FieldType::Text, Phase::Observation},
    {"file.sourcePath", FieldType::Text, Phase::Observation},
    {"file.desiredAccess", FieldType::U64, Phase::Observation},
    {"file.creationDisposition", FieldType::U64, Phase::Observation},
    // 网络域名只来自当前调用；不将 WinHttpConnect 的句柄当作已建立 TCP 连接。
    {"service.name", FieldType::Text, Phase::Observation},
    {"service.nameLower", FieldType::Text, Phase::Observation},
    {"service.type", FieldType::U64, Phase::Observation},
    {"service.startType", FieldType::U64, Phase::Observation},
    {"service.binaryPath", FieldType::Text, Phase::Observation},
    {"network.host", FieldType::Text, Phase::Observation},
    {"network.hostLower", FieldType::Text, Phase::Observation},
    {"network.domainLower", FieldType::Text, Phase::Observation},
    {"network.port", FieldType::U64, Phase::Observation},
    {"network.method", FieldType::Text, Phase::Observation},
    {"network.object", FieldType::Text, Phase::Observation},
};

// 小型投影器仅添加确知字段；有效位缺失时不发布零值或 false。
class Projection {
public:
    std::vector<FieldSample> fields; // 本次行的拥有型字段容器，文本借用参数或常量。

    // 追加一个类型已确定的已知字段；id 和文本值由调用方保持生命周期。
    template<class T>
    void Add(std::string_view id, T value)
    {
        fields.push_back({id, Quality::Known, value});
    }

    // 四类协议的身份有效位布局相同，稳定结果和线程身份由各自协议单独添加。
    template<class T>
    void Identity(const T& value)
    {
        if (value.flags & 1u) {
            Add("actor.creationFileTime", value.actorCreationFileTime);
        }
        if (value.flags & 2u) {
            Add("target.pid", value.targetPid);
            Add("target.creationFileTime", value.targetCreationFileTime);
        }
    }

    // 仅已知原 API 返回才发布返回阶段；无此字段时不允许结果规则命中。
    void Outcome(std::string_view format, bool succeeded)
    {
        Add("evidence.format", format);
        Add("evidence.phase", std::string_view{"return"});
        Add("result.succeeded", succeeded);
    }
};

} // namespace

// 原包解码复用协议闭集；普通返回只走精确导出的 formatter 布局，不做摘要子串判断。
ApiPresetEvidence ReadApiPresetEvidence(const ks::winapi_monitor::ApiMonitorEventPacket& packet)
{
    ApiPresetEvidence result; // 整条观察拥有的独立协议值。
    if (!Evidence::ClassifyApiMonitorClue(packet)) {
        return result;
    }
    result.actorPid = packet.pid;
    result.memory = Evidence::ReadApiMemoryLifecycleFields(packet);
    result.apc = Evidence::ReadApiApcFields(packet);
    result.apcOutcome = Evidence::ApiApcCallOutcome(packet);
    result.context = Evidence::ReadApiContextFields(packet);
    result.contextOutcome = Evidence::ApiContextCallOutcome(packet);
    result.map = Evidence::ReadApiSectionMapFields(packet);
    result.mapOutcome = Evidence::ApiSectionMapCallOutcome(packet);
    result.behavior = ReadApiBehaviorObservation(packet);
    return result;
}

// 目录查询借用静态字段定义，不根据读端平台或当前数据行扩展类型。
std::span<const FieldBinding> ApiPresetBehaviorFields()
{
    return Catalog;
}

// 机器目录和编辑帮助可复用同一份来源边界；字符串均为静态存储。
std::string_view ApiPresetFieldSource(std::string_view id) noexcept
{
    if (id == "registry.pathLower") {
        return "Formatter-decoded HKLM/HKCU root plus subkey; ASCII case folding only; ordinary handles remain unknown; legacy text has no independent completeness flag.";
    }
    if (id.starts_with("registry.")) {
        return "Strict RegOpenKey/RegGetValue/RegSetKeyValue/RegQueryValueEx/RegSetValueEx formatter layout; no value data or handle-to-path inference.";
    }
    if (id.starts_with("module.")) {
        return "Strict GetModuleHandle or successful Module32 formatter layout; requested name or one returned entry, not a complete inventory.";
    }
    if (id.starts_with("system.")) {
        return "NtQuerySystemInformation input class; response structures and firmware contents are not projected.";
    }
    if (id == "thread.previousSuspendCount") {
        return "Successful ResumeThread DWORD return only; zero is valid, 0xffffffff is failure; NtResumeThread optional output and current suspend state are not inferred.";
    }
    if (id.starts_with("process.")) {
        return "Strict CreateProcess application/command-line layout; basename is from application argument, not executable identity.";
    }
    if (id.starts_with("file.")) {
        return "Strict CreateFile or CopyFile request layout; no current handle lookup, payload contents or durability inference.";
    }
    if (id.starts_with("service.")) {
        return "Strict CreateService/OpenService request layout and complete generated argument trailer; no running-state inference.";
    }
    if (id == "network.domainLower") {
        return "Decoded GetAddrInfo/WinHttpConnect/InternetConnect host with valid ASCII DNS labels; one trailing dot removed; IP literals excluded.";
    }
    if (id.starts_with("network.")) {
        return "Strict current-call network formatter and generated argument trailer; no cross-handle host attribution or transport success inference.";
    }
    if (id == "result.status" || id == "result.statusDomain" || id == "result.returnBits") {
        return "Explicit Strong API return marker; status follows the exact API contract; StatusUnknown omits status; GetAddrInfo uses its own return code.";
    }
        return "Validated packet/protocol fields or exact formatter layout; legacy text has no independent completeness flag; absent values remain NotCollected; single archived observation only.";
}

// 协议已由生产读侧核验；仍以原有效位区分已采零值与没有采到。
std::vector<FieldSample> ProjectApiPresetFields(std::string_view api, std::string_view family,
    std::optional<Evidence::ApiMonitorMemoryWriteReturn> returned, const ApiPresetEvidence& evidence)
{
    Projection output; // 此行的唯一字段来源。
    output.Add("api.family", family);
    output.Add("api.name", api);
    if (evidence.actorPid) {
        output.Add("actor.pid", static_cast<std::uint64_t>(evidence.actorPid));
    }
    if (returned) {
        output.Add("result.returned", returned->returned);
        output.Add("result.win32Status", static_cast<std::uint64_t>(returned->statusCode));
    }
    if (const auto& memory = evidence.memory; memory && memory->returnValid) {
        output.Outcome("AAIM1", memory->status >= 0);
        output.Identity(*memory);
        output.Add("memory.operation", static_cast<std::uint64_t>(memory->operation));
        if (memory->flags & Evidence::ApiMemoryTargetStable) {
            output.Add("target.stable", true);
        }
        if (memory->operation == Evidence::ApiMemoryOperation::Allocate || memory->operation == Evidence::ApiMemoryOperation::Protect) {
            output.Add("memory.newProtection", memory->newProtection);
        }
        if (memory->operation == Evidence::ApiMemoryOperation::Allocate) {
            output.Add("memory.allocationType", memory->allocationType);
        }
        if (memory->flags & Evidence::ApiMemoryOldProtection) {
            output.Add("memory.oldProtection", memory->oldProtection);
        }
        if (memory->flags & Evidence::ApiMemoryOutputBase) {
            output.Add("memory.outputBase", memory->outputBase);
        }
        if (memory->flags & Evidence::ApiMemoryOutputBytes) {
            output.Add("memory.outputBytes", memory->outputBytes);
        }
    } else if (const auto& apc = evidence.apc; apc && evidence.apcOutcome != Evidence::ApiApcQueueOutcome::Unknown) {
        output.Outcome("AAAP1", evidence.apcOutcome == Evidence::ApiApcQueueOutcome::Accepted);
        output.Identity(*apc);
        if (apc->flags & Evidence::ApiApcThreadIdentity) {
            output.Add("target.tid", apc->targetTid);
            output.Add("target.threadCreationFileTime", apc->targetThreadCreationFileTime);
        }
        if (apc->flags & Evidence::ApiApcTargetStable) {
            output.Add("target.stable", true);
        }
        if (apc->flags & Evidence::ApiApcRoutineAddress) {
            output.Add("apc.requestedRoutine", apc->routineAddress);
        }
    } else if (const auto& context = evidence.context; context && evidence.contextOutcome != Evidence::ApiContextOutcome::Unknown) {
        output.Outcome("AACT1", evidence.contextOutcome == Evidence::ApiContextOutcome::Accepted);
        output.Identity(*context);
        if (context->flags & Evidence::ApiContextThreadIdentity) {
            output.Add("target.tid", context->targetTid);
            output.Add("target.threadCreationFileTime", context->targetThreadCreationFileTime);
        }
        if (context->flags & Evidence::ApiContextTargetStable) {
            output.Add("target.stable", true);
        }
        if (context->flags & Evidence::ApiContextControlRegisters) {
            output.Add("context.requestedIp", context->requestedIp);
            output.Add("context.requestedSp", context->requestedSp);
        }
    } else if (const auto& map = evidence.map; map && evidence.mapOutcome != Evidence::ApiSectionMapOutcome::Unknown) {
        output.Outcome("AASM1", evidence.mapOutcome == Evidence::ApiSectionMapOutcome::Accepted);
        output.Identity(*map);
        output.Add("map.requestedProtection", map->requestedProtection);
        if (map->flags & Evidence::ApiSectionMapTargetStable) {
            output.Add("target.stable", true);
        }
        if (map->flags & Evidence::ApiSectionMapMappedBase) {
            output.Add("map.outputBase", map->mappedBase);
        }
        if (map->flags & Evidence::ApiSectionMapMappedBytes) {
            output.Add("map.outputBytes", map->mappedBytes);
        }
    } else if (const auto& behavior = evidence.behavior; behavior) {
        output.Outcome("api-typed-return-v1", behavior->succeeded);
        output.Add("result.returnBits", behavior->returnBits);
        output.Add("result.statusDomain", behavior->statusDomain);
        if (behavior->status) {
            output.Add("result.status", static_cast<std::uint64_t>(*behavior->status));
        }
        for (const auto& parameter : behavior->parameters) {
            if (const auto* number = std::get_if<std::uint64_t>(&parameter.value)) {
                output.Add(parameter.id, *number);
            } else {
                output.Add(parameter.id, std::string_view(std::get<std::string>(parameter.value)));
            }
        }
    }
    std::ranges::sort(output.fields, {}, &FieldSample::id);
    return std::move(output.fields);
}

} // namespace Ksword::ActionAnalyze::Rules
