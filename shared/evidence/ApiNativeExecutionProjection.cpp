#include "ApiNativeExecutionProjection.h"
#include "../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include <filesystem>
#include <algorithm>

namespace Ksword::ActionAnalyze {
// 只读适配器借用项目已固定的目录，与 API/网络检查点的访问规则一致。
struct ProjectNativeExecutionAccess {
    static const ProjectStorage::Directory* Root(const ProjectDocument& project)
    {
        return project.RootForRead(); // 仅供当前后台读取调用，不转交 UI。
    }
};
}

namespace Ksword::Evidence {
namespace {

// 输入真实 API 引用，输出无损坐标；独立保留 sourceSequence，不冒充 raw 序号。
JsonValue Reference(const ActionAnalyze::Detection::EvidenceRef& reference)
{
    return JsonValue::makeObject({
        {"projectId", JsonValue::makeString(reference.projectId)},
        {"sampleId", JsonValue::makeString(reference.sampleId)},
        {"sourceId", JsonValue::makeString(reference.sourceId)},
        {"sourceEpoch", JsonValue::makeString(reference.sourceEpoch)},
        {"segmentOrdinal", JsonValue::makeString(std::to_string(reference.raw->segmentOrdinal))},
        {"recordSequence", JsonValue::makeString(std::to_string(reference.raw->sequence))},
        {"sourceSequence", reference.sourceSequence
            ? JsonValue::makeString(std::to_string(*reference.sourceSequence)) : JsonValue{}}
    });
}

// 后台读取传入项目、采样及取消来源；count输出从1连续的实际段数，返回目录核对状态。
// 缺中间段不能当作成功空尾，取消由上层转换成独立Canceled状态。
ActionAnalyze::ProjectResult NativeSegmentCount(const ActionAnalyze::ProjectDocument& project,
    std::string_view sample, std::uint64_t& count, const std::function<bool()>& canceled)
{
    namespace storage = ActionAnalyze::ProjectStorage;
    count = 0;
    const auto* root = ActionAnalyze::ProjectNativeExecutionAccess::Root(project); // 本次后台固定的项目目录。
    if (!root)
    {
        return storage::Failure(ActionAnalyze::ProjectError::NotOpen, "nativeHistoryProject");
    }
    if (!storage::IsUuid(sample))
    {
        return storage::Failure(ActionAnalyze::ProjectError::InvalidArgument, "nativeHistorySample");
    }
    storage::Directory directory; // 枚举期间固定完整目录链，不使用 UI 提供的任意路径。
    const auto opened = storage::OpenDirectory(*root, {L"samples", storage::WideAscii(sample), L"raw-native"}, directory);
    if (opened.error == ActionAnalyze::ProjectError::NotFound)
    {
        return {};
    }
    if (!opened)
    {
        return opened;
    }
    std::error_code error; // 文件系统枚举错误，不能解释为零记录。
    std::filesystem::directory_iterator entry(directory.path, error), end;
    std::uint64_t maximum = 0; // 文件名对应的最高原生段号。
    if (error)
    {
        return storage::WinFailure("nativeHistoryDirectory", static_cast<DWORD>(error.value()));
    }
    for (; entry != end; entry.increment(error))
    {
        if (canceled && canceled())
        {
            return {}; // 由调用方发布取消态，不把取消解释为成功空链。
        }
        if (error)
        {
            break;
        }
        const auto name = entry->path().filename().wstring(); // 原生链只允许规范20位段名。
        if (name.size() != 27 || name.substr(20) != L".ksaseg")
        {
            return storage::Failure(ActionAnalyze::ProjectError::Corrupt, "nativeHistorySegmentName");
        }
        std::uint64_t ordinal = 0; // 溢出或非数字文件名不进入链。
        for (std::size_t index = 0; index < 20; ++index)
        {
            const auto digit = name[index]; // 当前规范十进制位。
            if (digit < L'0' || digit > L'9' || ordinal > (UINT64_MAX - (digit - L'0')) / 10)
            {
                return storage::Failure(ActionAnalyze::ProjectError::Corrupt, "nativeHistorySegmentName");
            }
            ordinal = ordinal * 10 + (digit - L'0');
        }
        if (!ordinal)
        {
            return storage::Failure(ActionAnalyze::ProjectError::Corrupt, "nativeHistorySegmentName");
        }
        maximum = (std::max)(maximum, ordinal);
        ++count;
    }
    if (error)
    {
        return storage::WinFailure("nativeHistoryDirectory", static_cast<DWORD>(error.value()));
    }
    return count == maximum ? ActionAnalyze::ProjectResult{} :
        storage::Failure(ActionAnalyze::ProjectError::Corrupt, "nativeHistorySegmentGap");
}
}

// 已有异步读任务传项目句柄；空目录为成功空链，缺段或损坏不发布局部匹配。
NativeExecutionHistory ReadNativeExecutionHistory(const ActionAnalyze::ProjectDocument& project,
    std::string_view sample, const std::function<bool()>& canceled)
{
    NativeExecutionHistory result; // 独立原生状态，不修改调用方 API 读回执。
    std::uint64_t count = 0; // 本轮固定目录中实际存在且连续的段数。
    if (canceled && canceled())
    {
        result.state = NativeHistoryState::Canceled;
        return result;
    }
    const auto directoryStatus = NativeSegmentCount(project, sample, count, canceled); // 目录扫描沿用同一取消来源。
    if (canceled && canceled())
    {
        result.state = NativeHistoryState::Canceled;
        return result;
    }
    if (!directoryStatus)
    {
        result.state = NativeHistoryState::Failed;
        result.problem = directoryStatus;
        return result;
    }
    std::optional<std::uint64_t> previous = 0; // 首段从原生链零水位开始。
    const auto limit = (std::min)(count, std::uint64_t{4096}); // 固定范围内按原 CLI 上限逐段核验。
    for (std::uint64_t ordinal = 1; ordinal <= limit; ++ordinal)
    {
        if (canceled && canceled())
        {
            result.state = NativeHistoryState::Canceled;
            result.records.clear();
            return result;
        }
        ActionAnalyze::ArchivedNativeExecution execution; // 当前待核验段，不提前加入输出。
        const auto status = ActionAnalyze::ReadNativeExecution(project, sample, ordinal, previous, execution);
        // 明确记录首个坏段；只在完整成功或明确限额时消费已验证的连续历史。
        if (!status)
        {
            result.state = NativeHistoryState::Failed;
            result.problem = status;
            result.failedOrdinal = ordinal;
            result.records.clear();
            return result;
        }
        previous = execution.end.lastSequence;
        result.records.push_back(std::move(execution));
    }
    if (canceled && canceled())
    {
        result.state = NativeHistoryState::Canceled;
        result.records.clear();
        return result;
    }
    result.state = count > limit ? NativeHistoryState::Limited : NativeHistoryState::Complete;
    result.failedOrdinal = count > limit ? limit + 1 : 0;
    return result;
}

// 输入已核验原生段及真实段号，生成没有API依赖的来源文档；保留完整绑定和寄存器。
NativeExecutionHistoryEntry NativeExecutionHistorySource(
    const ActionAnalyze::ArchivedNativeExecution& execution, std::uint64_t ordinal)
{
    const auto count = [](std::uint64_t value) { // 协议计数用十进制字符串保留64位精度。
        return JsonValue::makeString(std::to_string(value));
    };
    NativeExecutionHistoryEntry entry; // 当前独立历史叶的值，不拥有任何活owner。
    entry.nativeOrdinal = ordinal;
    entry.nativeSequence = execution.end.lastSequence;
    entry.nativeRecordOffset = execution.recordOffset;
    entry.nativeSha256 = execution.sha256;
    entry.sourceDocument = JsonValue::makeObject({
        {"kind", JsonValue::makeString("native-execution-history")},
        {"historical", JsonValue::makeBool(true)},
        {"nativeSegmentOrdinal", count(ordinal)},
        {"nativeRecordSequence", count(execution.end.lastSequence)},
        {"nativeRecordOffset", count(execution.recordOffset)},
        {"nativeBlockOrdinal", count(execution.blockOrdinal)},
        {"nativeEndOffset", count(execution.end.byteOffset)},
        {"nativeSha256", JsonValue::makeString(execution.sha256)},
        {"native", execution.document}
    });
    return entry;
}

// 三端在用户显式准备时调用；只消费原读端已核验的来源，旧档不补造私有绑定资格。
std::optional<NativeExecutionSiteDraft> PrepareNativeExecutionSiteDraft(const JsonValue& source, bool range)
{
    namespace storage = ActionAnalyze::ProjectStorage;
    const auto* native = source.find("native"); // 唯一原生文档，不从请求IP或下一RIP替代实际指令。
    if (!native || !ActionAnalyze::IsNativeExecutionDocument(*native))
    {
        return {};
    }
    const auto* target = native->find("target"); // 原进程强实例字段。
    const auto* binding = native->find("binding"); // v3保留的原停点绑定；v1/v2保持不可准备。
    const auto* pid = target ? target->find("pid") : nullptr; // PID使用原UInt形状。
    NativeExecutionSiteDraft draft; // 所有字段成功后才返回，不产生部分可执行草稿。
    std::uint64_t process = 0, module = 0, writeBytes = 0; // 原PID、模块基址及写关注宽度。
    std::uint64_t instruction = 0; // 原生真实指令起点，步进完成也不使用下一RIP。
    if (!binding || !pid || pid->type() != JsonType::UInt || !pid->tryGetU64(process) ||
        !process || process > UINT32_MAX || !storage::GetNumber(*target, "creationFileTime", draft.creationFileTime) ||
        !draft.creationFileTime || !storage::GetNumber(*binding, "moduleBase", module) || module ||
        !storage::GetNumber(*binding, "writeWatchBytes", writeBytes) || writeBytes ||
        !storage::GetNumber(*native, "instructionAddress", instruction) || !instruction ||
        !storage::GetString(*native, "projectId", draft.projectId) || !storage::IsUuid(draft.projectId) ||
        !storage::GetString(*native, "sampleId", draft.sampleId) || !storage::IsUuid(draft.sampleId) ||
        !storage::GetNumber(source, "nativeSegmentOrdinal", draft.nativeOrdinal) || !draft.nativeOrdinal ||
        !storage::GetString(source, "nativeSha256", draft.nativeSha256) || !storage::IsHash(draft.nativeSha256))
    {
        return {};
    }
    draft.pid = static_cast<std::uint32_t>(process);
    draft.address = instruction;
    if (range)
    {
        const auto* ranges = binding->find("executionRanges"); // 只使用该事件实际纳入的原范围。
        if (!ranges || !ranges->asArray())
        {
            return {};
        }
        bool found = false; // 没有包含实际指令的范围时不回退为单页或单地址。
        for (const auto& item : *ranges->asArray())
        {
            std::uint64_t base = 0, bytes = 0; // 每个原范围独立核对，不合并相邻分配。
            if (storage::GetNumber(item, "base", base) && storage::GetNumber(item, "bytes", bytes) &&
                base && bytes && base % 4096 == 0 && bytes % 4096 == 0 &&
                base <= UINT64_MAX - bytes && instruction >= base && instruction - base < bytes)
            {
                draft.address = base;
                draft.rangeBytes = bytes;
                found = true;
                break;
            }
        }
        if (!found)
        {
            return {};
        }
    }
    return draft;
}

// 保持原站点文件协议的UInt PID和无损十进制字符串；不输出任何旧控制令牌。
JsonValue NativeExecutionDraftSites(const NativeExecutionSiteDraft& draft)
{
    JsonObject site{{"pid", JsonValue::makeUInt(draft.pid)},
        {"creationFileTime", JsonValue::makeString(std::to_string(draft.creationFileTime))},
        {"address", JsonValue::makeString(std::to_string(draft.address))},
        {"rangeBytes", JsonValue::makeString(std::to_string(draft.rangeBytes))}}; // 原ReadSites四字段私有地址形状，零范围也须显式。
    return JsonValue::makeObject({{"schemaVersion", JsonValue::makeUInt(1)},
        {"sites", JsonValue::makeArray({JsonValue::makeObject(std::move(site))})}});
}

// 输出包含匹配类型、原包坐标和完整原生文档；历史来源不转换为活停点或放行票据。
JsonValue NativeExecutionSourceDocument(int kind, const ActionAnalyze::Detection::EvidenceRef* write,
    const ActionAnalyze::Detection::EvidenceRef& request,
    const ActionAnalyze::ArchivedNativeExecution& execution, std::uint64_t ordinal,
    const ActionAnalyze::Detection::ArchivedGraphRecord& requestRecord, std::optional<std::uint64_t> writeOffset,
    std::string_view mappingSha256)
{
    const auto count = [](std::uint64_t value) { return JsonValue::makeString(std::to_string(value)); }; // 无损计数。
    const char* kinds[]{"thread-create", "apc-queue", "thread-context", "section-map"}; // 稳定候选分类。
    const bool memoryRange = kind == 3 && requestRecord.apiMemoryLifecycle.has_value(); // kind3共用范围树，来源类型仍精确区分。
    JsonValue memory = JsonValue::makeNull(); // 非AAIM1关联不添加假输出。
    if (memoryRange)
    {
        const auto& fields = *requestRecord.apiMemoryLifecycle; // 核心已核对成功输出，仍保留请求和有效位供回查。
        memory = JsonValue::makeObject({{"operation", JsonValue::makeString(fields.operation == ApiMemoryOperation::Allocate ? "allocate" : "protect")},
            {"flags", count(fields.flags)}, {"targetPid", count(fields.targetPid)}, {"targetCreationFileTime", count(fields.targetCreationFileTime)},
            {"outputBase", count(fields.outputBase)}, {"outputBytes", count(fields.outputBytes)},
            {"requestedBase", (fields.flags & ApiMemoryRequestedBase) ? count(fields.requestedBase) : JsonValue{}},
            {"requestedBytes", (fields.flags & ApiMemoryRequestedBytes) ? count(fields.requestedBytes) : JsonValue{}},
            {"actorCreationFileTime", count(fields.actorCreationFileTime)}, {"pointerBits", count(fields.pointerBits)},
            {"inputProcessHandle", count(fields.inputProcessHandle)}, {"allocationType", count(fields.allocationType)},
            {"oldProtection", (fields.flags & ApiMemoryOldProtection) ? count(fields.oldProtection) : JsonValue{}},
            {"newProtection", count(fields.newProtection)}, {"enterQpc", count(fields.enterQpc)}, {"returnQpc", count(fields.returnQpc)}});
    }
    JsonValue entry = JsonValue::makeNull(); // 三类入口独立保留请求；没有写入也不借请求构造执行事实。
    if (const auto fields = ActionAnalyze::Detection::ReadNativeExecutionRequest(requestRecord))
    {
        const auto& context = requestRecord.apiContext; // AACT1可选请求寄存器，非原生实际现场。
        const auto& apc = requestRecord.apiApc; // AAAP1原参数，不表示已投递。
        const auto inputHandle = fields->kind == 0 ? requestRecord.apiInjection->inputHandle :
            fields->kind == 1 ? apc->inputThreadHandle : context->inputThreadHandle; // 仅显示原位模式，不作对象身份。
        entry = JsonValue::makeObject({
            {"operation", JsonValue::makeString(requestRecord.operation)},
            {"flags", count(fields->flags)},
            {"actorPid", count(fields->actorPid)},
            {"actorCreationFileTime", count(fields->actorCreationFileTime)},
            {"targetPid", count(fields->targetPid)},
            {"targetCreationFileTime", count(fields->targetCreationFileTime)},
            {"tid", count(fields->tid)},
            {"threadCreationFileTime", count(fields->threadCreationFileTime)},
            {"requestedAddress", count(fields->requestedAddress)},
            {"inputHandle", count(inputHandle)},
            {"enterQpc", count(fields->enterQpc)},
            {"returnQpc", count(fields->returnQpc)},
            {"contextFlags", context ? count(context->contextFlags) : JsonValue{}},
            {"contextArchitecture", context ? count(context->contextArchitecture) : JsonValue{}},
            {"requestedSp", context ? count(context->requestedSp) : JsonValue{}},
            {"inputContextAddress", context ? count(context->inputContextAddress) : JsonValue{}},
            {"argument1", apc ? count(apc->argument1) : JsonValue{}},
            {"argument2", apc ? count(apc->argument2) : JsonValue{}},
            {"argument3", apc ? count(apc->argument3) : JsonValue{}}
        });
    }
    return JsonValue::makeObject({
        {"kind", JsonValue::makeString("api-native-consistency-candidate")},
        {"candidateType", JsonValue::makeString(memoryRange ? "memory-range" : kinds[kind])},
        {"memoryRange", std::move(memory)},
        {"entryRequest", std::move(entry)},
        {"writeObserved", JsonValue::makeBool(write != nullptr)},
        {"write", write ? Reference(*write) : JsonValue{}},
        {"writeRecordOffset", writeOffset ? count(*writeOffset) : JsonValue{}},
        {"request", Reference(request)},
        {"requestRecordOffset", count(requestRecord.recordOffset)},
        {"mappingSha256", mappingSha256.empty() ? JsonValue{} : JsonValue::makeString(std::string(mappingSha256))},
        {"requestSha256", mappingSha256.empty() ? JsonValue{} : JsonValue::makeString(std::string(mappingSha256))},
        {"nativeSegmentOrdinal", count(ordinal)},
        {"nativeRecordSequence", count(execution.end.lastSequence)},
        {"nativeRecordOffset", count(execution.recordOffset)},
        {"nativeBlockOrdinal", count(execution.blockOrdinal)},
        {"nativeEndOffset", count(execution.end.byteOffset)},
        {"nativeSha256", JsonValue::makeString(execution.sha256)},
        {"native", execution.document},
        {"commonClockVerified", JsonValue::makeBool(false)},
        {"sourceAuthenticated", JsonValue::makeBool(false)},
        {"regionVersionVerified", JsonValue::makeBool(false)},
        {"causalityConfirmed", JsonValue::makeBool(false)}
    });
}

} // namespace Ksword::Evidence
