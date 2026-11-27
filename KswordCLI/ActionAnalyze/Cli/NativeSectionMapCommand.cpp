#include "NativeSectionMapCommand.h"

#include "NativeExecutionJournal.h"
#include "../Detection/NativeSectionMapAssociation.h"
#include "../Detection/NativeTransferAssociation.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"

#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
namespace detection = project::Detection;

// Failed：把 status 原项目错误转换为退出码 3；失败不附带已构造的局部匹配页。
Result Failed(const project::ProjectResult& status)
{
    return {3, Json::object({
        {L"error", Json::string(storage::WideAscii(project::ProjectErrorName(status.error)))},
        {L"stage", Json::string(storage::WideAscii(status.detail))},
        {L"win32Error", Json::number(status.nativeError)}
    }), {}};
}

// Sample：从 args 读取规范 ASCII 采样 UUID；非法输入抛参数错误，不替换为默认采样。
std::string Sample(const Args& args)
{
    std::string sample; // 要传给项目只读端的规范采样 ID。
    for (const auto character : args.require(L"--sample")) { // 原命令行的当前宽字符。
        if (character > 127) {
            throw std::invalid_argument("--sample must be a canonical UUID");
        }
        sample.push_back(static_cast<char>(character));
    }
    if (!storage::IsUuid(sample)) {
        throw std::invalid_argument("--sample must be a canonical UUID");
    }
    return sample;
}

// Reference：把 source 的原 API 坐标、摘要及文件位置 location 输出，不省略来源代次。
// 调用方只传核心成功匹配且已核对 raw 坐标的 source；sha256 来自已核验 API 页。
Json Reference(const detection::EvidenceRef& source, std::string_view sha256,
    const detection::ArchivedGraphRecord& location)
{
    return Json::object({
        {L"stream", Json::string(L"raw")},
        {L"projectId", Json::string(storage::WideAscii(source.projectId))},
        {L"sampleId", Json::string(storage::WideAscii(source.sampleId))},
        {L"segmentOrdinal", Json::count(source.raw->segmentOrdinal)},
        {L"recordSequence", Json::count(source.raw->sequence)},
        {L"recordOffset", Json::count(location.recordOffset)},
        {L"blockOrdinal", Json::count(location.blockOrdinal)},
        {L"sha256", Json::string(storage::WideAscii(sha256))},
        {L"sourceId", Json::string(storage::WideAscii(source.sourceId))},
        {L"sourceEpoch", Json::string(storage::WideAscii(source.sourceEpoch))},
        {L"sourceSequence", source.sourceSequence ? Json::count(*source.sourceSequence) : Json{}}
    });
}

// Association：投影 match 及其原 location/execution 两路坐标；请求有效位缺失时保持 null。
// 原 observation、SHA 和时钟保留，不生成写入或节别名关系，也不推断跨源时间先后。
Json Association(const detection::NativeSectionMapAssociation& match,
    const detection::ArchivedGraphRecord& location, const project::ArchivedNativeExecution& execution)
{
    const auto& fields = match.fields; // 核心已经核对的原 AASM1 请求和实际映射输出。
    return Json::object({
        {L"kind", Json::string(L"native-section-map-consistency-candidate")},
        {L"observation", Json::string(storage::WideAscii(match.observation))},
        {L"mapping", Reference(match.mapping, match.mappingSha256, location)},
        {L"native", Json::object({
            {L"stream", Json::string(L"raw-native")},
            {L"segmentOrdinal", Json::count(match.nativeSegmentOrdinal)},
            {L"recordSequence", Json::count(match.nativeRecordSequence)},
            {L"sha256", Json::string(storage::WideAscii(match.nativeSha256))},
            {L"endOffset", Json::count(execution.end.byteOffset)},
            {L"blockOrdinal", Json::count(execution.end.blockOrdinal)}
        })},
        {L"actorPid", Json::number(match.actorPid)},
        {L"actorCreationFileTime", Json::count(fields.actorCreationFileTime)},
        {L"targetPid", Json::number(static_cast<std::uint32_t>(fields.targetPid))},
        {L"targetCreationFileTime", Json::count(fields.targetCreationFileTime)},
        {L"tid", Json::number(match.tid)},
        {L"threadCreationFileTime", Json::count(match.threadCreationFileTime)},
        {L"mappedBase", Json::count(fields.mappedBase)},
        {L"mappedBytes", Json::count(fields.mappedBytes)},
        {L"requestedBase", (fields.flags & Ksword::Evidence::ApiSectionMapRequestedBase)
            ? Json::count(fields.requestedBase) : Json{}},
        {L"requestedBytes", (fields.flags & Ksword::Evidence::ApiSectionMapRequestedBytes)
            ? Json::count(fields.requestedBytes) : Json{}},
        {L"sectionOffset", (fields.flags & Ksword::Evidence::ApiSectionMapSectionOffset)
            ? Json::count(fields.sectionOffset) : Json{}},
        {L"inputSectionHandle", Json::count(fields.inputSectionHandle)},
        {L"inputProcessHandle", Json::count(fields.inputProcessHandle)},
        {L"requestedProtection", Json::count(fields.requestedProtection)},
        {L"mappingFlags", Json::count(fields.flags)},
        {L"mappingOutcome", Json::string(L"accepted")},
        {L"instructionAddress", Json::count(match.instructionAddress)},
        {L"apiClock", Json::object({
            {L"mapEnterQpc", Json::count(fields.enterQpc)},
            {L"mapReturnQpc", Json::count(fields.returnQpc)},
            {L"qpcFrequency", Json{}}
        })},
        {L"nativeClock", Json::object({
            {L"observedQpc", match.observedQpc ? Json::count(*match.observedQpc) : Json{}},
            {L"qpcFrequency", match.nativeQpcFrequency ? Json::count(*match.nativeQpcFrequency) : Json{}}
        })},
        {L"sourceAuthenticated", Json::boolean(match.sourceAuthenticated)},
        {L"regionVersionVerified", Json::boolean(match.regionVersionVerified)},
        {L"causalityConfirmed", Json::boolean(match.causalityConfirmed)},
        {L"commonClockVerified", Json::boolean(match.commonClockVerified)},
        {L"writeObserved", Json::boolean(match.writeObserved)},
        {L"aliasPropagationVerified", Json::boolean(match.aliasPropagationVerified)}
    });
}

// Map：args 明确选择项目、采样及两路段号；完整核验两条链后才输出本 API 观察页中的候选。
// 没有匹配返回成功空页；读链/坐标失败整体退出 3，不返回部分候选，不访问任何目标进程。
enum class NativeMatchMode { SectionMap, MemoryRange, EntryRequest }; // 保持三个命令各自的输出集合。

Result Map(const Args& args, NativeMatchMode mode = NativeMatchMode::SectionMap)
{
    const bool memoryRange = mode == NativeMatchMode::MemoryRange; // 本次显式选择的独立范围查询。
    const bool entryRequest = mode == NativeMatchMode::EntryRequest; // 无前置写入的精确入口查询。
    const auto sample = Sample(args); // 本次明确选择的采样 UUID。
    const auto apiOrdinal = args.integer(L"--api-ordinal"); // API 链目标段号。
    const auto nativeOrdinal = args.integer(L"--native-ordinal"); // 原生链目标段号。
    const auto after = args.has(L"--after") ? args.integer(L"--after") : 0; // 原 API 记录序号游标。
    const auto limit = args.has(L"--limit") ? args.integer(L"--limit")
        : detection::kArchivedGraphDefaultRows; // 本页 API 观察预算，默认 100。
    if (!apiOrdinal || apiOrdinal > detection::kArchivedGraphMaxApiSegments ||
        !nativeOrdinal || nativeOrdinal > 4096 || !limit || limit > detection::kArchivedGraphMaxRows) {
        throw std::invalid_argument("Require --api-ordinal 1..128, --native-ordinal 1..4096 and --limit 1..4096");
    }

    project::ProjectDocument document; // 只读打开的项目文档，不获取活会话控制权。
    if (const auto status = document.Open(args.require(L"--project")); !status) { // 项目打开结果。
        return Failed(status);
    }
    detection::ArchivedGraphPage page; // 首段连续核验后的当前 API 观察页及其原始坐标。
    const detection::ArchivedGraphRequest request{
        sample, apiOrdinal, after, static_cast<std::size_t>(limit), {}
    }; // 使用原 API 观察游标，不将零匹配误作无下一页。
    if (const auto status = detection::ReadArchivedEvidenceGraph(document, request, page); !status) { // API 链读取结果。
        return Failed(status);
    }
    if (page.source != detection::ArchivedGraphSource::ImportedApi &&
        page.source != detection::ArchivedGraphSource::CommittedApiFollow) {
        return Failed(storage::Failure(project::ProjectError::Unsupported, "nativeSectionMapApiSource"));
    }
    project::ArchivedNativeExecution execution; // 按原生链从首段核验的历史执行证据。
    if (const auto status = ReadNativeExecutionChain(document, sample, nativeOrdinal, execution); !status) { // 原生链读取结果。
        return Failed(status);
    }
    if (page.records.size() != page.graph.observations.size()) {
        return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeSectionMapObservationCoordinates"));
    }

    std::vector<Json> candidates; // 只暂存当前有界页的候选，所有读链成功后才能发布。
    for (std::size_t index = 0; index < page.records.size(); ++index) { // 当前 API 观察的同行索引。
        const auto& mapping = page.records[index]; // 当前页的原映射记录或其它 API 记录。
        if (entryRequest ? !detection::ReadNativeExecutionRequest(mapping) :
            memoryRange ? !mapping.apiMemoryLifecycle : !mapping.apiSectionMap) {
            continue;
        }
        const auto& observation = page.graph.observations[index]; // 与原记录严格同行的来源定位。
        if (!observation.evidence || !observation.evidence->raw ||
            !detection::HasArchivedApiLocation(page.graph.scope, *observation.evidence) ||
            observation.evidence->raw->segmentOrdinal != mapping.segmentOrdinal ||
            observation.evidence->raw->sequence != mapping.recordSequence) {
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeSectionMapMappingCoordinate"));
        }
        if (entryRequest)
        {
            const auto match = detection::AssociateNativeExecutionRequest(page.graph.scope,
                *observation.evidence, mapping, page.sha256, execution, nativeOrdinal); // 强实例和入口精确相等。
            if (!match)
            {
                continue;
            }
            const wchar_t* kinds[]{L"thread-create", L"apc-queue", L"thread-context"}; // 与桌面根分类相同。
            const auto& context = mapping.apiContext; // 原请求上下文，仅原样展示。
            const auto& apc = mapping.apiApc; // 原APC参数，不推定已投递。
            std::string observedKind; // 保存原生实际观察种类，不统一改为“执行完成”。
            storage::GetString(execution.document, "observation", observedKind);
            std::uint64_t instructionAddress = 0; // 从原生文档读出真实指令起点，不以请求值填补。
            std::uint64_t nativeQpc = 0; // 原生原时钟，仅展示不跨源排序。
            std::uint64_t nativeFrequency = 0; // 原生档案报告的时钟频率。
            storage::GetNumber(execution.document, "instructionAddress", instructionAddress);
            const bool hasQpc = storage::GetNumber(execution.document, "observedQpc", nativeQpc);
            const bool hasFrequency = storage::GetNumber(execution.document, "qpcFrequency", nativeFrequency);
            const auto inputHandle = match->kind == 0 ? mapping.apiInjection->inputHandle :
                match->kind == 1 ? apc->inputThreadHandle : context->inputThreadHandle; // 原句柄位模式，不作对象身份。
            candidates.push_back(Json::object({
                {L"kind", Json::string(L"native-entry-request-consistency-candidate")},
                {L"candidateType", Json::string(kinds[match->kind])},
                {L"operation", Json::string(storage::WideAscii(mapping.operation))},
                {L"request", Reference(*observation.evidence, page.sha256, mapping)},
                {L"nativeSegmentOrdinal", Json::count(nativeOrdinal)},
                {L"nativeRecordSequence", Json::count(execution.end.lastSequence)},
                {L"nativeRecordOffset", Json::count(execution.recordOffset)},
                {L"nativeBlockOrdinal", Json::count(execution.blockOrdinal)},
                {L"nativeEndOffset", Json::count(execution.end.byteOffset)},
                {L"nativeSha256", Json::string(storage::WideAscii(execution.sha256))},
                {L"observation", Json::string(storage::WideAscii(observedKind))},
                {L"actorPid", Json::number(match->actorPid)},
                {L"actorCreationFileTime", Json::count(match->actorCreationFileTime)},
                {L"targetPid", Json::number(match->targetPid)},
                {L"targetCreationFileTime", Json::count(match->targetCreationFileTime)},
                {L"tid", Json::number(match->tid)},
                {L"threadCreationFileTime", Json::count(match->threadCreationFileTime)},
                {L"flags", Json::count(match->flags)},
                {L"requestedAddress", Json::count(match->requestedAddress)},
                {L"instructionAddress", Json::count(instructionAddress)},
                {L"inputHandle", Json::count(inputHandle)},
                {L"apiEnterQpc", Json::count(match->enterQpc)},
                {L"apiReturnQpc", Json::count(match->returnQpc)},
                {L"nativeObservedQpc", hasQpc ? Json::count(nativeQpc) : Json{}},
                {L"nativeQpcFrequency", hasFrequency ? Json::count(nativeFrequency) : Json{}},
                {L"contextFlags", context ? Json::count(context->contextFlags) : Json{}},
                {L"contextArchitecture", context ? Json::count(context->contextArchitecture) : Json{}},
                {L"requestedSp", context ? Json::count(context->requestedSp) : Json{}},
                {L"argument1", apc ? Json::count(apc->argument1) : Json{}},
                {L"argument2", apc ? Json::count(apc->argument2) : Json{}},
                {L"argument3", apc ? Json::count(apc->argument3) : Json{}},
                {L"reserveHandle", apc ? Json::count(apc->reserveHandle) : Json{}},
                {L"queueFlags", apc && (apc->flags & Ksword::Evidence::ApiApcQueueFlags) ? Json::count(apc->queueFlags) : Json{}},
                {L"writeObserved", Json::boolean(false)},
                {L"commonClockVerified", Json::boolean(false)},
                {L"sourceAuthenticated", Json::boolean(false)},
                {L"regionVersionVerified", Json::boolean(false)},
                {L"causalityConfirmed", Json::boolean(false)}
            }));
        }
        else if (memoryRange)
        {
            const auto match = detection::AssociateNativeMemoryRange(page.graph.scope, *observation.evidence,
                mapping, page.sha256, execution, nativeOrdinal); // AAIM1独立核对，不改写原节映射命令语义。
            if (!match)
            {
                continue;
            }
            const auto& fields = match->fields; // 已核验的实际输出及有效位，所有64位数仍使用无损字符串。
            std::uint64_t nativeQpc = 0, nativeFrequency = 0; // 原生时钟只按原值保存，不与API时钟排序。
            const bool hasQpc = storage::GetNumber(execution.document, "observedQpc", nativeQpc);
            const bool hasFrequency = storage::GetNumber(execution.document, "qpcFrequency", nativeFrequency);
            candidates.push_back(Json::object({
                {L"kind", Json::string(L"native-memory-range-consistency-candidate")},
                {L"operation", Json::string(fields.operation == Ksword::Evidence::ApiMemoryOperation::Allocate ? L"allocate" : L"protect")},
                {L"request", Reference(match->request, match->requestSha256, mapping)},
                {L"nativeSegmentOrdinal", Json::count(nativeOrdinal)}, {L"nativeRecordSequence", Json::count(execution.end.lastSequence)},
                {L"nativeRecordOffset", Json::count(execution.recordOffset)}, {L"nativeSha256", Json::string(storage::WideAscii(execution.sha256))},
                {L"targetPid", Json::number(static_cast<std::uint32_t>(fields.targetPid))},
                {L"targetCreationFileTime", Json::count(fields.targetCreationFileTime)},
                {L"tid", Json::number(match->tid)}, {L"threadCreationFileTime", Json::count(match->threadCreationFileTime)},
                {L"outputBase", Json::count(fields.outputBase)}, {L"outputBytes", Json::count(fields.outputBytes)},
                {L"requestedBase", (fields.flags & Ksword::Evidence::ApiMemoryRequestedBase) ? Json::count(fields.requestedBase) : Json{}},
                {L"requestedBytes", (fields.flags & Ksword::Evidence::ApiMemoryRequestedBytes) ? Json::count(fields.requestedBytes) : Json{}},
                {L"flags", Json::count(fields.flags)}, {L"newProtection", Json::count(fields.newProtection)},
                {L"actorPid", Json::number(*mapping.headerPid)}, {L"actorCreationFileTime", Json::count(fields.actorCreationFileTime)},
                {L"pointerBits", Json::count(fields.pointerBits)}, {L"inputProcessHandle", Json::count(fields.inputProcessHandle)},
                {L"allocationType", Json::count(fields.allocationType)},
                {L"oldProtection", (fields.flags & Ksword::Evidence::ApiMemoryOldProtection) ? Json::count(fields.oldProtection) : Json{}},
                {L"instructionAddress", Json::count(match->instructionAddress)}, {L"observation", Json::string(storage::WideAscii(match->observation))},
                {L"apiEnterQpc", Json::count(fields.enterQpc)}, {L"apiReturnQpc", Json::count(fields.returnQpc)},
                {L"nativeObservedQpc", hasQpc ? Json::count(nativeQpc) : Json{}},
                {L"nativeQpcFrequency", hasFrequency ? Json::count(nativeFrequency) : Json{}},
                {L"sourceAuthenticated", Json::boolean(false)}, {L"regionVersionVerified", Json::boolean(false)},
                {L"causalityConfirmed", Json::boolean(false)}, {L"commonClockVerified", Json::boolean(false)}, {L"writeObserved", Json::boolean(false)}}));
        }
        else
        {
            const auto match = detection::AssociateNativeSectionMap(
                page.graph.scope, *observation.evidence, mapping, page.sha256, execution, nativeOrdinal); // 原映射路径保持原条件。
            if (match)
            {
                candidates.push_back(Association(*match, mapping, execution));
            }
        }
    }
    return {0, Json::object({
        {L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))},
        {L"historical", Json::boolean(true)},
        {L"apiOrdinal", Json::count(apiOrdinal)},
        {L"nativeOrdinal", Json::count(nativeOrdinal)},
        {L"apiSegmentVerified", Json::boolean(true)},
        {L"nativeSegmentVerified", Json::boolean(true)},
        {L"apiSha256", Json::string(storage::WideAscii(page.sha256))},
        {L"nativeSha256", Json::string(storage::WideAscii(execution.sha256))},
        {L"after", Json::count(after)},
        {L"limit", Json::count(limit)},
        {L"nextAfter", page.nextAfterSequence ? Json::count(*page.nextAfterSequence) : Json{}},
        {L"apiObservationCount", Json::count(page.observationCount)},
        {L"retainedApiObservations", Json::count(page.records.size())},
        {L"candidateCount", Json::count(candidates.size())},
        {L"candidates", Json::array(candidates)},
        {L"sourceAuthenticated", Json::boolean(false)},
        {L"regionVersionVerified", Json::boolean(false)},
        {L"causalityConfirmed", Json::boolean(false)},
        {L"commonClockVerified", Json::boolean(false)},
        {L"writeObserved", Json::boolean(false)},
        {L"aliasPropagationVerified", Json::boolean(false)},
        {L"limitations", Json::string(entryRequest
            ? L"Historical cross-process request/native exact thread-instance and entry-address consistency, with no write prerequisite. Request acceptance does not establish APC delivery, applied context, causality, region version or cross-source time ordering. Original entry attempts and completed instructions remain distinct."
            : memoryRange
            ? L"Historical successful Allocate/Protect output-range/instruction consistency only. No current allocation, MEM_PRIVATE, region/content version, ordering, write or causality is established; Free/Unmap never yield candidates."
            : L"Historical mapping-range/instruction consistency only; no write is required or established. Section handle bits do not identify a section object or aliases. API/native clocks are preserved separately, without cross-source ordering or strong execution causality.")}
    }), {}};
}
} // namespace

// 将独立离线命令及内置 help 一起登记，统一注册入口由 Commands.cpp 所有者挂接。
void RegisterNativeSectionMapCommands()
{
    Command command; // 新命令的调度函数、参数语法及内置帮助元数据。
    command.path = L"analyze execution map";
    command.syntax = L"KswordCLI.exe analyze execution map --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]";
    command.summary = L"Compare one verified native instruction observation with archived accepted section mappings.";
    command.options = L"Requires --project, --sample, --api-ordinal (1..128) and --native-ordinal (1..4096). --after defaults to 0; --limit defaults to 100 (max 4096 API observations).";
    command.notes = L"Verifies both chains from ordinal 1. Accepts only NtMapViewOfSection Accepted records with actor/target creation identity, target stability and actual mapped base/bytes. Matches target PID/creation FILETIME and actual instructionAddress in the overflow-checked half-open mapping range. Preserves mapping/native coordinates, hashes, observation and separate original clocks. Does not require or establish writes, section aliases, common clock, region version, source authentication or execution causality; all six corresponding flags remain false. Empty matches return a successful empty candidates page and the original API nextAfter cursor. Any chain read failure fails the entire query without partial candidates. Reads archives only; no process access or live control.";
    command.run = [](const Args& args) { return Map(args); }; // 旧命令只查询节映射，不因新增AAIM1范围改变输出集合。
    addCommand(std::move(command));

    Command memory; // 新增入口复用同一分页及链读取，只切换共享AAIM1关联核心。
    memory.path = L"analyze execution memory-range";
    memory.syntax = L"KswordCLI.exe analyze execution memory-range --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]";
    memory.summary = L"Compare a verified native instruction observation with successful Allocate/Protect output ranges.";
    memory.options = L"Requires --project, --sample, --api-ordinal (1..128), --native-ordinal (1..4096). --after defaults to 0; --limit defaults to 100 (max 4096 API observations).";
    memory.notes = L"Verifies both chains from ordinal 1. Requires AAIM1 success, actor identity, stable target PID/creation FILETIME, actual output base/bytes, and native instructionAddress inside that half-open range. Free/Unmap and failed or incomplete output do not match. Keeps both source coordinates, hashes and original clocks; does not prove ordering, writes, current allocation, MEM_PRIVATE, region version or causality. Empty matches retain the original API nextAfter cursor. Archive-only; no process access or live control. Qt/Light expose the same matcher in the memory-range execution tree.";
    memory.run = [](const Args& args) { return Map(args, NativeMatchMode::MemoryRange); };
    addCommand(std::move(memory));

    Command entry; // 原生入口查询复用原双链读取及分页，不改写已有transfer/apc/context命令。
    entry.path = L"analyze execution entry";
    entry.syntax = L"KswordCLI.exe analyze execution entry --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]";
    entry.summary = L"Compare cross-process creation, APC or context requests with a native thread/entry observation without requiring a write.";
    entry.options = L"Requires --project, --sample, --api-ordinal (1..128), --native-ordinal (1..4096). --after defaults to 0; --limit defaults to 100 (max 4096 API observations).";
    entry.notes = L"Verifies both archive chains from ordinal 1. Requires successful AAIP1 CreateRemoteThread/CreateRemoteThreadEx/NtCreateThreadEx, accepted AAAP1 QueueUserAPC/QueueUserAPC2/NtQueueApcThread/NtQueueApcThreadEx, or accepted AMD64 CONTROL AACT1 SetThreadContext/NtSetContextThread. Actor/target identities and stable target/thread FILETIMEs must be complete. Matches exact target process, thread instance and native instructionAddress to the requested entry. Does not require or establish a preceding write, APC delivery, applied context, causality, region version, source authentication or cross-source ordering. Empty matches preserve API nextAfter. Archive-only; never attaches, pauses or continues targets. Qt/Light use the same matcher in their existing native consistency trees.";
    entry.run = [](const Args& args) { return Map(args, NativeMatchMode::EntryRequest); };
    addCommand(std::move(entry));
}

} // namespace ks::cli::action_analyze
