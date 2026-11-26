#include "NativeExecutionCommand.h"

#include "NativeExecutionJournal.h"
#include "../Detection/NativeExecutionMemory.h"
#include "../Detection/NativeTransferAssociation.h"
#include "../Project/MemorySnapshotReader.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"
#include "../../../shared/evidence/ApiNativeExecutionProjection.h"

#include <algorithm>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
namespace detection = project::Detection;

Json Document(const JsonValue& value)
{
    const auto bytes = Ksword::Evidence::WriteJson(value);
    const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (!size) throw std::runtime_error("Invalid native execution document UTF-8");
    std::wstring wide(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), wide.data(), size))
        throw std::runtime_error("Invalid native execution document UTF-8");
    return {wide, wide};
}

Result Failed(const project::ProjectResult& status)
{
    return {3, Json::object({{L"error", Json::string(storage::WideAscii(project::ProjectErrorName(status.error)))},
        {L"stage", Json::string(storage::WideAscii(status.detail))}, {L"win32Error", Json::number(status.nativeError)}}), {}};
}

std::string Sample(const Args& args)
{
    std::string sample;
    for (const auto ch : args.require(L"--sample")) {
        if (ch > 127) throw std::invalid_argument("--sample must be a canonical UUID");
        sample.push_back(static_cast<char>(ch));
    }
    if (!storage::IsUuid(sample)) throw std::invalid_argument("--sample must be a canonical UUID");
    return sample;
}

Result Read(const Args& args)
{
    const auto sample = Sample(args);
    const auto ordinal = args.has(L"--ordinal") ? args.integer(L"--ordinal") : 1;
    if (!ordinal) throw std::invalid_argument("--ordinal must be a positive uint64");
    project::ProjectDocument document;
    if (const auto status = document.Open(args.require(L"--project")); !status) return Failed(status);
    project::ArchivedNativeExecution archived;
    if (const auto status = ReadNativeExecutionChain(document, sample, ordinal, archived); !status) return Failed(status);
    return {0, Json::object({{L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))}, {L"stream", Json::string(L"raw-native")},
        {L"ordinal", Json::count(ordinal)}, {L"segmentVerified", Json::boolean(true)},
        {L"sha256", Json::string(storage::WideAscii(archived.sha256))},
        {L"endOffset", Json::count(archived.end.byteOffset)}, {L"blockOrdinal", Json::count(archived.end.blockOrdinal)},
        {L"lastSequence", Json::count(archived.end.lastSequence)}, {L"historical", Json::boolean(true)},
        {L"document", Document(archived.document)}}), {}};
}

// 输入项目、采样和段号游标，分页列出原生观察摘要；完整原文沿execution read读取。
Result History(const Args& args)
{
    const auto sample = Sample(args); // 规范采样UUID，禁止把当前进程身份当采样身份。
    const auto after = args.has(L"--after") ? args.integer(L"--after") : 0; // 已消费的原生段号。
    const auto limit = args.has(L"--limit") ? args.integer(L"--limit") : 32; // 单页摘要数量。
    if (after > 4096 || !limit || limit > 128)
    {
        throw std::invalid_argument("--after must be 0..4096; --limit must be 1..128");
    }
    project::ProjectDocument document; // 当前命令独占只读项目，不启动任何实时会话。
    if (const auto status = document.Open(args.require(L"--project"), project::ProjectAccess::ReadOnly); !status)
    {
        return Failed(status);
    }
    project::SampleRecord frozen; // 空历史也必须属于已登记采样，随机UUID不冒充成功空结果。
    if (const auto status = document.ReadSample(sample, frozen); !status)
    {
        return Failed(status);
    }
    const auto history = Ksword::Evidence::ReadNativeExecutionHistory(document, sample); // 同桌面读取器核验整条受限链。
    if (history.state == Ksword::Evidence::NativeHistoryState::Failed)
    {
        return Failed(history.problem);
    }
    std::vector<Json> records; // 单页只保存摘要；不重复输出18寄存器和全部NX范围。
    auto nextAfter = after; // 空页不向前伪造游标。
    const auto end = (std::min)(static_cast<std::uint64_t>(history.records.size()), after + limit); // 本页真实上界。
    for (auto index = after; index < end; ++index)
    {
        const auto& record = history.records[static_cast<std::size_t>(index)]; // 从首段连续核验的历史记录。
        const auto source = Ksword::Evidence::NativeExecutionHistorySource(record, index + 1); // 与桌面叶项同源。
        auto fields = *source.sourceDocument.asObject(); // 复制来源坐标后只替换native为摘要，原记录不变。
        std::erase_if(fields, [](const auto& field) { return field.first == "native"; });
        for (const auto* name : {"observation", "target", "thread", "instructionAddress"})
        {
            const auto* value = record.document.find(name); // 旧档缺失字段仍为空，不推断或查当前PID。
            fields.emplace_back(name, value ? *value : JsonValue{});
        }
        records.push_back(Document(JsonValue::makeObject(std::move(fields))));
        nextAfter = index + 1;
    }
    return {0, Json::object({
        {L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))},
        {L"stream", Json::string(L"raw-native")}, {L"historical", Json::boolean(true)},
        {L"verifiedRecords", Json::count(history.records.size())},
        {L"historyLimited", Json::boolean(history.state == Ksword::Evidence::NativeHistoryState::Limited)},
        {L"firstUnreadOrdinal", Json::count(history.failedOrdinal)},
        {L"after", Json::count(after)}, {L"nextAfter", Json::count(nextAfter)},
        {L"hasMore", Json::boolean(nextAfter < history.records.size())},
        {L"records", Json::array(records)}}), {}};
}

// 两条独立 lane 各自从首段核验，不能从旧实时快照回退拼接证据。
project::ProjectResult ReadMemoryChain(const project::ProjectDocument& document,
    std::string_view sample, std::uint64_t ordinal, project::ArchivedMemorySnapshot& out)
{
    out = {};
    std::optional<std::uint64_t> previous = 0;
    for (std::uint64_t index = 1; index <= ordinal; ++index) {
        if (const auto status = project::ReadMemorySnapshot(document, sample, index, previous, out); !status) {
            out = {};
            return status;
        }
        previous = out.boundary.lastSequence;
    }
    return {};
}

std::wstring BytesHex(std::string_view bytes)
{
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(bytes.size() * 2);
    for (const unsigned char byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

Result ExecutionMemory(const Args& args)
{
    try {
        const auto sample = Sample(args);
        const auto nativeOrdinal = args.integer(L"--native-ordinal");
        const auto memoryOrdinal = args.integer(L"--memory-ordinal");
        const auto byteCount = args.has(L"--bytes") ? args.integer(L"--bytes") : 1;
        if (!nativeOrdinal || nativeOrdinal > 4096 || !memoryOrdinal || memoryOrdinal > 4096 ||
            !byteCount || byteCount > 15) {
            return Failed(storage::Failure(project::ProjectError::InvalidArgument,
                "nativeExecutionMemoryReadRequest"));
        }

        project::ProjectDocument document;
        if (const auto status = document.Open(args.require(L"--project")); !status) {
            return Failed(status);
        }
        project::ArchivedNativeExecution execution;
        if (const auto status = ReadNativeExecutionChain(document, sample, nativeOrdinal, execution); !status) {
            return Failed(status);
        }
        project::ArchivedMemorySnapshot memory;
        if (const auto status = ReadMemoryChain(document, sample, memoryOrdinal, memory); !status) {
            return Failed(status);
        }

        // 核心只接已核验的历史输入，并核对同一停点完整令牌及实际范围。
        // 不使用 nextInstructionAddress，也不访问目标或比较两路 QPC。
        detection::NativeExecutionMemoryMatch match;
        const auto associated = detection::AssociateNativeExecutionMemory(
            document.Info()->projectId, sample, execution, memory, byteCount, match);
        if (!associated) {
            return Failed(associated);
        }

        std::vector<Json> pageSequences;
        pageSequences.reserve(match.memoryRecordSequences.size());
        for (const auto sequence : match.memoryRecordSequences) {
            pageSequences.push_back(Json::count(sequence));
        }
        const auto nativeSource = Json::object({
            {L"stream", Json::string(L"raw-native")},
            {L"ordinal", Json::count(nativeOrdinal)},
            {L"segmentVerified", Json::boolean(true)},
            {L"sha256", Json::string(storage::WideAscii(execution.sha256))},
            {L"recordSequence", Json::count(execution.end.lastSequence)},
            {L"endOffset", Json::count(execution.end.byteOffset)},
            {L"blockOrdinal", Json::count(execution.end.blockOrdinal)},
            {L"document", Document(execution.document)}
        });
        const auto memorySource = Json::object({
            {L"stream", Json::string(L"raw-memory")},
            {L"ordinal", Json::count(memoryOrdinal)},
            {L"segmentVerified", Json::boolean(true)},
            {L"sha256", Json::string(storage::WideAscii(memory.sha256))},
            {L"recordSequences", Json::array(pageSequences)},
            {L"endOffset", Json::count(memory.boundary.byteOffset)},
            {L"lastSequence", Json::count(memory.boundary.lastSequence)},
            {L"blockOrdinal", Json::count(memory.boundary.blockOrdinal)},
            {L"plan", Document(memory.plan)}
        });
        return {0, Json::object({
            {L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
            {L"sampleId", Json::string(storage::WideAscii(sample))},
            {L"historical", Json::boolean(true)},
            {L"observation", Json::string(storage::WideAscii(match.observation))},
            {L"instructionAddress", Json::count(match.instructionAddress)},
            {L"byteCount", Json::count(match.bytes.size())},
            {L"bytesHex", Json::string(BytesHex(match.bytes))},
            {L"native", nativeSource},
            {L"memory", memorySource},
            {L"heldAtBothChecks", Json::boolean(match.heldAtBothChecks)},
            {L"bytesAtExecutionVerified", Json::boolean(match.bytesAtExecutionVerified)},
            {L"allocationGenerationVerified", Json::boolean(match.allocationGenerationVerified)},
            {L"sourceAuthenticated", Json::boolean(match.sourceAuthenticated)},
            {L"instructionDecoded", Json::boolean(false)},
            {L"limitations", Json::string(L"Bytes were read while the same historical native stop was held. They do not establish CPU fetch-time bytes or a decoded complete instruction; QPC values are not compared.")}
        }), {}};
    } catch (const std::invalid_argument&) {
        // 参数失败同样不发布局部字节，沿用该查询的失败退出码。
        return Failed(storage::Failure(project::ProjectError::InvalidArgument,
            "nativeExecutionMemoryReadRequest"));
    }
}

Json Reference(const detection::EvidenceRef& source)
{
    return Json::object({{L"stream", Json::string(L"raw")},
        {L"projectId", Json::string(storage::WideAscii(source.projectId))},
        {L"sampleId", Json::string(storage::WideAscii(source.sampleId))},
        {L"segmentOrdinal", Json::count(source.raw->segmentOrdinal)}, {L"recordSequence", Json::count(source.raw->sequence)},
        {L"sourceId", Json::string(storage::WideAscii(source.sourceId))},
        {L"sourceEpoch", Json::string(storage::WideAscii(source.sourceEpoch))},
        {L"sourceSequence", source.sourceSequence ? Json::count(*source.sourceSequence) : Json{}}});
}

Json Association(const detection::NativeTransferAssociation& match,
    const detection::ArchivedGraphRecord& creation, const project::ArchivedNativeExecution& execution)
{
    const auto& transfer = match.transfer;
    const auto* frequency = execution.document.find("qpcFrequency");
    return Json::object({{L"kind", Json::string(L"native-transfer-consistency-candidate")},
        {L"observation", Json::string(storage::WideAscii(match.observation))},
        {L"write", Reference(transfer.write)}, {L"threadCreate", Reference(transfer.threadCreate)},
        {L"native", Json::object({{L"stream", Json::string(L"raw-native")},
            {L"segmentOrdinal", Json::count(match.nativeSegmentOrdinal)},
            {L"recordSequence", Json::count(match.nativeRecordSequence)},
            {L"sha256", Json::string(storage::WideAscii(match.nativeSha256))},
            {L"endOffset", Json::count(execution.end.byteOffset)}, {L"blockOrdinal", Json::count(execution.end.blockOrdinal)}})},
        {L"actorPid", Json::number(transfer.actorPid)}, {L"actorCreationFileTime", Json::count(transfer.actorCreationFileTime)},
        {L"targetPid", Json::number(transfer.targetPid)}, {L"targetCreationFileTime", Json::count(transfer.targetCreationFileTime)},
        {L"tid", Json::number(match.tid)}, {L"threadCreationFileTime", Json::count(match.threadCreationFileTime)},
        {L"writtenAddress", Json::count(transfer.writtenAddress)}, {L"writtenBytes", Json::count(transfer.writtenBytes)},
        {L"requestedStartAddress", Json::count(transfer.requestedStartAddress)},
        {L"instructionAddress", Json::count(match.instructionAddress)},
        {L"apiClock", Json::object({{L"createEnterQpc", Json::count(match.createEnterQpc)},
            {L"createReturnQpc", Json::count(creation.apiInjection->returnQpc)}, {L"qpcFrequency", Json{}}})},
        {L"nativeClock", Json::object({{L"observedQpc", match.observedQpc ? Json::count(*match.observedQpc) : Json{}},
            {L"qpcFrequency", frequency ? Document(*frequency) : Json{}}})},
        {L"sourceAuthenticated", Json::boolean(match.sourceAuthenticated)},
        {L"regionVersionVerified", Json::boolean(match.regionVersionVerified)},
        {L"causalityConfirmed", Json::boolean(match.causalityConfirmed)},
        {L"commonClockVerified", Json::boolean(match.commonClockVerified)}});
}

// 公开APC请求与实际执行的三份原坐标，队列接受状态不转换成投递结论。
Json ApcAssociation(const detection::NativeApcTransferAssociation& match,
    const detection::ArchivedGraphRecord& queue, const project::ArchivedNativeExecution& execution)
{
    const auto& transfer = match.transfer; // 同来源写入到请求例程的已核验候选。
    const auto* frequency = execution.document.find("qpcFrequency"); // 保留原生时钟的原频率。
    return Json::object({{L"kind", Json::string(L"native-apc-consistency-candidate")},
        {L"observation", Json::string(storage::WideAscii(match.observation))},
        {L"write", Reference(transfer.write)}, {L"apcQueue", Reference(transfer.queue)},
        {L"native", Json::object({{L"stream", Json::string(L"raw-native")},
            {L"segmentOrdinal", Json::count(match.nativeSegmentOrdinal)},
            {L"recordSequence", Json::count(match.nativeRecordSequence)},
            {L"sha256", Json::string(storage::WideAscii(match.nativeSha256))},
            {L"endOffset", Json::count(execution.end.byteOffset)},
            {L"blockOrdinal", Json::count(execution.end.blockOrdinal)}})},
        {L"actorPid", Json::number(transfer.actorPid)},
        {L"actorCreationFileTime", Json::count(transfer.actorCreationFileTime)},
        {L"targetPid", Json::number(transfer.targetPid)},
        {L"targetCreationFileTime", Json::count(transfer.targetCreationFileTime)},
        {L"tid", Json::number(transfer.targetTid)},
        {L"threadCreationFileTime", Json::count(transfer.targetThreadCreationFileTime)},
        {L"writtenAddress", Json::count(transfer.writtenAddress)},
        {L"writtenBytes", Json::count(transfer.writtenBytes)},
        {L"requestedRoutineAddress", Json::count(transfer.requestedRoutineAddress)},
        {L"instructionAddress", Json::count(match.instructionAddress)},
        {L"queueOutcome", Json::string(L"accepted")}, {L"delivery", Json{}},
        {L"apiClock", Json::object({{L"queueEnterQpc", Json::count(queue.apiApc->enterQpc)},
            {L"queueReturnQpc", Json::count(queue.apiApc->returnQpc)}, {L"qpcFrequency", Json{}}})},
        {L"nativeClock", Json::object({{L"observedQpc", match.observedQpc ? Json::count(*match.observedQpc) : Json{}},
            {L"qpcFrequency", frequency ? Document(*frequency) : Json{}}})},
        {L"sourceAuthenticated", Json::boolean(match.sourceAuthenticated)},
        {L"regionVersionVerified", Json::boolean(match.regionVersionVerified)},
        {L"causalityConfirmed", Json::boolean(match.causalityConfirmed)},
        {L"commonClockVerified", Json::boolean(match.commonClockVerified)}});
}

// 上下文请求与实际执行分别投影，不把请求IP或API接受结果解释为已应用上下文。
Json ContextAssociation(const detection::NativeContextTransferAssociation& match,
    const detection::ArchivedGraphRecord& context, const project::ArchivedNativeExecution& execution)
{
    const auto& transfer = match.transfer; // 已核验写入和上下文请求的原坐标及请求值。
    const auto& request = *context.apiContext; // 核心匹配成功的同页原始上下文记录。
    const auto* frequency = execution.document.find("qpcFrequency"); // 仅保留原生时钟频率，不跨源比较。
    return Json::object({
        {L"kind", Json::string(L"native-context-consistency-candidate")},
        {L"observation", Json::string(storage::WideAscii(match.observation))},
        {L"write", Reference(transfer.write)},
        {L"context", Reference(transfer.context)},
        {L"native", Json::object({
            {L"stream", Json::string(L"raw-native")},
            {L"segmentOrdinal", Json::count(match.nativeSegmentOrdinal)},
            {L"recordSequence", Json::count(match.nativeRecordSequence)},
            {L"sha256", Json::string(storage::WideAscii(match.nativeSha256))},
            {L"endOffset", Json::count(execution.end.byteOffset)},
            {L"blockOrdinal", Json::count(execution.end.blockOrdinal)}
        })},
        {L"actorPid", Json::number(transfer.actorPid)},
        {L"actorCreationFileTime", Json::count(transfer.actorCreationFileTime)},
        {L"targetPid", Json::number(transfer.targetPid)},
        {L"targetCreationFileTime", Json::count(transfer.targetCreationFileTime)},
        {L"tid", Json::number(transfer.targetTid)},
        {L"threadCreationFileTime", Json::count(transfer.targetThreadCreationFileTime)},
        {L"writtenAddress", Json::count(transfer.writtenAddress)},
        {L"writtenBytes", Json::count(transfer.writtenBytes)},
        {L"requestedIp", Json::count(transfer.requestedIp)},
        {L"requestedSp", Json::count(transfer.requestedSp)},
        {L"contextArchitecture", Json::count(transfer.contextArchitecture)},
        {L"instructionAddress", Json::count(match.instructionAddress)},
        {L"contextOutcome", Json::string(L"accepted")},
        {L"contextApplied", Json{}},
        {L"apiClock", Json::object({
            {L"contextEnterQpc", Json::count(request.enterQpc)},
            {L"contextReturnQpc", Json::count(request.returnQpc)},
            {L"qpcFrequency", Json{}}
        })},
        {L"nativeClock", Json::object({
            {L"observedQpc", match.observedQpc ? Json::count(*match.observedQpc) : Json{}},
            {L"qpcFrequency", frequency ? Document(*frequency) : Json{}}
        })},
        {L"sourceAuthenticated", Json::boolean(match.sourceAuthenticated)},
        {L"regionVersionVerified", Json::boolean(match.regionVersionVerified)},
        {L"causalityConfirmed", Json::boolean(match.causalityConfirmed)},
        {L"commonClockVerified", Json::boolean(match.commonClockVerified)}
    });
}

Result Correlate(const Args& args)
{
    const auto sample = Sample(args);
    const auto apiOrdinal = args.integer(L"--api-ordinal");
    const auto nativeOrdinal = args.integer(L"--native-ordinal");
    const auto after = args.has(L"--after") ? args.integer(L"--after") : 0;
    const auto limit = args.has(L"--limit") ? args.integer(L"--limit") : detection::kArchivedGraphDefaultRows;
    if (!apiOrdinal || apiOrdinal > detection::kArchivedGraphMaxApiSegments || !nativeOrdinal || nativeOrdinal > 4096 ||
        !limit || limit > detection::kArchivedGraphMaxRows)
        throw std::invalid_argument("Require --api-ordinal 1..128, --native-ordinal 1..4096 and --limit 1..4096");
    project::ProjectDocument document;
    if (const auto status = document.Open(args.require(L"--project")); !status) return Failed(status);
    detection::ArchivedGraphPage page;
    const detection::ArchivedGraphRequest request{sample, apiOrdinal, after, static_cast<std::size_t>(limit), {}};
    if (const auto status = detection::ReadArchivedEvidenceGraph(document, request, page); !status) return Failed(status);
    if (page.source != detection::ArchivedGraphSource::ImportedApi && page.source != detection::ArchivedGraphSource::CommittedApiFollow)
        return Failed(storage::Failure(project::ProjectError::Unsupported, "nativeTransferApiSource"));
    project::ArchivedNativeExecution execution;
    if (const auto status = ReadNativeExecutionChain(document, sample, nativeOrdinal, execution); !status) return Failed(status);
    std::vector<Json> candidates;
    for (const auto& transfer : page.transferCandidates) {
        if (!transfer.threadCreate.raw || !transfer.write.raw)
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeTransferCandidateCoordinate"));
        const auto creation = std::find_if(page.records.begin(), page.records.end(), [&](const auto& row) {
            return row.segmentOrdinal == transfer.threadCreate.raw->segmentOrdinal &&
                row.recordSequence == transfer.threadCreate.raw->sequence;
        });
        if (creation == page.records.end())
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeTransferCreationCoordinate"));
        if (const auto match = detection::AssociateNativeTransfer(page.graph.scope, transfer, *creation, execution, nativeOrdinal))
            candidates.push_back(Association(*match, *creation, execution));
    }
    std::vector<Json> apcCandidates; // 独立窗口保留APC候选，已有线程创建输出的含义不变。
    for (const auto& transfer : page.apcTransferCandidates) {
        if (!transfer.queue.raw || !transfer.write.raw) {
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeApcCandidateCoordinate"));
        }
        const auto queue = std::find_if(page.records.begin(), page.records.end(), [&](const auto& row) {
            return row.segmentOrdinal == transfer.queue.raw->segmentOrdinal &&
                row.recordSequence == transfer.queue.raw->sequence;
        }); // 候选请求端必须落在本次已核验API观察页。
        if (queue == page.records.end()) {
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeApcQueueCoordinate"));
        }
        if (const auto match = detection::AssociateNativeApcTransfer(page.graph.scope, transfer, *queue, execution, nativeOrdinal)) {
            apcCandidates.push_back(ApcAssociation(*match, *queue, execution));
        }
    }
    std::vector<Json> contextCandidates; // 上下文候选窗口独立，不改变创建或APC候选的计数语义。
    for (const auto& transfer : page.contextTransferCandidates) {
        if (!transfer.context.raw || !transfer.write.raw) {
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeContextCandidateCoordinate"));
        }
        const auto context = std::find_if(page.records.begin(), page.records.end(), [&](const auto& row) {
            return row.segmentOrdinal == transfer.context.raw->segmentOrdinal &&
                row.recordSequence == transfer.context.raw->sequence;
        }); // 请求端必须精确对应本次已核验页中的原始记录，不从旧页补取。
        if (context == page.records.end() || !context->apiContext) {
            return Failed(storage::Failure(project::ProjectError::Corrupt, "nativeContextRequestCoordinate"));
        }
        const auto match = detection::AssociateNativeContextTransfer(
            page.graph.scope, transfer, *context, execution, nativeOrdinal);
        if (match) {
            contextCandidates.push_back(ContextAssociation(*match, *context, execution));
        }
    }
    return {0, Json::object({{L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sample))}, {L"historical", Json::boolean(true)},
        {L"apiOrdinal", Json::count(apiOrdinal)}, {L"nativeOrdinal", Json::count(nativeOrdinal)},
        {L"apiSha256", Json::string(storage::WideAscii(page.sha256))},
        {L"nativeSha256", Json::string(storage::WideAscii(execution.sha256))},
        {L"after", Json::count(after)}, {L"limit", Json::count(limit)},
        {L"nextAfter", page.nextAfterSequence ? Json::count(*page.nextAfterSequence) : Json{}},
        {L"apiObservationCount", Json::count(page.observationCount)},
        {L"transferCandidateCount", Json::count(page.transferCandidateCount)},
        {L"retainedTransferCandidates", Json::count(page.transferCandidates.size())},
        {L"evictedTransferWrites", Json::count(page.evictedTransferWrites)},
        {L"transferCandidatesTruncated", Json::boolean(page.transferCandidates.size() < page.transferCandidateCount)},
        {L"candidateCount", Json::count(candidates.size())}, {L"candidates", Json::array(candidates)},
        {L"apcTransferCandidateCount", Json::count(page.apcTransferCandidateCount)},
        {L"retainedApcTransferCandidates", Json::count(page.apcTransferCandidates.size())},
        {L"apcTransferCandidatesTruncated", Json::boolean(page.apcTransferCandidates.size() < page.apcTransferCandidateCount)},
        {L"apcCandidateCount", Json::count(apcCandidates.size())}, {L"apcCandidates", Json::array(apcCandidates)},
        {L"contextTransferCandidateCount", Json::count(page.contextTransferCandidateCount)},
        {L"retainedContextTransferCandidates", Json::count(page.contextTransferCandidates.size())},
        {L"contextTransferCandidatesTruncated", Json::boolean(page.contextTransferCandidates.size() < page.contextTransferCandidateCount)},
        {L"contextCandidateCount", Json::count(contextCandidates.size())},
        {L"contextCandidates", Json::array(contextCandidates)},
        {L"sourceAuthenticated", Json::boolean(false)}, {L"regionVersionVerified", Json::boolean(false)},
        {L"causalityConfirmed", Json::boolean(false)}, {L"commonClockVerified", Json::boolean(false)},
        {L"limitations", Json::string(L"Identity and half-open write-range consistency only. API and native clocks are preserved separately without cross-source ordering. Source authentication, region/content version and causality remain unverified.")}}), {}};
}
} // namespace

void RegisterNativeExecutionCommands()
{
    Command read;
    read.path = L"analyze execution read";
    read.syntax = L"KswordCLI.exe analyze execution read --project PATH --sample UUID [--ordinal N] [--json]";
    read.summary = L"Read a verified historical native execution observation from a project sample.";
    read.options = L"Requires --project and --sample. --ordinal defaults to 1 and must be a positive uint64.";
    read.notes = L"Verifies every raw-native segment from 1 through the requested ordinal. Accepts legacy native-execution-v1/v2 and current native-execution-v3 with full event-thread registers and the original event binding. The binding retains admitted NX ranges and any measured image SHA256; missing legacy fields remain unknown. Returns the historical document, SHA-256 and raw-native boundary. Archived registers are event-stop values; instruction-completed registers describe the state after the instruction. Historical binding and stop IDs cannot grant live control.";
    read.run = Read;
    addCommand(std::move(read));
    Command history; // 历史列表按raw-native游标分页，不依赖API流存在。
    history.path = L"analyze execution history";
    history.syntax = L"KswordCLI.exe analyze execution history --project PATH --sample UUID [--after N --limit N] [--json]";
    history.summary = L"List verified native execution history independently of API transfer candidates.";
    history.options = L"Requires --project and --sample. --after is the last consumed raw-native ordinal (default 0, max 4096). --limit defaults to 32 (1..128).";
    history.notes = L"Uses the desktop history reader to verify the continuous raw-native chain, up to 4096 segments. Returns original coordinates, hashes, observation phase, process/thread identities and instruction address. Empty history is distinct from read failure. nextAfter/hasMore page the verified range; historyLimited and firstUnreadOrdinal report the independent scan limit. Use execution read --ordinal N for the complete historical binding and registers. Reads no target process and grants no live control.";
    history.run = History;
    addCommand(std::move(history));
    Command correlate;
    correlate.path = L"analyze execution correlate";
    correlate.syntax = L"KswordCLI.exe analyze execution correlate --project PATH --sample UUID --api-ordinal N --native-ordinal N [--after N --limit N] [--json]";
    correlate.summary = L"Compare archived API transfer candidates with one verified native execution observation.";
    correlate.options = L"Requires --project, --sample, --api-ordinal (1..128), --native-ordinal (1..4096). --after defaults to 0; --limit defaults to 100 (max 4096).";
    correlate.notes = L"Reads and verifies both chains without accessing processes. Matches target PID/creation FILETIME, returned thread TID/creation FILETIME and actual instruction address in the half-open actual write range. APC candidates additionally require the queued thread identity and the exact requested routine entry. Returns separate candidates/apcCandidates and nextAfter using API raw observation pagination. An accepted APC queue request does not prove delivery or causality. Source authentication, region version, causality and common clock remain unverified; no partial candidates are returned after a read failure.";
    correlate.notes += L" Context consistency results use a separate contextCandidates array and window counts with the same after/limit cursor. Original write/context/native coordinates and clocks are preserved; contextApplied remains null. A requested IP does not establish execution or grant live control, and no cross-source QPC ordering is inferred.";
    correlate.run = Correlate;
    addCommand(std::move(correlate));

    Command memory;
    memory.path = L"analyze execution memory";
    memory.syntax = L"KswordCLI.exe analyze execution memory --project PATH --sample UUID --native-ordinal N --memory-ordinal N [--bytes N] [--json]";
    memory.summary = L"Read archived bytes at an execution observation's instruction address from the same held native stop.";
    memory.options = L"Requires --project, --sample, --native-ordinal and --memory-ordinal (both 1..4096). --bytes defaults to 1 and must be 1..15.";
    memory.notes = L"Verifies both independent segment chains from ordinal 1, then matches project/sample, process identity and the complete held-event tokens. Returns bytesHex, native and memory source hashes/coordinates, the original execution document and memory plan. No live-read or changed-stop fallback. Does not access processes, compare QPC, establish CPU fetch-time bytes or decode a complete instruction. Failure exits 3 without partial bytes.";
    memory.run = ExecutionMemory;
    addCommand(std::move(memory));
}
} // namespace ks::cli::action_analyze
