#include "LiveCapture.h"

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <algorithm>
#include <filesystem>
#include <span>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
namespace Archive = ks::cli::action_analyze::archive;
namespace Etw = ks::r3::monitor;
using Storage::Number;
using Storage::Object;
using Storage::Text;
using Value = Ksword::Evidence::JsonValue;
constexpr std::uint64_t kProcessIntervalMs = 1000; // 两次进程活动查询之间的最短间隔。
constexpr std::uint64_t kSegmentIntervalMs = 1000; // 低事件率时的归档推进间隔。
constexpr std::size_t kMaxQueue = 512; // 原生回调的接纳队列上限。
constexpr std::size_t kMaxPayload = 4096; // 与现有读端相容的每条负载前缀上限。
constexpr std::size_t kBlockRecords = 32; // 单块的观察数量，控制元数据及内联负载大小。

struct ProcessCounters {
    std::uint64_t tickMs = 0; // 读取完成的单调时间。
    std::uint64_t cpu100ns = 0; // 用户和内核累计 CPU 时间。
    std::optional<std::uint64_t> receiveQpc; // 与 ETW 接收时钟处于同一本机域。
    std::optional<IO_COUNTERS> io; // 成功读取的累积 I/O。
    DWORD ioError = ERROR_SUCCESS; // I/O 查询未成功时实际错误码。
};

// 将原生双 DWORD 时戳合为同单位无损整数。
std::uint64_t FileTicks(const FILETIME& time) noexcept {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

// 读取冻结句柄的身份与计数。CPU 查询失败时返回主错误，I/O 失败留在本轮快照中。
DWORD ReadCounters(HANDLE process, std::uint64_t expectedCreation, ProcessCounters& out) {
    FILETIME created{}, exited{}, kernel{}, user{}; // 同一查询的创建、退出与累计时间。
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        return GetLastError();
    }
    if (FileTicks(created) != expectedCreation) {
        return ERROR_INVALID_PARAMETER;
    }
    const auto kernelTicks = FileTicks(kernel); // 本轮内核和用户 CPU 值。
    const auto userTicks = FileTicks(user);
    if (userTicks > UINT64_MAX - kernelTicks) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }
    IO_COUNTERS io{}; // 可选 I/O 计数，失败保留未知。
    if (GetProcessIoCounters(process, &io)) {
        out.io = io;
    } else {
        out.ioError = GetLastError();
    }
    out.cpu100ns = kernelTicks + userTicks;
    out.tickMs = GetTickCount64();
    LARGE_INTEGER ticks{}; // 实际完成读数的时间点。
    if (QueryPerformanceCounter(&ticks) && ticks.QuadPart >= 0) {
        out.receiveQpc = static_cast<std::uint64_t>(ticks.QuadPart);
    }
    return ERROR_SUCCESS;
}

// 比较两份同实例快照。CPU 及时间单调性由调用者保证。
LiveProcessInterval MakeInterval(const ProcessCounters& previous, const ProcessCounters& current,
                                 std::uint64_t sequence) {
    LiveProcessInterval row; // 本轮实际区间。
    row.sequence = sequence;
    row.beginTickMs = previous.tickMs;
    row.endTickMs = current.tickMs;
    row.receiveQpc = current.receiveQpc;
    row.cpu100ns = current.cpu100ns - previous.cpu100ns;
    row.ioError = current.ioError != ERROR_SUCCESS ? current.ioError : previous.ioError;
    if (previous.io && current.io) {
        if (current.io->ReadTransferCount >= previous.io->ReadTransferCount) {
            row.readBytes = current.io->ReadTransferCount - previous.io->ReadTransferCount;
        }
        if (current.io->WriteTransferCount >= previous.io->WriteTransferCount) {
            row.writeBytes = current.io->WriteTransferCount - previous.io->WriteTransferCount;
        }
        if (!row.readBytes || !row.writeBytes) {
            row.ioError = ERROR_INVALID_DATA;
        }
    }
    return row;
}

// 转换共享 ETW GUID 文本为 A0 使用的小写无括号形式。
std::string GuidText(const GUID& guid) {
    const auto native = Etw::GuidToString(guid); // 共享格式化结果。
    std::string text; // 已规范化的 ASCII 标识。
    if (native.size() != 38) {
        return text;
    }
    text.reserve(36);
    for (std::size_t i = 1; i + 1 < native.size(); ++i) {
        const auto ch = native[i]; // GUID 文本中的一个 ASCII 字符。
        text.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + (L'a' - L'A') : ch));
    }
    return text;
}

// 未取得的原生 Win32 统计或状态以空值编码，实测 0 保留为数值。
Value OptionalStat(bool known, ULONG value) {
    return known ? Value::makeUInt(value) : Value::makeNull();
}

// 序列化终态或轮换时的来源回执，字段与现有 ETW Coverage 核验一致。
Value SourceMetadata(const Etw::PassiveEtwStatus& status, std::uint64_t outOfScope) {
    const auto& native = status.native; // 原生阶段、停止和丢失回执。
    const auto& stops = native.stopStatuses; // 首次及最近一次 STOP 的结果。
    return Object({
        {"sourceEpoch", Text(status.sourceEpoch)},
        {"inputWin32Error", Value::makeUInt(status.inputError)},
        {"startWin32Error", OptionalStat(native.startAttempted, native.startStatus)},
        {"enableWin32Error", OptionalStat(!native.providers.empty(),
            native.providers.empty() ? ERROR_SUCCESS : native.providers.front().status)},
        {"openWin32Error", OptionalStat(native.openAttempted, native.openStatus)},
        {"processAttempted", Value::makeBool(native.processAttempted)},
        {"processWin32Error", OptionalStat(native.processCompleted, native.processStatus)},
        {"closeWin32Error", OptionalStat(native.closeAttempted, native.closeStatus)},
        {"firstStopWin32Error", OptionalStat(!stops.empty(), stops.empty() ? ERROR_SUCCESS : stops.front())},
        {"lastStopWin32Error", OptionalStat(!stops.empty(), stops.empty() ? ERROR_SUCCESS : stops.back())},
        {"nativeSessionStopped", Value::makeBool(native.sessionStopped)},
        {"consumerJoined", Value::makeBool(native.consumerJoined)},
        {"tailDeliveryUnconfirmed", Value::makeBool(native.tailDeliveryUnconfirmed)},
        {"callbackFailed", Value::makeBool(native.callbackFailed)},
        {"eventsLost", OptionalStat(native.statisticsKnown, native.eventsLost)},
        {"logBuffersLost", OptionalStat(native.statisticsKnown, native.logBuffersLost)},
        {"realTimeBuffersLost", OptionalStat(native.statisticsKnown, native.realTimeBuffersLost)},
        {"providerEvents", Number(status.providerEvents)},
        {"headerFiltered", Number(status.headerFiltered)},
        {"enqueued", Number(status.enqueued)},
        {"queued", Number(status.queued)},
        {"queueDropped", Number(status.queueDropped)},
        {"payloadTruncated", Number(status.payloadTruncated)},
        {"malformedPayload", Number(status.malformedPayload)},
        {"targetWindowExcluded", Number(outOfScope)},
    });
}

// 将原生观察映射到三端现有的 ETW 原始正文。负载字节作为独立内联区写入。
std::string RecordMetadata(const Etw::PassiveEtwRecord& record) {
    const auto& descriptor = record.descriptor; // ETW 的原生事件布局身份。
    const bool receiveClockKnown = record.receivedQpc && record.qpcFrequencyHz != 0; // 时钟缺少频率时整对留空。
    return Ksword::Evidence::WriteJson(Object({
        {"kind", Text("etw-observation-v1")},
        {"sourceEpoch", Text(record.sourceEpoch)},
        {"providerId", Text(GuidText(record.provider))},
        {"descriptor", Object({
            {"id", Value::makeUInt(descriptor.id)}, {"version", Value::makeUInt(descriptor.version)},
            {"channel", Value::makeUInt(descriptor.channel)}, {"level", Value::makeUInt(descriptor.level)},
            {"opcode", Value::makeUInt(descriptor.opcode)}, {"task", Value::makeUInt(descriptor.task)},
            {"keyword", Number(descriptor.keyword)},
        })},
        {"headerPid", Value::makeUInt(record.headerPid)},
        {"headerTid", Value::makeUInt(record.headerTid)},
        {"headerFlags", Value::makeUInt(record.headerFlags)},
        {"sourceFileTime100ns", Number(record.sourceFileTime100ns)},
        {"receiveQpc", receiveClockKnown ? Number(*record.receivedQpc) : Value::makeNull()},
        {"qpcFrequencyHz", receiveClockKnown ? Number(record.qpcFrequencyHz) : Value::makeNull()},
        {"activityId", Text(GuidText(record.activityId))},
        {"relatedActivityId", record.relatedActivityId ? Text(GuidText(*record.relatedActivityId)) : Value::makeNull()},
        {"extendedDataCount", Value::makeUInt(record.extendedDataCount)},
        {"originalPayloadBytes", Value::makeUInt(record.originalPayloadBytes)},
        {"malformedPayload", Value::makeBool(record.malformedPayload)},
        {"storedPayloadBytes", Number(record.payloadPrefix.size())},
    }));
}

// 返回已有回放器可识别的最终停止原因。
std::string_view EndName(LiveCaptureEnd end) noexcept {
    switch (end) {
    case LiveCaptureEnd::TargetExited: return "target-exited";
    case LiveCaptureEnd::ProcessError: return "process-error";
    default: return "requested";
    }
}

// 将共享 writer 首个错误转换为项目回执，保留原始系统错误。
Project::ProjectResult Append(Archive::RawEvidenceArchive& writer,
                              std::span<const Archive::RawEvidenceInput> inputs) {
    const auto receipt = writer.Append(inputs); // 块写入及封装状态。
    if (receipt.result.status == Archive::SegmentWriteStatus::Ok) {
        return {};
    }
    if (receipt.result.status == Archive::SegmentWriteStatus::IoError) {
        return Storage::WinFailure("lightRawWrite", receipt.result.error.win32Error);
    }
    return Storage::Failure(Project::ProjectError::InvalidArgument, "lightRawInput");
}

} // namespace

struct LiveCapture::Impl {
    LiveCaptureStatus status; // 所有可见状态的规范源。
    Storage::Handle target; // 最小访问权限的冻结目标句柄。
    Project::ProjectDocument project; // 共享存储的唯一写租约。
    Project::SampleRecord sample; // 已核验的采样描述和配置哈希。
    std::optional<Etw::PassiveEtwOptions> options; // 非空时开始时请求了 ETW。
    Etw::PassiveEtwSource source; // 独立会话资源由共享控制器管理。
    ProcessCounters previous; // 同一进程实例的上次实际快照。
    std::string providerId; // 已选来源的规范 UUID 文本。
    std::uint64_t startUtc = 0; // 该会话接受报头上下文的时间起点。
    std::uint64_t exitUtc = 0; // 目标退出后从原句柄读出的时间上界。
    std::uint64_t nextSegmentTick = 0; // ETW 后台下一次低流量分段时点。
    std::uint64_t lastRawSequence = 0; // 已发布前缀的真实末序号。
    bool nativeRetired = false; // 成功清退后继续排空，无需重复发出 STOP。
    bool targetExited = false; // 已观测到退出，即使无法读取退出时刻。

    // 按工件当前状态填写启动失败，关闭本端已取得的资源。
    LiveCaptureStatus FailStart(const char* stage, DWORD error) {
        status.processStage = stage;
        status.processError = error;
        status.state = LiveCaptureState::Failed;
        target.reset();
        project.Close();
        return status;
    }

    // 原句柄退出后获取时间上界。缺失上界时排空到的记录无法确认范围。
    void ObserveExit() {
        targetExited = true;
        FILETIME created{}, exited{}, kernel{}, user{}; // 原目标句柄的终态字段。
        if (GetProcessTimes(target.get(), &created, &exited, &kernel, &user) &&
            FileTicks(created) == status.creationFileTime) {
            exitUtc = FileTicks(exited);
        }
    }

    // 根据原句柄状态推进区间采样。返回本轮有资格发布的新增区间。
    std::optional<LiveProcessInterval> SampleProcess() {
        const DWORD wait = WaitForSingleObject(target.get(), 0); // 不等待目标动作。
        if (wait == WAIT_OBJECT_0) {
            ObserveExit();
            status.end = LiveCaptureEnd::TargetExited;
            return {};
        }
        if (wait != WAIT_TIMEOUT) {
            status.processStage = "wait-target";
            status.processError = wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
            status.end = LiveCaptureEnd::ProcessError;
            return {};
        }
        const auto now = GetTickCount64(); // 只在实际节拍到期后查询计数。
        if (now - previous.tickMs < kProcessIntervalMs) {
            return {};
        }
        ProcessCounters current; // 新查询的值，不覆盖已有的有效区间。
        const auto error = ReadCounters(target.get(), status.creationFileTime, current);
        if (error != ERROR_SUCCESS || current.cpu100ns < previous.cpu100ns || current.tickMs <= previous.tickMs) {
            status.processStage = "read-process-counters";
            status.processError = error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
            status.end = LiveCaptureEnd::ProcessError;
            return {};
        }
        auto row = MakeInterval(previous, current, ++status.processIntervals); // 区间由实际快照计算。
        previous = current;
        return row;
    }

    // 生成与现有检查点兼容的持续采集计划。
    std::string Plan(const Etw::PassiveEtwStatus& native) const {
        return Ksword::Evidence::WriteJson(Object({
            {"kind", Text("etw-capture-plan-v1")},
            {"backend", Text("r3")},
            {"session", Object({{"id", Text(status.sampleId)}, {"epoch", Text(status.sessionEpoch)}})},
            {"sourceEpoch", Text(native.sourceEpoch)},
            {"revisionId", Text(sample.info.revisionId)},
            {"snapshotId", Text(sample.info.snapshotId)},
            {"revisionHash", Text(sample.revisionHash)},
            {"configSemanticHash", Text(sample.configSemanticHash)},
            {"providerId", Text(providerId)},
            {"headerPid", Value::makeUInt(status.pid)},
            {"processCreationFileTime", Number(status.creationFileTime)},
            {"durationMs", Value::makeUInt(0)},
            {"headerRole", Text("record-context")},
            {"sourceClock", Text("filetime-100ns")},
            {"receiveClock", Text("local-qpc")},
            {"captureStartFileTime", Number(startUtc)},
            {"level", Value::makeUInt(options->level)},
            {"matchAnyKeyword", Number(options->matchAnyKeyword)},
            {"maxRecords", Value::makeUInt(options->maxQueuedRecords)},
            {"maxPayloadBytes", Value::makeUInt(options->maxPayloadBytes)},
        }));
    }

    // 从同一组观察建立原始段。返回取得了双流检查点的坐标。
    void Commit(std::vector<LiveEtwObservation>& rows, const Etw::PassiveEtwStatus& native, bool final) {
        if (status.sampleId.empty() || !status.archive || (rows.empty() && !final)) {
            return;
        }
        if (native.sourceEpoch.empty()) {
            status.archive = Storage::Failure(Project::ProjectError::Corrupt, "lightSourceEpoch", native.inputError);
            return;
        }
        const auto ordinal = status.verifiedSegments + 1; // 下一份不可变段的标识。
        const auto first = lastRawSequence + 1; // 分段计划占 raw 中的第一条记录。
        const auto end = first + rows.size() + 1; // 分段尾回执的 raw 序号。
        Archive::RawEvidenceReceipt receipt; // 原始段的实际刷盘回执。
        const auto previousRaw = lastRawSequence ? std::optional{lastRawSequence} : std::nullopt;
        status.archive = project.WriteRawEvidenceSegment({status.projectId, status.sampleId, ordinal, previousRaw,
            [&](Archive::RawEvidenceArchive& writer) -> Project::ProjectResult {
                const auto plan = Plan(native); // 覆盖依赖的计划正文。
                const Archive::RawEvidenceInput head{plan, {}}; // 写入借用计划值的视图。
                if (const auto result = Append(writer, std::span(&head, 1)); !result) {
                    return result;
                }
                for (std::size_t i = 0; i < rows.size(); i += kBlockRecords) {
                    const auto count = (std::min)(kBlockRecords, rows.size() - i); // 本块包含的最大观察数。
                    std::vector<std::string> metadata; // 本块拥有的元数据，保留至 Append 同步完成。
                    std::vector<Archive::RawEvidenceInput> inputs; // 同行原字节视图。
                    metadata.reserve(count);
                    inputs.reserve(count);
                    for (std::size_t j = i; j < i + count; ++j) {
                        const auto& row = rows[j].record; // 实时投影与归档共用此观察。
                        const auto& payload = row.payloadPrefix; // 本次真实取得的字节前缀。
                        metadata.push_back(RecordMetadata(row));
                        inputs.push_back({metadata.back(), payload.empty() ? std::string_view{} :
                            std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size())});
                    }
                    if (const auto result = Append(writer, inputs); !result) {
                        return result;
                    }
                }
                const auto tail = Ksword::Evidence::WriteJson(Object({
                    {"kind", Text("etw-capture-end-v1")},
                    {"stopReason", Text(final ? EndName(status.end) : "segment-rotated")},
                    {"finalSegment", Value::makeBool(final)},
                    {"segmentObservations", Number(rows.size())},
                    {"targetExitFileTime", exitUtc ? Number(exitUtc) : Value::makeNull()},
                    {"source", SourceMetadata(native, status.etwOutOfScope)},
                })); // 同一段的逐层覆盖与收尾回执。
                const Archive::RawEvidenceInput finish{tail, {}}; // 最后一个块的正文视图。
                return Append(writer, std::span(&finish, 1));
            }}, receipt);
        if (!status.archive) {
            return;
        }
        if (!receipt.flushed || receipt.flushed->lastSequence != end) {
            status.archive = Storage::Failure(Project::ProjectError::Corrupt, "lightRawBoundary");
            return;
        }

        // 核验原始段、写覆盖段、复核两流，最后提交项目标记。
        const auto statistic = [known = native.native.statisticsKnown](ULONG value) -> std::optional<std::uint32_t> {
            return known ? std::optional{static_cast<std::uint32_t>(value)} : std::nullopt;
        };
        const Archive::EtwCoverageV1 coverage{providerId, native.sourceEpoch, ordinal, first, end, rows.size(),
            statistic(native.native.eventsLost), statistic(native.native.logBuffersLost),
            statistic(native.native.realTimeBuffersLost), native.queueDropped,
            native.payloadTruncated, native.malformedPayload}; // 原生事件和缓冲区各自保留单位。
        Project::ProjectEtwCheckpoint checkpoint; // 本段已核验并发布的双流结果。
        status.archive = project.PublishEtwCheckpoint(status.sampleId, *receipt.flushed, coverage, checkpoint);
        if (!status.archive) {
            return;
        }
        lastRawSequence = end;
        status.verifiedSegments = ordinal;
        status.archivedEtw += rows.size();
        status.finalCheckpoint = final;
        for (std::size_t i = 0; i < rows.size(); ++i) {
            rows[i].segmentOrdinal = ordinal;
            rows[i].rawSequence = first + i + 1;
        }
    }

    // 每次移出有限记录，按冻结范围计数并用同一组对象提交归档和实时投影。
    void CollectEtw(LiveCaptureUpdate& update, bool stopping) {
        if (!options) {
            return;
        }
        auto native = source.status(); // 源队列和原生状态的实际回读。
        const auto now = GetTickCount64(); // 运行中按积压或节拍推进。
        const auto batchLimit = (std::min)(LiveCapture::kMaxEtwBatch, options->maxQueuedRecords); // 尊重冻结的较小队列。
        if (!stopping && native.queued < batchLimit && now < nextSegmentTick) {
            status.etw = std::move(native);
            return;
        }
        nextSegmentTick = now + kSegmentIntervalMs;
        auto records = source.drain(batchLimit); // 接管当前批次所有权。
        if (!targetExited && WaitForSingleObject(target.get(), 0) == WAIT_OBJECT_0) {
            ObserveExit();
            if (status.end == LiveCaptureEnd::None) {
                status.end = LiveCaptureEnd::TargetExited;
            }
        }
        update.etw.reserve(records.size());
        for (auto& record : records) {
            const auto time = record.sourceFileTime100ns; // 原始来源时间，仅用于限定报头上下文。
            if (time < startUtc || (targetExited && (!exitUtc || time >= exitUtc))) {
                ++status.etwOutOfScope;
                continue;
            }
            if (!record.qpcFrequencyHz) {
                record.receivedQpc.reset();
            }
            update.etw.push_back({std::move(record), ++status.etwObserved, {}, {}});
        }
        native = source.status();
        Commit(update.etw, native, stopping && native.queued == 0);
        status.etw = std::move(native);
    }
};

// 构造只分配本端状态对象。实际目标和项目在 Start 中取得。
LiveCapture::LiveCapture() : impl_(std::make_unique<Impl>()) {}

LiveCapture::~LiveCapture() = default;

LiveCaptureStatus LiveCapture::Start(const LiveCaptureRequest& request) {
    auto& capture = *impl_; // 本端工作线程独占的状态。
    auto& status = capture.status; // 通过值返回已确认的启动事实。
    if (status.state != LiveCaptureState::Idle) {
        return status;
    }
    status.pid = request.pid;
    status.creationFileTime = request.creationFileTime;
    status.archiveRequested = request.project.has_value();
    if (!request.pid || !request.creationFileTime || (request.project && !request.etw)) {
        return capture.FailStart("capture-request", ERROR_INVALID_PARAMETER);
    }
    if (request.etw) {
        const auto& options = *request.etw; // 冻结调用方设置之前先核对范围与预算。
        capture.providerId = GuidText(options.provider);
        if (!Storage::IsUuid(capture.providerId) || IsEqualGUID(options.provider, GUID{}) ||
            (options.headerPid && *options.headerPid != request.pid) ||
            options.maxPayloadBytes > kMaxPayload || options.maxQueuedRecords == 0 ||
            options.maxQueuedRecords > kMaxQueue) {
            return capture.FailStart("etw-request", ERROR_INVALID_PARAMETER);
        }
        capture.options = options;
        capture.options->headerPid = request.pid;
    }
    if (const auto id = Storage::NewId(status.sessionEpoch); !id) {
        return capture.FailStart("session-id", id.nativeError ? id.nativeError : ERROR_GEN_FAILURE);
    }
    if (stopRequested_.load()) {
        status.end = LiveCaptureEnd::Requested;
        status.state = LiveCaptureState::Stopped;
        return status;
    }

    // 在首次读数前打开身份固定且仅允许查询／等待的句柄。
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.pid); // 仅从原实例读取。
    if (!process) {
        return capture.FailStart("open-target", GetLastError());
    }
    capture.target = Storage::Handle(process);
    if (const auto error = ReadCounters(process, request.creationFileTime, capture.previous); error) {
        return capture.FailStart("read-initial-process-counters", error);
    }
    const DWORD wait = WaitForSingleObject(process, 0); // 起点确认发生在写项目或启用来源之前。
    if (wait != WAIT_TIMEOUT) {
        return capture.FailStart("wait-initial-target", wait == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED);
    }

    // 项目 API 负责目录固定、单写者和样本提交。重核选择时的冻结项目修订。
    if (request.project) {
        const auto& frozen = *request.project; // 页面所选项目的不可变副本。
        const std::filesystem::path manifest(frozen.manifestPath); // 明确的本地项目清单路径。
        if (!manifest.is_absolute() || CompareStringOrdinal(manifest.filename().c_str(), -1,
                L"project.ksaproj", -1, TRUE) != CSTR_EQUAL || !Storage::IsUuid(frozen.projectId) ||
            !Storage::IsUuid(frozen.revisionId)) {
            status.archive = Storage::Failure(Project::ProjectError::InvalidArgument, "lightProjectRequest");
        } else {
            status.archive = capture.project.Open(frozen.manifestPath, Project::ProjectAccess::ReadWrite);
        }
        if (status.archive && (capture.project.Info()->projectId != frozen.projectId ||
                capture.project.Info()->revisionId != frozen.revisionId)) {
            status.archive = Storage::Failure(Project::ProjectError::StaleRevision, "lightProjectContext");
        }
        if (!status.archive) {
            return capture.FailStart("open-project", status.archive.nativeError);
        }
        if (!stopRequested_.load()) {
            Project::SampleInfo sample; // 项目 API 返回已登记的真实采样。
            status.archive = capture.project.CreateSample("PID " + std::to_string(request.pid), sample, frozen.revisionId);
            if (status.archive) {
                status.projectId = capture.project.Info()->projectId;
                status.sampleId = sample.sampleId;
                status.archive = capture.project.ReadSample(status.sampleId, capture.sample);
            }
        }
        if (!status.archive) {
            return capture.FailStart("register-sample", status.archive.nativeError);
        }
    }

    capture.startUtc = Storage::UtcNow(); // ETW 来源时钟使用与计划相同的 FILETIME 域。
    capture.nextSegmentTick = GetTickCount64() + kSegmentIntervalMs;
    if (stopRequested_.load()) {
        status.state = LiveCaptureState::Stopped;
        status.end = LiveCaptureEnd::Requested;
        if (!status.sampleId.empty()) {
            status.archive = Storage::Failure(Project::ProjectError::RecoveryRequired, "lightCanceledBeforeSource", ERROR_CANCELLED);
        }
        capture.target.reset();
        capture.project.Close();
        return status;
    }
    if (capture.options) {
        (void)capture.source.start(*capture.options);
        status.etw = capture.source.status();
    }
    status.state = LiveCaptureState::Running;
    return status;
}

LiveCaptureUpdate LiveCapture::Poll() {
    auto& capture = *impl_; // 本轮调用在采集所有者线程上执行。
    auto& status = capture.status; // 原生回执和本端归档状态共用这一快照。
    LiveCaptureUpdate update; // 数据批次只在本轮移交一次。
    if (status.state == LiveCaptureState::Running) {
        if (status.end == LiveCaptureEnd::None && stopRequested_.load()) {
            status.end = LiveCaptureEnd::Requested;
        } else if (status.end == LiveCaptureEnd::None) {
            update.process = capture.SampleProcess();
        }
        if (status.end == LiveCaptureEnd::None) {
            capture.CollectEtw(update, false);
            update.status = status;
            return update;
        }
        status.state = LiveCaptureState::Stopping;
    }
    if (status.state == LiveCaptureState::Stopping && !capture.nativeRetired) {
        capture.nativeRetired = !capture.options || capture.source.stop();
        if (!capture.nativeRetired) {
            status.state = LiveCaptureState::CleanupPending;
            status.etw = capture.source.status();
        }
    }
    if (status.state == LiveCaptureState::Stopping) {
        capture.CollectEtw(update, true);
        if (!status.etw || status.etw->queued == 0) {
            capture.project.Close();
            capture.target.reset();
            status.state = LiveCaptureState::Stopped;
        }
    } else if (status.state == LiveCaptureState::CleanupPending) {
        status.etw = capture.source.status();
    }
    update.status = status;
    return update;
}

LiveCaptureUpdate LiveCapture::Stop() {
    RequestStop();
    if (impl_->status.state == LiveCaptureState::CleanupPending) {
        impl_->status.state = LiveCaptureState::Stopping;
    }
    return Poll();
}

void LiveCapture::RequestStop() noexcept {
    stopRequested_.store(true);
}

} // namespace Ksword::Features::ActionAnalyze
