#include "NativeLiveSession.h"
#include "ProjectReplay.h"
#include "ApiTransferPresentation.h"

#include "../../Ui/BackgroundWork.h"
#include "../../../KswordCLI/ActionAnalyze/Cli/PassiveApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/CooperativeApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/LaunchedApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwEvidence.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"
#include "../../../shared/usermode/backend/process/ProcessNavigationIdentity.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <iterator>
#include <mutex>
#include <thread>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr std::size_t kProcessPreviewRows = 256; // 繁忙的 ETW 不挤掉全部进程区间。
constexpr std::size_t kEtwPreviewRows = kEvidenceRows - kProcessPreviewRows; // 与历史共用有界窗口。

// 将受控的协议标识和阶段名称映射为原生文字。
std::wstring WideAscii(std::string_view value) {
    return {value.begin(), value.end()};
}

// 输入共享控制器确认的实际阶段，返回原生详情使用的中文标签；不根据连接或装载事实推断 Ready。
const wchar_t* StartupStageText(ks::winapi_monitor::CaptureStartupStage stage)
{
    using Stage = ks::winapi_monitor::CaptureStartupStage; // 与Qt及项目采集共用唯一阶段定义。
    switch (stage)
    {
    case Stage::IdentityVerified:
        return L"身份核对完成";
    case Stage::AgentResolved:
        return L"Agent 路径已解析";
    case Stage::ConfigPublished:
        return L"配置已发布";
    case Stage::AgentLoadStarted:
        return L"Agent 装载已开始";
    case Stage::AgentModuleVerified:
        return L"Agent 模块已核验";
    // 协议阶段分别显示，安装回执不能代替含当前活动覆盖核验的Ready屏障。
    case Stage::PipeConnected:
        return L"管道已核对";
    case Stage::SessionReady:
        return L"SessionReady";
    case Stage::HooksInstalled:
        return L"HooksInstalled";
    case Stage::Ready:
        return L"Ready";
    }
    return L"";
}

namespace Passive = ks::cli::action_analyze;
using Ksword::Evidence::JsonValue;
using ks::r3::process::Utf8ToWide;

std::string ReportString(const JsonValue& report, std::string_view name) {
    std::string value;
    if (const auto* field = report.find(name)) (void)field->tryGetString(value);
    return value;
}

std::wstring ReportCount(const JsonValue& report, std::string_view name) {
    std::uint64_t count = 0;
    const auto* field = report.find(name);
    return field && field->tryGetU64(count) ? std::to_wstring(count) : L"—";
}

// 投影后台的既有归档回执，向总览同时返回可用于触发读回的段水位。
std::wstring ApiReceiptText(const Passive::PassiveApiCapture& capture, std::uint64_t& committedSegment) {
    const auto source = capture.SourceReport();
    const auto archive = capture.ArchiveReport();
    if (const auto* segment = archive.find("segmentOrdinal")) {
        (void)segment->tryGetU64(committedSegment);
    }
    const auto entry = capture.ReadinessReport();
    const auto rules = capture.RulesReport();
    const auto* diagnosis = source.find("diagnosis");
    const auto input = diagnosis ? ReportString(*diagnosis, "input") : ReportString(source, "state");
    std::wstring text = L"源 " + WideAscii(input) + L" · 已核验 " +
        ReportCount(source, "validatedRows") + L" 行 · 已提交 " + ReportCount(archive, "recordedRows") +
        L" 包 · raw/" + ReportCount(archive, "segmentOrdinal");
    if (const auto error = ReportCount(source, "win32Error"); error != L"0" && error != L"—") text += L" · Win32 " + error;
    if (ReportString(archive, "status") == "failed") {
        text += L" · 归档失败 " + WideAscii(ReportString(archive, "error")) + L" / Win32 " + ReportCount(archive, "win32Error");
    }
    text += L"\r\n规则命中 " + ReportCount(rules, "matchedRows");
    const auto configError = ReportString(rules, "configError"); // 与采集和归档故障分开。
    if (!configError.empty()) {
        text += L" · 规则库加载失败：" + Utf8ToWide(configError);
    } else if (ReportString(rules, "state") == "evaluation-failed") {
        text += L" · 求值中断，保留已有命中";
    }
    if (const auto* latest = rules.find("latest"); latest && !latest->isNull()) {
        text += L" · " + Utf8ToWide(ReportString(*latest, "ruleId")) + L" · raw/" +
            ReportCount(*latest, "segmentOrdinal") + L" #" + ReportCount(*latest, "rawSequence") +
            L"（源行 " + ReportCount(*latest, "sourceSequence") + L"）";
        // 独立一行保留原有计数排版，不为缺少返回证据的命中显示旧释义。
        if (const auto* behavior = latest->find("behavior")) {
            const auto id = ReportString(*behavior, "ruleId"); // 该坐标实际命中的行为规则。
            const auto evidence = ReportString(*behavior, "evidence"); // 后端返回的证据级别。
            if (!id.empty()) {
                text += L"\r\n" + Utf8ToWide(id) + L" · " + Utf8ToWide(evidence);
                auto summary = ReportString(*behavior, "summaryZh"); // Light 优先显示中文释义。
                if (summary.empty()) {
                    summary = ReportString(*behavior, "summary");
                }
                if (!summary.empty()) {
                    text += L" · " + Utf8ToWide(summary);
                }
            }
        }
    }
    // 保留命中计数和坐标的整行格式，规则集放在同一回执的独立行。
    if (const auto presetSet = ReportString(rules, "presetSet"); !presetSet.empty()) {
        text += L"\r\n规则集：" + Utf8ToWide(presetSet);
        text += L"\r\nSHA-256：" + Utf8ToWide(ReportString(rules, "sourceSha256"));
    }
    if (const auto* raw = entry.find("firstRaw"); raw && !raw->isNull()) {
        text += L"\r\n首个 API 原包：raw/" + ReportCount(*raw, "segmentOrdinal") + L" #" + ReportCount(*raw, "rawSequence");
    } else if (const auto notice = ReportCount(entry, "hooksInstalledSourceSequence"); notice != L"—") {
        text += L"\r\n文件包含安装声明（源行 " + notice + L"），尚无已提交的普通 API 原包";
    }
    return text;
}

// 只投影被冻结进程的回执。EOF、停钩及清退是独立事实。
void ApplyCooperativeReceipt(NativeLiveSnapshot& next, const Ksword::ActionAnalyze::CooperativeApiReceipt& run) {
    namespace Project = Ksword::ActionAnalyze;
    auto& last = next.capture;
    auto& api = *next.api;
    const auto& capture = run.capture;
    const auto target = std::find_if(capture.processes.begin(), capture.processes.end(), [&](const auto& process) {
        return process.pid == last.pid && process.creation == last.creationFileTime;
    });
    const bool connected = target != capture.processes.end() && target->connected;
    const auto observed = [connected](bool value) { return !connected ? L"未核实" : value ? L"已确认" : L"未确认"; };
    if (connected) api.sourceSessionId = target->session;
    api.readyCoverageRevision = capture.readyCoverageRevision;
    // 复制原控制器的独立回执，不由连接、归档或 DLL 存在代替启动屏障。
    api.attachmentIdentityVerified = capture.attachmentIdentityVerified;
    api.agentLoadAttempted = capture.agentLoadAttempted;
    api.agentModuleVerified = capture.agentModuleVerified;
    api.agentReady = capture.started;
    if (capture.startup)
    {
        // 保留控制器冻结的最后启动阶段，不按清退阶段晚到的握手或安装包重新推导。
        api.startup = capture.startup;
    }

    api.details = std::wstring(L"连接 ") + (connected ? L"已核验" : L"未核实") +
        L" · 握手 " + observed(connected && target->sessionReady) +
        L" · 启动 " + (capture.started ? L"已确认" : L"未确认") +
        L" · 安装 Hook " + observed(connected && target->installed);
    api.details += std::wstring(L"\r\n正常 EOF ") + observed(connected && target->cleanPipeEof) +
        L" · 停钩 " + observed(connected && target->removed) + L" · 清退 " +
        (capture.configPublished ? (capture.cleanupComplete ? L"已确认" : L"未确认") : L"未发布配置") +
        (capture.cancelled ? L" · 已响应停止请求" : L"");
    if (target != capture.processes.end() && target->exited) api.details += L" · 目标已退出";
    if (!run.agentPathAvailable && run.sampleStatus) api.details += L"\r\n无法确定正式 Agent 路径";

    last.archive = run.sampleStatus ? run.archiveStatus : run.sampleStatus;
    bool prefixVerified = false; // 零线索或零普通包也可拥有已核验的终段。
    std::string readbackDiagnostic; // 读侧动态诊断有独立生存期，不放进项目错误码字段。
    const auto& flushed = run.archive.flushed; // 后段失败时仍指向最后发布的段。
    if (flushed && run.committedSegments) {
        api.sampleDescriptionHash = run.sample.descriptionHash; // 首次核验失败仍可按原样本重试。
        const auto replay = ReadProjectReplay({api.manifestPath, last.projectId, last.sampleId, api.sampleDescriptionHash});
        const auto& raw = replay.raw; // 字节端点、块号和序号都属于最后核验的实际段。
        const auto& checkpoint = replay.checkpoint; // 采样身份仍以 raw/1 为锚，段数取检查点。
        prefixVerified = raw.identity && checkpoint.kind == ReplayCheckpointKind::PassiveApi &&
            checkpoint.lastVerifiedOrdinal == run.committedSegments && raw.decodedPrefixBytes == flushed->byteOffset &&
            raw.lastBlockOrdinal == flushed->blockOrdinal && raw.lastSequence == flushed->lastSequence &&
            raw.apiClues == run.retainedClues && replay.apiSourcePackets == run.archivedPackets &&
            checkpoint.apiArchiveSource == Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe &&
            (!run.archiveStatus || checkpoint.state == CheckpointState::Verified);
        if (prefixVerified) {
            last.verifiedSegments = checkpoint.lastVerifiedOrdinal;
            last.finalCheckpoint = checkpoint.state == CheckpointState::Verified;
        } else {
            // 若二次读回只确认到更短前缀，使用实际读回水位并保留诊断。
            if (checkpoint.apiArchiveSource == Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe) {
                last.verifiedSegments = checkpoint.lastVerifiedOrdinal;
            }
            last.finalCheckpoint = false;
            if (last.archive) {
                last.archive = {Project::ProjectError::Corrupt, raw.systemError, "cooperativeApiReadbackBoundary"};
            }
            readbackDiagnostic = raw.diagnostic.empty() ? "cooperativeApiReadbackBoundary" : raw.diagnostic;
        }
    }
    const bool etwIncomplete = (api.captureAgentEtw && !run.etw) || (run.etw && run.etw->Incomplete()); // 独立ETW缺口不能显示成采样完成。
    const bool partial = etwIncomplete || capture.code == 6 || (prefixVerified && capture.code != 0) ||
        run.archivedPackets != run.ordinaryPackets || (capture.started && !last.archive);
    last.state = (capture.code == 0 || partial) ? LiveCaptureState::Stopped : LiveCaptureState::Failed;
    api.details = std::wstring(partial ? L"部分完成" : capture.code == 0 ? L"采样完成" : L"采样未完成") + L" · " + api.details;
    if (run.transferHandoff.type() != Ksword::Evidence::JsonType::Null)
    {
        api.details += ApiHandoffDetails(run.transferHandoff); // 两端共用分组字段，失败与执行观察独立呈现。
        api.details += L"\r\n自动接管原始回执=" + Utf8ToWide(Ksword::Evidence::WriteJson(run.transferHandoff)); // 同一正文保留完整可复核原文。
    }
    api.details += L"\r\n普通调用 " + std::to_wstring(run.ordinaryPackets) + L" · 已提交 " +
        std::to_wstring(run.archivedPackets) + L" 包 · 已保留线索 " + std::to_wstring(run.retainedClues) +
        L" · 线索未归档 " + std::to_wstring(run.omittedClues);
    api.details += ApiTransferProgress(run.transfers);
    if (prefixVerified) {
        api.details += L"\r\n已核验回读 " + std::to_wstring(run.retainedClues) + L" 条线索 · raw/" +
            std::to_wstring(last.verifiedSegments);
    } else if (flushed) {
        api.details += L"\r\n已刷盘，但未核验回读";
    } else {
        api.details += L"\r\n未归档";
    }
    // 终态替换正文时冻结原writer的完整窗口，失败仍保留此前已提交行为，不从归档重建。
    api.rules = std::make_shared<const Project::CooperativeApiRuleReceipt>(run.rules);
    api.details += ApiRuleProgress(*api.rules);
    if (connected) api.details += L"\r\nAgent 报告丢失 " + std::to_wstring(target->agentDropped) +
        (target->partialHooks ? L" · 部分 Hook" : L"");
    if (capture.invalidPackets) api.details += L" · 无效包 " + std::to_wstring(capture.invalidPackets);
    if (!capture.errors.empty()) api.details += L"\r\n" + capture.errors.front();
    if (!readbackDiagnostic.empty()) api.details += L"\r\n" + WideAscii(readbackDiagnostic);
}

// 以实际的已知值呈现读取结果。
template <typename T>
std::wstring DisplayNumber(const std::optional<T>& value) {
    return value ? std::to_wstring(*value) : L"—";
}

// 将共享 GUID 文本转换为归档使用的形式。
std::string ProviderId(const GUID& provider) {
    auto text = ks::r3::monitor::GuidToString(provider); // 系统 GUID 文本，仍含括号。
    if (text.size() != 38) {
        return {};
    }
    std::string result(36, '\0');
    std::transform(text.begin() + 1, text.end() - 1, result.begin(), [](wchar_t ch) {
        return static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + L'a' - L'A' : ch);
    });
    return result;
}

// 生成进程区间详情。PID 和创建时间来自同一冻结状态。
EvidenceRecord ProcessRow(const LiveProcessInterval& observation, const LiveCaptureStatus& capture) {
    EvidenceRecord row; // 区间是实时观察，没有归档记录类型。
    row.receiveQpc = observation.receiveQpc;
    const auto duration = observation.endTickMs - observation.beginTickMs; // 实际经过时间。
    row.preview = L"进程活动 · PID " + std::to_wstring(capture.pid) + L" · 创建 FILETIME " +
        std::to_wstring(capture.creationFileTime) + L"\r\n区间 " + std::to_wstring(duration) + L" ms · CPU " +
        std::to_wstring(observation.cpu100ns) + L" × 100 ns\r\n进程 I/O 读取 " + DisplayNumber(observation.readBytes) +
        L" B · 写入 " + DisplayNumber(observation.writeBytes) + L" B";
    if (observation.ioError != ERROR_SUCCESS) {
        row.preview += L" · Win32 " + std::to_wstring(observation.ioError);
    }
    return row;
}

// 保存原生 ETW 上下文的现有结果字段，以及已提交的归档坐标。
EvidenceRecord EtwRow(const LiveEtwObservation& observation) {
    const auto& record = observation.record; // 采集线程已经拥有的原始观察。
    EvidenceRecord row; // 表、详情和时间线共用的来源行。
    row.type = 3;
    row.schemaVersion = 1;
    row.segmentOrdinal = observation.segmentOrdinal.value_or(0);
    row.rawSequence = observation.rawSequence;
    row.receiveQpc = record.receivedQpc;
    row.headerPid = record.headerPid;
    row.headerTid = record.headerTid;
    row.payloadBytes = static_cast<std::uint32_t>(record.payloadPrefix.size());
    row.etw = Ksword::Evidence::ArchivedEtwObservation{ProviderId(record.provider), record.sourceEpoch,
        record.sourceFileTime100ns, record.receivedQpc, record.receivedQpc ? std::optional{record.qpcFrequencyHz} : std::nullopt,
        record.headerPid, record.headerTid, record.descriptor.id, record.descriptor.version, record.descriptor.opcode,
        record.originalPayloadBytes, record.malformedPayload};

    // 详情显示有限前缀及实际长度，以对应归档可取得的字节。
    row.preview = L"提供程序 " + WideAscii(row.etw->providerId) + L"\r\n来源代次 " + WideAscii(record.sourceEpoch) +
        L" · 原始 FILETIME " + std::to_wstring(record.sourceFileTime100ns) +
        L"\r\n报头 PID " + std::to_wstring(record.headerPid) + L" · TID " + std::to_wstring(record.headerTid) +
        L"\r\n源载荷 " + std::to_wstring(record.originalPayloadBytes) + L" B · 采到 " + std::to_wstring(row.payloadBytes) + L" B";
    if (record.malformedPayload) {
        row.preview += L" · 载荷异常";
    }
    constexpr wchar_t hex[] = L"0123456789abcdef"; // 有界字节预览的十六进制表。
    constexpr std::size_t previewBytes = 24; // 预览窗口不保留整条原始字节副本。
    if (!record.payloadPrefix.empty()) {
        row.preview += L"\r\n";
    }
    for (std::size_t i = 0; i < (std::min)(previewBytes, record.payloadPrefix.size()); ++i) {
        const auto byte = record.payloadPrefix[i]; // 精确本地前缀中的一个字节。
        row.preview += hex[byte >> 4];
        row.preview += hex[byte & 15];
        row.preview += L' ';
    }
    if (record.payloadPrefix.size() > previewBytes) {
        row.preview += L"…";
    }
    return row;
}

// 准备与现有归档表相同的列和稳定的实时行键。
Ui::VirtualListRow BuildRow(const EvidenceRecord& record, DWORD pid, std::size_t index) {
    Ui::VirtualListRow row; // 已格式化成可直接提交的原生表行。
    row.itemData = static_cast<LPARAM>(index);
    const auto sequence = std::to_wstring(record.sequence);
    row.stableKey = L"live/" + sequence;
    const auto name = record.etw ? L"ETW 事件 " + std::to_wstring(record.etw->eventId) + L" / v" +
        std::to_wstring(record.etw->version) : L"进程活动"; // 表与选中详情共享同一观察。
    row.cells = {DisplayNumber(record.receiveQpc), record.etw ? DisplayNumber(record.headerPid) : std::to_wstring(pid),
        DisplayNumber(record.headerTid), L"—", name, record.etw ? WideAscii(record.etw->providerId) : L"R3 进程计数",
        sequence};
    return row;
}

// 在工作线程冻结实际进程与项目身份。调用方负责显示结构化失败。
bool Freeze(const NativeLiveRequest& request, LiveCaptureRequest& frozen, LiveCaptureStatus& failure) {
    namespace Process = ks::r3::process;
    Process::ProcessIdentityEvidence check; // 导航底层已有的最小权限身份回读。
    failure.pid = request.pid;
    const auto creation = Process::QueryProcessCreationTimeR3(request.pid, 0, &check);
    if (!creation) {
        failure.processStage = "resolve-target";
        failure.processError = check.openError ? check.openError : check.timeError ? check.timeError : ERROR_INVALID_PARAMETER;
        return false;
    }
    frozen.pid = request.pid;
    frozen.creationFileTime = creation;
    if (request.provider) {
        frozen.etw.emplace();
        frozen.etw->provider = *request.provider;
    }
    if (request.project) {
        namespace Project = Ksword::ActionAnalyze;
        Project::ProjectDocument document; // 短暂读取当前项目修订，写入前由采集层重核。
        failure.archiveRequested = true;
        failure.archive = document.Open(request.project->manifestPath);
        if (!failure.archive) {
            return false;
        }
        const auto& info = *document.Info(); // 已验证清单的 UUID 与修订。
        if (info.projectId != request.project->projectId) {
            failure.archive = {Project::ProjectError::StaleRevision, 0, "lightProjectIdentity"};
            return false;
        }
        frozen.project = LiveCaptureProject{request.project->manifestPath, info.projectId, info.revisionId};
    }
    return true;
}

} // namespace

struct NativeLiveSession::Shared final : std::enable_shared_from_this<Shared> {
    mutable std::mutex mutex; // 保护 GUI 可读的状态、请求和一个待交付快照。
    std::condition_variable wake; // 停止、投影和清退重试共用唤醒入口。
    NativeLiveSnapshot status; // 与实时请求绑定的最新状态。
    std::optional<NativeLiveProjection> projection; // 只保留最新的完整投影。
    std::deque<EvidenceRecord> processRows, etwRows; // 仅采集线程更新的结果窗口。
    std::uint64_t sequence = 0; // 全窗口的唯一实时行序号。
    std::uint64_t evicted = 0; // 从实时预览移除的累计记录。
    std::uint64_t retryRevision = 0, attemptedRetry = 0; // 真实原生重试请求和完成代次。
    bool wantProjection = true; // 已合并的后台快照请求。
    bool projected = false; // 至少一次成功准备了可提交的窗口。
    bool dirty = true; // 当前预览有新行等待投影。
    bool retirementRegistered = false; // 清退失败时只在现有目录登记一次。
    std::atomic_bool stop{false}; // 同一停止意图交给合作采集器。

    // 返回当前已接受的停止意图。
    bool StopRequested() const {
        return stop.load();
    }

    // 请求后台推进并唤醒正在等待的线程。
    void RequestStop() {
        {
            std::lock_guard lock(mutex); // 关闭投递后准入不会恢复旧会话。
            stop = true;
        }
        wake.notify_all();
    }

    // 追加一条实时结果，分别执行两种来源的固定滑窗。
    void Push(std::deque<EvidenceRecord>& rows, std::size_t limit, EvidenceRecord row) {
        row.sequence = ++sequence;
        if (rows.size() == limit) {
            rows.pop_front();
            ++evicted;
        }
        rows.push_back(std::move(row));
        dirty = true;
    }

    // 在后台将来源滑窗合成同一个结果快照，按行身份保留原交付顺序。
    NativeLiveProjection BuildProjection(const LiveCaptureStatus& capture) {
        NativeLiveProjection next; // 一次交付同时提交证据与表格映射。
        auto& evidence = next.evidence;
        evidence.identity = SegmentIdentity{capture.projectId,
            capture.sampleId.empty() ? capture.sessionEpoch : capture.sampleId, 0, 0};
        evidence.rows.reserve(processRows.size() + etwRows.size());
        std::merge(processRows.begin(), processRows.end(), etwRows.begin(), etwRows.end(),
            std::back_inserter(evidence.rows), [](const auto& a, const auto& b) { return a.sequence < b.sequence; });
        auto rows = std::make_shared<std::vector<Ui::VirtualListRow>>(); // 现有虚拟表的共享数据。
        rows->reserve(evidence.rows.size());
        for (const auto& row : evidence.rows) {
            rows->push_back(BuildRow(row, capture.pid, rows->size()));
        }
        next.presentation = std::move(rows);
        evidence.records = static_cast<std::size_t>(sequence);
        return next;
    }

    // 发布一份工作线程的事实回执。投影构造位于短锁外。
    void Publish(LiveCaptureStatus capture, bool active = true) {
        bool build = false; // 用一次请求合并同一窗口的多次更新。
        {
            std::lock_guard lock(mutex);
            const bool requested = std::exchange(wantProjection, false);
            build = dirty && (requested || !active) &&
                !capture.sessionEpoch.empty() && capture.state != LiveCaptureState::Failed &&
                (projected || capture.state == LiveCaptureState::Running || sequence != 0);
        }
        std::optional<NativeLiveProjection> next; // 待提交的纯值对象。
        DWORD error = ERROR_SUCCESS; // 投影失败仍保留已取得的状态和采集职责。
        if (build) {
            try {
                next = BuildProjection(capture);
                projected = true;
                dirty = false;
            } catch (...) {
                error = ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        std::optional<NativeLiveProjection> previous; // 旧数据在锁外释放。
        {
            std::lock_guard lock(mutex);
            if (next) {
                previous = std::exchange(projection, std::move(next));
            }
            status = {std::move(capture), evicted, active, false, build ? error : status.projectionError, {}};
            status.cleanupPending = status.capture.state == LiveCaptureState::CleanupPending;
        }
        wake.notify_all();
    }

    // 吸收一次有界采集回执并发布最新状态。
    void Ingest(LiveCaptureUpdate update) {
        if (update.process) {
            Push(processRows, kProcessPreviewRows, ProcessRow(*update.process, update.status));
        }
        for (const auto& row : update.etw) {
            Push(etwRows, kEtwPreviewRows, EtwRow(row));
        }
        Publish(std::move(update.status));
    }

    // 通过原生后台登记转发显式重试，由原采集线程执行实际 STOP 和 CloseTrace。
    void RegisterCleanup() {
        if (retirementRegistered) {
            return;
        }
        const auto owner = shared_from_this(); // 清退职责可以长于页面。
        Ui::RunBackgroundRetirement([owner, first = true]() mutable {
            if (std::exchange(first, false)) {
                return false; // 当前已有明确失败，等用户从既有入口重试。
            }
            std::unique_lock lock(owner->mutex);
            if (!owner->status.active) {
                return true;
            }
            const auto revision = ++owner->retryRevision; // 一次原生尝试的身份。
            owner->wake.notify_all();
            owner->wake.wait(lock, [&] {
                return !owner->status.active || (owner->status.cleanupPending && owner->attemptedRetry >= revision);
            });
            return !owner->status.active;
        });
        retirementRegistered = true;
    }

    // 清退失败时停放本工作线程。投影请求仍可使用现有预览。
    LiveCaptureUpdate RetryCleanup(LiveCapture& capture, const LiveCaptureStatus& last) {
        RegisterCleanup();
        std::unique_lock lock(mutex);
        while (retryRevision <= attemptedRetry) {
            wake.wait(lock, [&] { return wantProjection || retryRevision > attemptedRetry; });
            if (wantProjection && retryRevision <= attemptedRetry) {
                lock.unlock();
                Publish(last);
                lock.lock();
            }
        }
        const auto revision = retryRevision; // 等待实际原生回执后才确认该代次。
        status.cleanupPending = false;
        status.capture.state = LiveCaptureState::Stopping;
        lock.unlock();
        auto update = capture.Stop(); // 同一个对象重新尝试释放原生资源。
        lock.lock();
        attemptedRetry = revision;
        return update;
    }

    // 在原采集worker执行冻结请求；启动事实同步发布为值快照，由既有页面回读，不另建会话或计时器。
    void RunCooperativeApi(const NativeLiveRequest& request) {
        namespace Project = Ksword::ActionAnalyze;
        namespace Process = ks::r3::process;
        NativeLiveSnapshot next;
        {
            std::lock_guard lock(mutex);
            next = status;
        }
        auto& last = next.capture;
        auto& api = *next.api;
        const auto& frozen = *request.project;
        Project::ProjectDocument project;
        Process::ProcessIdentityEvidence identity;
        last.state = LiveCaptureState::Failed;
        api.details = L"尚未启动 · 未归档";
        try {
            if (StopRequested()) {
                last.state = LiveCaptureState::Stopped;
            } else if (!request.api->launched && !Process::QueryProcessCreationTimeR3(request.pid, last.creationFileTime, &identity)) {
                api.details = identity.timeKnown ? L"目标 PID 与创建 FILETIME 不匹配 · 未归档" : L"无法读取目标身份 · 未归档";
                last.processStage = "cooperativeTargetIdentity";
                last.processError = identity.openError ? identity.openError : identity.timeError ? identity.timeError : ERROR_NOT_FOUND;
            } else if ((last.archive = project.Open(frozen.manifestPath, Project::ProjectAccess::ReadWrite))) {
                const auto& info = *project.Info();
                if (info.projectId != frozen.projectId || info.revisionId != frozen.revisionId) {
                    last.archive = {Project::ProjectError::StaleRevision, 0, "lightProjectIdentityOrRevision"};
                } else if (StopRequested()) {
                    last.state = LiveCaptureState::Stopped;
                } else {
                    const auto mode = request.api->explicitAttachment ? Project::ApiCaptureMode::ExplicitAttachment :
                        Project::ApiCaptureMode::CooperativeResident; // 用户确认的模式，不依赖合作标记或探测回退。
                    const auto title = request.api->launched ? std::string("Launched EXE API") :
                        std::string(request.api->explicitAttachment ? "Attached API / PID " :
                            "Cooperative API / PID ") + std::to_string(request.pid); // 本采样冻结标题，不伪造PID。
                    Project::CooperativeApiTransferReceipt latestTransfers; // 与最近成功发布的规则水位一同显示。
                    std::wstring committedApiDetails; // 已归档API摘要与活动接管状态分开，避免每次回调重复追加正文。
                    const Project::CooperativeApiReady ready = [this, &api](std::uint64_t session, std::uint64_t revision) {
                            // 回调在本工作线程同步执行，GUI 一次读到同一会话及其修订。
                            api.sourceSessionId = session;
                            api.readyCoverageRevision = revision;
                            api.agentReady = true; // 原Ready回调已核验同一管道及当前活动覆盖。
                            std::lock_guard lock(mutex);
                            status.api->sourceSessionId = session;
                            status.api->readyCoverageRevision = revision;
                            status.api->agentReady = true;
                            status.capture.state = LiveCaptureState::Running;
                        };
                    const Project::CooperativeApiCommitted committed = [&](const Project::SampleInfo& sample, const Project::ProjectApiCheckpoint& checkpoint,
                            const Project::CooperativeApiRuleReceipt& rules) {
                            // 同轮更新冻结身份和归档水位，保持活动与清退状态的原有所有权。
                            last.projectId = frozen.projectId;
                            last.sampleId = sample.sampleId;
                            last.verifiedSegments = checkpoint.ordinal;
                            last.finalCheckpoint = checkpoint.finalSegment;
                            api.sampleDescriptionHash = sample.descriptionHash;
                            api.details = L"已提交 " + std::to_wstring(checkpoint.lastSourceSequence) +
                                L" 包 · raw/" + std::to_wstring(checkpoint.ordinal);
                            if (checkpoint.finalSegment) api.details += L" · 终段已发布";
                            // 通知参数只在回调内借用；先复制完整有界回执再生成同版本详情。
                            api.rules = std::make_shared<const Project::CooperativeApiRuleReceipt>(rules);
                            api.details += ApiRuleProgress(*api.rules);
                            api.details += ApiTransferProgress(latestTransfers);
                            committedApiDetails = api.details;
                            api.details += ApiHandoffDetails(latestTransfers.handoff);
                            // 锁内一次发布，读取端不会把新水位和旧采样混用。
                            std::lock_guard lock(mutex);
                            status.capture.projectId = last.projectId;
                            status.capture.sampleId = last.sampleId;
                            status.capture.verifiedSegments = last.verifiedSegments;
                            status.capture.finalCheckpoint = last.finalCheckpoint;
                            status.api->sampleDescriptionHash = api.sampleDescriptionHash;
                            status.api->rules = api.rules; // 与水位、正文同锁发布，旧快照继续持有旧窗口。
                            status.api->details = api.details;
                        };
                    const Project::CooperativeApiTransferCommitted transferred = [&](const Project::CooperativeApiTransferReceipt& transfers) {
                            // 候选及接管快照都由同一worker通知；控制快照不冒充新的API归档水位。
                            latestTransfers = transfers;
                            if (!transfers.handoff.isNull())
                            {
                                api.details = committedApiDetails + ApiHandoffDetails(transfers.handoff);
                                {
                                    std::lock_guard lock(mutex); // 页面只读取同一冻结快照，不访问控制器。
                                    status.api->details = api.details;
                                    if (transfers.handoffSample)
                                    {
                                        last.projectId = frozen.projectId;
                                        last.sampleId = transfers.handoffSample->sampleId;
                                        status.capture.projectId = last.projectId;
                                        status.capture.sampleId = last.sampleId;
                                        api.sampleDescriptionHash = transfers.handoffSample->descriptionHash;
                                        status.api->sampleDescriptionHash = api.sampleDescriptionHash;
                                    }
                                }
                            }
                        };
                    const Project::CooperativeApiStartup startupProgress = [&](const ks::winapi_monitor::CaptureStartupProgress& startup) {
                            // 只在阶段快照变化时搬运事实，Ready仍只由原onReady回调确认。
                            if (api.startup == startup)
                            {
                                return;
                            }
                            api.startup = startup;
                            api.attachmentIdentityVerified = startup.attachmentIdentityVerified;
                            api.agentLoadAttempted = startup.agentLoadAttempted;
                            api.agentModuleVerified = startup.agentModuleVerified;
                            // 同一把锁发布整组启动字段，旧归档及当前采样身份均不在此处改写。
                            std::lock_guard lock(mutex); // 与页面ReadStatus同步值快照。
                            status.api->startup = api.startup;
                            status.api->attachmentIdentityVerified = api.attachmentIdentityVerified;
                            status.api->agentLoadAttempted = api.agentLoadAttempted;
                            status.api->agentModuleVerified = api.agentModuleVerified;
                        };
                    Project::CooperativeApiReceipt run; // 原worker唯一项目写者，启动与采集按序执行。
                    if (request.api->launched)
                    {
                        const auto launched = Project::CaptureLaunchedApi(project,
                            {request.api->executable, request.api->entryRva, request.api->durationMs, title,
                                frozen.revisionId, request.api->autoTransfer, request.api->networkTraffic, request.api->captureAgentEtw}, stop,
                            ready, committed, transferred, startupProgress, [&](const Project::LaunchedApiProgress& progress) {
                                if (progress.launch)
                                {
                                    last.pid = progress.launch->pid;
                                    last.creationFileTime = progress.launch->creationFileTime;
                                }
                                api.launchProgress = Utf8ToWide(Ksword::Evidence::WriteJson(Project::LaunchedApiProgressJson(progress)));
                                std::lock_guard lock(mutex); // UI只读事实快照，不查询当前PID。
                                status.capture.pid = last.pid;
                                status.capture.creationFileTime = last.creationFileTime;
                                status.api->launchProgress = api.launchProgress;
                            });
                        run = launched.api;
                        if (launched.error)
                        {
                            last.processStage = launched.stage;
                            last.processError = launched.error;
                        }
                    }
                    else
                    {
                        run = Project::CaptureCooperativeApi(project,
                            {last.pid, last.creationFileTime, request.api->durationMs, title, frozen.revisionId, request.api->captureAgentEtw, mode,
                                {}, request.api->autoTransfer, request.api->networkTraffic}, stop,
                            ready, committed, transferred, startupProgress);
                    }
                    if (request.api->networkTraffic || run.networkTraffic)
                    {
                        // 原采集Close后搬运同采样网络回执；页面不重新查询现场或按API结果补造网络状态。
                        api.networkTraffic = Utf8ToWide(Ksword::Evidence::WriteJson(Project::ApiCaptureNetworkJson(run.networkTraffic)));
                    }
                    last.projectId = frozen.projectId;
                    if (last.sampleId.empty()) last.sampleId = run.sample.sampleId;
                    project.Close(); // 交还写租约后通过正常项目读侧重新核验。
                    if (request.api->captureAgentEtw || run.etw)
                    {
                        // 原采集已Close；全文保留setup/archive/checkpoint及Incomplete，页面沿原详情复制导出。
                        api.agentEtw = Utf8ToWide(Ksword::Evidence::WriteJson(Project::ApiCaptureEtwJson(run.etw)));
                    }
                    ApplyCooperativeReceipt(next, run);
                    if (last.processError)
                    {
                        last.state = LiveCaptureState::Failed; // 默认空管道回执不能把启动故障投影为成功。
                    }
                }
            }
        } catch (...) {
            last.state = LiveCaptureState::Failed;
            last.archive = {Project::ProjectError::IoError, ERROR_GEN_FAILURE, "lightCooperativeApiWorker"};
        }
        project.Close();
        next.active = false;
        std::lock_guard lock(mutex);
        status = std::move(next);
    }

    // 不打开源进程；只由这一工作线程持有文件游标和项目写租约。
    void RunApi(const NativeLiveRequest& request) {
        namespace Project = Ksword::ActionAnalyze;
        const auto& source = *request.api;
        const auto& frozen = *request.project;
        NativeLiveSnapshot next;
        auto& last = next.capture;
        next.api.emplace();
        next.api->manifestPath = frozen.manifestPath;
        next.api->sourcePath = source.path;
        next.api->sourceSessionId = source.sessionIdentity;
        last.pid = request.pid;
        last.creationFileTime = source.creationFileTime;
        last.archiveRequested = true;
        const auto publish = [&](bool active) {
            next.active = active;
            auto snapshot = next;
            std::lock_guard lock(mutex);
            status = std::move(snapshot);
        };

        Project::ProjectDocument project;
        std::optional<Passive::PassiveApiCapture> capture(std::in_place);
        bool begun = false;
        bool finished = false;
        const auto finish = [&](std::string_view reason) {
            finished = true; // Finish 可能推进持久边界，同一次调用异常后不重试写入。
            capture->Finish(project, last.sampleId, reason);
        };
        try {
            if (StopRequested()) {
                last.state = LiveCaptureState::Stopped;
            } else {
                const int size = static_cast<int>(source.path.size());
                const int bytes = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                    source.path.data(), size, nullptr, 0, nullptr, nullptr);
                std::string path(static_cast<std::size_t>(bytes), '\0');
                if (bytes <= 0 || !::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                        source.path.data(), size, path.data(), bytes, nullptr, nullptr)) {
                    last.archive = {Project::ProjectError::InvalidArgument, ::GetLastError(), "apiArchivePathEncoding"};
                } else {
                    last.archive = project.Open(frozen.manifestPath, Project::ProjectAccess::ReadWrite);
                }
                if (!last.archive) last.state = LiveCaptureState::Failed;
                else if (StopRequested()) last.state = LiveCaptureState::Stopped;
                else {
                    Project::SampleInfo sample;
                    Passive::PassiveApiStartStage stage{};
                    const auto title = "Passive API / PID " + std::to_string(request.pid);
                    last.archive = capture->BeginProject(project, {path, frozen.projectId, frozen.revisionId, title,
                        {source.sessionIdentity, static_cast<std::uint32_t>(request.pid), source.creationFileTime}, 0},
                        sample, last.sessionEpoch, stage);
                    if (!last.archive) last.state = LiveCaptureState::Failed;
                    else {
                        last.sampleId = std::move(sample.sampleId);
                        begun = true;
                        last.projectId = frozen.projectId;
                        next.api->sampleDescriptionHash = std::move(sample.descriptionHash);
                        last.state = LiveCaptureState::Running;
                        std::string_view reason = "requested";
                        while (!StopRequested()) {
                            if (!capture->Tick(project, last.sampleId)) {
                                reason = capture->FailureReason();
                                break;
                            }
                            next.api->details = ApiReceiptText(*capture, last.verifiedSegments);
                            publish(true);
                            std::unique_lock lock(mutex);
                            wake.wait_for(lock, LiveCapture::kPollInterval, [&] { return StopRequested(); });
                        }
                        last.state = LiveCaptureState::Stopping;
                        publish(true);
                        finish(reason);
                        last.state = capture->Incomplete() ? LiveCaptureState::Failed : LiveCaptureState::Stopped;
                        next.api->details = ApiReceiptText(*capture, last.verifiedSegments);
                    }
                }
            }
        } catch (...) {
            if (begun && !finished) {
                try { finish("worker-error"); } catch (...) {}
            }
            last.state = LiveCaptureState::Failed;
            last.archive = {Project::ProjectError::IoError, ERROR_GEN_FAILURE, "lightApiWorker"};
        }
        capture.reset();
        project.Close();
        publish(false);
    }

    // 推进活动会话。原生句柄的所有方法始终由当前线程串行调用。
    void Run(const NativeLiveRequest& request) {
        LiveCapture capture; // 当前工作的唯一采集对象。
        LiveCaptureRequest frozen; // 工作线程核对后的真实查询目标。
        LiveCaptureStatus last; // 采集和失败回执。
        try {
            if (!Freeze(request, frozen, last)) {
                last.state = LiveCaptureState::Failed;
                Publish(std::move(last), false);
                return;
            }
            if (StopRequested()) {
                capture.RequestStop();
            }
            last = capture.Start(frozen);
            Publish(last);
            while (last.state != LiveCaptureState::Stopped && last.state != LiveCaptureState::Failed) {
                const bool stopping = StopRequested(); // 本轮是否已有停止请求。
                if (stopping) {
                    capture.RequestStop();
                }
                auto update = last.state == LiveCaptureState::CleanupPending ? RetryCleanup(capture, last) : capture.Poll();
                last = update.status;
                Ingest(std::move(update));
                if (last.state == LiveCaptureState::Running && !stopping) {
                    std::unique_lock lock(mutex); // 只有活动间隙需要等待下一轮。
                    wake.wait_for(lock, LiveCapture::kPollInterval, [&] { return StopRequested() || wantProjection; });
                }
            }
        } catch (...) {
            // 后台投影或请求失败后仍回读采集并清退同一对象。
            auto update = capture.Stop();
            while (update.status.state == LiveCaptureState::Stopping ||
                   update.status.state == LiveCaptureState::CleanupPending) {
                if (update.status.state == LiveCaptureState::CleanupPending) {
                    Publish(update.status);
                    update = RetryCleanup(capture, update.status);
                } else {
                    update = capture.Poll();
                }
            }
            last = std::move(update.status);
            last.state = LiveCaptureState::Failed;
            last.processStage = "live-worker";
            last.processError = ERROR_GEN_FAILURE;
        }
        Publish(std::move(last), false);
    }
};

NativeLiveSession::~NativeLiveSession() {
    BeginRetirement();
}

DWORD NativeLiveSession::Start(NativeLiveRequest request) {
    if (retiring_ || !Ready()) {
        return ERROR_BUSY;
    }
    // 所有输入均为页面冻结值。严格附加必须独立确认，不能落入文件或合作准入。
    bool invalidApi = false; // 合并同一请求的即时准入结果，不进行系统查询或装载。
    if (request.api) {
        const auto& source = *request.api; // 本次来源模式与强实例参数。
        const bool live = source.cooperative || source.explicitAttachment || source.launched; // 三种活采共用原worker。
        invalidApi = request.provider.has_value() || !request.project || (!source.launched && !source.creationFileTime) ||
            (source.launched && (source.cooperative || source.explicitAttachment || source.attachmentConfirmed ||
                source.executable.empty() || source.creationFileTime || request.pid)) ||
            (!source.launched && (!source.executable.empty() || source.entryRva.has_value())) ||
            (source.explicitAttachment && (!source.attachmentConfirmed || source.cooperative)) ||
            (!source.explicitAttachment && source.attachmentConfirmed);
        if (live) {
            invalidApi = invalidApi || (!source.launched && (request.pid <= 4 || request.pid == ::GetCurrentProcessId())) ||
                !source.path.empty() || source.sessionIdentity != 0 ||
                (source.durationMs != 0 && (source.durationMs < 1000 || source.durationMs > 120000));
        } else {
            invalidApi = invalidApi || source.path.empty() || !source.sessionIdentity || source.durationMs != 0 ||
                source.networkTraffic.has_value() || source.captureAgentEtw; // JSONL只跟随文件，不启用网络或配套ETW源。
        }
    }
    if ((!request.pid && !(request.api && request.api->launched)) || invalidApi || (!request.api && request.project && !request.provider)) {
        return ERROR_INVALID_PARAMETER;
    }
    try {
        const auto lease = Ui::TryAcceptBackgroundWork(); // 与现有关闭协调器共享准入和计数。
        if (!lease) {
            return ERROR_OPERATION_ABORTED;
        }
        auto next = std::make_shared<Shared>(); // 线程只捕获稳定的会话值和请求。
        next->status.active = true;
        next->status.capture.pid = request.pid;
        if (request.api) {
            next->status.capture.creationFileTime = request.api->creationFileTime;
            next->status.api = NativeLiveApiReceipt{request.project->manifestPath, request.api->path,
                request.api->sessionIdentity, {}, {}, request.api->cooperative, {}};
            next->status.api->explicitAttachment = request.api->explicitAttachment;
            next->status.api->durationMs = request.api->durationMs;
            next->status.api->launched = request.api->launched;
            next->status.api->executable = request.api->executable;
            next->status.api->captureAgentEtw = request.api->captureAgentEtw; // 启动失败仍保留本轮策略。
        }
        std::thread([next, lease, request = std::move(request)] {
            try {
                if (request.api && (request.api->cooperative || request.api->explicitAttachment || request.api->launched))
                {
                    next->RunCooperativeApi(request); // 启动来源仍沿本端唯一worker串行写入项目。
                }
                else if (request.api)
                {
                    next->RunApi(request);
                }
                else
                {
                    next->Run(request);
                }
            } catch (...) {
                std::lock_guard lock(next->mutex);
                next->status.active = false;
                next->status.capture.state = LiveCaptureState::Failed;
                next->status.capture.processStage = "live-worker";
                next->status.capture.processError = ERROR_GEN_FAILURE;
                next->wake.notify_all();
            }
        }).detach();
        session_ = std::move(next);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

void NativeLiveSession::Stop() {
    if (session_) {
        session_->RequestStop();
        if (ReadStatus().cleanupPending) {
            Ui::BackgroundWorkRegistry::global().retry(true);
        }
    }
}

void NativeLiveSession::BeginRetirement() {
    retiring_ = true;
    if (session_) {
        session_->RequestStop();
    }
}

bool NativeLiveSession::Ready() const {
    if (!session_) {
        return true;
    }
    std::lock_guard lock(session_->mutex); // GUI 只回读工作线程的状态。
    return !session_->status.active;
}

void NativeLiveSession::CancelRetirement() {
    retiring_ = false;
}

void NativeLiveSession::RequestProjection() {
    if (!session_) {
        return;
    }
    {
        std::lock_guard lock(session_->mutex); // 一个布尔位合并同一窗口的多个刷新请求。
        session_->wantProjection = session_->status.active;
    }
    session_->wake.notify_all();
}

std::optional<NativeLiveProjection> NativeLiveSession::TakeProjection() {
    if (!session_) {
        return {};
    }
    std::lock_guard lock(session_->mutex); // 最新完整预览一次性交付给 GUI。
    return std::exchange(session_->projection, {});
}

NativeLiveSnapshot NativeLiveSession::ReadStatus() const {
    if (!session_) {
        return {};
    }
    std::lock_guard lock(session_->mutex); // 单次读取保留同一版本的状态和统计。
    return session_->status;
}

std::wstring FormatLiveStatus(const NativeLiveSnapshot& status) {
    const auto& capture = status.capture; // 本次已确认的目标和可用来源。
    if (status.api) {
        if (status.api->cooperative || status.api->explicitAttachment || status.api->launched) {
            std::wstring text = status.api->launched ? L"EXE 启动采集 · " : status.api->explicitAttachment ? L"显式 API 附加 · " : L"合作 Agent · ";
            if (status.active) text += status.api->agentReady ? L"采集中 · " : L"等待就绪核验 · ";
            if (capture.pid && capture.creationFileTime)
            {
                text += L"PID " + std::to_wstring(capture.pid) + L" · 创建 FILETIME " + std::to_wstring(capture.creationFileTime);
            }
            else
            {
                text += L"等待创建进程实例"; // 创建前不把空手填PID或零值显示成已核验实例。
            }
            if (const auto& startup = status.api->startup) // 当前运行或终态均沿用同一份最后已确认快照。
            {
                text += std::wstring(L"\r\n最后确认的启动阶段：") + StartupStageText(startup->stage);
                text += L" · " + std::to_wstring(startup->elapsedMs) + L" ms";
            }
            if (status.api->launched)
            {
                text += L"\r\n启动 EXE：" + status.api->executable;
                text += L"\r\n入口交接回执：" + status.api->launchProgress; // 两端同一规范文档，复制导出保留完整字段。
            }
            if (status.api->explicitAttachment || status.api->launched) {
                // 运行回调确认的真值立即显示；未完成字段等待终态，不借旧结果补齐。
                const auto fact = [&](bool value) {
                    return !value && status.active ? L"等待最终回执" : value ? L"是" : L"否";
                }; // 运行时默认false是尚未发布，不能显示成已核实的否。
                text += std::wstring(L"\r\n附加实例已核验：") + fact(status.api->attachmentIdentityVerified) +
                    L"\r\n已尝试装载 Agent：" + fact(status.api->agentLoadAttempted) +
                    L"\r\nAgent 模块已核验：" + fact(status.api->agentModuleVerified);
            }
            text += std::wstring(L"\r\nAgent 已就绪：") + (status.api->agentReady ? L"是" : L"否");
            text += L"\r\n采集时限（毫秒，0 为持续）：" + std::to_wstring(status.api->durationMs);
            if (status.api->sourceSessionId) text += L"\r\n源会话 " + std::to_wstring(status.api->sourceSessionId);
            if (status.api->readyCoverageRevision) {
                text += L" · 就绪覆盖修订 " + std::to_wstring(*status.api->readyCoverageRevision);
            }
            if (!capture.sampleId.empty()) text += L"\r\n采样 " + WideAscii(capture.sampleId);
            if (!status.api->details.empty()) text += L"\r\n" + status.api->details;
            if (!status.api->networkTraffic.empty())
            {
                // 原详情与搜索/复制共用规范全文，网络失败和空结果均按后端回执呈现。
                text += L"\r\n同采样网络回执：\r\n" + status.api->networkTraffic;
            }
            text += std::wstring(L"\r\n采集自有 Agent ETW：") + (status.api->captureAgentEtw ? L"是" : L"否");
            if (!status.api->agentEtw.empty())
            {
                text += L"\r\n同采样 ETW 回执：\r\n" + status.api->agentEtw; // ETW独立结果沿现有全文详情展示。
            }
            if (!capture.archive) text += L"\r\n" + WideAscii(Ksword::ActionAnalyze::ProjectErrorName(capture.archive.error)) +
                L" · " + WideAscii(capture.archive.detail) + L" · Win32 " + std::to_wstring(capture.archive.nativeError);
            if (capture.processError) text += L"\r\n" + WideAscii(capture.processStage) +
                L" · Win32 " + std::to_wstring(capture.processError);
            return text;
        }
        const wchar_t* state = L"正在打开已授权文件";
        switch (capture.state) {
        case LiveCaptureState::Running: state = L"正在跟随文件"; break;
        case LiveCaptureState::Stopping: state = L"正在停止并归档"; break;
        case LiveCaptureState::Stopped: state = L"已停止"; break;
        case LiveCaptureState::Failed: state = L"失败或部分完成"; break;
        default: break;
        }
        std::wstring text = std::wstring(L"被动 API · ") + state + L" · 活连接与覆盖未核实";
        if (!capture.sampleId.empty()) text += L" · 采样 " + WideAscii(capture.sampleId);
        text += L"\r\n源会话 " + std::to_wstring(status.api->sourceSessionId) + L" · PID " + std::to_wstring(capture.pid) +
            L" · 创建 FILETIME " + std::to_wstring(capture.creationFileTime);
        if (!capture.archive) text += L"\r\n" + WideAscii(Ksword::ActionAnalyze::ProjectErrorName(capture.archive.error)) +
            L" · " + WideAscii(capture.archive.detail) + L" · Win32 " + std::to_wstring(capture.archive.nativeError);
        if (capture.processError) text += L"\r\n后台执行失败 · Win32 " + std::to_wstring(capture.processError);
        if (!status.api->details.empty()) text += L"\r\n" + status.api->details;
        return text;
    }
    if (!capture.pid) {
        return {};
    }
    std::wstring text = L"PID " + std::to_wstring(capture.pid) + L" · "; // 固定显示当前会话目标。
    switch (capture.state) {
    case LiveCaptureState::Idle: text += L"正在核验目标"; break;
    case LiveCaptureState::Running: text += L"采集中"; break;
    case LiveCaptureState::Stopping: text += L"正在清退"; break;
    case LiveCaptureState::CleanupPending: text += L"ETW 清退失败，可重试"; break;
    case LiveCaptureState::Stopped: text += L"已停止"; break;
    case LiveCaptureState::Failed: text += L"采集失败"; break;
    }
    if (capture.end == LiveCaptureEnd::TargetExited) {
        text += L" · 目标已退出";
    }
    if (capture.creationFileTime) {
        text += L" · 创建 " + std::to_wstring(capture.creationFileTime);
    }
    if (capture.processError) {
        text += L" · " + WideAscii(capture.processStage) + L" / Win32 " + std::to_wstring(capture.processError);
    }
    text += L"\r\n进程区间 " + std::to_wstring(capture.processIntervals) + L" · ETW " + std::to_wstring(capture.etwObserved) +
        L" · 预览移出 " + std::to_wstring(status.previewEvicted);
    if (capture.etw) {
        namespace Etw = ks::r3::monitor;
        const auto& source = *capture.etw; // ETW 独立于进程采集报告覆盖。
        if (source.state == Etw::PassiveEtwState::Starting) {
            text += L" · ETW 启动中";
        } else if (source.state == Etw::PassiveEtwState::CleanupPending) {
            const auto& native = source.native;
            if (!native.stopStatuses.empty()) text += L" · STOP " + std::to_wstring(native.stopStatuses.back());
            if (native.closeAttempted) text += L" · CloseTrace " + std::to_wstring(native.closeStatus);
        } else if (source.state == Etw::PassiveEtwState::AccessDenied || source.state == Etw::PassiveEtwState::Failed ||
            source.state == Etw::PassiveEtwState::ProviderUnavailable) {
            const auto code = source.inputError ? source.inputError : !source.native.providers.empty() &&
                source.native.providers.front().status != ERROR_SUCCESS ? source.native.providers.front().status :
                source.native.startStatus ? source.native.startStatus : source.native.openStatus ? source.native.openStatus :
                source.native.processStatus; // 按实际失败阶段取原始回执。
            text += L" · ETW 不可用（Win32 " + std::to_wstring(code) + L"）";
        }
        text += L" · 队列丢弃 " + std::to_wstring(source.queueDropped);
        if (source.native.statisticsKnown) {
            text += L" · ETW 丢失 " + std::to_wstring(source.native.eventsLost);
        } else {
            text += L" · ETW 丢失未知";
        }
    }
    if (capture.archiveRequested) {
        text += L" · 已提交 " + std::to_wstring(capture.verifiedSegments) + L" 段";
        if (capture.finalCheckpoint) {
            text += L" · 终段已发布";
        } else if (!capture.archive) {
            text += L" · 归档失败 " + WideAscii(capture.archive.detail) + L" / Win32 " + std::to_wstring(capture.archive.nativeError);
        }
    }
    if (status.projectionError) {
        text += L" · 预览准备失败";
    }
    return text;
}

} // namespace Ksword::Features::ActionAnalyze
