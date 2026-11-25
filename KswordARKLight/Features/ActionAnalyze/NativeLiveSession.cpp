#include "NativeLiveSession.h"

#include "../../Ui/BackgroundWork.h"
#include "../../../shared/usermode/backend/process/ProcessNavigationIdentity.h"

#include <algorithm>
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
    bool stop = false; // GUI 写入的协作停止意图。

    // 返回当前已接受的停止意图。
    bool StopRequested() const {
        std::lock_guard lock(mutex); // 从同一线程安全状态读回。
        return stop;
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
            status = {std::move(capture), evicted, active, false, build ? error : status.projectionError};
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
                    wake.wait_for(lock, LiveCapture::kPollInterval, [&] { return stop || wantProjection; });
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
    if (!request.pid || (request.project && !request.provider)) {
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
        std::thread([next, lease, request = std::move(request)] {
            try {
                next->Run(request);
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
