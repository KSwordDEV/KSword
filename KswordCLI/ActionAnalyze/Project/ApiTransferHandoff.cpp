#include "ApiTransferHandoff.h"
#include "ApiTransferAgentCapture.h"
#include "ProjectStorage.h"
#include "../Control/OwnedExecutionGroup.h"
#include <sddl.h>
#include <algorithm>
#include <map>
#include <new>
#include <deque>

namespace Ksword::ActionAnalyze {
namespace {
namespace n = ks::cli::action_analyze::control;
namespace m = ks::winapi_monitor;
using V = Evidence::JsonValue;
using ProjectStorage::Handle;

bool PipeSecurity(PSECURITY_DESCRIPTOR* out)
{
    // 输出仅当前用户及SYSTEM可连接的ACL；描述符由调用方LocalFree。
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    Handle token(raw);
    DWORD bytes = 0;
    GetTokenInformation(raw, TokenUser, nullptr, 0, &bytes);
    std::vector<unsigned char> buffer(bytes);
    if (!bytes || !GetTokenInformation(raw, TokenUser, buffer.data(), bytes, &bytes)) return false;
    wchar_t* sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) return false;
    const auto acl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, out, nullptr) != FALSE;
}
bool Covered(const n::ExecutionGroupMember& member, std::uint64_t base, std::uint64_t bytes)
{
    // 输入同owner回读及完整范围，核对原NX绑定；不把请求已接受当作Armed。
    if (!member.control.attached || !member.control.breakpoint || member.control.firstRecoveryFailure ||
        member.control.pid != member.site.pid || member.control.processCreationTime != member.site.creationFileTime ||
        member.owner.backendInstanceId.empty() || member.owner.sessionId.empty()) return false;
    const auto& binding = *member.control.breakpoint;
    if (binding.state != n::NativeBreakpointState::Armed && binding.state != n::NativeBreakpointState::Held) return false;
    if (!bytes || base > UINT64_MAX - bytes) return false; // 覆盖判断只接受可表示的非空半开区间。
    return std::any_of(binding.executionRanges.begin(), binding.executionRanges.end(), [&](const auto& range) {
        return base >= range.base && base - range.base <= range.bytes && bytes <= range.bytes - (base - range.base);
    });
}
DWORD VerifyArmedRange(HANDLE process, const n::ExecutionGroupMember& member, std::uint64_t base, std::uint64_t bytes)
{
    // ACK前重读整段当前内存状态；旧owner登记和同地址的新分配都不能代替实际NX保护。
    const auto& ranges = member.control.breakpoint->executionRanges;
    const auto binding = std::find_if(ranges.begin(), ranges.end(), [&](const auto& range) {
        return base >= range.base && base - range.base <= range.bytes && bytes <= range.bytes - (base - range.base);
    });
    if (binding == ranges.end()) return ERROR_INVALID_STATE;
    for (auto address = base; address < base + bytes;) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(address), &memory, sizeof(memory))) return GetLastError();
        const auto region = reinterpret_cast<std::uint64_t>(memory.BaseAddress);
        if (memory.State != MEM_COMMIT || memory.Type != MEM_PRIVATE || !memory.RegionSize ||
            region > address || memory.RegionSize > UINT64_MAX - region ||
            region + memory.RegionSize <= address ||
            reinterpret_cast<std::uint64_t>(memory.AllocationBase) != binding->allocationBase ||
            (memory.Protect & PAGE_GUARD))
            return ERROR_INVALID_STATE;
        if (memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        {
            // 同一范围的前一次命中正在内部TF推进时，NX暂时开放且同伴仍由原owner暂停。
            // 新调用保持在Hook屏障内，等原owner关回NX再核对；不把暂开窗口当成旧ACK失效后放行。
            const auto& advance = member.control.pageAdvance; // 只采用本次真实owner的运行状态。
            return advance && advance->receipt.state == n::NativeStepState::Running &&
                !advance->receipt.resourcesRestored ? ERROR_IO_PENDING : ERROR_INVALID_STATE;
        }
        address = std::min(base + bytes, region + static_cast<std::uint64_t>(memory.RegionSize));
    }
    return ERROR_SUCCESS;
}
}

class ApiTransferHandoff::Impl {
public:
    ProjectDocument& project; // 借用原采集writer，所有归档均在该worker执行。
    std::string sample; // 本轮采样身份，目标owner沿用同一sample。
    DWORD sourcePid; // 原主capture已认证来源，递归来源另按真实Ready登记。
    std::uint64_t sourceCreation; // 来源创建时间，防止PID复用。
    std::uint64_t originalSession = 0, originalRevision = 0;
    bool originalReady = false, originalEnded = false;
    const std::atomic_bool& cancel; // 原采集取消位，不新建停止任务。
    m::InjectionEndpoint endpoint; // 本轮独立的同步交接端点。
    HANDLE pipe = INVALID_HANDLE_VALUE;
    OVERLAPPED io{};
    enum class Phase { Connect, Read, Reply, Release } phase = Phase::Connect;
    bool pending = false, immediate = false, started = false, closing = false;
    DWORD immediateBytes = 0, setupError = 0, lastError = 0;
    DWORD firstPipeError = 0;
    std::uint64_t pipeFailures = 0;
    ULONGLONG ioStarted = 0;
    m::TransferHandoffRequest request{};
    m::TransferHandoffResponse response{};
    n::OwnedExecutionGroup group; // 自动发现成员的唯一集合及原恢复责任。
    n::ExecutionGroupResult current; // 最近原owner回读，不接受外来反序列化控制。
    std::uint64_t requests = 0, armed = 0, rejected = 0, saved = 0;
    std::uint64_t nativeOrdinal = 0;
    std::optional<std::uint64_t> previousSequence;
    ProjectResult archiveStatus;
    std::map<std::string, n::NativeEventKey> observed;
    std::map<std::string, bool> failedOwnerRecovery; // 已发单成员清退的原owner，后续仅回读，不反复提交Close。
    std::wstring agentPath; // 主capture使用的同一产品Agent路径，不另接受用户DLL参数。
    SourcePacket onPacket; // 借原worker合并到唯一API归档流。
    TargetDiscovered onTarget; // 同一worker登记网络目标，不等待目标首个API包。
    struct Source {
        DWORD pid = 0;
        std::uint64_t creation = 0, session = 0, revision = 0, dropped = 0, deliveryDropped = 0;
        bool ready = false, ended = false, failed = false;
        bool stopping = false; // 已请求停止的采集器只排空尾包，不再授予来源认证或Ready资格。
        DWORD error = 0;
        std::deque<ks::winapi_monitor::ApiMonitorEventPacket> pendingPackets; // Ready前暂存已验包，Ready后按原序交付。
        std::optional<m::CaptureStartupProgress> startup;
        std::optional<m::CaptureResult> result;
        std::unique_ptr<ApiTransferAgentCapture> capture;
    };
    std::map<DWORD, Source> sources; // 每个强实例仅一份控制器；原来源不重装、不申请第二会话。
    enum class Admission { Initial, Armed, Paused, Running, Agent, Done };
    struct Transfer {
        m::TransferHandoffRequest request;
        DWORD source = 0, error = ERROR_IO_PENDING;
        std::uint64_t base = 0, bytes = 0;
        ULONGLONG started = 0;
        Handle target; // 保留从准入到ACK的真实目标对象。
        Admission stage = Admission::Initial;
        bool ownPause = false;
        std::string pauseRequestId; // 只结清本次主动暂停票据，不按ManualPause标签释放其它请求。
        V entryObservation = V::makeNull(); // 精确请求入口的首份已核验执行坐标，不借用同进程最后一个停点。
    };
    std::deque<Transfer> transfers; // 处理中请求与终态短窗口；Hook重连不会重复建owner。
    bool callbackFailed = false;

    Impl(ProjectDocument& p, std::string s, DWORD pid, std::uint64_t creation, const std::atomic_bool& c,
        const std::wstring& path, SourcePacket packets, TargetDiscovered targets)
        : project(p), sample(std::move(s)), sourcePid(pid), sourceCreation(creation), cancel(c),
          agentPath(path), onPacket(std::move(packets)), onTarget(std::move(targets)) {}
    ~Impl() { ClosePipe(); if (io.hEvent) CloseHandle(io.hEvent); }

    void PipeFailure(DWORD error)
    {
        lastError = error;
        if (!firstPipeError) firstPipeError = error;
        ++pipeFailures;
    }

    void ClosePipe()
    {
        // 取消并排空当前overlapped操作后关闭；不让栈上缓冲仍被内核使用。
        if (pipe == INVALID_HANDLE_VALUE) return;
        if (pending) {
            CancelIoEx(pipe, &io);
            DWORD ignored = 0;
            GetOverlappedResult(pipe, &io, &ignored, TRUE);
        }
        pending = immediate = false;
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        pipe = INVALID_HANDLE_VALUE;
    }
    void Begin(Phase next)
    {
        // 沿同一事件驱动Connect→Read→Reply，不创建专门的轮询线程。
        phase = next;
        const auto event = io.hEvent;
        io = {};
        io.hEvent = event;
        ResetEvent(io.hEvent);
        pending = immediate = false;
        DWORD bytes = 0;
        const BOOL ok = next == Phase::Connect ? ConnectNamedPipe(pipe, &io) : next == Phase::Read
            ? ReadFile(pipe, &request, sizeof(request), &bytes, &io)
            : WriteFile(pipe, &response, sizeof(response), &bytes, &io);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (ok || (next == Phase::Connect && error == ERROR_PIPE_CONNECTED)) {
            immediate = true; immediateBytes = bytes;
        } else if (error == ERROR_IO_PENDING) pending = true;
        else { PipeFailure(error); DisconnectNamedPipe(pipe); }
        ioStarted = GetTickCount64();
    }
    bool Start()
    {
        // 为当前采样发布唯一私有管道；配置发布前完成创建，失败不装载Agent。
        if (agentPath.empty() || !onPacket) { setupError = ERROR_INVALID_PARAMETER; return false; }
        std::string id;
        if (!ProjectStorage::NewId(id)) { setupError = ERROR_GEN_FAILURE; return false; }
        endpoint.hostPid = GetCurrentProcessId();
        endpoint.hostCreation = m::transferProcessCreation(GetCurrentProcess());
        endpoint.token.assign(id.begin(), id.end());
        endpoint.pipeName = L"\\\\.\\pipe\\KswordTransfer_" + endpoint.token;
        io.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!io.hEvent) { setupError = GetLastError(); return false; }
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!PipeSecurity(&descriptor)) { setupError = GetLastError(); return false; }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        pipe = CreateNamedPipeW(endpoint.pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
            sizeof(response), sizeof(request), 0, &security);
        setupError = pipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        LocalFree(descriptor);
        if (setupError) return false;
        started = true;
        Begin(Phase::Connect);
        return true;
    }
    const n::ExecutionGroupMember* Member(const m::TransferHandoffRequest& r) const
    {
        // 用请求冻结PID+创建时间定位本集合成员；返回值只借用到下次回读。
        const auto found = std::find_if(current.members.begin(), current.members.end(), [&](const auto& member) {
            return member.site.pid == r.targetPid && member.site.creationFileTime == r.targetCreation &&
                member.owner.sampleId == sample;
        });
        return found == current.members.end() ? nullptr : &*found;
    }
    bool SourceReady(DWORD pid, std::uint64_t creation) const
    {
        if (pid == sourcePid) return creation == sourceCreation && originalReady && !originalEnded;
        const auto found = sources.find(pid);
        return found != sources.end() && found->second.creation == creation && found->second.ready &&
            !found->second.failed && !found->second.ended && !found->second.stopping;
    }
    bool SourceAuthenticated(DWORD pid, std::uint64_t creation) const
    {
        // 身份准入与观察就绪分开：递归Agent安装Hook后、Ready前也可能产生下一跳调用。
        // 已由本轮创建的精确来源先进入Pending，Advance仍要求真实Ready，不能直接发成功ACK。
        if (pid == sourcePid)
        {
            return creation == sourceCreation && !originalEnded;
        }
        const auto found = sources.find(pid); // 只接受本轮已登记的capture，不凭端点token新增来源。
        return found != sources.end() && found->second.creation == creation && found->second.capture &&
            !found->second.failed && !found->second.ended && !found->second.stopping;
    }
    DWORD Prepare()
    {
        // 输入已接收请求；先核验来源和目标对象，再查询入口所在MEM_PRIVATE范围。
        ULONG client = 0;
        if (request.size != sizeof(request) || request.version != m::kTransferHandoffVersion ||
            request.kind < 1 || request.kind > 3 || !std::wmemchr(request.token, 0, std::size(request.token)) ||
            request.token != endpoint.token || !GetNamedPipeClientProcessId(pipe, &client) ||
            !SourceAuthenticated(client, request.sourceCreation) || !request.address ||
            request.targetPid <= 4 || request.targetPid == GetCurrentProcessId() ||
             !request.targetCreation) return ERROR_ACCESS_DENIED;
        // 单成员清退后旧Agent可能尚未卸钩；同实例的新请求不能重用恢复中的NX owner。
        const auto retiring = std::any_of(current.members.begin(), current.members.end(), [&](const auto& member) {
            return member.site.pid == request.targetPid && member.site.creationFileTime == request.targetCreation &&
                failedOwnerRecovery.contains(member.owner.backendInstanceId);
        });
        if (retiring) return ERROR_OPERATION_ABORTED;
        const auto sourceHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, client);
        if (!sourceHandle) return GetLastError();
        Handle source(sourceHandle);
        const auto targetHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, request.targetPid);
        if (!targetHandle) return GetLastError();
        Handle target(targetHandle);
        if (m::transferProcessCreation(source.get()) != request.sourceCreation ||
            m::transferProcessCreation(target.get()) != request.targetCreation ||
            WaitForSingleObject(source.get(), 0) != WAIT_TIMEOUT ||
            WaitForSingleObject(target.get(), 0) != WAIT_TIMEOUT) return ERROR_INVALID_HANDLE;
        // Pending返回只让Hook重连，原API仍同步等待最终ACK；释放单实例管道服务安装期间的其它请求。
        const auto existing = std::find_if(transfers.begin(), transfers.end(), [&](const auto& t) {
            return t.source == client && t.request.sourceCreation == request.sourceCreation &&
                t.request.targetPid == request.targetPid && t.request.targetCreation == request.targetCreation &&
                t.request.address == request.address && t.request.kind == request.kind;
        });
        if (existing != transfers.end()) {
            if (existing->stage != Admission::Done) return ERROR_IO_PENDING;
            if (existing->error) return existing->error;
            // ACK重试仍核对当前原owner/范围和已认证Agent；旧成功不跨清退或范围失效复用。
            current = group.QueryWithoutCondition();
            const auto* member = Member(request);
            if (!SourceReady(request.targetPid, request.targetCreation) || !member ||
                !Covered(*member, existing->base, existing->bytes)) return ERROR_INVALID_STATE;
            const auto protectionError = VerifyArmedRange(target.get(), *member, existing->base, existing->bytes);
            if (protectionError) return protectionError;
            response.rangeBase = existing->base; response.rangeBytes = existing->bytes;
            return ERROR_SUCCESS;
        }
        // 只淘汰终态，不丢弃活准入及其恢复责任；拒绝也进入本轮Incomplete。
        if (transfers.size() >= 256) {
            const auto done = std::find_if(transfers.begin(), transfers.end(), [](const auto& t) {
                return t.stage == Admission::Done && !t.ownPause;
            });
            if (done == transfers.end()) return ERROR_BUSY;
            transfers.erase(done);
        }
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(target.get(), reinterpret_cast<void*>(request.address), &memory, sizeof(memory))) return GetLastError();
        auto base = reinterpret_cast<std::uint64_t>(memory.BaseAddress);
        auto bytes = static_cast<std::uint64_t>(memory.RegionSize);
        current = group.QueryWithoutCondition();
        const auto* member = Member(request);
        bool covered = false;
        if (memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE && member && member->control.breakpoint &&
            !(memory.Protect & PAGE_GUARD))
        {
            // 撤X及内部TF临时还X都会拆合VirtualQuery区域。先沿原owner目录解析入口，
            // 不把临时合并后的RegionSize当成新范围；最终ACK仍由VerifyArmedRange确认实际NX。
            for (const auto& range : member->control.breakpoint->executionRanges)
            {
                if (request.address >= range.base && request.address - range.base < range.bytes &&
                    range.allocationBase == reinterpret_cast<std::uint64_t>(memory.AllocationBase) &&
                     Covered(*member, range.base, range.bytes))
                {
                    base = range.base; bytes = range.bytes; covered = true;
                    break;
                }
            }
        }
        // NX只取得已提交私有执行页；不把整段裁成单页，也不将映像/映射冒充私有。
        if (!covered && (memory.State != MEM_COMMIT || memory.Type != MEM_PRIVATE || (memory.Protect & PAGE_GUARD) ||
            !(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
            !bytes || base % 4096 || bytes % 4096 || base > UINT64_MAX - bytes ||
            request.address < base || request.address - base >= bytes)) return ERROR_NOT_SUPPORTED;
        if (!covered && member && member->control.pageAdvance &&
            member->control.pageAdvance->receipt.state == n::NativeStepState::Running &&
            !member->control.pageAdvance->receipt.resourcesRestored)
        {
            // 新入口不在原目录内时，临时还X可能使其区域与旧页合并。保持Hook等待，
            // 关回NX后重新查询新区域，不能冻结一个与旧范围重叠的追加请求。
            return ERROR_IO_PENDING;
        }
        Transfer transfer;
        transfer.request = request; transfer.source = client;
        transfer.base = base; transfer.bytes = bytes; transfer.started = GetTickCount64();
        transfer.target = std::move(target);
        transfers.push_back(std::move(transfer));
        if (onTarget) onTarget(request.targetPid, request.targetCreation);
        return ERROR_IO_PENDING;
    }
    void Finish(Transfer& transfer, DWORD error)
    {
        transfer.error = error;
        transfer.stage = Admission::Done;
        lastError = error;
        if (error) ++rejected; else ++armed;
        if (error) {
            const auto found = sources.find(transfer.request.targetPid);
            if (found != sources.end() && !found->second.ready && found->second.creation == transfer.request.targetCreation) {
                found->second.failed = true;
                found->second.stopping = true;
                if (!found->second.error) found->second.error = error;
                found->second.capture->Stop(); // 过期准入不能由清退期晚到Ready重新授予执行资格。
            }
        }
    }
    void DrainSources()
    {
        // 后台仅发布纯值；原包和终态归档始终回到原worker，不申请第二项目writer。
        for (auto& [pid, source] : sources) {
            auto batch = source.capture->Drain();
            source.startup = std::move(batch.startup);
            source.dropped = batch.dropped;
            if (batch.ready) {
                source.ready = true;
                source.session = batch.session;
                source.revision = batch.coverageRevision;
            }
            if (source.dropped) { source.failed = true; source.error = ERROR_BUFFER_OVERFLOW; }
            // captureApiMonitor 已先核对协议、PID 与底层会话。递归 Agent 在
            // Ready 前仍会发送 SessionReady、覆盖快照及 HooksInstalled；不能因
            // 控制器尚未收到 onResidentReady 就把这些正常启动包判成错来源。
            for (const auto& packet : batch.packets) {
                if (packet.pid != pid) {
                    source.failed = true;
                    if (!source.error) source.error = ERROR_INVALID_DATA;
                    ++source.deliveryDropped;
                    continue;
                }
                if (source.pendingPackets.size() >= 4096) {
                    source.failed = true;
                    if (!source.error) source.error = ERROR_BUFFER_OVERFLOW;
                    ++source.deliveryDropped;
                    source.capture->Stop();
                    continue;
                }
                source.pendingPackets.push_back(packet);
            }
            if (source.ready) {
                while (!source.pendingPackets.empty()) {
                    const auto packet = source.pendingPackets.front();
                    source.pendingPackets.pop_front();
                    // Ready后才进入项目writer；此处最终核对来源会话，避免错代次包入档。
                    if (!source.session || packet.sessionIdentity != source.session) {
                        source.failed = true;
                        if (!source.error) source.error = ERROR_INVALID_DATA;
                        ++source.deliveryDropped;
                        continue;
                    }
                    if (callbackFailed) { ++source.deliveryDropped; continue; }
                    try { onPacket(pid, source.creation, packet); }
                    catch (...) {
                        callbackFailed = source.failed = true;
                        source.error = ERROR_WRITE_FAULT;
                        ++source.deliveryDropped;
                        for (auto& [otherPid, other] : sources) other.capture->Stop();
                    }
                }
            }
            if (batch.finished) {
                source.ended = true;
                source.result = std::move(batch.finished);
                const auto& result = *source.result;
                // 持续采集由本轮Close取消，不拿code=6/未到时作为伪失败，也不掩盖清退和实际丢失。
                bool failed = !result.started || !result.cleanupComplete || !result.errors.empty() ||
                    result.bufferDropped || result.invalidPackets;
                bool exited = false;
                for (const auto& process : result.processes)
                {
                    // HooksPartial is a non-fatal installation diagnostic: this source
                    // already crossed the strict Ready barrier and the transfer request
                    // itself proves the relevant observation hook is active.  Do not
                    // revoke an otherwise valid handoff because an unrelated optional
                    // hook was unavailable; pipe loss, install failure and stale coverage
                    // remain hard failures.
                    failed = failed || process.pipeError || process.agentDropped ||
                        process.installFailed || !process.installed || !process.coverageComplete || process.coverageStale ||
                        (process.connected && !process.cleanPipeEof);
                    exited = exited || process.exited;
                }
                if (failed || (!closing && !exited)) {
                    source.failed = true;
                    if (!source.error) source.error = failed ? ERROR_GEN_FAILURE : ERROR_BROKEN_PIPE;
                }
            }
        }
    }
    void AddRange(Transfer& transfer, const n::ExecutionGroupMember& member)
    {
        // 追加可能由Pause回读后进入；已收到停止时保留暂停账交给Close，不再扩展执行范围。
        if (cancel.load() || closing) { Finish(transfer, ERROR_OPERATION_ABORTED); return; }
        current = group.AddRange(member.control, transfer.base, transfer.bytes);
        const auto* updated = Member(transfer.request);
        const bool added = updated && updated->control.executionRange &&
            updated->control.executionRange->added && Covered(*updated, transfer.base, transfer.bytes);
        const auto error = updated && updated->control.win32Error ? updated->control.win32Error : ERROR_NOT_SUPPORTED;
        // 仅归还本请求主动暂停；真实NX事件必须走归档，并等Agent Ready后才继续。
        if (!cancel.load() && !closing && transfer.ownPause && updated && updated->control.armedPause &&
            updated->control.armedPause->request.requestId == transfer.pauseRequestId &&
            updated->control.stopReason == n::NativeStopReason::ManualPause &&
            n::OwnedExecutionGroup::CanContinueMember(*updated)) {
            const n::ExecutionGroupSessionEntry entry{updated->owner, updated->control};
            current = group.Continue(std::span(&entry, 1), false);
        }
        if (!added) Finish(transfer, error);
        else transfer.stage = Admission::Running;
    }
    void Advance(Transfer& transfer)
    {
        const auto& r = transfer.request;
        if (cancel.load() || closing) { Finish(transfer, ERROR_OPERATION_ABORTED); return; }
        if (!SourceAuthenticated(transfer.source, r.sourceCreation)) { Finish(transfer, ERROR_ACCESS_DENIED); return; }
        if (GetTickCount64() - transfer.started >= 12000) { Finish(transfer, ERROR_TIMEOUT); return; }
        if (!SourceReady(transfer.source, r.sourceCreation)) return;
        if (WaitForSingleObject(transfer.target.get(), 0) != WAIT_TIMEOUT ||
            m::transferProcessCreation(transfer.target.get()) != r.targetCreation) {
            Finish(transfer, ERROR_INVALID_HANDLE); return;
        }
        current = group.QueryWithoutCondition();
        // owner回读可跨越取消到达时点；新建owner、Pause及后续安装前重新确认本轮仍在执行。
        if (cancel.load() || closing) { Finish(transfer, ERROR_OPERATION_ABORTED); return; }
        const auto* member = Member(r);
        if (member && member->control.firstRecoveryFailure) {
            const auto error = member->control.firstRecoveryFailure->win32Error;
            Finish(transfer, error ? error : ERROR_GEN_FAILURE); return;
        }
        if (transfer.stage == Admission::Initial) {
            if (!member) {
                // 回跳原来源也可在此新增NX owner；来源Agent仍复用原capture，不创建双会话。
                n::ExecutionGroupSite site;
                site.pid = r.targetPid; site.creationFileTime = r.targetCreation;
                site.address = transfer.base; site.rangeBytes = transfer.bytes;
                if (current.collectionId.empty())
                    current = group.Start({site}, true, n::NativeTargetDisposition::ResumeAndDetach, sample, false, true);
                else current = group.AppendMembers({site}, true, current.collectionId);
                if (current.operation && !current.operation->admitted) {
                    Finish(transfer, current.operation->win32Error ? current.operation->win32Error : ERROR_ACCESS_DENIED); return;
                }
                transfer.stage = Admission::Armed;
                return;
            }
            if (Covered(*member, transfer.base, transfer.bytes)) transfer.stage = Admission::Running;
            else if (n::CanPauseDataWatchSession(member->control)) {
                const n::ExecutionGroupSessionEntry entry{member->owner, member->control};
                current = group.Pause(std::span(&entry, 1), false);
                const auto* paused = Member(r);
                if (paused && paused->control.armedPause &&
                    (paused->control.armedPause->state == n::NativeArmedPauseState::Pending ||
                        paused->control.armedPause->state == n::NativeArmedPauseState::Held &&
                        paused->control.stopReason == n::NativeStopReason::ManualPause))
                {
                    transfer.pauseRequestId = paused->control.armedPause->request.requestId;
                    transfer.ownPause = !transfer.pauseRequestId.empty();
                }
                // Pause再次回读前可能已命中NX；此时没有本请求的手动暂停债，
                // 直接沿真实Held追加，后续由Observe保存事件并执行原继续策略。
                if (!transfer.ownPause && paused && n::OwnedExecutionGroup::CanAddRangeMember(*paused))
                {
                    AddRange(transfer, *paused);
                    return;
                }
                if (!transfer.ownPause && paused && paused->control.pageAdvance &&
                    paused->control.pageAdvance->receipt.state == n::NativeStepState::Running &&
                    !paused->control.pageAdvance->receipt.resourcesRestored)
                {
                    return; // 请求尚未取得暂停责任，保持Initial等内部推进完成。
                }
                if (!transfer.ownPause) {
                    Finish(transfer, paused && paused->control.win32Error ? paused->control.win32Error : ERROR_INVALID_STATE);
                    return;
                }
                transfer.stage = Admission::Paused;
                return;
            } else if (n::OwnedExecutionGroup::CanAddRangeMember(*member)) { AddRange(transfer, *member); return; }
            else if (member->control.pageAdvance &&
                member->control.pageAdvance->receipt.state == n::NativeStepState::Running &&
                !member->control.pageAdvance->receipt.resourcesRestored)
            {
                // 前一NX命中正推进一条指令，暂时不能Pause/AddRange不代表下一范围准入失败。
                // 请求仍留在原Hook屏障内，沿已有时限等待原owner关回NX并归还同伴暂停。
                return;
            }
            else { Finish(transfer, member->control.win32Error ? member->control.win32Error : ERROR_BUSY); return; }
        }
        if (transfer.stage == Admission::Armed) {
            if (!member) { Finish(transfer, ERROR_INVALID_STATE); return; }
            if (!member->attachAccepted || member->control.win32Error) {
                Finish(transfer, member->control.win32Error ? member->control.win32Error : ERROR_ACCESS_DENIED); return;
            }
            if (!Covered(*member, transfer.base, transfer.bytes)) return;
            transfer.stage = Admission::Running;
        }
        if (transfer.stage == Admission::Paused) {
            if (!member) { Finish(transfer, ERROR_INVALID_STATE); return; }
            if (n::OwnedExecutionGroup::CanAddRangeMember(*member)) AddRange(transfer, *member);
            else if (member->control.win32Error) Finish(transfer, member->control.win32Error);
            return;
        }
        if (transfer.stage == Admission::Running) {
            if (!member || !Covered(*member, transfer.base, transfer.bytes)) return;
            const auto protectionError = VerifyArmedRange(transfer.target.get(), *member, transfer.base, transfer.bytes);
            if (protectionError == ERROR_IO_PENDING) return;
            if (protectionError) { Finish(transfer, protectionError); return; }
            if (transfer.ownPause)
            {
                // 追加范围的保护已生效，但本请求主动暂停尚未确认归还时不能发成功ACK。
                // RestoreRequestPauses继续处理原票据，下一轮只接受真实Armed运行状态。
                if (!n::CanPauseDataWatchSession(member->control)) return;
                transfer.ownPause = false;
            }
            if (SourceReady(r.targetPid, r.targetCreation)) { Finish(transfer, ERROR_SUCCESS); return; }
            auto found = sources.find(r.targetPid);
            if (found == sources.end()) {
                if (r.targetPid == sourcePid) {
                    // 原capture还未Ready可等它正常推进；已经结束不能重装来冒充原会话仍在采集。
                    if (originalEnded) Finish(transfer, ERROR_BROKEN_PIPE);
                    return;
                }
                // NX设防后原owner须已恢复运行。持真实debug停点盲装LoadLibrary会冻结其helper。
                if (!n::CanPauseDataWatchSession(member->control)) {
                    Finish(transfer, ERROR_BUSY); return;
                }
                Source source;
                source.pid = r.targetPid; source.creation = r.targetCreation;
                source.capture = std::make_unique<ApiTransferAgentCapture>(r.targetPid, r.targetCreation, endpoint, agentPath);
                found = sources.emplace(r.targetPid, std::move(source)).first;
                // 构造capture尚未装载Agent；取消时删除未启动对象，避免Close等待不存在的worker。
                if (cancel.load() || closing)
                {
                    sources.erase(found);
                    Finish(transfer, ERROR_OPERATION_ABORTED);
                    return;
                }
                if (!found->second.capture->Start()) {
                    found->second.failed = true; found->second.error = ERROR_NOT_ENOUGH_MEMORY;
                    Finish(transfer, ERROR_NOT_ENOUGH_MEMORY); return;
                }
            }
            if (found->second.creation != r.targetCreation || found->second.failed || found->second.ended) {
                Finish(transfer, found->second.error ? found->second.error : ERROR_INVALID_STATE); return;
            }
            transfer.stage = Admission::Agent;
        }
        if (transfer.stage == Admission::Agent) {
            const auto found = sources.find(r.targetPid);
            if (found == sources.end() || found->second.failed || found->second.ended) {
                Finish(transfer, found == sources.end() || !found->second.error ? ERROR_INVALID_STATE : found->second.error); return;
            }
            if (SourceReady(r.targetPid, r.targetCreation) && member && Covered(*member, transfer.base, transfer.bytes))
            {
                // Agent安装期间原owner仍在处理执行事件；Ready本身不能证明页已关回NX。
                const auto protectionError = VerifyArmedRange(transfer.target.get(), *member, transfer.base, transfer.bytes);
                if (protectionError != ERROR_IO_PENDING) Finish(transfer, protectionError);
            }
        }
    }
    void AdvanceTransfers()
    {
        for (auto currentTransfer = transfers.begin(); currentTransfer != transfers.end(); ++currentTransfer) {
            if (currentTransfer->stage == Admission::Done) continue;
            // 同目标范围更改串行；其它目标及管道服务照常推进，绝不嵌套同步等待Ready。
            if (std::any_of(transfers.begin(), currentTransfer, [&](const auto& prior) {
                return prior.stage != Admission::Done && prior.request.targetPid == currentTransfer->request.targetPid;
            })) continue;
            try { Advance(*currentTransfer); }
            catch (const std::bad_alloc&) { Finish(*currentTransfer, ERROR_NOT_ENOUGH_MEMORY); }
            catch (...) { Finish(*currentTransfer, ERROR_GEN_FAILURE); }
        }
    }
    void RestoreRequestPauses()
    {
        // 超时/拒绝不能遗留本请求引入的手动暂停；真实执行停点仍由归档及Ready策略持有。
        for (auto& transfer : transfers) {
            if (cancel.load() || closing) return; // 取消后的暂停责任统一交Close恢复，不再继续业务。
            if (!transfer.ownPause || transfer.stage == Admission::Paused) continue;
            current = group.QueryWithoutCondition();
            const auto* member = Member(transfer.request);
            if (!member || member->control.clean || n::CanPauseDataWatchSession(member->control)) {
                transfer.ownPause = false;
                continue;
            }
            if (member->control.armedPause && !transfer.pauseRequestId.empty() &&
                member->control.armedPause->request.requestId != transfer.pauseRequestId) {
                transfer.ownPause = false;
                continue;
            }
            if (member->control.armedPause && member->control.armedPause->state != n::NativeArmedPauseState::Pending &&
                member->control.armedPause->state != n::NativeArmedPauseState::Held &&
                member->control.armedPause->state != n::NativeArmedPauseState::RecoveryRequired) {
                transfer.ownPause = false; // 请求被真实命中抢先或已拒绝；不释放替代事件。
                continue;
            }
            if (!transfer.pauseRequestId.empty() && member->control.armedPause &&
                member->control.armedPause->request.requestId == transfer.pauseRequestId &&
                member->control.stopReason == n::NativeStopReason::ManualPause &&
                n::OwnedExecutionGroup::CanContinueMember(*member)) {
                if (cancel.load() || closing) return;
                const n::ExecutionGroupSessionEntry entry{member->owner, member->control};
                current = group.Continue(std::span(&entry, 1), false);
            }
        }
    }
    void Observe()
    {
        // 输入原集合最新停点，按同一原事件去重写raw-native；失败保留现场与首错。
        if (current.collectionId.empty()) return;
        current = group.Query();
        for (const auto& member : current.members) {
            const auto execution = n::NativeExecutionFromOwnedStop(member.control);
            if (!execution || observed.contains(member.owner.backendInstanceId) &&
                observed.at(member.owner.backendInstanceId) == execution->event) continue;
            if (!archiveStatus) continue; // 写失败保留原事件和首错，不自动放行未保存停点。
            ProjectNativeExecutionReceipt receipt;
            archiveStatus = WriteNativeExecution(project, member.owner, nativeOrdinal + 1, previousSequence, member.control, receipt);
            if (!archiveStatus || !receipt.verified || !receipt.raw.flushed) continue;
            nativeOrdinal = receipt.ordinal;
            previousSequence = receipt.raw.flushed->lastSequence;
            ++saved;
            observed[member.owner.backendInstanceId] = execution->event;
            for (auto& transfer : transfers)
            {
                if (transfer.entryObservation.type() != Evidence::JsonType::Null ||
                    transfer.request.targetPid != execution->pid ||
                    transfer.request.targetCreation != execution->processCreationFileTime ||
                    transfer.request.address != execution->instructionAddress) continue;
                transfer.entryObservation = V::makeObject({
                    {"instructionAddress", V::makeString(std::to_string(execution->instructionAddress))},
                    {"observation", V::makeString(execution->kind == n::NativeExecutionKind::EnterAttempt
                        ? "execution-enter-attempt" : "instruction-completed")},
                    {"pid", V::makeUInt(execution->pid)},
                    {"creationFileTime", V::makeString(std::to_string(execution->processCreationFileTime))},
                    {"tid", V::makeUInt(execution->thread.tid)},
                    {"threadCreationFileTime", V::makeString(std::to_string(execution->thread.creationTime))},
                    {"segmentOrdinal", V::makeString(std::to_string(receipt.ordinal))},
                    {"recordSequence", V::makeString(std::to_string(receipt.raw.flushed->lastSequence))},
                    {"sha256", V::makeString(receipt.sha256)}});
            }
        }
        if (closing || cancel.load())
        {
            // 取消可能早于Close到达；只保存已持有事件，随后由Close恢复/脱离，不再开页或置TF。
            return;
        }
        // 追踪模式只在执行停点保存后沿原NX owner的TF/重设防路径继续，不伪造令牌。
        std::vector<n::ExecutionGroupSessionEntry> resume;
        for (const auto& member : current.members) {
            const auto execution = n::NativeExecutionFromOwnedStop(member.control);
            const auto found = observed.find(member.owner.backendInstanceId);
            if (execution && SourceReady(member.site.pid, member.site.creationFileTime) &&
                found != observed.end() && found->second == execution->event &&
                n::OwnedExecutionGroup::CanContinueMember(member)) resume.push_back({member.owner, member.control});
        }
        // 归档和构造继续列表期间也可能收到取消；提交前再次检查，避免继续已经要求停止的采样。
        if (!resume.empty() && !cancel.load()) current = group.Continue(resume, false);
    }
    void RecoverFailedTargets()
    {
        // 失败准入且没有可用Agent时，原API仍会放行；不能让该目标的NX停点无限等待Ready。
        if (closing || current.collectionId.empty() || !archiveStatus) return;
        // 集合成员保留完整恢复责任，不能依赖会淘汰的最近准入窗口。
        // CloseMember会替换current；先冻结身份，再逐个回读对应成员。
        std::vector<n::OwnerIdentity> owners;
        for (const auto& member : current.members) owners.push_back(member.owner);
        for (const auto& owner : owners)
        {
            const auto member = std::find_if(current.members.begin(), current.members.end(), [&](const auto& entry) {
                return entry.owner.backendInstanceId == owner.backendInstanceId;
            });
            if (member == current.members.end() || owner.backendInstanceId.empty() ||
                failedOwnerRecovery.contains(owner.backendInstanceId)) continue;
            const auto pid = member->site.pid;
            const auto creation = member->site.creationFileTime;
            const auto source = sources.find(pid);
            const bool sourceFailed = source != sources.end() &&
                source->second.creation == creation && source->second.failed;
            const bool admissionFailed = std::any_of(transfers.begin(), transfers.end(), [&](const auto& transfer) {
                return transfer.stage == Admission::Done && transfer.error &&
                    transfer.request.targetPid == pid && transfer.request.targetCreation == creation;
            });
            if ((!admissionFailed && !sourceFailed) || SourceReady(pid, creation)) continue;
            const auto pendingTarget = std::any_of(transfers.begin(), transfers.end(), [&](const auto& other) {
                return other.stage != Admission::Done && other.request.targetPid == pid &&
                    other.request.targetCreation == creation;
            }); // 同一实例尚有准入在推进时，不撤掉其仍需使用的NX范围。
            if (pendingTarget) continue;
            failedOwnerRecovery.emplace(owner.backendInstanceId, true);
            if (source != sources.end() && source->second.creation == creation)
            {
                // 先撤来源资格并通知停止，再撤NX/debug owner；不能同步等待被冻结的卸钩helper。
                source->second.stopping = true;
                source->second.capture->Stop();
            }
            if (!member->control.clean) current = group.CloseMember(owner);
        }
    }
    void Poll()
    {
        // 每次只处理一个已完成阶段；未完成返回原采集循环，不阻塞GUI。
        DrainSources();
        AdvanceTransfers();
        RestoreRequestPauses();
        Observe();
        RecoverFailedTargets(); // 已持有停点先归档，再沿原owner恢复；不借Continue伪造Agent就绪。
        if (!started || closing || cancel.load()) return;
        if (phase == Phase::Release) {
            // overlapped写完成只表示入管道，不能马上Disconnect丢掉尚未被Hook读取的ACK。
            DWORD available = 0;
            const bool connected = PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) != FALSE;
            if (connected && GetTickCount64() - ioStarted < 15000) return;
            DisconnectNamedPipe(pipe); Begin(Phase::Connect); return;
        }
        DWORD bytes = immediateBytes;
        if (pending) {
            if (WaitForSingleObject(io.hEvent, 0) != WAIT_OBJECT_0) {
                if (GetTickCount64() - ioStarted < 15000 || phase == Phase::Connect) return;
                CancelIoEx(pipe, &io);
                DWORD ignored = 0; GetOverlappedResult(pipe, &io, &ignored, TRUE);
                PipeFailure(ERROR_TIMEOUT);
                pending = false; DisconnectNamedPipe(pipe); Begin(Phase::Connect); return;
            }
            const bool ok = GetOverlappedResult(pipe, &io, &bytes, FALSE) != FALSE;
            pending = false;
            if (!ok) { PipeFailure(GetLastError()); DisconnectNamedPipe(pipe); Begin(Phase::Connect); return; }
        } else if (!immediate) { Begin(Phase::Connect); return; }
        immediate = false;
        if (phase == Phase::Connect) { request = {}; Begin(Phase::Read); }
        else if (phase == Phase::Read) {
            response = {};
            ++requests;
            try
            {
                response.error = bytes == sizeof(request) ? Prepare() : ERROR_INVALID_DATA;
            }
            catch (const std::bad_alloc&)
            {
                response.error = ERROR_NOT_ENOUGH_MEMORY; // owner仍留在集合内，清退沿原账继续。
            }
            catch (...)
            {
                response.error = ERROR_GEN_FAILURE;
            }
            if (response.error && response.error != ERROR_IO_PENDING) { lastError = response.error; ++rejected; }
            Begin(Phase::Reply);
        } else {
            if (bytes != sizeof(response)) PipeFailure(ERROR_INVALID_DATA);
            phase = Phase::Release; ioStarted = GetTickCount64();
        }
    }
};

ApiTransferHandoff::ApiTransferHandoff(ProjectDocument& project, std::string sampleId,
    DWORD pid, std::uint64_t creation, const std::atomic_bool& cancel,
    const std::wstring& agentPath, SourcePacket onPacket, TargetDiscovered onTarget)
    : impl_(std::make_unique<Impl>(project, std::move(sampleId), pid, creation, cancel, agentPath,
        std::move(onPacket), std::move(onTarget))) {}
ApiTransferHandoff::~ApiTransferHandoff() { Close(); }
bool ApiTransferHandoff::Start() { return impl_->Start(); }
void ApiTransferHandoff::Poll() { impl_->Poll(); }
void ApiTransferHandoff::OriginalSourceReady(std::uint64_t session, std::uint64_t coverageRevision)
{
    if (impl_->closing || impl_->originalEnded || !session || !coverageRevision) return;
    impl_->originalSession = session;
    impl_->originalRevision = coverageRevision;
    impl_->originalReady = true;
}
void ApiTransferHandoff::OriginalSourceFinished() { impl_->originalEnded = true; }
void ApiTransferHandoff::Close()
{
    auto& self = *impl_;
    if (self.closing) return; // 析构沿同一账清退，不再次提交已经完成的关闭操作。
    self.closing = true;
    self.ClosePipe();
    for (auto& transfer : self.transfers)
        if (transfer.stage != Impl::Admission::Done) self.Finish(transfer, ERROR_OPERATION_ABORTED);
    for (auto& [pid, source] : self.sources)
    {
        source.stopping = true; // 全轮关闭同样先撤来源准入，尾包由DrainSources继续写入。
        source.capture->Stop();
    }
    // 先保存已持有的停点，再撤本轮NX/调试owner；Held事件会冻结目标的卸钩线程，不能先等Agent退出。
    self.Observe();
    if (!self.current.collectionId.empty())
    {
        self.current = self.group.Close(); // 显式结束沿原恢复账释放停点；原API writer此时仍保持打开。
    }
    // owner已收到恢复请求后，所有来源尾包仍由同一worker排空，最后才交还原writer封API终段。
    while (std::any_of(self.sources.begin(), self.sources.end(), [](const auto& entry) {
        return !entry.second.capture->Finished();
    })) {
        self.DrainSources();
        if (!self.current.collectionId.empty() && !self.current.clean)
            self.current = self.group.QueryWithoutCondition(); // 推进已请求的清退，不再自动继续业务执行。
        Sleep(5); // 原capture自身启动/清退有界；此处不重发装载或Stop。
    }
    self.DrainSources();
    if (!self.current.collectionId.empty())
    {
        const auto deadline = GetTickCount64() + 10000; // 有限等待本次集合排空，不无限重发Close。
        while (!self.current.clean && GetTickCount64() < deadline)
        {
            Sleep(5);
            self.current = self.group.QueryWithoutCondition();
        }
    }
}
m::InjectionEndpoint ApiTransferHandoff::Endpoint() const { return impl_->started ? impl_->endpoint : m::InjectionEndpoint{}; }
bool ApiTransferHandoff::Incomplete() const
{
    const auto& self = *impl_; // 只读取冻结回执，不再向原owner发新控制。
    return !self.started || self.setupError || self.rejected || self.pipeFailures || self.callbackFailed || !self.archiveStatus ||
        std::any_of(self.sources.begin(), self.sources.end(), [](const auto& entry) {
            const auto& source = entry.second;
            return source.failed || source.dropped || source.deliveryDropped || !source.ready ||
                !source.ended || !source.result || !source.result->cleanupComplete;
        }) ||
        (!self.current.collectionId.empty() && !self.current.clean) ||
        std::any_of(self.current.members.begin(), self.current.members.end(), [](const auto& member) {
            // 资源最终归还与执行期间故障分别报告；Close成功不能抹掉真实恢复失败。
            return member.control.firstRecoveryFailure.has_value();
        });
}
bool ApiTransferHandoff::HasActiveAgents() const
{
    const auto& self = *impl_;
    return !self.closing && (std::any_of(self.sources.begin(), self.sources.end(), [](const auto& entry) {
        return !entry.second.ended;
    }) || std::any_of(self.transfers.begin(), self.transfers.end(), [](const auto& transfer) {
        return transfer.stage != Impl::Admission::Done;
    }));
}
Evidence::JsonValue ApiTransferHandoff::Describe() const
{
    const auto& s = *impl_;
    Evidence::JsonArray sources;
    sources.push_back(V::makeObject({{"pid", V::makeUInt(s.sourcePid)},
        {"creationFileTime", V::makeString(std::to_string(s.sourceCreation))}, {"original", V::makeBool(true)},
        {"ready", V::makeBool(s.originalReady)}, {"ended", V::makeBool(s.originalEnded)},
        {"session", V::makeString(std::to_string(s.originalSession))},
        {"coverageRevision", V::makeString(std::to_string(s.originalRevision))}}));
    for (const auto& [pid, source] : s.sources) {
        Evidence::JsonArray errors, processes;
        if (source.result) {
            for (const auto& error : source.result->errors) {
                const auto bytes = WideCharToMultiByte(CP_UTF8, 0, error.data(), static_cast<int>(error.size()), nullptr, 0, nullptr, nullptr);
                std::string text(bytes > 0 ? bytes : 0, '\0');
                if (bytes > 0) WideCharToMultiByte(CP_UTF8, 0, error.data(), static_cast<int>(error.size()), text.data(), bytes, nullptr, nullptr);
                errors.push_back(V::makeString(text));
            }
            for (const auto& process : source.result->processes)
                processes.push_back(V::makeObject({{"pid", V::makeUInt(process.pid)},
                    {"creationFileTime", V::makeString(std::to_string(process.creation))},
                    {"session", V::makeString(std::to_string(process.session))},
                    {"connected", V::makeBool(process.connected)}, {"installed", V::makeBool(process.installed)},
                    {"removed", V::makeBool(process.removed)}, {"exited", V::makeBool(process.exited)},
                    {"sessionReady", V::makeBool(process.sessionReady)}, {"cleanPipeEof", V::makeBool(process.cleanPipeEof)},
                    {"coverageComplete", V::makeBool(process.coverageComplete)}, {"coverageStale", V::makeBool(process.coverageStale)},
                    {"partialHooks", V::makeBool(process.partialHooks)}, {"installFailed", V::makeBool(process.installFailed)},
                    {"agentDropped", V::makeUInt(process.agentDropped)}, {"pipeError", V::makeUInt(process.pipeError)}}));
        }
        sources.push_back(V::makeObject({{"pid", V::makeUInt(pid)},
            {"creationFileTime", V::makeString(std::to_string(source.creation))},
            {"ready", V::makeBool(source.ready)}, {"session", V::makeString(std::to_string(source.session))},
            {"stopRequested", V::makeBool(source.stopping)},
            {"coverageRevision", V::makeString(std::to_string(source.revision))}, {"ended", V::makeBool(source.ended)},
            {"failed", V::makeBool(source.failed)}, {"error", V::makeUInt(source.error)},
            {"queueDropped", V::makeUInt(source.dropped)}, {"deliveryDropped", V::makeUInt(source.deliveryDropped)},
            {"startupStage", source.startup ? V::makeString(m::CaptureStartupStageName(source.startup->stage)) : V::makeNull()},
            {"captureCode", source.result ? V::makeUInt(source.result->code) : V::makeNull()},
            {"attachmentIdentityVerified", V::makeBool(source.result ? source.result->attachmentIdentityVerified :
                source.startup && source.startup->attachmentIdentityVerified)},
            {"agentModuleVerified", V::makeBool(source.result ? source.result->agentModuleVerified :
                source.startup && source.startup->agentModuleVerified)},
            {"started", V::makeBool(source.result ? source.result->started : source.ready)},
            {"cancelled", V::makeBool(source.result && source.result->cancelled)},
            {"cleanupComplete", V::makeBool(source.result && source.result->cleanupComplete)},
            {"stopWritten", V::makeBool(source.result && source.result->stopWritten)},
            {"invalidPackets", V::makeUInt(source.result ? source.result->invalidPackets : 0)},
            {"bufferDropped", V::makeUInt(source.result ? source.result->bufferDropped : 0)},
            {"received", V::makeUInt(source.result ? source.result->received : 0)},
            {"errors", V::makeArray(std::move(errors))}, {"processes", V::makeArray(std::move(processes))}}));
    }
    Evidence::JsonArray admissions;
    for (const auto& transfer : s.transfers)
    {
        const auto* member = s.Member(transfer.request); // 当前原 owner 快照，用于解释准入失败码。
        const auto* recovery = member && member->control.firstRecoveryFailure
            ? &*member->control.firstRecoveryFailure : nullptr;
        V pageAdvance = V::makeNull();
        if (member && member->control.pageAdvance)
        {
            const auto& advance = *member->control.pageAdvance;
            pageAdvance = V::makeObject({{"stage", V::makeString(advance.receipt.stage)},
                {"error", V::makeUInt(advance.receipt.win32Error)},
                {"tid", V::makeUInt(advance.receipt.request.tid)},
                {"threadCreationFileTime", V::makeString(std::to_string(advance.receipt.request.threadCreationTime))},
                {"startIp", V::makeString(std::to_string(advance.receipt.startIp))},
                {"observedIp", advance.receipt.observedIp ? V::makeString(std::to_string(*advance.receipt.observedIp)) : V::makeNull()},
                {"observedDr6", V::makeString(std::to_string(advance.observedDr6))},
                {"observedFlags", V::makeUInt(advance.observedFlags)},
                {"observedDr7", V::makeString(std::to_string(advance.observedDr7))},
                {"continuation", V::makeUInt(advance.continuation)},
                {"resourcesRestored", V::makeBool(advance.receipt.resourcesRestored)}});
        }
        admissions.push_back(V::makeObject({{"sourcePid", V::makeUInt(transfer.source)},
            {"sourceCreationFileTime", V::makeString(std::to_string(transfer.request.sourceCreation))},
            {"targetPid", V::makeUInt(transfer.request.targetPid)},
            {"targetCreationFileTime", V::makeString(std::to_string(transfer.request.targetCreation))},
            {"address", V::makeString(std::to_string(transfer.request.address))},
            {"rangeBase", V::makeString(std::to_string(transfer.base))},
            {"rangeBytes", V::makeString(std::to_string(transfer.bytes))},
            {"handoffKind", V::makeUInt(transfer.request.kind)},
            {"entryObservation", transfer.entryObservation},
            {"nativePageAdvanceScope", V::makeString("target-owner-latest")},
            {"requestPauseOutstanding", V::makeBool(transfer.ownPause)},
            {"completed", V::makeBool(transfer.stage == Impl::Admission::Done)}, {"error", V::makeUInt(transfer.error)},
            {"nativeOwnerStage", member && member->control.stage
                ? V::makeString(member->control.stage) : V::makeNull()},
            {"nativeOwnerError", V::makeUInt(member ? member->control.win32Error : 0)},
            {"failedTargetRecoveryRequested", V::makeBool(member &&
                s.failedOwnerRecovery.contains(member->owner.backendInstanceId))},
            {"nativePageAdvance", std::move(pageAdvance)},
            {"nativeExitCode", member && member->control.retirement && member->control.retirement->exitCode
                ? V::makeUInt(*member->control.retirement->exitCode) : V::makeNull()},
            {"nativeRecoveryFailureStage", recovery && recovery->stage
                ? V::makeString(recovery->stage) : V::makeNull()},
            {"nativeRecoveryFailureError", V::makeUInt(recovery ? recovery->win32Error : 0)}}));
    }
    return V::makeObject({{"kind", V::makeString("api-transfer-handoff-v1")}, {"enabled", V::makeBool(s.started)},
        {"sourcePid", V::makeUInt(s.sourcePid)}, {"sourceCreationFileTime", V::makeString(std::to_string(s.sourceCreation))},
        {"requests", V::makeUInt(s.requests)}, {"armed", V::makeUInt(s.armed)}, {"rejected", V::makeUInt(s.rejected)},
        {"savedExecutionStops", V::makeUInt(s.saved)}, {"setupError", V::makeUInt(s.setupError)},
        {"lastError", V::makeUInt(s.lastError)}, {"archiveError", V::makeUInt(s.archiveStatus.nativeError)},
        {"pipeFailures", V::makeUInt(s.pipeFailures)}, {"firstPipeError", V::makeUInt(s.firstPipeError)},
        {"collectionId", V::makeString(s.current.collectionId)}, {"members", V::makeUInt(s.current.members.size())},
        {"acceptingTargets", V::makeBool(!s.closing && !s.cancel.load() && s.current.acceptingMembers)},
        {"clean", V::makeBool(s.current.clean)}, {"callbackFailed", V::makeBool(s.callbackFailed)},
        {"activeAgents", V::makeBool(HasActiveAgents())}, {"sources", V::makeArray(std::move(sources))},
        {"admissions", V::makeArray(std::move(admissions))},
        {"recursiveAgentReady", V::makeBool(!s.sources.empty() && std::all_of(s.sources.begin(), s.sources.end(),
            [](const auto& entry) {
                return entry.second.ready && !entry.second.failed && !entry.second.ended && !entry.second.stopping;
            }))}});
}
}
