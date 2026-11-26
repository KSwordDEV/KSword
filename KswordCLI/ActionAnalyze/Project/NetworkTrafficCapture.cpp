#include "NetworkTrafficCapture.h"

// 现有网络头会经进程协议包含 Windows.h，先加载 Winsock2 保持无 Qt 宿主的正确包含顺序。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>

#include "../../../Ksword5.1/Ksword5.1/ksword/network/network.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "ProjectStorage.h"

#include <algorithm>
#include <deque>
#include <mutex>
#include <utility>

namespace Ksword::ActionAnalyze {
namespace {
namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;

// 有界邮箱只复制目标 PID 线索，所有磁盘写入都由外部串行归档通道完成。
struct CapturedRecord {
    ks::network::PacketRecord packet; // 原抓包器交付的统一报文，不重建字节。
    bool nativePid = false; // WFP row 原生 PID 与 R3 端口表补全明确区分。
    std::optional<std::uint64_t> timestamp100ns; // WFP 原始 FILETIME，不丢失到毫秒。
};

struct Mailbox {
    std::mutex mutex; // 保护原生回调与归档线程之间的包队列。
    std::deque<CapturedRecord> rows; // 仅拥有现有 PacketRecord 提供的字节。
    std::uint64_t dropped = 0; // 邮箱容量满后未能保留的本目标线索。
    std::vector<std::string> diagnostics; // 最多保存 16 条服务状态。
    bool failed = false; // 回调分配异常，交给所有者停止并报告部分结果。
};

// 将 FILETIME 原样转为无符号整数，用于请求进程身份复核。
std::uint64_t FileTime(const FILETIME& time)
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

// 从现有 PacketRecord 构造可归档视图；端口表只产生 PID 线索，不构造强实例 proof。
bool Observation(const ks::network::PacketRecord& packet, bool nativePid,
    ProjectNetworkObservation& out)
{
    if (!packet.processId || packet.wfpAleEventNoPayload || packet.packetBytes.empty() ||
        packet.direction == ks::network::PacketDirection::Unknown) return false;
    const auto version = packet.packetBytes.front() >> 4; // 原 IP 头决定地址族。
    if (version != 4 && version != 6) return false;
    const auto family = version == 4 ? AF_INET : AF_INET6; // 原包地址族对应的系统转换入口。
    auto& flow = out.flow; // 正文 span 借用当前批次拥有的 PacketRecord。
    flow.family = version == 4 ? Archive::NetworkFamily::IPv4 : Archive::NetworkFamily::IPv6;
    flow.transport = static_cast<Archive::NetworkTransport>(packet.protocol);
    flow.direction = packet.direction == ks::network::PacketDirection::Outbound ?
        Archive::NetworkDirection::Outbound : Archive::NetworkDirection::Inbound;
    Archive::NetworkEndpointMetadata local, remote; // 保留 local/remote 的原始端口语义。
    if (InetPtonA(family, packet.localAddress.c_str(), local.address.data()) != 1 ||
        InetPtonA(family, packet.remoteAddress.c_str(), remote.address.data()) != 1) return false;
    local.port = packet.localPort;
    remote.port = packet.remotePort;
    const bool outbound = flow.direction == Archive::NetworkDirection::Outbound; // 决定原local/remote端点方向。
    flow.sourceField = outbound ? local : remote;
    flow.destinationField = outbound ? remote : local;
    flow.processId = packet.processId;
    flow.processAttribution = nativePid ? Archive::NetworkFlowMetadata::ProcessAttribution::NativePidHint :
        Archive::NetworkFlowMetadata::ProcessAttribution::EndpointTableHint;
    constexpr std::uint64_t epoch = 116444736000000000ULL; // Unix ms 转 FILETIME；保留来源毫秒精度。
    if (packet.captureTimestampMs > (UINT64_MAX - epoch) / 10000) return false;
    flow.sourceTimestamp = epoch + packet.captureTimestampMs * 10000;
    flow.producerSequence = packet.sourceSequenceId ? packet.sourceSequenceId : packet.sequenceId;
    flow.observedBytes = packet.totalPacketSize;
    out.capture = {Archive::NetworkCaptureLayer::IpPacket, std::nullopt,
        packet.packetBytes, packet.packetBytesTruncated};
    // 旧 R3 totalPacketSize 夹紧到实收长度，不能拿它猜完整长度；保留 IP 头中的真实声明。
    if (version == 4 && packet.packetBytes.size() >= 20) {
        out.capture.originalLength = (std::uint32_t(packet.packetBytes[2]) << 8) | packet.packetBytes[3];
    } else if (version == 6 && packet.packetBytes.size() >= 40) {
        const auto payload = (std::uint32_t(packet.packetBytes[4]) << 8) | packet.packetBytes[5]; // 原IPv6声明的载荷长度。
        if (payload) out.capture.originalLength = payload + 40;
    }
    return !out.capture.originalLength || *out.capture.originalLength >= packet.packetBytes.size();
}

// 原 WFP ring row 已由 DriverClient 校验。只投影它的端点和字节，不另写抓包器或包解析器。
ks::network::PacketRecord WfpRecord(const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& row,
    ks::network::detail::ConnectionPidResolver& resolver)
{
    ks::network::PacketRecord packet; // 保存原WFP端点、字节前缀及来源序号。
    constexpr std::uint64_t epoch = 116444736000000000ULL; // FILETIME与Unix时间的纪元差。
    packet.captureTimestampMs = row.timestamp100ns >= epoch ? (row.timestamp100ns - epoch) / 10000 : 0;
    packet.protocol = static_cast<ks::network::PacketTransportProtocol>(row.protocol);
    packet.direction = row.direction == KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND ?
        ks::network::PacketDirection::Outbound : ks::network::PacketDirection::Inbound;
    packet.processId = row.processId;
    packet.sourceText = "R0-WFP-PACKET";
    packet.sourceSequenceId = row.sequence;
    packet.sourceFlags = row.flags;
    const auto family = row.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6 ? AF_INET6 : AF_INET; // 原驱动行地址族。
    char address[INET6_ADDRSTRLEN]{}; // 系统地址转换保留双栈端点。
    if (InetNtopA(family, row.localAddress, address, sizeof(address))) packet.localAddress = address;
    if (InetNtopA(family, row.remoteAddress, address, sizeof(address))) packet.remoteAddress = address;
    packet.localPort = row.localPort;
    packet.remotePort = row.remotePort;
    packet.totalPacketSize = row.totalPacketLength;
    packet.payloadSize = row.payloadLength;
    packet.payloadOffset = row.payloadOffset;
    packet.packetBytesTruncated = (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED) != 0;
    packet.packetBytes.assign(row.capturedBytes, row.capturedBytes + row.capturedLength);
    // 与网络 Tab 同样复用既有 IP Helper resolver；补全的 PID 仍明确标为端口表线索。
    if (!packet.processId && family == AF_INET) {
        std::uint32_t local = 0, remote = 0; // IP Helper解析器使用的原IPv4地址值。
        std::memcpy(&local, row.localAddress, sizeof(local));
        std::memcpy(&remote, row.remoteAddress, sizeof(remote));
        packet.processId = resolver.ResolveProcessId(packet.protocol, ntohl(local), row.localPort,
            ntohl(remote), row.remotePort);
    } else if (!packet.processId) {
        ks::network::detail::Ipv6Bytes local{}, remote{}; // IP Helper解析器使用的原IPv6地址值。
        std::memcpy(local.data(), row.localAddress, local.size());
        std::memcpy(remote.data(), row.remoteAddress, remote.size());
        packet.processId = resolver.ResolveProcessIdV6(packet.protocol, local, row.localPort, remote, row.remotePort);
    }
    return packet;
}
} // namespace

// 状态只借用原worker的项目与取消位；目标/邮箱先于服务构造，保证回调清退期间仍然有效。
struct NetworkTrafficSession::State {
    ProjectDocument& project; // 已由原API或独立入口持有的唯一项目写租约。
    NetworkTrafficCapturePlan plan; // 构造时冻结的单目标与来源，不接入子进程自动跟随。
    const std::atomic_bool& cancelled; // 所有者控制的取消位，生命周期覆盖整个会话。
    NetworkTrafficCaptureReceipt out; // 已提交水位及实时来源状态，不返回旧段冒充本次结果。
    Handle target; // 经过PID/创建时间复核的同一进程对象。
    Mailbox mailbox; // 来源线程只接触此邮箱及固定目标，不访问项目。
    ks::network::TrafficMonitorService service; // 原Raw Socket来源，Join仅由Close执行。
    ksword::ark::DriverClient driver; // 仅只读既有WFP ring，不改变全局来源状态。
    ks::network::detail::ConnectionPidResolver resolver; // 原弱PID解析器，不补造强实例身份。
    Archive::NetworkEvidenceBinding binding; // 本次采集独立来源代次及原sample绑定。
    ProjectNetworkCheckpoint checkpoint; // 原链续写水位，提交成功后才复制到回执。
    std::uint64_t cursor = 0; // WFP已消费的全局ring序号。
    std::uint64_t startUtc = 0; // 来源开始时刻，保留R3的毫秒精度。
    std::uint64_t started = 0; // 单调时钟起点，仅有界时长使用。
    std::optional<std::uint64_t> plannedEndUtc; // 无时限会话不设计划截止时间。
    std::optional<std::uint64_t> cutoffUtc; // 取消/退出/Close时冻结，禁止吸入后续同PID流量。
    std::optional<std::uint64_t> drainThrough; // WFP首次末轮查询的固定水位，不追赶新流量。
    std::uint64_t reportedGap = 0; // 已提交来源缺口，按段提交增量。
    std::uint64_t reportedDrops = 0; // 已提交邮箱丢弃，避免跨段重复累计。
    unsigned drainQueries = 0; // WFP有界排空查询次数。
    bool attempted = false; // Start只准尝试一次，失败后不静默重启来源。
    bool active = false; // 来源已接受启动，允许Poll读取及Close发终态。
    bool stopping = false; // 已冻结截止范围；Poll不join，等待所有者Close。
    bool closed = false; // Close完成后幂等返回，不重复写终态。
    bool wfpDrained = false; // WFP末轮固定范围已完成或明确记录排空缺口。

    // 保存外部引用与冻结值，构造不执行项目/来源操作。
    State(ProjectDocument& document, NetworkTrafficCapturePlan frozen, const std::atomic_bool& cancel)
        : project(document), plan(std::move(frozen)), cancelled(cancel)
    {
    }

    // 返回当前显式来源；非法枚举由Start拒绝，不按未知值隐式选择Raw Socket。
    bool Wfp() const
    {
        return plan.backend == NetworkTrafficBackend::ExistingWfp;
    }
    // 当前允许的最晚来源时间；无时限时使用实际当前时刻。
    std::uint64_t EndUtc() const;
    // 检查取消、目标退出、时长及来源状态，只请求停止而不阻塞join。
    void ObserveStop();
    // 冻结首次停止原因与截止时间，并通知原Raw Socket线程退出。
    void RequestStop(const char* reason);
    // 每次获取最多一个原批次；返回是否已取尽冻结的来源范围。
    bool ReadBatch(std::deque<CapturedRecord>& batch);
    // 原调用线程转换与提交原字节；finished只在Close排空后发布。
    void Commit(const std::deque<CapturedRecord>& batch, bool finished);
};

// 构造只持有冻结值；调用方必须保证原项目与取消位活到Close/析构之后。
NetworkTrafficSession::NetworkTrafficSession(ProjectDocument& project, NetworkTrafficCapturePlan plan,
    const std::atomic_bool& cancel)
    : state_(std::make_unique<State>(project, std::move(plan), cancel))
{
}

// 复用原sample与网络尾链，不申请第二writer；Raw Socket真实就绪由Poll回读。
bool NetworkTrafficSession::Start()
{
    auto& state = *state_; // 所有状态仅由原项目worker访问。
    if (state.attempted || state.closed)
    {
        return state.active && !state.stopping && !state.closed;
    }
    state.attempted = true;
    const auto& plan = state.plan; // 构造时冻结的身份及来源。
    auto& out = state.out; // 启动失败只更新本次回执，不返回旧网络检查点。
    out.cleanupConfirmed = true; // 在真正启动线程前，本会话尚无来源清退责任。
    if (!IsUuid(plan.sampleId) || !IsUuid(plan.bootId) || !plan.pid || plan.pid == UINT32_MAX ||
        !plan.creationFileTime || (plan.durationMs && plan.durationMs < 100) || plan.durationMs > 60000 ||
        (plan.backend != NetworkTrafficBackend::RawSocket && plan.backend != NetworkTrafficBackend::ExistingWfp))
    {
        out.status = Failure(ProjectError::InvalidArgument, "networkCapturePlan");
        return false;
    }
    if (state.cancelled.load())
    {
        out.reason = "cancelled";
        return false;
    }
    const auto* info = state.project.Info(); // 借用已打开项目，不修改其访问模式。
    if (!info || info->access != ProjectAccess::ReadWrite)
    {
        out.status = Failure(info ? ProjectError::ReadOnly : ProjectError::NotOpen, "networkCaptureProject");
        return false;
    }
    state.target = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, plan.pid));
    if (!state.target || state.target.get() == nullptr)
    {
        out.status = WinFailure("networkCaptureTarget", GetLastError());
        return false;
    }
    FILETIME created{}, exited{}, kernel{}, user{}; // 同一对象创建时间及存活状态，拒绝PID复用。
    if (!GetProcessTimes(state.target.get(), &created, &exited, &kernel, &user) ||
        FileTime(created) != plan.creationFileTime || WaitForSingleObject(state.target.get(), 0) != WAIT_TIMEOUT)
    {
        out.status = Failure(ProjectError::InvalidArgument, "networkCaptureTargetIdentity");
        return false;
    }
    out.status = LoadNetworkEvidenceTail(state.project, plan.sampleId, state.checkpoint);
    if (!out.status)
    {
        return false;
    }
    std::string epoch; // 每次显式会话生成来源代次，不与旧段序号混淆。
    out.status = NewId(epoch);
    if (!out.status)
    {
        return false;
    }
    state.binding = {UuidBytes(info->projectId), UuidBytes(plan.sampleId),
        state.Wfp() ? "ksword-r0-wfp-existing" : "ksword-r3-raw-socket", UuidBytes(epoch), epoch,
        plan.bootId, Archive::NetworkTimeDomain::FileTime, std::nullopt};

    // 回调只复制目标线索到原有界邮箱；捕获稳定State指针，绝不访问ProjectDocument。
    state.service.SetPacketCallback([owner = &state](const ks::network::PacketRecord& packet) noexcept
    {
        if (packet.processId != owner->plan.pid || WaitForSingleObject(owner->target.get(), 0) != WAIT_TIMEOUT)
        {
            return;
        }
        try
        {
            std::lock_guard lock(owner->mailbox.mutex); // 与worker交换当前目标字节的唯一锁。
            if (owner->mailbox.failed)
            {
                return;
            }
            if (owner->mailbox.rows.size() == Archive::kNetworkQueueCapacity)
            {
                ++owner->mailbox.dropped;
            }
            else
            {
                owner->mailbox.rows.push_back({packet, false, std::nullopt});
            }
        }
        catch (...)
        {
            std::lock_guard lock(owner->mailbox.mutex); // 异常只标记邮箱失败，由所有者停止来源。
            owner->mailbox.failed = true;
        }
    });
    state.service.SetStatusCallback([owner = &state](const std::string& message) noexcept
    {
        try
        {
            std::lock_guard lock(owner->mailbox.mutex); // 原服务状态有界保留，不写项目档案。
            if (owner->mailbox.diagnostics.size() < 16)
            {
                owner->mailbox.diagnostics.push_back(message);
            }
        }
        catch (...)
        {
            // 状态文字分配失败不改变来源清退责任。
        }
    });

    // 既有WFP只取当前cursor；Raw Socket只启动原服务，没有第二抓包实现。
    if (state.Wfp())
    {
        const auto initial = state.driver.queryNetworkTrafficPackets(0, 1); // 略过会话开始前的旧包。
        if (!initial.io.ok || initial.status != KSWORD_ARK_NETWORK_STATUS_APPLIED)
        {
            out.reason = "source-unavailable";
            out.diagnostics.push_back(initial.io.message);
            return false;
        }
        state.cursor = initial.newestSequence;
        out.sourceReady = true;
    }
    else if (!state.service.StartCapture())
    {
        out.reason = "source-unavailable";
        out.cleanupConfirmed = state.service.StopCapture();
        std::lock_guard lock(state.mailbox.mutex); // 启动失败收回已停止来源的诊断。
        out.diagnostics = std::move(state.mailbox.diagnostics);
        return false;
    }
    state.startUtc = UtcNow() / 10000 * 10000;
    state.started = GetTickCount64();
    if (plan.durationMs)
    {
        state.plannedEndUtc = state.startUtc + static_cast<std::uint64_t>(plan.durationMs) * 10000;
    }
    state.active = true;
    out.cleanupConfirmed = state.Wfp();
    return true;
}

// 读取当前允许的来源截止时间；Stop之后始终使用同一冻结值。
std::uint64_t NetworkTrafficSession::State::EndUtc() const
{
    const auto now = UtcNow(); // 当前墙钟仅用于来源时间过滤，不控制会话持续时长。
    return cutoffUtc.value_or(plannedEndUtc ? (std::min)(now, *plannedEndUtc) : now);
}

// 首次停止冻结边界并仅请求来源退出；此方法不等待来源线程。
void NetworkTrafficSession::State::RequestStop(const char* reason)
{
    if (stopping)
    {
        return;
    }
    out.reason = reason;
    cutoffUtc = EndUtc();
    if (out.reason == "target-exited")
    {
        FILETIME created{}, exited{}, kernel{}, user{}; // 同一对象的真实退出时刻收紧边界。
        if (GetProcessTimes(target.get(), &created, &exited, &kernel, &user) && FileTime(exited))
        {
            cutoffUtc = (std::min)(*cutoffUtc, FileTime(exited));
        }
    }
    stopping = true;
    if (!Wfp())
    {
        service.RequestStopCapture();
    }
}

// 原worker每轮用零超时检查对象与取消位；无时限不会按durationMs=0自动终止。
void NetworkTrafficSession::State::ObserveStop()
{
    if (stopping)
    {
        return;
    }
    out.sourceReady = out.sourceReady || (!Wfp() && service.IsCaptureReady());
    const auto alive = WaitForSingleObject(target.get(), 0); // 只观察已持有对象，不重新按PID查询。
    if (cancelled.load())
    {
        RequestStop("cancelled");
    }
    else if (alive == WAIT_OBJECT_0)
    {
        RequestStop("target-exited");
    }
    else if (alive != WAIT_TIMEOUT)
    {
        RequestStop("target-wait-failed");
    }
    else if (plan.durationMs && GetTickCount64() - started >= plan.durationMs)
    {
        RequestStop("duration-elapsed");
    }
    else if (!Wfp())
    {
        bool failed = false; // 原来源回调的内存失败只从邮箱取值。
        {
            std::lock_guard lock(mailbox.mutex); // 不在锁内写档或等待来源。
            failed = mailbox.failed;
        }
        if (failed)
        {
            RequestStop("callback-failed");
        }
        else if (!service.IsRunning())
        {
            RequestStop(out.sourceReady ? "source-ended" : "source-unavailable");
        }
    }
}

// 单轮至多取得kNetworkBatchRecords条，源回调不会等待归档；Close时返回是否排空。
bool NetworkTrafficSession::State::ReadBatch(std::deque<CapturedRecord>& batch)
{
    if (!Wfp())
    {
        std::lock_guard lock(mailbox.mutex); // 只搬移有界批次，正文所有权转给调用线程。
        while (!mailbox.rows.empty() && batch.size() < Archive::kNetworkBatchRecords)
        {
            batch.push_back(std::move(mailbox.rows.front()));
            mailbox.rows.pop_front();
        }
        out.queueDropped += std::exchange(mailbox.dropped, 0);
        return mailbox.rows.empty();
    }
    if (wfpDrained)
    {
        return true;
    }
    const auto previousCursor = cursor; // 防止全局ring末轮不前进。
    const auto queried = driver.queryNetworkTrafficPackets(cursor,
        static_cast<unsigned long>(Archive::kNetworkBatchRecords)); // 一次原只读IOCTL，不轮询等待。
    if (!queried.io.ok || queried.status != KSWORD_ARK_NETWORK_STATUS_APPLIED ||
        (queried.flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET))
    {
        RequestStop("source-ended");
        out.reason = "source-ended"; // 末轮读失败也必须覆盖原正常停止原因。
        out.diagnostics.push_back(queried.io.message);
        wfpDrained = true;
        return true;
    }
    if (stopping && !drainThrough)
    {
        drainThrough = queried.newestSequence;
    }
    cursor = queried.nextSequence;
    out.sourceGap += queried.cursorGapCount;
    for (const auto& row : queried.entries) // 只保留原目标PID线索，保持原WFP前缀和时间。
    {
        if (drainThrough && row.sequence > *drainThrough)
        {
            break;
        }
        auto packet = WfpRecord(row, resolver); // 复用网络页原弱PID映射。
        if (packet.processId == plan.pid)
        {
            batch.push_back({std::move(packet), row.processId != 0, row.timestamp100ns});
        }
    }
    if (stopping)
    {
        wfpDrained = cursor >= *drainThrough;
        if (!wfpDrained && (queried.entries.empty() || cursor <= previousCursor || ++drainQueries == 128))
        {
            out.sourceGap += *drainThrough - cursor;
            out.reason = "source-drain-incomplete";
            wfpDrained = true;
        }
    }
    return wfpDrained;
}

// 仅在原项目worker上同步提交。批次拥有正文，span有效期覆盖归档核验返回。
void NetworkTrafficSession::State::Commit(const std::deque<CapturedRecord>& batch, bool finished)
{
    std::vector<ProjectNetworkObservation> observations; // 原字节视图，不创建第二套包存储。
    std::uint64_t bytes = 0; // 此段实际保留的IP字节数。
    const auto endUtc = EndUtc(); // 本批次使用同一截止值，结束后不追随新流量。
    for (const auto& captured : batch) // 原记录只在调用线程投影，不提升进程归属强度。
    {
        const auto& packet = captured.packet; // 原抓包器拥有的IP字节与端点。
        ProjectNetworkObservation observation; // 当前原始记录对应的归档视图。
        if (!Observation(packet, captured.nativePid, observation))
        {
            ++out.unsupportedPackets;
            continue;
        }
        if (captured.timestamp100ns)
        {
            observation.flow.sourceTimestamp = *captured.timestamp100ns;
            observation.flow.packetSourceFlags = packet.sourceFlags;
        }
        if (observation.flow.sourceTimestamp < startUtc || observation.flow.sourceTimestamp > endUtc)
        {
            continue;
        }
        bytes += observation.capture.bytes.size();
        observations.push_back(observation);
    }
    if (observations.empty() && !finished)
    {
        return;
    }
    Archive::NetworkLoss loss; // 原来源没有完整系统丢包计数，覆盖始终未知。
    loss.sourceLost = out.sourceGap - reportedGap + out.queueDropped - reportedDrops;
    loss.sourceLossUnquantified = true;
    ProjectNetworkEvidenceReceipt receipt; // 本批次原归档器回执，成功后才推进外部水位。
    const auto reason = finished ? out.reason : "segment-rotated"; // 末段才携带终态原因。
    const bool failed = out.reason == "source-ended" || out.reason == "target-wait-failed" ||
        out.reason == "callback-failed" || out.reason == "source-drain-incomplete";
    const auto end = failed ? Archive::NetworkArchiveEnd::SourceFailed : out.sourceReady ?
        Archive::NetworkArchiveEnd::Stopped : Archive::NetworkArchiveEnd::SourceUnavailable;
    out.status = CommitNetworkEvidence(project, plan.sampleId, binding, observations, loss, end,
        plan.pid, plan.creationFileTime, reason, checkpoint, receipt);
    if (!out.status)
    {
        RequestStop("archive-failed");
        out.reason = "archive-failed"; // 不重试坏尾或把旧水位冒充本次成功提交。
        return;
    }
    out.checkpoint = checkpoint;
    reportedGap = out.sourceGap;
    reportedDrops = out.queueDropped;
    out.packets += observations.size();
    out.capturedBytes += bytes;
}

// 每轮只服务一个批次，无等待/休眠/Join；来源终止后留给Close统一排空与终态提交。
void NetworkTrafficSession::Poll()
{
    auto& state = *state_; // 原worker独占的会话状态。
    if (!state.active || state.closed || state.stopping)
    {
        return;
    }
    state.ObserveStop();
    if (state.stopping)
    {
        return;
    }
    std::deque<CapturedRecord> batch; // 本轮有界批次，离开函数后释放原包所有权。
    state.ReadBatch(batch);
    state.Commit(batch, false);
}

// 所有者结束时同步停止并排空；不启停WFP，不关闭借用的项目，不新建writer。
void NetworkTrafficSession::Close()
{
    auto& state = *state_; // 原API或独立入口持有的同一状态。
    if (state.closed)
    {
        return;
    }
    if (state.active)
    {
        state.ObserveStop();
        state.RequestStop("stopped"); // 已存在的取消/退出/失败原因保持原值。
        if (!state.Wfp())
        {
            state.out.cleanupConfirmed = state.service.StopCapture();
            // Join之后不会再进回调，尾部诊断和失败标记均来自原邮箱。
            std::lock_guard lock(state.mailbox.mutex); // 短锁不跨归档提交。
            state.out.diagnostics = std::move(state.mailbox.diagnostics);
            if (state.mailbox.failed && state.out.status)
            {
                state.out.reason = "callback-failed";
            }
        }
        while (state.out.status) // 邮箱有限；WFP额外受固定水位及128次查询约束。
        {
            std::deque<CapturedRecord> batch; // 逐批搬移，保留原包span直到本段提交返回。
            const bool drained = state.ReadBatch(batch); // 停止后才判断最后一批。
            state.Commit(batch, drained);
            if (drained)
            {
                break;
            }
        }
    }
    if (!state.Wfp())
    {
        std::lock_guard lock(state.mailbox.mutex); // 写档失败也回收尚未交接的真实邮箱丢弃计数。
        state.out.queueDropped += std::exchange(state.mailbox.dropped, 0);
    }
    // 写档失败时也已先停止来源，未提交邮箱不重试；保留真实错误及最后成功水位。
    state.active = false;
    state.closed = true;
    state.target.reset();
}

// 返回同一worker读取的原回执；不翻译、不回读项目、不改变来源状态。
const NetworkTrafficCaptureReceipt& NetworkTrafficSession::Receipt() const
{
    return state_->out;
}

// 显式Close为正常使用路径；异常离开时仍清退原来源，避免回调访问已析构邮箱。
NetworkTrafficSession::~NetworkTrafficSession()
{
    try
    {
        Close();
    }
    catch (...)
    {
        state_->service.StopCapture(); // 原服务先Join，State成员之后才逆序析构。
    }
}

// 兼容独立CLI/Qt/Light：保持原有时长准入，唯一循环驱动同一个会话实现。
NetworkTrafficCaptureReceipt CaptureNetworkTraffic(ProjectDocument& project,
    const NetworkTrafficCapturePlan& plan, const std::atomic_bool& cancelled)
{
    if (plan.durationMs < 100 || plan.durationMs > 60000)
    {
        NetworkTrafficCaptureReceipt out; // 非法独立请求不启动来源或创建网络段。
        out.status = Failure(ProjectError::InvalidArgument, "networkCapturePlan");
        return out;
    }
    NetworkTrafficSession session(project, plan, cancelled); // 借用独立入口原先打开的写租约。
    if (session.Start())
    {
        while (session.Receipt().reason.empty()) // 等待只属于旧同步入口，Poll本身不等待。
        {
            session.Poll();
            if (session.Receipt().reason.empty())
            {
                Sleep(25);
            }
        }
    }
    session.Close();
    return session.Receipt();
}

} // namespace Ksword::ActionAnalyze
