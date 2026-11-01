#include "ProcessNetworkController.h"
#include <QDataStream>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <deque>
#include <map>

namespace ks::network {
namespace {
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) ::CloseHandle(value); }
};
bool alive(HANDLE handle) { return handle && ::WaitForSingleObject(handle, 0) == WAIT_TIMEOUT; }
std::shared_ptr<Handle> openTarget(const ProcessNetworkTarget& target, QString& error)
{
    if (!target.pid || !target.creationTime100ns) { error = QStringLiteral("无法确认目标进程身份。"); return {}; }
    auto handle = std::make_shared<Handle>();
    handle->value = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.pid);
    FILETIME created{}, exit{}, kernel{}, user{};
    if (!handle->value || !::GetProcessTimes(handle->value, &created, &exit, &kernel, &user)
        || ((static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime) != target.creationTime100ns
        || !alive(handle->value)) { error = QStringLiteral("目标进程已退出、身份已变化或没有查询权限。"); return {}; }
    if (!target.imagePath.empty()) {
        std::wstring path(32768, L'\0'); DWORD length = static_cast<DWORD>(path.size());
        if (!::QueryFullProcessImageNameW(handle->value, 0, path.data(), &length)) {
            error = QStringLiteral("无法复核进程映像路径。"); return {};
        }
        path.resize(length);
        if (_wcsicmp(path.c_str(), target.imagePath.c_str()) != 0) {
            error = QStringLiteral("进程映像路径与目标快照不一致。"); return {};
        }
    }
    return handle;
}
struct Subscription {
    std::mutex mutex;
    std::shared_ptr<Handle> process;
    std::atomic_bool active{true};
    std::uint32_t pid = 0;
    std::deque<PacketRecord> pending;
    std::uint64_t dropped = 0, rx = 0, tx = 0;
};
class CaptureHub final {
public:
    CaptureHub() {
        service.SetPacketCallback([this](const PacketRecord& packet) {
            std::vector<std::shared_ptr<Subscription>> recipients;
            { std::lock_guard lock(routesMutex);
                for (const auto& [key, weak] : routes) {
                    (void)key;
                    if (auto sub = weak.lock(); sub && sub->pid == packet.processId) recipients.push_back(std::move(sub));
                }
            }
            for (const auto& sub : recipients) {
                if (!sub->active.load() || !alive(sub->process->value)) { sub->active.store(false); continue; }
                std::lock_guard lock(sub->mutex);
                if (!sub->active.load()) continue;
                if (packet.direction == PacketDirection::Inbound) sub->rx += packet.totalPacketSize;
                if (packet.direction == PacketDirection::Outbound) sub->tx += packet.totalPacketSize;
                if (sub->pending.size() >= 1024) { sub->pending.pop_front(); ++sub->dropped; }
                sub->pending.push_back(packet);
            }
        });
        service.SetStatusCallback([this](const std::string& message) { std::lock_guard lock(statusMutex); status = QString::fromUtf8(message); });
    }
    ~CaptureHub() { service.StopCapture(); }
    std::uint64_t subscribe(const std::shared_ptr<Subscription>& sub) {
        std::lock_guard life(lifecycleMutex);
        std::uint64_t key = 0;
        { std::lock_guard lock(routesMutex); key = ++next; routes[key] = sub; }
        if (!service.StartCapture()) { std::lock_guard lock(routesMutex); routes.erase(key); return 0; }
        return key;
    }
    void unsubscribe(std::uint64_t key) {
        if (!key) return;
        std::lock_guard life(lifecycleMutex);
        bool empty = false;
        { std::lock_guard lock(routesMutex); routes.erase(key); empty = routes.empty(); }
        if (empty) service.RequestStopCapture();
    }
    QString diagnostic() { std::lock_guard lock(statusMutex); return status; }
    TrafficMonitorService service;
private:
    std::mutex lifecycleMutex, routesMutex, statusMutex;
    std::map<std::uint64_t, std::weak_ptr<Subscription>> routes;
    std::uint64_t next = 0;
    QString status;
};
CaptureHub& hub() { static CaptureHub value; return value; }
struct ConnectionCache {
    std::mutex mutex;
    std::chrono::steady_clock::time_point sampled;
    ks::r3::network::ConnectionEnumerationResult result;
};
ConnectionCache& connectionCache() { static ConnectionCache value; return value; }
bool sameConnection(const ks::r3::network::ConnectionEntry& a, const ks::r3::network::ConnectionEntry& b)
{
    return a.protocol == b.protocol && a.processId == b.processId && a.localAddress == b.localAddress
        && a.remoteAddress == b.remoteAddress && a.localPort == b.localPort && a.remotePort == b.remotePort;
}
bool rawIpPacket(const PacketRecord& packet)
{
    if (packet.wfpAleEventNoPayload || packet.packetBytes.empty()) return false;
    const auto version = packet.packetBytes.front() >> 4;
    return (version == 4 && packet.packetBytes.size() >= 20) || (version == 6 && packet.packetBytes.size() >= 40);
}
}
struct ProcessNetworkController::State {
    explicit State(ProcessNetworkTarget value) : target(std::move(value)) {}
    ProcessNetworkTarget target;
    std::mutex mutex;
    std::atomic<std::uint64_t> generation{0};
    std::shared_ptr<Subscription> subscription;
    std::uint64_t lease = 0;
};
ProcessNetworkController::ProcessNetworkController(ProcessNetworkTarget target) : m_state(std::make_shared<State>(std::move(target))) {}
ProcessNetworkController::~ProcessNetworkController() { stopCapture(); }
const ProcessNetworkTarget& ProcessNetworkController::target() const { return m_state->target; }
ProcessNetworkResult ProcessNetworkController::validateTarget(const ProcessNetworkTarget& target)
{
    QString error; const auto handle = openTarget(target, error);
    return {bool(handle), handle ? QStringLiteral("目标进程身份已确认。") : error};
}
std::uint64_t ProcessNetworkController::beginStartRequest() { return ++m_state->generation; }
ProcessNetworkResult ProcessNetworkController::startCapture(const std::uint64_t generation)
{
    const auto state = m_state;
    if (state->generation.load() != generation) return {false, QStringLiteral("启动请求已停止。")};
    QString error; const auto process = openTarget(state->target, error);
    if (!process) return {false, error};
    auto sub = std::make_shared<Subscription>(); sub->process = process; sub->pid = state->target.pid;
    const auto lease = hub().subscribe(sub);
    if (!lease) return {false, QStringLiteral("抓包服务启动失败。")};
    std::shared_ptr<Subscription> previous; std::uint64_t previousLease = 0; bool accepted = false;
    { std::lock_guard lock(state->mutex);
        if (state->generation.load() == generation) {
            previous = std::move(state->subscription); previousLease = state->lease;
            state->subscription = sub; state->lease = lease; accepted = true;
        }
    }
    if (!accepted) { sub->active.store(false); hub().unsubscribe(lease); return {false, QStringLiteral("启动请求已停止。")}; }
    if (previous) previous->active.store(false);
    hub().unsubscribe(previousLease);
    return {true, QStringLiteral("报文捕获已启动；当前进程的报文将显示在右侧。")};
}
void ProcessNetworkController::stopCapture()
{
    const auto state = m_state; ++state->generation;
    std::shared_ptr<Subscription> sub; std::uint64_t lease = 0;
    { std::lock_guard lock(state->mutex); sub = std::move(state->subscription); lease = std::exchange(state->lease, 0); }
    if (sub) sub->active.store(false);
    if (lease) hub().unsubscribe(lease);
}
ProcessPacketBatch ProcessNetworkController::takePackets(const std::size_t maximum)
{
    ProcessPacketBatch output;
    std::shared_ptr<Subscription> sub;
    { std::lock_guard lock(m_state->mutex); sub = m_state->subscription; }
    if (!sub) return output;
    output.targetAlive = alive(sub->process->value); output.active = sub->active.load() && output.targetAlive;
    output.serviceRunning = hub().service.IsRunning(); output.status = hub().diagnostic();
    std::lock_guard lock(sub->mutex);
    output.dropped = sub->dropped; output.receivedBytes = sub->rx; output.sentBytes = sub->tx;
    const auto count = (std::min)(maximum, sub->pending.size()); output.packets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) { output.packets.push_back(std::move(sub->pending.front())); sub->pending.pop_front(); }
    return output;
}
ks::r3::network::ConnectionEnumerationResult ProcessNetworkController::connections(const ProcessNetworkTarget& target)
{
    QString error; const auto process = openTarget(target, error);
    if (!process) return {false, error.toStdWString(), {}};
    auto& cache = connectionCache(); std::lock_guard lock(cache.mutex);
    const auto now = std::chrono::steady_clock::now();
    if (cache.sampled.time_since_epoch().count() == 0 || now - cache.sampled > std::chrono::seconds(1)) {
        cache.result = ks::r3::network::EnumerateConnections(); cache.sampled = now;
    }
    ks::r3::network::ConnectionEnumerationResult result;
    result.success = cache.result.success; result.diagnosticText = cache.result.diagnosticText;
    for (const auto& row : cache.result.entries) if (row.processId == target.pid) result.entries.push_back(row);
    if (!alive(process->value)) return {false, L"目标进程已退出，连接结果未发布。", {}};
    return result;
}
ProcessNetworkResult ProcessNetworkController::disconnect(const ProcessNetworkTarget& target, const ks::r3::network::ConnectionEntry& connection)
{
    QString error; const auto process = openTarget(target, error);
    if (!process) return {false, error};
    if (connection.processId != target.pid) return {false, QStringLiteral("连接不属于当前进程。")};
    const auto current = ks::r3::network::EnumerateConnections();
    const auto found = std::find_if(current.entries.cbegin(), current.entries.cend(), [&](const auto& row) { return sameConnection(row, connection); });
    if (found == current.entries.cend() || !alive(process->value)) return {false, QStringLiteral("连接或进程身份已变化，请刷新后重试。")};
    const auto result = ks::r3::network::CloseTcpConnection(*found);
    return {result.success, QString::fromStdWString(result.message)};
}
ProcessNetworkResult ProcessNetworkController::exportPcap(const QString& path, const std::vector<PacketRecord>& packets)
{
    QSaveFile file(path); if (!file.open(QIODevice::WriteOnly)) return {false, file.errorString()};
    QDataStream stream(&file); stream.setByteOrder(QDataStream::LittleEndian);
    stream << quint32(0xa1b2c3d4) << quint16(2) << quint16(4) << qint32(0) << quint32(0) << quint32(65535) << quint32(101); // DLT_RAW
    std::size_t written = 0, skipped = 0;
    for (const auto& packet : packets) {
        if (!rawIpPacket(packet)) { ++skipped; continue; }
        const auto retained = static_cast<quint32>((std::min<std::size_t>)(packet.packetBytes.size(), 65535));
        stream << quint32(packet.captureTimestampMs / 1000) << quint32((packet.captureTimestampMs % 1000) * 1000)
            << retained << quint32((std::max)(packet.totalPacketSize, retained));
        stream.writeRawData(reinterpret_cast<const char*>(packet.packetBytes.data()), static_cast<int>(retained)); ++written;
    }
    if (stream.status() != QDataStream::Ok || !file.commit()) return {false, file.errorString()};
    return {true, QStringLiteral("PCAP 已保存：%1 个真实 IP 报文；%2 条无原始字节的事件未写入。截断报文保留实际捕获长度。").arg(written).arg(skipped)};
}
ProcessNetworkResult ProcessNetworkController::exportDump(const QString& path, const std::vector<PacketRecord>& packets)
{
    QSaveFile file(path); if (!file.open(QIODevice::WriteOnly)) return {false, file.errorString()};
    for (const auto& packet : packets) {
        const QJsonObject value{{QStringLiteral("timestampMs"), QString::number(packet.captureTimestampMs)},
            {QStringLiteral("sequence"), QString::number(packet.sequenceId)}, {QStringLiteral("pid"), static_cast<qint64>(packet.processId)},
            {QStringLiteral("direction"), QString::fromStdString(PacketDirectionToString(packet.direction))},
            {QStringLiteral("protocol"), QString::fromStdString(PacketProtocolToString(packet.protocol))},
            {QStringLiteral("local"), QString::fromStdString(packet.localAddress)}, {QStringLiteral("remote"), QString::fromStdString(packet.remoteAddress)},
            {QStringLiteral("localPort"), packet.localPort}, {QStringLiteral("remotePort"), packet.remotePort},
            {QStringLiteral("wireLength"), static_cast<qint64>(packet.totalPacketSize)}, {QStringLiteral("truncated"), packet.packetBytesTruncated},
            {QStringLiteral("metadataOnly"), packet.wfpAleEventNoPayload},
            {QStringLiteral("hex"), QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(packet.packetBytes.data()), static_cast<qsizetype>(packet.packetBytes.size())).toHex())}};
        const auto line = QJsonDocument(value).toJson(QJsonDocument::Compact) + '\n';
        if (file.write(line) != line.size()) return {false, file.errorString()};
    }
    if (!file.commit()) return {false, file.errorString()};
    return {true, QStringLiteral("报文数据已保存为 JSONL。")};
}
}
