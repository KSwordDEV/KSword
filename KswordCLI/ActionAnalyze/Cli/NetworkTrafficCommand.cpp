#include "NetworkTrafficCommand.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "../../CommandRegistry.h"
#include "../Project/NetworkTrafficCapture.h"
#include "../Project/ProjectStorage.h"

#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;

// CLI UUID 使用 ASCII，异常输入不能在宽窄转换中被静默丢弃或替换。
std::string Uuid(const std::wstring& value)
{
    std::string text;
    for (const auto ch : value) {
        if (ch > 127) throw std::invalid_argument("Expected an ASCII UUID");
        text.push_back(static_cast<char>(ch));
    }
    if (!storage::IsUuid(text)) throw std::invalid_argument("Expected a UUID");
    return text;
}

// 统一返回项目错误，保留原生错误码及具体责任阶段。
Json Issue(const project::ProjectResult& status)
{
    if (status) return {};
    return Json::object({{L"error", Json::string(storage::WideAscii(project::ProjectErrorName(status.error)))},
        {L"detail", Json::string(storage::WideAscii(status.detail))}, {L"win32Error", Json::number(status.nativeError)}});
}

// 将已校验的归档网络序地址输出为可阅读的端点，端口保持有值零与缺失的区别。
Json Endpoint(const archive::NetworkEndpointMetadata& endpoint, archive::NetworkFamily family)
{
    char address[INET6_ADDRSTRLEN]{};
    const auto native = family == archive::NetworkFamily::IPv4 ? AF_INET : AF_INET6;
    const auto* text = InetNtopA(native, endpoint.address.data(), address, sizeof(address));
    return Json::object({{L"address", text ? Json::string(storage::WideAscii(address)) : Json{}},
        {L"port", endpoint.port ? Json::number(*endpoint.port) : Json{}}});
}

// 来源标签来自新归档字段；缺字段的历史档继续使用原有强实例语义。
std::wstring Attribution(archive::NetworkFlowMetadata::ProcessAttribution value)
{
    using enum archive::NetworkFlowMetadata::ProcessAttribution;
    switch (value) {
    case EndpointTableHint: return L"endpoint-table-hint";
    case NativePidHint: return L"native-pid-hint";
    case VerifiedInstance: return L"verified-instance";
    }
    return L"unknown";
}

// 输入记录的实际采集层，输出稳定机器值；不根据TCP端口推测HTTPS明文或应用层负载。
const wchar_t* CaptureLayer(archive::NetworkCaptureLayer layer)
{
    switch (layer)
    {
    case archive::NetworkCaptureLayer::FlowMetadata:
        return L"flow-metadata";
    case archive::NetworkCaptureLayer::TransportPayload:
        return L"transport-payload";
    case archive::NetworkCaptureLayer::IpPacket:
        return L"ip-packet";
    case archive::NetworkCaptureLayer::LinkFrame:
        return L"link-frame";
    }
    return L"unknown";
}

// 输入原归档字节状态，输出与桌面详情相同的口径；captured不自动等于complete。
const wchar_t* PayloadState(archive::NetworkPayloadState state)
{
    switch (state)
    {
    case archive::NetworkPayloadState::MetadataOnly:
        return L"metadata-only";
    case archive::NetworkPayloadState::NoPayload:
        return L"no-payload";
    case archive::NetworkPayloadState::Complete:
        return L"complete";
    case archive::NetworkPayloadState::Truncated:
        return L"truncated";
    case archive::NetworkPayloadState::Captured:
        return L"captured";
    }
    return L"unknown";
}

// 将同一段保存的实例窗口原样返回CLI；输入为已核验快照，输出不授予实时控制或逐包强归属。
Json TargetWindows(const std::vector<project::ProjectNetworkTargetWindow>& windows)
{
    std::vector<Json> result; // 与当前网络段一致的采集范围，旧档没有窗口时保持空数组。
    result.reserve(windows.size());
    for (const auto& window : windows)
    {
        result.push_back(Json::object({{L"pid", Json::number(window.pid)},
            {L"creationFileTime", Json::count(window.creationFileTime)},
            {L"startUtc", Json::count(window.startUtc)},
            {L"endUtc", window.endUtc ? Json::count(window.endUtc) : Json{}},
            {L"root", Json::boolean(window.root)},
            {L"endReason", Json::string(storage::WideAscii(window.endReason))}}));
    }
    return Json::array(result);
}

// 已存在 sample 是唯一结果归属；显式来源选择没有 R0/R3 失败后的隐式切换。
Result Capture(const Args& args, const std::string& bootId)
{
    project::NetworkTrafficCapturePlan plan;
    plan.sampleId = Uuid(args.require(L"--sample"));
    plan.bootId = bootId;
    plan.pid = args.u32(L"--pid");
    plan.creationFileTime = args.integer(L"--create-time");
    plan.durationMs = args.u32(L"--duration-ms");
    const auto source = args.get(L"--source", L"raw-socket"); // 用户明确选择的采集能力。
    if (source == L"raw-socket") plan.backend = project::NetworkTrafficBackend::RawSocket;
    else if (source == L"existing-wfp") plan.backend = project::NetworkTrafficBackend::ExistingWfp;
    else throw std::invalid_argument("Use --source raw-socket or existing-wfp");
    if (!plan.pid || !plan.creationFileTime || plan.durationMs < 100 || plan.durationMs > 60000) {
        throw std::invalid_argument("Expected a PID, creation FILETIME and duration of 100..60000 ms");
    }
    project::ProjectDocument document; // 同一项目的写租约覆盖采集和检查点发布全过程。
    const auto opened = document.Open(args.require(L"--project"), project::ProjectAccess::ReadWrite);
    if (!opened) return {3, Json::object({{L"projectError", Issue(opened)}}), {}};
    const Cancellation cancellation;
    const auto receipt = project::CaptureNetworkTraffic(document, plan, *cancellation.token);
    std::vector<Json> diagnostics; // 原始服务 UTF-8 状态转为 CLI Unicode，避免 ASCII 扩展损坏中文。
    for (const auto& message : receipt.diagnostics) {
        const auto count = MultiByteToWideChar(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), nullptr, 0);
        std::wstring text(count > 0 ? static_cast<std::size_t>(count) : 0, L'\0');
        if (count > 0) MultiByteToWideChar(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), text.data(), count);
        diagnostics.push_back(Json::string(text));
    }
    // 即使有有效正文，也不把原抓包器未知覆盖率包装为完整采集成功。
    const int code = !receipt.status ? 3 : !receipt.sourceReady ? 5 :
        receipt.reason == "duration-elapsed" && receipt.cleanupConfirmed && !receipt.queueDropped &&
            !receipt.sourceGap && !receipt.unsupportedPackets ? 0 : 6;
    return {code, Json::object({
        {L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(plan.sampleId))}, {L"stream", Json::string(L"raw-network")},
        {L"checkpointDirectory", Json::string(L"checkpoints-network")},
        {L"source", Json::string(source)}, {L"captureLayer", Json::string(L"ip-packet")},
        {L"captureCoverage", Json::string(L"unknown")}, {L"sourceReady", Json::boolean(receipt.sourceReady)},
        {L"requestedPid", Json::number(plan.pid)}, {L"requestedCreationFileTime", Json::count(plan.creationFileTime)},
        {L"targetWindows", TargetWindows(receipt.targets)},
        {L"processAttribution", Json::string(source == L"raw-socket" ? L"endpoint-table-hint" : L"per-record-pid-hint")},
        {L"reason", Json::string(storage::WideAscii(receipt.reason))},
        {L"ordinal", Json::count(receipt.checkpoint.ordinal)}, {L"endOffset", Json::count(receipt.checkpoint.endOffset)},
        {L"lastSequence", Json::count(receipt.checkpoint.lastSequence)},
        {L"sha256", Json::string(storage::WideAscii(receipt.checkpoint.sha256))},
        {L"packetCount", Json::count(receipt.packets)}, {L"capturedLength", Json::count(receipt.capturedBytes)},
        {L"queueDropped", Json::count(receipt.queueDropped)}, {L"sourceCursorGap", Json::count(receipt.sourceGap)},
        {L"unsupportedPackets", Json::count(receipt.unsupportedPackets)},
        {L"cleanupConfirmed", Json::boolean(receipt.cleanupConfirmed)}, {L"projectError", Issue(receipt.status)},
        {L"sourceDiagnostics", Json::array(diagnostics)}}), {}};
}

// 只读原 sample 已发布的网络段。可选精确序号返回完整内联字节，默认给有界预览。
Result Read(const Args& args)
{
    const auto sampleId = Uuid(args.require(L"--sample"));
    const auto ordinal = args.integer(L"--ordinal");
    const auto selected = args.integer(L"--record-sequence");
    project::ProjectDocument document;
    if (const auto opened = document.Open(args.require(L"--project")); !opened) {
        return {3, Json::object({{L"projectError", Issue(opened)}}), {}};
    }
    project::ProjectNetworkCheckpoint checkpoint; // 查询先核验网络检查点，不读取未发布尾部。
    std::vector<Json> rows;
    const auto status = project::ReadNetworkEvidence(document, sampleId, ordinal, checkpoint,
        [&](const auto&, const auto& flows, std::span<const archive::RecordView> records) {
            for (std::size_t index = 0; index < flows.size(); ++index) {
                const auto& row = flows[index];
                if (selected && row.recordSequence != selected) continue;
                if (rows.size() == archive::kNetworkQueueCapacity) break;
                const auto projected = archive::ProjectNetworkFlowRecord(
                    {archive::StreamKind::Raw, ordinal, storage::UuidBytes(document.Info()->projectId),
                        storage::UuidBytes(sampleId)}, records[index]);
                if (!projected) continue;
                const auto& flow = row.observation;
                std::vector<std::uint8_t> bytes(projected->inlineBytes.begin(), projected->inlineBytes.end());
                rows.push_back(Json::object({{L"recordSequence", Json::count(row.recordSequence)},
                    {L"recordOffset", Json::count(row.recordOffset)}, {L"pid", Json::number(flow.processId)},
                    {L"processAttribution", Json::string(Attribution(flow.processAttribution))},
                    {L"creationFileTime", flow.processCreatedUtc100ns ? Json::count(flow.processCreatedUtc100ns) : Json{}},
                    {L"direction", Json::string(flow.direction == archive::NetworkDirection::Outbound ? L"outbound" : L"inbound")},
                    {L"protocol", Json::string(flow.transport == archive::NetworkTransport::Tcp ? L"TCP" : L"UDP")},
                    {L"sourceEndpoint", Endpoint(flow.sourceField, flow.family)},
                    {L"destinationEndpoint", Endpoint(flow.destinationField, flow.family)},
                    {L"sourceFileTime", Json::count(flow.sourceTimestamp)},
                    {L"producerSequence", flow.producerSequence ? Json::count(*flow.producerSequence) : Json{}},
                    {L"packetSourceFlags", flow.packetSourceFlags ? Json::number(*flow.packetSourceFlags) : Json{}},
                    {L"capturedLength", Json::number(row.capture.capturedLength)},
                    {L"captureLayer", Json::string(CaptureLayer(row.capture.layer))},
                    {L"payloadState", Json::string(PayloadState(row.capture.state))},
                    {L"producerCapturedLength", Json::count(row.capture.producerCapturedLength)},
                    {L"sourceTruncated", Json::boolean(row.capture.sourceTruncated)},
                    {L"originalLength", row.capture.originalLength ? Json::count(*row.capture.originalLength) : Json{}},
                    {L"truncated", Json::boolean(row.capture.sourceTruncated || row.capture.state == archive::NetworkPayloadState::Truncated)},
                    {L"bytes", Json::bytes(bytes, selected ? archive::kNetworkMaxInlineBytes : 64)}}));
            }
        });
    if (!status) return {3, Json::object({{L"projectError", Issue(status)}}), {}};
    return {selected && rows.empty() ? 5 : 0, Json::object({
        {L"projectId", Json::string(storage::WideAscii(document.Info()->projectId))},
        {L"sampleId", Json::string(storage::WideAscii(sampleId))}, {L"stream", Json::string(L"raw-network")},
        {L"ordinal", Json::count(checkpoint.ordinal)}, {L"checkpointVerified", Json::boolean(true)},
        {L"sha256", Json::string(storage::WideAscii(checkpoint.sha256))},
        {L"sourceId", Json::string(storage::WideAscii(checkpoint.source.sourceId))},
        {L"sourceClockId", Json::string(storage::WideAscii(checkpoint.source.clockId))},
        {L"sourceTimeDomain", Json::string(checkpoint.source.clockDomain == archive::NetworkTimeDomain::FileTime ? L"filetime" : L"qpc")},
        {L"requestedPid", Json::number(checkpoint.requestedPid)},
        {L"requestedCreationFileTime", Json::count(checkpoint.requestedCreation)},
        {L"targetWindows", TargetWindows(checkpoint.targetWindows)},
        {L"loss", Json::object({{L"queueDropped", Json::count(checkpoint.loss.queueDropped)},
            {L"sourceLost", Json::count(checkpoint.loss.sourceLost)},
            {L"sourceLossUnquantified", Json::boolean(checkpoint.loss.sourceLossUnquantified)},
            {L"queueCounterSaturated", Json::boolean(checkpoint.loss.queueCounterSaturated)},
            {L"sourceCounterSaturated", Json::boolean(checkpoint.loss.sourceCounterSaturated)}})},
        {L"stopReason", Json::string(storage::WideAscii(checkpoint.stopReason))}, {L"records", Json::array(rows)}}), {}};
}
} // namespace

// 由既有 RegisterNetworkCaptureCommand 接入正式命令目录和 help，不触碰旧主入口文件。
void RegisterNetworkTrafficCommands(std::function<std::string()> bootId)
{
    Command capture;
    capture.path = L"analyze network-traffic";
    capture.syntax = L"KswordCLI.exe analyze network-traffic --project PATH --sample UUID --pid PID --create-time FILETIME --duration-ms MS [--source raw-socket|existing-wfp] [--json]";
    capture.summary = L"Capture real IP packet bytes into an existing ActionAnalyze sample using the Network traffic monitor backend.";
    capture.options = L"The sample must already exist. Duration: 100..60000 ms. Source defaults to raw-socket; existing-wfp reads an already enabled WFP ring.";
    capture.notes = L"Raw sockets observe interfaces and filter PID hints after capture. PID hints are not verified event-time process instances. Requires capture permissions. WFP is read-only and never enables, disables or resets global capture. Coverage is unknown; HTTPS decryption is deferred. Output: raw-network plus checkpoints-network; read with analyze network-read.";
    capture.run = [bootId = std::move(bootId)](const Args& args) { return Capture(args, bootId()); };
    addCommand(std::move(capture));
    Command read;
    read.path = L"analyze network-read";
    read.syntax = L"KswordCLI.exe analyze network-read --project PATH --sample UUID --ordinal N [--record-sequence N] [--json]";
    read.summary = L"Verify and read a committed sample-local network segment and its captured bytes.";
    read.options = L"Select a committed network ordinal. Optional --record-sequence returns all retained bytes for one exact record; otherwise each record has a 64-byte preview.";
    read.notes = L"Read-only. Verifies sample identity, checkpoint SHA-256, framing, network bodies and adjacent checkpoint chain. targetWindows preserves the registered process identities and capture intervals from this checkpoint; it does not upgrade packet PID hints to verified event-time instances. Source declarations and weak PID attribution remain explicit.";
    read.notes += L" Each record preserves captureLayer, payloadState, producerCapturedLength and sourceTruncated separately from retained bytes. IP packet bytes are not application payload or decrypted HTTPS. sourceTimeDomain and sourceClockId describe the original timestamp scale.";
    read.run = Read;
    addCommand(std::move(read));
}

} // namespace ks::cli::action_analyze
