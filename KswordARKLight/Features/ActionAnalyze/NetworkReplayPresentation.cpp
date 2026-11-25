#include "../../Core/Win32Lean.h"
#include "NetworkReplayPresentation.h"

#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

namespace Ksword::Features::ActionAnalyze {
namespace {

using namespace ks::cli::action_analyze::archive;

// 按 RFC 字节顺序格式化归档 UUID，返回可复制的文本。
std::wstring UuidText(const ArchiveUuid& bytes) {
    constexpr wchar_t digits[] = L"0123456789abcdef"; // 十六进制数字表。
    std::wstring text; // 逐字节追加的 UUID 文本。
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            text += L'-';
        }
        text += digits[bytes[i] >> 4];
        text += digits[bytes[i] & 0xf];
    }
    return text;
}

// 仅做本地数字格式化。保留归档端口零值，并明确标出缺失端口。
std::wstring Endpoint(NetworkFamily family, const NetworkEndpointMetadata& endpoint) {
    wchar_t address[INET6_ADDRSTRLEN]{}; // Winsock 数字地址缓冲区，不进行名称解析。
    const bool ipv6 = family == NetworkFamily::IPv6; // IPv6 需要括号区分地址和端口。
    if (!::InetNtopW(ipv6 ? AF_INET6 : AF_INET, endpoint.address.data(), address, std::size(address))) {
        return L"地址格式化失败";
    }
    const auto port = endpoint.port ? std::to_wstring(*endpoint.port) : L"端口未知"; // 缺失不同于 0。
    return ipv6 ? L"[" + std::wstring(address) + L"]:" + port : std::wstring(address) + L":" + port;
}

// 输出真实方向、协议与地址族，供列表和详情复用。
std::wstring Protocol(const NetworkFlowMetadata& flow) {
    const auto transport = flow.transport == NetworkTransport::Tcp ? L"TCP" : L"UDP"; // 已校验的传输协议。
    const auto family = flow.family == NetworkFamily::IPv6 ? L"IPv6" : L"IPv4"; // 已校验的地址族。
    const auto direction = flow.direction == NetworkDirection::Outbound ? L"出站" : L"入站"; // 原始方向。
    return std::wstring(transport) + L"/" + family + L" " + direction;
}

// 根据已保存的材料分类说明字节状态，独立保留完整、截断与完整性未知。
const wchar_t* ByteState(const NetworkCaptureSummary& capture) {
    switch (capture.CommunicationEvidence()) {
    case NetworkCommunicationEvidence::MetadataOnly: return L"仅元数据";
    case NetworkCommunicationEvidence::ConfirmedEmpty: return L"已确认原始长度为 0";
    case NetworkCommunicationEvidence::RetainedBytes:
        if (capture.state == NetworkPayloadState::Complete) {
            return L"完整字节已归档";
        }
        return capture.state == NetworkPayloadState::Truncated ? L"已归档字节（截断）" : L"已归档字节（完整性未知）";
    case NetworkCommunicationEvidence::MissingBytes: return L"已截断，归档未保留字节";
    case NetworkCommunicationEvidence::UnknownPresence: return L"归档未保留字节，原始内容存在性未知";
    }
    return L"未知";
}

// 归档口径中的采集层不同于计数来源，保持独立名称。
const wchar_t* Layer(NetworkCaptureLayer layer) {
    switch (layer) {
    case NetworkCaptureLayer::FlowMetadata: return L"流元数据";
    case NetworkCaptureLayer::TransportPayload: return L"传输层负载";
    case NetworkCaptureLayer::IpPacket: return L"IP 包";
    case NetworkCaptureLayer::LinkFrame: return L"链路帧";
    }
    return L"未知";
}

// 仅对缺失值返回未知，零为有效观测。
std::wstring Number(std::optional<std::uint64_t> number) {
    return number ? std::to_wstring(*number) : L"未知";
}

} // namespace

std::wstring NetworkReplaySummary(const NetworkStoredFlowPreview& record) {
    const auto& flow = record.flow.observation; // 端点字段和方向来自同一条已验证记录。
    const auto& peer = flow.direction == NetworkDirection::Outbound ? flow.destinationField : flow.sourceField;
    return Protocol(flow) + L" · " + Endpoint(flow.family, peer);
}

std::wstring NetworkReplayDetails(const NetworkStoredFlowPreview& record) {
    const auto& flow = record.flow.observation; // 归档观测，不进行实时进程或网络查询。
    const auto& source = record.source; // 源、时钟及代次声明。
    const auto& capture = record.flow.capture; // 字节长度按本条的采集层解释。
    const auto epoch = UuidText(source.sourceEpoch); // 来源代次 UUID，独立于采样 ID。
    std::wstring text = Protocol(flow) + L"\r\n源端点：" + Endpoint(flow.family, flow.sourceField) +
        L"\r\n目的端点：" + Endpoint(flow.family, flow.destinationField) +
        L"\r\n归档进程 PID：" + std::to_wstring(flow.processId) + L"    创建 FILETIME：" +
        std::to_wstring(flow.processCreatedUtc100ns) + L"    进程对象 ID：" + Number(flow.processObjectId) +
        L"\r\n来源（归档声明）：" + std::wstring(source.sourceId.begin(), source.sourceId.end()) +
        L"    代次：" + epoch + L"\r\n时钟：" + std::wstring(source.clockId.begin(), source.clockId.end()) +
        L"    启动标识：" + std::wstring(source.bootId.begin(), source.bootId.end()) +
        (source.clockDomain == NetworkTimeDomain::Qpc ? L"    域：QPC" : L"    域：FILETIME") +
        L"    频率（Hz）：" + Number(source.frequencyHz) + L"\r\n来源时间戳：" +
        std::to_wstring(flow.sourceTimestamp) + L"    接收 QPC：" + Number(flow.receiveQpc) +
        L"    生产者序号：" + Number(flow.producerSequence);
    // ETW 描述符可缺失，缺失时不能据此推断为 API 或其他采集器。
    if (flow.etw) {
        text += L"\r\nETW 描述符（归档声明）：事件 " + std::to_wstring(flow.etw->eventId) + L" / v" +
            std::to_wstring(flow.etw->version) + L" / opcode " + std::to_wstring(flow.etw->opcode);
    } else {
        text += L"\r\nETW 描述符：未知";
    }

    // 来源观测计数与已归档的通信字节各自按对应的口径和上下文展示。
    text += L"\r\n来源观测计数（字节）：" + Number(flow.observedBytes) + L"\r\n采集层：" + Layer(capture.layer) +
        L"    通信字节：" + ByteState(capture) + L"\r\n原始长度：" + Number(capture.originalLength) +
        L"    生产端保留：" + std::to_wstring(capture.producerCapturedLength) +
        L"    归档保留：" + std::to_wstring(capture.capturedLength) +
        (capture.sourceTruncated ? L"    来源声明截断" : L"");
    if (!record.bytes.empty()) {
        text += L"\r\n\r\n通信字节预览：" + std::to_wstring(record.bytes.size()) + L" / " +
            std::to_wstring(capture.capturedLength) + L" B";
        if (record.inlineFileOffset) {
            text += L"    文件字节偏移：" + std::to_wstring(*record.inlineFileOffset);
        }
        // 每行显示 16 字节，保留精确位值并明确标记预览边界。
        constexpr wchar_t digits[] = L"0123456789abcdef";
        for (std::size_t i = 0; i < record.bytes.size(); ++i) {
            text += i % 16 == 0 ? L"\r\n" : L" ";
            const auto byte = record.bytes[i]; // 已完成 CRC 与正文校验的真实内联字节。
            text += digits[byte >> 4];
            text += digits[byte & 0xf];
        }
        if (record.bytes.size() < capture.capturedLength) {
            text += L"\r\n[字节预览截断]";
        }
    }
    return text;
}

} // namespace Ksword::Features::ActionAnalyze
