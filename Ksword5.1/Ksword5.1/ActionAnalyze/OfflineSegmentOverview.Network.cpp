#include "OfflineSegmentOverview.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

#include <QHostAddress>
#include <algorithm>

namespace ks::action_analyze
{
namespace
{
    namespace archive = ks::cli::action_analyze::archive;
    using ks::i18n::sourceText;

    // 按原生地址字段解码网络字节序；端口缺失时只显示地址。
    QString EndpointText(archive::NetworkFamily family, const archive::NetworkEndpointMetadata& endpoint)
    {
        QHostAddress address; // 面向显示的标准 IPv4 或 IPv6 地址。
        if (family == archive::NetworkFamily::IPv4)
        {
            quint32 ipv4 = 0; // 将四个网络顺序字节折叠为 IPv4 值。
            for (std::size_t index = 0; index < 4; ++index)
            {
                ipv4 = (ipv4 << 8) | endpoint.address[index];
            }
            address.setAddress(ipv4);
        }
        else
        {
            Q_IPV6ADDR ipv6{}; // 内存中的 16 个地址字节保持在线顺序。
            std::copy(endpoint.address.cbegin(), endpoint.address.cend(), ipv6.c);
            address.setAddress(ipv6);
        }
        if (!endpoint.port)
        {
            return address.toString();
        }
        return family == archive::NetworkFamily::IPv6
            ? QStringLiteral("[%1]:%2").arg(address.toString()).arg(*endpoint.port)
            : QStringLiteral("%1:%2").arg(address.toString()).arg(*endpoint.port);
    }

    // 将底层捕获状态映射为可见文案，保留未知原始长度的情况。
    QString CaptureState(archive::NetworkPayloadState state)
    {
        switch (state)
        {
        case archive::NetworkPayloadState::MetadataOnly:
            return sourceText(QStringLiteral("仅网络元数据"));
        case archive::NetworkPayloadState::NoPayload:
            return sourceText(QStringLiteral("已证实无通信载荷"));
        case archive::NetworkPayloadState::Complete:
            return sourceText(QStringLiteral("已保留完整通信字节"));
        case archive::NetworkPayloadState::Truncated:
            return sourceText(QStringLiteral("已保留部分通信字节"));
        case archive::NetworkPayloadState::Captured:
            return sourceText(QStringLiteral("已保留通信字节，原始长度未知"));
        }
        return {};
    }

    // 输入归档的逐包归属枚举，返回本地化说明；来源绑定通过不自动提升PID线索为强实例。
    QString AttributionText(archive::NetworkFlowMetadata::ProcessAttribution attribution)
    {
        using Attribution = archive::NetworkFlowMetadata::ProcessAttribution;
        switch (attribution)
        {
        case Attribution::VerifiedInstance:
            return sourceText(QStringLiteral("已核验进程实例"));
        case Attribution::EndpointTableHint:
            return sourceText(QStringLiteral("端口表 PID 线索"));
        case Attribution::NativePidHint:
            return sourceText(QStringLiteral("原生 PID 线索"));
        }
        return sourceText(QStringLiteral("未知"));
    }
}

// 使用共享详情文档，同时展示记录级捕获状态及界面实际显示的字节。
void OfflineSegmentOverview::appendNetworkEvidence(ks::ui::FieldDocument& document, const SegmentNetworkEvidence& evidence)
{
    const auto& flow = evidence.flow.observation; // 经共享归档检查的端点与方向。
    const auto& capture = evidence.flow.capture; // 原始、采集方及保留范围各自独立。
    const auto outbound = flow.direction == archive::NetworkDirection::Outbound; // 以记录的方向为准。
    const bool instanceKnown = flow.processAttribution == archive::NetworkFlowMetadata::ProcessAttribution::VerifiedInstance &&
        flow.processCreatedUtc100ns != 0; // 弱PID线索中的保留零不能显示成一个已核验创建时间。
    document.section(QStringLiteral("网络证据"))
        .field(QStringLiteral("协议"), flow.transport == archive::NetworkTransport::Tcp ? QStringLiteral("TCP") : QStringLiteral("UDP"))
        .field(QStringLiteral("方向"), outbound ? QStringLiteral("出站") : QStringLiteral("入站"))
        .field(QStringLiteral("源端点"), EndpointText(flow.family, flow.sourceField))
        .field(QStringLiteral("目的端点"), EndpointText(flow.family, flow.destinationField))
        .field(QStringLiteral("进程 PID"), QString::number(flow.processId))
        .field(QStringLiteral("归档中的进程创建时间（FILETIME）"), instanceKnown
            ? QString::number(flow.processCreatedUtc100ns) : sourceText(QStringLiteral("未知")))
        .field(QStringLiteral("进程归属说明"), AttributionText(flow.processAttribution))
        .field(QStringLiteral("来源 ID"), QString::fromStdString(evidence.source.sourceId))
        .field(QStringLiteral("网络来源绑定"), evidence.sourceTrust == archive::NetworkSourceTrust::MatchedVerifiedBinding
            ? QStringLiteral("已核验来源绑定") : QStringLiteral("仅归档来源声明"), true)
        .field(QStringLiteral("来源时间刻度"), QString::number(flow.sourceTimestamp))
        .field(QStringLiteral("归档载荷状态"), CaptureState(capture.state))
        .field(QStringLiteral("归档保留字节数"), QString::number(capture.capturedLength))
        .field(QStringLiteral("来源采集字节数"), QString::number(capture.producerCapturedLength));

    // 来源声明与独立验证分栏，未分类记录不参与 API 或 ETW 专属条件。
    if (flow.etw)
    {
        const auto verified = evidence.sourceTrust == archive::NetworkSourceTrust::MatchedVerifiedBinding;
        document.field(QStringLiteral("事件来源"), verified ? QStringLiteral("ETW（已验证来源绑定）") : QStringLiteral("ETW（归档声明，来源未验证）"));
    }
    else if (!evidence.source.sourceId.empty())
    {
        // Raw Socket/WFP已有独立绑定，不再因缺少ETW描述符被错误展示为未知来源。
        document.field(QStringLiteral("事件来源"), QString::fromStdString(evidence.source.sourceId));
    }
    else
    {
        document.field(QStringLiteral("事件来源"), QStringLiteral("未知来源"));
    }
    if (capture.originalLength)
    {
        document.field(QStringLiteral("原始通信长度（字节）"), QString::number(*capture.originalLength));
    }
    if (flow.processObjectId)
    {
        document.field(QStringLiteral("进程对象 ID"), QString::number(*flow.processObjectId));
    }

    // 预览上限只影响本页，保留长度和部分采集仍来自原记录。
    if (!evidence.preview.isEmpty())
    {
        document.field(QStringLiteral("归档字节起点"), QString::number(evidence.inlineFileOffset))
            .field(QStringLiteral("预览字节数"), QString::number(evidence.preview.size()))
            .field(QStringLiteral("通信字节预览（十六进制）"), QString::fromLatin1(evidence.preview.toHex(' ')));
    }
}

// 在当前网络记录的可读端点及协议中匹配用户的关键字。
bool OfflineSegmentOverview::matchesNetworkKeyword(const SegmentNetworkEvidence& evidence, const QString& keyword)
{
    const auto& flow = evidence.flow.observation; // 已验证的端点及记录中的 PID。
    const auto protocol = flow.transport == archive::NetworkTransport::Tcp ? QStringLiteral("TCP") : QStringLiteral("UDP");
    return protocol.contains(keyword, Qt::CaseInsensitive) || QString::number(flow.processId).contains(keyword)
        || EndpointText(flow.family, flow.sourceField).contains(keyword, Qt::CaseInsensitive)
        || EndpointText(flow.family, flow.destinationField).contains(keyword, Qt::CaseInsensitive);
}
}
