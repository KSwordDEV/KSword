#include "../Framework.h"
#include "NetworkTrafficWorker.h"

#include <WS2tcpip.h>

namespace ks::action_analyze {
namespace project = Ksword::ActionAnalyze;
namespace archive = ks::cli::action_analyze::archive;
namespace {

// 使用归档器的实际字节状态，避免将“未标截断”误读为完整捕获。
QString PayloadState(archive::NetworkPayloadState state)
{
    switch (state) {
    case archive::NetworkPayloadState::MetadataOnly:
        return QStringLiteral("metadata-only");
    case archive::NetworkPayloadState::NoPayload:
        return QStringLiteral("no-payload");
    case archive::NetworkPayloadState::Complete:
        return QStringLiteral("complete");
    case archive::NetworkPayloadState::Truncated:
        return QStringLiteral("truncated");
    case archive::NetworkPayloadState::Captured:
        return QStringLiteral("captured");
    }
    return QStringLiteral("unknown");
}

// 将归档采集层转为详情源文案；只接受本条记录的层级，不根据端口猜测应用协议。
QString CaptureLayer(archive::NetworkCaptureLayer layer)
{
    switch (layer)
    {
    case archive::NetworkCaptureLayer::FlowMetadata:
        return QStringLiteral("流元数据");
    case archive::NetworkCaptureLayer::TransportPayload:
        return QStringLiteral("传输层负载");
    case archive::NetworkCaptureLayer::IpPacket:
        return QStringLiteral("IP 包");
    case archive::NetworkCaptureLayer::LinkFrame:
        return QStringLiteral("链路帧");
    }
    return QStringLiteral("未知");
}

// 仅格式化归档中的网络序地址，不做DNS或实时连接查询。
QString Endpoint(const archive::NetworkEndpointMetadata& endpoint, archive::NetworkFamily family)
{
    wchar_t address[INET6_ADDRSTRLEN]{}; // 系统转换的地址文字。
    const bool ipv6 = family == archive::NetworkFamily::IPv6; // IPv6端口用括号分隔。
    if (!InetNtopW(ipv6 ? AF_INET6 : AF_INET, endpoint.address.data(), address, INET6_ADDRSTRLEN)) {
        return QStringLiteral("unknown");
    }
    const auto host = QString::fromWCharArray(address); // 纯数值端点，不翻译。
    const auto port = endpoint.port ? QString::number(*endpoint.port) : QStringLiteral("unknown");
    return ipv6 ? QStringLiteral("[%1]:%2").arg(host, port) : host + QLatin1Char(':') + port;
}

// 原始错误名及阶段保持不变，字段名由统一语言层翻译。
void Issue(ks::ui::FieldDocument& fields, const QString& name, const project::ProjectResult& status)
{
    fields.field(name, QString::fromLatin1(project::ProjectErrorName(status.error)))
        .field(QStringLiteral("原生诊断"), QString::fromLatin1(status.detail))
        .field(QStringLiteral("Win32 错误"), QString::number(status.nativeError));
}

// 构造回执与正文，页面参数变更不会重新解释已发布结果的身份。
void Present(NetworkTrafficView& view)
{
    const auto& result = view.result; // 已完成操作的唯一结果。
    const auto& request = result.request; // 点击时冻结的参数。
    auto& fields = view.fields; // 共享字段文档同时用于搜索、复制和导出。
    // 后台只保存稳定源文案；共享视图用UI线程取得的翻译快照处理标题、字段及translateValue值。
    fields.title = QStringLiteral("网络流量采集与回读");
    fields.section(QStringLiteral("实际结果来源"))
        .field(QStringLiteral("项目路径"), QString::fromStdWString(request.projectPath))
        .field(QStringLiteral("项目 ID"), QString::fromStdString(result.projectId))
        .field(QStringLiteral("采样 ID"), QString::fromStdString(request.plan.sampleId))
        .field(QStringLiteral("操作"), request.capture ? QStringLiteral("采集") : QStringLiteral("只读回放"), true)
        .field(QStringLiteral("网络流"), QStringLiteral("raw-network / checkpoints-network"));
    Issue(fields, QStringLiteral("项目结果"), result.opened);
    if (!result.opened) {
        return;
    }

    if (request.capture) {
        const auto& receipt = result.receipt; // 真实采集器回执，不用包数推定来源完整性。
        fields.section(QStringLiteral("采集回执"))
            .field(QStringLiteral("请求 PID"), QString::number(request.plan.pid))
            .field(QStringLiteral("请求创建 FILETIME"), QString::number(request.plan.creationFileTime))
            .field(QStringLiteral("采集时长（毫秒）"), QString::number(request.plan.durationMs))
            .field(QStringLiteral("采集来源"), request.plan.backend == project::NetworkTrafficBackend::RawSocket ?
                QStringLiteral("raw-socket") : QStringLiteral("existing-wfp"))
            .field(QStringLiteral("结束原因"), QString::fromStdString(receipt.reason))
            .field(QStringLiteral("来源就绪"), receipt.sourceReady ? QStringLiteral("true") : QStringLiteral("false"))
            .field(QStringLiteral("清退确认"), receipt.cleanupConfirmed ? QStringLiteral("true") : QStringLiteral("false"))
            .field(QStringLiteral("已提交包数"), QString::number(receipt.packets))
            .field(QStringLiteral("已提交字节数"), QString::number(receipt.capturedBytes))
            .field(QStringLiteral("队列丢弃"), QString::number(receipt.queueDropped))
            .field(QStringLiteral("来源游标缺口"), QString::number(receipt.sourceGap))
            .field(QStringLiteral("不支持的记录"), QString::number(receipt.unsupportedPackets))
            .field(QStringLiteral("覆盖率"), QStringLiteral("unknown"))
            .field(QStringLiteral("进程归属说明"), QStringLiteral("逐包 PID 仅为归属线索，不能证明数据包发生时的进程实例；采集不保证覆盖全部流量。"), true);
        Issue(fields, QStringLiteral("归档结果"), receipt.status);
        for (const auto& diagnostic : receipt.diagnostics) {
            fields.field(QStringLiteral("来源诊断"), QString::fromUtf8(diagnostic.data(), diagnostic.size()));
        }
        if (!receipt.checkpoint.ordinal) {
            return; // 无本次提交时不把旧网络尾段冒充本次采集结果。
        }
    }

    const auto& read = result.read; // 显式读端或采集末段的只读核验。
    fields.section(QStringLiteral("网络检查点"));
    Issue(fields, QStringLiteral("回读结果"), read.status);
    if (!read.status) {
        return;
    }
    fields.field(QStringLiteral("网络段号"), QString::number(read.checkpoint.ordinal))
        .field(QStringLiteral("段末偏移"), QString::number(read.checkpoint.endOffset))
        .field(QStringLiteral("末记录序号"), QString::number(read.checkpoint.lastSequence))
        .field(QStringLiteral("SHA-256"), QString::fromStdString(read.checkpoint.sha256))
        .field(QStringLiteral("请求 PID"), QString::number(read.checkpoint.requestedPid))
        .field(QStringLiteral("请求创建 FILETIME"), QString::number(read.checkpoint.requestedCreation))
        .field(QStringLiteral("来源 ID"), QString::fromStdString(read.checkpoint.source.sourceId))
        .field(QStringLiteral("来源时钟 ID"), QString::fromStdString(read.checkpoint.source.clockId))
        .field(QStringLiteral("启动 ID"), QString::fromStdString(read.checkpoint.source.bootId))
        .field(QStringLiteral("结束原因"), QString::fromStdString(read.checkpoint.stopReason))
        .field(QStringLiteral("段内包数"), QString::number(read.totalRecords))
        .field(QStringLiteral("显示记录数"), QString::number(read.records.size()));

    // 展示本段实际纳入的实例窗口；这是采集筛选范围，不给任一弱PID报文补造强实例身份。
    for (const auto& target : read.checkpoint.targetWindows)
    {
        fields.section(QStringLiteral("网络采集目标窗口"))
            .field(QStringLiteral("PID"), QString::number(target.pid))
            .field(QStringLiteral("创建 FILETIME"), QString::number(target.creationFileTime))
            .field(QStringLiteral("根目标"), target.root ? QStringLiteral("true") : QStringLiteral("false"))
            .field(QStringLiteral("准入 FILETIME"), QString::number(target.startUtc))
            .field(QStringLiteral("窗口截止 FILETIME"), target.endUtc ? QString::number(target.endUtc) : QStringLiteral("尚未关闭"), !target.endUtc)
            .field(QStringLiteral("结束原因"), QString::fromStdString(target.endReason));
    }

    // 全段预览限制256条/每包64B；指定序号返回该记录的全部归档字节。
    for (const auto& record : read.records) {
        const auto& flow = record.flow.observation; // 原观测，弱PID标签不升级为强实例。
        const auto attribution = flow.processAttribution == archive::NetworkFlowMetadata::ProcessAttribution::VerifiedInstance ?
            QStringLiteral("verified-instance") : flow.processAttribution == archive::NetworkFlowMetadata::ProcessAttribution::NativePidHint ?
            QStringLiteral("native-pid-hint") : QStringLiteral("endpoint-table-hint");
        const bool instanceKnown = flow.processAttribution == archive::NetworkFlowMetadata::ProcessAttribution::VerifiedInstance &&
            flow.processCreatedUtc100ns != 0; // PID线索中占位的零不作为真实进程创建时间展示。
        fields.section(QStringLiteral("网络记录"))
            .field(QStringLiteral("记录序号"), QString::number(record.flow.recordSequence))
            .field(QStringLiteral("记录偏移"), QString::number(record.flow.recordOffset))
            .field(QStringLiteral("PID 归属"), attribution)
            .field(QStringLiteral("PID"), QString::number(flow.processId))
            .field(QStringLiteral("创建 FILETIME"), instanceKnown ? QString::number(flow.processCreatedUtc100ns) : QStringLiteral("未知"), !instanceKnown)
            .field(QStringLiteral("来源 ID"), QString::fromStdString(record.source.sourceId))
            .field(QStringLiteral("网络来源绑定"), record.sourceTrust == archive::NetworkSourceTrust::MatchedVerifiedBinding ?
                QStringLiteral("已核验来源绑定") : QStringLiteral("仅归档来源声明"), true)
            .field(QStringLiteral("网络采集层"), CaptureLayer(record.flow.capture.layer), true)
            .field(QStringLiteral("源端点"), Endpoint(flow.sourceField, flow.family))
            .field(QStringLiteral("目的端点"), Endpoint(flow.destinationField, flow.family))
            .field(QStringLiteral("协议与方向"), QStringLiteral("%1 / %2").arg(
                flow.transport == archive::NetworkTransport::Tcp ? QStringLiteral("TCP") : QStringLiteral("UDP"),
                flow.direction == archive::NetworkDirection::Outbound ? QStringLiteral("outbound") : QStringLiteral("inbound")))
            .field(QStringLiteral("来源 FILETIME"), QString::number(flow.sourceTimestamp))
            .field(QStringLiteral("来源记录序号"), flow.producerSequence ? QString::number(*flow.producerSequence) : QStringLiteral("unknown"))
            .field(QStringLiteral("来源标志"), flow.packetSourceFlags ? QString::number(*flow.packetSourceFlags) : QStringLiteral("unknown"))
            .field(QStringLiteral("原始长度"), record.flow.capture.originalLength ?
                QString::number(*record.flow.capture.originalLength) : QStringLiteral("unknown"))
            .field(QStringLiteral("生产端保留字节数"), QString::number(record.flow.capture.producerCapturedLength))
            .field(QStringLiteral("归档保留字节数"), QString::number(record.flow.capture.capturedLength))
            .field(QStringLiteral("当前显示字节数"), QString::number(record.bytes.size()))
            .field(QStringLiteral("字节状态"), PayloadState(record.flow.capture.state))
            .field(QStringLiteral("截断"), record.flow.capture.sourceTruncated ||
                record.flow.capture.state == archive::NetworkPayloadState::Truncated ? QStringLiteral("true") : QStringLiteral("false"));
        view.bytes += QStringLiteral("recordSequence=%1 offset=%2 bytes=%3/%4\n").arg(record.flow.recordSequence)
            .arg(record.flow.recordOffset).arg(record.bytes.size()).arg(record.flow.capture.capturedLength);
        for (std::size_t index = 0; index < record.bytes.size(); ++index) {
            view.bytes += QStringLiteral("%1%2").arg(record.bytes[index], 2, 16, QLatin1Char('0'))
                .arg(index % 16 == 15 ? QLatin1Char('\n') : QLatin1Char(' '));
        }
        view.bytes += QStringLiteral("\n\n");
    }
}
} // namespace

// 本端worker串行拥有正式文档，原生服务及归档器均由CaptureNetworkTraffic复用。
NetworkTrafficView RunNetworkTraffic(project::NetworkTrafficRequest request, const std::atomic_bool& cancelled)
{
    NetworkTrafficView view; // 回投给Qt的纯值，不持窗口。
    view.result.request = std::move(request);
    auto& result = view.result; // worker唯一可变结果。
    project::ProjectDocument document; // 正式项目目录锁覆盖整个采集和提交过程。
    result.opened = document.Open(result.request.projectPath, result.request.capture ?
        project::ProjectAccess::ReadWrite : project::ProjectAccess::ReadOnly);
    if (result.opened) {
        result.projectId = document.Info()->projectId;
        if (result.request.capture) {
            result.request.plan.bootId = project::ReadNetworkTrafficBootId();
            result.receipt = project::CaptureNetworkTraffic(document, result.request.plan, cancelled);
            if (result.receipt.checkpoint.ordinal) {
                result.read = project::ReadNetworkTraffic(document, result.request.plan.sampleId,
                    result.receipt.checkpoint.ordinal);
            }
        } else {
            result.read = project::ReadNetworkTraffic(document, result.request.plan.sampleId,
                result.request.ordinal, result.request.recordSequence);
        }
    }
    Present(view);
    return view;
}

} // namespace ks::action_analyze
