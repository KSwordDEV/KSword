#include "LightNetworkTrafficWorker.h"
#include "NetworkReplayPresentation.h"

namespace Ksword::Features::ActionAnalyze {
namespace project = Ksword::ActionAnalyze;
namespace archive = ks::cli::action_analyze::archive;
namespace {

// 底层诊断使用UTF-8，按实际编码输出，不做逐字节ANSI扩展。
std::wstring Wide(std::string_view text)
{
    if (text.empty()) {
        return {};
    }
    const int count = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(count > 0 ? static_cast<std::size_t>(count) : 0, L'\0'); // 拥有转换后的文字。
    if (count > 0) {
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count);
    }
    return out;
}

// 错误分类、责任阶段和Win32值保持原始来源，成功空结果不会被格式化为失败。
std::wstring Issue(const project::ProjectResult& status)
{
    return Wide(project::ProjectErrorName(status.error)) + L" / " + Wide(status.detail) +
        L" / Win32=" + std::to_wstring(status.nativeError) + L"\r\n";
}

// 从同一冻结结果构造规范文本，当前编辑框不能重写旧结果的归属身份。
std::wstring Present(const project::NetworkTrafficResult& result)
{
    const auto& request = result.request; // 点击时复制的项目、sample与目标。
    std::wstring text = L"网络流量采集与回读\r\n项目路径：" + request.projectPath +
        L"\r\n项目 ID：" + Wide(result.projectId) + L"\r\n采样 ID：" + Wide(request.plan.sampleId) +
        L"\r\n网络流：raw-network / checkpoints-network\r\n操作：" +
        (request.capture ? L"采集" : L"只读回放") + L"\r\n项目结果：" + Issue(result.opened);
    if (!result.opened) {
        return text;
    }

    if (request.capture) {
        const auto& receipt = result.receipt; // 不以非零包数掩盖启动/排空失败。
        text += L"\r\n请求 PID：" + std::to_wstring(request.plan.pid) + L"\r\n请求创建 FILETIME：" +
            std::to_wstring(request.plan.creationFileTime) + L"\r\n采集来源：" +
            (request.plan.backend == project::NetworkTrafficBackend::RawSocket ? L"raw-socket" : L"existing-wfp") +
            L"\r\n结束原因：" + Wide(receipt.reason) + L"\r\n来源就绪：" + (receipt.sourceReady ? L"true" : L"false") +
            L"\r\n清退确认：" + (receipt.cleanupConfirmed ? L"true" : L"false") +
            L"\r\n采集时长（毫秒）：" + std::to_wstring(request.plan.durationMs) +
            L"\r\n已提交包数：" + std::to_wstring(receipt.packets) + L"\r\n已提交字节数：" +
            std::to_wstring(receipt.capturedBytes) + L"\r\n队列丢弃：" + std::to_wstring(receipt.queueDropped) +
            L"\r\n来源游标缺口：" + std::to_wstring(receipt.sourceGap) + L"\r\n不支持的记录：" +
            std::to_wstring(receipt.unsupportedPackets) + L"\r\n覆盖率：unknown\r\n归档结果：" + Issue(receipt.status);
        for (const auto& message : receipt.diagnostics) {
            text += L"来源诊断：" + Wide(message) + L"\r\n";
        }
        if (!receipt.checkpoint.ordinal) {
            return text; // 无本次提交时不把旧段的正文标为本次采集。
        }
    }

    const auto& read = result.read; // 原网络检查点及其已验证正文。
    text += L"\r\n回读结果：" + Issue(read.status);
    if (!read.status) {
        return text;
    }
    text += L"网络段号：" + std::to_wstring(read.checkpoint.ordinal) + L"\r\n段末偏移：" +
        std::to_wstring(read.checkpoint.endOffset) + L"\r\n末记录序号：" + std::to_wstring(read.checkpoint.lastSequence) +
        L"\r\nSHA-256：" + Wide(read.checkpoint.sha256) + L"\r\n请求 PID：" + std::to_wstring(read.checkpoint.requestedPid) +
        L"\r\n请求创建 FILETIME：" + std::to_wstring(read.checkpoint.requestedCreation) +
        L"\r\n来源 ID：" + Wide(read.checkpoint.source.sourceId) + L"\r\n来源时钟 ID：" +
        Wide(read.checkpoint.source.clockId) + L"\r\n启动 ID：" + Wide(read.checkpoint.source.bootId) +
        L"\r\n结束原因：" + Wide(read.checkpoint.stopReason) + L"\r\n段内包数：" + std::to_wstring(read.totalRecords) +
        L"\r\n显示记录数：" + std::to_wstring(read.records.size()) + L"\r\n";
    // 同一检查点的接管成员窗口独立展示，不与某个报文的弱PID线索拼成强进程归属。
    for (const auto& target : read.checkpoint.targetWindows)
    {
        text += L"\r\n网络采集目标窗口\r\nPID：" + std::to_wstring(target.pid) +
            L"\r\n创建 FILETIME：" + std::to_wstring(target.creationFileTime) +
            L"\r\n根目标：" + (target.root ? L"true" : L"false") +
            L"\r\n准入 FILETIME：" + std::to_wstring(target.startUtc) +
            L"\r\n窗口截止 FILETIME：" + (target.endUtc ? std::to_wstring(target.endUtc) : L"尚未关闭") +
            L"\r\n结束原因：" + Wide(target.endReason) + L"\r\n";
    }
    for (const auto& record : read.records) {
        const auto attribution = record.flow.observation.processAttribution; // 标签保留弱PID线索语义。
        text += L"\r\n记录序号：" + std::to_wstring(record.flow.recordSequence) + L"  偏移：" +
            std::to_wstring(record.flow.recordOffset) + L"\r\nPID 归属：" +
            (attribution == archive::NetworkFlowMetadata::ProcessAttribution::VerifiedInstance ? L"verified-instance" :
                attribution == archive::NetworkFlowMetadata::ProcessAttribution::NativePidHint ? L"native-pid-hint" : L"endpoint-table-hint") +
            L"\r\n来源标志：" + (record.flow.observation.packetSourceFlags ?
                std::to_wstring(*record.flow.observation.packetSourceFlags) : L"unknown") +
            L"\r\n" + NetworkReplayDetails(record) + L"\r\n";
    }
    return text;
}
} // namespace

// 通过本端后台任务调用真实采集后端；没有第二抓包器或共享会话宿主。
LightNetworkTrafficView RunLightNetworkTraffic(project::NetworkTrafficRequest request, const std::atomic_bool& cancelled)
{
    LightNetworkTrafficView view; // UI只接收此纯值回执。
    auto& result = view.result; // worker唯一结果对象。
    result.request = std::move(request);
    project::ProjectDocument document; // 原项目跨进程写租约，不复制运行目录。
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
    view.text = Present(result);
    return view;
}

} // namespace Ksword::Features::ActionAnalyze
