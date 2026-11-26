#include "../Framework.h"
#include "NativeSessionApiPane.h"
#include "../UI/StructuredFieldView.h"

#include <algorithm>

namespace ks::action_analyze {
namespace project = Ksword::ActionAnalyze;
namespace {
// 输入布尔原值，输出规范文档翻译源，不能从描述文本猜成功。
QString YesNo(bool value)
{
    return value ? QStringLiteral("是") : QStringLiteral("否");
}

// status是某一独立阶段原回执，document追加阶段、错误及Win32，不提升为整个采集成功。
void AppendStatus(ks::ui::FieldDocument& document, const QString& title, const project::ProjectResult& status)
{
    document.section(title);
    document.field(QStringLiteral("状态"), QString::fromLatin1(project::ProjectErrorName(status.error)));
    document.field(QStringLiteral("阶段"), QString::fromLatin1(status.detail));
    document.field(QStringLiteral("Win32 错误"), QString::number(status.nativeError));
}
} // namespace

// 输入原文档和worker冻结回执，追加同一规范字段；不创建第二份详情或查询当前草稿。
void NativeSessionApiPane::AppendFields(ks::ui::FieldDocument& document, const project::NativeBoundApiResult& result)
{
    const auto& run = result.receipt; // 原worker公布的完整冻结回执，不重新查询任何来源。
    const auto& capture = run.capture; // 附加和管道控制结果，独立于archiveStatus。
    document.section(QStringLiteral("同采样 API 来源"));
    document.field(QStringLiteral("项目 ID"), QString::fromStdString(result.projectId));
    document.field(QStringLiteral("采样 ID"), QString::fromStdString(result.sampleId));
    document.field(QStringLiteral("API 来源 PID"), QString::number(result.request.sourcePid));
    document.field(QStringLiteral("创建 FILETIME"), QString::number(result.request.sourceCreationFileTime));
    document.field(QStringLiteral("同采样 API 时长（毫秒）"), QString::number(result.request.durationMs));
    // 原目标与来源分列，只有原owner值能说明native目标，不能相互回填。
    document.field(QStringLiteral("原调试目标 PID"), QString::number(result.nativeTarget.pid));
    document.field(QStringLiteral("原调试目标创建 FILETIME"), QString::number(result.nativeTarget.creationFileTime));
    document.field(QStringLiteral("请求已接纳"), YesNo(result.accepted), true);
    AppendStatus(document, QStringLiteral("API 准入结果"), result.admission);
    if (!result.accepted)
    {
        document.field(QStringLiteral("准入拒绝码"), QString::number(static_cast<unsigned>(result.rejection)));
        return; // 未发起采集，不能把默认空回执显示成已清退或成功空结果。
    }

    AppendStatus(document, QStringLiteral("API 采样绑定结果"), run.sampleStatus);
    document.field(QStringLiteral("冻结修订 ID"), QString::fromStdString(run.sample.revisionId));
    document.section(QStringLiteral("API 附加与采集"));
    document.field(QStringLiteral("综合退出码"), QString::number(result.ExitCode()));
    document.field(QStringLiteral("采集退出码"), QString::number(result.CaptureExitCode()));
    document.field(QStringLiteral("Agent 路径可用"), YesNo(run.agentPathAvailable), true);
    document.field(QStringLiteral("已尝试装载 Agent"), YesNo(capture.agentLoadAttempted), true);
    document.field(QStringLiteral("Agent 模块已核验"), YesNo(capture.agentModuleVerified), true);
    document.field(QStringLiteral("附加实例已核验"), YesNo(capture.attachmentIdentityVerified), true);
    if (capture.startup)
    {
        // 同采样详情使用原采集器最后阶段，不从当前native停点或已保存包数推导Ready。
        const auto stage = ks::winapi_monitor::CaptureStartupStageName(capture.startup->stage); // 稳定阶段ID，便于与CLI原回执核对。
        document.field(QStringLiteral("最后确认的启动阶段"), QString::fromLatin1(stage));
        document.field(QStringLiteral("启动阶段耗时（毫秒）"), QString::number(capture.startup->elapsedMs));
    }
    document.field(QStringLiteral("就绪覆盖修订"), capture.readyCoverageRevision
        ? QString::number(*capture.readyCoverageRevision) : QStringLiteral("—"));
    // Ready、有限区间及丢失单独列出，成功归档不覆盖这些采集状态。
    document.field(QStringLiteral("已发布配置"), YesNo(capture.configPublished), true);
    document.field(QStringLiteral("采集已就绪"), YesNo(capture.started), true);
    document.field(QStringLiteral("完整有限区间"), YesNo(capture.completedInterval), true);
    document.field(QStringLiteral("已取消"), YesNo(capture.cancelled), true);
    document.field(QStringLiteral("收到包数"), QString::number(capture.received));
    document.field(QStringLiteral("无效包数"), QString::number(capture.invalidPackets));
    document.field(QStringLiteral("缓冲丢包数"), QString::number(capture.bufferDropped));
    for (const auto& error : capture.errors) // 每条原控制错误完整保留，原文不当作翻译键。
    {
        document.field(QStringLiteral("采集错误"), QString::fromStdWString(error));
    }

    // 仅匹配实际来源PID+创建时间，不能拿processes首行或native目标补管道身份。
    const auto process = std::find_if(capture.processes.begin(), capture.processes.end(), [&](const auto& value)
    {
        return value.pid == result.request.sourcePid && value.creation == result.request.sourceCreationFileTime;
    });
    document.section(QStringLiteral("API 清退结果"));
    document.field(QStringLiteral("清退完成"), YesNo(capture.cleanupComplete), true);
    document.field(QStringLiteral("已写停止标记"), YesNo(capture.stopWritten), true);
    if (process != capture.processes.end())
    {
        document.field(QStringLiteral("管道已连接"), YesNo(process->connected), true);
        document.field(QStringLiteral("Hook 已安装"), YesNo(process->installed), true);
        document.field(QStringLiteral("Hook 已移除"), YesNo(process->removed), true);
        document.field(QStringLiteral("管道正常结束"), YesNo(process->cleanPipeEof), true);
        document.field(QStringLiteral("来源进程已退出"), YesNo(process->exited), true);
        document.field(QStringLiteral("管道错误"), QString::number(process->pipeError));
        if (process->connected)
        {
            document.field(QStringLiteral("来源会话 ID"), QString::number(process->session));
            document.field(QStringLiteral("Agent 报告丢包数"), QString::number(process->agentDropped));
        }
    }

    AppendStatus(document, QStringLiteral("API 原包归档结果"), run.archiveStatus);
    // 以下计数及端点来自原提交回执，零段与已保存前缀均按实保留。
    document.field(QStringLiteral("已接收普通包数"), QString::number(run.ordinaryPackets));
    document.field(QStringLiteral("已归档普通包数"), QString::number(run.archivedPackets));
    document.field(QStringLiteral("已提交段数"), QString::number(run.committedSegments));
    document.field(QStringLiteral("保留线索数"), QString::number(run.retainedClues));
    document.field(QStringLiteral("遗漏线索数"), QString::number(run.omittedClues));
    if (run.archive.written)
    {
        document.field(QStringLiteral("原包写入字节坐标"), QString::number(run.archive.written->byteOffset));
    }
    if (run.archive.flushed)
    {
        document.field(QStringLiteral("原包刷盘字节坐标"), QString::number(run.archive.flushed->byteOffset));
        document.field(QStringLiteral("原包末记录序号"), QString::number(run.archive.flushed->lastSequence));
    }

    document.section(QStringLiteral("API 规则与转移候选"));
    // 规则失败与候选计数独立；候选不升级为native执行或因果证据。
    document.field(QStringLiteral("规则集"), QString::fromStdString(run.rules.presetSet));
    document.field(QStringLiteral("规则来源 SHA-256"), QString::fromStdString(run.rules.sourceSha256));
    document.field(QStringLiteral("规则失败"), YesNo(run.rules.failed), true);
    document.field(QStringLiteral("规则配置错误"), QString::fromStdString(run.rules.configError));
    document.field(QStringLiteral("规则命中行数"), QString::number(run.rules.matchedRows));
    document.field(QStringLiteral("线程创建候选数"), QString::number(run.transfers.candidateCount));
    document.field(QStringLiteral("APC 候选数"), QString::number(run.transfers.apcCandidateCount));
    document.field(QStringLiteral("上下文候选数"), QString::number(run.transfers.contextCandidateCount));
    document.field(QStringLiteral("已淘汰写入数"), QString::number(run.transfers.evictedWrites));
    document.note(QStringLiteral("同采样仅表示保存归属；API 来源与原调试目标分别保留。采集、清退、归档和规则结果相互独立，不证明执行、区域代次或因果。"));
}
} // namespace ks::action_analyze
