#include "../Framework.h"
#include "NativeSessionApiPane.h"
#include "../UI/StructuredFieldView.h"
#include "../Internationalization/LanguageManager.h"

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

// 输入一条已提交原命中与段号，追加原坐标及双语释义；不查询当前规则或归档。
void AppendRuleMatch(ks::ui::FieldDocument& document, std::uint64_t segment,
    const Ksword::ActionAnalyze::Rules::ApiPresetMatch& match)
{
    document.field(QStringLiteral("API 最近命中坐标"), QStringLiteral("raw/%1 #%2")
        .arg(segment).arg(match.rawSequence));
    document.field(QStringLiteral("API 最近命中规则"), QString::fromStdString(match.ruleId));
    if (!match.behavior)
    {
        return;
    }

    // 只在UI生成文档时按当前语言选择原释义，不触碰采集线程、不重新求值。
    const bool useChinese = ks::i18n::LanguageManager::instance().currentLanguageId()
        .compare(QStringLiteral("zh-CN"), Qt::CaseInsensitive) == 0; // 本次字段文档的应用语言。
    const auto& summary = useChinese && !match.behavior->summaryZh.empty()
        ? match.behavior->summaryZh : match.behavior->summary; // 中文缺失时使用原英文。
    document.field(QStringLiteral("行为释义"), QString::fromStdString(summary));
    document.field(QStringLiteral("API 规则证据"), QString::fromStdString(match.behavior->evidence));
}

// 输入累计回执，保留有界行为历史及最后普通分类；最新记录与窗口最后一条相同时不重复显示。
void AppendLatestRule(ks::ui::FieldDocument& document, const project::CooperativeApiRuleReceipt& rules)
{
    document.field(QStringLiteral("行为命中数"), QString::number(rules.behaviorMatches));
    document.field(QStringLiteral("行为窗口截断"), YesNo(rules.behaviorMatches > rules.recentBehaviors.size()), true);
    for (const auto& behavior : rules.recentBehaviors)
    {
        AppendRuleMatch(document, behavior.segmentOrdinal, behavior.match);
    }
    if (!rules.latest)
    {
        return;
    }
    if (!rules.recentBehaviors.empty())
    {
        const auto& last = rules.recentBehaviors.back(); // 原窗口末项身份，不用释义相等代替坐标相等。
        if (last.segmentOrdinal == rules.latestSegment && last.match.rawSequence == rules.latest->rawSequence)
        {
            return;
        }
    }
    AppendRuleMatch(document, rules.latestSegment, *rules.latest);
}
} // namespace

// 由原字段视图消费同一值快照，搜索、复制、导出包括实际在途来源，不读取参数控件。
void NativeSessionApiPane::AppendProgress(ks::ui::FieldDocument& document,
    const project::NativeBoundApiProgress& progress)
{
    const auto& startup = progress.startup; // 当前请求原采集线程发布的最后事实。
    document.section(QStringLiteral("API 附加与采集"));
    document.field(QStringLiteral("项目 ID"), QString::fromStdString(progress.projectId));
    document.field(QStringLiteral("采样 ID"), QString::fromStdString(progress.sampleId));
    document.field(QStringLiteral("API 来源 PID"), QString::number(progress.request.sourcePid));
    document.field(QStringLiteral("创建 FILETIME"), QString::number(progress.request.sourceCreationFileTime));
    document.field(QStringLiteral("原调试目标 PID"), QString::number(progress.nativeTarget.pid));
    document.field(QStringLiteral("最后确认的启动阶段"),
        QString::fromLatin1(ks::winapi_monitor::CaptureStartupStageName(startup.stage)));
    // Ready只按原控制器里程碑呈现；安装和模块核验不能代替完整覆盖屏障。
    document.field(QStringLiteral("启动阶段耗时（毫秒）"), QString::number(startup.elapsedMs));
    document.field(QStringLiteral("采集已就绪"),
        YesNo(startup.stage == ks::winapi_monitor::CaptureStartupStage::Ready), true);
    document.field(QStringLiteral("就绪覆盖修订"), startup.coverageRevision
        ? QString::number(startup.coverageRevision) : QStringLiteral("—"));
}

// 输入同次回调借用的checkpoint与规则纯值，输出规范详情字段供单目标和执行集合共用。
void NativeSessionApiPane::AppendCheckpoint(ks::ui::FieldDocument& document,
    const project::ProjectApiCheckpoint& checkpoint, const project::CooperativeApiRuleReceipt& rules)
{
    document.section(QStringLiteral("API 已提交运行进度"))
        .field(QStringLiteral("采样 ID"), QString::fromStdString(checkpoint.sampleId))
        .field(QStringLiteral("API 归档段"), QString::number(checkpoint.ordinal))
        .field(QStringLiteral("API 归档序号"), QString::number(checkpoint.rawEnd.lastSequence))
        .field(QStringLiteral("API 来源序号"), QString::number(checkpoint.lastSourceSequence))
        .field(QStringLiteral("SHA256"), QString::fromStdString(checkpoint.rawSha256))
        .field(QStringLiteral("API 终段已提交"), checkpoint.finalSegment ? QStringLiteral("是") : QStringLiteral("否"), true)
        .field(QStringLiteral("API 规则命中数"), QString::number(rules.matchedRows))
        .field(QStringLiteral("API 规则内容 SHA256"), QString::fromStdString(rules.sourceSha256));
    if (rules.failed)
    {
        document.field(QStringLiteral("规则配置错误"), QString::fromStdString(rules.configError));
    }
    AppendLatestRule(document, rules);
}

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
    AppendLatestRule(document, run.rules); // 最终详情替换在途文档时仍保留释义，不退化为只有计数。
    document.field(QStringLiteral("线程创建候选数"), QString::number(run.transfers.candidateCount));
    document.field(QStringLiteral("APC 候选数"), QString::number(run.transfers.apcCandidateCount));
    document.field(QStringLiteral("上下文候选数"), QString::number(run.transfers.contextCandidateCount));
    document.field(QStringLiteral("已淘汰写入数"), QString::number(run.transfers.evictedWrites));
    document.note(QStringLiteral("同采样仅表示保存归属；API 来源与原调试目标分别保留。采集、清退、归档和规则结果相互独立，不证明执行、区域代次或因果。"));
}
} // namespace ks::action_analyze
