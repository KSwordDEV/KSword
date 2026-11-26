#include "CallbackArchivePresentation.h"
#include "OfflineSegmentReader.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;
    using Ksword::ActionAnalyze::CallbackBatchState;
    using Ksword::ActionAnalyze::kProjectCallbackSourceId;

    // 由回执枚举返回本地化源文案，描述一次原生读取的游标状态。
    QString CursorStateText(CallbackBatchState state)
    {
        switch (state)
        {
        case CallbackBatchState::CaughtUp:
            return QStringLiteral("已读至本次源快照末尾");
        case CallbackBatchState::MoreAvailable:
            return QStringLiteral("源快照仍有后续记录");
        case CallbackBatchState::SnapshotRace:
            return QStringLiteral("源快照在读取期间发生变化");
        case CallbackBatchState::NotRead:
            return QStringLiteral("未知");
        }
        return QStringLiteral("未知");
    }

    // 显示源回执提供的值，数值零单独保留；空字段使用本地化的未知。
    template<class Number>
    QString ReportedNumber(const std::optional<Number>& value)
    {
        return value ? QString::number(static_cast<qulonglong>(*value)) : sourceText(QStringLiteral("未知"));
    }
}

// 返回已识别的回调观测标签，供表、关系叶项和关键字筛选复用。
QString CallbackArchiveRowLabel()
{
    return sourceText(QStringLiteral("KSwordARK 线程创建回调"));
}

// 输入为核验通过的归档观测数；提示整批的可读性和实际采集覆盖是两个字段。
QString CallbackArchiveStatus(qsizetype observationCount)
{
    return observationCount == 0
        ? sourceText(QStringLiteral("已核验 KSwordARK 回调空批次。采集覆盖未知。"))
        : sourceText(QStringLiteral("已核验 KSwordARK 回调批次。采集覆盖未知。"));
}

// 向当前规范文档加入整批的来源和游标诊断，供详情视图、复制与导出共用。
void AppendCallbackBatchFields(ks::ui::FieldDocument& document, const SegmentCallbackBatch& batch)
{
    document.section(QStringLiteral("KSwordARK 回调批次"))
        .field(QStringLiteral("事件来源"), QString::fromLatin1(kProjectCallbackSourceId))
        .field(QStringLiteral("来源代次"), QString::fromStdString(batch.plan.sourceEpoch))
        .field(QStringLiteral("采集覆盖"), QStringLiteral("未知"), true)
        .field(QStringLiteral("回调批次游标状态"), CursorStateText(batch.end.state), true)
        .field(QStringLiteral("请求游标（不含）"), QString::number(batch.plan.afterSequence))
        .field(QStringLiteral("响应游标"), QString::number(batch.end.nextSequence))
        .field(QStringLiteral("源快照最新序号"), QString::number(batch.end.latestSequence))
        .field(QStringLiteral("源返回记录数"), QString::number(batch.end.returnedCount));
    // 源返回数可以包含未归档的其他回调。两类漏失各自保留回执原值。
    document.field(QStringLiteral("游标前缀覆盖数"), ReportedNumber(batch.end.lostBeforeFirst))
        .field(QStringLiteral("回调环累计丢弃数"), ReportedNumber(batch.end.droppedCount))
        .field(QStringLiteral("归档块号"), QString::number(batch.blockOrdinal));
}

// 只在当前行具有回调原包时调用，显示同一 raw 段的实际记录和原包坐标。
void AppendCallbackObservation(ks::ui::FieldDocument& document, const QString& sampleId, const SegmentRow& row)
{
    const auto& callback = *row.archivedCallback; // 当前所选回调记录的冻结值。
    document.section(QStringLiteral("KSwordARK 线程创建回调"))
        .field(QStringLiteral("采样 ID"), sampleId)
        .field(QStringLiteral("归档段号"), QString::number(row.segmentOrdinal))
        .field(QStringLiteral("记录序号"), QString::number(row.sequence))
        .field(QStringLiteral("文件偏移（字节）"), QString::number(row.offset))
        .field(QStringLiteral("原包起点（字节）"), QString::number(callback.inlineOffset))
        .field(QStringLiteral("原包长度（字节）"), QString::number(callback.inlineBytes))
        .field(QStringLiteral("原始回调序号"), QString::number(callback.sourceSequence))
        .field(QStringLiteral("FILETIME"), QString::number(callback.timeUtc100ns));
    // 上下文和目标都是来源提示，不送入对象引用、执行或归因字段。
    document.field(QStringLiteral("回调上下文 PID 提示"), ReportedNumber(callback.contextPid))
        .field(QStringLiteral("回调上下文 TID 提示"), ReportedNumber(callback.contextTid))
        .field(QStringLiteral("目标 PID 提示"), ReportedNumber(row.pid))
        .field(QStringLiteral("目标 TID 提示"), ReportedNumber(row.tid))
        .note(QStringLiteral("进程和线程实例、实际写入、执行及跨进程归因均未知。"));
}

// 仅匹配回调行已有的来源 ID、原生序号和上下文提示。目标编号由表格筛选处理。
bool MatchesCallbackKeyword(const SegmentRow& row, const QString& keyword)
{
    if (!row.archivedCallback)
    {
        return false;
    }
    const auto& callback = *row.archivedCallback; // 同一行的来源和提示。
    return QString::fromLatin1(kProjectCallbackSourceId).contains(keyword, Qt::CaseInsensitive) ||
        QString::number(callback.sourceSequence).contains(keyword) ||
        (callback.contextPid && QString::number(*callback.contextPid).contains(keyword)) ||
        (callback.contextTid && QString::number(*callback.contextTid).contains(keyword));
}
}
