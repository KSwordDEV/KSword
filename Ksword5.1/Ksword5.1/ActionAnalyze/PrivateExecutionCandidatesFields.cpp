#include "../Framework.h"
#include "PrivateExecutionCandidatesFields.h"
#include "ApiTransferPresentation.h"
#include "OfflineSegmentReader.h"
#include "../Internationalization/LanguageManager.h"

namespace ks::action_analyze
{
    namespace detection = Ksword::ActionAnalyze::Detection;
    using ks::i18n::sourceText;

    // 输入同一原调用，追加完整字节定位和共享AAIM1规范字段；不复制字段解析器。
    static void AppendCall(ks::ui::FieldDocument& document, const detection::PrivateMemoryCall& call)
    {
        const auto& record = call.record; // 核验后的归档文件坐标，与来源流水号分列。
        const auto& evidence = call.evidence; // 此调用自己的原项目/采样/来源强身份声明。
        document.section(QStringLiteral("原调用归档坐标"));
        document.field(QStringLiteral("API"), QString::fromStdString(record.operation));
        document.field(QStringLiteral("项目 ID"), QString::fromStdString(evidence.projectId));
        document.field(QStringLiteral("采样 ID"), QString::fromStdString(evidence.sampleId));
        document.field(QStringLiteral("候选原段号"), QString::number(record.segmentOrdinal));
        document.field(QStringLiteral("原包末记录序号"), QString::number(record.recordSequence));
        document.field(QStringLiteral("原调用字节偏移"), QString::number(record.recordOffset));
        document.field(QStringLiteral("原调用块序号"), QString::number(record.blockOrdinal));
        document.field(QStringLiteral("原包内联偏移"), QString::number(record.inlineOffset));
        document.field(QStringLiteral("原包内联字节数"), QString::number(record.inlineBytes));
        document.field(QStringLiteral("SHA-256"), QString::fromStdString(call.sha256));

        // 来源身份与Stored坐标独立保存，源缺位显示未知，不能用目标身份回填。
        document.field(QStringLiteral("来源 ID"), QString::fromStdString(evidence.sourceId));
        document.field(QStringLiteral("来源代次"), QString::fromStdString(evidence.sourceEpoch));
        document.field(QStringLiteral("来源序号"), evidence.sourceSequence ?
            QString::number(*evidence.sourceSequence) : QStringLiteral("未知"), true);
        document.field(QStringLiteral("源 PID"), record.headerPid ?
            QString::number(*record.headerPid) : QStringLiteral("未知"), true);
        document.field(QStringLiteral("源 TID"), record.headerTid ?
            QString::number(*record.headerTid) : QStringLiteral("未知"), true);
        SegmentApiClue clue; // 仅把已经核验的原字段交给现有唯一AAIM1字段投影。
        clue.apiMemoryLifecycle = record.apiMemoryLifecycle;
        clue.memorySourceSession = record.apiSourceSession.value_or(0);
        AppendApiMemoryLifecycleFields(document, clue);
    }

    // 输入原候选，输出短状态；不将成功API或稳定历史身份表述为当前活实例。
    QString PrivateCandidateState(const detection::PrivateExecutionCandidate& row)
    {
        const auto& fields = *row.origin.record.apiMemoryLifecycle; // 核心只返回合法AAIM1行。
        if (fields.operation == Ksword::Evidence::ApiMemoryOperation::Free)
        {
            return sourceText(QStringLiteral("Free 请求；实际释放未知"));
        }
        if (!row.rangeCandidate)
        {
            return sourceText(QStringLiteral("仅原调用线索"));
        }
        return row.strongTarget ? sourceText(QStringLiteral("范围候选；待现场核验")) :
            sourceText(QStringLiteral("范围线索；缺目标强身份"));
    }

    // 只显示两个实际输出有效位均存在的范围；Free和失败返回绝不显示请求值为实际值。
    QString PrivateCandidateRange(const detection::PrivateExecutionCandidate& row)
    {
        const auto& fields = *row.origin.record.apiMemoryLifecycle; // 保留原实际输出，未对齐或截断。
        constexpr auto flags = Ksword::Evidence::ApiMemoryOutputBase | Ksword::Evidence::ApiMemoryOutputBytes;
        if (fields.operation == Ksword::Evidence::ApiMemoryOperation::Free ||
            !fields.returnValid || fields.status < 0 || (fields.flags & flags) != flags)
        {
            return sourceText(QStringLiteral("实际范围未知"));
        }
        return sourceText(QStringLiteral("0x%1 / %2 字节"))
            .arg(QString::number(fields.outputBase, 16)).arg(fields.outputBytes);
    }

    // view是原worker完整回执，row是同一成功页内行号；生成值文档，调用者无需查询文件。
    ks::ui::FieldDocument PrivateExecutionCandidatesFields(const NativeExecutionCandidatesResult& view, int row)
    {
        ks::ui::FieldDocument document; // 唯一规范文档供折叠字段视图的搜索/复制/导出使用。
        document.title = QStringLiteral("私有执行候选字段");
        document.section(QStringLiteral("候选读取来源"));
        document.field(QStringLiteral("项目目录"), QString::fromStdWString(view.context.projectDirectory));
        document.field(QStringLiteral("项目 ID"), QString::fromStdString(view.context.projectId));
        document.field(QStringLiteral("采样 ID"), QString::fromStdString(view.context.sampleId));
        document.field(QStringLiteral("原调试目标 PID"), QString::number(view.context.target.pid));
        document.field(QStringLiteral("原调试目标创建 FILETIME"), QString::number(view.context.target.creationFileTime));
        document.field(QStringLiteral("候选截止段"), QString::number(view.request.throughOrdinal));
        document.field(QStringLiteral("读取完成 FILETIME"), QString::number(view.readFileTime));
        document.field(QStringLiteral("状态"), QString::fromLatin1(Ksword::ActionAnalyze::ProjectErrorName(view.result.error)));
        document.field(QStringLiteral("阶段"), QString::fromLatin1(view.result.detail));
        document.field(QStringLiteral("Win32 错误"), QString::number(view.result.nativeError));
        if (!view.result || !view.page)
        {
            return document; // 失败不能补成功空目录，完整错误仍可以复制。
        }

        const auto& page = *view.page; // 以下数值均属于已核验的冻结前缀，非当前输入框。
        document.section(QStringLiteral("已核验候选前缀"));
        document.field(QStringLiteral("候选快照"), QString::fromStdString(page.snapshot));
        document.field(QStringLiteral("已核验观察数"), QString::number(page.observationCount));
        document.field(QStringLiteral("合法生命周期调用数"), QString::number(page.lifecycleCount));
        document.field(QStringLiteral("损坏生命周期调用数"), QString::number(page.malformedLifecycleCount));
        document.field(QStringLiteral("旧格式生命周期调用数"), QString::number(page.legacyLifecycleCount));
        document.field(QStringLiteral("范围候选数"), QString::number(page.rangeCandidateCount));
        document.field(QStringLiteral("Free 请求总数"), QString::number(page.freeRequestCount));
        document.field(QStringLiteral("来源声明的终段"), page.finalSegment ? QStringLiteral("是") : QStringLiteral("否"), true);
        document.note(QStringLiteral("候选来自历史已提交前缀；MEM_PRIVATE、同一 allocation、分配代次、实际释放和当前存活仍须分别核验。"));
        if (row < 0 || static_cast<std::size_t>(row) >= page.rows.size())
        {
            return document; // 未选择时只提供当前结果来源和缺口计数。
        }

        const auto& candidate = page.rows[static_cast<std::size_t>(row)]; // 唯一选中原调用的纯值快照。
        document.section(QStringLiteral("选中候选"));
        document.field(QStringLiteral("候选原因码"), QString::fromLatin1(candidate.reason));
        document.field(QStringLiteral("范围候选"), candidate.rangeCandidate ? QStringLiteral("是") : QStringLiteral("否"), true);
        document.field(QStringLiteral("原保护可执行"), candidate.executableProtection ? QStringLiteral("是") : QStringLiteral("否"), true);
        document.field(QStringLiteral("后续 Free 请求关联数"), QString::number(candidate.freeRequestCount));
        document.field(QStringLiteral("已保留 Free 请求关联数"), QString::number(candidate.freeRequests.size()));
        AppendCall(document, candidate.origin);
        for (const auto& link : candidate.freeRequests) // 至多四条完整Free原调用，不推断候选失活。
        {
            document.section(QStringLiteral("相关 Free 原请求"));
            document.field(QStringLiteral("请求基址位于实际范围"), link.requestedBaseInside ? QStringLiteral("是") : QStringLiteral("否"), true);
            document.field(QStringLiteral("请求范围与实际范围相交"), link.requestedRangeOverlaps ? QStringLiteral("是") : QStringLiteral("否"), true);
            AppendCall(document, link.call);
        }
        return document;
    }
}
