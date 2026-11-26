#include "../Framework.h"
#include "ExecutionGroupFields.h"
#include "../Internationalization/LanguageManager.h"

#include <QStringList>
#include <algorithm>

namespace ks::action_analyze
{
    namespace native = execution_group_native;
    namespace
    {
        using ks::i18n::sourceText;

        // 输入原生枚举，返回成员真实状态；不从附加准入推断已经武装或命中。
        QString MemberState(native::NativeControlStatus state)
        {
            switch (state)
            {
            case native::NativeControlStatus::Idle: return sourceText(QStringLiteral("空闲"));
            case native::NativeControlStatus::Accepted: return sourceText(QStringLiteral("已受理，等待停点"));
            case native::NativeControlStatus::Held: return sourceText(QStringLiteral("持有原生停点"));
            case native::NativeControlStatus::Released: return sourceText(QStringLiteral("已继续，等待脱离"));
            case native::NativeControlStatus::Detached: return sourceText(QStringLiteral("已脱离"));
            case native::NativeControlStatus::Ended: return sourceText(QStringLiteral("目标已退出"));
            case native::NativeControlStatus::ClosePending: return sourceText(QStringLiteral("清退未完成"));
            case native::NativeControlStatus::Closed: return sourceText(QStringLiteral("已清退"));
            case native::NativeControlStatus::Rejected: return sourceText(QStringLiteral("操作被拒绝"));
            case native::NativeControlStatus::RecoveryRequired: return sourceText(QStringLiteral("恢复未确认"));
            }
            return {};
        }

        // 地址仅作显示，零值仍有明确数值语义，不重建任何控制票据。
        QString Hex(std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 0, 16);
        }

        // 输入冻结站点，生成紧凑位置；完整模块路径通过tooltip和字段文档保留。
        QString SiteText(const native::ExecutionGroupSite& site)
        {
            if (site.address)
            {
                return site.rangeBytes ? QStringLiteral("%1 / %2 bytes").arg(Hex(site.address)).arg(site.rangeBytes) : Hex(site.address);
            }
            return QString::fromStdWString(site.modulePath) + QStringLiteral(" ! ") +
                (site.rva ? Hex(*site.rva) : QString::fromStdString(site.exactExport));
        }

        // 将同一份原始NativeControlResult投影为字段，不借用页面行号或历史身份授控制权。
        void AppendControl(ks::ui::FieldDocument& document, const native::NativeControlResult& state)
        {
            document.field(QStringLiteral("成员状态"), MemberState(state.status))
                .field(QStringLiteral("原生诊断"), QString::fromLatin1(state.stage))
                .field(QStringLiteral("Win32 错误"), QString::number(state.win32Error))
                .field(QStringLiteral("账本结果码"), QString::number(static_cast<int>(state.ledgerResult)))
                .field(QStringLiteral("进程实例 ID"), QString::fromStdString(state.processInstanceId))
                .field(QStringLiteral("停止原因码"), QString::number(static_cast<int>(state.stopReason)))
                .field(QStringLiteral("清退确认"), state.clean ? QStringLiteral("是") : QStringLiteral("否"), true);
            if (state.armedPause)
            {
                const auto& pause = *state.armedPause; // 主动暂停回执独立于执行命中、继续和步进回执。
                document.field(QStringLiteral("主动暂停请求 ID"), QString::fromStdString(pause.request.requestId))
                    .field(QStringLiteral("主动暂停状态码"), QString::number(static_cast<int>(pause.state)))
                    .field(QStringLiteral("主动暂停诊断"), QString::fromLatin1(pause.stage))
                    .field(QStringLiteral("主动暂停 Win32"), QString::number(pause.win32Error))
                    .field(QStringLiteral("主动暂停停止组"), pause.groupId ? QString::fromStdString(*pause.groupId) : QString())
                    .field(QStringLiteral("主动暂停事件序号"), pause.event ? QString::number(pause.event->serial) : QString());
            }
            if (state.responsibility)
            {
                const auto& stop = *state.responsibility; // 事件责任与线程冻结汇总分别保留。
                document.field(QStringLiteral("停点 ID"), QString::fromStdString(stop.stopId))
                    .field(QStringLiteral("停止组 ID"), QString::fromStdString(stop.groupId))
                    .field(QStringLiteral("原生事件序号"), QString::number(stop.event.serial))
                    .field(QStringLiteral("后端实例 ID"), QString::fromStdString(stop.event.backendInstanceId))
                    .field(QStringLiteral("事件线程身份"), QString::fromStdString(stop.actualEventThread.threadId));
            }
            if (state.group)
            {
                const auto& group = *state.group; // 当前停止组完整版本和覆盖摘要。
                document.field(QStringLiteral("状态修订"), QString::number(group.stateRevision))
                    .field(QStringLiteral("成员修订"), QString::number(group.membershipRevision))
                    .field(QStringLiteral("成员摘要"), QString::fromStdString(group.membershipSha256))
                    .field(QStringLiteral("停止组状态码"), QString::number(static_cast<int>(group.state)))
                    .field(QStringLiteral("冻结线程数"), QString::number(state.frozenThreads.size()));
            }
            if (state.pending)
            {
                document.field(QStringLiteral("事件 TID"), QString::number(state.pending->tid))
                    .field(QStringLiteral("原生事件类型"), QString::number(state.pending->eventCode));
            }
            if (state.breakpoint)
            {
                const auto& binding = *state.breakpoint; // 实际绑定与站点草稿分别显示。
                document.field(QStringLiteral("实际执行地址"), Hex(binding.address))
                    .field(QStringLiteral("执行范围字节数"), QString::number(binding.rangeBytes))
                    .field(QStringLiteral("断点状态码"), QString::number(static_cast<int>(binding.state)))
                    .field(QStringLiteral("断点诊断"), QString::fromLatin1(binding.stage))
                    .field(QStringLiteral("断点 Win32"), QString::number(binding.win32Error));
            }
            if (state.registers)
            {
                document.field(QStringLiteral("RIP"), Hex(state.registers->rip))
                    .field(QStringLiteral("RSP"), Hex(state.registers->rsp))
                    .field(QStringLiteral("RAX"), Hex(state.registers->rax));
            }
            if (state.step)
            {
                const auto& step = *state.step; // 步进票据包括原请求、事件和恢复状态。
                document.field(QStringLiteral("步进请求 ID"), QString::fromStdString(step.request.release.requestId))
                    .field(QStringLiteral("步进状态码"), QString::number(static_cast<int>(step.state)))
                    .field(QStringLiteral("步进诊断"), QString::fromLatin1(step.stage))
                    .field(QStringLiteral("步进 Win32"), QString::number(step.win32Error))
                    .field(QStringLiteral("步进起点"), Hex(step.startIp))
                    .field(QStringLiteral("步进资源已恢复"), step.resourcesRestored ? QStringLiteral("是") : QStringLiteral("否"), true);
            }
            if (state.release)
            {
                document.field(QStringLiteral("继续请求 ID"), state.releaseRequestId ? QString::fromStdString(*state.releaseRequestId) : QString())
                    .field(QStringLiteral("继续发出修订"), QString::number(state.release->issuedRevision));
                if (state.release->receipt)
                {
                    document.field(QStringLiteral("继续返回码"), QString::number(static_cast<int>(state.release->receipt->result)));
                }
                if (state.release->readback)
                {
                    document.field(QStringLiteral("继续回读码"), QString::number(static_cast<int>(state.release->readback->result)));
                }
            }
            if (state.firstRecoveryFailure)
            {
                document.field(QStringLiteral("首次恢复失败"), QString::fromLatin1(state.firstRecoveryFailure->stage))
                    .field(QStringLiteral("首次恢复错误"), QString::number(state.firstRecoveryFailure->win32Error));
            }
        }
    }

    // 输入集合枚举，返回准确状态文案；HeldComplete指各成员停点，不承诺同时冻结。
    QString ExecutionGroupStateText(native::ExecutionGroupState state)
    {
        using ks::i18n::sourceText;
        switch (state)
        {
        case native::ExecutionGroupState::Idle: return sourceText(QStringLiteral("执行站点草稿，尚未开始"));
        case native::ExecutionGroupState::Active: return sourceText(QStringLiteral("正在等待成员回执"));
        case native::ExecutionGroupState::HeldPartial: return sourceText(QStringLiteral("部分成员持有停点"));
        case native::ExecutionGroupState::HeldComplete: return sourceText(QStringLiteral("全部成员持有停点"));
        case native::ExecutionGroupState::PartialFailure: return sourceText(QStringLiteral("部分成员启动失败"));
        case native::ExecutionGroupState::RecoveryRequired: return sourceText(QStringLiteral("原集合仍有恢复责任"));
        case native::ExecutionGroupState::Closing: return sourceText(QStringLiteral("正在清退原集合"));
        case native::ExecutionGroupState::Closed: return sourceText(QStringLiteral("原集合已清退"));
        }
        return {};
    }

    // 输入已发布成员，核对停止和条件同代次；不执行Query，后台实际动作仍再次验证完整票据。
    bool ExecutionGroupCanRelease(const native::ExecutionGroupMember& member)
    {
        // 单成员步进仍要求Held；批量Continue的already-running资格由共享backend单独判断。
        return native::DataWatchHeldStop(member.control) && native::OwnedExecutionGroup::CanContinueMember(member);
    }

    int ExecutionGroupMemberModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : static_cast<int>(sites.size()); // Start后目录不可被查询隐式扩展。
    }

    int ExecutionGroupMemberModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : 4; // 管理概览无需密集列，完整字段使用下方统一文档。
    }

    QVariant ExecutionGroupMemberModel::data(const QModelIndex& index, int role) const
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || index.column() < 0 || index.column() >= 4 ||
            (role != Qt::DisplayRole && role != Qt::ToolTipRole))
        {
            return {};
        }
        const auto& site = sites.at(index.row()); // PID和创建时间共同构成行身份。
        const auto member = std::find_if(result.members.begin(), result.members.end(), [&](const auto& item)
        {
            return item.site.pid == site.pid && item.site.creationFileTime == site.creationFileTime;
        });
        if (index.column() == 0)
        {
            return QStringLiteral("%1 / %2").arg(site.pid).arg(site.creationFileTime);
        }
        if (index.column() == 1)
        {
            return SiteText(site);
        }
        if (member == result.members.end())
        {
            return index.column() == 2 ? sourceText(QStringLiteral("草稿，尚未核验")) : QString();
        }
        return index.column() == 2 ? MemberState(member->control.status) :
            QStringLiteral("%1 / Win32 %2").arg(QString::fromLatin1(member->control.stage)).arg(member->control.win32Error);
    }

    QVariant ExecutionGroupMemberModel::headerData(int section, Qt::Orientation orientation, int role) const
    {
        const QStringList titles{QStringLiteral("PID / 创建 FILETIME"), QStringLiteral("执行站点"),
            QStringLiteral("成员状态"), QStringLiteral("原生诊断")}; // 四列互补，宽路径允许原生表格横向滚动。
        return orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < titles.size()
            ? sourceText(titles.at(section)) : QVariant();
    }

    void ExecutionGroupMemberModel::Replace(std::vector<native::ExecutionGroupSite> rows)
    {
        beginResetModel(); // 仅显式草稿增删使用重置，调用方恢复未变行选择。
        sites = std::move(rows);
        result = {};
        endResetModel();
    }

    void ExecutionGroupMemberModel::Apply(const native::ExecutionGroupResult& snapshot)
    {
        result = snapshot; // 固定目录只更新值，不丢弃多选。
        if (!sites.empty())
        {
            emit dataChanged(index(0, 0), index(rowCount() - 1, 3));
        }
    }

    void ExecutionGroupMemberModel::Relocalize()
    {
        emit headerDataChanged(Qt::Horizontal, 0, 3); // 翻译切换不重置模型身份。
        Apply(result);
    }

    // 输入实际快照、冻结目录和选择，输出唯一可搜索/复制/导出的字段文档。
    ks::ui::FieldDocument ExecutionGroupDocument(const ExecutionGroupSessionSnapshot& snapshot,
        const std::vector<native::ExecutionGroupSite>& sites, const std::vector<int>& selected)
    {
        ks::ui::FieldDocument document; // 全部字段同源，不维护隐藏的第二份数据树。
        document.title = QStringLiteral("执行断点集合");
        document.section(QStringLiteral("集合身份"))
            .field(QStringLiteral("集合 ID"), QString::fromStdString(snapshot.result.collectionId))
            .field(QStringLiteral("成员数量"), QString::number(sites.size()))
            .field(QStringLiteral("回读 FILETIME"), QString::number(snapshot.observedFileTime))
            .note(QStringLiteral("逐成员回读，不保证跨进程同时冻结。"));
        if (!snapshot.diagnostic.empty())
        {
            document.field(QStringLiteral("后台异常摘要"), QString::fromStdString(snapshot.diagnostic));
        }
        for (const int row : selected)
        {
            if (row < 0 || row >= static_cast<int>(sites.size()))
            {
                continue;
            }
            const auto& site = sites.at(row); // 所选草稿和当前成员都以同一强实例定位。
            document.section(QStringLiteral("执行站点"))
                .field(QStringLiteral("PID"), QString::number(site.pid))
                .field(QStringLiteral("创建 FILETIME"), QString::number(site.creationFileTime))
                .field(QStringLiteral("执行位置"), SiteText(site))
                .field(QStringLiteral("命中条件"), QString::fromStdWString(site.conditionSource));
            for (const auto& member : snapshot.result.members)
            {
                if (member.site.pid != site.pid || member.site.creationFileTime != site.creationFileTime)
                {
                    continue;
                }
                document.field(QStringLiteral("采样 ID"), QString::fromStdString(member.owner.sampleId))
                    .field(QStringLiteral("会话 ID"), QString::fromStdString(member.owner.sessionId))
                    .field(QStringLiteral("会话代次"), QString::fromStdString(member.owner.epoch))
                    .field(QStringLiteral("后端实例 ID"), QString::fromStdString(member.owner.backendInstanceId))
                    .field(QStringLiteral("附加准入"), member.attachAccepted ? QStringLiteral("是") : QStringLiteral("否"), true);
                AppendControl(document, member.control);
                document.field(QStringLiteral("条件真 / 假 / 未知"), QStringLiteral("%1 / %2 / %3")
                    .arg(member.condition.trueCount).arg(member.condition.falseCount).arg(member.condition.unknownCount));
                if (member.condition.last)
                {
                    const auto& decision = *member.condition.last; // 条件来源事件和实际自动恢复错误独立显示。
                    document.field(QStringLiteral("条件事件序号"), QString::number(decision.event.serial))
                        .field(QStringLiteral("条件状态修订"), QString::number(decision.stateRevision))
                        .field(QStringLiteral("条件真值码"), QString::number(static_cast<int>(decision.evaluation.truth)))
                        .field(QStringLiteral("条件求值故障码"), QString::number(static_cast<int>(decision.evaluation.fault)))
                        .field(QStringLiteral("条件自动继续错误"), QString::number(decision.releaseError));
                }
            }
        }
        if (snapshot.result.operation)
        {
            const auto& operation = *snapshot.result.operation; // 上次原始操作与当前成员状态分别列出。
            document.section(QStringLiteral("最近显式操作回执"))
                .field(QStringLiteral("操作类型"), QString::number(static_cast<int>(operation.action)))
                .field(QStringLiteral("批次准入"), operation.admitted ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("原生诊断"), QString::fromLatin1(operation.stage))
                .field(QStringLiteral("Win32 错误"), QString::number(operation.win32Error));
            for (const auto& outcome : operation.outcomes)
            {
                document.section(QStringLiteral("成员操作回执"))
                    .field(QStringLiteral("PID"), QString::number(outcome.pid))
                    .field(QStringLiteral("创建 FILETIME"), QString::number(outcome.creationFileTime))
                    .field(QStringLiteral("实际调用原会话"), outcome.actionAttempted ? QStringLiteral("是") : QStringLiteral("否"), true)
                    .field(QStringLiteral("成员操作分类"), QString::fromLatin1(outcome.disposition));
                AppendControl(document, outcome.control); // 全部实际调用成员均可查，不以第一行代表整个批次。
            }
        }
        return document;
    }
}
