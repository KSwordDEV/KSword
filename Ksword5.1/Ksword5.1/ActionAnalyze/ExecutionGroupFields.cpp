#include "../Framework.h"
#include "ExecutionGroupFields.h"
#include "NativeSessionApiPane.h"
#include "ApiTransferPresentation.h"
#include "ProcessGroupMemoryPane.h"
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
                document.field(QStringLiteral("等待模块加载"), binding.waitingForModule
                    ? QStringLiteral("是") : QStringLiteral("否"), true); // 使用原owner状态，与实际地址和诊断保留同源。
                document.field(QStringLiteral("实际装载文件 SHA256"), binding.imageSha256
                    ? QString::fromStdString(*binding.imageSha256) : sourceText(QStringLiteral("无实际测量值")));
                document.field(QStringLiteral("已纳入执行范围"), QString::number(binding.executionRanges.size()));
                std::uint64_t totalRangeBytes = 0; // 成功范围目录总量独立于初始站点，不计失败回滚中的页。
                bool totalValid = true; // 超过数值可表示范围时显示不可用，不能发布回绕总量。
                for (const auto& range : binding.executionRanges)
                {
                    document.field(QStringLiteral("范围起点 / 字节数 / 分配基址"),
                        QStringLiteral("%1 / %2 / %3").arg(Hex(range.base)).arg(range.bytes).arg(Hex(range.allocationBase)));
                    if (range.bytes > UINT64_MAX - totalRangeBytes)
                    {
                        totalValid = false;
                    }
                    else
                    {
                        totalRangeBytes += range.bytes;
                    }
                }
                document.field(QStringLiteral("已纳入范围总字节数"), totalValid ? QString::number(totalRangeBytes) : sourceText(QStringLiteral("不可用")))
                    .field(QStringLiteral("已纳入范围总页数"), totalValid ? QString::number(totalRangeBytes / 4096) : sourceText(QStringLiteral("不可用")));
            }
            if (state.executionRange)
            {
                const auto& receipt = *state.executionRange; // 本次范围事务回执，独立于初始站点及当前范围目录。
                const auto& stop = receipt.request.stop; // 保存提交时的完整授权坐标，不借当前选中成员补字段。
                document.field(QStringLiteral("执行范围纳入回执"), QString::fromLatin1(receipt.stage))
                    .field(QStringLiteral("新范围起点"), Hex(receipt.request.address))
                    .field(QStringLiteral("范围字节数"), QString::number(receipt.request.bytes))
                    .field(QStringLiteral("范围已纳入"), receipt.added ? QStringLiteral("是") : QStringLiteral("否"), true)
                    .field(QStringLiteral("新增范围回滚完整"), receipt.rollbackComplete ? QStringLiteral("是") : QStringLiteral("否"), true)
                    .field(QStringLiteral("请求 ID"), QString::fromStdString(receipt.request.stop.requestId))
                    .field(QStringLiteral("状态修订"), QString::number(receipt.stateRevision))
                    .field(QStringLiteral("范围请求状态修订"), QString::number(stop.expectedStateRevision))
                    .field(QStringLiteral("范围请求停止组"), QString::fromStdString(stop.groupId))
                    .field(QStringLiteral("范围请求停点"), QString::fromStdString(stop.stopId))
                    .field(QStringLiteral("范围请求事件"), QStringLiteral("%1 / %2")
                        .arg(QString::fromStdString(stop.event.backendInstanceId)).arg(stop.event.serial))
                    .field(QStringLiteral("范围请求采样"), QString::fromStdString(stop.owner.sampleId))
                    .field(QStringLiteral("范围请求会话"), QString::fromStdString(stop.owner.sessionId))
                    .field(QStringLiteral("范围请求代次"), QString::fromStdString(stop.owner.epoch))
                    .field(QStringLiteral("范围请求后端"), QString::fromStdString(stop.owner.backendInstanceId))
                    .field(QStringLiteral("Win32"), QString::number(receipt.win32Error));
            }
            if (state.registers)
            {
                for (const auto& field : native::NativeStopRegisterFields)
                {
                    document.field(QString::fromLatin1(field.name).toUpper(), Hex((*state.registers).*(field.value)));
                }
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
            auto text = SiteText(site); // 列表紧凑显示期望约束，tooltip保留完整64位；实际测量值只来自control。
            if (site.imageSha256)
            {
                const auto expected = QString::fromStdString(*site.imageSha256); // 显示冻结站点的用户期望值。
                text += sourceText(QStringLiteral(" · 期望 SHA256 %1"))
                    .arg(role == Qt::ToolTipRole ? expected : expected.left(12) + QStringLiteral("…"));
            }
            return text;
        }
        if (member == result.members.end())
        {
            return index.column() == 2 ? sourceText(QStringLiteral("草稿，尚未核验")) : QString();
        }
        if (index.column() == 2 && member->control.breakpoint && member->control.breakpoint->waitingForModule)
        {
            // 原native仍附加但尚未武装，列表不能把Accepted当作已有执行覆盖。
            return sourceText(QStringLiteral("等待模块加载"));
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
        result = snapshot; // 原成员只更新值；追加新行保持已有多选和稳定行身份。
        if (!snapshot.collectionId.empty() && snapshot.members.size() > sites.size())
        {
            const auto first = sites.size(); // 原成员不会移除或重排，新增目录仅在末尾发布。
            beginInsertRows({}, static_cast<int>(first), static_cast<int>(snapshot.members.size() - 1));
            for (std::size_t row = first; row < snapshot.members.size(); ++row)
            {
                sites.push_back(snapshot.members[row].site); // 保留实际解析后的新站点，不借当前表单重建。
            }
            endInsertRows();
        }
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
            .field(QStringLiteral("命中联停策略"), snapshot.result.holdPeersOnHit ? QStringLiteral("是") : QStringLiteral("否"), true)
            .note(QStringLiteral("逐成员回读，不保证跨进程同时冻结。"));
        if (!snapshot.diagnostic.empty())
        {
            document.field(QStringLiteral("后台异常摘要"), QString::fromStdString(snapshot.diagnostic));
        }
        if (snapshot.archive.configured || !snapshot.archive.setup)
        {
            // 三端共用规范存储文档，正文、复制和导出保留同一原事件及written/flushed/verified边界。
            const auto archive = Ksword::ActionAnalyze::DescribeExecutionGroupArchive(snapshot.archive); // worker纯值，不重读目标。
            document.section(QStringLiteral("执行观察归档"))
                .field(QStringLiteral("项目 ID"), QString::fromStdString(snapshot.archive.projectId))
                .field(QStringLiteral("采样 ID"), QString::fromStdString(snapshot.archive.sampleId))
                .field(QStringLiteral("项目目录"), QString::fromStdWString(snapshot.archive.directory))
                .field(QStringLiteral("自动保存新的执行观察"), snapshot.archive.autoSaveExecution ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("归档结果 JSON"), QString::fromStdString(Ksword::Evidence::WriteJson(archive)));
        }
        if (snapshot.archive.api)
        {
            NativeSessionApiPane::AppendFields(document, *snapshot.archive.api); // 不随当前成员选择改写采集时来源。
        }
        if (snapshot.archive.memory.capture || snapshot.archive.memory.receipt)
        {
            if (snapshot.archive.memory.capture)
            {
                ProcessGroupMemoryPane::AppendCapture(document, *snapshot.archive.memory.capture); // 与原停点页共享可读字段和原字节预览。
            }
            document.section(QStringLiteral("本次选中范围内存"))
                .field(QStringLiteral("内存结果 JSON"), QString::fromStdString(Ksword::Evidence::WriteJson(
                    Ksword::ActionAnalyze::DescribeExecutionGroupMemory(snapshot.archive.memory)))); // 原读取、保存身份与页状态同源。
        }
        if (snapshot.apiStartup)
        {
            NativeSessionApiPane::AppendProgress(document, *snapshot.apiStartup); // 在途真实阶段，原字段视图保留搜索和导出。
        }
        if (snapshot.apiCheckpoint && snapshot.apiRules)
        {
            // 单目标和集合使用同一份规范字段，语言切换、搜索、复制与导出保持同源。
            NativeSessionApiPane::AppendCheckpoint(document, *snapshot.apiCheckpoint, *snapshot.apiRules);
        }
        if (snapshot.apiTransfers)
        {
            // 候选与实际执行分别显示；共享投影保留最近写入/请求双方各自的归档坐标。
            const auto& transfers = *snapshot.apiTransfers; // 同一worker发布的累计数和有界窗口。
            AppendApiTransferProgress(document, transfers.candidateCount, transfers.evictedWrites,
                transfers.recent.empty() ? nullptr : &transfers.recent.back(),
                transfers.networkTraffic.type() == Ksword::Evidence::JsonType::Null ? QString() :
                    QString::fromStdString(Ksword::Evidence::WriteJson(transfers.networkTraffic)),
                transfers.agentEtw.type() == Ksword::Evidence::JsonType::Null ? QString() :
                    QString::fromStdString(Ksword::Evidence::WriteJson(transfers.agentEtw)));
            AppendApiApcProgress(document, transfers.apcCandidateCount,
                transfers.recentApc.empty() ? nullptr : &transfers.recentApc.back());
            AppendApiContextProgress(document, transfers.contextCandidateCount,
                transfers.recentContext.empty() ? nullptr : &transfers.recentContext.back());
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
                .field(QStringLiteral("期望映像 SHA256"), site.imageSha256
                    ? QString::fromStdString(*site.imageSha256) : sourceText(QStringLiteral("未指定")))
                .field(QStringLiteral("命中条件"), QString::fromStdWString(site.conditionSource));
            if (!site.definitionId.empty())
            {
                document.field(QStringLiteral("冻结断点定义 ID（可选）"), QString::fromStdString(site.definitionId)); // 草稿选择不会覆盖已核对结果。
            }
            for (const auto& member : snapshot.result.members)
            {
                if (member.site.pid != site.pid || member.site.creationFileTime != site.creationFileTime)
                {
                    continue;
                }
                if (!member.site.definitionId.empty())
                {
                    // 实际核对后的继承约束来自worker冻结目录，不能以原输入框空值显示成无约束。
                    document.section(QStringLiteral("冻结定义绑定"))
                        .field(QStringLiteral("冻结断点定义 ID（可选）"), QString::fromStdString(member.site.definitionId))
                        .field(QStringLiteral("期望映像 SHA256"), member.site.imageSha256
                            ? QString::fromStdString(*member.site.imageSha256) : sourceText(QStringLiteral("未指定")));
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
        if (snapshot.result.peerHold)
        {
            const auto& hold = *snapshot.result.peerHold; // 联停回执独立于手动操作，不随后来成员选择改写关联源。
            document.section(QStringLiteral("最近命中联停回执"))
                .field(QStringLiteral("后端实例"), QString::fromStdString(hold.triggerOwner.backendInstanceId))
                .field(QStringLiteral("采样 ID"), QString::fromStdString(hold.triggerOwner.sampleId))
                .field(QStringLiteral("会话 ID"), QString::fromStdString(hold.triggerOwner.sessionId))
                .field(QStringLiteral("事件序号"), QString::number(hold.triggerEvent.serial));
            for (const auto& outcome : hold.outcomes)
            {
                document.section(QStringLiteral("成员操作回执"))
                    .field(QStringLiteral("PID"), QString::number(outcome.pid))
                    .field(QStringLiteral("创建 FILETIME"), QString::number(outcome.creationFileTime))
                    .field(QStringLiteral("实际调用原会话"), outcome.actionAttempted ? QStringLiteral("是") : QStringLiteral("否"), true)
                    .field(QStringLiteral("成员操作分类"), QString::fromLatin1(outcome.disposition));
                AppendControl(document, outcome.control); // 接纳不等于已停止；完整回执用于查明部分拒绝。
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
                const auto member = std::find_if(snapshot.result.members.begin(), snapshot.result.members.end(), [&](const auto& item)
                {
                    return item.site.pid == outcome.pid && item.site.creationFileTime == outcome.creationFileTime;
                }); // 操作详情只取同一冻结集合站点；不向可能已编辑的表单借用期望值。
                if (member != snapshot.result.members.end())
                {
                    document.field(QStringLiteral("期望映像 SHA256"), member->site.imageSha256
                        ? QString::fromStdString(*member->site.imageSha256) : sourceText(QStringLiteral("未指定")));
                }
                AppendControl(document, outcome.control); // 全部实际调用成员均可查，不以第一行代表整个批次。
            }
        }
        return document;
    }
}
