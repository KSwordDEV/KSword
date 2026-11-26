#include "OfflineSegmentOverview.h"
#include "CallbackArchivePresentation.h"
#include "ObjectContextMenu.h"
#include "NativeExecutionPresentation.h"
#include "../UI/StructuredFieldView.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TablePresentation.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/VisibleTableWidget.h"

#include <QAbstractItemModel>
#include <QHeaderView>
#include <QLabel>
#include <QItemSelectionModel>
#include <QSignalBlocker>
#include <QStringList>
#include <QToolButton>
#include <QTreeView>
#include <QVBoxLayout>
#include <algorithm>
#include <array>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;

    // 返回对象类型与编号，用于筛选摘要和选中证据范围。
    QString ObjectScopeText(const ArchivedObjectObservation& object)
    {
        return object.kind == ArchivedObjectKind::Process
            ? sourceText(QStringLiteral("进程对象 ID %1（采样内）")).arg(object.id)
            : sourceText(QStringLiteral("线程对象 ID %1（采样内）")).arg(object.id);
    }

    // 把菜单冻结的样本内引用转换为当前视图的同值范围。
    ArchivedObjectObservation FromMenu(const ObjectMenuRef& ref)
    {
        const auto kind = ref.kind == ObjectMenuKind::Process ? ArchivedObjectKind::Process : ArchivedObjectKind::Thread; // 保持进程和线程编号空间。
        return {ref.sample.projectId, ref.sample.sampleId, kind, ref.objectId};
    }

    // 同一归档行的分类供 AA-01 标签及关系树共用。段号为零时没有原始坐标。
    std::optional<ArchivedRelationAnchor> RelationAnchor(const SegmentRow& row)
    {
        if (row.segmentOrdinal && row.archivedApi)
        {
            return ArchivedRelationAnchor{ArchivedRelationKind::ApiCandidate, RowAnchor(row)};
        }
        if (row.segmentOrdinal && (row.archivedEtw || row.network || row.archivedCallback))
        {
            return ArchivedRelationAnchor{ArchivedRelationKind::SourceContext, RowAnchor(row)};
        }
        return std::nullopt;
    }

    // 给定类型化的归档叶项，返回带真实段号和序号的浏览名称。
    QString RelationRowText(const SegmentRow& row)
    {
        QString label; // 根据已核验的记录种类返回叶项标题。
        if (row.archivedApi)
        {
            label = row.archivedApi->api;
        }
        else if (row.archivedEtw && row.liveEtw)
        {
            label = sourceText(QStringLiteral("ETW 事件 %1 / v%2"))
                .arg(row.liveEtw->eventId).arg(row.liveEtw->version);
        }
        else if (row.archivedCallback)
        {
            label = CallbackArchiveRowLabel();
        }
        else
        {
            label = row.network ? sourceText(QStringLiteral("网络通信记录")) : QStringLiteral("ETW");
        }
        return QStringLiteral("%1/%2 #%3 · %4").arg(RawLaneName(row.evidenceLane)).arg(row.segmentOrdinal).arg(row.sequence).arg(label);
    }
}

// 归档关系借用当前有界快照；前两组索引事件表，后两组分别展开创建与 APC 双方原包。
class ArchiveRelationModel final : public QAbstractItemModel
{
    using Groups = std::array<QList<qsizetype>, 2>; // 两组在当前快照中的行索引。

public:
    using QAbstractItemModel::QAbstractItemModel;

    // 输入已发布快照和范围身份；候选拓扑未变时增量更新，否则重置并由页面恢复选区。
    void setSnapshot(std::shared_ptr<const SegmentSnapshot> snapshot, bool sameScope)
    {
        if (m_snapshot == snapshot)
        {
            return;
        }
        Groups next; // 与事件表共享同一份有界窗口，显示筛选独立于这里的分组。
        if (snapshot)
        {
            for (qsizetype offset = 0; offset < snapshot->rows.size(); ++offset)
            {
                const auto anchor = RelationAnchor(snapshot->rows.at(offset)); // 只采纳已分类且可定位的归档行。
                if (anchor)
                {
                    const auto group = anchor->kind == ArchivedRelationKind::ApiCandidate ? 0 : 1; // 与两类根节点顺序一致。
                    next[group].append(offset);
                }
            }
        }
        const bool hasGroups = !next[0].isEmpty() || !next[1].isEmpty() ||
            (snapshot && (!snapshot->transferCandidates.empty() || !snapshot->apcTransferCandidates.empty() ||
                !snapshot->contextTransferCandidates.empty() || snapshot->evictedTransferWrites ||
                snapshot->nativeExecution.state != Ksword::Evidence::NativeHistoryState::NotRequested)); // 原生失败和成功空结果也保留入口。
        if (sameScope && m_hasGroups && hasGroups &&
            m_snapshot->checkpoint == SegmentCheckpoint::ApiRawVerified && snapshot->checkpoint == SegmentCheckpoint::ApiRawVerified &&
            m_snapshot->lastVerifiedOrdinal <= snapshot->lastVerifiedOrdinal && sameCandidates(*snapshot) && applyPrefix(snapshot, next))
        {
            return;
        }
        beginResetModel();
        m_snapshot = std::move(snapshot);
        m_groups = std::move(next);
        m_hasGroups = hasGroups;
        endResetModel();
    }

    // 十根含独立原生历史；200000为历史叶，不与候选双方或四类执行编号混用。
    QModelIndex index(int row, int column, const QModelIndex& parent = {}) const override
    {
        if (!hasIndex(row, column, parent))
        {
            return {};
        }
        // 执行候选使用独立 ID 空间，保留既有 API 三类分支的身份和定位语义。
        if (parent.isValid() && parent.internalId() == 0 && parent.row() == 9)
        {
            return createIndex(row, column, quintptr(200000));
        }
        if (parent.isValid() && parent.internalId() == 0 && parent.row() >= 5)
        {
            return createIndex(row, column, quintptr(100000 + parent.row() - 5));
        }
        if (parent.isValid() && parent.internalId() >= 100000 && parent.internalId() < 100004)
        {
            return createIndex(row, column, quintptr(1000000 + parent.row() * 4 + parent.internalId() - 100000));
        }
        const auto groupId = !parent.isValid() ? quintptr(0) : parent.internalId() >= 3
            ? static_cast<quintptr>(6 + parent.row() * 3 + parent.internalId() - 3)
            : static_cast<quintptr>(parent.row() + 1); // 3/4/5 是创建/APC/上下文父项，6 起为叶项。
        return createIndex(row, column, groupId);
    }

    // 把叶项的内部 ID 转回分组节点，顶级分组没有父节点。
    QModelIndex parent(const QModelIndex& index) const override
    {
        if (index.internalId() == 200000)
        {
            return createIndex(9, 0, quintptr(0));
        }
        if (index.internalId() >= 1000000)
        {
            return createIndex(static_cast<int>((index.internalId() - 1000000) / 4), 0,
                quintptr(100000 + (index.internalId() - 1000000) % 4));
        }
        if (index.internalId() >= 100000 && index.internalId() < 100004)
        {
            return createIndex(static_cast<int>(index.internalId() - 100000 + 5), 0, quintptr(0));
        }
        if (index.internalId() >= 6)
        {
            const auto encoded = index.internalId() - 6; // 除三为窗口下标，余数为候选类型。
            return createIndex(static_cast<int>(encoded / 3), 0, quintptr(3 + encoded % 3));
        }
        return index.internalId() ? createIndex(static_cast<int>(index.internalId() - 1), 0, quintptr(0)) : QModelIndex();
    }

    // 只有快照包含归档关系时才显示根节点，各组中的行数取实际归档索引。
    int rowCount(const QModelIndex& parent = {}) const override
    {
        if (!parent.isValid())
        {
            return m_hasGroups ? 10 : 0;
        }
        if (parent.internalId() == 200000)
        {
            return 0;
        }
        if (parent.internalId() >= 1000000)
        {
            return 0;
        }
        if (parent.internalId() >= 100000 && parent.internalId() < 100004)
        {
            return 3; // 写入（映射为空）、请求、独立原生观察各保留自己的身份。
        }
        if (parent.internalId() >= 3 && parent.internalId() <= 5)
        {
            return 2; // 每个候选固定展开同一对写入和请求返回原包。
        }
        if (parent.internalId())
        {
            return 0;
        }
        if (parent.row() >= 2)
        {
            if (parent.row() == 9)
            {
                return static_cast<int>(m_snapshot->nativeExecution.observations.size());
            }
            if (parent.row() >= 5)
            {
                return static_cast<int>(std::count_if(m_snapshot->nativeExecution.candidates.begin(),
                    m_snapshot->nativeExecution.candidates.end(), [&](const auto& item) { return item.kind == parent.row() - 5; }));
            }
            if (parent.row() == 4)
            {
                return static_cast<int>(m_snapshot->contextTransferCandidates.size());
            }
            return parent.row() == 2 ? static_cast<int>(m_snapshot->transferCandidates.size())
                : static_cast<int>(m_snapshot->apcTransferCandidates.size());
        }
        return static_cast<int>(m_groups[parent.row()].size());
    }

    // 一个字段并列原始坐标和来源名称，窄窗可由提示查看完整名称。
    int columnCount(const QModelIndex& = {}) const override
    {
        return 1;
    }

    // 只给当前快照中有效的叶项提供原始行，根分组不提供定位目标。
    const SegmentRow* record(const QModelIndex& index, const SegmentSnapshot* snapshot) const
    {
        const auto groupId = index.internalId(); // 0 根，1/2 普通叶，3/4/5 候选父，6 起为双方叶项。
        if (groupId >= 100000)
        {
            const auto* candidate = execution(index, snapshot); // 原生分支 API 叶仍返回原行而不是投影行。
            if (!candidate || groupId < 1000000)
            {
                return nullptr;
            }
            return index.row() == 0 ? (candidate->write ? &*candidate->write : nullptr)
                : index.row() == 1 ? &candidate->request : nullptr;
        }
        if (m_snapshot && (!snapshot || m_snapshot.get() == snapshot) && index.model() == this && groupId >= 6)
        {
            const auto candidate = (groupId - 6) / 3; // 对应类型窗口中的候选下标。
            const auto kind = (groupId - 6) % 3; // 0 创建，1 APC，2 上下文，不因共享写入跳组。
            if (kind == 2 && candidate < m_snapshot->contextTransferCandidates.size() && index.row() >= 0 && index.row() < 2)
            {
                const auto& pair = m_snapshot->contextTransferCandidates[candidate]; // 请求与写入的真实双方。
                return index.row() == 0 ? &pair.write : &pair.context;
            }
            if (kind == 1 && candidate < m_snapshot->apcTransferCandidates.size() && index.row() >= 0 && index.row() < 2)
            {
                const auto& pair = m_snapshot->apcTransferCandidates[candidate]; // APC 的写入与入队返回双方。
                return index.row() == 0 ? &pair.write : &pair.queue;
            }
            if (kind == 0 && candidate < m_snapshot->transferCandidates.size() && index.row() >= 0 && index.row() < 2)
            {
                const auto& pair = m_snapshot->transferCandidates[candidate]; // 同一候选的双方详情。
                return index.row() == 0 ? &pair.write : &pair.threadCreate;
            }
            return nullptr;
        }
        if (!m_snapshot || (snapshot && m_snapshot.get() != snapshot) || index.model() != this || !groupId || groupId > m_groups.size())
        {
            return nullptr;
        }
        const auto& group = m_groups[groupId - 1]; // 叶项所属的快照内索引组。
        return index.row() >= 0 && index.row() < group.size() ? &m_snapshot->rows.at(group.at(index.row())) : nullptr;
    }

    // 仅查询展示和悬停文字，原包数据仍由原详情文档提供。
    QVariant data(const QModelIndex& index, int role) const override
    {
        if (!index.isValid() || (role != Qt::DisplayRole && role != Qt::ToolTipRole))
        {
            return {};
        }
        if ((!index.internalId() && index.row() == 9) || index.internalId() == 200000)
        {
            if (role == Qt::ToolTipRole)
            {
                return sourceText(QStringLiteral("历史观察保留原始停点、绑定和寄存器；不授予实时控制权。"));
            }
            if (!index.internalId())
            {
                return sourceText(QStringLiteral("原生执行历史（保留 %1 / 已核验 %2）"))
                    .arg(m_snapshot->nativeExecution.observations.size()).arg(m_snapshot->nativeExecution.verifiedNativeCount);
            }
            const auto* entry = history(index); // 只取当前不可变快照中的真实观察。
            const auto* native = entry ? entry->sourceDocument.find("native") : nullptr;
            const auto* observation = native ? native->find("observation") : nullptr;
            std::string kind; // 使用归档原值区分进入尝试与完成。
            if (observation)
            {
                observation->tryGetString(kind);
            }
            return entry ? QStringLiteral("raw-native/%1 #%2 @%3 · %4")
                .arg(entry->nativeOrdinal).arg(entry->nativeSequence).arg(entry->nativeRecordOffset)
                .arg(QString::fromStdString(kind)) : QString();
        }
        if ((index.internalId() == 0 && index.row() >= 5) || index.internalId() >= 100000)
        {
            const QStringList types{QStringLiteral("线程创建"), QStringLiteral("APC 入队"),
                QStringLiteral("上下文请求"), QStringLiteral("内存范围（映射／分配／保护）")}; // 共用第四范围根，不改变旧节点编码。
            if (!index.internalId())
            {
                return sourceText(QStringLiteral("%1 → 原生执行一致性候选（%2）"))
                    .arg(sourceText(types[index.row() - 5])).arg(rowCount(index));
            }
            const auto* candidate = execution(index, m_snapshot.get()); // 当前已发布候选。
            if (!candidate)
            {
                return {};
            }
            if (role == Qt::ToolTipRole)
            {
                return sourceText(QStringLiteral("候选不证明注入、因果、区域版本或跨来源时序；进入尝试与指令完成按原记录分别呈现。"));
            }
            if (index.internalId() < 1000000)
            {
                return RelationRowText(candidate->request) + QStringLiteral(" → raw-native/%1 #%2")
                    .arg(candidate->nativeOrdinal).arg(candidate->nativeSequence);
            }
            if (const auto* row = record(index, m_snapshot.get()))
            {
                return (index.row() == 0 ? sourceText(QStringLiteral("写入：")) : sourceText(QStringLiteral("API 请求："))) + RelationRowText(*row);
            }
            if (index.row() == 0)
            {
                return sourceText(QStringLiteral("范围关联不要求写入前置条件。"));
            }
            const auto* native = candidate->sourceDocument.find("native"); // 真实原生观察，不从请求地址填补。
            const auto* observation = native ? native->find("observation") : nullptr;
            const auto* target = native ? native->find("target") : nullptr; // 实际进程代次。
            const auto* thread = native ? native->find("thread") : nullptr; // 实际执行线程代次。
            std::string kind; // 保留 execution-enter-attempt / instruction-completed 原值。
            if (observation)
            {
                observation->tryGetString(kind);
            }
            const auto number = [](const auto* object, std::string_view field) { // 已核验文档中的无损字段原值。
                const auto* value = object ? object->find(field) : nullptr;
                std::uint64_t decoded = 0; // 本字段的真实整数值。
                return value && value->tryGetU64(decoded) ? QString::number(decoded) : QStringLiteral("?");
            };
            return QStringLiteral("raw-native/%1 #%2 @%3 · %4 · PID %5/%6 · TID %7/%8 · IP %9")
                .arg(candidate->nativeOrdinal).arg(candidate->nativeSequence)
                .arg(number(&candidate->sourceDocument, "nativeRecordOffset")).arg(QString::fromStdString(kind))
                .arg(number(target, "pid")).arg(number(target, "creationFileTime"))
                .arg(number(thread, "tid")).arg(number(thread, "creationFileTime"))
                .arg(number(native, "instructionAddress"));
        }
        // 上下文三层均保留请求边界，不能把写入一致性候选解释为 contextApplied 或执行。
        if (role == Qt::ToolTipRole && ((index.internalId() == 0 && index.row() == 4) ||
            index.internalId() == 5 || (index.internalId() >= 6 && (index.internalId() - 6) % 3 == 2)))
        {
            return sourceText(QStringLiteral("IP、SP、ContextFlags 和 ABI 仅描述请求；接受请求不证明上下文已生效或发生执行。输入句柄和 CONTEXT 地址不授予对象身份。"));
        }
        // APC 根、父项和双方叶项均在提示中说明边界，写入叶项也不冒充投递或执行证据。
        if (role == Qt::ToolTipRole && ((index.internalId() == 0 && index.row() == 3) ||
            index.internalId() == 4 || (index.internalId() >= 6 && (index.internalId() - 6) % 3 == 1)))
        {
            return sourceText(QStringLiteral("接受入队不证明 APC 已投递或执行；请求例程地址不是实际执行地址。"));
        }
        if (index.internalId())
        {
            if (index.internalId() == 5)
            {
                const auto& link = m_snapshot->contextTransferCandidates[index.row()].link; // 只描述请求 IP 与先前写入区间一致。
                return sourceText(QStringLiteral("上下文来源声明候选 · PID %1 → %2 / TID %3 · 请求 IP %4"))
                    .arg(link.actorPid).arg(link.targetPid).arg(link.targetTid).arg(QString::number(link.requestedIp, 16));
            }
            if (index.internalId() == 4)
            {
                const auto& link = m_snapshot->apcTransferCandidates[index.row()].link; // 队列接受只构成来源声明。
                return sourceText(QStringLiteral("APC 来源声明候选 · PID %1 → %2 / TID %3 · 例程 %4"))
                    .arg(link.actorPid).arg(link.targetPid).arg(link.targetTid).arg(QString::number(link.requestedRoutineAddress, 16));
            }
            if (index.internalId() == 3)
            {
                const auto& link = m_snapshot->transferCandidates[index.row()].link; // 共享匹配器的区间候选。
                return sourceText(QStringLiteral("来源声明候选 · PID %1 → %2 · 入口 %3"))
                    .arg(link.actorPid).arg(link.targetPid).arg(QString::number(link.requestedStartAddress, 16));
            }
            const auto* row = record(index, m_snapshot.get()); // 叶项按当前发布的行解释。
            if (!row)
            {
                return {};
            }
            QString prefix; // 候选双方角色标签；普通原行不追加前缀。
            if (index.internalId() >= 6)
            {
                const auto kind = (index.internalId() - 6) % 3; // 当前叶项的候选类型。
                prefix = index.row() == 0 ? sourceText(QStringLiteral("写入：")) : kind == 2
                    ? sourceText(QStringLiteral("上下文请求：")) : kind == 1
                        ? sourceText(QStringLiteral("APC 入队：")) : sourceText(QStringLiteral("线程创建："));
            }
            return prefix + RelationRowText(*row);
        }
        if (index.row() == 2)
        {
            return sourceText(QStringLiteral("写入 → 线程创建候选（保留 %1 / 总计 %2；写入淘汰 %3）"))
                .arg(m_snapshot->transferCandidates.size()).arg(m_snapshot->transferCandidateCount).arg(m_snapshot->evictedTransferWrites);
        }
        if (index.row() == 3)
        {
            return sourceText(QStringLiteral("写入 → APC 入队候选（保留 %1 / 总计 %2；写入淘汰 %3）"))
                .arg(m_snapshot->apcTransferCandidates.size()).arg(m_snapshot->apcTransferCandidateCount).arg(m_snapshot->evictedTransferWrites);
        }
        if (index.row() == 4)
        {
            return sourceText(QStringLiteral("写入 → 上下文请求候选（保留 %1 / 总计 %2；写入淘汰 %3）"))
                .arg(m_snapshot->contextTransferCandidates.size()).arg(m_snapshot->contextTransferCandidateCount).arg(m_snapshot->evictedTransferWrites);
        }
        const auto count = m_groups[index.row()].size(); // 候选与上下文按其实际行数标记。
        return index.row() == 0 ? sourceText(QStringLiteral("未解析候选（%1）")).arg(count)
            : sourceText(QStringLiteral("来源上下文（%1）")).arg(count);
    }

    // 更新本地化投影时保留展开状态与当前叶项。
    void retranslate()
    {
        if (const int count = rowCount())
        {
            emit dataChanged(index(0, 0), index(count - 1, 0));
            for (int row = 0; row < count; ++row)
            {
                const auto group = index(row, 0); // 当前分组限定叶项变更范围。
                if (const int children = rowCount(group))
                {
                    emit dataChanged(index(0, 0, group), index(children - 1, 0, group));
                    if (row >= 2 && row < 9)
                    {
                        for (int candidate = 0; candidate < children; ++candidate)
                        {
                            const auto pair = index(candidate, 0, group); // 双方角色标签随语言更新。
                            emit dataChanged(index(0, 0, pair), index(rowCount(pair) - 1, 0, pair));
                        }
                    }
                }
            }
        }
    }

    // 输入独立历史叶，返回当前已发布观察；根、旧模型及越界节点均没有历史来源。
    const Ksword::Evidence::NativeExecutionHistoryEntry* history(const QModelIndex& index) const
    {
        if (!m_snapshot || index.model() != this || index.internalId() != 200000 || index.row() < 0 ||
            static_cast<std::size_t>(index.row()) >= m_snapshot->nativeExecution.observations.size())
        {
            return nullptr;
        }
        return &m_snapshot->nativeExecution.observations[static_cast<std::size_t>(index.row())];
    }

    // 输入树节点及可选快照身份，输出同一已发布候选；只遍历当前 512 条只读窗口。
    const Ksword::Evidence::ApiNativeExecutionCandidate<SegmentRow>* execution(
        const QModelIndex& index, const SegmentSnapshot* snapshot) const
    {
        if (!m_snapshot || (snapshot && snapshot != m_snapshot.get()) || index.model() != this || index.internalId() < 100000)
        {
            return nullptr;
        }
        const auto kind = index.internalId() >= 1000000 ? (index.internalId() - 1000000) % 4 : index.internalId() - 100000;
        const auto member = index.internalId() >= 1000000 ? (index.internalId() - 1000000) / 4 : static_cast<quintptr>(index.row());
        quintptr current = 0; // 当前分类中的下标，不能把不同类型的同坐标候选合并。
        for (const auto& candidate : m_snapshot->nativeExecution.candidates)
        {
            if (static_cast<quintptr>(candidate.kind) == kind && current++ == member)
            {
                return &candidate;
            }
        }
        return nullptr;
    }

    // 选择与展开使用类型、双方坐标及原生坐标；不同分支共享原包也不会互相替代。
    QString identity(const QModelIndex& index) const
    {
        if (!index.isValid())
        {
            return {};
        }
        if (!index.parent().isValid())
        {
            return QStringLiteral("root:%1").arg(index.row());
        }
        if (const auto* entry = history(index))
        {
            return QStringLiteral("history:%1:%2:%3:%4").arg(entry->nativeOrdinal).arg(entry->nativeSequence)
                .arg(entry->nativeRecordOffset).arg(QString::fromStdString(entry->nativeSha256));
        }
        if (const auto* candidate = execution(index, nullptr))
        {
            return QStringLiteral("native:%1:%2:%3:%4:%5:%6:%7:%8").arg(candidate->kind)
                .arg(candidate->write ? candidate->write->segmentOrdinal : 0).arg(candidate->write ? candidate->write->sequence : 0)
                .arg(candidate->request.segmentOrdinal).arg(candidate->request.sequence)
                .arg(candidate->nativeOrdinal).arg(candidate->nativeSequence)
                .arg(index.internalId() >= 1000000 ? index.row() : -1) +
                QStringLiteral(":%1:%2:%3:%4").arg(candidate->write ? candidate->write->offset : 0)
                    .arg(candidate->request.offset).arg(candidate->nativeRecordOffset).arg(QString::fromStdString(candidate->nativeSha256));
        }
        if (const auto* row = record(index, nullptr))
        {
            return identity(index.parent()) + QStringLiteral(":%1:%2:%3")
                .arg(static_cast<int>(row->evidenceLane)).arg(row->segmentOrdinal).arg(row->sequence);
        }
        const auto* write = record(this->index(0, 0, index), nullptr); // 原有来源候选双方。
        const auto* request = record(this->index(1, 0, index), nullptr);
        return write && request ? QStringLiteral("pair:%1:%2:%3:%4:%5").arg(index.parent().row())
            .arg(write->segmentOrdinal).arg(write->sequence).arg(request->segmentOrdinal).arg(request->sequence) : QString();
    }

private:
    // 候选拓扑未变时才能复用旧树持久索引；来源计数变化通过根文字刷新。
    bool sameCandidates(const SegmentSnapshot& next) const
    {
        if (!m_snapshot->nativeExecution.observations.empty() || !next.nativeExecution.observations.empty() ||
            !m_snapshot->nativeExecution.candidates.empty() || !next.nativeExecution.candidates.empty() ||
            m_snapshot->nativeExecution.state != next.nativeExecution.state)
        {
            return false; // 原生拓扑按完整来源键恢复，不沿用旧持久下标。
        }
        return std::ranges::equal(m_snapshot->transferCandidates, next.transferCandidates,
            [](const auto& before, const auto& after) { return before.link == after.link; }) &&
            std::ranges::equal(m_snapshot->apcTransferCandidates, next.apcTransferCandidates,
                [](const auto& before, const auto& after) { return before.link == after.link; }) &&
            std::ranges::equal(m_snapshot->contextTransferCandidates, next.contextTransferCandidates,
                [](const auto& before, const auto& after) { return before.link == after.link; }); // 各类型拓扑分别比较。
    }

    // 对同一来源比较旧后缀和新前缀。返回 false 时模型仍属于旧快照。
    bool applyPrefix(const std::shared_ptr<const SegmentSnapshot>& snapshot, const Groups& next)
    {
        const auto sameLeaf = [&](qsizetype oldOffset, qsizetype newOffset) {
            const auto& before = m_snapshot->rows.at(oldOffset); // 旧快照原包。
            const auto& after = snapshot->rows.at(newOffset); // 新快照中的候选原包。
            if (before.offset != after.offset || RowAnchor(before) != RowAnchor(after))
            {
                return false;
            }
            if (before.archivedApi && after.archivedApi)
            {
                return before.archivedApi->api == after.archivedApi->api;
            }
            // 比较上下文的显示信息，重读内容已变化时让模型重新发布旧分组。
            return RelationRowText(before) == RelationRowText(after);
        };
        std::array<qsizetype, 2> removed{}; // 每组失去的连续前缀长度。
        for (int group = 0; group < static_cast<int>(m_groups.size()); ++group)
        {
            const auto& before = m_groups[group]; // 旧快照中该组的叶项顺序。
            const auto& after = next[group]; // 新快照中该组的叶项顺序。
            const auto first = after.isEmpty() ? before.cend() : std::find_if(before.cbegin(), before.cend(),
                [&](qsizetype offset) { return sameLeaf(offset, after.front()); }); // 第一个仍存在的旧叶项。
            removed[group] = first - before.cbegin();
            if (before.cend() - first > after.size() || !std::equal(first, before.cend(), after.cbegin(), sameLeaf))
            {
                return false;
            }
        }

        // 删除信号发出时，旧叶项仍能查询旧快照。根节点在两组暂时为空时也保持有效。
        for (int group = 0; group < static_cast<int>(m_groups.size()); ++group)
        {
            if (removed[group])
            {
                const int count = static_cast<int>(removed[group]); // 快照窗口有固定上限。
                beginRemoveRows(index(group, 0), 0, count - 1);
                m_groups[group].remove(0, count);
                endRemoveRows();
            }
        }

        // 同时切换两组保留叶项的下标，保证新增信号期间只借用这份新快照。
        m_snapshot = snapshot;
        emit dataChanged(index(2, 0), index(4, 0), {Qt::DisplayRole, Qt::ToolTipRole});
        for (int group = 0; group < static_cast<int>(m_groups.size()); ++group)
        {
            auto& members = m_groups[group]; // 仍存的叶项由 Qt 持久索引保持选中。
            std::copy_n(next[group].cbegin(), members.size(), members.begin());
        }
        for (int group = 0; group < static_cast<int>(m_groups.size()); ++group)
        {
            auto& members = m_groups[group]; // 把新后缀追加到原有关系根。
            const auto parent = index(group, 0); // 现有分组根索引。
            const auto retained = members.size(); // 追加前已有的叶项数。
            if (retained < next[group].size())
            {
                beginInsertRows(parent, static_cast<int>(retained), static_cast<int>(next[group].size() - 1));
                members = next[group];
                endInsertRows();
            }
            if (removed[group] || retained != members.size())
            {
                emit dataChanged(parent, parent, {Qt::DisplayRole, Qt::ToolTipRole});
            }
        }
        return true;
    }

    std::shared_ptr<const SegmentSnapshot> m_snapshot; // 与事件表共享的已发布归档，不复制正文。
    Groups m_groups; // 根节点对应的快照行索引，按读取顺序保留。
    bool m_hasGroups = false; // 只在发布新拓扑时变动，批量增删叶项期间保持有效。
};

// 底部证据图独立于可折叠详情，每个有明确身份的对象节点使用统一菜单。
QWidget* OfflineSegmentOverview::createObjectEvidence(QWidget* parent)
{
    auto* panel = new QWidget(parent); // 已选记录的对象引用与查看回执。
    ks::ui::StylePrimaryContentPanel(panel, false);
    auto* layout = new QVBoxLayout(panel); // 共享内容面内的紧凑证据区。
    layout->setContentsMargins(8, 8, 8, 8);
    m_objectStatus = new QLabel(panel);
    m_objectStatus->setTextFormat(Qt::PlainText);
    m_objectStatus->setWordWrap(true);
    m_objectStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
    ObjectMenuCallbacks callbacks; // 图节点统一使用这些只读证据动作。
    callbacks.capabilities = [this](const ObjectMenuRef& ref) {
        ObjectMenuCapabilities state; // Dump 保持未解析，等待已验证的归档诊断目录。
        const bool current = matchesSample(FromMenu(ref)); // 菜单阅读时只查询当前快照。
        state.viewEvidence.available = current;
        state.filterByObject.available = current;
        return state;
    };
    callbacks.viewEvidence = [this](const ObjectMenuRef& ref) {
        const auto object = FromMenu(ref); // 菜单可以在排队执行前失去当前来源。
        if (matchesSample(object))
        {
            m_viewedObject = object;
            updateDetails();
        }
    };
    callbacks.filterByObject = [this](const ObjectMenuRef& ref) {
        const auto object = FromMenu(ref); // 身份由菜单打开时冻结。
        if (matchesSample(object))
        {
            m_objectFilter = object;
            applyFilters();
        }
    };
    auto* menu = new ObjectContextMenu(panel, std::move(callbacks)); // 唯一菜单处理器。
    m_objects = new OfflineObjectEvidence(panel, menu);
    // 保留面板入口，让未选事件与无关系记录都有明确空态。
    layout->addWidget(m_objects);
    layout->addWidget(m_objectStatus);

    // 独立展开关系列表。原图、对象菜单和原图的窄窗换行继续由原控件负责。
    m_archiveRelationToggle = new QToolButton(panel);
    m_archiveRelationToggle->setObjectName(QStringLiteral("aa_archive_relation_toggle"));
    m_archiveRelationToggle->setCheckable(true);
    m_archiveRelationToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_archiveRelationToggle->setArrowType(Qt::RightArrow);
    ks::ui::NormalizeToolbarControl(m_archiveRelationToggle);
    layout->addWidget(m_archiveRelationToggle, 0, Qt::AlignLeft);
    m_archiveRelationToggle->hide();

    // 与底部面板等宽，树视口独立滚动，不把全部分组行加入页面高度。
    m_archiveRelationPanel = new QWidget(panel);
    auto* relationLayout = new QVBoxLayout(m_archiveRelationPanel); // 复用外侧证据面的留白。
    relationLayout->setContentsMargins(0, 0, 0, 0);
    m_archiveRelationStatus = new QLabel(m_archiveRelationPanel);
    m_archiveRelationStatus->setTextFormat(Qt::PlainText);
    m_archiveRelationStatus->setWordWrap(true);
    relationLayout->addWidget(m_archiveRelationStatus);

    m_archiveRelationTree = new QTreeView(m_archiveRelationPanel);
    m_archiveRelationTree->setObjectName(QStringLiteral("aa_archive_relation_tree"));
    m_archiveRelationTree->setProperty("ks_i18n_preserve_model_data", true);
    m_archiveRelationTree->setProperty(ks::ui::TableActionBarModeProperty,
        static_cast<int>(ks::ui::TableActionBarMode::None));
    m_archiveRelationModel = new ArchiveRelationModel(m_archiveRelationTree);
    m_archiveRelationTree->setModel(m_archiveRelationModel);
    m_archiveRelationTree->setHeaderHidden(true);
    m_archiveRelationTree->header()->setSectionResizeMode(QHeaderView::Stretch);
    m_archiveRelationTree->setUniformRowHeights(true);
    m_archiveRelationTree->setAlternatingRowColors(true);
    m_archiveRelationTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_archiveRelationTree->setExpandsOnDoubleClick(false);
    m_archiveRelationTree->setMinimumWidth(0);
    m_archiveRelationTree->setMaximumHeight(m_archiveRelationTree->fontMetrics().lineSpacing() * 7);
    ks::ui::SetTableColumnAutoFitEnabled(m_archiveRelationTree, false);
    ks::ui::SetTablePresentationDensity(m_archiveRelationTree, ks::ui::TablePresentationDensity::Compact);
    ks::ui::ApplyTablePresentation(m_archiveRelationTree);
    relationLayout->addWidget(m_archiveRelationTree);
    layout->addWidget(m_archiveRelationPanel);
    m_archiveRelationPanel->hide();

    // Qt 原生方向键浏览。双击或 Enter 激活叶项，分组自身只改变展开状态。
    connect(m_archiveRelationToggle, &QToolButton::toggled, this, [this](bool expanded) {
        m_archiveRelationToggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
        m_archiveRelationPanel->setVisible(expanded);
    });
    connect(m_archiveRelationTree, &QTreeView::activated, this, [this](const QModelIndex& index) {
        if (const auto* entry = m_archiveRelationModel->history(index))
        {
            selectNativeHistory(*entry);
        }
        else if (index.internalId() >= 1000000 && index.row() == 2)
        {
            if (const auto* candidate = m_archiveRelationModel->execution(index, m_snapshot.get()))
            {
                selectNativeExecution(*candidate);
            }
        }
        else if (const auto* row = m_archiveRelationModel->record(index, m_snapshot.get()))
        {
            selectRecord(RowAnchor(*row), true); // 复用表、瀑布和详情的稳定定位，保留显示筛选。
        }
        else if (m_archiveRelationModel->hasChildren(index))
        {
            m_archiveRelationTree->setExpanded(index, !m_archiveRelationTree->isExpanded(index));
        }
    });
    connect(m_archiveRelationTree->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex& index) {
            if (const auto* entry = m_archiveRelationModel->history(index))
            {
                selectNativeHistory(*entry);
            }
            else if (index.internalId() >= 1000000 && index.row() == 2)
            {
                if (const auto* candidate = m_archiveRelationModel->execution(index, m_snapshot.get()))
                {
                    selectNativeExecution(*candidate);
                }
            }
        });
    retranslateArchiveRelations();
    return panel;
}

// 归档读取成功后更新关系树，切换采样时清除旧叶项。
void OfflineSegmentOverview::updateArchiveRelations(bool sameScope)
{
    const QSignalBlocker selectionGuard(m_archiveRelationTree->selectionModel()); // 发布恢复不等同用户选择，避免中途切换详情。
    std::optional<SegmentRowAnchor> selected; // 模型重置时按真实原包保留树选择。
    std::optional<std::pair<SegmentRowAnchor, SegmentRowAnchor>> selectedCandidate; // 重叠候选需双方坐标区分所在分支。
    int selectedGroup = -1; // 普通叶项恢复到原分类，候选叶项不跳到同坐标的普通行。
    bool selectedRoot = false; // 分类根的键盘选择也在模型重置后保留。
    std::array<bool, 10> expanded{}; // 原有候选与独立历史分别恢复。
    QString selectedNativeKey; // 完整分支来源键，不将原生坐标误作 API 坐标。
    QSet<QString> expandedNativeKeys; // 新旧模型之间不保存节点地址或 QModelIndex。
    std::array<QList<std::pair<SegmentRowAnchor, SegmentRowAnchor>>, 3> expandedCandidates; // 类型及双方坐标共同区分候选。
    if (sameScope)
    {
        const auto current = m_archiveRelationTree->currentIndex(); // 旧树的选择仍由旧快照解释。
        if (current.internalId() >= 100000)
        {
            selectedNativeKey = m_archiveRelationModel->identity(current);
        }
        for (int kind = 0; kind < 4; ++kind)
        {
            const auto root = m_archiveRelationModel->index(kind + 5, 0); // 四类执行候选根。
            for (int member = 0; member < m_archiveRelationModel->rowCount(root); ++member)
            {
                const auto node = m_archiveRelationModel->index(member, 0, root); // 当前执行候选分支。
                if (m_archiveRelationTree->isExpanded(node))
                {
                    expandedNativeKeys.insert(m_archiveRelationModel->identity(node));
                }
            }
        }
        if (const auto* row = m_archiveRelationModel->record(current, nullptr))
        {
            selected = RowAnchor(*row);
            const auto parent = current.parent(); // 普通叶项的分类根，或候选叶项的候选父项。
            selectedGroup = parent.parent().isValid() ? parent.parent().row() : parent.row();
            if (selectedGroup >= 2)
            {
                const auto* write = m_archiveRelationModel->record(m_archiveRelationModel->index(0, 0, parent), nullptr);
                const auto* create = m_archiveRelationModel->record(m_archiveRelationModel->index(1, 0, parent), nullptr);
                if (write && create)
                {
                    selectedCandidate = std::pair{RowAnchor(*write), RowAnchor(*create)};
                }
            }
        }
        else if (current.isValid())
        {
            selectedRoot = !current.parent().isValid();
            selectedGroup = selectedRoot ? current.row() : current.parent().row();
            if (!selectedRoot && selectedGroup >= 2)
            {
                const auto* write = m_archiveRelationModel->record(m_archiveRelationModel->index(0, 0, current), nullptr);
                const auto* create = m_archiveRelationModel->record(m_archiveRelationModel->index(1, 0, current), nullptr);
                if (write && create)
                {
                    selectedCandidate = std::pair{RowAnchor(*write), RowAnchor(*create)};
                }
            }
        }
        for (int group = 0; group < m_archiveRelationModel->rowCount(); ++group)
        {
            expanded[group] = m_archiveRelationTree->isExpanded(m_archiveRelationModel->index(group, 0));
        }
        for (int kind = 0; kind < 3; ++kind) // kind 分别保存创建/APC/上下文，避免相同写入跨组跳转。
        {
            const auto root = m_archiveRelationModel->index(kind + 2, 0); // 旧模型持有自身不可变快照。
            for (int member = 0; member < m_archiveRelationModel->rowCount(root); ++member)
            {
                const auto pair = m_archiveRelationModel->index(member, 0, root); // 当前候选父项。
                const auto* write = m_archiveRelationModel->record(m_archiveRelationModel->index(0, 0, pair), nullptr); // 写入原行。
                const auto* request = m_archiveRelationModel->record(m_archiveRelationModel->index(1, 0, pair), nullptr); // 创建或入队原行。
                if (write && request && m_archiveRelationTree->isExpanded(pair))
                {
                    expandedCandidates[kind].append({RowAnchor(*write), RowAnchor(*request)});
                }
            }
        }
    }
    const bool archive = m_snapshot && !m_snapshot->live; // 仅已发布文件快照可以浏览关系。
    m_archiveRelationModel->setSnapshot(archive ? m_snapshot : nullptr, sameScope);
    m_archiveRelationToggle->setVisible(archive);
    if (!archive)
    {
        m_archiveRelationToggle->setChecked(false);
    }
    m_archiveRelationTree->setVisible(archive && m_archiveRelationModel->rowCount() > 0);
    for (int group = 0; group < m_archiveRelationModel->rowCount(); ++group)
    {
        m_archiveRelationTree->setExpanded(m_archiveRelationModel->index(group, 0), sameScope && expanded[group]);
    }
    for (int kind = 0; kind < 3; ++kind) // kind 与双方坐标及叶项角色共同恢复旧分支。
    {
        const auto candidateRoot = m_archiveRelationModel->index(kind + 2, 0); // 新模型对应类型的候选根。
        for (int member = 0; member < m_archiveRelationModel->rowCount(candidateRoot); ++member)
        {
            const auto pair = m_archiveRelationModel->index(member, 0, candidateRoot); // 候选父项。
            const auto* write = m_archiveRelationModel->record(m_archiveRelationModel->index(0, 0, pair), m_snapshot.get()); // 写入原行。
            const auto* request = m_archiveRelationModel->record(m_archiveRelationModel->index(1, 0, pair), m_snapshot.get()); // 请求原行。
            if (write && request && expandedCandidates[kind].contains({RowAnchor(*write), RowAnchor(*request)}))
            {
                m_archiveRelationTree->setExpanded(pair, true);
            }
            if (!selected && selectedCandidate && selectedGroup == kind + 2 && write && request &&
                *selectedCandidate == std::pair{RowAnchor(*write), RowAnchor(*request)})
            {
                m_archiveRelationTree->setCurrentIndex(pair);
            }
        }
    }
    if (selectedRoot)
    {
        m_archiveRelationTree->setCurrentIndex(m_archiveRelationModel->index(selectedGroup, 0));
    }
    for (int kind = 0; kind < 4; ++kind)
    {
        const auto root = m_archiveRelationModel->index(kind + 5, 0); // 新模型只使用已发布候选。
        for (int member = 0; member < m_archiveRelationModel->rowCount(root); ++member)
        {
            const auto node = m_archiveRelationModel->index(member, 0, root); // 与双方及 native 坐标共同匹配。
            m_archiveRelationTree->setExpanded(node, expandedNativeKeys.contains(m_archiveRelationModel->identity(node)));
            for (int side = -1; side < 3; ++side)
            {
                const auto leaf = side < 0 ? node : m_archiveRelationModel->index(side, 0, node); // 父项与三个角色独立选择。
                if (!selectedNativeKey.isEmpty() && selectedNativeKey == m_archiveRelationModel->identity(leaf))
                {
                    m_archiveRelationTree->setCurrentIndex(leaf);
                }
            }
        }
    }
    if (!sameScope)
    {
        m_nativeSelection.reset(); // 新采样不能继承任何旧原生历史文档。
        m_nativeHistorySelection.reset();
    }
    const auto historyRoot = m_archiveRelationModel->index(9, 0); // 历史叶按原物理来源恢复，不按列表位置恢复。
    for (int member = 0; member < m_archiveRelationModel->rowCount(historyRoot); ++member)
    {
        const auto leaf = m_archiveRelationModel->index(member, 0, historyRoot); // 新快照的历史叶。
        if (!selectedNativeKey.isEmpty() && selectedNativeKey == m_archiveRelationModel->identity(leaf))
        {
            m_archiveRelationTree->setCurrentIndex(leaf);
        }
    }
    if (selected && selectedNativeKey.isEmpty())
    {
        // 仅遍历 256 对创建、各 128 对 APC/上下文及近期行索引，不进行归档 I/O。
        for (int group = 0; group < m_archiveRelationModel->rowCount(); ++group)
        {
            if (group != selectedGroup)
            {
                continue;
            }
            const auto root = m_archiveRelationModel->index(group, 0); // 稳定的关系分类根。
            for (int member = 0; member < m_archiveRelationModel->rowCount(root); ++member)
            {
                const auto node = m_archiveRelationModel->index(member, 0, root); // 普通原包或候选对。
                const int count = m_archiveRelationModel->rowCount(node); // 候选有两个原包子项。
                if (selectedCandidate)
                {
                    const auto* write = m_archiveRelationModel->record(m_archiveRelationModel->index(0, 0, node), m_snapshot.get());
                    const auto* create = m_archiveRelationModel->record(m_archiveRelationModel->index(1, 0, node), m_snapshot.get());
                    if (!write || !create || *selectedCandidate != std::pair{RowAnchor(*write), RowAnchor(*create)})
                    {
                        continue;
                    }
                }
                for (int side = -1; side < count; ++side)
                {
                    const auto leaf = side < 0 ? node : m_archiveRelationModel->index(side, 0, node); // 实际可定位节点。
                    const auto* row = m_archiveRelationModel->record(leaf, m_snapshot.get()); // 新快照中的原始行。
                    if (row && RowAnchor(*row) == *selected)
                    {
                        m_archiveRelationTree->setCurrentIndex(leaf);
                    }
                }
            }
        }
    }
}

// 更新归档操作及树项文案，保持当前采样、节点与展开状态。
void OfflineSegmentOverview::retranslateArchiveRelations()
{
    if (!m_archiveRelationToggle)
    {
        return;
    }
    const auto title = sourceText(QStringLiteral("归档关系")); // 展开按钮与树共享的无障碍入口名称。
    m_archiveRelationToggle->setText(title);
    m_archiveRelationToggle->setToolTip(sourceText(QStringLiteral("展开或收起当前归档窗口中的候选与来源上下文。")));
    m_archiveRelationTree->setAccessibleName(title);
    m_archiveRelationTree->setAccessibleDescription(sourceText(QStringLiteral("双击或按 Enter 定位原始行。")));
    m_archiveRelationModel->retranslate();
}

// 将当前已核验的表行投影成归档图。空行转换成同一工作台的空态。
void OfflineSegmentOverview::updateObjectEvidence(const SegmentRow* row, bool filteredOut)
{
    EvidenceGraphSnapshot graph; // 归档与实时使用相同接口，默认来源为归档。
    if (m_snapshot && m_snapshot->live)
    {
        graph.source = EvidenceGraphSource::Live;
    }
    if (m_snapshot && row)
    {
        const QUuid project(m_snapshot->projectId); // 已校验段头中的项目身份。
        const QUuid sample(m_snapshot->sampleId); // 已校验段头中的采样身份。
        graph.event = EvidenceGraphEvent{project, sample, row->ordinal, m_snapshot->live
            ? std::nullopt : std::optional<quint64>(row->sequence)};
        // 只使用回放器已经分类的原始记录。来源报头和 PID 不参与对象推断。
        if (!m_snapshot->live)
        {
            graph.archivedRelation = RelationAnchor(*row);
        }
        if (row->network)
        {
            graph.associatedProcessId = row->network->flow.observation.processObjectId;
        }
        else if (!row->archivedCallback)
        {
            // 规范事件里的执行者、目标及观测线程是独立引用。
            graph.actorProcessId = row->actorId;
            graph.targetProcessId = row->targetId;
            graph.observedThreadId = row->threadId;
        }
    }

    m_objects->setEvidence(graph);
    if (m_snapshot && !m_snapshot->live)
    {
        if (!m_archiveRelationModel->rowCount())
        {
            m_archiveRelationStatus->setText(sourceText(QStringLiteral("当前归档窗口没有候选或来源上下文。")));
        }
        else if (filteredOut && graph.archivedRelation)
        {
            m_archiveRelationStatus->setText(sourceText(QStringLiteral("当前筛选隐藏了所选原始行，仍可查看详情。")));
        }
        else
        {
            m_archiveRelationStatus->setText(sourceText(QStringLiteral("双击或按 Enter 定位原始行。")) + u' ' +
                sourceText(QStringLiteral("写入与线程创建仅为来源声明候选，不证明实际执行或强归因。")));
        }
        const auto nativeStatus = NativeExecutionStatus(m_snapshot->nativeExecution); // 与 API 状态分别显示。
        if (!nativeStatus.isEmpty())
        {
            m_archiveRelationStatus->setText(m_archiveRelationStatus->text() + u' ' + nativeStatus);
        }
    }
    const bool viewing = m_viewedObject && matchesSample(*m_viewedObject); // 显式查看的对象身份。
    m_objectStatus->setVisible(viewing);
    if (viewing)
    {
        qsizetype references = 0; // 归档预览内直接引用该对象的记录数。
        for (const auto& record : m_snapshot->rows)
        {
            references += RowReferencesObject(record, *m_viewedObject) ? 1 : 0;
        }
        m_objectStatus->setText(sourceText(QStringLiteral("%1 · 采样 %2 · 预览中有 %3 条记录引用此对象。"))
            .arg(ObjectScopeText(*m_viewedObject), m_snapshot->sampleId, QString::number(references)));
    }
}

// 菜单打开后切换归档时，旧范围不能作用于另一个项目或采样。
bool OfflineSegmentOverview::matchesSample(const ArchivedObjectObservation& object) const
{
    return m_snapshot && !object.projectId.isNull() && !object.sampleId.isNull() && object.id &&
        QUuid(m_snapshot->projectId) == object.projectId && QUuid(m_snapshot->sampleId) == object.sampleId;
}

// 显示实际生效的样本内对象范围，清除筛选可恢复全部对象。
QString OfflineSegmentOverview::objectFilterSummary() const
{
    return m_objectFilter ? ObjectScopeText(*m_objectFilter) : QString();
}
}
