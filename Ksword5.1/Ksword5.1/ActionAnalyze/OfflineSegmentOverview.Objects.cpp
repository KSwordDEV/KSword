#include "OfflineSegmentOverview.h"
#include "ObjectContextMenu.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/PrimaryPageStyle.h"

#include <QLabel>
#include <QVBoxLayout>
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
}

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
    return panel;
}

// 将当前已核验的表行投影成归档图。空行转换成同一工作台的空态。
void OfflineSegmentOverview::updateObjectEvidence(const SegmentRow* row)
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
        if (row->network)
        {
            graph.associatedProcessId = row->network->flow.observation.processObjectId;
        }
        else
        {
            // 规范事件里的执行者、目标及观测线程是独立引用。
            graph.actorProcessId = row->actorId;
            graph.targetProcessId = row->targetId;
            graph.observedThreadId = row->threadId;
        }
    }

    m_objects->setEvidence(graph);
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
