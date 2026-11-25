#include "OfflineObjectEvidence.h"
#include "ObjectContextMenu.h"
#include "OfflineSegmentReader.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/MainSurfaceStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../theme.h"

#include <QBoxLayout>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QLabel>
#include <QPainter>
#include <QPushButton>
#include <QStringList>
#include <algorithm>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;

    enum Role : unsigned { Actor = 1, Target = 2, Thread = 4, Associated = 8 }; // 每一位对应一个明确的来源字段。
    constexpr int kEdgeGutter = 16; // 窄布局留给竖向连线的间距。

    // 把节点的所有证据角色转为同一标签，保留重复对象的多个角色。
    QString RoleText(unsigned roles)
    {
        QStringList labels; // 按事件字段顺序排列角色。
        if (roles & Actor)
        {
            labels.append(sourceText(QStringLiteral("执行方")));
        }
        if (roles & Target)
        {
            labels.append(sourceText(QStringLiteral("目标")));
        }
        if (roles & Thread)
        {
            labels.append(sourceText(QStringLiteral("观测线程")));
        }
        if (roles & Associated)
        {
            labels.append(sourceText(QStringLiteral("关联进程")));
        }
        return labels.join(QStringLiteral(" / "));
    }

    // 标签展示来源和已知编号，零值与不可用字段分别保留。
    QString EventText(const EvidenceGraphSnapshot& snapshot)
    {
        QStringList parts; // 第一项说明当前节点的来源。
        parts.append(snapshot.source == EvidenceGraphSource::Live ? sourceText(QStringLiteral("实时事件")) :
            sourceText(QStringLiteral("归档事件")));
        const auto& event = *snapshot.event; // 仅在已选事件时调用。
        if (event.eventOrdinal)
        {
            parts.append(sourceText(QStringLiteral("事件序号 %1")).arg(*event.eventOrdinal));
        }
        if (event.recordSequence)
        {
            parts.append(sourceText(QStringLiteral("归档记录序号 %1")).arg(*event.recordSequence));
        }
        return parts.join(QStringLiteral(" · "));
    }
}

// 输入是相同项目、采样下的已核验行和对象引用；仅匹配同类型的正文编号。
bool RowReferencesObject(const SegmentRow& row, const ArchivedObjectObservation& object)
{
    if (!object.id)
    {
        return false;
    }
    if (object.kind == ArchivedObjectKind::Process)
    {
        return row.actorId == object.id || row.targetId == object.id;
    }
    return row.threadId == object.id;
}

// 使用同一套布局承载事件、可聚焦的对象按钮及实际关系。
OfflineObjectEvidence::OfflineObjectEvidence(QWidget* owner, ObjectContextMenu* menu)
    : QWidget(owner), m_menu(menu)
{
    auto* layout = new QVBoxLayout(this); // 外层面板拥有留白，图仅保留连线所需间隔。
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);
    m_eventLabel = new QLabel(this);
    m_eventLabel->setAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
    m_eventLabel->setTextFormat(Qt::PlainText);
    m_eventLabel->setWordWrap(true);
    ks::ui::StylePrimarySectionTitle(m_eventLabel);
    layout->addWidget(m_eventLabel);

    // 同一按钮跨窄宽布局保留对象身份与键盘焦点。
    m_nodeLayout = new QHBoxLayout;
    m_nodeLayout->setSpacing(6);
    layout->addLayout(m_nodeLayout);
    m_stateLabel = new QLabel(this);
    m_stateLabel->setWordWrap(true);
    m_stateLabel->setTextFormat(Qt::PlainText);
    layout->addWidget(m_stateLabel);
    updateText();
}

// 提交选中事件及其受支持的对象引用。通过对象身份复用现有按钮。
void OfflineObjectEvidence::setEvidence(const EvidenceGraphSnapshot& snapshot)
{
    if (m_snapshot == snapshot)
    {
        return;
    }
    // 源切换时不同语义的菜单由当前工作台重新判断资格。
    const bool sameSource = m_snapshot.source == snapshot.source; // 仅在相同来源内复用焦点对象。
    m_snapshot = snapshot;
    auto previous = std::exchange(m_nodes, {}); // 旧节点用于恢复同一个对象的按钮。

    // 仅将已声明的非零字段转为事件引用边。同一编号的进程与线程不合并。
    const auto add = [&](ArchivedObjectKind kind, std::optional<quint64> id, Role role) {
        if (!id || !*id)
        {
            return;
        }
        const auto& event = *m_snapshot.event; // 调用前已确定完整的采样范围。
        const ArchivedObjectObservation object{event.projectId, event.sampleId, kind, *id}; // 冻结稳定身份。
        const auto node = std::find_if(m_nodes.begin(), m_nodes.end(), [&](const Node& candidate) {
            return candidate.object == object;
        }); // 检查本次事件是否已包含该对象。
        if (node != m_nodes.end())
        {
            node->roles |= role;
            return;
        }

        const auto existing = std::find_if(previous.begin(), previous.end(), [&](const Node& candidate) {
            return sameSource && candidate.object == object;
        }); // 复用前后快照中都存在的对象按钮。
        QPushButton* button = nullptr; // 新建或按身份复用的菜单入口。
        if (existing != previous.end())
        {
            button = existing->button;
            previous.erase(existing);
            m_nodeLayout->removeWidget(button);
        }
        else
        {
            button = new QPushButton(this);
            button->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
            button->installEventFilter(this);
            // 点击和 Enter 都使用共享菜单。事件过滤器负责原生右键与方向键。
            connect(button, &QPushButton::clicked, this, [this, button, object]() {
                showObjectMenu(button->mapToGlobal(button->rect().bottomLeft()), object);
            });
        }
        m_nodes.append(Node{object, role, button});
        m_nodeLayout->addWidget(button, 1);
        button->show();
    };
    // 明确引用只从同一事件投影获得，源头 PID/TID 不参与构图。
    if (m_snapshot.event && !m_snapshot.event->projectId.isNull() && !m_snapshot.event->sampleId.isNull())
    {
        add(ArchivedObjectKind::Process, m_snapshot.actorProcessId, Actor);
        add(ArchivedObjectKind::Process, m_snapshot.targetProcessId, Target);
        add(ArchivedObjectKind::Thread, m_snapshot.observedThreadId, Thread);
        add(ArchivedObjectKind::Process, m_snapshot.associatedProcessId, Associated);
    }
    for (const auto& stale : previous) // 移除不属于当前事件的对象按钮。
    {
        m_nodeLayout->removeWidget(stale.button);
        stale.button->hide();
        stale.button->deleteLater();
    }
    for (qsizetype index = 1; index < m_nodes.size(); ++index) // 对应图上的先后顺序。
    {
        setTabOrder(m_nodes.at(index - 1).button, m_nodes.at(index).button);
    }
    layoutNodes();
    updateText();
}

// 把角色标签和真实对象 ID 提供给原生无障碍及提示，窄窗缩短显示文字。
void OfflineObjectEvidence::updateText()
{
    setAccessibleName(sourceText(QStringLiteral("对象证据图")));
    m_eventLabel->setVisible(m_snapshot.event.has_value());
    if (m_snapshot.event)
    {
        m_eventLabel->setText(EventText(m_snapshot));
    }
    // 空态区分未选事件和该事件没有受支持的关系。
    m_stateLabel->setVisible(m_nodes.isEmpty());
    if (!m_snapshot.event)
    {
        m_stateLabel->setText(sourceText(QStringLiteral("选择事件以查看对象关系。")));
    }
    else if (m_nodes.isEmpty())
    {
        m_stateLabel->setText(sourceText(QStringLiteral("此事件没有可用的对象引用。")));
    }

    const int spacing = m_nodeLayout->spacing(); // 节点之间留给边的画布宽度。
    const int count = static_cast<int>(m_nodes.size()); // 每个角色至多一个对象。
    const int nodeWidth = m_vertical ? width() - kEdgeGutter :
        (width() - spacing * std::max(0, count - 1)) / std::max(1, count); // 预计节点宽度。
    for (const auto& node : m_nodes)
    {
        const auto kind = node.object.kind == ArchivedObjectKind::Process ? sourceText(QStringLiteral("进程")) :
            sourceText(QStringLiteral("线程")); // 对象编号空间也在节点中可见。
        const auto title = QStringLiteral("%1 · %2 #%3").arg(RoleText(node.roles), kind, QString::number(node.object.id)); // 完整节点身份。
        node.button->setAccessibleName(title);
        node.button->setToolTip(title + u'\n' + sourceText(QStringLiteral("右键或菜单键可查看、筛选或复制同采样对象引用。")));
        node.button->setText(node.button->fontMetrics().elidedText(title, Qt::ElideRight, std::max(0, nodeWidth - 24)));
    }
    update();
}

// 保持原生按钮布局可伸缩。窄窗通过纵向连线留出角色和对象编号的宽度。
void OfflineObjectEvidence::layoutNodes()
{
    const int minNodeWidth = fontMetrics().horizontalAdvance(QStringLiteral("00000000000000000000")) + 36; // 可读节点的宽度基准。
    m_vertical = m_nodes.size() > 1 && width() < m_nodes.size() * minNodeWidth;
    m_nodeLayout->setDirection(m_vertical ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
    m_nodeLayout->setContentsMargins(m_vertical ? kEdgeGutter : 0, 0, 0, 0);
}

// 画载于事件上的引用边。整幅图没有对象间连线，也没有方向箭头。
void OfflineObjectEvidence::paintEvent(QPaintEvent* event)
{
    QWidget::paintEvent(event);
    if (m_nodes.isEmpty())
    {
        return;
    }
    QPainter painter(this); // 使用当前内容面的动态主题颜色绘制连线。
    const auto surface = ks::ui::MainControlSurfaceColor(KswordTheme::SurfaceColor(), this); // 用实际内容面校准线条对比度。
    painter.setPen(QPen(KswordTheme::EnsureTextContrast(KswordTheme::BorderStrongColor(), surface, 3.0), 1));
    const auto eventBox = m_eventLabel->geometry(); // 以事件标签底边为所有关系的起点。
    const QPoint origin(eventBox.center().x(), eventBox.bottom()); // 事件锚点。
    const int junction = (origin.y() + m_nodes.front().button->geometry().top()) / 2; // 首行上方的分支高度。
    painter.drawLine(origin, QPoint(origin.x(), junction));

    // 每个对象按钮提供一条独立分支。竖排沿左侧留白绘制。
    for (const auto& node : m_nodes)
    {
        const QRect box = node.button->geometry(); // 和鼠标命中的实际按钮共用几何。
        if (m_vertical)
        {
            const int spine = kEdgeGutter / 2; // 所有窄布局分支的竖向通道。
            const QPoint points[]{{origin.x(), junction}, {spine, junction}, {spine, box.center().y()},
                {box.left(), box.center().y()}};
            painter.drawPolyline(points, 4);
        }
        else
        {
            const QPoint points[]{{origin.x(), junction}, {box.center().x(), junction}, {box.center().x(), box.top()}};
            painter.drawPolyline(points, 3);
        }
    }
}

// 读取子按钮的上下文事件或方向键。未处理的事件继续走 QPushButton。
bool OfflineObjectEvidence::eventFilter(QObject* watched, QEvent* event)
{
    const auto node = std::find_if(m_nodes.cbegin(), m_nodes.cend(), [watched](const Node& candidate) {
        return candidate.button == watched;
    }); // 确定焦点或鼠标命中的图节点。
    if (node == m_nodes.cend())
    {
        return QWidget::eventFilter(watched, event);
    }
    if (event->type() == QEvent::ContextMenu)
    {
        auto* context = static_cast<QContextMenuEvent*>(event); // Qt 转交的鼠标或键盘菜单请求。
        const auto anchor = context->reason() == QContextMenuEvent::Keyboard ?
            node->button->mapToGlobal(node->button->rect().bottomLeft()) : context->globalPos(); // 保留对应输入设备的锚点。
        if (showObjectMenu(anchor, node->object))
        {
            context->accept();
            return true;
        }
    }
    else if (event->type() == QEvent::KeyPress)
    {
        const auto* key = static_cast<QKeyEvent*>(event); // 原生焦点节点收到的键事件。
        const bool menuKey = key->key() == Qt::Key_Menu ||
            (key->key() == Qt::Key_F10 && key->modifiers() == Qt::ShiftModifier); // 菜单键的原生等价操作。
        if (menuKey || key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter)
        {
            const auto anchor = node->button->mapToGlobal(node->button->rect().bottomLeft()); // 焦点节点的菜单锚点。
            if (!key->isAutoRepeat())
            {
                showObjectMenu(anchor, node->object);
            }
            event->accept();
            return true;
        }
        const auto current = node - m_nodes.cbegin(); // 当前角色顺序索引。
        auto next = current; // 循环移动焦点时的下一对象索引。
        switch (key->key())
        {
        case Qt::Key_Left:
        case Qt::Key_Up:
            next = (current + m_nodes.size() - 1) % m_nodes.size();
            break;
        case Qt::Key_Right:
        case Qt::Key_Down:
            next = (current + 1) % m_nodes.size();
            break;
        case Qt::Key_Home:
            next = 0;
            break;
        case Qt::Key_End:
            next = m_nodes.size() - 1;
            break;
        default:
            return QWidget::eventFilter(watched, event);
        }
        m_nodes.at(next).button->setFocus(Qt::TabFocusReason);
        event->accept();
        return true;
    }
    return QWidget::eventFilter(watched, event);
}

// 把当前节点的冻结引用交给统一菜单控制器并返回是否显示。
bool OfflineObjectEvidence::showObjectMenu(const QPoint& globalPosition, const ArchivedObjectObservation& object)
{
    const auto kind = object.kind == ArchivedObjectKind::Process ? ObjectMenuKind::Process :
        ObjectMenuKind::Thread; // 菜单复核的对象种类。
    return m_menu->popup(globalPosition, {{object.projectId, object.sampleId}, kind, object.id});
}

// 重新排布后按实际宽度更新文字，复用对象按钮和证据身份。
void OfflineObjectEvidence::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    layoutNodes();
    updateText();
}

// 语言或字体变化时更新布局与文本，调色变化由绘图时直接读取。
void OfflineObjectEvidence::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange || event->type() == QEvent::FontChange)
    {
        layoutNodes();
        updateText();
    }
}
}
