#include "OfflineSegmentOverview.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ThemeAccentIcon.h"
#include "../theme.h"

#include <QDialog>
#include <QPushButton>
#include <QScreen>
#include <QVBoxLayout>

namespace ks::action_analyze
{
using ks::i18n::sourceText;

// 创建总览的停靠位置并返回给页面布局。浮出时只移动已有按钮所在的控件。
QWidget* OfflineSegmentOverview::createActionToolbar()
{
    m_actionDock = new QWidget(this);
    auto* dockLayout = new QVBoxLayout(m_actionDock); // 内嵌位置的布局，由动作带负责内部留白。
    dockLayout->setContentsMargins(0, 0, 0, 0);
    m_actionStrip = new QWidget(m_actionDock);
    m_actionStrip->setObjectName(QStringLiteral("action_analyze_action_strip"));
    ks::ui::StylePrimaryToolbar(m_actionStrip);
    new ks::ui::FlowLayout(m_actionStrip, 8, 8, 6); // 两个宿主使用同一个自适应布局。
    dockLayout->addWidget(m_actionStrip);

    // 图钉浮出工具条。浮窗关闭和同一按钮都可以将动作带停回原位。
    m_floatActions = new QPushButton(m_actionStrip);
    m_floatActions->setObjectName(QStringLiteral("action_analyze_float_actions"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_floatActions);
    ks::ui::SetThemeButtonIcon(m_floatActions, QIcon(QStringLiteral(":/Icon/titlebar_pin_line.svg")));
    connect(m_floatActions, &QPushButton::clicked, this, &OfflineSegmentOverview::toggleActionToolbar);
    return m_actionDock;
}

// 在内嵌工具带和原生置顶窗口之间切换。标题栏由 Windows 执行拖动和缩放换屏。
void OfflineSegmentOverview::toggleActionToolbar()
{
    if (m_actionStrip->parentWidget() == m_actionWindow)
    {
        m_actionWindow->reject();
        return;
    }
    const bool first = !m_actionWindow; // 第一次浮出从停靠位置定位，以后沿用最后的窗口位置。
    if (first)
    {
        m_actionWindow = new QDialog(this, Qt::Tool | Qt::WindowStaysOnTopHint
            | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
        m_actionWindow->setObjectName(QStringLiteral("action_analyze_floating_toolbar"));
        m_actionWindow->setAttribute(Qt::WA_QuitOnClose, false);
        auto* toolLayout = new QVBoxLayout(m_actionWindow); // 普通弹窗主题提供不透明底板。
        toolLayout->setContentsMargins(6, 6, 6, 6);
        toolLayout->setSizeConstraint(QLayout::SetFixedSize);
        connect(m_actionWindow, &QDialog::finished, this, &OfflineSegmentOverview::restoreActionToolbar);
    }

    // 在移动控件前读取停靠坐标，避免此处因隐藏而丢失原位置。
    const QPoint anchor = m_actionDock->mapToGlobal(QPoint{}); // 工具带原屏幕坐标。
    m_actionDock->layout()->removeWidget(m_actionStrip);
    m_actionWindow->layout()->addWidget(m_actionStrip);
    m_actionDock->hide();
    m_actionStrip->show();
    updateActionToolbarText();
    fitFloatingActionToolbar();
    if (first)
    {
        m_actionWindow->adjustSize();
        const QRect area = screen()->availableGeometry(); // 以当前工作屏幕初始放置为准。
        const int right = qMax(area.left(), area.right() - m_actionWindow->width()); // 留在工作区域内。
        const int bottom = qMax(area.top(), area.bottom() - m_actionWindow->height()); // 保留标题栏可达。
        m_actionWindow->move(qBound(area.left(), anchor.x(), right), qBound(area.top(), anchor.y(), bottom));
    }
    m_actionWindow->show();
}

// 浮窗关闭、Esc 或停靠按钮触发。把同一个动作带归还给总览。
void OfflineSegmentOverview::restoreActionToolbar()
{
    m_actionWindow->layout()->removeWidget(m_actionStrip);
    m_actionStrip->setMinimumWidth(0);
    m_actionDock->layout()->addWidget(m_actionStrip);
    m_actionDock->show();
    m_actionStrip->show();
    updateActionToolbarText();
}

// 流式布局的最小宽度只够一项。浮出时按整排动作定宽，窄屏仍由原布局换行。
void OfflineSegmentOverview::fitFloatingActionToolbar()
{
    if (!m_actionWindow || m_actionStrip->parentWidget() != m_actionWindow)
    {
        return;
    }
    const auto* actions = static_cast<ks::ui::FlowLayout*>(m_actionStrip->layout()); // 唯一按钮布局。
    const auto margins = actions->contentsMargins(); // 工具带自己的留白。
    int naturalWidth = margins.left() + margins.right(); // 所有可见按钮的自然单排宽度。
    int shown = 0; // 控件之间才计算间隔。
    for (int index = 0; index < actions->count(); ++index)
    {
        const auto* item = actions->itemAt(index); // 当前动作自身的共享度量。
        if (item && !item->isEmpty())
        {
            naturalWidth += item->sizeHint().width();
            if (shown++ != 0)
            {
                naturalWidth += actions->horizontalSpacing();
            }
        }
    }
    // 至少保留一个最大的完整控件，为原生边框和内容外边距预留空间。
    const int usable = m_actionWindow->screen()->availableGeometry().width() - 32;
    const int width = qMax(actions->minimumSize().width(), qMin(naturalWidth, usable));
    m_actionStrip->setMinimumWidth(width);
}

// 由语言刷新和布局切换调用，更新窗口标题及图钉的可访问名称和悬停释义。
void OfflineSegmentOverview::updateActionToolbarText()
{
    const bool floating = m_actionStrip->parentWidget() == m_actionWindow; // 使用真实宿主判断归属。
    const auto label = floating ? sourceText(QStringLiteral("停靠工具条"))
        : sourceText(QStringLiteral("浮出并置顶工具条")); // 按钮执行的下一步动作。
    m_floatActions->setAccessibleName(label);
    m_floatActions->setToolTip(label);
    if (m_actionWindow)
    {
        m_actionWindow->setWindowTitle(sourceText(QStringLiteral("行为分析工具条")));
    }
}
}
