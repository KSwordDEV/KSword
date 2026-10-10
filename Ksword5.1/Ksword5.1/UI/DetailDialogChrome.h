#pragma once
#include "./FlatButtonTheme.h"
#include "./DetailNavigationGroups.h"

// 只共享详情外框；页面、模型、索引和业务动作继续由原控件持有。
#include "../theme.h"
#include <QButtonGroup>
#include <QDialogButtonBox>
#include <QEvent>
#include <QHBoxLayout>
#include <QPointer>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace ks::ui
{
    inline QString BuildDetailDialogChromeStyle(const QString& rootObjectName = QString())
    {
        QString style = QStringLiteral(
            "QWidget[ksword_detail_shell=\"true\"]{background:%1;color:%2;border:0;}"
            "QWidget[ksword_detail_shell=\"true\"] QTabWidget::pane{background:%1;border:0;padding:0;margin:0;}"
            "QWidget[ksword_detail_shell=\"true\"] QStackedWidget{background:%1;border:0;}"
            "QWidget[ksword_detail_shell=\"true\"] QScrollArea{background:%1;border:0;padding:0;margin:0;}"
            "QWidget[ksword_detail_shell=\"true\"] QScrollArea > QWidget{background:%1;}"
            "QWidget[ksword_detail_shell=\"true\"] QAbstractItemView{border:0;}"
            // 内容分组用完整细线框区分范围，控件仍保留纯色样式，字段行本身不加网格。
            "QWidget[ksword_detail_shell=\"true\"] QGroupBox{background:%3;border:1px solid %4;border-radius:6px;margin-top:10px;padding-top:8px;}"
            "QWidget[ksword_detail_shell=\"true\"] QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 7px;color:%2;background:%3;font-weight:600;}"
            "QWidget[ksword_detail_shell=\"true\"] QWidget[ksword_detail_sidebar=\"true\"],QWidget[ksword_detail_shell=\"true\"] QScrollArea[ksword_detail_sidebar=\"true\"],QWidget[ksword_detail_shell=\"true\"] QScrollArea[ksword_detail_sidebar=\"true\"] > QWidget,QWidget[ksword_detail_shell=\"true\"] QScrollArea[ksword_detail_sidebar=\"true\"] > QWidget > QWidget{background:%3;border:0;padding:0;margin:0;}"
            // 分界仅画在滚动区的外缘，导航项与 viewport 不重复描边。
            "QWidget[ksword_detail_shell=\"true\"] QScrollArea[ksword_detail_sidebar=\"true\"]{border-right:1px solid %4;}"
            "QWidget[ksword_detail_shell=\"true\"] QWidget[ksword_detail_sidebar=\"true\"] QToolButton{border-radius:5px;padding:8px 10px;text-align:left;}"
            "QWidget[ksword_detail_shell=\"true\"] QWidget#ks_detail_footer{background:%1;border:0;border-top:1px solid %4;}")
            .arg(KswordTheme::SurfaceHex(), KswordTheme::TextPrimaryHex(), KswordTheme::SurfaceAltHex(),
                KswordTheme::BorderHex());
        if (!rootObjectName.isEmpty())
            style.replace(QStringLiteral("QWidget[ksword_detail_shell=\"true\"]"),
                QStringLiteral("QWidget#%1[ksword_detail_shell=\"true\"]").arg(rootObjectName));
        return style;
    }

    inline void ConfigureDetailDialogRoot(QWidget* window)
    {
        if (window == nullptr) return;
        window->setProperty("ksword_detail_shell", true);
        window->setAttribute(Qt::WA_StyledBackground, true);
        if (window->layout() != nullptr)
        {
            window->layout()->setContentsMargins(0, 0, 0, 0);
            window->layout()->setSpacing(0);
            for (int index = 0; index < window->layout()->count(); ++index)
            {
                auto* box = qobject_cast<QDialogButtonBox*>(window->layout()->itemAt(index)->widget());
                if (box != nullptr)
                {
                    box->setObjectName(QStringLiteral("ks_detail_footer"));
                    box->setContentsMargins(8, 6, 8, 6);
                }
            }
        }
    }

    inline void ApplyDetailDialogChrome(QWidget* window)
    {
        if (window == nullptr) return;
        const int spacing = window->layout() != nullptr ? window->layout()->spacing() : 0;
        ConfigureDetailDialogRoot(window);
        // 单页详情的根layout也排列摘要、工具和状态，它们的业务间距不能被当作外框清掉。
        if (window->layout() != nullptr) window->layout()->setSpacing(spacing);
        window->setStyleSheet(window->styleSheet() + BuildDetailDialogChromeStyle(window->objectName()));
    }

    inline void ConfigureDetailNavigation(QScrollArea* scroll, QWidget* navigation, const int width = 240)
    {
        if (scroll == nullptr || navigation == nullptr) return;
        scroll->setProperty("ksword_detail_sidebar", true);
        navigation->setProperty("ksword_detail_sidebar", true);
        navigation->setAttribute(Qt::WA_StyledBackground, true);
        navigation->setMinimumWidth(0);
        navigation->setMaximumWidth(QWIDGETSIZE_MAX);
        navigation->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll->setFixedWidth(width);
        // 宽度由真实viewport分配，不再为不存在的滚动条保留16px空白。
        if (navigation->layout() != nullptr)
        {
            navigation->layout()->setContentsMargins(8, 12, 8, 12);
            navigation->layout()->setSpacing(4);
        }
    }

    class DetailTabNavigation final : public QObject
    {
    public:
        DetailTabNavigation(QTabWidget* tabs, QWidget* navigation)
            : QObject(navigation), m_tabs(tabs), m_navigation(navigation), m_buttons(new QButtonGroup(navigation))
        {
            m_buttons->setExclusive(true);
            tabs->tabBar()->installEventFilter(this);
            tabs->installEventFilter(this);
            connect(tabs, &QTabWidget::currentChanged, this, [this](int) { scheduleSynchronize(); });
            connect(m_buttons, &QButtonGroup::idClicked, this, [this](int index)
            { if (m_tabs != nullptr && m_tabs->isTabEnabled(index)) m_tabs->setCurrentIndex(index); });
            synchronize();
        }
    protected:
        bool eventFilter(QObject* object, QEvent* event) override
        {
            if (event->type() == QEvent::LayoutRequest || event->type() == QEvent::Show ||
                event->type() == QEvent::LanguageChange || event->type() == QEvent::StyleChange
                || event->type() == QEvent::DynamicPropertyChange)
            {
                scheduleSynchronize();
            }
            return QObject::eventFilter(object, event);
        }
    private:
        void scheduleSynchronize()
        {
            if (m_refreshPending) return;
            m_refreshPending = true;
            // 延迟到当前按钮事件结束后再增删导航，不能在click回调里删除发送者。
            QTimer::singleShot(0, this, [this]()
            { m_refreshPending = false; synchronize(); });
        }

        void synchronize()
        {
            if (m_tabs == nullptr || m_navigation == nullptr) return;
            m_tabs->tabBar()->hide();
            if (m_tabButtons.size() != m_tabs->count())
            {
                for (const auto& button : m_tabButtons) delete button.data();
                m_tabButtons.clear();
                m_navigation->setProperty("ksword_detail_navigation_layout", QVariant());
                auto* layout = qobject_cast<QVBoxLayout*>(m_navigation->layout());
                for (int index = 0; index < m_tabs->count(); ++index)
                {
                    auto* button = new QToolButton(m_navigation);
                    button->setCheckable(true);
                    // 详情导航只接管按钮颜色，不改变 tab 索引、checked、可见性或图标。
                    ApplyDetailNavigationButtonTheme(button);
                    button->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
                    button->setIconSize(QSize(18, 18));
                    button->setMinimumHeight(38);
                    button->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
                    m_buttons->addButton(button, index);
                    m_tabButtons.append(button);
                    layout->insertWidget(index, button);
                }
            }
            for (int index = 0; index < m_tabButtons.size(); ++index)
            {
                QToolButton* button = m_tabButtons.at(index);
                button->setText(m_tabs->tabText(index));
                button->setToolTip(m_tabs->tabToolTip(index).isEmpty() ? m_tabs->tabText(index) : m_tabs->tabToolTip(index));
                const QIcon icon = m_tabs->tabIcon(index);
                button->setIcon(icon.isNull() ? QIcon(QStringLiteral(":/Icon/process_details.svg")) : icon);
                button->setEnabled(m_tabs->isTabEnabled(index));
                button->setVisible(m_tabs->isTabVisible(index));
                button->setChecked(m_tabs->currentIndex() == index);
            }
            ArrangeDetailNavigationGroups(m_navigation, m_tabs, m_buttons);
        }
        QPointer<QTabWidget> m_tabs;
        QPointer<QWidget> m_navigation;
        QButtonGroup* m_buttons;
        QList<QPointer<QToolButton>> m_tabButtons;
        bool m_refreshPending = false;
    };

    inline QWidget* CreateDetailTabShell(QTabWidget* tabs, QWidget* parent, const int width = 240)
    {
        tabs->setProperty("ksword_detail_tabs", true);
        auto* shell = new QWidget(parent);
        shell->setAttribute(Qt::WA_StyledBackground, true);
        auto* layout = new QHBoxLayout(shell);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(0);
        auto* navigation = new QWidget(shell);
        auto* navigationLayout = new QVBoxLayout(navigation);
        navigationLayout->addStretch(1);
        auto* scroll = new QScrollArea(shell);
        scroll->setWidget(navigation);
        ConfigureDetailNavigation(scroll, navigation, width);
        tabs->setMinimumSize(0, 0);
        tabs->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        if (auto* stack = tabs->findChild<QStackedWidget*>())
        { stack->setMinimumSize(0, 0); stack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored); }
        layout->addWidget(scroll);
        layout->addWidget(tabs, 1);
        new DetailTabNavigation(tabs, navigation);
        return shell;
    }
}
