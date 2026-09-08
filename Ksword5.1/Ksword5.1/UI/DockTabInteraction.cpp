#include "DockTabInteraction.h"

#include "../include/ads/DockAreaTabBar.h"
#include "../include/ads/DockAreaTitleBar.h"
#include "../include/ads/DockAreaWidget.h"
#include "../include/ads/DockContainerWidget.h"
#include "../include/ads/DockManager.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QScrollBar>
#include <QTimer>
#include <QToolButton>
#include <QWheelEvent>
#include <cmath>

namespace ks::ui
{
    namespace
    {
        constexpr int kWheelStepPixels = 48;
        constexpr const char* kInstalledProperty = "ksword_dock_tab_scrolling_installed";

        class DockTabScroller final : public QObject
        {
        public:
            explicit DockTabScroller(ads::CDockAreaTitleBar* titleBar)
                : QObject(titleBar->tabBar()), m_tabBar(titleBar->tabBar()),
                  m_viewport(m_tabBar->viewport())
            {
                // 标签栏使用剩余宽度，完整标签在内部滚动，不撑大窗口最小宽度。
                m_tabBar->setMinimumWidth(0);
                m_tabBar->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                m_tabBar->setProperty("ksword_disable_smooth_scroll", true);
                m_tabBar->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                m_tabBar->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

                m_left = new QToolButton(titleBar);
                m_right = new QToolButton(titleBar);
                m_left->setObjectName(QStringLiteral("ks_dock_scroll_left"));
                m_right->setObjectName(QStringLiteral("ks_dock_scroll_right"));
                m_left->setArrowType(Qt::LeftArrow);
                m_right->setArrowType(Qt::RightArrow);
                for (QToolButton* button : { m_left, m_right })
                {
                    KswordTheme::ApplyCompactIconButtonMetrics(button);
                    button->setAutoRepeat(true);
                    button->setAutoRaise(true);
                    button->hide();
                }
                auto& language = ks::i18n::LanguageManager::instance();
                language.bindToolTip(m_left, QStringLiteral("dock.tabs.scroll_left"), QStringLiteral("向左滚动标签"));
                language.bindToolTip(m_right, QStringLiteral("dock.tabs.scroll_right"), QStringLiteral("向右滚动标签"));
                titleBar->insertWidget(titleBar->indexOf(m_tabBar), m_left);
                titleBar->insertWidget(titleBar->indexOf(m_tabBar) + 1, m_right);

                QScrollBar* const bar = m_tabBar->horizontalScrollBar();
                connect(m_left, &QToolButton::clicked, this, [this, bar]()
                    { bar->setValue(bar->value() - qMax(kWheelStepPixels, m_tabBar->viewport()->width() / 2)); });
                connect(m_right, &QToolButton::clicked, this, [this, bar]()
                    { bar->setValue(bar->value() + qMax(kWheelStepPixels, m_tabBar->viewport()->width() / 2)); });
                connect(bar, &QScrollBar::rangeChanged, this, [this]() { scheduleButtons(); });
                connect(bar, &QScrollBar::valueChanged, this, [this]() { scheduleButtons(); });

                // 在 viewportEvent 转发前捕获滚轮，覆盖文字、图标和动态子控件。
                // QApplication 过滤器只接管本标签栏的后代。
                qApp->installEventFilter(this);
                scheduleButtons();
            }

        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (event->type() == QEvent::Resize && watched == m_viewport)
                {
                    scheduleButtons();
                }
                if (event->type() != QEvent::Wheel)
                {
                    return false;
                }
                auto* widget = qobject_cast<QWidget*>(watched);
                while (widget != nullptr && widget != m_tabBar)
                {
                    widget = widget->parentWidget();
                }
                if (widget != m_tabBar)
                {
                    return false;
                }

                auto* const wheel = static_cast<QWheelEvent*>(event);
                const QPoint pixelDelta = wheel->pixelDelta();
                const QPoint angleDelta = wheel->angleDelta();
                const bool pixels = !pixelDelta.isNull();
                const QPoint delta = pixels ? pixelDelta : angleDelta;
                const int axisDelta = delta.x() != 0 ? delta.x() : delta.y();
                if (axisDelta == 0)
                {
                    return false;
                }
                const qreal distance = pixels ? qreal(axisDelta)
                    : qreal(axisDelta) * kWheelStepPixels / 120.0;
                // 累计高分辨率滚轮的亚像素余量，换向时清除上一方向的余量。
                if (distance * m_remainder < 0)
                {
                    m_remainder = 0;
                }
                m_remainder += distance;
                const int wholePixels = static_cast<int>(std::trunc(m_remainder));
                m_remainder -= wholePixels;
                QScrollBar* const bar = m_tabBar->horizontalScrollBar();
                bar->setValue(bar->value() - wholePixels);
                if ((distance > 0 && bar->value() == bar->minimum())
                    || (distance < 0 && bar->value() == bar->maximum()))
                {
                    m_remainder = 0;
                }
                // 到边界仍归标签栏处理，防止 ADS 改为切页或滚动下方内容。
                wheel->accept();
                return true;
            }

        private:
            void scheduleButtons()
            {
                if (m_updatePending)
                {
                    return;
                }
                m_updatePending = true;
                QTimer::singleShot(0, this, [this]()
                    {
                        m_updatePending = false;
                        QScrollBar* const bar = m_tabBar->horizontalScrollBar();
                        // 加回箭头占用空间再判断溢出，避免临界宽度反复显示/隐藏。
                        const int buttonWidth = (m_left->isHidden() ? 0 : m_left->width())
                            + (m_right->isHidden() ? 0 : m_right->width());
                        const bool overflowing = bar->maximum() - bar->minimum() > buttonWidth;
                        m_left->setVisible(overflowing);
                        m_right->setVisible(overflowing);
                        m_left->setEnabled(bar->value() > bar->minimum());
                        m_right->setEnabled(bar->value() < bar->maximum());
                    });
            }

            ads::CDockAreaTabBar* m_tabBar;
            QWidget* m_viewport;
            QToolButton* m_left;
            QToolButton* m_right;
            qreal m_remainder = 0;
            bool m_updatePending = false;
        };

        void installOnTabBar(ads::CDockAreaWidget* dockArea)
        {
            if (dockArea == nullptr || dockArea->titleBar() == nullptr)
            {
                return;
            }
            ads::CDockAreaTabBar* const tabBar = dockArea->titleBar()->tabBar();
            if (tabBar == nullptr || tabBar->property(kInstalledProperty).toBool())
            {
                return;
            }
            tabBar->setProperty(kInstalledProperty, true);
            new DockTabScroller(dockArea->titleBar());
        }
    }

    void installDockTabWheelScrolling(ads::CDockManager* dockManager)
    {
        if (dockManager == nullptr || dockManager->property(kInstalledProperty).toBool())
        {
            return;
        }
        dockManager->setProperty(kInstalledProperty, true);
        for (ads::CDockContainerWidget* container : dockManager->dockContainers())
        {
            if (container != nullptr)
            {
                for (ads::CDockAreaWidget* area : container->openedDockAreas())
                {
                    installOnTabBar(area);
                }
            }
        }
        QObject::connect(dockManager, &ads::CDockManager::dockAreaCreated,
            dockManager, [](ads::CDockAreaWidget* area) { installOnTabBar(area); });
    }

    bool discardSavedDockLayout(const QString& layoutConfigPath)
    {
        if (layoutConfigPath.isEmpty())
        {
            return false;
        }
        const QFileInfo info(layoutConfigPath);
        if (!info.exists())
        {
            return true;
        }
        return QFile::remove(layoutConfigPath);
    }
}
