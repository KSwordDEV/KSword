#include "DockTabInteraction.h"

// ADS 头按**相对路径**引，与 MainWindow.h 的 "include/ads/..." 同源。
// 这个项目没有把 include/ 放进包含目录，`<ads/...>` 形式找不到。
#include "../include/ads/DockAreaTabBar.h"
#include "../include/ads/DockAreaTitleBar.h"
#include "../include/ads/DockAreaWidget.h"
#include "../include/ads/DockContainerWidget.h"
#include "../include/ads/DockManager.h"

#include <QAbstractScrollArea>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QPointer>
#include <QScrollBar>
#include <QWheelEvent>

namespace ks::ui
{
    namespace
    {
        // 一次滚轮"格"走多少像素。
        //
        // 取一个标签典型宽度的一小半：太小要滚很多下才看得出在动，太大会一下
        // 掠过好几个标签，两种都让人觉得"这东西不受控"。
        constexpr int kWheelStepPixels = 48;

        // 标记已经装过过滤器的标签栏，保证幂等。
        //
        // 用动态属性而不是容器：标签栏会被 ADS 随时销毁（浮动、合并、恢复布局），
        // 外部容器就得跟着处理销毁通知，而属性随对象一起消失，不会留下悬垂键。
        constexpr const char* kWheelFilterInstalledProperty =
            "kswordDockTabWheelFilterInstalled";

        class DockTabWheelScroller final : public QObject
        {
        public:
            explicit DockTabWheelScroller(QObject* parent)
                : QObject(parent)
            {
            }

        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (event == nullptr || event->type() != QEvent::Wheel)
                {
                    return QObject::eventFilter(watched, event);
                }
                auto* const scrollArea = qobject_cast<QAbstractScrollArea*>(watched);
                if (scrollArea == nullptr)
                {
                    return QObject::eventFilter(watched, event);
                }
                QScrollBar* const bar = scrollArea->horizontalScrollBar();
                if (bar == nullptr || bar->minimum() >= bar->maximum())
                {
                    // 没有可滚的余量：**不要吞掉事件**。吞了就等于告诉外层
                    // "这里处理过了"，而实际上什么都没发生，用户会觉得滚轮死了。
                    return QObject::eventFilter(watched, event);
                }

                auto* const wheel = static_cast<QWheelEvent*>(event);
                // 竖直滚轮映射成横向位移 —— 大多数鼠标只有竖轮，而这排标签
                // 只有横向可滚。同时保留真正的横向滚动（触控板、水平轮）。
                int delta = wheel->angleDelta().x();
                if (delta == 0)
                {
                    delta = wheel->angleDelta().y();
                }
                if (delta == 0)
                {
                    return QObject::eventFilter(watched, event);
                }

                const int previous = bar->value();
                // angleDelta 以 1/8 度计，一"格"是 120。按格数走，
                // 高分辨率滚轮（每次几度）也能平滑推进而不是原地不动。
                const int steps = delta / 120;
                const int pixels = (steps != 0)
                    ? steps * kWheelStepPixels
                    : ((delta > 0) ? kWheelStepPixels : -kWheelStepPixels);
                // 轮子向前（正）= 看更靠前的标签 = 向左滚。
                bar->setValue(previous - pixels);

                if (bar->value() == previous)
                {
                    // 已经顶到头，这一次没能滚动：同样不吞，让上层还有机会响应。
                    return QObject::eventFilter(watched, event);
                }
                event->accept();
                return true;
            }
        };

        void installOnTabBar(ads::CDockAreaWidget* dockArea, QObject* filter)
        {
            if (dockArea == nullptr || filter == nullptr)
            {
                return;
            }
            ads::CDockAreaTitleBar* const titleBar = dockArea->titleBar();
            if (titleBar == nullptr)
            {
                return;
            }
            ads::CDockAreaTabBar* const tabBar = titleBar->tabBar();
            if (tabBar == nullptr)
            {
                return;
            }
            if (tabBar->property(kWheelFilterInstalledProperty).toBool())
            {
                return;
            }
            tabBar->setProperty(kWheelFilterInstalledProperty, true);
            tabBar->installEventFilter(filter);
        }
    }

    void installDockTabWheelScrolling(ads::CDockManager* dockManager)
    {
        if (dockManager == nullptr)
        {
            return;
        }
        // 过滤器挂在管理器名下，生命周期跟着它走。
        auto* const filter = new DockTabWheelScroller(dockManager);

        // 已经存在的区域。注意要遍历**全部容器**而不只是主容器：浮动出去的
        // 窗口各有自己的容器，而它们同样会溢出。
        const auto containers = dockManager->dockContainers();
        for (ads::CDockContainerWidget* const container : containers)
        {
            if (container == nullptr)
            {
                continue;
            }
            const auto areas = container->openedDockAreas();
            for (ads::CDockAreaWidget* const area : areas)
            {
                installOnTabBar(area, filter);
            }
        }

        // 之后新建的区域。restoreState、浮动、以及新增 Dock 都会走到这里 ——
        // 只在启动时扫一遍的话，用户拖出一个浮动窗口就又滚不动了。
        QPointer<QObject> safeFilter(filter);
        QObject::connect(
            dockManager,
            &ads::CDockManager::dockAreaCreated,
            filter,
            [safeFilter](ads::CDockAreaWidget* dockArea)
            {
                if (safeFilter.isNull())
                {
                    return;
                }
                installOnTabBar(dockArea, safeFilter.data());
            });
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
            // 本来就没有保存过：目标已经达成，不是失败。
            return true;
        }
        return QFile::remove(layoutConfigPath);
    }
}
