#include "SmoothScrollSupport.h"

#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QEasingCurve>
#include <QEvent>
#include <QHash>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPointingDevice>
#include <QPropertyAnimation>
#include <QScrollBar>
#include <QScopedValueRollback>
#include <QSignalBlocker>
#include <QTabBar>
#include <QTextBlock>
#include <QTextLayout>
#include <QVariant>
#include <QVariantAnimation>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr char kInstalledProperty[] = "KSWORD_SMOOTH_SCROLL_SUPPORT_INSTALLED";
    constexpr char kEnabledProperty[] = "ksword_smooth_scrolling_enabled";
    constexpr char kOriginalVerticalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_VERTICAL_MODE";
    constexpr char kOriginalHorizontalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_HORIZONTAL_MODE";
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr int kWheelAnimationDurationMs = 180;
    constexpr int kPixelAnimationDurationMs = 100;
    constexpr int kTabWheelStepPixels = 48;
    thread_local const QEvent* g_tabScrollFrame = nullptr;

    // 保留原 QTabBar 和连接，借助 Qt 的像素滚动路径移动标签，避免切页触发懒加载。
    class TabStripAnimator final : public QObject
    {
    public:
        explicit TabStripAnimator(QTabBar* tabBar)
            : QObject(tabBar), m_tabBar(tabBar), m_animation(this),
              m_pixelDevice(QStringLiteral("KSWORD_TAB_SCROLL_DEVICE"), 0,
                  QInputDevice::DeviceType::TouchPad, QPointingDevice::PointerType::Finger,
                  QInputDevice::Capability::Position | QInputDevice::Capability::PixelScroll, 1, 0)
        {
            connect(&m_animation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value)
                {
                    const int position = value.toInt();
                    movePixels(position - m_delivered);
                    m_delivered = position;
                });
            connect(tabBar, &QTabBar::currentChanged, this, [this]() { stop(); });
            connect(tabBar, &QTabBar::tabMoved, this, [this]() { stop(); });
        }

        bool forwarding() const { return m_forwarding; }

        void stop()
        {
            m_animation.stop();
            m_remainder = 0;
        }

        void wheel(QWheelEvent* event, bool smooth)
        {
            const QPoint delta = event->pixelDelta().isNull() ? event->angleDelta() : event->pixelDelta();
            const int axis = std::abs(delta.x()) > std::abs(delta.y()) ? delta.x() : delta.y();
            const bool pixels = !event->pixelDelta().isNull();
            const qreal distance = -qreal(axis) * (event->inverted() ? -1 : 1) *
                (pixels ? 1.0 : kTabWheelStepPixels / 120.0);
            if (event->phase() == Qt::ScrollBegin || distance * m_remainder < 0)
                m_remainder = 0;
            m_remainder += distance;
            const int wholePixels = static_cast<int>(std::trunc(m_remainder + std::copysign(1e-9, m_remainder)));
            m_remainder -= wholePixels;
            if (ks::ui::IsTabWheelSwitchingEnabled())
            {
                m_animation.stop();
                m_switchRemainder += distance;
                if (distance * (m_switchRemainder - distance) < 0)
                    m_switchRemainder = distance;
                const int steps = static_cast<int>(m_switchRemainder / kTabWheelStepPixels);
                m_switchRemainder -= steps * kTabWheelStepPixels;
                for (int step = 0; step < std::abs(steps); ++step)
                {
                    const int direction = steps > 0 ? 1 : -1;
                    for (int index = m_tabBar->currentIndex() + direction;
                        index >= 0 && index < m_tabBar->count(); index += direction)
                    {
                        if (m_tabBar->isTabEnabled(index) && m_tabBar->isTabVisible(index))
                        {
                            m_tabBar->setCurrentIndex(index);
                            break;
                        }
                    }
                }
            }
            else
            {
                m_switchRemainder = 0;
                scroll(wholePixels, smooth, pixels ? kPixelAnimationDurationMs : kWheelAnimationDurationMs);
            }
            if (event->phase() == Qt::ScrollEnd)
                m_remainder = m_switchRemainder = 0;
            // 无溢出、修饰键和边界事件也归标签栏处理，禁止向内容区传播或回退到切页。
            event->accept();
        }

    private:
        bool vertical() const
        {
            return m_tabBar->shape() == QTabBar::RoundedWest || m_tabBar->shape() == QTabBar::RoundedEast ||
                m_tabBar->shape() == QTabBar::TriangularWest || m_tabBar->shape() == QTabBar::TriangularEast;
        }

        void movePixels(int distance)
        {
            if (!distance || !m_tabBar->isVisible())
                return;
            const QPoint local = m_tabBar->rect().center();
            const int delta = m_tabBar->isRightToLeft() ? distance : -distance;
            const QPoint pixels = vertical() ? QPoint(0, delta) : QPoint(delta, 0);
            QWheelEvent frame(local, m_tabBar->mapToGlobal(local), pixels, pixels,
                Qt::NoButton, Qt::NoModifier, Qt::ScrollUpdate, false,
                Qt::MouseEventSynthesizedByApplication, &m_pixelDevice);
            m_forwarding = true;
            const QScopedValueRollback<const QEvent*> frameGuard(g_tabScrollFrame, &frame);
            QCoreApplication::sendEvent(m_tabBar, &frame);
            m_forwarding = false;
        }

        void scroll(int distance, bool smooth, int duration)
        {
            if (!distance)
                return;
            const int extent = vertical() ? m_tabBar->height() : m_tabBar->width();
            const int pending = m_animation.state() == QAbstractAnimation::Running
                ? m_animation.endValue().toInt() - m_delivered : 0;
            const int target = std::clamp(distance + (distance * qint64(pending) > 0 ? pending : 0),
                -std::max(1, extent), std::max(1, extent));
            m_animation.stop();
            m_delivered = 0;
            if (!smooth)
            {
                movePixels(target);
                return;
            }
            {
                // 重设已结束的动画时，Qt 可能按旧 currentTime 发出 valueChanged；这不是滚动帧。
                const QSignalBlocker blocker(&m_animation);
                m_animation.setDuration(duration);
                m_animation.setStartValue(0);
                m_animation.setEndValue(target);
                m_animation.setCurrentTime(0);
                m_animation.setEasingCurve(QEasingCurve::OutCubic);
            }
            m_animation.start();
        }

        QTabBar* m_tabBar;
        QVariantAnimation m_animation;
        QPointingDevice m_pixelDevice;
        qreal m_remainder = 0;
        qreal m_switchRemainder = 0;
        int m_delivered = 0;
        bool m_forwarding = false;
    };

    class GlobalSmoothScrollFilter;
    QPointer<GlobalSmoothScrollFilter> g_installedFilter;

    class GlobalSmoothScrollFilter final : public QObject
    {
    public:
        explicit GlobalSmoothScrollFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        void applyEnabledStateToAllWidgets(const bool enabled)
        {
            const QWidgetList widgetList = QApplication::allWidgets();
            for (QWidget* widget : widgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    !scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            // 冻结覆盖视图必须在主表切换完滚动模式后再同步，防止关闭平滑滚动时单位不一致。
            for (QWidget* widget : widgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            if (!enabled)
            {
                stopAllAnimations();
                for (TabStripAnimator* animator : std::as_const(m_tabAnimators))
                    animator->stop();
            }
        }

        void scrollTabStripByPixels(QAbstractScrollArea* area, int distance, int duration = kWheelAnimationDurationMs)
        {
            if (!area)
                return;
            QScrollBar* bar = area->horizontalScrollBar();
            const int maximumDistance = std::max(1, area->viewport()->width());
            QPropertyAnimation* animation = animationForScrollBar(bar);
            const qint64 current = bar->value();
            const qint64 pending = animation->state() == QAbstractAnimation::Running
                ? animation->endValue().toInt() : current;
            const int target = static_cast<int>(std::clamp(
                (distance * (pending - current) > 0 ? pending : current) + distance,
                std::max<qint64>(bar->minimum(), current - maximumDistance),
                std::min<qint64>(bar->maximum(), current + maximumDistance)));
            animation->stop();
            if (!enabled())
                bar->setValue(target);
            else if (target != current)
            {
                // QPropertyAnimation 的 setter 可按旧 currentTime 立即写属性；配置期间解除目标。
                animation->setTargetObject(nullptr);
                animation->setStartValue(static_cast<int>(current));
                animation->setEndValue(target);
                animation->setDuration(duration);
                animation->setCurrentTime(0);
                animation->setEasingCurve(QEasingCurve::OutCubic);
                animation->setTargetObject(bar);
                animation->start();
            }
        }

        void stopTabStripScrolling(QAbstractScrollArea* area)
        {
            if (area)
                stopAnimation(area->horizontalScrollBar());
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject == g_tabScrollFrame && !qobject_cast<QTabBar*>(watchedObject))
            {
                // Qt 像素滚动到边界会 ignore；内部动画帧不能再传给外层页面。
                eventObject->accept();
                return true;
            }

            if (eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::Polish)
            {
                if (auto* tabBar = qobject_cast<QTabBar*>(watchedObject))
                    configureTabBar(tabBar);
                if (QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(watchedObject))
                {
                    configureScrollArea(scrollArea,
                        enabled() && !isSmoothScrollDisabled(scrollArea));
                }
            }

            const bool tabStructureEvent = eventObject->type() == QEvent::Resize ||
                eventObject->type() == QEvent::Hide || eventObject->type() == QEvent::StyleChange ||
                eventObject->type() == QEvent::LayoutRequest || eventObject->type() == QEvent::FontChange;
            if (eventObject->type() == QEvent::Wheel || tabStructureEvent ||
                eventObject->type() == QEvent::MouseButtonPress)
            {
                if (QTabBar* tabBar = tabBarForEventObject(watchedObject))
                {
                    TabStripAnimator* animator = tabAnimator(tabBar);
                    if (eventObject->type() == QEvent::Wheel)
                    {
                        if (animator->forwarding())
                            return false;
                        if (tabBar->isEnabled() && tabBar->isVisible())
                        {
                            configureTabBar(tabBar);
                            animator->wheel(static_cast<QWheelEvent*>(eventObject), enabled());
                            return true;
                        }
                    }
                    else if ((watchedObject == tabBar && tabStructureEvent) ||
                        eventObject->type() == QEvent::MouseButtonPress)
                        animator->stop();
                }
            }

            if (eventObject->type() == QEvent::Resize)
            {
                if (QAbstractScrollArea* scrollArea = scrollAreaForEventObject(watchedObject))
                {
                    // 缩小视口后，旧动画的终点可能超过新的可见范围。
                    stopAnimation(scrollArea->verticalScrollBar());
                    stopAnimation(scrollArea->horizontalScrollBar());
                }
            }

            if (eventObject->type() != QEvent::Wheel)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QAbstractScrollArea* scrollArea = scrollAreaForEventObject(watchedObject);
            if (scrollArea == nullptr ||
                scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool() ||
                isSmoothScrollDisabled(scrollArea))
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            auto* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (wheelEvent->modifiers().testFlag(Qt::ControlModifier) ||
                wheelEvent->modifiers().testFlag(Qt::AltModifier))
            {
                // 保留 Ctrl+滚轮缩放和业务自定义 Alt+滚轮行为。
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QPoint pixelDelta = wheelEvent->pixelDelta();
            const QPoint angleDelta = wheelEvent->angleDelta();
            const QScrollBar* directScrollBar = qobject_cast<QScrollBar*>(watchedObject);
            const bool horizontal = directScrollBar != nullptr
                ? directScrollBar->orientation() == Qt::Horizontal
                : (wheelEvent->modifiers().testFlag(Qt::ShiftModifier) ||
                    std::abs(pixelDelta.x()) > std::abs(pixelDelta.y()) ||
                    std::abs(angleDelta.x()) > std::abs(angleDelta.y()));

            const QRect visibleRect = scrollArea->viewport()->visibleRegion().boundingRect();
            // QPlainTextEdit 纵向 value/pageStep 是视觉行，不是像素；通常沿用 Qt
            // 对换行、触控板增量和一页上限的处理，禁止对行号做像素动画。
            if (!horizontal)
            {
                if (QPlainTextEdit* plainEdit = qobject_cast<QPlainTextEdit*>(scrollArea))
                {
                    // 结构报告中的固定高度代码块可能被外层滚动区裁切。Qt 的 pageStep
                    // 仍按代码块完整视口计算，此时额外以真正露出的视觉行数限幅。
                    return scrollClippedPlainText(plainEdit, visibleRect, wheelEvent);
                }
            }
            if (!enabled())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(scrollArea))
            {
                const auto mode = horizontal
                    ? itemView->horizontalScrollMode() : itemView->verticalScrollMode();
                if (mode != QAbstractItemView::ScrollPerPixel)
                {
                    return QObject::eventFilter(watchedObject, eventObject);
                }
            }
            QScrollBar* scrollBar = horizontal
                ? scrollArea->horizontalScrollBar()
                : scrollArea->verticalScrollBar();
            if (scrollBar == nullptr || scrollBar->minimum() == scrollBar->maximum())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int rawPixelDelta = horizontal
                ? (pixelDelta.x() != 0 ? pixelDelta.x() : pixelDelta.y())
                : (pixelDelta.y() != 0 ? pixelDelta.y() : pixelDelta.x());
            const int rawAngleDelta = horizontal
                ? (angleDelta.x() != 0 ? angleDelta.x() : angleDelta.y())
                : (angleDelta.y() != 0 ? angleDelta.y() : angleDelta.x());
            if (rawPixelDelta == 0 && rawAngleDelta == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int directionMultiplier = wheelEvent->inverted() ? -1 : 1;
            const int visibleExtent = horizontal ? visibleRect.width() : visibleRect.height();
            if (visibleExtent <= 0 || scrollBar->pageStep() <= 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }
            const int pageExtent = std::min(visibleExtent, scrollBar->pageStep());
            const int overlap = std::min(scrollArea->fontMetrics().lineSpacing(), pageExtent / 2);
            const int maximumDistance = std::max(1, pageExtent - overlap);
            double requestedDistance = 0.0;
            int durationMs = kWheelAnimationDurationMs;
            if (rawPixelDelta != 0)
            {
                requestedDistance = -static_cast<double>(rawPixelDelta) * directionMultiplier;
                durationMs = kPixelAnimationDurationMs;
            }
            else
            {
                const double wheelSteps =
                    static_cast<double>(rawAngleDelta) * directionMultiplier / 120.0;
                const double pixelsPerStep = std::clamp(
                    static_cast<double>(scrollBar->singleStep()) * 3.0,
                    48.0,
                    120.0);
                requestedDistance = -wheelSteps * pixelsPerStep;
            }
            const int distance = static_cast<int>(std::lround(std::clamp(
                requestedDistance, -static_cast<double>(maximumDistance),
                static_cast<double>(maximumDistance))));
            if (distance == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QPropertyAnimation* animation = animationForScrollBar(scrollBar);
            const qint64 currentValue = scrollBar->value();
            const qint64 pendingTarget = animation->state() == QAbstractAnimation::Running
                ? animation->endValue().toInt() : currentValue;
            // 反向滚动立即从当前位置反向；连续事件的待滚距离也不能超过一屏。
            const bool sameDirection = distance > 0
                ? pendingTarget > currentValue : pendingTarget < currentValue;
            const qint64 accumulatedStart = sameDirection
                ? pendingTarget : currentValue;
            const int targetValue = static_cast<int>(std::clamp(
                accumulatedStart + distance,
                std::max<qint64>(scrollBar->minimum(), currentValue - maximumDistance),
                std::min<qint64>(scrollBar->maximum(), currentValue + maximumDistance)));
            if (targetValue == scrollBar->value())
            {
                // 到达边界时让未消费的滚轮事件继续向父滚动区域传播。
                animation->stop();
                return QObject::eventFilter(watchedObject, eventObject);
            }

            animation->stop();
            animation->setDuration(durationMs);
            animation->setStartValue(scrollBar->value());
            animation->setEndValue(targetValue);
            animation->setEasingCurve(QEasingCurve::OutCubic);
            animation->start();
            wheelEvent->accept();
            return true;
        }

    private:
        static void configureTabBar(QTabBar* bar)
        {
            if (!bar->usesScrollButtons())
                bar->setUsesScrollButtons(true);
            // setElideMode 即使写相同值也会重排并定位当前标签，不能每档滚轮都调用。
            if (bar->elideMode() != Qt::ElideNone)
                bar->setElideMode(Qt::ElideNone);
        }

        static QTabBar* tabBarForEventObject(QObject* object)
        {
            for (QWidget* widget = qobject_cast<QWidget*>(object); widget; widget = widget->parentWidget())
            {
                if (auto* bar = qobject_cast<QTabBar*>(widget))
                    return bar;
                if (widget->isWindow() || qobject_cast<QAbstractScrollArea*>(widget))
                    break;
            }
            return nullptr;
        }

        TabStripAnimator* tabAnimator(QTabBar* bar)
        {
            if (auto* animator = m_tabAnimators.value(bar, nullptr))
                return animator;
            auto* animator = new TabStripAnimator(bar);
            m_tabAnimators.insert(bar, animator);
            connect(bar, &QObject::destroyed, this, [this, bar]() { m_tabAnimators.remove(bar); });
            return animator;
        }

        bool scrollClippedPlainText(QPlainTextEdit* edit, const QRect& visibleRect,
            QWheelEvent* event)
        {
            if (visibleRect.isEmpty() || visibleRect.height() >= edit->viewport()->height())
            {
                return false;
            }
            QScrollBar* bar = edit->verticalScrollBar();
            const int direction = event->inverted() ? -1 : 1;
            const int pixelDelta = event->pixelDelta().y();
            const double requested = pixelDelta != 0
                ? -static_cast<double>(pixelDelta) * direction /
                    std::max(1, edit->fontMetrics().lineSpacing())
                : -static_cast<double>(event->angleDelta().y()) * direction / 120.0 *
                    QApplication::wheelScrollLines() * bar->singleStep();
            if (requested == 0.0 ||
                (requested < 0 && bar->value() == bar->minimum()) ||
                (requested > 0 && bar->value() == bar->maximum()))
            {
                bar->setProperty("ksword_clipped_scroll_remainder", 0.0);
                return false;
            }

            const auto visualLineAt = [edit](const QPoint& point)
            {
                const QTextCursor cursor = edit->cursorForPosition(point);
                const QTextBlock block = cursor.block();
                const QTextLine line = block.layout()->lineForTextPosition(cursor.positionInBlock());
                return block.firstLineNumber() + std::max(0, line.lineNumber());
            };
            const int visibleLines = visualLineAt(visibleRect.bottomLeft()) -
                visualLineAt(visibleRect.topLeft());
            const int maximumDistance = std::max(1, visibleLines - 1);
            double remainder = bar->property("ksword_clipped_scroll_remainder").toDouble();
            if (remainder * requested < 0)
            {
                remainder = 0.0;
            }
            const double bounded = std::clamp(remainder + requested,
                -static_cast<double>(maximumDistance), static_cast<double>(maximumDistance));
            const int distance = static_cast<int>(bounded);
            bar->setProperty("ksword_clipped_scroll_remainder", bounded - distance);
            bar->setValue(static_cast<int>(std::clamp<qint64>(
                static_cast<qint64>(bar->value()) + distance, bar->minimum(), bar->maximum())));
            event->accept();
            return true;
        }

        bool isSmoothScrollDisabled(const QWidget* widget) const
        {
            for (const QWidget* current = widget; current != nullptr;
                current = current->parentWidget())
            {
                if (current->property("ksword_disable_smooth_scroll").toBool())
                {
                    return true;
                }
            }
            return false;
        }

        void stopAnimation(QScrollBar* scrollBar)
        {
            if (QPropertyAnimation* animation = m_animations.value(scrollBar, nullptr))
            {
                animation->stop();
            }
        }

        bool enabled() const
        {
            QApplication* appInstance =
                qobject_cast<QApplication*>(QCoreApplication::instance());
            return appInstance != nullptr &&
                appInstance->property(kEnabledProperty).toBool();
        }

        QAbstractScrollArea* scrollAreaForEventObject(QObject* watchedObject) const
        {
            if (QAbstractScrollArea* directArea =
                qobject_cast<QAbstractScrollArea*>(watchedObject))
            {
                return directArea;
            }
            if (QScrollBar* scrollBar = qobject_cast<QScrollBar*>(watchedObject))
            {
                for (QWidget* parent = scrollBar->parentWidget(); parent != nullptr;
                    parent = parent->parentWidget())
                {
                    if (QAbstractScrollArea* area = qobject_cast<QAbstractScrollArea*>(parent))
                    {
                        return scrollBar == area->verticalScrollBar() ||
                            scrollBar == area->horizontalScrollBar()
                            ? area : nullptr;
                    }
                }
                return nullptr;
            }
            QAbstractScrollArea* parentArea = qobject_cast<QAbstractScrollArea*>(
                watchedObject != nullptr ? watchedObject->parent() : nullptr);
            return parentArea != nullptr && parentArea->viewport() == watchedObject
                ? parentArea
                : nullptr;
        }

        void configureScrollArea(QAbstractScrollArea* scrollArea, const bool enabledState)
        {
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(scrollArea);
            if (itemView == nullptr)
            {
                return;
            }
            if (itemView->property(kFrozenPaneAuxiliaryProperty).toBool())
            {
                // 冻结窗格的偏移由 TableFrozenPaneController 按像素直接写入滚动条，
                // 跟随主表切到按整行滚动会让冻结区与主表错行，因此这里固定按像素。
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            if (enabledState && !isSmoothScrollDisabled(scrollArea))
            {
                if (!itemView->property(kOriginalVerticalModeProperty).isValid())
                {
                    itemView->setProperty(
                        kOriginalVerticalModeProperty,
                        static_cast<int>(itemView->verticalScrollMode()));
                    itemView->setProperty(
                        kOriginalHorizontalModeProperty,
                        static_cast<int>(itemView->horizontalScrollMode()));
                }
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            const QVariant originalVerticalMode =
                itemView->property(kOriginalVerticalModeProperty);
            const QVariant originalHorizontalMode =
                itemView->property(kOriginalHorizontalModeProperty);
            if (originalVerticalMode.isValid())
            {
                itemView->setVerticalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        originalVerticalMode.toInt()));
                itemView->setProperty(kOriginalVerticalModeProperty, QVariant());
            }
            if (originalHorizontalMode.isValid())
            {
                itemView->setHorizontalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        originalHorizontalMode.toInt()));
                itemView->setProperty(kOriginalHorizontalModeProperty, QVariant());
            }
        }

        QPropertyAnimation* animationForScrollBar(QScrollBar* scrollBar)
        {
            QPropertyAnimation* animation = m_animations.value(scrollBar, nullptr);
            if (animation != nullptr)
            {
                return animation;
            }

            animation = new QPropertyAnimation(scrollBar, "value", this);
            m_animations.insert(scrollBar, animation);
            connect(scrollBar, &QScrollBar::sliderPressed, animation, [animation]()
                {
                    animation->stop();
                });
            connect(scrollBar, &QObject::destroyed, this, [this, scrollBar]()
                {
                    if (QPropertyAnimation* removedAnimation =
                        m_animations.take(scrollBar))
                    {
                        removedAnimation->stop();
                        removedAnimation->deleteLater();
                    }
                });
            return animation;
        }

        void stopAllAnimations()
        {
            for (QPropertyAnimation* animation : std::as_const(m_animations))
            {
                if (animation != nullptr)
                {
                    animation->stop();
                }
            }
        }

        QHash<QScrollBar*, QPropertyAnimation*> m_animations;
        QHash<QTabBar*, TabStripAnimator*> m_tabAnimators;
    };

    GlobalSmoothScrollFilter* installedFilter()
    {
        return g_installedFilter.data();
    }
}

void ks::ui::InstallGlobalSmoothScrollSupport(QApplication* appInstance)
{
    if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
    {
        return;
    }

    auto* filter = new GlobalSmoothScrollFilter(appInstance);
    filter->setObjectName(QStringLiteral("KSWORD_GLOBAL_SMOOTH_SCROLL_FILTER"));
    g_installedFilter = filter;
    appInstance->installEventFilter(filter);
    appInstance->setProperty(kInstalledProperty, true);
    filter->applyEnabledStateToAllWidgets(
        appInstance->property(kEnabledProperty).toBool());
}

void ks::ui::SetGlobalSmoothScrollingEnabled(const bool enabled)
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        return;
    }
    appInstance->setProperty(kEnabledProperty, enabled);
    if (GlobalSmoothScrollFilter* filter = installedFilter())
    {
        filter->applyEnabledStateToAllWidgets(enabled);
    }
}

bool ks::ui::IsGlobalSmoothScrollingEnabled()
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    return appInstance != nullptr &&
        appInstance->property(kEnabledProperty).toBool();
}

bool ks::ui::IsTabWheelSwitchingEnabled()
{
    return qApp && qApp->property("ksword_slider_wheel_adjust_enabled").toBool();
}

void ks::ui::ScrollTabStripWithWheel(QAbstractScrollArea* area, QWheelEvent* event)
{
    if (!area || !event)
        return;
    const bool pixels = !event->pixelDelta().isNull();
    const QPoint delta = pixels ? event->pixelDelta() : event->angleDelta();
    const int axis = std::abs(delta.x()) > std::abs(delta.y()) ? delta.x() : delta.y();
    qreal remainder = area->property("ksword_tab_scroll_remainder").toDouble();
    const qreal distance = -qreal(axis) * (event->inverted() ? -1 : 1) *
        (pixels ? 1.0 : kTabWheelStepPixels / 120.0);
    if (event->phase() == Qt::ScrollBegin || remainder * distance < 0)
        remainder = 0;
    remainder += distance;
    const int whole = static_cast<int>(std::trunc(remainder + std::copysign(1e-9, remainder)));
    area->setProperty("ksword_tab_scroll_remainder", event->phase() == Qt::ScrollEnd ? 0.0 : remainder - whole);
    if (whole && installedFilter())
        installedFilter()->scrollTabStripByPixels(area, whole,
            pixels ? kPixelAnimationDurationMs : kWheelAnimationDurationMs);
    event->accept();
}

void ks::ui::ScrollTabStripByPixels(QAbstractScrollArea* area, int distance)
{
    if (installedFilter())
        installedFilter()->scrollTabStripByPixels(area, distance);
}

void ks::ui::StopTabStripScrolling(QAbstractScrollArea* area)
{
    if (installedFilter())
        installedFilter()->stopTabStripScrolling(area);
    if (area)
        area->setProperty("ksword_tab_scroll_remainder", 0.0);
}
