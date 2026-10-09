#include "./FloatingScrollbars.h"

#include "../theme.h"

#include <QAbstractScrollArea>
#include <QApplication>
#include <QEvent>
#include <QHash>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QTimer>
#include <QVariant>
#include <QVector>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>

namespace
{
    // 属性与对象名用于幂等安装、页面例外和独立回归定位，不属于用户可见文本。
    constexpr char kControllerName[] = "ksword_floating_scrollbar_controller";
    constexpr char kInstalledProperty[] = "KSWORD_FLOATING_SCROLLBARS_INSTALLED";
    constexpr char kPreserveNativeProperty[] = "ksword_preserve_native_scrollbars";
    constexpr char kFrozenPaneProperty[] = "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr char kComparisonSourceProperty[] = "KSWORD_TABLE_INTERACTION_COMPARISON_SOURCE_ACTIVE";
    constexpr char kStyleBegin[] = "/* KSWORD_FLOATING_SCROLLBAR_BEGIN */";
    constexpr char kStyleEnd[] = "/* KSWORD_FLOATING_SCROLLBAR_END */";

    // 移除本组件拥有的片段，保留页面后来追加或重设的全部其他样式。
    QString withoutOwnedStyle(QString style)
    {
        const QString begin = QString::fromLatin1(kStyleBegin);
        const QString end = QString::fromLatin1(kStyleEnd);
        qsizetype start = style.indexOf(begin);
        while (start >= 0)
        {
            const qsizetype finish = style.indexOf(end, start + begin.size());
            if (finish < 0)
            {
                break;
            }
            style.remove(start, finish + end.size() - start);
            start = style.indexOf(begin);
        }
        return style;
    }

    // 仅将原生条的布局厚度归零；不强改 AlwaysOff，不替换条或解绑业务连接。
    QString collapsedStyle(const QString& original, Qt::Orientation orientation)
    {
        const QString dimensions = orientation == Qt::Vertical
            ? QStringLiteral("width:0px;min-width:0px;max-width:0px;")
            : QStringLiteral("height:0px;min-height:0px;max-height:0px;");
        return withoutOwnedStyle(original) + QString::fromLatin1(kStyleBegin)
            + QStringLiteral("QScrollBar {") + dimensions
            + QStringLiteral("border:0px;padding:0px;margin:0px;}")
            + QString::fromLatin1(kStyleEnd);
    }

    // 冻结辅助窗格从主表同步偏移，显式原生例外由页面拥有，均不接管外观。
    bool preservesNative(const QAbstractScrollArea* area)
    {
        return area == nullptr || area->property(kPreserveNativeProperty).toBool()
            || area->property(kFrozenPaneProperty).toBool();
    }

    // 视觉条保留 QAbstractSlider 的信号协议，仅替换鼠标映射和绘制。
    class FloatingScrollbar final : public QScrollBar
    {
    public:
        explicit FloatingScrollbar(Qt::Orientation orientation, QWidget* parent)
            : QScrollBar(orientation, parent)
        {
            setObjectName(orientation == Qt::Vertical
                ? QStringLiteral("ksword_floating_vertical_scrollbar")
                : QStringLiteral("ksword_floating_horizontal_scrollbar"));
            setFocusPolicy(Qt::NoFocus);
            setMouseTracking(true);
            setAutoFillBackground(false);
            setAttribute(Qt::WA_NoSystemBackground, true);
            hide();
        }

        // 保存原生事件目标；滚轮仍交原条上的全局平滑滚动或 Qt 自身处理。
        void setSource(QScrollBar* source)
        {
            m_source = source;
        }

        // 倍率只控制画出的线和命中带，不改原生 value/pageStep 的单位。
        void setScale(qreal scale)
        {
            m_scale = scale;
            update();
        }

        int hitThickness() const
        {
            return std::max(4, qRound(10.0 * m_scale));
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            if (maximum() <= minimum())
            {
                return;
            }
            const QRectF thumb = thumbRect();
            const qreal width = std::max(1.0, (m_hovered || isSliderDown() ? 5.0 : 3.0) * m_scale);
            QRectF line = thumb;
            if (orientation() == Qt::Vertical)
            {
                line.setLeft((this->width() - width) / 2.0);
                line.setWidth(width);
            }
            else
            {
                line.setTop((height() - width) / 2.0);
                line.setHeight(width);
            }
            // 使用当前宿主 palette 校准主题强调色，独立深浅浮窗也保持可见。
            const QPalette::ColorGroup group = isEnabled() ? QPalette::Active : QPalette::Disabled;
            const QColor color = KswordTheme::EnsureTextContrast(
                palette().color(group, QPalette::Highlight), palette().color(group, QPalette::Base), 3.0);
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setPen(Qt::NoPen);
            painter.setBrush(color);
            painter.drawRoundedRect(line, width / 2.0, width / 2.0);
        }

        void enterEvent(QEnterEvent* event) override
        {
            m_hovered = true;
            update();
            QScrollBar::enterEvent(event);
        }

        void leaveEvent(QEvent* event) override
        {
            m_hovered = false;
            update();
            QScrollBar::leaveEvent(event);
        }

        void mousePressEvent(QMouseEvent* event) override
        {
            if (event->button() != Qt::LeftButton || maximum() <= minimum())
            {
                event->ignore();
                return;
            }
            const QRectF thumb = thumbRect();
            const qreal point = axisPoint(event->position());
            m_dragOffset = thumb.contains(event->position())
                ? point - axisStart(thumb) : axisLength(thumb) / 2.0;
            const QPointer<FloatingScrollbar> alive(this);
            setSliderDown(true);
            if (alive.isNull())
            {
                return;
            }
            // 滑块按下会同步原条 sliderPressed，现有动画先停止再接收拖动。
            dragTo(point);
            event->accept();
        }

        void mouseMoveEvent(QMouseEvent* event) override
        {
            if (!isSliderDown())
            {
                event->ignore();
                return;
            }
            dragTo(axisPoint(event->position()));
            event->accept();
        }

        void mouseReleaseEvent(QMouseEvent* event) override
        {
            if (event->button() == Qt::LeftButton && isSliderDown())
            {
                const QPointer<FloatingScrollbar> alive(this);
                dragTo(axisPoint(event->position()));
                if (alive.isNull())
                {
                    return;
                }
                setSliderDown(false);
                if (alive.isNull())
                {
                    return;
                }
                update();
                event->accept();
                return;
            }
            event->ignore();
        }

        void hideEvent(QHideEvent* event) override
        {
            // 比较态、页面关闭或策略改变中断拖动时，也必须释放原条 sliderDown。
            if (isSliderDown())
            {
                setSliderDown(false);
            }
            QScrollBar::hideEvent(event);
        }

        void wheelEvent(QWheelEvent* event) override
        {
            const QPointer<QScrollBar> source = m_source;
            if (source.isNull())
            {
                event->ignore();
                return;
            }
            // 原样转发保留轴向、修饰键、触控板增量与嵌套边界传播，不造第二套动画。
            QCoreApplication::sendEvent(source.data(), event);
        }

    private:
        // 以下坐标辅助统一横纵轴；RTL 横轴沿用原生条的方向语义。
        qreal axisPoint(const QPointF& point) const
        {
            return orientation() == Qt::Vertical ? point.y() : point.x();
        }

        qreal axisStart(const QRectF& rect) const
        {
            return orientation() == Qt::Vertical ? rect.top() : rect.left();
        }

        qreal axisLength(const QRectF& rect) const
        {
            return orientation() == Qt::Vertical ? rect.height() : rect.width();
        }

        bool reversed() const
        {
            return invertedAppearance()
                != (orientation() == Qt::Horizontal && layoutDirection() == Qt::RightToLeft);
        }

        QRectF thumbRect() const
        {
            const qreal extent = orientation() == Qt::Vertical ? height() : width();
            const double range = static_cast<double>(static_cast<qint64>(maximum()) - minimum());
            const double page = std::max(0, pageStep());
            const qreal length = std::min(extent, std::max(24.0 * m_scale,
                range + page > 0.0 ? extent * page / (range + page) : extent));
            double ratio = range > 0.0
                ? (static_cast<double>(sliderPosition()) - minimum()) / range : 0.0;
            if (reversed())
            {
                ratio = 1.0 - ratio;
            }
            const qreal start = std::clamp(ratio, 0.0, 1.0) * std::max(0.0, extent - length);
            return orientation() == Qt::Vertical
                ? QRectF(0.0, start, width(), length) : QRectF(start, 0.0, length, height());
        }

        void dragTo(qreal point)
        {
            const QRectF thumb = thumbRect();
            const qreal extent = orientation() == Qt::Vertical ? height() : width();
            const qreal travel = extent - axisLength(thumb);
            if (travel <= 0.0)
            {
                return;
            }
            double ratio = std::clamp((point - m_dragOffset) / travel, 0.0, 1.0);
            if (reversed())
            {
                ratio = 1.0 - ratio;
            }
            // 先以 64 位计算量程，比例映射不会在 INT_MAX 或负量程端点溢出。
            const qint64 range = static_cast<qint64>(maximum()) - minimum();
            const qint64 position = static_cast<qint64>(minimum())
                + std::llround(ratio * static_cast<double>(range));
            setSliderPosition(static_cast<int>(std::clamp(position,
                static_cast<qint64>(minimum()), static_cast<qint64>(maximum()))));
        }

        QPointer<QScrollBar> m_source; // 唯一业务滚动条，销毁或替换后自动失效。
        qreal m_scale = 1.0;          // 当前浮窗倍率。
        qreal m_dragOffset = 0.0;     // 鼠标在滑块内部的按下位置。
        bool m_hovered = false;      // 悬停时仅加粗视觉线，不改命中带。
    };

    // 一个区域只拥有一个控制器，两个视觉条不占其 viewport 布局尺寸。
    class FloatingScrollbarController final : public QObject
    {
    public:
        explicit FloatingScrollbarController(QAbstractScrollArea* area)
            : QObject(area), m_area(area)
        {
            setObjectName(QString::fromLatin1(kControllerName));
            m_overlays[0] = new FloatingScrollbar(Qt::Vertical, area);
            m_overlays[1] = new FloatingScrollbar(Qt::Horizontal, area);
            area->installEventFilter(this);
            for (int axis = 0; axis < 2; ++axis)
            {
                FloatingScrollbar* overlay = m_overlays[axis].data();
                connect(overlay, &QScrollBar::sliderPressed, this, [this, axis]()
                {
                    if (!m_sources[axis].isNull())
                    {
                        m_sources[axis]->setSliderDown(true);
                    }
                });
                connect(overlay, &QScrollBar::sliderReleased, this, [this, axis]()
                {
                    if (!m_sources[axis].isNull())
                    {
                        m_sources[axis]->setSliderDown(false);
                    }
                });
                connect(overlay, &QScrollBar::sliderMoved, this, [this, axis](int position)
                {
                    if (!m_sources[axis].isNull())
                    {
                        m_sources[axis]->setSliderPosition(position);
                    }
                });
                connect(overlay, &QScrollBar::valueChanged, this, [this, axis](int value)
                {
                    if (!m_sources[axis].isNull())
                    {
                        m_sources[axis]->setValue(value);
                    }
                });
            }
        }

        void setScale(qreal scale)
        {
            m_scale = std::clamp(std::isfinite(scale) ? scale : 1.0, 0.25, 3.0);
            refresh();
        }

        void setInsets(const QMargins& insets)
        {
            m_insets = QMargins(std::max(0, insets.left()), std::max(0, insets.top()),
                std::max(0, insets.right()), std::max(0, insets.bottom()));
            refresh();
        }

        // 原条与视口均可能被业务重建，每次刷新先核验身份，再同步数值和几何。
        void refresh()
        {
            if (m_area.isNull() || m_updating)
            {
                return;
            }
            m_updating = true;
            if (m_viewport != m_area->viewport())
            {
                if (!m_viewport.isNull())
                {
                    m_viewport->removeEventFilter(this);
                }
                m_viewport = m_area->viewport();
                if (!m_viewport.isNull())
                {
                    m_viewport->installEventFilter(this);
                }
            }
            bindSource(0, m_area->verticalScrollBar());
            bindSource(1, m_area->horizontalScrollBar());
            const bool enabled = !preservesNative(m_area.data());
            if (m_area->property(kInstalledProperty).toBool() != enabled)
            {
                m_area->setProperty(kInstalledProperty, enabled);
            }
            for (int axis = 0; axis < 2; ++axis)
            {
                QScrollBar* source = m_sources[axis].data();
                if (source != nullptr)
                {
                    const QString style = enabled
                        ? collapsedStyle(source->styleSheet(), source->orientation())
                        : withoutOwnedStyle(source->styleSheet());
                    if (style != source->styleSheet())
                    {
                        source->setStyleSheet(style);
                    }
                    mirrorSource(axis);
                }
            }
            updateGeometry(enabled);
            m_updating = false;
        }

    protected:
        bool eventFilter(QObject*, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::Resize:
            case QEvent::LayoutRequest:
            case QEvent::Show:
            case QEvent::Hide:
            case QEvent::StyleChange:
            case QEvent::PaletteChange:
            case QEvent::FontChange:
            case QEvent::LayoutDirectionChange:
            case QEvent::ChildAdded:
            case QEvent::ChildRemoved:
            case QEvent::DynamicPropertyChange:
            case QEvent::EnabledChange:
                scheduleRefresh();
                break;
            case QEvent::Paint:
                // 原生条的步长/追踪开关没有变化信号；只在实际状态落后时补同步。
                // 不对每一帧无条件刷新，避免视觉条 update() 自己形成绘制循环。
                for (int axis = 0; axis < 2; ++axis)
                {
                    const QScrollBar* source = m_sources[axis].data();
                    const QScrollBar* overlay = m_overlays[axis].data();
                    if (source != nullptr && overlay != nullptr
                        && (source->pageStep() != overlay->pageStep()
                            || source->singleStep() != overlay->singleStep()
                            || source->hasTracking() != overlay->hasTracking()
                            || source->invertedAppearance() != overlay->invertedAppearance()
                            || source->invertedControls() != overlay->invertedControls()))
                    {
                        scheduleRefresh();
                        break;
                    }
                }
                break;
            default:
                break;
            }
            return false;
        }

    private:
        // 原条替换后仅恢复旧条自己的样式片段，不干涉任何业务连接。
        void bindSource(int axis, QScrollBar* source)
        {
            if (m_sources[axis] == source)
            {
                return;
            }
            for (const QMetaObject::Connection& connection : m_connections[axis])
            {
                disconnect(connection);
            }
            m_connections[axis].clear();
            if (!m_sources[axis].isNull())
            {
                QScrollBar* oldSource = m_sources[axis].data();
                oldSource->removeEventFilter(this);
                oldSource->setStyleSheet(withoutOwnedStyle(oldSource->styleSheet()));
            }
            m_sources[axis] = source;
            m_overlays[axis]->setSource(source);
            if (source == nullptr)
            {
                return;
            }
            source->installEventFilter(this);
            const auto changed = [this]() { scheduleRefresh(); };
            m_connections[axis].append(connect(source, &QScrollBar::rangeChanged, this, changed));
            m_connections[axis].append(connect(source, &QScrollBar::valueChanged, this, changed));
            m_connections[axis].append(connect(source, &QScrollBar::sliderMoved, this, changed));
            m_connections[axis].append(connect(source, &QObject::destroyed, this, changed));
        }

        // 屏蔽视觉镜像的回写信号，原条业务观察者仍完整收到源对象自己的变化。
        void mirrorSource(int axis)
        {
            QScrollBar* source = m_sources[axis].data();
            FloatingScrollbar* overlay = m_overlays[axis].data();
            if (source == nullptr || overlay == nullptr)
            {
                return;
            }
            const QSignalBlocker blocker(overlay);
            overlay->setRange(source->minimum(), source->maximum());
            overlay->setPageStep(source->pageStep());
            overlay->setSingleStep(source->singleStep());
            overlay->setTracking(source->hasTracking());
            overlay->setInvertedAppearance(source->invertedAppearance());
            overlay->setInvertedControls(source->invertedControls());
            overlay->setValue(source->value());
            overlay->setSliderPosition(source->sliderPosition());
            overlay->setLayoutDirection(m_area->layoutDirection());
            overlay->setEnabled(m_area->isEnabled() && source->isEnabled());
            if (overlay->palette() != m_area->palette())
            {
                overlay->setPalette(m_area->palette());
            }
            overlay->setScale(m_scale);
        }

        void updateGeometry(bool enabled)
        {
            const bool sourceSuspended = m_area->property(kComparisonSourceProperty).toBool();
            const bool visible = enabled && !sourceSuspended && m_area->isVisible()
                && !m_viewport.isNull() && m_viewport->isVisible();
            bool show[2] = { false, false };
            if (visible)
            {
                show[0] = m_area->verticalScrollBarPolicy() != Qt::ScrollBarAlwaysOff
                    && !m_sources[0].isNull() && m_sources[0]->maximum() > m_sources[0]->minimum();
                show[1] = m_area->horizontalScrollBarPolicy() != Qt::ScrollBarAlwaysOff
                    && !m_sources[1].isNull() && m_sources[1]->maximum() > m_sources[1]->minimum();
            }
            QRect content;
            if (!m_viewport.isNull())
            {
                content = QRect(m_viewport->mapTo(m_area.data(), QPoint(0, 0)), m_viewport->size());
                content.adjust(m_insets.left(), m_insets.top(), -m_insets.right(), -m_insets.bottom());
            }
            if (content.isEmpty())
            {
                show[0] = show[1] = false;
            }
            const int verticalWidth = show[0] ? std::min(content.width(), m_overlays[0]->hitThickness()) : 0;
            const int horizontalHeight = show[1] ? std::min(content.height(), m_overlays[1]->hitThickness()) : 0;
            const bool rightToLeft = m_area->layoutDirection() == Qt::RightToLeft;
            for (int axis = 0; axis < 2; ++axis)
            {
                FloatingScrollbar* overlay = m_overlays[axis].data();
                if (!show[axis])
                {
                    overlay->hide();
                    continue;
                }
                // 两轴相交处留空，不覆盖表头、动作条或冻结区，也不改视口留白。
                const QRect geometry = axis == 0
                    ? QRect(rightToLeft ? content.left() : content.right() - verticalWidth + 1,
                        content.top(), verticalWidth,
                        std::max(0, content.height() - horizontalHeight))
                    : QRect(content.left() + (rightToLeft ? verticalWidth : 0),
                        content.bottom() - horizontalHeight + 1,
                        std::max(0, content.width() - verticalWidth), horizontalHeight);
                overlay->setGeometry(geometry);
                overlay->setVisible(!geometry.isEmpty());
                overlay->raise();
                overlay->update();
            }
        }

        void scheduleRefresh()
        {
            if (m_pending || m_updating)
            {
                return;
            }
            m_pending = true;
            // 在当前原生事件栈返回后刷新，避免 setStyleSheet 的同步布局重入。
            QTimer::singleShot(0, this, [this]()
            {
                m_pending = false;
                refresh();
            });
        }

        QPointer<QAbstractScrollArea> m_area;       // 控制器唯一宿主。
        QPointer<QWidget> m_viewport;              // 可被 GPU 回退等业务替换的实际视口。
        QPointer<QScrollBar> m_sources[2];         // 两轴的原生业务条。
        QPointer<FloatingScrollbar> m_overlays[2]; // 两轴的纯视觉条。
        QVector<QMetaObject::Connection> m_connections[2]; // 原条更换时解除自己的连接。
        QMargins m_insets;                        // 页面右缘动作等显式避让距离。
        qreal m_scale = 1.0;                       // 当前浮窗内容倍率。
        bool m_pending = false;                   // 合并同一轮事件循环的布局刷新。
        bool m_updating = false;                  // 屏蔽样式应用产生的同步事件。
    };

    // 无 Q_OBJECT 的控制器用对象名定位后做 C++ 类型核验，不依赖新增 moc。
    FloatingScrollbarController* controllerFor(const QAbstractScrollArea* area)
    {
        if (area == nullptr)
        {
            return nullptr;
        }
        return dynamic_cast<FloatingScrollbarController*>(area->findChild<QObject*>(
            QString::fromLatin1(kControllerName), Qt::FindDirectChildrenOnly));
    }

    // 全局仅负责发现真正的 QAbstractScrollArea；自有 QChartView(QFrame)不进入此路径。
    class GlobalFloatingScrollbarFilter final : public QObject
    {
    public:
        explicit GlobalFloatingScrollbarFilter(QApplication* application)
            : QObject(application)
        {
            application->installEventFilter(this);
            for (QWidget* widget : QApplication::allWidgets())
            {
                if (auto* area = qobject_cast<QAbstractScrollArea*>(widget))
                {
                    queueInstall(area);
                }
            }
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::Polish:
            case QEvent::Show:
            case QEvent::LayoutRequest:
            case QEvent::ChildAdded:
            case QEvent::ChildRemoved:
            case QEvent::StyleChange:
            case QEvent::PaletteChange:
            case QEvent::DynamicPropertyChange:
                for (QWidget* widget = qobject_cast<QWidget*>(watched); widget != nullptr;
                    widget = widget->parentWidget())
                {
                    if (auto* area = qobject_cast<QAbstractScrollArea*>(widget))
                    {
                        queueInstall(area);
                        break;
                    }
                    if (widget->isWindow())
                    {
                        break;
                    }
                }
                break;
            default:
                break;
            }
            return false;
        }

    private:
        void queueInstall(QAbstractScrollArea* area)
        {
            if (m_pending.contains(area))
            {
                return;
            }
            const QPointer<QAbstractScrollArea> guarded(area);
            m_pending.insert(area, guarded);
            // QObject 构造期间的 ChildAdded 不立即判断子类；下一轮才安装，防止半构造接管。
            QTimer::singleShot(0, this, [this, guarded, area]()
            {
                m_pending.remove(area);
                if (!guarded.isNull())
                {
                    ks::ui::InstallFloatingScrollbars(guarded.data());
                }
            });
        }

        QHash<QAbstractScrollArea*, QPointer<QAbstractScrollArea>> m_pending; // 延迟发现去重。
    };

    QPointer<GlobalFloatingScrollbarFilter> g_filter; // 应用销毁时失效的唯一发现器。
}

namespace ks::ui
{
    void InstallGlobalFloatingScrollbars(QApplication* application)
    {
        if (application != nullptr && g_filter.isNull())
        {
            g_filter = new GlobalFloatingScrollbarFilter(application);
        }
    }

    void InstallFloatingScrollbars(QAbstractScrollArea* area)
    {
        if (area == nullptr)
        {
            return;
        }
        FloatingScrollbarController* controller = controllerFor(area);
        if (controller == nullptr)
        {
            if (preservesNative(area)
                || (area->verticalScrollBarPolicy() == Qt::ScrollBarAlwaysOff
                    && area->horizontalScrollBarPolicy() == Qt::ScrollBarAlwaysOff))
            {
                return;
            }
            controller = new FloatingScrollbarController(area);
        }
        controller->refresh();
    }

    void RefreshFloatingScrollbars(QAbstractScrollArea* area)
    {
        InstallFloatingScrollbars(area);
    }

    void SetFloatingScrollbarScale(QAbstractScrollArea* area, qreal scale)
    {
        InstallFloatingScrollbars(area);
        if (FloatingScrollbarController* controller = controllerFor(area))
        {
            controller->setScale(scale);
        }
    }

    void SetFloatingScrollbarInsets(QAbstractScrollArea* area, const QMargins& insets)
    {
        InstallFloatingScrollbars(area);
        if (FloatingScrollbarController* controller = controllerFor(area))
        {
            controller->setInsets(insets);
        }
    }

    bool HasFloatingScrollbars(const QAbstractScrollArea* area)
    {
        return controllerFor(area) != nullptr && !preservesNative(area)
            && area->property(kInstalledProperty).toBool();
    }
}
