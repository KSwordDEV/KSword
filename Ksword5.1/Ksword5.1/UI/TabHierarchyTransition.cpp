#include "../Framework.h"
#include "./TabHierarchyTransition.h"
#include "../theme.h"

#include <QEvent>
#include <QPainter>
#include <QPointer>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVariantAnimation>
#include <algorithm>

namespace
{
    struct TabStripSnapshot
    {
        QPixmap image; // 子栏的完整绘制快照，保留当前字体、图标与设备像素比。
        QRect band; // 子栏在父级标签容器内的区域，动画只覆盖这一行。
        QColor background; // 动画留白区域使用子栏实际中性底色。
    };

    // 覆盖层挡住移动图像下方的旧命中位置，父级导航与数据区域仍能正常使用。
    class TabStripSlide final : public QWidget
    {
    public:
        TabStripSlide(QWidget* parent, TabStripSnapshot outgoing,
            TabStripSnapshot incoming, int direction)
            : QWidget(parent), m_outgoing(std::move(outgoing)),
              m_incoming(std::move(incoming)), m_direction(direction)
        {
            setFocusPolicy(Qt::NoFocus);
            setAttribute(Qt::WA_NoSystemBackground, true);
            const QRect band = m_incoming.band.isValid() ? m_incoming.band : m_outgoing.band;
            setGeometry(band);
            show();
            raise();
        }

        void setProgress(qreal progress)
        {
            m_progress = progress;
            update();
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this); // 每帧只画这一条导航，不重新绘制页面或读取模型。
            painter.setClipRect(rect());
            const QColor background = m_incoming.background.isValid()
                ? m_incoming.background : m_outgoing.background;
            painter.fillRect(rect(), background);
            const qreal distance = width(); // 整条导航移出边界后再恢复真实子栏。
            if (!m_outgoing.image.isNull())
            {
                painter.drawPixmap(QPointF(-m_direction * distance * m_progress, 0), m_outgoing.image);
            }
            if (!m_incoming.image.isNull())
            {
                painter.drawPixmap(QPointF(m_direction * distance * (1.0 - m_progress), 0), m_incoming.image);
            }
        }

    private:
        TabStripSnapshot m_outgoing; // 离开的父页对应的子栏。
        TabStripSnapshot m_incoming; // 进入的父页对应的子栏，可为空。
        int m_direction = 1; // 正数代表目标父 Tab 在右侧，负数代表在左侧。
        qreal m_progress = 0.0; // 单次动画的归一化进度。
    };

    // 一个父级只持有一个控制器；子栏惰性创建后登记，不改变父级原有激活连接。
    class ChildTabTransition final : public QObject
    {
    public:
        explicit ChildTabTransition(QTabWidget* tabs)
            : QObject(tabs), m_tabs(tabs), m_page(tabs->currentWidget()),
              m_motion(new QVariantAnimation(this))
        {
            setObjectName(QStringLiteral("ks_child_tab_transition"));
            tabs->installEventFilter(this);
            m_motion->setDuration(180);
            m_motion->setEasingCurve(QEasingCurve::OutCubic);
            m_motion->setStartValue(0.0);
            m_motion->setEndValue(1.0);
            connect(m_motion, &QVariantAnimation::valueChanged, this, [this](const QVariant& value)
            {
                if (m_overlay)
                {
                    m_overlay->setProgress(value.toReal());
                }
            });
            connect(m_motion, &QVariantAnimation::finished, this, [this]() { clearOverlay(); });
            connect(tabs, &QTabWidget::currentChanged, this, [this](int index) { switchPage(index); });
        }

        void addChild(QTabWidget* child)
        {
            if (!m_children.contains(child))
            {
                m_children.append(child);
            }
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            // 几何、字体或主题改变后立即归还真实栏位，避免使用已经过期的快照。
            if (event->type() == QEvent::Resize || event->type() == QEvent::Hide
                || event->type() == QEvent::FontChange || event->type() == QEvent::PaletteChange)
            {
                cancel();
            }
            return QObject::eventFilter(watched, event);
        }

    private:
        TabStripSnapshot snapshot(QWidget* page) const
        {
            if (!m_tabs || page == nullptr)
            {
                return {};
            }
            for (const QPointer<QTabWidget>& child : m_children)
            {
                if (!child || !page->isAncestorOf(child) || child->tabBar()->isHidden()
                    || !child->isVisibleTo(page))
                {
                    continue;
                }
                QTabBar* bar = child->tabBar(); // 隐藏的父页仍保留真实子栏几何。
                const QPoint origin = bar->mapTo(m_tabs, QPoint());
                const int availableWidth = std::min(child->width(), m_tabs->width() - origin.x());
                TabStripSnapshot result;
                result.band = QRect(origin, QSize(std::max(0, availableWidth), bar->height()));
                result.background = KswordTheme::SurfaceColor();
                result.image = bar->grab(); // 仅取导航快照，避免渲染数据页及惰性业务内容。
                return result;
            }
            return {};
        }

        void clearOverlay()
        {
            if (m_overlay)
            {
                m_overlay->hide();
                m_overlay->deleteLater();
                m_overlay.clear();
            }
        }

        void cancel()
        {
            ++m_generation;
            m_motion->stop();
            clearOverlay();
        }

        void switchPage(int index)
        {
            if (!m_tabs)
            {
                return;
            }
            QWidget* nextPage = m_tabs->widget(index);
            QWidget* previousPage = m_page;
            if (nextPage == previousPage)
            {
                return; // 拖动重排同一父 Tab 不触发页面切换动画。
            }
            const int oldIndex = m_tabs->indexOf(previousPage);
            const TabStripSnapshot outgoing = snapshot(previousPage);
            int direction = 1;
            if (oldIndex >= 0 && index >= 0)
            {
                // 使用视觉位置而非序号，RTL界面以及标签横向滚动也能保持正确方向。
                direction = m_tabs->tabBar()->tabRect(index).center().x()
                    > m_tabs->tabBar()->tabRect(oldIndex).center().x() ? 1 : -1;
            }
            m_page = nextPage;
            cancel();
            BOOL animationsEnabled = TRUE;
            SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animationsEnabled, 0);
            if (!animationsEnabled || !m_tabs->isVisible())
            {
                return;
            }
            const quint64 generation = m_generation;
            const QPointer<QWidget> page(nextPage);
            // 等父页原有惰性构建和布局结束后获取新子栏，连续切换取消旧排队任务。
            QTimer::singleShot(0, this, [this, page, outgoing, direction, generation]()
            {
                // 再让出一轮，使父级在同一currentChanged后排队的构建先完成；均按值捕获。
                QTimer::singleShot(0, this, [this, page, outgoing, direction, generation]()
                {
                    if (!m_tabs || !page || generation != m_generation || m_tabs->currentWidget() != page)
                    {
                        return;
                    }
                    const TabStripSnapshot incoming = snapshot(page);
                    if (outgoing.image.isNull() && incoming.image.isNull())
                    {
                        return;
                    }
                    m_overlay = new TabStripSlide(m_tabs, outgoing, incoming, direction);
                    m_motion->start();
                });
            });
        }

        QPointer<QTabWidget> m_tabs; // 父级业务标签容器。
        QPointer<QWidget> m_page; // 上一实际页面身份，不依赖可能变化的页序号。
        QList<QPointer<QTabWidget>> m_children; // 明确登记的子栏，生命周期由页面拥有。
        QVariantAnimation* m_motion; // 仅在切换的180ms内运转。
        QPointer<TabStripSlide> m_overlay; // 动画结束即移除的单行覆盖层。
        quint64 m_generation = 0; // 连续切换、尺寸或主题变化时取消过期回调。
    };

    void attachChildTabs(QTabWidget* child)
    {
        for (QWidget* owner = child->parentWidget(); owner != nullptr && !owner->isWindow();
            owner = owner->parentWidget())
        {
            auto* parent = qobject_cast<QTabWidget*>(owner);
            if (parent == nullptr)
            {
                continue;
            }
            auto* existing = parent->findChild<QObject*>(
                QStringLiteral("ks_child_tab_transition"), Qt::FindDirectChildrenOnly);
            auto* transition = existing != nullptr
                ? static_cast<ChildTabTransition*>(existing) : new ChildTabTransition(parent);
            transition->addChild(child);
            break;
        }
    }

    // 自建驱动页会跨Dock迁移；子栏显示时按当前父链接入，不能绑定创建时的旧宿主。
    class ChildTabAttachment final : public QObject
    {
    public:
        explicit ChildTabAttachment(QTabWidget* child) : QObject(child), m_child(child)
        {
            setObjectName(QStringLiteral("ks_child_tab_attachment"));
            child->installEventFilter(this);
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (m_child && (event->type() == QEvent::Show || event->type() == QEvent::ParentChange))
            {
                attachChildTabs(m_child);
            }
            return QObject::eventFilter(watched, event);
        }

    private:
        QPointer<QTabWidget> m_child; // 原业务子栏，不转移其父对象。
    };
}

namespace ks::ui
{
    void InstallParentTabTransition(QTabWidget* parentTabs)
    {
        if (parentTabs != nullptr && parentTabs->findChild<QObject*>(
            QStringLiteral("ks_child_tab_transition"), Qt::FindDirectChildrenOnly) == nullptr)
        {
            new ChildTabTransition(parentTabs);
        }
    }

    void InstallChildTabTransition(QTabWidget* childTabs)
    {
        if (childTabs == nullptr)
        {
            return;
        }
        if (childTabs->findChild<QObject*>(QStringLiteral("ks_child_tab_attachment"), Qt::FindDirectChildrenOnly) == nullptr)
        {
            new ChildTabAttachment(childTabs);
        }
        attachChildTabs(childTabs);
    }
}
