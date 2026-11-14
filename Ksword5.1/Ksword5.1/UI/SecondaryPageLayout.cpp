#include "../Framework.h"
#include "./SecondaryPageLayout.h"
#include "./ThemeBinding.h"
#include "./FlatButtonTheme.h"
#include "./ToolbarMetrics.h"
#include "./PageTabMotion.h"
#include "./GroupBoxStyle.h"
#include "../theme.h"

#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QAbstractSpinBox>
#include <QComboBox>
#include <functional>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QToolButton>
#include <QStackedWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <algorithm>

namespace
{
    // 主题更新只替换自身块，保留页面的专用编辑器、提示色和其它局部规则。
    void SetOwnedStyle(QWidget* widget, const QString& rules)
    {
        const QString begin = QStringLiteral("/* ks_secondary_begin */");
        const QString end = QStringLiteral("/* ks_secondary_end */");
        QString style = widget->styleSheet(); // style 保存调用方已有的局部样式。
        const qsizetype first = style.indexOf(begin);
        const qsizetype last = first < 0 ? -1 : style.indexOf(end, first);
        if (first >= 0 && last >= first)
        {
            style.remove(first, last + end.size() - first);
        }
        const QString ownedBlock = begin + rules + end;
        widget->setProperty("ksword_secondary_style_block", ownedBlock);
        style = style.trimmed() + QLatin1Char('\n') + ownedBlock;
        if (widget->styleSheet() != style)
        {
            widget->setStyleSheet(style);
        }
    }

    // 已登记底栏只处理布局中的普通动作，不扫描其它页面或重置业务按钮状态/颜色。
    void styleFooterAction(QAbstractButton* button, QObject* observer = nullptr)
    {
        if (!qobject_cast<QPushButton*>(button) && !qobject_cast<QToolButton*>(button))
        {
            return;
        }
        const QPointer<QAbstractButton> alive(button);
        if (observer) button->installEventFilter(observer);
        ks::ui::NormalizeToolbarControl(button);
        if (!alive) return;
        QString remaining = button->styleSheet();
        remaining.remove(ks::ui::ToolbarControlGeometryStyle().trimmed());
        remaining.remove(ks::ui::ToolbarIconGeometryStyle().trimmed());
        if (button->property("ksword_flat_button_managed").toBool())
        {
            // managed标记可能在业务改成专用QSS后仍保留；只剔除实际共享块，不能抢回业务色。
            const QString begin = QStringLiteral("/*KSWORD_FLAT_BUTTON_BEGIN*/");
            const QString end = QStringLiteral("/*KSWORD_FLAT_BUTTON_END*/");
            const qsizetype first = remaining.indexOf(begin);
            const qsizetype last = first < 0 ? -1 : remaining.indexOf(end, first);
            if (first >= 0 && last >= first)
            {
                remaining.remove(first, last + end.size() - first);
            }
            if (button->property("ksword_flat_button_appearance").toInt()
                == static_cast<int>(ks::ui::FlatButtonAppearance::Auto)
                && remaining.trimmed().isEmpty())
            {
                ks::ui::ApplyFlatButtonTheme(button,
                    static_cast<ks::ui::FlatButtonTone>(button->property("ksword_flat_button_tone").toInt()),
                    ks::ui::FlatButtonAppearance::Solid);
            }
            return; // 显式Danger/Accent/Flat策略和其原信号由业务继续持有。
        }
        if (ks::ui::HasWidgetThemeBinding(button))
        {
            return;
        }
        if (remaining.trimmed().isEmpty())
        {
            ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
                ks::ui::FlatButtonAppearance::Solid);
        }
    }

    void collectFooterActions(QLayout* layout, QList<QPointer<QAbstractButton>>& actions)
    {
        if (!layout) return;
        for (int index = 0; index < layout->count(); ++index)
        {
            QLayoutItem* item = layout->itemAt(index);
            if (item->layout()) collectFooterActions(item->layout(), actions);
            else if (auto* box = qobject_cast<QDialogButtonBox*>(item->widget()))
                for (auto* button : box->buttons()) actions.append(button);
            else if (auto* button = qobject_cast<QAbstractButton*>(item->widget())) actions.append(button);
        }
    }

    void styleFooterLayout(QLayout* layout, QObject* observer = nullptr)
    {
        const QPointer<QLayout> alive(layout);
        QList<QPointer<QAbstractButton>> actions;
        collectFooterActions(layout, actions);
        for (const auto& button : actions)
        {
            if (!alive) return;
            if (button) styleFooterAction(button, observer);
        }
    }

    struct SecondaryStructure
    {
        int rows = 0;
        QList<QPointer<QAbstractButton>> actions;
        bool operator==(const SecondaryStructure& other) const
        { return rows == other.rows && actions == other.actions; }
    };

    // Only explicitly registered forms/footers participate. Geometry is ready
    // before their first layout/Show; the old queued callback becomes a no-op
    // when that work has already been consumed. No application-wide observer.
    class SecondaryGeometryPreparation final : public QObject
    {
    public:
        SecondaryGeometryPreparation(QObject* owner, std::function<QWidget*()> host,
            std::function<void(QObject*)> apply, std::function<SecondaryStructure()> structure)
            : QObject(owner), m_resolveHost(std::move(host)), m_apply(std::move(apply)),
              m_structure(std::move(structure))
        {
            owner->installEventFilter(this);
            refreshHost();
            schedule();
        }

        void refresh(bool changed = true)
        {
            m_dirty = m_dirty || changed;
            prepare();
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            const QPointer<QObject> alive(watched);
            if (event->type() == QEvent::Show || event->type() == QEvent::Polish)
            {
                if (watched == m_host) prepare();
            }
            else if (event->type() == QEvent::LayoutRequest)
            {
                // Qt posts this outside resize/layout calculation, before the
                // low-priority UpdateRequest which will paint the widget.
                if (watched == m_host) prepare();
            }
            else if (event->type() == QEvent::FontChange
                || event->type() == QEvent::ApplicationFontChange
                || event->type() == QEvent::ScreenChangeInternal)
            {
                if (!m_applying) schedule();
            }
            else if (event->type() == QEvent::ChildAdded || event->type() == QEvent::ChildRemoved)
            {
                if (!m_applying) schedule(); // A real child replacement can preserve rowCount().
            }
            return alive.isNull();
        }

    private:
        void refreshHost()
        {
            QWidget* host = m_resolveHost();
            if (host == m_host) return;
            if (m_host) m_host->removeEventFilter(this);
            m_host = host;
            if (m_host) m_host->installEventFilter(this);
        }

        void schedule(bool changed = true)
        {
            m_dirty = m_dirty || changed;
            if (m_pending) return;
            m_pending = true;
            QTimer::singleShot(0, this, [this]()
            {
                m_pending = false;
                prepare(true);
            });
        }

        void prepare(bool deferred = false)
        {
            if (m_applying) return;
            refreshHost();
            const SecondaryStructure structure = m_structure();
            if (!m_structureReady || !(structure == m_lastStructure)) m_dirty = true;
            if (!m_dirty) return;
            if (!deferred && m_host && (m_host->window()->windowType() == Qt::Popup
                || m_host->window()->windowType() == Qt::ToolTip))
            {
                schedule(); // Popup Show/Resize must not synchronously repolish.
                return;
            }
            m_dirty = false;
            m_lastStructure = structure;
            m_structureReady = true;
            m_applying = true;
            const QPointer<SecondaryGeometryPreparation> alive(this);
            const auto apply = m_apply;
            apply(this);
            if (alive) m_applying = false;
        }

        QPointer<QWidget> m_host;
        std::function<QWidget*()> m_resolveHost;
        std::function<void(QObject*)> m_apply;
        std::function<SecondaryStructure()> m_structure;
        SecondaryStructure m_lastStructure;
        bool m_structureReady = false;
        bool m_dirty = true;
        bool m_pending = false;
        bool m_applying = false;
    };

    QWidget* secondaryFormHost(const QFormLayout* form)
    {
        if (form->parentWidget()) return form->parentWidget();
        // Forms are often styled just before addLayout(). Existing fields
        // already belong to their final page even while the layout is unparented.
        for (int row = 0; row < form->rowCount(); ++row)
            for (const auto role : {QFormLayout::LabelRole, QFormLayout::FieldRole})
                if (QLayoutItem* item = form->itemAt(row, role); item && item->widget())
                    if (QWidget* host = item->widget()->parentWidget()) return host;
        return nullptr;
    }

    void prepareSecondaryForm(QFormLayout* form, QObject* observer)
    {
        const QPointer<QFormLayout> alive(form);
        const int labelWidth = form->property("ksword_secondary_label_width").toInt();
        for (int row = 0; alive && row < form->rowCount(); ++row)
        {
            QLayoutItem* labelItem = form->itemAt(row, QFormLayout::LabelRole);
            const QPointer<QLabel> label(labelItem ? qobject_cast<QLabel*>(labelItem->widget()) : nullptr);
            if (label)
            {
                label->installEventFilter(observer);
                if (label->minimumWidth() != labelWidth) label->setMinimumWidth(labelWidth);
                if (!alive) return;
                if (label && !label->wordWrap()) label->setWordWrap(true);
                if (!alive) return;
            }
            QLayoutItem* field = form->itemAt(row, QFormLayout::FieldRole);
            const QPointer<QWidget> control(field ? field->widget() : nullptr);
            if (control) control->installEventFilter(observer);
            if (qobject_cast<QLineEdit*>(control.data()) || qobject_cast<QComboBox*>(control.data())
                || qobject_cast<QAbstractSpinBox*>(control.data()))
                ks::ui::NormalizeToolbarControl(control);
        }
    }

    // 表单滚动区的建议高度来自真实内容；伸缩空白交给同页结果或预览。
    class SecondaryFormScroll final : public QScrollArea
    {
    public:
        SecondaryFormScroll(QWidget* content, QWidget* parent)
            : QScrollArea(parent)
        {
            setWidgetResizable(true);
            setFrameShape(QFrame::NoFrame);
            setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
            content->setMinimumWidth(0);
            setWidget(content);
            content->installEventFilter(this);
            viewport()->installEventFilter(this);
        }

        // 布局按当前宽度测量换行高度；不把表单区拉满窗口，也不固定字段行高。
        QSize sizeHint() const override
        {
            QSize hint = QScrollArea::sizeHint(); // 保留原视口的横向建议。
            if (widget())
            {
                QLayout* body = widget()->layout(); // 明确表单根布局，不扫描全部后代。
                const int measured = body && body->hasHeightForWidth()
                    ? body->totalHeightForWidth(std::max(1, viewport()->width()))
                    : widget()->sizeHint().height();
                hint.setHeight(std::max(0, measured) + frameWidth() * 2);
            }
            return hint;
        }

    protected:
        // 尺寸、字体与分栏变化合并更新建议高度；值未变化时不反复触发布局。
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event->type() == QEvent::Resize || event->type() == QEvent::LayoutRequest
                || event->type() == QEvent::FontChange || event->type() == QEvent::Show)
            {
                if (!m_pending)
                {
                    m_pending = true;
                    QTimer::singleShot(0, this, [this]()
                    {
                        m_pending = false;
                        const QSize hint = sizeHint(); // 最新宽度对应的自然内容高度。
                        if (hint != m_lastHint)
                        {
                            m_lastHint = hint;
                            updateGeometry();
                        }
                    });
                }
            }
            return QScrollArea::eventFilter(watched, event);
        }

    private:
        bool m_pending = false; // 合并同一轮事件中的布局变化。
        QSize m_lastHint; // 避免没有真实高度变化时循环安排布局。
    };

    // 双栏只在容器宽度跨阈值时重新排列，避免每次内容刷新都重建表单。
    class SecondaryColumns final : public QWidget
    {
    public:
        SecondaryColumns(QWidget* primary, QWidget* secondary, QWidget* parent,
            int breakpoint, int primaryStretch, int secondaryStretch)
            : QWidget(parent), m_primary(primary), m_secondary(secondary),
              m_breakpoint(breakpoint), m_primaryStretch(primaryStretch),
              m_secondaryStretch(secondaryStretch), m_grid(new QGridLayout(this))
        {
            // 横向尺寸由宿主分配，内容高度仍保留，供页面内部滚动计算。
            setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            m_grid->setContentsMargins(0, 0, 0, 0);
            m_grid->setHorizontalSpacing(24);
            m_grid->setVerticalSpacing(12);
            primary->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            secondary->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            // 初次按低高度的双栏测量；拿到真实宽度后再收为单列，避免先撑高宽窗。
            arrange(true);
        }

        QSize minimumSizeHint() const override
        {
            return QSize(0, QWidget::minimumSizeHint().height());
        }

    protected:
        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            scheduleArrange();
        }

        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            prepareArrangement();
        }

        bool event(QEvent* event) override
        {
            if (event->type() == QEvent::LayoutRequest)
            {
                m_pending = false;
                const QPointer<SecondaryColumns> alive(this);
                prepareArrangement();
                if (!alive) return true;
            }
            return QWidget::event(event);
        }

        void changeEvent(QEvent* event) override
        {
            QWidget::changeEvent(event);
            if (event->type() == QEvent::FontChange)
            {
                scheduleArrange();
            }
        }

    private:
        // Normal-priority layout work precedes the low-priority paint request;
        // resizing itself never rebuilds the layout recursively.
        void scheduleArrange()
        {
            if (m_pending) return;
            m_pending = true;
            QCoreApplication::postEvent(this, new QEvent(QEvent::LayoutRequest));
        }

        void prepareArrangement()
        {
            if (m_arranging) return;
            const int threshold = m_breakpoint * std::max(14, fontMetrics().height()) / 14;
            const bool wide = width() >= threshold;
            if (wide == m_wide) return;
            m_arranging = true;
            const QPointer<SecondaryColumns> alive(this);
            arrange(wide);
            if (!alive) return;
            m_grid->activate();
            if (alive) m_arranging = false;
        }

        void arrange(bool wide)
        {
            m_grid->removeWidget(m_primary);
            m_grid->removeWidget(m_secondary);
            m_grid->addWidget(m_primary, 0, 0, Qt::AlignTop);
            m_grid->addWidget(m_secondary, wide ? 0 : 1, wide ? 1 : 0, Qt::AlignTop);
            m_grid->setColumnStretch(0, wide ? m_primaryStretch : 1);
            m_grid->setColumnStretch(1, wide ? m_secondaryStretch : 0);
            m_wide = wide;
            updateGeometry();
        }

        QWidget* m_primary; // 左侧或上方的主要配置区，由容器持有。
        QWidget* m_secondary; // 右侧或下方的辅助区，始终保持可见。
        int m_breakpoint; // 正常字号下切换为两列的宽度。
        int m_primaryStretch; // 宽布局左列的宽度权重。
        int m_secondaryStretch; // 宽布局右列的宽度权重。
        QGridLayout* m_grid; // 唯一布局，重新排列时不重建业务控件。
        bool m_wide = false; // 当前是否并列显示。
        bool m_pending = false; // 合并连续尺寸和字体变化。
        bool m_arranging = false; // 不在布局激活产生的嵌套事件内重排。
    };
}

namespace ks::ui
{
    // 仅供明确的表单/预览混合页调用，普通整页设置滚动区仍保留原行为。
    QWidget* CreateSecondaryFormScroll(QWidget* content, QWidget* parent)
    {
        return content ? new SecondaryFormScroll(content, parent) : nullptr;
    }

    void StyleSecondaryManagerWindow(QWidget* window)
    {
        if (!window) return;
        window->setProperty("ksword_secondary_keep_layout", true);
        StyleSecondaryWindow(window);
    }

    void StyleSecondaryWindow(QWidget* window)
    {
        if (window == nullptr || window->property("ksword_secondary_window").toBool())
        {
            return;
        }
        window->setProperty("ksword_secondary_window", true);
        window->setAttribute(Qt::WA_StyledBackground, true);
        // 部分页面在登记前已触发过旧弹窗兜底，先移除它拥有的尾块，避免两套样式竞争。
        QString ownedStyle = window->styleSheet();
        const QString oldStyle = ownedStyle;
        const qsizetype oldBlock = oldStyle.indexOf(QStringLiteral("/* KSWORD_GLOBAL_DIALOG_THEME_BEGIN */"));
        if (oldBlock >= 0)
        {
            ownedStyle = oldStyle.left(oldBlock);
        }
        // Late enrollment must also relinquish an already installed detail block.
        // Otherwise the secondary binding and detail controller keep moving their
        // own blocks to the end and trigger each other's palette/style refresh.
        const QString detailBegin = QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_BEGIN */");
        const QString detailEnd = QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_END */");
        const qsizetype detailFirst = ownedStyle.indexOf(detailBegin);
        const qsizetype detailLast = detailFirst < 0 ? -1 : ownedStyle.indexOf(detailEnd, detailFirst);
        if (detailFirst >= 0 && detailLast >= detailFirst)
        {
            ownedStyle.remove(detailFirst, detailLast + detailEnd.size() - detailFirst);
        }
        if (ownedStyle != oldStyle)
        {
            window->setStyleSheet(ownedStyle);
        }
        const QPointer<QWidget> target(window); // 窗口关闭后不再执行排队的主题刷新。
        BindWidgetTheme(window, [target]()
        {
            if (!target)
            {
                return;
            }
            // 显式窗口底面避免继承主窗口透明背景；输入与内容只用中性色区分。
            const QString rules = QStringLiteral(
                "QWidget[ksword_secondary_window=\"true\"]{background:%1;color:%2;}"
                "QWidget[ksword_secondary_window=\"true\"] QLabel{background:transparent;}"
                "QWidget[ksword_secondary_window=\"true\"] QScrollArea#ks_adaptive_page_scroll{border:0;background:transparent;}"
                "QWidget[ksword_secondary_window=\"true\"] QMenu{background:%3;color:%2;border:1px solid %4;}"
                "QWidget[ksword_secondary_window=\"true\"] QMenu::item:selected{background:%6;color:%7;}"
                "QWidget[ksword_secondary_window=\"true\"] QMenu::item:disabled{color:%5;}")
                .arg(KswordTheme::WindowColor().name(), KswordTheme::TextPrimaryColor().name(),
                    KswordTheme::ControlInputSurfaceColor().name(), KswordTheme::BorderColor().name(),
                    KswordTheme::TextDisabledColor().name(), KswordTheme::ControlAccentColor().name(),
                    KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()).name());
            SetOwnedStyle(target, rules);
        });
    }

    void StyleSecondaryTabs(QTabWidget* tabs)
    {
        if (tabs == nullptr || tabs->property("ksword_secondary_tabs").toBool())
        {
            return;
        }
        tabs->setProperty("ksword_secondary_tabs", true);
        tabs->setTabPosition(QTabWidget::North);
        tabs->setDocumentMode(true);
        // 栈与标签栏不将隐藏页的最小高度传给窗口；每页保留自己的滚动语义。
        if (auto* stack = tabs->findChild<QStackedWidget*>())
        {
            stack->setMinimumSize(0, 0);
            stack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        }
        tabs->setStyleSheet(tabs->styleSheet() + QStringLiteral(
            "QTabWidget[ksword_secondary_tabs=\"true\"]::pane{border:0;padding:0;margin:0;background:transparent;}"));
        QTabBar* bar = tabs->tabBar(); // 只绑定明确传入的栏，不修改全局或详情导航。
        if (bar->property("ksword_page_tabs_style").toBool())
        {
            bar->setStyleSheet(QString());
        }
        bar->setProperty("ksword_secondary_tabs", true);
        bar->setExpanding(false);
        bar->setUsesScrollButtons(true);
        InstallPageTabMotion(bar, []()
        {
            const QColor selected = KswordTheme::WindowColor();
            return PageTabMotionColors{selected, KswordTheme::EnsureTextContrast(
                KswordTheme::ControlAccentColor(), selected, 3.0)};
        });
        const QPointer<QTabBar> target(bar);
        BindWidgetTheme(bar, [target]()
        {
            if (!target)
            {
                return;
            }
            const QColor base = KswordTheme::WindowColor();
            const QString rules = QStringLiteral(
                "QTabBar[ksword_secondary_tabs=\"true\"]{background:transparent;border-bottom:1px solid %1;}"
                "QTabBar[ksword_secondary_tabs=\"true\"]::tab{background:transparent;color:%2;"
                "border:0;border-bottom:2px solid transparent;padding:8px 14px;margin:0;min-height:16px;}"
                "QTabBar[ksword_secondary_tabs=\"true\"]::tab:selected{color:%3;border-bottom-color:transparent;}"
                "QTabBar[ksword_secondary_tabs=\"true\"]::tab:hover{background:%4;color:%3;}"
                "QTabBar[ksword_secondary_tabs=\"true\"]::tab:disabled{color:%5;}")
                .arg(KswordTheme::BorderColor().name(), KswordTheme::TextSecondaryColor().name(),
                    KswordTheme::TextPrimaryColor().name(),
                    KswordTheme::BlendColors(base, KswordTheme::ControlAccentColor(), 16).name(),
                    KswordTheme::TextDisabledColor().name());
            SetOwnedStyle(target, rules + (target->property("ksword_settings_tabs").toBool()
                ? QStringLiteral("QTabBar[ksword_settings_tabs=\"true\"]::tab:selected{font-weight:600;}") : QString()));
        });
    }

    void StyleSecondarySection(QGroupBox* section)
    {
        if (section == nullptr || section->property("ksword_secondary_section").toBool())
        {
            return;
        }
        section->setProperty("ksword_secondary_section", true);
        const QPointer<QGroupBox> target(section);
        BindWidgetTheme(section, [target]()
        {
            if (!target)
            {
                return;
            }
            // 设置页可隔着零边距列壳借用外层留白，窄边距工具页仍由卡片拥有16px内距。
            bool embedded = false; // 只读取当前窗口内实际存在的外围布局，不改动祖先。
            const bool settings = target->property("ksword_settings_section").toBool();
            QWidget* const content = target->parentWidget(); // 普通分区只借用直属内容壳。
            for (QWidget* outer = content; outer; outer = outer->parentWidget())
            {
                if (outer != content && (!settings || qobject_cast<QGroupBox*>(outer))) break;
                if (const QLayout* layout = outer->layout())
                {
                    const QMargins margins = layout->contentsMargins();
                    if (margins.left() != 0 || margins.right() != 0)
                    {
                        embedded = margins.left() >= 16 && margins.right() >= 16;
                        break; // 最近的侧边留白就是当前内容边界，不能继续借用更外层页根。
                    }
                }
                if (outer->isWindow()) break;
            }
            ConfigureGroupBoxLayout(target);
            SetOwnedStyle(target, GroupBoxStyle(
                QStringLiteral("QGroupBox[ksword_secondary_section=\"true\"]"),
                QStringLiteral("transparent"), KswordTheme::TextSecondaryColor().name(),
                KswordTheme::TextDisabledColor().name(), target->fontMetrics().height(),
                embedded, !target->title().isEmpty()));
        });
    }

    void StyleSecondaryForm(QFormLayout* form, int labelWidth)
    {
        if (form == nullptr)
        {
            return;
        }
        if (form->horizontalSpacing() != 18) form->setHorizontalSpacing(18);
        if (form->verticalSpacing() != 8) form->setVerticalSpacing(8);
        if (form->labelAlignment() != (Qt::AlignLeft | Qt::AlignVCenter)) form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        if (form->formAlignment() != (Qt::AlignLeft | Qt::AlignTop)) form->setFormAlignment(Qt::AlignLeft | Qt::AlignTop);
        if (form->fieldGrowthPolicy() != QFormLayout::AllNonFixedFieldsGrow) form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        if (form->rowWrapPolicy() != QFormLayout::WrapLongRows) form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        const bool labelWidthChanged = form->property("ksword_secondary_label_width").toInt() != labelWidth;
        if (labelWidthChanged) form->setProperty("ksword_secondary_label_width", labelWidth);
        auto* metrics = static_cast<SecondaryGeometryPreparation*>(
            form->property("ksword_secondary_form_metrics").value<QObject*>());
        if (!metrics)
        {
            const QPointer<QFormLayout> target(form);
            metrics = new SecondaryGeometryPreparation(form,
                [target]() { return target ? secondaryFormHost(target) : nullptr; },
                [target](QObject* observer) { if (target) prepareSecondaryForm(target, observer); },
                [target]() { return SecondaryStructure{target ? target->rowCount() : 0, {}}; });
            form->setProperty("ksword_secondary_form_metrics", QVariant::fromValue<QObject*>(metrics));
        }
        metrics->refresh(labelWidthChanged);
    }

    void StyleSecondaryFooter(QWidget* footer)
    {
        if (footer == nullptr || footer->property("ksword_secondary_footer").toBool())
        {
            return;
        }
        footer->setProperty("ksword_secondary_footer", true);
        footer->setAttribute(Qt::WA_StyledBackground, true);
        if (footer->layout() != nullptr)
        {
            footer->layout()->setContentsMargins(16, 8, 16, 8);
            footer->layout()->setSpacing(8);
        }
        const QPointer<QWidget> actions(footer);
        auto* preparation = new SecondaryGeometryPreparation(footer,
            [actions]() { return actions.data(); }, [actions](QObject* observer)
            {
                if (!actions) return;
                if (auto* box = qobject_cast<QDialogButtonBox*>(actions.data()))
                {
                    QList<QPointer<QAbstractButton>> buttons;
                    for (auto* button : box->buttons()) buttons.append(button);
                    for (const auto& button : buttons)
                    {
                        if (button) styleFooterAction(button, observer);
                        if (!actions) return;
                    }
                }
                else styleFooterLayout(actions->layout(), observer);
            }, [actions]()
            {
                SecondaryStructure structure;
                if (!actions) return structure;
                if (auto* box = qobject_cast<QDialogButtonBox*>(actions.data()))
                    for (auto* button : box->buttons()) structure.actions.append(button);
                else collectFooterActions(actions->layout(), structure.actions);
                return structure;
            });
        preparation->refresh();
        if (!actions) return;
        const QPointer<QWidget> target(actions);
        BindWidgetTheme(footer, [target]()
        {
            if (target)
            {
                SetOwnedStyle(target, QStringLiteral(
                    "QWidget[ksword_secondary_footer=\"true\"]{background:%1;border:0;border-top:1px solid %2;}")
                    .arg(KswordTheme::WindowColor().name(), KswordTheme::BorderColor().name()));
            }
        });
    }

    void StyleSecondaryButtonBox(QDialogButtonBox* buttons)
    {
        if (buttons == nullptr)
        {
            return;
        }
        StyleSecondaryFooter(buttons);
        // 保留默认、取消及业务角色；只规范按钮大小，不重新连接 accepted/rejected。
        for (QAbstractButton* button : buttons->buttons())
        {
            NormalizeToolbarControl(button);
            button->setMinimumWidth(std::max(76, button->minimumWidth()));
        }
    }

    void StyleSecondaryContentLayout(QLayout* layout)
    {
        if (layout != nullptr)
        {
            layout->setContentsMargins(16, 12, 16, 12);
            layout->setSpacing(12);
        }
    }

    QWidget* CreateSecondaryColumns(QWidget* primary, QWidget* secondary,
        QWidget* parent, int breakpoint, int primaryStretch, int secondaryStretch)
    {
        if (primary == nullptr || secondary == nullptr)
        {
            return nullptr;
        }
        return new SecondaryColumns(primary, secondary, parent, breakpoint, primaryStretch, secondaryStretch);
    }
}
