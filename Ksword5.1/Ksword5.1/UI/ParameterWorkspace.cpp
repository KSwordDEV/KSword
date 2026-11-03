#include "../Framework.h"
#include "./ParameterWorkspace.h"
#include "./PrimaryPageStyle.h"
#include "./FlatButtonTheme.h"
#include "./ThemeBinding.h"
#include "./MainSurfaceStyle.h"
#include "./GroupBoxStyle.h"
#include "./ToolbarMetrics.h"
#include "./CodeTextEdit.h"
#include "./CodeEditorWidget.h"
#include "./StructuredFieldView.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QAbstractItemView>
#include <QAbstractSpinBox>
#include <QComboBox>
#include <QApplication>
#include <QCheckBox>
#include <QRadioButton>
#include <QFormLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QSplitter>
#include <QStyleOptionButton>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace
{
    // 明确登记的参数分区使用独立两列，在正常布局事件内按实际宽度选择列数。
    class ParameterColumns final : public QWidget
    {
    public:
        ParameterColumns(QWidget* parent, const QList<QWidget*>& primary,
            const QList<QWidget*>& secondary, const QList<QWidget*>& originalOrder, int minimumColumnWidth)
            : QWidget(parent), m_primary(primary), m_secondary(secondary), m_originalOrder(originalOrder),
            m_minimumColumnWidth(qMax(200, minimumColumnWidth))
        {
            setMinimumWidth(0);
            QSizePolicy policy(QSizePolicy::Ignored, QSizePolicy::Maximum);
            policy.setHeightForWidth(true);
            setSizePolicy(policy);
            m_columns = new QHBoxLayout(this);
            m_columns->setContentsMargins(0, 0, 0, 0);
            m_columns->setSpacing(16);

            // 两列各自使用自然高度，长分区不会把另一列的短分区撑成大块空白。
            m_primaryPanel = new QWidget(this);
            m_secondaryPanel = new QWidget(this);
            m_primaryPanel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Maximum);
            m_secondaryPanel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Maximum);
            m_primaryPanel->setMinimumWidth(0);
            m_secondaryPanel->setMinimumWidth(0);
            m_primaryLayout = createColumn(m_primaryPanel);
            m_secondaryLayout = createColumn(m_secondaryPanel);
            m_columns->addWidget(m_primaryPanel, 1, Qt::AlignTop);
            m_columns->addWidget(m_secondaryPanel, 1, Qt::AlignTop);
            m_primaryPanel->installEventFilter(this);
            m_secondaryPanel->installEventFilter(this);
            for (QWidget* section : m_originalOrder) section->installEventFilter(this);
            applyColumns(false);
        }
        bool hasHeightForWidth() const override { return true; }
        int heightForWidth(int availableWidth) const override
        {
            const bool twoColumns = availableWidth >= m_minimumColumnWidth * 2 + m_columns->spacing();
            const int columnWidth = twoColumns
                ? qMax(0, (availableWidth - m_columns->spacing()) / 2) : qMax(0, availableWidth);
            const auto columnHeight = [columnWidth](const QList<QWidget*>& sections)
            {
                int total = 0;
                int count = 0;
                for (QWidget* section : sections)
                {
                    QWidgetItem item(section);
                    if (item.isEmpty()) continue;
                    const int height = item.hasHeightForWidth()
                        ? item.heightForWidth(columnWidth) : item.sizeHint().height();
                    total += qBound(item.minimumSize().height(), height, item.maximumSize().height());
                    ++count;
                }
                return total + qMax(0, count - 1) * 16;
            };
            return twoColumns ? qMax(columnHeight(m_primary), columnHeight(m_secondary))
                : columnHeight(m_originalOrder);
        }
    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            // The outer layout caches this widget's custom heightForWidth.
            // Section visibility changes must invalidate that cache directly,
            // rather than waiting for both nested native column layouts.
            if (event->type() == QEvent::ShowToParent || event->type() == QEvent::HideToParent
                || event->type() == QEvent::LayoutRequest)
            {
                const QPointer<QObject> target(watched);
                updateGeometry();
                return target.isNull();
            }
            return QWidget::eventFilter(watched, event);
        }
        bool event(QEvent* event) override
        {
            const QPointer<ParameterColumns> alive(this);
            if (event->type() == QEvent::Show || event->type() == QEvent::LayoutRequest)
            {
                arrange();
                if (!alive) return true;
            }
            return QWidget::event(event);
        }
        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            arrange();
        }
    private:
        void arrange()
        {
            if (m_arranging || !m_columns) return;
            const bool twoColumns = width() >= m_minimumColumnWidth * 2 + m_columns->spacing();
            if (twoColumns == m_twoColumns) return;
            m_arranging = true;
            const QPointer<ParameterColumns> alive(this);
            applyColumns(twoColumns);
            if (!alive) return;
            m_columns->activate();
            if (!alive) return;
            m_primaryLayout->activate();
            if (!alive) return;
            if (twoColumns) m_secondaryLayout->activate();
            if (alive) m_arranging = false;
        }
        // 输入列容器，返回只在顶部排列且不传播硬最小宽度的纵向布局。
        static QVBoxLayout* createColumn(QWidget* panel)
        {
            auto* column = new QVBoxLayout(panel);
            column->setContentsMargins(0, 0, 0, 0);
            column->setSpacing(16);
            column->setAlignment(Qt::AlignTop);
            column->setSizeConstraint(QLayout::SetNoConstraint);
            return column;
        }
        void applyColumns(bool twoColumns)
        {
            const QPointer<ParameterColumns> alive(this);
            // 删除的只是布局项；业务分区、字段对象、折叠状态与已有信号连接继续保留。
            while (QLayoutItem* item = m_primaryLayout->takeAt(0)) delete item;
            while (QLayoutItem* item = m_secondaryLayout->takeAt(0)) delete item;
            const QList<QWidget*>& first = twoColumns ? m_primary : m_originalOrder;
            for (QWidget* section : first)
            {
                m_primaryLayout->addWidget(section);
                if (!alive) return;
            }
            if (twoColumns)
            {
                for (QWidget* section : m_secondary)
                {
                    m_secondaryLayout->addWidget(section);
                    if (!alive) return;
                }
            }
            m_secondaryPanel->setVisible(twoColumns);
            if (!alive) return;
            m_twoColumns = twoColumns;
            updateGeometry();
        }
        QList<QWidget*> m_primary; // 宽屏第一列中由页面明确选择的分区。
        QList<QWidget*> m_secondary; // 宽屏第二列中由页面明确选择的分区。
        QList<QWidget*> m_originalOrder; // 单列恢复原阅读顺序。
        QHBoxLayout* m_columns = nullptr; // 两列之间仅使用间隔，不增加边框。
        QWidget* m_primaryPanel = nullptr; // 第一列独立自然高度容器。
        QWidget* m_secondaryPanel = nullptr; // 第二列仅在空间足够时可见。
        QVBoxLayout* m_primaryLayout = nullptr;
        QVBoxLayout* m_secondaryLayout = nullptr;
        int m_minimumColumnWidth = 300; // 每列最少正文宽度。
        bool m_twoColumns = false;
        bool m_arranging = false;
    };

    // 只作用于明确登记的参数复选框/单选框。保留原文与对象，仅重绘标签并按宽度测量高度。
    class ParameterChoiceWrap final : public QObject
    {
    public:
        explicit ParameterChoiceWrap(QAbstractButton* button) : QObject(button), m_button(button)
        {
            button->setMinimumWidth(0);
            button->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
            button->setMinimumHeight(qMax(28, button->fontMetrics().height() + 6));
            button->installEventFilter(this);
            schedule();
        }
    protected:
        bool eventFilter(QObject*, QEvent* event) override
        {
            if (!m_button) return false;
            if (event->type() == QEvent::Paint)
            {
                QStyleOptionButton option = styleOption();
                QPainter painter(m_button);
                // 指示器继续由主题 QStyle 绘制，三态、禁用、按下、键盘状态不会变成假图标。
                m_button->style()->drawControl(isRadio() ? QStyle::CE_RadioButton : QStyle::CE_CheckBox,
                    &option, &painter, m_button);
                const QRect label = labelRect();
                const int flags = Qt::AlignVCenter | Qt::AlignLeading | Qt::TextWordWrap
                    | Qt::TextWrapAnywhere | (m_button->style()->styleHint(QStyle::SH_UnderlineShortcut, &option, m_button)
                        ? Qt::TextShowMnemonic : Qt::TextHideMnemonic);
                m_button->style()->drawItemText(&painter, label, flags, option.palette,
                    m_button->isEnabled(), m_button->text(), QPalette::WindowText);
                return true;
            }
            if (!m_forwarding && (event->type() == QEvent::MouseButtonPress
                || event->type() == QEvent::MouseButtonRelease || event->type() == QEvent::MouseMove
                || event->type() == QEvent::MouseButtonDblClick))
            {
                auto* mouse = static_cast<QMouseEvent*>(event);
                if (m_button->rect().contains(mouse->position().toPoint()))
                {
                    // 多行正文同样可点击。将行内命中交回原按钮指示器，原生按下/释放/拖出取消仍保留。
                    const QStyleOptionButton option = styleOption();
                    const QRect indicator = m_button->style()->subElementRect(isRadio()
                        ? QStyle::SE_RadioButtonIndicator : QStyle::SE_CheckBoxIndicator, &option, m_button);
                    const QPointF local = indicator.center();
                    QMouseEvent forwarded(mouse->type(), local, mouse->scenePosition(), mouse->globalPosition(),
                        mouse->button(), mouse->buttons(), mouse->modifiers(), mouse->pointingDevice());
                    forwarded.setTimestamp(mouse->timestamp());
                    m_forwarding = true;
                    QPointer<ParameterChoiceWrap> alive(this);
                    QApplication::sendEvent(m_button, &forwarded);
                    if (alive) m_forwarding = false;
                    event->setAccepted(forwarded.isAccepted());
                    return true;
                }
            }
            if (event->type() == QEvent::Show || event->type() == QEvent::LayoutRequest)
            {
                const QPointer<QAbstractButton> owner(m_button);
                m_pending = false;
                applyMetrics();
                return owner.isNull();
            }
            else if (event->type() == QEvent::Resize || event->type() == QEvent::FontChange
                || event->type() == QEvent::ApplicationFontChange || event->type() == QEvent::StyleChange
                || event->type() == QEvent::ScreenChangeInternal || event->type() == QEvent::LanguageChange)
                schedule();
            return false;
        }
    private:
        bool isRadio() const { return qobject_cast<QRadioButton*>(m_button.data()) != nullptr; }
        QStyleOptionButton styleOption() const
        {
            QStyleOptionButton option;
            option.initFrom(m_button);
            option.icon = m_button->icon();
            option.iconSize = m_button->iconSize();
            if (m_button->isDown()) option.state |= QStyle::State_Sunken;
            else option.state |= QStyle::State_Raised;
            const auto* check = qobject_cast<QCheckBox*>(m_button.data());
            if (check && check->checkState() == Qt::PartiallyChecked) option.state |= QStyle::State_NoChange;
            else option.state |= m_button->isChecked() ? QStyle::State_On : QStyle::State_Off;
            return option;
        }
        QRect labelRect() const
        {
            const QStyleOptionButton option = styleOption();
            const int indicator = m_button->style()->pixelMetric(isRadio()
                ? QStyle::PM_ExclusiveIndicatorWidth : QStyle::PM_IndicatorWidth, &option, m_button);
            return m_button->layoutDirection() == Qt::RightToLeft
                ? m_button->rect().adjusted(0, 3, -indicator - 7, -3)
                : m_button->rect().adjusted(indicator + 7, 3, 0, -3);
        }
        void schedule()
        {
            if (m_pending || m_applying) return;
            m_pending = true;
            if (m_button && m_button->isVisible())
                QCoreApplication::postEvent(m_button, new QEvent(QEvent::LayoutRequest));
        }
        void applyMetrics()
        {
            if (m_applying || !m_button || !m_button->isVisible() || m_button->width() <= 0) return;
            const int width = qMax(1, labelRect().width());
            const QFont font = m_button->font();
            const QString text = m_button->text();
            const int dpi = m_button->logicalDpiY();
            if (width == m_measuredWidth && font == m_measuredFont
                && text == m_measuredText && dpi == m_measuredDpi) return;
            m_measuredWidth = width;
            m_measuredFont = font;
            m_measuredText = text;
            m_measuredDpi = dpi;
            const int height = m_button->fontMetrics().boundingRect(QRect(0, 0, width, 10000),
                Qt::TextWordWrap | Qt::TextWrapAnywhere | Qt::TextHideMnemonic, text).height() + 6;
            const int needed = qMax(28, height);
            m_applying = true;
            const QPointer<ParameterChoiceWrap> alive(this);
            if (m_button->minimumHeight() != needed) m_button->setMinimumHeight(needed);
            if (alive) m_applying = false;
        }
        QPointer<QAbstractButton> m_button; // 原始业务控件，不复制 checked 或 text 状态。
        bool m_pending = false;
        bool m_forwarding = false;
        bool m_applying = false;
        int m_measuredWidth = -1;
        int m_measuredDpi = 0;
        QFont m_measuredFont;
        QString m_measuredText;
    };

    // 仅用于参数滚动正文：矩形、零圆角且由本模块对每个像素实填。
    // 外部卡片仍承担8px圆角，不能把这个契约扩散到普通面板或透明画布。
    class ParameterScrollCanvas final : public QWidget
    {
    public:
        explicit ParameterScrollCanvas(QWidget* parent)
            : QWidget(parent), m_surface(ks::ui::MainWindowSurfaceColors().content)
        {
            setAttribute(Qt::WA_OpaquePaintEvent, m_surface.alpha() == 255);
        }
        void setSurface(const QColor& surface)
        {
            const bool changed = m_surface != surface;
            m_surface = surface;
            setAttribute(Qt::WA_OpaquePaintEvent, m_surface.alpha() == 255);
            if (changed) update();
        }
    protected:
        bool event(QEvent* event) override
        {
            const bool handled = QWidget::event(event);
            if (event->type() == QEvent::Polish || event->type() == QEvent::StyleChange)
            {
                setAttribute(Qt::WA_OpaquePaintEvent, m_surface.alpha() == 255);
            }
            return handled;
        }
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.fillRect(rect(), m_surface);
        }
    private:
        QColor m_surface;
    };

    // 参数框架的色块自身无描边，只在操作区与正文之间留一条低对比度分隔线。
    void bindWorkspaceSurface(QWidget* widget, bool footer = false, bool canvas = false)
    {
        widget->setAttribute(Qt::WA_StyledBackground);
        widget->setProperty("ksword_parameter_surface", true);
        const QPointer<QWidget> target(widget);
        ks::ui::BindWidgetTheme(widget, [target, footer, canvas]()
        {
            if (!target) return;
            const bool transparent = ks::ui::UsesTransparentMainSurface(target);
            const QColor surface = transparent && canvas ? QColor(Qt::transparent)
                : ks::ui::MainControlSurfaceColor(ks::ui::MainWindowSurfaceColors().content, target);
            const QColor divider = KswordTheme::BlendColors(surface, KswordTheme::BorderColor(), 70);
            const QString style = QStringLiteral(
                "QWidget[ksword_parameter_surface=\"true\"]{background:%1;border:0;border-radius:%2px;%3}")
                .arg(surface.name(QColor::HexArgb)).arg(canvas ? 0 : 8).arg(footer
                    ? QStringLiteral("border-top:1px solid %1;border-top-left-radius:0;border-top-right-radius:0;").arg(divider.name())
                    : QString());
            target->setProperty("ksword_parameter_surface_style_block", style); // 完整中性容器块供按钮所有权识别。
            if (target->styleSheet() != style)
            {
                target->setStyleSheet(style); // 语言/重复palette通知不重写同一面板底色。
            }
            if (auto* scrollCanvas = dynamic_cast<ParameterScrollCanvas*>(target.data()))
            {
                // 与原有实底QSS使用同一颜色源；alpha不满时自动退出opaque快路径。
                scrollCanvas->setSurface(surface);
            }
        });
    }

    // 绘制小号空心折角，绕开平台 QStyle 默认的亮色大三角；点击与键盘仍由原按钮处理。
    class ParameterFoldButton final : public QToolButton
    {
    public:
        explicit ParameterFoldButton(QWidget* parent) : QToolButton(parent)
        {
            setCheckable(true);
            setMouseTracking(true);
            setAttribute(Qt::WA_Hover);
            setFocusPolicy(Qt::StrongFocus);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setMinimumHeight(30);
            connect(this, &QToolButton::toggled, this, [this]() { update(); });
        }
        QSize sizeHint() const override
        {
            return QSize(200, qMax(30, fontMetrics().height() + 10));
        }
        QSize minimumSizeHint() const override
        {
            // 标题已有省略与完整 tooltip，不让原生按钮的长文本宽度撑出横向滚动。
            return QSize(0, qMax(30, fontMetrics().height() + 10));
        }
    protected:
        void paintEvent(QPaintEvent*) override
        {
            const QColor panel = ks::ui::MainWindowSurfaceColors().content;
            QColor fill = KswordTheme::BlendColors(panel, KswordTheme::SurfaceAltColor(), 140);
            if (isDown()) fill = KswordTheme::ControlInputFocusColor(fill);
            else if (underMouse() || ks::ui::HasFlatButtonKeyboardFocus(this)) fill = KswordTheme::ControlInputHoverColor(fill);
            const QColor label = KswordTheme::EnsureTextContrast(isEnabled()
                ? KswordTheme::TextSecondaryColor() : KswordTheme::TextDisabledColor(), fill, isEnabled() ? 4.5 : 3.0);
            const QColor chevron = KswordTheme::EnsureTextContrast(
                KswordTheme::BlendColors(fill, label, 150), fill, 3.0);
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setPen(Qt::NoPen);
            painter.setBrush(ks::ui::MainControlSurfaceColor(fill, this));
            painter.drawRoundedRect(rect(), 5, 5);

            // 折角约 4×7 逻辑像素，低于正文的视觉权重，并跟随展开方向旋转。
            const bool rtl = layoutDirection() == Qt::RightToLeft;
            painter.save();
            painter.translate(rtl ? width() - 14.0 : 14.0, height() / 2.0);
            painter.rotate(isChecked() ? 90.0 : rtl ? 180.0 : 0.0);
            QPainterPath arrow;
            arrow.moveTo(-1.5, -3.0);
            arrow.lineTo(1.5, 0.0);
            arrow.lineTo(-1.5, 3.0);
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(chevron, 1.3, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter.drawPath(arrow);
            painter.restore();
            painter.setPen(label);
            painter.setFont(font());
            const QRect textArea = rect().adjusted(rtl ? 10 : 27, 0, rtl ? -27 : -10, 0);
            painter.drawText(textArea, Qt::AlignVCenter | (rtl ? Qt::AlignRight : Qt::AlignLeft),
                fontMetrics().elidedText(text(), Qt::ElideRight, textArea.width()));
        }
    };

    // 编辑输入是独立实底，结果日志与结果面板同底；同时同步 palette，避免行号栏仍沿用黑底。
    void styleWorkspaceEditors(QWidget* container)
    {
        if (!container) return;
        QList<QPlainTextEdit*> editors = container->findChildren<QPlainTextEdit*>();
        if (auto* self = qobject_cast<QPlainTextEdit*>(container)) editors.prepend(self);
        for (auto* editor : editors)
        {
            QFont textFont = editor->font();
            if (textFont.pixelSize() > 0) textFont.setPixelSize(qMax(14, textFont.pixelSize()));
            else textFont.setPointSizeF(qMax(10.0, textFont.pointSizeF()));
            if (editor->font() != textFont) editor->setFont(textFont);
            editor->setFrameShape(QFrame::NoFrame);
            const QPointer<QPlainTextEdit> target(editor);
            ks::ui::BindWidgetTheme(editor, [target]()
            {
                if (!target) return;
                const QColor panel = ks::ui::MainWindowSurfaceColors().content;
                const QColor input = ks::ui::UsesMainSurfaceHierarchy(target)
                    ? ks::ui::MainWindowSurfaceColors().input : KswordTheme::ControlInputSurfaceColor();
                const QColor base = target->isReadOnly() ? panel : input;
                const QColor text = KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), base, 4.5);
                const QColor placeholder = KswordTheme::EnsureTextContrast(KswordTheme::TextSecondaryColor(), base, 4.5);
                const QColor accent = KswordTheme::ControlAccentColor();
                const QColor disabledBase = KswordTheme::BlendColors(panel, base, 90);
                const QColor disabledText = KswordTheme::EnsureTextContrast(KswordTheme::TextDisabledColor(), disabledBase, 3.0);
                const QPalette previousColors = target->palette(); // 保存本轮前的角色，用于判断是否需要全文重高亮。
                const QString style = QStringLiteral(
                    "QPlainTextEdit{background:%1;color:%2;border:0;border-radius:5px;"
                    "selection-background-color:%3;selection-color:%4;placeholder-text-color:%5;}"
                    "QPlainTextEdit:disabled{background:%6;color:%7;}")
                    .arg(base.name(), text.name(), accent.name(), KswordTheme::OnAccentColor(accent).name(),
                        placeholder.name(), disabledBase.name(), disabledText.name());
                const bool styleChanged = target->styleSheet() != style;
                if (styleChanged) target->setStyleSheet(style);
                if (!target) return; // 样式事件可能关闭原宿主，继续写入前必须探活。
                QPalette colors = target->palette();
                colors.setColor(QPalette::Base, base);
                colors.setColor(QPalette::Window, base);
                colors.setColor(QPalette::Text, text);
                colors.setColor(QPalette::PlaceholderText, placeholder);
                colors.setColor(QPalette::Disabled, QPalette::Base, disabledBase);
                colors.setColor(QPalette::Disabled, QPalette::Window, disabledBase);
                colors.setColor(QPalette::Disabled, QPalette::Text, disabledText);
                colors.setColor(QPalette::Disabled, QPalette::PlaceholderText, disabledText);
                if (target->palette() != colors) target->setPalette(colors);
                if (!target) return;
                if (target->viewport()->palette() != colors) target->viewport()->setPalette(colors);
                if (!target) return;
                // CodeTextEdit的refreshThemeColors会全文rehighlight；颜色未变时不再重复执行。
                if (styleChanged || previousColors != colors)
                {
                    if (auto* code = dynamic_cast<CodeTextEdit*>(target.data())) code->refreshThemeColors();
                }
            });
        }
    }
}

namespace ks::ui
{
    void StyleParameterCanvas(QWidget* canvas)
    {
        if (canvas) bindWorkspaceSurface(canvas, false, true);
    }

    ParameterWorkspace::ParameterWorkspace(QWidget* parent, int parameterWidth)
        : QWidget(parent), m_parameterWidth(parameterWidth)
    {
        // 共享参数骨架拥有分栏、滚动和固定动作区；详情兼容框架只整理外围导航，避免二次接管。
        setProperty("ksword_parameter_workspace", true);
        // 放大正文而保留用户字体家族；Qt 负责 DPI，不改变应用级字号与其他专业视图。
        QFont body = font();
        if (body.pixelSize() > 0) body.setPixelSize(qMax(14, body.pixelSize()));
        else body.setPointSizeF(qMax(10.0, body.pointSizeF()));
        setFont(body);
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(0, 0, 0, 0);
        m_splitter = new QSplitter(Qt::Horizontal, this);
        m_splitter->setChildrenCollapsible(false);
        m_splitter->setHandleWidth(10);
        root->addWidget(m_splitter);

        // 参数面板与结果面板处于同一视觉层级，中间留白代替重复的大组框。
        m_parameterPanel = new QWidget(m_splitter);
        m_resultPanel = new QWidget(m_splitter);
        m_parameterPanel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        m_resultPanel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        bindWorkspaceSurface(m_parameterPanel);
        bindWorkspaceSurface(m_resultPanel);
        auto* left = new QVBoxLayout(m_parameterPanel);
        left->setContentsMargins(16, 16, 16, 16);
        left->setSpacing(0);
        m_scroll = new QScrollArea(m_parameterPanel);
        m_scroll->setWidgetResizable(true);
        m_scroll->setFrameShape(QFrame::NoFrame);
        m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        auto* form = new ParameterScrollCanvas(m_scroll);
        form->setProperty("ksword_parameter_body", true); // 默认组框据此选择分区结构，而非把结果卡片也当参数。
        form->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        form->setMinimumWidth(0);
        m_parameters = new QVBoxLayout(form);
        m_parameters->setContentsMargins(0, 0, 0, 0);
        m_parameters->setSpacing(16);
        m_parameters->setAlignment(Qt::AlignTop);
        m_scroll->setWidget(form);
        // QScrollArea的viewport与setWidget后的表单会自动填Window底色，不能继承页根的深色。
        // 三个承载层共用外部卡片色，内部不再叠圆角；仍由原视口承担滚动与裁剪。
        bindWorkspaceSurface(m_scroll, false, true);
        bindWorkspaceSurface(m_scroll->viewport(), false, true);
        bindWorkspaceSurface(form, false, true);
        left->addWidget(m_scroll, 1);

        auto* footer = new QWidget(m_parameterPanel);
        bindWorkspaceSurface(footer, true);
        m_actions = new QHBoxLayout(footer);
        m_actions->setContentsMargins(0, 12, 0, 0);
        m_actions->setSpacing(8);
        left->addWidget(footer);
        m_results = new QVBoxLayout(m_resultPanel);
        m_results->setContentsMargins(16, 16, 16, 16);
        m_results->setSpacing(8);
        m_splitter->setStretchFactor(0, 0);
        m_splitter->setStretchFactor(1, 1);
        setMinimumSize(0, 0);
    }

    QVBoxLayout* ParameterWorkspace::parameterHeader()
    {
        if (!m_parameterHeader)
        {
            auto* header = new QWidget(m_parameterPanel);
            bindWorkspaceSurface(header, false, true);
            m_parameterHeader = new QVBoxLayout(header);
            m_parameterHeader->setContentsMargins(0, 0, 0, 16);
            m_parameterHeader->setSpacing(8);
            static_cast<QVBoxLayout*>(m_parameterPanel->layout())->insertWidget(0, header);
        }
        return m_parameterHeader;
    }

    void ParameterWorkspace::enableHorizontalParameterScroll()
    {
        m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        m_scroll->widget()->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
        m_parameters->setSizeConstraint(QLayout::SetMinimumSize);
    }

    void ParameterWorkspace::revealParameter(QWidget* target)
    {
        const QPointer<QWidget> guarded(target);
        QTimer::singleShot(0, this, [this, guarded]()
        {
            if (guarded && m_scroll->widget()->isAncestorOf(guarded))
            {
                const QPointer<ParameterWorkspace> alive(this);
                m_scroll->ensureWidgetVisible(guarded, 16, 16);
                // 整列可能高于视口；横向露出该列后从列首开始阅读。
                if (alive && guarded)
                    m_scroll->verticalScrollBar()->setValue(guarded->mapTo(m_scroll->widget(), QPoint()).y());
            }
        });
    }

    // 页面显式选择参数密集布局；百分比只控制初次分配，后续尺寸由 QSplitter 保留。
    void ParameterWorkspace::useWideParameterLayout(int parameterPercent)
    {
        m_parameterPercent = qBound(40, parameterPercent, 70);
        m_splitter->setStretchFactor(0, 1);
        m_splitter->setStretchFactor(1, 1);
        m_positioned = false;
    }

    // 仅首次显示和宽窄布局转换重分配；两种方向独立记住拖动后的位置。
    void ParameterWorkspace::resizeEvent(QResizeEvent* event)
    {
        QWidget::resizeEvent(event);
        const auto orientation = width() < 860 ? Qt::Vertical : Qt::Horizontal;
        if (!m_positioned || m_splitter->orientation() != orientation)
        {
            if (m_positioned)
            {
                if (m_splitter->orientation() == Qt::Horizontal) m_horizontalSizes = m_splitter->sizes();
                else m_verticalSizes = m_splitter->sizes();
            }
            m_splitter->setOrientation(orientation);
            if (orientation == Qt::Horizontal)
            {
                const int available = qMax(1, width() - m_splitter->handleWidth());
                const int parameterSize = m_parameterPercent > 0
                    ? available * m_parameterPercent / 100 : m_parameterWidth;
                m_splitter->setSizes(m_horizontalSizes.isEmpty()
                    ? QList<int>{parameterSize, qMax(1, available - parameterSize)} : m_horizontalSizes);
            }
            else
            {
                m_splitter->setSizes(m_verticalSizes.isEmpty()
                    ? QList<int>{qMax(220, height() / 2), qMax(180, height() / 2)} : m_verticalSizes);
            }
            m_positioned = true;
        }
    }

    void ParameterWorkspace::finish()
    {
        StyleParameterFields(m_scroll->widget());
        StyleWorkspaceTextViews(m_scroll->widget());
        StyleWorkspaceTextViews(m_resultPanel);
        // 参数区按内容自然高度排列，禁止多行表单把剩余高度摊成巨大行间空白。
        for (auto* section : m_scroll->widget()->findChildren<QGroupBox*>())
        {
            if (section->property("ksword_parameter_section").toBool())
            {
                section->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Maximum);
                ConfigureGroupBoxLayout(section);
            }
        }
        NormalizeToolbarRow(m_actions);
        // 底栏是明确的普通操作区；未声明配色的独立动作显式接实底，避免被祖先容器QSS阻断。
        for (int index = 0; index < m_actions->count(); ++index)
        {
            auto* button = qobject_cast<QAbstractButton*>(m_actions->itemAt(index)->widget());
            if (!button || button->property("ksword_flat_button_managed").toBool()
                || HasWidgetThemeBinding(button))
            {
                continue; // 原危险色/强调色或专用动作状态继续由原拥有者维护。
            }
            QString colors = button->styleSheet(); // 仅剔除共享几何，真实业务局部配色不能硬替换。
            if (button->property("ksword_toolbar_control").toBool())
            {
                colors.remove(ToolbarControlGeometryStyle().trimmed());
            }
            if (button->property("ksword_toolbar_icon_only").toBool())
            {
                colors.remove(ToolbarIconGeometryStyle().trimmed());
            }
            if (colors.trimmed().isEmpty())
            {
                ApplyFlatButtonTheme(button, FlatButtonTone::Neutral, FlatButtonAppearance::Solid);
            }
        }
        m_actions->parentWidget()->setVisible(m_actions->count() > 0);
    }

    void StyleWorkspaceTextViews(QWidget* container)
    {
        styleWorkspaceEditors(container);
    }

    void ArrangeParameterColumns(QVBoxLayout* layout, const QList<QWidget*>& primary,
        const QList<QWidget*>& secondary, int minimumColumnWidth)
    {
        if (!layout || primary.isEmpty() || secondary.isEmpty()) return;
        QList<QWidget*> originalOrder; // 先记录原阅读顺序，窄屏恢复时不按宽屏列顺序拼接。
        for (int index = 0; index < layout->count(); ++index)
        {
            QWidget* section = layout->itemAt(index)->widget();
            if (section && (primary.contains(section) || secondary.contains(section))) originalOrder.append(section);
        }
        // 要求调用方先将全部分区加入原布局，避免遗漏分区或无意接管其它页面内容。
        if (originalOrder.size() != primary.size() + secondary.size()) return;
        const int insertion = layout->indexOf(originalOrder.first());
        for (QWidget* section : originalOrder) layout->removeWidget(section);
        auto* columns = new ParameterColumns(layout->parentWidget(), primary, secondary,
            originalOrder, minimumColumnWidth);
        layout->insertWidget(insertion, columns);
    }

    void StyleParameterSection(QGroupBox* group)
    {
        if (!group) return;
        group->setProperty("ksword_parameter_card", false);
        group->setProperty("ksword_parameter_section", true);
        StylePrimaryGroup(group);
        ConfigureGroupBoxLayout(group);
    }

    void StyleParameterCard(QGroupBox* group)
    {
        if (!group) return;
        group->setProperty("ksword_parameter_card", true);
        group->setProperty("ksword_parameter_section", false);
        group->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
        StylePrimaryGroup(group);
        ConfigureGroupBoxLayout(group);
    }

    void StyleParameterFields(QWidget* container)
    {
        if (!container) return;
        const auto ownsCompositeLayout = [](QWidget* widget)
        {
            return qobject_cast<QAbstractItemView*>(widget)
                || qobject_cast<StructuredFieldView*>(widget)
                || qobject_cast<CodeEditorWidget*>(widget)
                || widget->property("ksword_detail_projection").toBool()
                || widget->property("ksword_detail_keep_layout").toBool();
        };
        if (ownsCompositeLayout(container)) return;
        const auto isCompositeInterior = [container, ownsCompositeLayout](QWidget* widget)
        {
            for (QWidget* ancestor = widget; ancestor && ancestor != container;
                ancestor = ancestor->parentWidget())
            {
                if (ownsCompositeLayout(ancestor) || ancestor->isWindow()) return true;
            }
            return false;
        };
        const auto fields = container->findChildren<QWidget*>();
        for (QWidget* field : fields)
        {
            // Shared field/editor toolbars and professional viewports own their
            // internal metrics. Parameter forms only normalize their own fields.
            if (isCompositeInterior(field)) continue;
            if (auto* label = qobject_cast<QLabel*>(field))
            {
                label->setWordWrap(true);
                label->setMinimumWidth(0);
                label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
            }
            else if (qobject_cast<QCheckBox*>(field) || qobject_cast<QRadioButton*>(field))
            {
                // 明确的单行工具栏保留选项的自然宽度；Ignored 会让旁边的 stretch 吞掉标签。
                if (field->property("ksword_toolbar_control").toBool()) continue;
                if (!field->property("ksword_parameter_wrap_choice").toBool())
                {
                    field->setProperty("ksword_parameter_wrap_choice", true);
                    new ParameterChoiceWrap(static_cast<QAbstractButton*>(field));
                }
            }
            if (auto* combo = qobject_cast<QComboBox*>(field))
            {
                combo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
                combo->setMinimumContentsLength(8);
                combo->setMinimumWidth(0);
                combo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                StylePrimaryCombo(combo);
                StyleStandaloneInput(combo);
            }
            else if (auto* spin = qobject_cast<QAbstractSpinBox*>(field))
            {
                BindSpinBoxTheme(spin);
                NormalizeToolbarControl(spin);
                StyleStandaloneInput(spin);
            }
            else if (auto* edit = qobject_cast<QLineEdit*>(field))
            {
                if (qobject_cast<QComboBox*>(edit->parentWidget())
                    || qobject_cast<QAbstractSpinBox*>(edit->parentWidget())
                    || edit->property("ksword_page_search_style").toBool()) continue;
                NormalizeToolbarControl(edit);
                // 搜索、参数输入和数值框使用同一编辑层；这里只拥有紧凑表单的横向留白。
                BindLineEditTheme(edit);
                const QString current = edit->styleSheet();
                const QString geometry = WithParameterInputGeometry(current);
                if (current != geometry)
                {
                    edit->setProperty("ksword_parameter_input_padding", true);
                    if (!RequestStandaloneInputThemeGeometry(edit))
                        edit->setStyleSheet(geometry); // 已准备/自定义拥有者保留原即时几何。
                }
                StyleStandaloneInput(edit);
            }
        }
        for (auto* form : container->findChildren<QFormLayout*>())
        {
            if (isCompositeInterior(form->parentWidget())) continue;
            if (form->rowWrapPolicy() == QFormLayout::DontWrapRows)
                form->setRowWrapPolicy(QFormLayout::WrapLongRows);
            form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
            form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }

    QWidget* FoldParameterSection(QGroupBox* group, bool expanded)
    {
        auto* wrapper = new QWidget(group->parentWidget());
        wrapper->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
        auto* layout = new QVBoxLayout(wrapper);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);
        auto* toggle = new ParameterFoldButton(wrapper);
        toggle->setText(group->title());
        toggle->setToolTip(group->title());
        // 标题显示所有权转给折叠按钮；源组不再在语言切换后重新长出重复标题。
        ks::i18n::LanguageManager::instance().moveTextBinding(group, toggle, true);
        toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        toggle->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        toggle->setCheckable(true);
        toggle->setChecked(expanded);
        toggle->setMinimumHeight(30);
        group->setTitle(QString());
        StyleParameterSection(group);
        layout->addWidget(toggle);
        layout->addWidget(group);
        group->setVisible(expanded);
        QObject::connect(toggle, &QToolButton::toggled, group, [group, toggle](bool open)
        {
            group->setVisible(open);
            toggle->update();
        });
        return wrapper;
    }
}
