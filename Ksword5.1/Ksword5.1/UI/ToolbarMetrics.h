#pragma once

#include <QAbstractButton>
#include <QEvent>
#include <QFontMetrics>
#include <QHBoxLayout>
#include <QAbstractSpinBox>
#include <QComboBox>
#include <QLineEdit>
#include <QKeySequenceEdit>
#include <QLayout>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QPointer>
#include <QTimer>
#include <QVariant>
#include <algorithm>

namespace ks::ui
{
    // 返回本模块只拥有的几何规则；颜色组件可精确排除它，不误判为业务配色覆盖。
    inline QString ToolbarControlGeometryStyle()
    {
        return QStringLiteral(
            "\nQPushButton[ksword_toolbar_control=\"true\"],"
            "QToolButton[ksword_toolbar_control=\"true\"]{padding:0px 10px;border-radius:5px;}");
    }

    // 图标按钮的几何仅移除内边距，不能切断实际底色与 SVG 前景的状态绑定。
    inline QString ToolbarIconGeometryStyle()
    {
        return QStringLiteral(
            "\nQPushButton[ksword_toolbar_icon_only=\"true\"],"
            "QToolButton[ksword_toolbar_icon_only=\"true\"]{padding:0px;}");
    }

    // 已审核的单个按钮/单行输入控件也可接入统一几何，供 FlowLayout 等换行工具行使用。
    // height 为整行共同高度；0 表示按该控件字体计算，不修改文字、状态或业务配色。
    inline void NormalizeToolbarControl(QWidget* widget, int height = 0, bool updateStyle = true)
    {
        if (widget == nullptr)
        {
            return;
        }
        const QPointer<QWidget> target(widget);
        const int controlHeight = height > 0 ? height
            : std::max(28, widget->fontMetrics().height() + 12);
        widget->setFixedHeight(controlHeight);
        if (!target) return;
        if (auto* button = qobject_cast<QAbstractButton*>(widget))
        {
            const QString geometryRule = ToolbarControlGeometryStyle();
            if (!button->property("ksword_toolbar_control").toBool())
            {
                button->setProperty("ksword_toolbar_control", true);
                if (!target) return;
            }
            button->setIconSize(QSize(16, 16));
            if (!target) return;
            const auto* toolButton = qobject_cast<QToolButton*>(button);
            // 翻译绑定前的文字按钮也可能暂时没有文字，不能因此把它锁成一个图标方块。
            const bool explicitIconTool = toolButton && toolButton->toolButtonStyle() == Qt::ToolButtonIconOnly;
            const bool fixedIconAction = button->text().isEmpty()
                && button->minimumWidth() == button->maximumWidth()
                && (button->maximumWidth() <= 40 || button->property("ksword_toolbar_icon_only").toBool());
            const bool iconOnlyAction = !button->icon().isNull() && (explicitIconTool || fixedIconAction);
            if (iconOnlyAction)
            {
                button->setFixedWidth(controlHeight);
                if (!target) return;
                // 图标按钮保持方形，不能被文字按钮的横向留白压缩可见图标。
                button->setProperty("ksword_toolbar_icon_only", true);
                if (!target) return;
            }
            // Font/style notifications may arrive during first-paint theme preparation.
            // Keep measured geometry current without re-entering QSS polish in that stack.
            if (!updateStyle) return;
            // 几何QSS只匹配这两类按钮。给复选框/单选框追加无效规则会与
            // 它们的独立主题绑定互相覆盖，并经StyleChange/PaletteChange循环排队。
            if (!toolButton && !qobject_cast<QPushButton*>(button)) return;
            // 保留当前业务/主题配色，按原顺序一次补齐最终几何，避免首次图标按钮两次 polish。
            const QString currentStyle = button->styleSheet();
            QString finalStyle = currentStyle;
            if (!finalStyle.contains(geometryRule))
            {
                finalStyle += geometryRule;
            }
            if (iconOnlyAction)
            {
                const QString iconRule = ToolbarIconGeometryStyle();
                if (!finalStyle.endsWith(iconRule))
                {
                    finalStyle += iconRule;
                }
            }
            if (finalStyle != currentStyle)
            {
                button->setStyleSheet(finalStyle);
            }
        }
    }

    // 只接管页面明确登记的工具控件；支持单行、流式和网格布局。
    class ToolbarRowMetrics final : public QObject
    {
    public:
        // row 完成添加控件后调用，随布局销毁；字号变化后按整行最高字体重新对齐。
        explicit ToolbarRowMetrics(QLayout* row) : QObject(row), m_row(row)
        {
            for (int index = 0; index < row->count(); ++index)
            {
                if (QWidget* widget = row->itemAt(index)->widget())
                {
                    widget->installEventFilter(this);
                }
            }
            apply();
        }

    protected:
        bool eventFilter(QObject* source, QEvent* event) override
        {
            if (m_applying) return false;
            if (event->type() == QEvent::Polish || event->type() == QEvent::Show)
            {
                const QPointer<QObject> target(source);
                if (m_pending)
                {
                    m_pending = false;
                    ++m_generation;
                    apply();
                }
                return target.isNull();
            }
            if (event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange
                || event->type() == QEvent::ScreenChangeInternal)
            {
                const QPointer<QObject> target(source);
                apply(false);
                return target.isNull();
            }
            if (event->type() == QEvent::StyleChange)
            {
                // Defaults are installed once by the row constructor. A color/focus
                // refresh does not require measuring and styling the whole row again.
                const auto* button = qobject_cast<QAbstractButton*>(source);
                if (!button || (!qobject_cast<const QPushButton*>(button)
                    && !qobject_cast<const QToolButton*>(button))) return false;
                const QString style = button->styleSheet();
                if (style.contains(ToolbarControlGeometryStyle())
                    && (!button->property("ksword_toolbar_icon_only").toBool()
                        || style.endsWith(ToolbarIconGeometryStyle()))) return false;
                if (!m_pending)
                {
                    m_pending = true;
                    const quint64 generation = ++m_generation;
                    QTimer::singleShot(0, this, [this, generation]()
                    {
                        if (!m_pending || generation != m_generation) return;
                        m_pending = false;
                        apply();
                    });
                }
            }
            return QObject::eventFilter(source, event);
        }

    private:
        // 只统一单行交互控件和简短标签；内容视图、复合页面和多行说明保留布局尺寸。
        static bool isSingleLineControl(QWidget* widget)
        {
            const auto* label = qobject_cast<QLabel*>(widget);
            return qobject_cast<QAbstractButton*>(widget) || qobject_cast<QLineEdit*>(widget)
                || qobject_cast<QKeySequenceEdit*>(widget)
                || qobject_cast<QComboBox*>(widget) || qobject_cast<QAbstractSpinBox*>(widget)
                || widget->property("ksword_segmented_control").toBool()
                || (label && !label->wordWrap());
        }

        void apply(bool updateStyle = true)
        {
            if (m_row.isNull() || m_applying)
            {
                return;
            }
            m_applying = true;
            const QPointer<ToolbarRowMetrics> alive(this);
            int height = 28; // 基础逻辑像素，Qt 负责设备 DPI；大字体不裁剪。
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget(); widget && isSingleLineControl(widget))
                {
                    height = std::max(height, widget->fontMetrics().height() + 12);
                }
            }
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget(); widget && isSingleLineControl(widget))
                {
                    const QPointer<QWidget> target(widget);
                    NormalizeToolbarControl(widget, height, updateStyle);
                    if (!alive || !m_row) return;
                    if (target) m_row->setAlignment(target, Qt::AlignVCenter);
                }
            }
            m_applying = false;
        }

        QPointer<QLayout> m_row; // 页面原布局，不重建、不移动动作或改变连接。
        bool m_pending = false;     // 合并同一轮字体/样式事件，防止布局反馈循环。
        bool m_applying = false;
        quint64 m_generation = 0; // 首显消费后不让旧队列重复修改度量。
    };

    // 调用方先插入全部控件；自适应布局继续拥有自己的间距和换行规则。
    inline void NormalizeToolbarLayout(QLayout* row)
    {
        if (row == nullptr)
        {
            return;
        }
        if (row->property("ksword_equal_control_height").toBool())
        {
            return;
        }
        row->setProperty("ksword_equal_control_height", true);
        new ToolbarRowMetrics(row);
    }

    inline void NormalizeToolbarRow(QHBoxLayout* row, int spacing = 8)
    {
        if (row == nullptr) return;
        // A/B 分段仍可显式传0；普通单行工具保持既有8px规则。
        row->setSpacing(spacing);
        NormalizeToolbarLayout(row);
    }
}
