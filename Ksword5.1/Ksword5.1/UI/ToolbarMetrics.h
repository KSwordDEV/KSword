#pragma once

#include <QAbstractButton>
#include <QEvent>
#include <QFontMetrics>
#include <QHBoxLayout>
#include <QAbstractSpinBox>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QToolButton>
#include <QPointer>
#include <QTimer>
#include <QVariant>
#include <algorithm>

namespace ks::ui
{
    // 已审核的单个按钮/单行输入控件也可接入统一几何，供 FlowLayout 等换行工具行使用。
    // height 为整行共同高度；0 表示按该控件字体计算，不修改文字、状态或业务配色。
    inline void NormalizeToolbarControl(QWidget* widget, int height = 0)
    {
        if (widget == nullptr)
        {
            return;
        }
        const int controlHeight = height > 0 ? height
            : std::max(28, QFontMetrics(widget->font()).height() + 12);
        widget->setFixedHeight(controlHeight);
        if (auto* button = qobject_cast<QAbstractButton*>(widget))
        {
            const QString geometryRule = QStringLiteral(
                "\nQPushButton[ksword_toolbar_control=\"true\"],"
                "QToolButton[ksword_toolbar_control=\"true\"]{padding:0px 10px;border-radius:5px;}");
            if (!button->property("ksword_toolbar_control").toBool())
            {
                button->setProperty("ksword_toolbar_control", true);
            }
            // 后续页面主题刷新可能替换局部 QSS；补回已登记几何且禁止重复追加。
            if (!button->styleSheet().contains(geometryRule))
            {
                button->setStyleSheet(button->styleSheet() + geometryRule);
            }
            button->setIconSize(QSize(16, 16));
            const auto* toolButton = qobject_cast<QToolButton*>(button);
            // 翻译绑定前的文字按钮也可能暂时没有文字，不能因此把它锁成一个图标方块。
            const bool explicitIconTool = toolButton && toolButton->toolButtonStyle() == Qt::ToolButtonIconOnly;
            const bool fixedIconAction = button->text().isEmpty()
                && button->minimumWidth() == button->maximumWidth() && button->maximumWidth() <= 40;
            if (!button->icon().isNull() && (explicitIconTool || fixedIconAction))
            {
                button->setFixedWidth(controlHeight);
                // 图标按钮保持方形，不能被文字按钮的横向留白压缩可见图标。
                button->setProperty("ksword_toolbar_icon_only", true);
                const QString iconRule = QStringLiteral(
                    "\nQPushButton[ksword_toolbar_icon_only=\"true\"],"
                    "QToolButton[ksword_toolbar_icon_only=\"true\"]{padding:0px;}" );
                if (!button->styleSheet().endsWith(iconRule))
                {
                    button->setStyleSheet(button->styleSheet() + iconRule);
                }
            }
        }
    }

    // 只接管页面明确登记的一行控件；全局主题不写高度，避免挤压标题栏和编辑器。
    class ToolbarRowMetrics final : public QObject
    {
    public:
        // row 完成添加控件后调用，随布局销毁；字号变化后按整行最高字体重新对齐。
        explicit ToolbarRowMetrics(QHBoxLayout* row) : QObject(row), m_row(row)
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
            if (event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange
                || event->type() == QEvent::StyleChange)
            {
                if (!m_pending)
                {
                    m_pending = true;
                    QTimer::singleShot(0, this, [this]()
                    {
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
                || qobject_cast<QComboBox*>(widget) || qobject_cast<QAbstractSpinBox*>(widget)
                || (label && !label->wordWrap());
        }

        void apply()
        {
            if (m_row.isNull())
            {
                return;
            }
            int height = 28; // 基础逻辑像素，Qt 负责设备 DPI；大字体不裁剪。
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget(); widget && isSingleLineControl(widget))
                {
                    height = std::max(height, QFontMetrics(widget->font()).height() + 12);
                }
            }
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget(); widget && isSingleLineControl(widget))
                {
                    NormalizeToolbarControl(widget, height);
                    m_row->setAlignment(widget, Qt::AlignVCenter);
                }
            }
        }

        QPointer<QHBoxLayout> m_row; // 页面原布局，不重建、不移动动作或改变连接。
        bool m_pending = false;     // 合并同一轮字体/样式事件，防止布局反馈循环。
    };

    // 一行只登记一次；调用方在该行全部控件插入后调用。
    inline void NormalizeToolbarRow(QHBoxLayout* row, int spacing = 8)
    {
        if (row == nullptr)
        {
            return;
        }
        // A/B 列组等有明确分段语义的行可显式传 0，普通工具行默认统一 8px。
        row->setSpacing(spacing);
        if (row->property("ksword_equal_control_height").toBool())
        {
            return;
        }
        row->setProperty("ksword_equal_control_height", true);
        new ToolbarRowMetrics(row);
    }
}
