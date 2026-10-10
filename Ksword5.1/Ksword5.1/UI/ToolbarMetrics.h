#pragma once

#include <QAbstractButton>
#include <QEvent>
#include <QFontMetrics>
#include <QHBoxLayout>
#include <QPointer>
#include <QTimer>
#include <QVariant>
#include <algorithm>

namespace ks::ui
{
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
        void apply()
        {
            if (m_row.isNull())
            {
                return;
            }
            int height = 28; // 基础逻辑像素，Qt 负责设备 DPI；大字体不裁剪。
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget())
                {
                    height = std::max(height, QFontMetrics(widget->font()).height() + 12);
                }
            }
            for (int index = 0; index < m_row->count(); ++index)
            {
                if (QWidget* widget = m_row->itemAt(index)->widget())
                {
                    widget->setFixedHeight(height);
                    m_row->setAlignment(widget, Qt::AlignVCenter);
                    if (auto* button = qobject_cast<QAbstractButton*>(widget);
                        button != nullptr && button->text().isEmpty() && !button->icon().isNull())
                    {
                        button->setFixedWidth(height);
                    }
                }
            }
        }

        QPointer<QHBoxLayout> m_row; // 页面原布局，不重建、不移动动作或改变连接。
        bool m_pending = false;     // 合并同一轮字体/样式事件，防止布局反馈循环。
    };

    // 一行只登记一次；调用方在该行全部控件插入后调用。
    inline void NormalizeToolbarRow(QHBoxLayout* row)
    {
        if (row == nullptr || row->property("ksword_equal_control_height").toBool())
        {
            return;
        }
        row->setProperty("ksword_equal_control_height", true);
        new ToolbarRowMetrics(row);
    }
}
