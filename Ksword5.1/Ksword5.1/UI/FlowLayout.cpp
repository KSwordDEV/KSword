#include "FlowLayout.h"

#include <QLayoutItem>
#include <QStyle>
#include <QWidget>

namespace ks::ui
{
    FlowLayout::FlowLayout(
        QWidget* const parent,
        const int margin,
        const int horizontalSpacing,
        const int verticalSpacing)
        : QLayout(parent)
        , m_horizontalSpacing(horizontalSpacing)
        , m_verticalSpacing(verticalSpacing)
    {
        if (margin >= 0)
        {
            setContentsMargins(margin, margin, margin, margin);
        }
    }

    FlowLayout::~FlowLayout()
    {
        // QLayout 不会替派生类回收 item：takeAt 是唯一的移交口径，
        // 析构时必须自己排空，否则每次重建界面都漏一批 QWidgetItem。
        while (QLayoutItem* const item = takeAt(0))
        {
            delete item;
        }
    }

    void FlowLayout::addItem(QLayoutItem* const item)
    {
        if (item == nullptr)
        {
            return;
        }
        m_items.append(item);
    }

    int FlowLayout::horizontalSpacing() const
    {
        if (m_horizontalSpacing >= 0)
        {
            return m_horizontalSpacing;
        }
        return smartSpacing(QStyle::PM_LayoutHorizontalSpacing);
    }

    int FlowLayout::verticalSpacing() const
    {
        if (m_verticalSpacing >= 0)
        {
            return m_verticalSpacing;
        }
        return smartSpacing(QStyle::PM_LayoutVerticalSpacing);
    }

    Qt::Orientations FlowLayout::expandingDirections() const
    {
        // 不声明任何扩展方向：这排按钮应当贴着顶部，多出来的竖向空间要留给
        // 下面的表格。声明了 Vertical 会让按钮行跟着窗口一起长高。
        return Qt::Orientations();
    }

    bool FlowLayout::hasHeightForWidth() const
    {
        return true;
    }

    int FlowLayout::heightForWidth(const int width) const
    {
        return doLayout(QRect(0, 0, width, 0), true);
    }

    int FlowLayout::count() const
    {
        return static_cast<int>(m_items.size());
    }

    QLayoutItem* FlowLayout::itemAt(const int index) const
    {
        return m_items.value(index);
    }

    QLayoutItem* FlowLayout::takeAt(const int index)
    {
        if (index < 0 || index >= static_cast<int>(m_items.size()))
        {
            return nullptr;
        }
        return m_items.takeAt(index);
    }

    QSize FlowLayout::minimumSize() const
    {
        QSize size;
        for (const QLayoutItem* const item : m_items)
        {
            size = size.expandedTo(item->minimumSize());
        }
        const QMargins margins = contentsMargins();
        // 最小宽度只按**最宽的单个控件**算，而不是所有控件之和：这正是换行
        // 布局存在的意义——窗口窄到只能放下一个按钮时也要能完整显示它。
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom());
        return size;
    }

    void FlowLayout::setGeometry(const QRect& rect)
    {
        QLayout::setGeometry(rect);
        doLayout(rect, false);
    }

    QSize FlowLayout::sizeHint() const
    {
        return minimumSize();
    }

    int FlowLayout::doLayout(const QRect& rect, const bool testOnly) const
    {
        int left = 0;
        int top = 0;
        int right = 0;
        int bottom = 0;
        getContentsMargins(&left, &top, &right, &bottom);
        const QRect effective = rect.adjusted(left, top, -right, -bottom);

        int x = effective.x();
        int y = effective.y();
        int lineHeight = 0;

        for (QLayoutItem* const item : m_items)
        {
            const QWidget* const widget = item->widget();
            int spaceX = horizontalSpacing();
            int spaceY = verticalSpacing();
            if (widget != nullptr)
            {
                // 间距未显式指定时向控件样式要：不同主题下的按钮间距不一样，
                // 写死会在其中一个主题里显得过挤或过散。
                if (spaceX < 0)
                {
                    spaceX = widget->style()->layoutSpacing(
                        QSizePolicy::PushButton,
                        QSizePolicy::PushButton,
                        Qt::Horizontal);
                }
                if (spaceY < 0)
                {
                    spaceY = widget->style()->layoutSpacing(
                        QSizePolicy::PushButton,
                        QSizePolicy::PushButton,
                        Qt::Vertical);
                }
            }
            if (spaceX < 0)
            {
                spaceX = 0;
            }
            if (spaceY < 0)
            {
                spaceY = 0;
            }

            const QSize itemHint = item->sizeHint();
            int next = x + itemHint.width() + spaceX;
            if (next - spaceX > effective.right() + 1 && lineHeight > 0)
            {
                // 这一行放不下了：换行。lineHeight > 0 的条件保证一个比整行
                // 还宽的控件不会被无限往下推——它独占一行，宽度照给。
                x = effective.x();
                y = y + lineHeight + spaceY;
                next = x + itemHint.width() + spaceX;
                lineHeight = 0;
            }

            if (!testOnly)
            {
                item->setGeometry(QRect(QPoint(x, y), itemHint));
            }

            x = next;
            lineHeight = qMax(lineHeight, itemHint.height());
        }
        return y + lineHeight - rect.y() + bottom;
    }

    int FlowLayout::smartSpacing(const int pixelMetric) const
    {
        QObject* const parentObject = parent();
        if (parentObject == nullptr)
        {
            return -1;
        }
        if (parentObject->isWidgetType())
        {
            auto* const parentWidget = static_cast<QWidget*>(parentObject);
            return parentWidget->style()->pixelMetric(
                static_cast<QStyle::PixelMetric>(pixelMetric),
                nullptr,
                parentWidget);
        }
        return static_cast<QLayout*>(parentObject)->spacing();
    }
}
