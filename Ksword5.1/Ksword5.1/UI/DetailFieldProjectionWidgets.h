#pragma once

#include <QLabel>
#include <QFormLayout>
#include <QPainter>
#include <QSet>
#include <QPointer>
#include <QMap>
#include <array>
#include <climits>

namespace ks::ui::detail_cards
{
    // 可见字段的原生控件与自然高度缓存；不拥有规范文档的副本。
    struct MaterializedRow
    {
        QPointer<QLabel> label, value; // 仍由原生父控件管理寿命的名称和值。
        int measuredWidth = -1; // 文字自然高度对应的宽度，文字改变时失效。
        int naturalHeight = 0; // 不受上一轮固定高度钳制的自然高度。
        QFont measuredFont; // 自然高度缓存使用的字体。
        // 无输入，返回是否必须保留原控件以维持选区/键盘焦点。
        bool pinned() const { return value && (value->hasFocus() || value->hasSelectedText()); }
    };

    // 共享卡片的有界物化状态；滚动窗口与外卡片几何分别管理。
    struct MaterializedCard
    {
        QPointer<QWidget> widget, firstPane, secondPane, notesPane, columnsHost; // 卡片及共享分栏宿主。
        QPointer<QLabel> heading; // 共享卡片的原始标题控件。
        std::array<QFormLayout*, 3> forms{}; // 两列字段和全宽附注的原生表单。
        QMap<int, MaterializedRow> rows; // 当前窗口与明确保留选区的字段控件。
        std::array<QVector<int>, 3> formRows; // 已挂入布局的行身份，负数表示预算占位。
        std::array<qint64, 3> formFirst{}, formLast{}; // 上一轮布局覆盖的逻辑范围。
        quint64 layoutRevision = 0; // 新文档/字体/宽度或行高校正使缓存失效。
        qint64 windowFirst = 0, windowLast = 0; // 含预取余量的有界物化窗口。
        bool columnsInLayout = false, notesInLayout = true; // 选区保留时的共享宿主挂载状态。
    };

    // 输入原生表单及新窗口字段身份；只移除离开窗口的布局行，保留重叠行的原布局项。
    // 有预算占位项时返回false，由调用者处理占位转实体，不把占位误认为规范字段。
    inline bool retainFormRows(QFormLayout* form, const QSet<int>& wanted)
    {
        for (int position = 0; position < form->rowCount(); ++position)
        {
            const auto* item = form->itemAt(position, QFormLayout::FieldRole); // 普通字段位于FieldRole，附注跨整行。
            if (!item)
            {
                item = form->itemAt(position, QFormLayout::SpanningRole);
            }
            if (!item || !item->widget())
            {
                return false;
            }
        }
        // 从尾到头移除，原生索引不影响尚未处理的行；不隐藏或重挂仍可见的标签。
        for (int position = form->rowCount() - 1; position >= 0; --position)
        {
            const auto* item = form->itemAt(position, QFormLayout::FieldRole); // 此行规范值标签布局项。
            if (!item)
            {
                item = form->itemAt(position, QFormLayout::SpanningRole);
            }
            if (!wanted.contains(item->widget()->property("ksword_card_field").toInt()))
            {
                const auto removed = form->takeRow(position); // 仅释放布局项；控件和选区寿命归原投影管理。
                delete removed.labelItem;
                delete removed.fieldItem;
            }
        }
        return true;
    }

    // 虚拟正文显式拥有画布；不透明时允许Qt搬移已绘像素，而不是整视口清底重画。
    class Canvas final : public QWidget
    {
    public:
        // 输入父控件，画布颜色由投影的唯一主题入口在首帧前设置。
        explicit Canvas(QWidget* parent) : QWidget(parent) {}

        // 输入当前实际底色；透明模式不能错误宣称opaque，变化时才请求绘制。
        void setCanvasColor(const QColor& color)
        {
            if (m_color == color)
            {
                return;
            }
            m_color = color;
            setAttribute(Qt::WA_OpaquePaintEvent, color.alpha() == 255);
            update();
        }
    protected:
        // 绘制当前脏区，QPainter沿用Qt提供的裁剪，不触发额外的布局或重绘。
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this); // 当前正文的原生光栅绘制上下文。
            painter.fillRect(rect(), m_color);
        }
    private:
        QColor m_color; // 仅由投影主题入口更新的真实画布色，包含透明度。
    };

    // 名称完整换行长信息类名；测量与绘制使用相同规则，不修改规范字段文本。
    class NameLabel final : public QLabel
    {
    public:
        // 输入原始字段名和卡片父控件，输出具有原生QLabel身份的名称控件。
        NameLabel(const QString& name, QWidget* parent) : QLabel(name, parent)
        {
            setWordWrap(true);
        }

        // 输入可用文字宽度，输出自然高度；允许在无空格的信息类名内部换行。
        int heightForWidth(int width) const override
        {
            return qMax(fontMetrics().height(), fontMetrics().boundingRect(
                QRect(0, 0, qMax(1, width), INT_MAX / 8),
                Qt::TextWordWrap | Qt::TextWrapAnywhere, text()).height());
        }
    protected:
        // 仅绘制名称前景；实底仍归共享卡片，不另铺矩形或改变选区/导出数据源。
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this); // 当前名称的绘制上下文，继承Qt脏区裁剪。
            painter.setPen(palette().color(foregroundRole()));
            painter.drawText(contentsRect(), alignment() | Qt::TextWordWrap | Qt::TextWrapAnywhere, text());
        }
    };
}
