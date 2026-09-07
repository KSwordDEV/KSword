#pragma once

// FlowLayout：一排放不下就换行的布局。
//
// 为什么需要它：QHBoxLayout 在宽度不够时不会换行，也不会省略号，而是把每个
// 子控件压到 sizeHint 以下——QPushButton 的文字就被**直接裁掉**。1024×768
// 上 KVM 页那两排按钮正是这么变成「efresh Capabilitie」「'repare VMX/EP」的：
// 布局本身没报错，按钮也还能点，但标签读不出来了。
//
// 用 QGridLayout 固定列数不能解决问题：列数在构造期就定死了，宽窗口浪费一半
// 版面，窄窗口照样裁。换行布局按**实际可用宽度**决定每行放几个，是这里唯一
// 随窗口变化的做法。
//
// 实现要点是 heightForWidth：布局的高度取决于宽度（换行数），Qt 只有在
// hasHeightForWidth() 返回 true 时才会问这个问题，两者缺一不可。

#include <QLayout>
#include <QList>
#include <QRect>
#include <QSize>

class QLayoutItem;
class QWidget;

namespace ks::ui
{
    class FlowLayout final : public QLayout
    {
    public:
        explicit FlowLayout(
            QWidget* parent = nullptr,
            int margin = -1,
            int horizontalSpacing = -1,
            int verticalSpacing = -1);
        ~FlowLayout() override;

        FlowLayout(const FlowLayout&) = delete;
        FlowLayout& operator=(const FlowLayout&) = delete;

        void addItem(QLayoutItem* item) override;

        int horizontalSpacing() const;
        int verticalSpacing() const;

        Qt::Orientations expandingDirections() const override;
        bool hasHeightForWidth() const override;
        int heightForWidth(int width) const override;
        int count() const override;
        QLayoutItem* itemAt(int index) const override;
        QLayoutItem* takeAt(int index) override;
        QSize minimumSize() const override;
        void setGeometry(const QRect& rect) override;
        QSize sizeHint() const override;

    private:
        // doLayout：真正的排布。testOnly 为真时只算高度不动控件，
        // heightForWidth 走这条路——布局计算期间移动控件会引发重入。
        int doLayout(const QRect& rect, bool testOnly) const;
        int smartSpacing(int pixelMetric) const;

        QList<QLayoutItem*> m_items;
        int m_horizontalSpacing;
        int m_verticalSpacing;
    };
}
