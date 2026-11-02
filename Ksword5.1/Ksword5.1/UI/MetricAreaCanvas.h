#pragma once
#include "MetricAreaRenderer.h"
#include <QWidget>
#include <QIcon>
#include <QColor>
#include <QPixmap>
#include <functional>
#include <vector>

class QPainter;

namespace ks::ui {
struct MetricAreaNode {
    QString key, name, identity, value, tooltip;
    QIcon icon;
    QColor background, foreground;
    // Non-negative finite area. For signed deltas the adapter supplies abs(value)
    // here while retaining the signed display text. Invalid areas are unavailable.
    double weight = 0;
    int parent = -1;
    bool group = false;
    bool known = true;
};

// A view of an immutable presentation snapshot. No sampling, process lookup or timers.
class MetricAreaCanvas final : public QWidget {
public:
    explicit MetricAreaCanvas(QWidget* parent = nullptr);
    void setNodes(std::vector<MetricAreaNode> nodes);
    void resetRoot();
    void goBack();
    int nodeAt(QPointF point) const;
    QRectF nodeRect(int index) const;
    int rootIndex() const { return m_root; }
    const std::vector<MetricAreaNode>& nodes() const { return m_nodes; }
    std::function<void(int, QPoint)> contextRequested;
    std::function<void(int)> activated;
    std::function<void()> rootChanged;
protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseDoubleClickEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override;
    void keyPressEvent(QKeyEvent*) override;
    bool event(QEvent*) override;
private:
    struct Box { QRectF rect; int node; bool container; };
    void rebuildLayout();
    void focusNode(int index);
    int boxAt(QPointF point) const;
    QColor boxColor(int index) const;
    void paintBox(QPainter& painter, const Box& box, bool hovered) const;
    std::vector<MetricAreaNode> m_nodes;
    std::vector<std::vector<int>> m_children;
    std::vector<int> m_parents;
    std::vector<int> m_colorAnchors;
    std::vector<double> m_totals;
    std::vector<Box> m_boxes;
    MetricAreaRenderer m_renderer;
    QPixmap m_surface;
    bool m_surfaceDirty = true;
    // Index into the visible boxes, so a process's own area and its child group stay distinct.
    int m_root = -1, m_hover = -1;
};
}
