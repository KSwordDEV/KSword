#pragma once
#include "../UI/MetricAreaRenderer.h"

#include <QRectF>
#include <QString>
#include <QVector>
#include <QWidget>

#include <functional>
#include <memory>

class QKeyEvent;
class QMouseEvent;
class QPaintEvent;
class QResizeEvent;
class QPainter;

// A projection of one immutable directory snapshot. This widget never queries
// the file system; the page computes directory sizes on its worker.
class NtfsSpaceMapWidget final : public QWidget
{
public:
    struct Item
    {
        quint64 reference = 0;
        QString name;
        QString path;
        QString extension;
        quint64 bytes = 0;
        bool directory = false;
    };
    struct Data
    {
        QVector<Item> items;
        QVector<long double> prefixWeights;
    };
    using DataPtr = std::shared_ptr<const Data>;

    // Blocking preparation belongs in the page's worker. Destruction of a
    // prepared value is also retired to the worker pool if released by the GUI.
    static DataPtr prepare(QVector<Item> items);

    explicit NtfsSpaceMapWidget(QWidget* parent = nullptr);
    void setData(DataPtr data);
    // Items should be prepared in descending byte order by the page worker.
    // Zero-byte items do not occupy space; their rows remain in the page table.
    void setItems(QVector<Item> items);
    void setSelectedReference(quint64 reference);
    // Distinguish unavailable/loading states from a successful empty directory.
    void setEmptyMessage(const QString& source);
    void refreshAppearance();

    std::function<void(quint64)> activated;
    std::function<void(quint64)> selected;

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    bool event(QEvent* event) override;

private:
    struct Tile
    {
        QRectF rectangle;
        qsizetype first = 0;
        qsizetype last = 0; // Exclusive; more than one item is an aggregate.
    };
    void rebuildLayout();
    int hitTest(const QPointF& point) const;
    void chooseTile(int tile);
    QString tileToolTip(int tile) const;
    void paintTile(QPainter& painter, int tile, bool interactive) const;

    DataPtr m_data;
    QVector<Tile> m_tiles;
    int m_hover = -1;
    int m_selectedTile = -1;
    quint64 m_selectedReference = 0;
    bool m_hasSelection = false;
    QString m_emptyMessage;
    ks::ui::MetricAreaRenderer m_renderer;
    QPixmap m_surface;
    bool m_surfaceDirty = true;
};
