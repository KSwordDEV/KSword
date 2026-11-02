#pragma once

#include <QColor>
#include <QPalette>
#include <QPixmap>
#include <QRectF>
#include <QString>

class QPainter;

namespace ks::ui {

struct MetricAreaTileState {
    bool group = false;
    bool hovered = false;
    bool selected = false;
    // A container's children are already in the scene cache; only emphasize its outline.
    bool outlineOnly = false;
};

// Shared drawing for metric trees and bounded file-space projections.
// Layout, object identity, selection and navigation stay with their owning view.
class MetricAreaRenderer final {
public:
    MetricAreaRenderer();
    static QColor identityColor(const QString& identity, const QPalette& palette,
        const QString& variant = {});
    static QColor captionColor(const QColor& color, const QPalette& palette);
    QColor paintTile(QPainter& painter, const QRectF& rectangle, const QColor& color,
        const MetricAreaTileState& state = {}) const;
private:
    QPixmap m_cushion;
};

}
